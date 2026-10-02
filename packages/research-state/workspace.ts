import type pg from 'pg';
import { mkdir, writeFile, rename, lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { transaction } from './db.js';
import { PolicySchema } from '../scope-engine/index.js';
import { ProgramSchema, type Program } from '../bounty-providers/index.js';

export async function saveProgram(pool: pg.Pool, program: Program) {
  program = ProgramSchema.parse(program);
  const policy = PolicySchema.parse(program.policy);
  if (policy.programId !== program.id) throw new Error('policy_program_mismatch');
  await transaction(pool, async c => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`program:${program.id}`]);
    await c.query(`INSERT INTO programs(id,name,platform,program_url,categories) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,platform=excluded.platform,program_url=excluded.program_url,categories=excluded.categories,updated_at=now()`,
      [program.id,program.name,program.platform,program.programUrl,JSON.stringify(program.categories)]);
    await c.query(`INSERT INTO scope_rules(program_id,policy) VALUES($1,$2) ON CONFLICT(program_id) DO UPDATE SET policy=excluded.policy`, [program.id,JSON.stringify(policy)]);
    const ids = program.assets.map(asset => asset.id);
    await c.query(`UPDATE assets SET active=false WHERE program_id=$1 AND NOT (id = ANY($2::text[]))`, [program.id, ids]);
    for (const asset of program.assets) {
      // Retire work tied to a former URL before changing the asset in place.
      await c.query(`UPDATE research_jobs j SET status='failed',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL,result=$3
        FROM assets a WHERE j.asset_id=a.id AND j.program_id=a.program_id AND a.id=$1 AND a.program_id=$2
        AND a.url<>$4 AND j.status IN ('queued','running')`, [asset.id, program.id, JSON.stringify({ error: 'asset_url_changed' }), asset.url]);
      const result = await c.query(`INSERT INTO assets(id,program_id,url,active,policy_revision) VALUES($1,$2,$3,true,$4)
        ON CONFLICT(id) DO UPDATE SET url=excluded.url,active=true,policy_revision=excluded.policy_revision
        WHERE assets.program_id=excluded.program_id`, [asset.id,program.id,asset.url,policy.revision]);
      if (!result.rowCount) throw new Error('asset_program_mismatch');
    }
    await c.query(`UPDATE research_jobs SET status='failed',lease_token=NULL,lease_until=NULL,lease_heartbeat_at=NULL,result=$2
      WHERE program_id=$1 AND policy_revision<>$3 AND status IN ('queued','running')`, [program.id, JSON.stringify({ error: 'policy_revision_changed' }), policy.revision]);
    await c.query(`UPDATE research_jobs SET policy_revision=$2 WHERE program_id=$1 AND status='queued'`, [program.id,policy.revision]);
    await c.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [program.id]);
  });
}

// Human-readable exports are projections, not authorization inputs. NOTES.md is operator-owned.
export async function exportWorkspace(pool: pg.Pool, root: string, programId: string) {
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(programId)) throw new Error('invalid_program_id');
  await transaction(pool, async c => {
    await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`workspace:${programId}`]);
    const pending = await c.query('SELECT revision FROM workspace_outbox WHERE program_id=$1', [programId]);
    const revision = pending.rows[0]?.revision;
    if (revision === undefined) return;
    const p = (await c.query('SELECT * FROM programs WHERE id=$1', [programId])).rows[0];
    const policy = (await c.query('SELECT policy FROM scope_rules WHERE program_id=$1', [programId])).rows[0]?.policy;
    const assets = (await c.query('SELECT id,url,active,policy_revision FROM assets WHERE program_id=$1 ORDER BY id', [programId])).rows;
    const observations = (await c.query('SELECT id,body FROM observations WHERE program_id=$1 ORDER BY created_at,id', [programId])).rows;
    const findings = (await c.query('SELECT id,status,body FROM findings WHERE program_id=$1 ORDER BY id', [programId])).rows;
    const hypotheses = (await c.query('SELECT id,body,observation_id,agent_run_id FROM hypotheses WHERE program_id=$1 ORDER BY id', [programId])).rows;
    const audit = (await c.query('SELECT event,job_id,asset_id,metadata,created_at FROM audit_events WHERE program_id=$1 ORDER BY created_at,id', [programId])).rows;
    const jobs = (await c.query('SELECT id,status,attempts FROM research_jobs WHERE program_id=$1 ORDER BY created_at,id', [programId])).rows;
    const directory = resolve(root, programId);
    await mkdir(directory, { recursive: true });
    if ((await lstat(directory)).isSymbolicLink()) throw new Error('workspace_symlink');
    const block = (value: unknown) => '```json\n' + JSON.stringify(value,null,2).replace(/`/g,'\\u0060').replace(/</g,'\\u003c') + '\n```\n';
    const header = `<!-- anteater workspace schema=1 revision=${revision}; generated, do not edit -->\n`;
    const files: Record<string,string> = {
      'PROGRAM.md': '# Program\n\n' + block(p),
      'SCOPE.md': '# Scope\n\nAuthoritative only in the database; export is for review.\n\n' + block(policy),
      'ASSETS.md': '# Assets\n\n' + block(assets),
      'RECON.md': '# Observations\n\nObservations are not confirmed vulnerabilities.\n\n' + block(observations),
      'FINDINGS.md': '# Findings\n\nStates: OBSERVATION, HYPOTHESIS, CANDIDATE, VERIFICATION, VERIFIED, HUMAN_REVIEW, REJECTED, SUBMITTED.\n\n' + block(findings),
      'HYPOTHESES.md': '# Accepted model hypotheses\n\nUnverified suggestions; human_review is an operator triage hint.\n\n' + block(hypotheses),
      'AUDIT.md': '# Execution events\n\n' + block(audit),
      'HISTORY.md': '# Job history\n\n' + block(jobs),
    };
    for (const [name, content] of Object.entries(files)) {
      const temporary = join(directory, `.${name}.${randomUUID()}.tmp`);
      await writeFile(temporary, header + content, { flag: 'wx' });
      await rename(temporary, join(directory,name));
    }
    try { await writeFile(join(directory,'NOTES.md'), '# Operator notes\n\nThis file is never overwritten by exports.\n', { flag: 'wx' }); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    // Conditional acknowledgment prevents a concurrent update from losing its pending export.
    await c.query('DELETE FROM workspace_outbox WHERE program_id=$1 AND revision=$2', [programId,revision]);
  });
}
