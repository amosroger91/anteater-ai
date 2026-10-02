import type pg from 'pg';
import { mkdir, writeFile, rename, lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { transaction } from './db.js';
import { PolicySchema } from '../scope-engine/index.js';
import type { fixture } from '../../fixtures/program.js';

export async function saveProgram(pool: pg.Pool, program: typeof fixture) {
  const policy = PolicySchema.parse(program.policy);
  if (policy.programId !== program.id) throw new Error('policy_program_mismatch');
  await transaction(pool, async c => {
    await c.query(`INSERT INTO programs(id,name,platform,program_url,categories) VALUES($1,$2,$3,$4,$5)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name,platform=excluded.platform,program_url=excluded.program_url,categories=excluded.categories,updated_at=now()`,
      [program.id,program.name,program.platform,program.programUrl,JSON.stringify(program.categories)]);
    await c.query(`INSERT INTO scope_rules(program_id,policy) VALUES($1,$2) ON CONFLICT(program_id) DO UPDATE SET policy=excluded.policy`, [program.id,JSON.stringify(policy)]);
    for (const asset of program.assets) {
      await c.query('INSERT INTO assets(id,program_id,url) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING', [asset.id,program.id,asset.url]);
    }
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
    const assets = (await c.query('SELECT id,url FROM assets WHERE program_id=$1 ORDER BY id', [programId])).rows;
    const observations = (await c.query('SELECT id,body FROM observations WHERE program_id=$1 ORDER BY created_at,id', [programId])).rows;
    const findings = (await c.query('SELECT id,status,body FROM findings WHERE program_id=$1 ORDER BY id', [programId])).rows;
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
