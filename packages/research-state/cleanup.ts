import type pg from 'pg';
import type { CleanupIntent, CleanupJournal } from '../application-research/cleanup.js';
import { transaction } from './db.js';

export class PostgresCleanupJournal implements CleanupJournal {
  constructor(private pool: pg.Pool, private programId: string) {}
  async pending(): Promise<CleanupIntent[]> {
    const rows = await this.pool.query('SELECT intent FROM resource_cleanup WHERE program_id=$1 ORDER BY created_at,id LIMIT 101', [this.programId]);
    if (rows.rows.length > 100) throw new Error('cleanup_backlog_requires_operator');
    return rows.rows.map(row => row.intent as CleanupIntent);
  }
  async prepare(intent: CleanupIntent) {
    await transaction(this.pool, async client => {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`program:${this.programId}`]);
      await client.query('INSERT INTO resource_cleanup(id,program_id,intent) VALUES($1,$2,$3)', [intent.id, this.programId, JSON.stringify(intent)]);
      await this.notify(client);
    });
  }
  async complete(id: string) {
    await transaction(this.pool, async client => {
      await client.query('DELETE FROM resource_cleanup WHERE id=$1 AND program_id=$2', [id, this.programId]);
      await this.notify(client);
    });
  }
  private async notify(client: pg.PoolClient) {
    await client.query(`INSERT INTO workspace_outbox(program_id) VALUES($1) ON CONFLICT(program_id) DO UPDATE SET revision=workspace_outbox.revision+1`, [this.programId]);
  }
}
