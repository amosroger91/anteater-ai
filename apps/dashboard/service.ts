import type pg from 'pg';

// Read-only live-progress view over main's real tables. Every query is defensive: a missing table
// (migrations not yet applied) yields zero rather than crashing, so the dashboard is always safe to open.

export interface DashboardState {
  programs: number;
  assets: number;
  jobs: Record<string, number>;       // research_jobs.status -> count
  observations: number;
  findings: Record<string, number>;   // findings.status -> count
  submissions: Record<string, number>;// submissions.state -> count (ledger), if present
  generatedAt: string;
}

async function scalar(pool: Pick<pg.Pool, 'query'>, sql: string): Promise<number> {
  try { const r = await pool.query(sql); return Number((r.rows[0] as { n?: number } | undefined)?.n ?? 0); }
  catch { return 0; }
}

async function grouped(pool: Pick<pg.Pool, 'query'>, sql: string): Promise<Record<string, number>> {
  try {
    const r = await pool.query(sql);
    const out: Record<string, number> = {};
    for (const row of r.rows as Array<{ k: unknown; n: unknown }>) out[String(row.k)] = Number(row.n);
    return out;
  } catch { return {}; }
}

export async function dashboardState(pool: Pick<pg.Pool, 'query'>): Promise<DashboardState> {
  return {
    programs: await scalar(pool, 'SELECT count(*)::int AS n FROM programs'),
    assets: await scalar(pool, 'SELECT count(*)::int AS n FROM assets'),
    jobs: await grouped(pool, 'SELECT status AS k, count(*)::int AS n FROM research_jobs GROUP BY status'),
    observations: await scalar(pool, 'SELECT count(*)::int AS n FROM observations'),
    findings: await grouped(pool, 'SELECT status AS k, count(*)::int AS n FROM findings GROUP BY status'),
    submissions: await grouped(pool, 'SELECT state AS k, count(*)::int AS n FROM submissions GROUP BY state'),
    generatedAt: new Date().toISOString(),
  };
}
