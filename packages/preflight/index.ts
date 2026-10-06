// Read-only first-run checks. This module does not contact HackerOne or any target.

const HANDLE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/;
const MAX_REQUESTS_PER_SECOND = 10;

export interface PreflightProgram { id: string; requestsPerSecond: number | null }
export interface PreflightFacts {
  killSwitch: boolean;
  passiveHttp: boolean;
  dbReachable: boolean;
  pendingMigrations: string[];
  hackerOneUser: boolean;
  hackerOneToken: boolean;
  handles: string[];
  programs: PreflightProgram[];
}
export interface PreflightReport { ok: boolean; lines: string[] }

export function parseHandles(text: string): string[] {
  return text.split(/\r?\n/).map(line => line.trim()).filter(line => line.length > 0 && !line.startsWith('#'));
}

export function evaluatePreflight(facts: PreflightFacts): PreflightReport {
  const lines: string[] = [];
  let ok = true;
  const check = (name: string, pass: boolean, detail: string) => {
    lines.push(`${pass ? 'ok' : 'fail'} ${name} ${detail}`);
    if (!pass) ok = false;
  };
  check('kill_switch', facts.killSwitch === false, facts.killSwitch ? 'GLOBAL_KILL_SWITCH=true' : 'GLOBAL_KILL_SWITCH=false');
  check('passive_http', facts.passiveHttp === true, facts.passiveHttp ? 'ENABLE_PASSIVE_HTTP=true' : 'ENABLE_PASSIVE_HTTP=false');
  check('database', facts.dbReachable, facts.dbReachable ? 'reachable' : 'unreachable');
  check('migrations', facts.dbReachable && facts.pendingMigrations.length === 0, facts.pendingMigrations.length ? `pending:${facts.pendingMigrations.join(',')}` : 'current');
  check('hackerone_credentials', facts.hackerOneUser && facts.hackerOneToken, 'username_and_token_required');
  const handlesOk = facts.handles.length > 0 && facts.handles.every(handle => HANDLE.test(handle));
  check('handles', handlesOk, handlesOk ? `count=${facts.handles.length}` : 'programs/handles.txt empty or invalid');
  const ratesOk = facts.programs.every(program => program.requestsPerSecond !== null && program.requestsPerSecond > 0 && program.requestsPerSecond <= MAX_REQUESTS_PER_SECOND);
  check('rate_budgets', ratesOk, ratesOk ? (facts.programs.length ? `programs=${facts.programs.length}` : 'none_loaded') : 'per_program_rate_out_of_range');
  return { ok, lines };
}
