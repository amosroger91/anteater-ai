import { runLocalFixtureScan } from '../apps/orchestrator/fixture-campaign.js';

// Runnable end-to-end campaign over local fixtures (PRODUCTION_ROADMAP.md §0 wiring). Demonstrates
// discover -> admit -> job -> check -> cover -> verify with no live target. usage: npm run campaign

const result = await runLocalFixtureScan();

console.log(JSON.stringify({
  admitted: result.admitted, held: result.held, jobs: result.jobs.length,
  coverage: result.coverage, verified: result.verification?.next, reproduced: result.verification?.reproduced,
  remediations: result.remediations.map(r => r.code),
}, null, 2));
