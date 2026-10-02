import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { z } from 'zod';
import { ScanResult, coverageReport, validateRegistry } from '../packages/coverage/index.js';

// Render a methodology coverage report from a posture scan's results JSON.
// usage: tsx scripts/coverage.ts [posture-results/latest.json] [--json]

validateRegistry();

const args = process.argv.slice(2);
const input = args.find(a => !a.startsWith('--')) ?? join('posture-results', 'latest.json');
const asJson = args.includes('--json');

try {
  const raw = JSON.parse(await readFile(input, 'utf8')) as unknown;
  const results = z.array(ScanResult).parse(raw)
    .filter(r => r.executed !== false); // held (not-run) aggressive rows are not coverage
  if (!results.length) throw new Error(`no executed results in ${input}`);

  const report = coverageReport(results);
  if (asJson) { console.log(JSON.stringify({ summary: report.summary, perTarget: report.perTarget }, null, 2)); }
  else {
    console.log(report.markdown);
    const out = join(dirname(input), 'coverage.md');
    await mkdir(dirname(out), { recursive: true });
    await writeFile(out, report.markdown);
    console.log(`\nSaved ${out}`);
  }
} catch (e) {
  console.error(e instanceof Error ? e.message : 'coverage_failed');
  process.exitCode = 1;
}
