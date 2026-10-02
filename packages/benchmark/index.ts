import type { HttpResponseView, WebFinding } from '../web-checks/index.js';

// Detector release gate + baseline metrics (PRODUCTION_ROADMAP.md §0).
// A detector may ship only if it FLAGS its vulnerable fixture and PASSES its patched fixture.

export interface DetectorCase {
  name: string;
  detector: (v: HttpResponseView) => WebFinding[];
  code: string;                 // the finding code that signals the issue
  vulnerable: HttpResponseView;
  patched: HttpResponseView;
}

export interface GateResult { ok: boolean; failures: string[]; metrics: { detectors: number; truePositives: number; falsePositives: number } }

export function detectorGate(cases: DetectorCase[]): GateResult {
  const failures: string[] = [];
  let truePositives = 0, falsePositives = 0;
  for (const c of cases) {
    const onVuln = c.detector(c.vulnerable).some(f => f.code === c.code);
    const onPatched = c.detector(c.patched).some(f => f.code === c.code);
    if (onVuln) truePositives++; else failures.push(`${c.name}: missed vulnerable (${c.code})`);
    if (onPatched) { falsePositives++; failures.push(`${c.name}: false positive on patched (${c.code})`); }
  }
  return { ok: failures.length === 0, failures, metrics: { detectors: cases.length, truePositives, falsePositives } };
}
