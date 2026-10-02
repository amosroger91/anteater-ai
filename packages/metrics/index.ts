// Operational metrics + alert thresholds (PRODUCTION_ROADMAP.md §7). Pure: given a fleet snapshot and
// thresholds, return the alerts that should fire. The collector/transport is infra; the policy is here.

export interface FleetSnapshot {
  queueAgeSeconds: number;
  coverageGaps: number;
  rateLimitHits: number;
  toolFailures: number;
  mailboxFailures: number;
  deadLettered: number;
}

export interface Thresholds {
  queueAgeSeconds: number;
  coverageGaps: number;
  rateLimitHits: number;
  toolFailures: number;
  mailboxFailures: number;
  deadLettered: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  queueAgeSeconds: 900, coverageGaps: 1, rateLimitHits: 50, toolFailures: 5, mailboxFailures: 1, deadLettered: 1,
};

export interface Alert { code: string; value: number; threshold: number }

export function computeAlerts(snapshot: FleetSnapshot, thresholds: Thresholds = DEFAULT_THRESHOLDS): Alert[] {
  const alerts: Alert[] = [];
  for (const key of Object.keys(thresholds) as (keyof Thresholds)[]) {
    if (snapshot[key] > thresholds[key]) alerts.push({ code: key, value: snapshot[key], threshold: thresholds[key] });
  }
  return alerts;
}
