import type { Policy } from '../packages/scope-engine/index.js';
export const fixture = {
  id: 'fixture-company', name: 'Fixture Company', platform: 'fixture',
  programUrl: 'https://bounty.example.test', categories: ['WEB_APPLICATION', 'API'],
  policy: {
    programId: 'fixture-company', revision: 'fixture-v1', sourceUrl: 'https://bounty.example.test/policy',
    reviewed: true, expiresAt: '2099-01-01T00:00:00Z',
    allowed: ['*.example.test'], excluded: ['payments.example.test'],
    allowedActions: ['inspect_http_target'], allowedPaths: ['/'], schemes: ['https'], ports: [443], requestsPerSecond: 1,
  } satisfies Policy,
  assets: [{ id: 'fixture-api', url: 'https://api.example.test' }],
};
