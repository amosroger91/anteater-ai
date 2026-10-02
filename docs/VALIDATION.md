# Initial milestone validation — 2026-10-02

- `npm run check`: TypeScript build and 33 unit tests passed.
- `npm run verify:local`: 9 reported integration tests (including the parent test) passed against native PostgreSQL 17; fixture demonstration and deduplicated replay passed.
- Verified lease fencing, expiry recovery, bounded retries, concurrent claims, rate reservation, invocation-time scope changes, kill switch, rejected arbitrary tools, persistent observations, Markdown export and operator-note preservation.
- `docker compose config --quiet`: passed.
- `npm install`: dependency audit reported zero known vulnerabilities at installation time.
- No requests were made to research targets. All observed responses are synthetic fixture data.

Docker Desktop failed during local Secrets Engine startup with a socket-access error. PostgreSQL container runtime and the inert Kali image could not be exercised locally. Temporary native PostgreSQL was used for real database integration tests instead; its process was stopped afterward. GitHub CI is configured to repeat the checks against PostgreSQL in a service container.

Ollama inference and real MCP execution were not exercised. The demo uses the deterministic model fixture. Live MCP is intentionally not implemented. See READINESS.md for the release gate.
