# Initial milestone validation — 2026-10-02

- `npm run check`: TypeScript build and 59 unit tests passed.
- `npm run verify:local`: 9 reported integration tests (including the parent test) passed against native PostgreSQL 17; fixture demonstration and deduplicated replay passed.
- Verified lease fencing, expiry recovery, bounded retries, policy-revision invalidation, concurrent claims, rate reservation, invocation-time scope changes, kill switch, rejected arbitrary tools, tool-only observations, structured model grounding, Markdown export and operator-note preservation.
- `docker compose config --quiet`: passed.
- `npm install`: dependency audit reported zero known vulnerabilities at installation time.
- No requests were made to research targets. All observed responses are synthetic fixture data.

Docker Desktop failed during local Secrets Engine startup with a socket-access error. PostgreSQL container runtime and the inert Kali image could not be exercised locally. Temporary native PostgreSQL was used for real database integration tests instead; its process was stopped afterward. GitHub CI is configured to repeat the checks against PostgreSQL in a service container.

Ollama inference and real MCP execution were not exercised. The demo and continuous worker use the deterministic model fixture; the Ollama adapter is covered with a stubbed transport. Live MCP and target execution are intentionally not implemented. See READINESS.md for the release gate.

## Web dependency library — 2026-10-02

- Registered and downloaded sparse source/data checkouts for all 29 Git submodules at their pinned commits.
- Verified every selected source directory and wordlist file exists. Corrected an outdated SecLists filename during this check.
- TypeScript build and 39 unit tests passed; the dependency registry check validates all 29 paths, origins, branches and commit pins.
- A dirty-checkout probe was rejected without losing the local test file; a clean repeat sync succeeded at the same pin.
- GitHub PR CI passed unit tests, registry validation, PostgreSQL integration tests and the fixture demonstration.
- No upstream installer, security script, browser, password attack or research target was executed during import. Runtime adapter validation remains separate work.
