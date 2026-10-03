# Local assessment dashboard

From the repository directory:

```powershell
npm ci
npm run dashboard
```

Open **http://127.0.0.1:4317**. The dashboard needs Node 22+ and the existing npm dependencies; it does not require PostgreSQL, Docker, a frontend build, or a hosted service. Set `DASHBOARD_PORT` or `DASHBOARD_DATA_DIR` before starting to change the port or history directory.

## Run an assessment

1. Try **Explore a demo** to see progress and synthetic results without contacting any target.
2. Enable passive requests in the sidebar. This is an explicit, process-local switch and starts off after every restart.
3. Choose **New assessment**, enter a name and up to 25 exact public hostnames, the authorization URL and expiry, and confirm your scope review.
4. Follow target progress, inspect observations and skipped checks, filter by severity, or download the JSON report.
5. **Stop assessment** cancels the selected running assessment. **Disable & stop requests** disarms this dashboard and cancels its current work.

Each live target receives one DNS-pinned HTTPS GET on port 443, with strict certificate validation, a 10-second deadline, a 64 KiB capture cap and no redirect following. Targets are sequential, with at least 1.1 seconds between requests. Private, loopback and link-local addresses remain blocked by the existing collector. Scope and expiry are rechecked immediately before connection. The dashboard exposes no login, resource creation, external scanner, or aggressive mode.

Checks cover selected response headers, cookie attributes, transport and disclosure observations. TLS protocol/certificate audits, authentication, business logic and broader penetration testing remain gaps. An HTTP redirect's destination is not assessed. Severity refers to a signal needing review, not proven impact. Explicit execution metadata determines coverage; missing findings do not imply a check passed.

## Storage and access

History is saved atomically under `dashboard-data/` (ignored by Git), with a limit of 100 assessments and 25 targets per assessment. Reports retain findings, response status, response hashes, coverage and reviewed-scope metadata. Raw bodies, credentials and cookie values are not saved. This history is independent of PostgreSQL worker observations and is not covered by `retention:sweep`; operators control retention of these local report files and downloaded copies. Archive old JSON reports outside the data directory before reaching the history limit.

The server binds only to `127.0.0.1`. An HttpOnly, SameSite session cookie, exact Host validation, same-origin JSON writes, content security policy and text-only rendering protect the local control surface. It is intended for one trusted operator, not remote/team hosting. The local scope checkbox records operator input; it is not authenticated organizational approval. The dashboard's controls do not stop separately running CLI workers.

After a crash, unfinished runs are marked **interrupted** instead of silently resuming. Previously completed results remain available. A storage failure disables live requests. Restart restores history but never re-enables requests automatically.

## Development validation

`npm run check` covers state, stop behavior, host/scope validation, persistence and HTTP controls. `npm run test:browser` covers the demo, report download, scope form, text-safe findings, reload and phone-width layout using synthetic transports. No live assessment runs as part of these tests.
