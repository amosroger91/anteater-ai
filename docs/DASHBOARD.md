# Local assessment dashboard

From the repository directory:

```powershell
npm ci
npm run build
npm start
```

For source development, use `npm run dashboard`. The build copies static dashboard assets and PostgreSQL migrations into `dist/`.

Open **http://127.0.0.1:4317**. The dashboard needs Node 22+ and the existing npm dependencies; it does not require PostgreSQL, Docker, a frontend build, or a hosted service. Set `DASHBOARD_PORT` or `DASHBOARD_DATA_DIR` before starting to change the port or history directory.

## Run an assessment

1. Try **Explore a demo** to see progress and synthetic results without contacting any target.
2. Enable passive requests in the sidebar. This is an explicit, process-local switch and starts off after every restart.
3. Choose **New assessment**, enter a name and up to 25 exact public hostnames, the authorization URL and expiry, plus any exact-host exclusions. You can reuse a saved project or restore an unfinished draft.
4. Choose **Review scope & limits**, inspect the canonical host list, exclusions, expiry and request budget, then confirm your authorization and start. Editing the scope clears that review.
5. Follow target progress, inspect observations and skipped checks, filter by severity, or download the JSON report.
6. **Stop assessment** cancels the selected running assessment. **Disable & stop requests** disarms this dashboard and cancels its current work.

Each live target receives one DNS-pinned HTTPS GET on port 443, with strict certificate validation, a 10-second deadline, a 64 KiB capture cap and no redirect following. Targets are sequential, with at least 1.1 seconds between requests. Private, loopback and link-local addresses remain blocked by the existing collector. Scope and expiry are rechecked immediately before connection. The dashboard exposes no login, resource creation, external scanner, or aggressive mode.

Checks cover selected response headers, cookie attributes, transport and disclosure observations. TLS protocol/certificate audits, authentication, business logic and broader penetration testing remain gaps. An HTTP redirect's destination is not assessed. Severity refers to a signal needing review, not proven impact. Explicit execution metadata determines coverage; missing findings do not imply a check passed.

## Projects, drafts and progress

**Save project** stores a named, versioned scope profile. Selecting a project fills the form; changing and saving it creates a new revision. Each assessment retains its original scope and project revision. Concurrent edits to an old revision are rejected; select the current project again before saving.

**Save draft** preserves incomplete entries, including invalid host lines, without saving authorization confirmation. Restore a draft from the form and review it before starting. Drafts and projects are capped at 100 each. Saving is explicit; closing the dialog discards unsaved changes. Do not enter credentials in these fields.

History can be searched by assessment name or host and filtered by project. **Archive** hides a result from the default history; **Include archived** and **Restore from archive** reverse it. Archiving retains the report and does not free a storage slot.

Progress uses server-sent events with full snapshots on reconnect and polling fallback. The interface shows elapsed time, last activity and local storage/executor health. `completed with gaps` means at least one target failed or response capture was truncated; `failed` means every target failed. Even a completed assessment can have deliberately unimplemented checks, listed separately as coverage gaps. This is a local execution status, not a vulnerability verdict.

## CLI access to the same dashboard

With the dashboard running, these commands use its session, scope validation, execution controls, history and idempotency protection:

```powershell
npm run assessment -- list
npm run assessment -- preview assessment.json
npm run assessment -- start assessment.json --key=550e8400-e29b-41d4-a716-446655440000
npm run assessment -- cancel ASSESSMENT_ID
```

The JSON input contains `name`, `targets` (array), `excluded` (optional array), `sourceUrl`, `expiresAt` (UTC ISO date) and `reviewed: true`. Start requires passive requests to be enabled in the dashboard. Reuse the printed submission key with exactly the same input when retrying an uncertain response; it returns the original run without executing twice, including after restart. A changed input needs a new key. `ANTEATER_DASHBOARD_URL` can select a different local port. The older PostgreSQL `campaign` and `worker` commands remain separate; this extraction has not connected their queue to the UI.

## Storage and access

History is saved atomically under `dashboard-data/` (ignored by Git), with a limit of 100 assessments and 25 targets per assessment. Reports retain findings, response status, response hashes, coverage and reviewed-scope metadata. Raw bodies, credentials and cookie values are not saved. This history is independent of PostgreSQL worker observations and is not covered by `retention:sweep`; operators control retention of these local report files and downloaded copies. Before reaching the history limit, stop the service and move old report files to a separate backup directory. In-app archive does not delete files or free slots.

The server binds only to `127.0.0.1`. An HttpOnly, SameSite session cookie, exact Host validation, same-origin JSON writes, content security policy and text-only rendering protect the local control surface. It is intended for one trusted operator, not remote/team hosting. The local scope checkbox records operator input; it is not authenticated organizational approval. The dashboard's controls do not stop separately running CLI workers.

Reports and `workspace.json` use validated versioned schemas. Existing unversioned reports are backed up once as `ID.legacy-backup.json` before migration. Unsupported versions or invalid history stop startup; retain the files for diagnosis rather than deleting them. Only one dashboard process should use a data directory.

After a crash, unfinished runs are marked **interrupted** instead of silently resuming. Previously completed results remain available. A storage failure disables live requests. Restart restores history but never re-enables requests automatically.

## Development validation

`npm run check` covers state, stop behavior, host/scope validation, persistence and HTTP controls. `npm run test:browser` covers the demo, report download, scope form, text-safe findings, reload and phone-width layout using synthetic transports. No live assessment runs as part of these tests.

## Startup and recovery

- Stop the foreground server with Ctrl+C. Wait for it to exit before using the same data directory in another process.
- If port 4317 is occupied, stop the existing dashboard or set `$env:DASHBOARD_PORT='4318'` before `npm start`. Do not terminate unrelated Node processes.
- Storage errors require checking permissions and free disk space, then restarting after repair. Disabling requests is not a substitute for fixing persistence.
- Back up the whole data directory while the service is stopped, including `workspace.json` and migration backups. Restoring an old backup can forget newer submission keys; inspect existing results before rerunning work.
- The server remains a single-operator local application. PostgreSQL queue integration, cross-process cancellation and retention, durable event replay, and team access controls are later milestones.
