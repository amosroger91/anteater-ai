# Development and deployment

## PostgreSQL

`docker compose up -d --wait postgres` exposes PostgreSQL only on loopback port 55432. The named volume survives container restarts. `npm run db:migrate` applies ordered migrations transactionally and can be repeated. Never edit an applied migration; add the next numbered file. Integration tests create and remove a randomly named schema and do not truncate existing research tables.

`npm run verify:local` is a Docker-independent verification path using temporary native PostgreSQL. It is a development aid, not a service or deployment architecture. The runner binds loopback, uses a random password, stops its server in `finally`, and leaves ordinary generated Markdown available for inspection.

## Kali and MCP

`docker compose --profile kali-boundary run --rm kali-boundary` builds a minimal Kali image that prints a disabled-boundary message and exits. It has no network, host mounts, Docker socket or security tools; it runs without capabilities as an unprivileged user with read-only root filesystem and resource limits. The rolling base is acceptable for this inert prototype; pin a reviewed image digest before a release.

`packages/mcp` is the future MCP integration boundary, not an MCP server/client implementation. Before wiring any transport, authenticate the caller, resolve identifiers server-side, independently enforce policy at the gateway and executor, pin DNS and egress, disallow redirects by default, bound output and execution time, and use typed allowlisted arguments. Agents must never receive generic command execution.

## Models

Install Ollama through a verified package-manager installation, then run `npm run models:inspect`. NVIDIA detection uses only `nvidia-smi`; AMD/Intel systems report unavailable detection and can use CPU fallback. Pull a model explicitly, record its `sha256` in `models.lock.json`, and set `OLLAMA_MODEL_DIGEST` before constructing `OllamaProvider`. The provider rejects unpinned model configuration, enforces the JSON schema, disables thinking, and fails closed on truncation. The demo deliberately uses `FixtureLLM`, so no downloaded model is needed.

## Posture CSV

`npm run posture:scan -- targets.csv --policy=reviewed-policy.json` reads `url,mode,notes`. The reviewed policy is required for every row and is checked with the same scope engine as queued jobs. A bare hostname is requested as `https://that-host/` and the runner does not add subdomains, ports, or paths. Passive mode is one pinned GET after one TLS handshake, following at most three same-host, same-port redirects. It records the note on the result. Loopback and link-local addresses are refused. Private addresses need `--allow-private`.

`latest.json` stores executed targets only. A held aggressive row is written to the timestamped scan file and does not replace the previous baseline. Diffs report new codes, resolved codes, and a severity or detail change on an existing code.

Aggressive mode also runs local `nuclei` only with `--confirm-aggressive --egress-proxy=http://127.0.0.1:8080`, `NUCLEI_BIN` set to an absolute executable, `NUCLEI_TEMPLATES` set to an absolute local template directory, and `NUCLEI_TEMPLATE_DIGEST` set to the reviewed template commit. The fixed tags are `ssl,misconfig,exposure,tech`; intrusive tags can never be enabled and Nuclei redirects are disabled. Nuclei is not started if the pinned passive check cannot reach the target. Results are retained for 30 days by default and written with restrictive file permissions.

## Bounty review inbox

Public platform APIs do not hand out an anonymous, complete scope list. `npm run bounty:fetch -- <platform> <handle>` reads one named program from the public `arkadiyt/bounty-targets-data` dump (HackerOne, Bugcrowd, Intigriti, YesWeHack, or Federacy) and stores it in `bounty-inbox.json`. In-scope assets and exclusions stay side by side. Wildcards are not expanded. The inbox is JSON, and `posture:scan` rejects it because that file has no `url` column.

`npm run bounty:review -- <platform> <handle> <asset>` marks one exact promotable host. Out-of-scope assets, wildcards, and path-scoped URLs cannot be marked. `npm run bounty:promote` appends only reviewed hosts to `targets.csv` as `passive` rows and leaves existing rows alone. `npm run bounty:refresh` updates programs already in the inbox and does not add the rest of a dump or edit the scan CSV. A scheduled run belongs on `bounty:refresh` only, for handles an operator has already fetched. The inbox holds at most 25 programs.

## Production posture

This milestone is not ready for autonomous deployment against live programs. Keep the kill switch on. Before production, use dedicated database credentials and network restrictions, TLS for remote database connections, versioned migrations, tested backups/restores, an authenticated operator interface, process supervision, a persistent scheduler and exporter, telemetry, host resource budgets and all items in READINESS.md. The local Compose password is a disposable development value only. No production rollout is provided or implied.

The bounded demo and continuous worker close their database pools on normal completion and errors. The worker handles SIGINT/SIGTERM by stopping new claims; a forced termination leaves a lease that another worker can reclaim, and the heartbeat extends leases during long tool calls.

## Reviewed program worker

Copy `fixtures/programs.example.json` to an operator-controlled `reviewed-programs.json`. The example uses reserved `.test` names; replace them only with the actual reviewed program, source policy, expiry, scope, asset IDs and grants. The JSON is either an array of programs or an object with a `programs` array, limited to 1 MiB and 100 programs. Asset identifiers are globally unique. Each asset is a canonical HTTPS origin on port 443; paths belong in `allowedPaths`.

| Action | Fixed request path |
| --- | --- |
| `inspect_http_target` | `/` |
| `inspect_robots` | `/robots.txt` |
| `inspect_sitemap` | `/sitemap.xml` |
| `inspect_openapi` | `/.well-known/openapi.json` |

Both the action and its exact path must be granted. Existing policies without `allowedPaths` default to `/` only. Do not grant a discovery path unless the program permits it. The worker never follows paths listed inside robots/sitemap/OpenAPI responses.

For an authorized development environment, set these process variables before running the worker:

```powershell
$env:PROGRAM_SOURCE = 'file'
$env:PROGRAMS_FILE = 'reviewed-programs.json'
$env:ENABLE_PASSIVE_HTTP = 'true'
$env:GLOBAL_KILL_SWITCH = 'false'
$env:MAX_CONCURRENT_JOBS = '4'
$env:MAX_REQUEST_RATE = '1'
npm run worker
```

Rate remains bounded by both global configuration and program policy, regardless of concurrency. `--once` processes one batch and exports pending work; it does not promise to drain all follow-ups. Continuous mode drains allowed follow-ups and retries. SIGINT/SIGTERM abort collection and stop new claims; an already-running local model call can finish within its request deadline. Keep concurrency configuration uniform across workers.

Manifests are loaded at startup. Restart after a reviewed change and increment the policy revision; completed work is deduplicated within that revision. There is no timer-based rescan or hot reload. Process environment switches cannot provide immediate fleet-wide revocation. Database policy/lease checks run at invocation, again after DNS resolution, and at completion; an in-flight external request cannot be undone.

The collector sends one GET without credentials/cookies, pins the checked address, verifies TLS, follows no redirects and bounds headers, bytes and wall time. Capture hashes cover the retained byte prefix, with truncation recorded. Body snippets are bounded but are not guaranteed free of sensitive content. Audit events are inserted by the application; they are not tamper-proof. Keep database/workspace access restricted and implement retention before production use.

`FINDINGS.md` contains observation-level posture signals. `HYPOTHESES.md` provides accepted model suggestions for human triage, and `AUDIT.md` records execution events. No state is automatically promoted to verified or submitted. The model defaults to the fixture; set `LLM_PROVIDER=ollama` and a configured model digest for real local classification. See the [model contract](DETERMINISTIC_MODEL.md) for digest and reproducibility limits.
