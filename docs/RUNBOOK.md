# Runbook — running Anteater autonomously

Two targets: **your own infrastructure** (full auto, no approval) and **HackerOne programs you've
enrolled in** (auto after you list the handles). You submit accepted findings yourself; everything
before that is automated and can run for long periods.

## 0. One-time setup

```bash
npm ci
npm run build
docker compose up -d        # or point DATABASE_URL at your Postgres
npm run db:migrate
```

Environment (a `.env` or your shell):

```
GLOBAL_KILL_SWITCH=false          # master stop; true = nothing runs
ENABLE_PASSIVE_HTTP=true          # allow real read-only HTTPS testing
ENABLE_APPLICATION_RESEARCH=true  # allow authenticated crawl + IDOR (needs account creds)
DATABASE_URL=postgresql://...
```

## 1. HackerOne programs you've enrolled in

You choose which programs to engage by **enrolling in them on hackerone.com** (that is the legal
"I accept your terms" act — the system never discovers or engages programs on its own). Then:

```
# programs/handles.txt — one handle per line, the programs you joined
example-program
another-program
```

Credentials (HackerOne hacker API): `HACKERONE_API_USERNAME`, `HACKERONE_API_TOKEN`.

```bash
npm run preflight       # read-only: kill switch off, passive HTTP on, database migrated,
                        # HackerOne credentials present, handles file non-empty, rates sane
npm run intake:h1       # pulls each program's published scope, skips any that forbid automation,
                        # saves the in-scope assets, and queues passive jobs
```

`npm run preflight` does not call HackerOne and does not scan. Fix every `fail` line before intake.
Programs whose policy prohibits automated scanning are reported as `skipped … prohibited` and never
tested. Scope comes straight from the H1 API, with its hash recorded as provenance; a changed scope is
re-reviewed automatically on the next intake.

Optional discovery binaries are absolute paths. An unset or relative path does not run. `PASSIVE_DNS_BIN`
and `CT_BIN` are invoked as `<bin> -d <apex>` and must print one hostname per line, or a JSON
`{"host":"..."}` line. Names outside that apex are dropped. Certificate transparency uses `https://crt.sh`
only when `CT_BIN` is unset.

```
SUBFINDER_BIN=/absolute/path/to/subfinder
PASSIVE_DNS_BIN=/absolute/path/to/passive-dns
CT_BIN=/absolute/path/to/ct-list
MONITOR_INTERVAL_MS=60000
```

## 2. Your own infrastructure (full auto, no approval)

Save your owned hosts in the setup profile's lab list and enable private-lab targets, then the setup
scanner (`npm run setup`, open http://127.0.0.1:...) or the worker tests them directly. See
`infrastructure/lab/README.md` for the hostname + internal-CA TLS steps and the Proxmox snapshot
prep before any aggressive run.

## 3. First real run

Run these in order. Nothing in this sequence submits a report for you.

```bash
npm run preflight
npm run intake:h1
npm run worker
npm run triage
npm run finding:submit -- --id=<finding-uuid> --reviewer="your name"
```

`npm run worker` claims jobs, tests in scope, verifies by replay, and records findings. It loops until
stopped. It honors the kill switch and per-program rate budgets, recovers leases after a crash, and
dead-letters non-retryable failures. Re-run `npm run intake:h1` whenever you join new programs.

Leave `npm run monitor` running beside the worker. Each cycle enumerates subdomains of every enrolled
wildcard (`*.example.com` is queried at the apex, not at hosts you already know). It records
`first_seen` and `last_seen`, and it queues a passive job only for a name that is new since the last
cycle and allowed by the current reviewed policy. A concrete-only program is not a discovery root.
`npm run monitor -- --once` runs a single cycle. The default interval is 60 seconds.

`npm run triage` prints the ranked queue (`payout tier × confidence`), dedupe status, and an evidence
hash. Each queue row is followed by the `finding:submit` command for that id. Info-severity rows are
not leads. Rows that match a prior submission or a known issue are listed as `suppressed` and are not
given a submit command.

```bash
npm run triage -- --known-issue --program=<program-id> --type=<finding-type> --location=<url>
```

## 4. Review and submit (your step)

The worker writes each program's state to its Markdown workspace (`FINDINGS.md`). A report draft exists
only for `VERIFIED` and `HUMAN_REVIEW`. A finding reaches `VERIFIED` only through deterministic replay.
`SUBMITTED` happens only when you run `finding:submit`. That command also writes the submissions row
that keeps the same program, type, and location out of the next queue.

```bash
npm run finding:submit -- --id=<finding-uuid> --reviewer="your name"
npm run ledger -- --infra=0
npm run ledger -- --record --finding=<finding-uuid> --status=paid --amount=500 --currency=USD
```

`npm run ledger` prints `net = paid − infra` from the submissions table. Recording a later outcome does
not submit anything. Sending the report to the program is still your action, under your identity.

## What stops the engine from doing something unauthorized

- Scope engine fails closed: HTTPS/443, read-only actions, only policy-allowed hosts/paths.
- Programs that forbid automation are skipped at intake.
- No program discovery — only handles you listed (programs you joined).
- Private IPs are blocked except for your explicitly-listed owned lab hosts.
- `VERIFIED` requires deterministic replay; `SUBMITTED` requires you.
- `GLOBAL_KILL_SWITCH=true` or `runtime_control.global_kill` stops everything, including in-flight work.

## Model (optional)

The local model only classifies observations for triage. Score a candidate model before trusting it:

```bash
npm run eval:model                      # fixture provider (offline)
LLM_PROVIDER=ollama LLM_MODEL=... npm run eval:model   # a running local model
```
