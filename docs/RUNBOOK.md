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
npm run intake:h1       # pulls each program's published scope, skips any that forbid automation,
                        # saves the in-scope assets, and queues passive jobs
```

Programs whose policy prohibits automated scanning are reported as `skipped … prohibited` and never
tested. Scope comes straight from the H1 API, with its hash recorded as provenance; a changed scope is
re-reviewed automatically on the next intake.

## 2. Your own infrastructure (full auto, no approval)

Save your owned hosts in the setup profile's lab list and enable private-lab targets, then the setup
scanner (`npm run setup`, open http://127.0.0.1:...) or the worker tests them directly. See
`infrastructure/lab/README.md` for the hostname + internal-CA TLS steps and the Proxmox snapshot
prep before any aggressive run.

## 3. Run the engine (continuously)

```bash
npm run worker          # claims jobs, tests in scope, verifies, records findings; loops until stopped
```

It honors the kill switch and per-program rate budgets, recovers leases after a crash, and dead-letters
non-retryable failures. Leave it running. Re-run `npm run intake:h1` whenever you join new programs.

## 4. Review and submit (your step)

The worker writes each program's state to its Markdown workspace (`FINDINGS.md`) and keeps candidates in
the database. A finding reaches `VERIFIED` only through deterministic replay; it never auto-submits.

```bash
npm run finding:submit -- --id=<finding-uuid> --reviewer="your name"
```

That is the one manual step, by design: submitting to a third party is done under your identity, so you
confirm the report and send it. Everything up to it is automated.

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
