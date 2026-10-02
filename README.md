# anteater-ai

A web-development-focused, scope-first foundation for authorized web and API security research with local AI.

## Overview

Anteater stores program policy, assets, bounded research jobs and observations in PostgreSQL, then exports a readable per-program Markdown workspace. Deterministic authorization sits between agents and tools. This initial milestone runs **only a synthetic fixture**: it does not discover or test real targets, run security commands, or submit reports.

## Architecture

```text
Fixture provider -> validated policy + PostgreSQL -> leased job
                                                       |
                                      scope + kill switch + rate limits
                                                       |
                                    fixed synthetic tool -> observation
                                                       |
                                         fixture LLM -> Markdown export
```

See [architecture](docs/ARCHITECTURE.md), [research decisions](docs/RESEARCH.md), and [readiness checklist](docs/READINESS.md).

## Web dependency library

The [dependency catalog](dependencies/README.md) contains **29 commit-pinned upstream repositories**: OWASP guidance, ZAP, Nuclei, HTTP discovery tools, API testing, Playwright, Lighthouse, static analysis, web wordlists, and password-strength libraries. Daily Dependabot checks propose parent-repository updates as reviewable PRs.

Run `npm run deps:sync` to fetch curated source/data checkouts, or `npm run deps:sync -- seclists zxcvbn-ts` to fetch selected dependencies. Sources live under `vendor/`; they are not automatically installed or executed. Common-password lists support offline web password-policy testing. Live network adapters remain disabled pending the readiness checklist.

## Quick start

Requires Node.js 22+ and Docker Compose with a running Linux engine.

```sh
npm ci
docker compose up -d --wait postgres
npm run db:migrate
npm run check
npm run test:integration
```

Run the fixture with an explicit kill-switch override:

```powershell
$env:GLOBAL_KILL_SWITCH = 'false'
npm run demo
Remove-Item Env:GLOBAL_KILL_SWITCH
```

On Bash: `GLOBAL_KILL_SWITCH=false npm run demo`.
Output is in `programs/fixture-company/`. Repeating the demo does not duplicate completed work.
Without Docker, `npm run verify:local` starts temporary PostgreSQL, runs integration tests and the demo twice, and stops PostgreSQL. It downloads no models and performs no target requests. PostgreSQL binaries are installed as a development dependency.

## Configuration

`.env.example` documents defaults. The application reads **process environment variables**, not `.env` automatically. Export values in your shell or use Node's environment-file support when invoking a script. Never commit local credentials.

| Variable | Required | Default / purpose |
| --- | --- | --- |
| DATABASE_URL | Production | Local Compose database on port 55432 |
| GLOBAL_KILL_SWITCH | No | `true`; denies tool execution |
| REQUIRE_SCOPE | No | Must remain `true` |
| REQUIRE_PROGRAM_POLICY | No | Must remain `true` |
| ALLOW_ACTIVE_TESTING | No | `false`; setting true does not enable a live executor |
| MAX_CONCURRENT_JOBS | No | `1`; same setting required across all workers |
| MAX_REQUEST_RATE | No | `1`; global invocations/second, bounded to 10 |
| JOB_LEASE_SECONDS | No | `30`; bounded 5–300 |
| PROGRAMS_DIR | No | `programs`; trusted operator-owned export directory |
| OLLAMA_URL | No | `http://127.0.0.1:11434`; loopback only |
| LLM_MODEL | No | `qwen3:4b`; operator-selectable model |

## Usage

| Command | Purpose |
| --- | --- |
| `npm run check` | Compile TypeScript and run unit tests |
| `npm run test:integration` | Test a running PostgreSQL in an isolated schema |
| `npm run verify:local` | Temporary native PostgreSQL, integration tests, fixture replay |
| `npm run db:migrate` | Apply idempotent initial schema |
| `npm run demo` | One bounded fixture iteration; explicit kill-switch override required |
| `npm run models:inspect` | Detect NVIDIA VRAM and display conservative setup guidance |
| `npm run deps:list` | List web dependencies and committed revisions |
| `npm run deps:check` | Verify catalog, origins, branches and gitlinks |
| `npm run deps:sync` | Fetch pinned source and selected data without executing it |

There is no HTTP API or continuously running daemon yet.

## Project structure

```text
apps/orchestrator/       bounded fixture demonstration
packages/scope-engine/  conservative deterministic authorization
packages/research-state/ PostgreSQL jobs, leases, rate limits, Markdown outbox
packages/bounty-providers/ discovery interface and fixture provider
packages/llm/           local provider interface, Ollama adapter, fixture model
packages/agent-runtime/ structured observation analysis boundary
packages/mcp/           authorization gateway; no live MCP transport yet
packages/shared/        strict configuration and structured event logging
infrastructure/        PostgreSQL schema and disabled Kali container boundary
dependencies/          curated web dependency catalog and update policy
vendor/                pinned Git submodules, populated by deps:sync
fixtures/              synthetic .test program
tests/                 scope, configuration, models, persistence and recovery
programs/              generated research workspaces (ignored)
docs/                  architecture, operating instructions and remaining work
```

## Tech stack

- TypeScript, Node.js, Zod, node-postgres
- PostgreSQL 17 with leased jobs and transactional outbox
- Node test runner and tsx
- Docker Compose and a network-disabled Kali boundary
- Local Ollama provider abstraction; deterministic fixture model in the demo

## Notes and conventions

No secrets or research evidence in Git. No unrestricted shell or Docker socket access for agents. Markdown and model output are untrusted data and cannot grant authorization. Scope currently supports HTTPS origins on port 443 only; paths, queries, IPs, IDNs, redirects and ambiguous normalization are rejected. Wildcards exclude the apex and exclusions take precedence. Real execution stays disabled until the readiness checklist is complete.

Code is provided under the [MIT license](LICENSE).
