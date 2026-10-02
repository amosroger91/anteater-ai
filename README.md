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

## Bounty review inbox

Public bug-bounty platforms do not offer an anonymous API that returns domains together with the rules for testing them. The free source is the public scope dump at `arkadiyt/bounty-targets-data` (HackerOne, Bugcrowd, Intigriti, YesWeHack, and Federacy). A listed host is not permission to scan it. The inbox stores one named program at a time, with exclusions beside the in-scope assets, and the posture scanner cannot read that file.

```text
bounty:fetch one handle -> bounty-inbox.json
        |                     (JSON, no url column)
        v
bounty:review one exact host
        |
        v
bounty:promote -> targets.csv as passive only
        |
        v
posture:scan
```

| Command | What it does |
| --- | --- |
| `npm run bounty:fetch -- hackerone <handle>` | Store one program from the public dump. Also accepts `bugcrowd`, `intigriti`, `yeswehack`, and `federacy`. The inbox holds at most 25 programs. |
| `npm run bounty:list` | Show each asset as excluded, held, unreviewed, or reviewed. Wildcards and path-scoped URLs stay held. |
| `npm run bounty:review -- hackerone <handle> api.example.com` | Mark one exact in-scope host. Add `--revoke` to clear it. Exclusions, wildcards, and path-only URLs are rejected. |
| `npm run bounty:promote` | Append reviewed hosts to `targets.csv` as `passive` rows. Existing rows are left alone. |
| `npm run bounty:refresh` | Update programs already in the inbox. A host that leaves scope loses its review. The rest of the dump is ignored, and `targets.csv` is not edited. |

`npm run posture:scan -- targets.csv --policy=reviewed-policy.json` reads `url,mode,notes` only after the reviewed scope policy authorizes each row. Each row is one URL. A bare hostname is checked as `https://that-host/` only. Passive mode is one pinned GET after one TLS handshake, with at most three same-host, same-port redirects. Loopback and link-local addresses are refused. Private addresses need `--allow-private`. Aggressive rows additionally require `--confirm-aggressive`, a loopback egress proxy, and pinned Nuclei configuration. See [operating instructions](docs/OPERATIONS.md).

Schedule `bounty:refresh` only after the handles you care about are already in the inbox. Do not point that job at `posture:scan`.

## Web dependency library

The [dependency catalog](dependencies/README.md) contains **29 commit-pinned upstream repositories**: OWASP guidance, ZAP, Nuclei, HTTP discovery tools, API testing, Playwright, Lighthouse, static analysis, web wordlists, and password-strength libraries. Daily Dependabot checks propose parent-repository updates as reviewable PRs.

Run `npm run deps:sync` to fetch curated source/data checkouts, or `npm run deps:sync -- seclists zxcvbn-ts` to fetch selected dependencies. Sources live under `vendor/`; they are not automatically installed or executed. Common-password lists support offline web password-policy testing. Live network adapters remain disabled pending the readiness checklist.

| Focus | Included upstream repositories |
| --- | --- |
| Secure web development | [OWASP WSTG](https://github.com/OWASP/wstg), [ASVS](https://github.com/OWASP/ASVS), [Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries) |
| Browser behavior, accessibility and performance | [Playwright](https://github.com/microsoft/playwright), [Lighthouse](https://github.com/GoogleChrome/lighthouse) |
| API contracts and testing | [Schemathesis](https://github.com/schemathesis/schemathesis), [Spectral](https://github.com/stoplightio/spectral) |
| Web application assessment | [ZAP](https://github.com/zaproxy/zaproxy), [Nuclei](https://github.com/projectdiscovery/nuclei), [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates), [Nikto](https://github.com/sullo/nikto) |
| HTTP metadata, crawling and candidate hosts | [httpx](https://github.com/projectdiscovery/httpx), [Katana](https://github.com/projectdiscovery/katana), [Subfinder](https://github.com/projectdiscovery/subfinder) |
| Web paths and parameters | [ffuf](https://github.com/ffuf/ffuf), [Gobuster](https://github.com/OJ/gobuster), [dirsearch](https://github.com/maurosoria/dirsearch), [Arjun](https://github.com/s0md3v/Arjun) |
| HTTPS/TLS configuration | [testssl.sh](https://github.com/testssl/testssl.sh), [SSL Labs client](https://github.com/ssllabs/ssllabs-scan) |
| Owned source, secrets and dependencies | [Retire.js](https://github.com/RetireJS/retire.js), [Semgrep](https://github.com/semgrep/semgrep), [Gitleaks](https://github.com/gitleaks/gitleaks), [Trivy](https://github.com/aquasecurity/trivy) |
| Web wordlists | [SecLists](https://github.com/danielmiessler/SecLists), [Assetnote wordlists](https://github.com/assetnote/wordlists), [fuzzdb](https://github.com/fuzzdb-project/fuzzdb) |
| Offline password policy and strength | SecLists common-password dictionaries, [zxcvbn](https://github.com/dropbox/zxcvbn), [zxcvbn-ts](https://github.com/zxcvbn-ts/zxcvbn) |

SecLists is one repository used in two categories. Its selected password files are `10k-most-common.txt` and `xato-net-10-million-passwords-10000.txt`; its selected web data includes common paths and the small RAFT lists. These support owned web-form policy tests. Credential-pair dumps and online password-guessing workflows are not integrated.

### How updates work

- Each `vendor/*` Git submodule is pinned to an exact commit; `.gitmodules` identifies its upstream branch.
- Dependabot checks upstream repositories daily at **08:00 America/Chicago**, and npm/GitHub Actions weekly. Updates arrive as PRs, with no automatic merge or replacement of running tools.
- After reviewing and merging an update, fetch the reviewed pins locally:

  ```sh
  git -c fetch.recurseSubmodules=false pull --ff-only
  npm ci
  npm run deps:check
  npm run deps:sync
  ```

- `deps:sync` checks origins and selected paths, preserves dirty checkouts by refusing to overwrite them, and fetches curated source without running upstream installers or recursively importing their submodules.

Use a normal clone followed by `deps:sync`; recursive submodule cloning can download much larger trees, including material outside the curated selection. Sparse sources are inspection and adapter-development inputs, and may not contain everything needed to build an upstream tool. Upstream licenses remain applicable; repositories marked `REVIEW_REQUIRED` need their code/data terms reviewed before packaging. A commit pin establishes content identity, not permission to execute it.

## Current implementation and next steps

| Available now | Still to implement |
| --- | --- |
| Strict configuration, scope matching, exclusions and default kill switch | Full policy ingestion, approval provenance, DNS/IP and redirect enforcement |
| PostgreSQL jobs, leases, fencing, deduplication and rate reservations | Continuous scheduler, lease renewal, cancellation and operational monitoring |
| Durable tool-only observations, versioned migrations, replayable Markdown exports and analysis provenance | Complete verification and finding transition services |
| Schema-constrained Ollama provider, grounded evidence checks and deterministic fixture model | Live model worker, evaluation corpus and health monitoring |
| 29 pinned source/data dependencies and update PRs | Reviewed runtime adapters, authenticated MCP and enforced sandbox egress |

The checked-in Kali container is an inert, network-disabled boundary demonstration. It is not a ready-to-run scanner image. `ALLOW_ACTIVE_TESTING=true` does not enable a live executor. Findings submission remains a human-reviewed future stage.

The dependency milestone passed the TypeScript build, **39 unit tests**, **9 reported PostgreSQL integration tests**, and fixture replay checks. All 29 curated source checkouts and their selected paths were verified. See [validation details](docs/VALIDATION.md), [operating instructions](docs/OPERATIONS.md), and the [live-research readiness checklist](docs/READINESS.md). Local container execution remained unverified because Docker Desktop failed to start; native PostgreSQL provided the local integration-test path.

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
| OLLAMA_MODEL_DIGEST | Production model worker | Immutable `sha256:` digest recorded from `ollama show` |

## Usage

| Command | Purpose |
| --- | --- |
| `npm run check` | Compile TypeScript and run unit tests |
| `npm run test:integration` | Test a running PostgreSQL in an isolated schema |
| `npm run verify:local` | Temporary native PostgreSQL, integration tests, fixture replay |
| `npm run db:migrate` | Apply ordered, idempotent schema migrations |
| `npm run demo` | One bounded fixture iteration; explicit kill-switch override required |
| `npm run worker -- --once` | Process one policy-bound queued fixture job with lease heartbeats |
| `npm run models:inspect` | Detect NVIDIA VRAM and display conservative setup guidance |
| `npm run deps:list` | List web dependencies and committed revisions |
| `npm run deps:check` | Verify catalog, origins, branches and gitlinks |
| `npm run deps:sync` | Fetch pinned source and selected data without executing it |
| `npm run bounty:fetch -- <platform> <handle>` | Store one public program in `bounty-inbox.json` |
| `npm run bounty:review -- <platform> <handle> <asset>` | Mark one exact host reviewed |
| `npm run bounty:promote` | Copy reviewed hosts into `targets.csv` as passive rows |
| `npm run bounty:refresh` | Refresh inbox programs already fetched; does not edit the scan CSV |
| `npm run bounty:list` | Show inbox assets and their review state |
| `npm run posture:scan -- <csv> --policy=<json>` | Policy-bound posture scan; one URL per row |
| `npm run posture:check -- <url>` | Read-only check of one host, outside the CSV |

The worker provides a continuously running fixture loop with graceful signal handling. Live target executors and authenticated HTTP/MCP control remain disabled until the readiness checklist is complete.

## Project structure

```text
apps/orchestrator/       bounded fixture demonstration
packages/scope-engine/  conservative deterministic authorization
packages/research-state/ PostgreSQL jobs, leases, rate limits, Markdown outbox
packages/bounty-providers/ discovery interface and fixture provider
scripts/bounty-inbox.ts  one-program review queue; does not feed the scanner directly
scripts/posture-scan.ts  CSV posture runner for operator-listed URLs
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
