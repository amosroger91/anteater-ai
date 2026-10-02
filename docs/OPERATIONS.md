# Development and deployment

## PostgreSQL

`docker compose up -d --wait postgres` exposes PostgreSQL only on loopback port 55432. The named volume survives container restarts. `npm run db:migrate` applies the initial schema transactionally and can be repeated. Future schema changes must introduce versioned migrations rather than editing a deployed schema in place. Integration tests create and remove a randomly named schema and do not truncate existing research tables.

`npm run verify:local` is a Docker-independent verification path using temporary native PostgreSQL. It is a development aid, not a service or deployment architecture. The runner binds loopback, uses a random password, stops its server in `finally`, and leaves ordinary generated Markdown available for inspection.

## Kali and MCP

`docker compose --profile kali-boundary run --rm kali-boundary` builds a minimal Kali image that prints a disabled-boundary message and exits. It has no network, host mounts, Docker socket or security tools; it runs without capabilities as an unprivileged user with read-only root filesystem and resource limits. The rolling base is acceptable for this inert prototype; pin a reviewed image digest before a release.

`packages/mcp` is the future MCP integration boundary, not an MCP server/client implementation. Before wiring any transport, authenticate the caller, resolve identifiers server-side, independently enforce policy at the gateway and executor, pin DNS and egress, disallow redirects by default, bound output and execution time, and use typed allowlisted arguments. Agents must never receive generic command execution.

## Models

Install Ollama using its official installer, then run `npm run models:inspect`. NVIDIA detection uses only `nvidia-smi`; AMD/Intel systems report unavailable detection and can use CPU fallback. Run `ollama pull qwen3:4b` explicitly if desired. Configure `LLM_MODEL` and loopback `OLLAMA_URL`, then instantiate `OllamaProvider` with them when building a worker. The demo deliberately uses `FixtureLLM`, so no downloaded model is needed. `ModelRegistry` supports a separate provider per role; runtime registry loading and health monitoring remain future work.

## Production posture

This milestone is not ready for autonomous deployment against live programs. Keep the kill switch on. Before production, use dedicated database credentials and network restrictions, TLS for remote database connections, versioned migrations, tested backups/restores, an authenticated operator interface, process supervision, a persistent scheduler and exporter, telemetry, host resource budgets and all items in READINESS.md. The local Compose password is a disposable development value only. No production rollout is provided or implied.

The current command handles normal completion and errors by closing its database pool. Forced termination leaves a lease that another worker can reclaim; graceful signal-driven worker shutdown is part of the next operations milestone.
