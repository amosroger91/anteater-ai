# Reference review — 2026-10-02

## Kali MCP reference

Reviewed [cyberillo/kali-mcp-server](https://github.com/cyberillo/kali-mcp-server), its [Python source](https://github.com/cyberillo/kali-mcp-server/blob/main/kali-mcp-server.py), and GitHub repository metadata. It is not archived; the API reports the last push as 2026-03-18. That indicates a small existing project, not a maintenance guarantee.

The Python FastMCP server exposes reconnaissance, scanning, fuzzing, credential cracking and exploitation tools. It calls subprocess argument arrays with timeouts, but permits free-form tool flags and builds Metasploit command strings. No deterministic per-program authorization layer was visible in the reviewed source. Its Dockerfile demonstrates container packaging; tool decorators make extension possible. Safe restriction would require removing tools/arguments and adding independent scope and egress controls. Decision: use the boundary concept only; do not depend on or execute this server. Containerization alone is insufficient authorization.

## Durable workflows

[Temporal documentation](https://docs.temporal.io/) describes durable application execution. It is a credible future orchestration option. The architectural choice for the current single-step fixture is PostgreSQL leases, with Temporal reconsidered for multi-step durable workflows.

## Bounty discovery

[HackerOne API documentation](https://api.hackerone.com/) separates hacker and program-owner API surfaces. API availability does not imply anonymous access to every public program or permission to test it. Before implementing a live provider, verify access requirements, terms, pagination, rate limits, policy completeness and deletion/revocation behavior. The reliable initial source is a checked-in synthetic provider; live-source selection and ingestion remain milestone 2. No platform was scraped.

## Local model starting point

[Ollama qwen3:4b](https://ollama.com/library/qwen3:4b) lists Q4_K_M weights at approximately 2.5 GB. This is a conservative candidate for an 8 GB GPU, leaving room for context and runtime overhead. It is not a benchmark claim or a claim of being the newest/best model. Start with 4096 context tokens and measure local memory/latency. General-purpose models are sufficient for the initial summarization experiment; cybersecurity model comparison needs a task-specific evaluation set.
