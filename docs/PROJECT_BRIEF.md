You are building a new open-source codebase for an autonomous, continuously running bug-bounty research platform.

The goal is to create a system that can discover publicly available bug-bounty programs, identify programs whose published scope permits web-application/security testing, maintain persistent research state for each program, and use isolated Kali Linux security tooling plus local LLM agents to perform authorized security research.

This is an authorized bug-bounty research system. **Scope and program policy are hard security boundaries. The system must never intentionally test assets outside a program's published scope or perform prohibited actions.**

Do not build a generic internet-wide vulnerability scanner.

---

# 1. Core objective

Build a long-running system capable of:

1. Discovering public bug-bounty programs.
2. Importing their published program rules and scopes.
3. Determining which programs have applicable web/application/API targets.
4. Creating a standardized persistent workspace for every program.
5. Enumerating authorized assets.
6. Performing passive reconnaissance and permitted security testing.
7. Maintaining a continuously updated record of discoveries.
8. Using LLM agents to reason about observations and determine useful next research steps.
9. Running security tools through an isolated Kali Linux environment.
10. Continuously scheduling work while respecting:

    * program scope
    * program exclusions
    * rate limits
    * testing restrictions
    * duplicate work
    * resource limits
11. Recording evidence and confidence for candidate findings.
12. Requiring human review before a vulnerability is submitted to a bounty program.

The system should be designed to eventually operate continuously, potentially 24/7, but must fail closed whenever scope or authorization cannot be established.

---

# 2. High-level architecture

Use a modular architecture similar to:

```
                Bug Bounty Sources
                       |
                       v
              Program Discovery
                       |
                       v
                Scope Compiler
                       |
                       v
             Program/Asset Database
                       |
                       v
                Research Scheduler
                       |
         +-------------+-------------+
         |             |             |
         v             v             v
     Research      Research      Research
      Worker        Worker        Worker
         |             |             |
         +-------------+-------------+
                       |
                       v
              Kali Security Sandbox
                       |
                       v
                MCP Tool Gateway
                       |
                       v
                   LLM Agent
                       |
                       v
              Findings / Evidence
                       |
                       v
                Human Review Queue
```

Use durable state. Do not make the entire system depend on a single LLM conversation.

---

# 3. Recommended technology

Prefer:

* TypeScript/Node.js for the orchestration application.
* PostgreSQL for structured persistent state.
* Redis where useful for queues/locks/caching.
* Docker for isolation.
* Kali Linux Docker containers for security tooling.
* MCP for exposing carefully selected security tools to agents.
* A workflow/job framework suitable for long-running workflows. Evaluate Temporal first, but don't blindly introduce it if a simpler architecture is more appropriate for the MVP.
* Local LLM inference through a provider abstraction such as Ollama, llama.cpp, or another suitable local inference runtime.
* GitHub for source control.
* Markdown files as a human-readable research record in addition to the database.

The architecture must not depend on a proprietary hosted LLM.

---

# 4. Kali + MCP architecture

Investigate using:

cyberillo/kali-mcp-server

as an inspiration/reference for exposing Kali tooling through MCP.

Do not blindly depend on it. Determine:

* whether it is maintained
* what tools it exposes
* how it handles command execution
* whether its security model is appropriate
* whether it can be safely containerized
* whether tools can be restricted
* whether it can be extended

The intended architecture is approximately:

Orchestrator
|
v
Agent
|
v
MCP client
|
v
Kali MCP server
|
v
Kali Docker container
|
v
Approved security tools

The agent must NOT receive unrestricted host shell access.

Tool execution must happen inside disposable/isolated environments.

---

# 5. Scope enforcement is mandatory

Implement a dedicated Scope Engine.

This is one of the most important components in the entire project.

The LLM must never be trusted to determine whether a target is authorized.

The Scope Engine should consume program policy and produce machine-readable rules such as:

```json
{
  "program": "example",
  "allowed": [
    "*.example.com",
    "api.example.com"
  ],
  "excluded": [
    "payments.example.com"
  ],
  "allowedTesting": [
    "web",
    "api"
  ],
  "disallowedTesting": [
    "dos",
    "social-engineering"
  ],
  "rateLimits": {
    "requestsPerSecond": 1
  }
}
```

The actual schema should be more robust than this example.

Every tool invocation should pass through this enforcement layer.

If the scope engine cannot determine whether an action is authorized:

STOP.

Do not guess.

---

# 6. Bug bounty program discovery

Build a provider abstraction for public bounty platforms.

Initially research available public sources/platforms and implement the cleanest reliable source first.

The system should identify:

* program name
* platform
* program URL
* policy URL
* scope
* exclusions
* bounty information where publicly available
* testing restrictions
* asset types
* whether web/API testing appears applicable
* last policy update if available

Do not scrape aggressively.

Respect platform terms, robots policies where applicable, rate limits, and APIs when available.

The discovery subsystem should produce normalized Program objects.

---

# 7. Program classification

Create a classifier that determines whether a program is relevant to this project.

For example:

```text
WEB_APPLICATION
API
MOBILE
DESKTOP
HARDWARE
NETWORK
SOURCE_CODE
OTHER
```

A program can have multiple categories.

The first version should prioritize:

* web applications
* APIs
* web infrastructure where explicitly authorized

Do not automatically assume that a hostname means it is authorized.

---

# 8. Persistent per-program Markdown workspace

This is a core feature.

Every program should receive a standardized directory such as:

```text
programs/
  example-company/
    PROGRAM.md
    SCOPE.md
    ASSETS.md
    RECON.md
    FINDINGS.md
    NOTES.md
    HISTORY.md
```

The exact structure can evolve.

Each file should have a clearly defined schema.

For example:

PROGRAM.md:

```markdown
# Example Company

## Program

- Platform:
- Program URL:
- Policy URL:
- Last synchronized:
- Status:

## Applicable Research

- Web:
- API:
- Other:

## Restrictions

- ...

## Research Status

- Last run:
- Current phase:
- Open investigations:
```

FINDINGS.md should distinguish:

```text
OBSERVATION
HYPOTHESIS
CANDIDATE
VERIFIED
REJECTED
SUBMITTED
```

Never represent an unverified observation as a confirmed vulnerability.

---

# 9. Database + Markdown

Use PostgreSQL for machine state.

Use Markdown for human-readable persistent research state.

The two must remain synchronized.

Database:

```text
programs
assets
scope_rules
research_jobs
observations
hypotheses
findings
evidence
tool_runs
agent_runs
```

Markdown:

```text
programs/<program>/*
```

The Markdown workspace should be useful even if the database is unavailable.

---

# 10. Research agent architecture

Do NOT create one giant autonomous agent.

Create specialized agents.

Suggested initial agents:

### Program Agent

Understands program policy and normalizes it.

### Recon Agent

Organizes authorized attack surface.

### Web Research Agent

Analyzes authorized web applications.

### API Research Agent

Analyzes authorized APIs.

### Analysis Agent

Looks for relationships between observations.

### Verification Agent

Reviews candidate findings and determines whether additional authorized evidence is needed.

### Documentation Agent

Maintains the Markdown research state.

### Scheduler Agent

Determines what research task should happen next.

Agents should communicate through structured state, not enormous prompt histories.

---

# 11. LLM abstraction

Implement a common model interface:

```typescript
interface LLMProvider {
  generate(request: LLMRequest): Promise<LLMResponse>;
}
```

Support local models.

The system should be capable of running models on approximately 8 GB VRAM GPUs.

Do not hardcode one model.

Create a model registry/configuration system.

For example:

```yaml
models:
  reasoning:
    provider: ollama
    model: <configured-model>

  classification:
    provider: ollama
    model: <configured-model>

  cybersecurity:
    provider: ollama
    model: <configured-model>
```

Research current suitable open-weight models during implementation.

Prefer models that fit comfortably within approximately 8 GB VRAM after quantization.

Use specialized cybersecurity models where they provide meaningful benefit, but allow general-purpose models for:

* summarization
* classification
* document processing
* planning
* Markdown maintenance
* general reasoning

Do not assume that a cybersecurity-specific model is automatically superior.

---

# 12. Agent/tool boundary

The LLM should not directly execute arbitrary commands.

Instead expose structured tools such as:

```text
enumerate_authorized_assets()
inspect_http_target()
retrieve_page()
analyze_javascript()
inspect_api_definition()
run_authorized_security_check()
record_observation()
create_hypothesis()
request_verification()
update_research_state()
```

Every security-related tool must independently validate scope.

The tool should receive a target identifier rather than trusting arbitrary text generated by the model.

---

# 13. Research loop

Implement a durable research loop.

Conceptually:

```text
while system_is_running:

    discover_programs()

    synchronize_program_policies()

    synchronize_scopes()

    prioritize_authorized_programs()

    for each program:

        select_next_research_task()

        verify_scope()

        execute_task()

        collect_observations()

        update_program_state()

        evaluate_candidates()

        schedule_followup_work()

        persist_everything()
```

Do NOT implement this as an infinite recursive LLM conversation.

It should be a durable job system.

Each iteration should have a bounded task.

Example:

```text
JOB #18291

Program: example-company
Asset: api.example.com
Task: inspect API surface

STATUS:
queued
running
completed

RESULT:
17 observations
2 hypotheses
0 verified findings

NEXT:
inspect endpoint relationships
```

---

# 14. 24/7 operation

The system should be designed to run indefinitely.

Requirements:

* graceful restart
* persistent state
* resumable jobs
* crash recovery
* worker health monitoring
* timeouts
* retry policies
* concurrency limits
* per-program rate limits
* global resource limits
* model health monitoring
* Kali container lifecycle management
* no duplicate jobs
* job leases/locks
* structured logging

A machine reboot should not destroy research state.

---

# 15. Research prioritization

Create a scoring mechanism for deciding which authorized task to run next.

This is an internal research-priority score, NOT a score for companies or bounty programs.

Potential factors:

```text
new asset discovered
new endpoint discovered
interesting technology discovered
previous hypothesis unresolved
new application version detected
recently changed asset
historically interesting observation
time since last assessment
```

Avoid repeatedly doing identical work.

---

# 16. Findings lifecycle

Every finding should follow:

```text
OBSERVATION
    ↓
HYPOTHESIS
    ↓
CANDIDATE
    ↓
VERIFICATION
    ↓
VERIFIED
    ↓
HUMAN REVIEW
    ↓
SUBMITTED
```

Rejected findings should also be preserved so the system learns not to repeatedly investigate the same false positive.

Example:

```markdown
# Finding F-0042

## Status

CANDIDATE

## Asset

api.example.com

## Observation

...

## Hypothesis

...

## Evidence

...

## Verification Attempts

...

## Why This May Matter

...

## Confidence

...

## Next Action

Human review
```

Do not allow the system to automatically submit reports initially.

---

# 17. Safety controls

Implement explicit safety controls before autonomous operation.

At minimum:

```text
GLOBAL_KILL_SWITCH=true

REQUIRE_SCOPE=true

REQUIRE_PROGRAM_POLICY=true

MAX_CONCURRENT_JOBS=...

MAX_REQUEST_RATE=...

ALLOW_ACTIVE_TESTING=false
```

Active testing should require an explicit configuration enabling it for authorized programs.

Anything involving:

* denial of service
* destructive actions
* credential attacks
* social engineering
* persistence
* malware
* destructive exploitation

must not be part of the autonomous MVP.

The MVP should concentrate on non-destructive web/API security research and evidence gathering within explicitly authorized scope.

---

# 18. Observability

Build first-class observability.

Every operation should produce structured events:

```text
PROGRAM_DISCOVERED
POLICY_UPDATED
SCOPE_UPDATED
ASSET_DISCOVERED
JOB_CREATED
JOB_STARTED
TOOL_EXECUTED
OBSERVATION_CREATED
HYPOTHESIS_CREATED
FINDING_CREATED
FINDING_REJECTED
FINDING_VERIFIED
JOB_FAILED
```

Include:

* timestamp
* program
* asset
* job ID
* agent
* model
* tool
* duration
* result
* error

Make it possible to understand exactly what the autonomous system did.

---

# 19. GitHub repository

Create the project as a clean Git repository.

Suggested structure:

```text
/
├── apps/
│   ├── orchestrator/
│   ├── scheduler/
│   └── dashboard/
│
├── packages/
│   ├── scope-engine/
│   ├── bounty-providers/
│   ├── agent-runtime/
│   ├── llm/
│   ├── mcp/
│   ├── research-state/
│   └── shared/
│
├── agents/
│   ├── program/
│   ├── recon/
│   ├── web/
│   ├── api/
│   ├── analysis/
│   ├── verification/
│   └── documentation/
│
├── infrastructure/
│   ├── docker/
│   ├── postgres/
│   └── kali/
│
├── programs/
│   └── .gitkeep
│
├── docs/
├── scripts/
├── docker-compose.yml
├── .env.example
├── package.json
└── README.md
```

Use sensible naming if the implementation suggests a better structure.

Do not commit secrets.

Provide:

* Docker Compose
* development setup
* production setup
* model installation instructions
* Kali setup
* database setup
* MCP setup
* configuration documentation

---

# 20. Model installation

Create an installation/setup process that detects available GPU resources.

Target approximately:

```text
8 GB VRAM
```

Provide sensible quantized-model defaults.

The installation process should tell the operator:

```text
GPU detected:
VRAM:
Recommended model:
Estimated memory:
```

Do not assume every machine has the same GPU.

Allow CPU fallback for non-security tasks.

---

# 21. MVP milestones

Do not attempt to implement everything simultaneously.

Build in stages.

### Milestone 1

Working project skeleton.

* TypeScript
* PostgreSQL
* configuration
* logging
* program state
* Markdown workspace

### Milestone 2

Program discovery.

* one bounty source
* policy ingestion
* scope normalization
* web/API classification

### Milestone 3

Kali integration.

* Dockerized Kali
* MCP integration
* isolated tool execution
* scope enforcement

### Milestone 4

LLM integration.

* local inference
* model registry
* tool calling
* structured agent state

### Milestone 5

Research loop.

* scheduler
* durable jobs
* recon
* web research
* persistent discoveries

### Milestone 6

Finding pipeline.

* observations
* hypotheses
* candidates
* verification
* evidence
* human review

### Milestone 7

24/7 operation.

* retries
* crash recovery
* health checks
* concurrency controls
* rate limiting
* dashboards/metrics

### Milestone 8

Multi-program operation.

Only after the previous stages work correctly.

---

# 22. Testing

Write tests for the most dangerous components first.

Especially:

```text
scope matching
wildcard handling
excluded assets
subdomain handling
redirect handling
URL normalization
program policy parsing
rate limiting
job locking
worker recovery
MCP authorization
tool isolation
```

Create fake bug-bounty programs for testing.

The test suite must demonstrate that:

```text
authorized target → allowed

excluded target → blocked

unknown target → blocked

malformed scope → blocked

scope unavailable → blocked

tool attempts unauthorized target → blocked
```

---

# 23. Development philosophy

Do not build a flashy demo.

Build infrastructure that can actually run continuously.

Prioritize:

1. Correctness
2. Scope safety
3. Persistent state
4. Reproducibility
5. Observability
6. Tool reliability
7. Model reliability
8. Performance

The LLM is a component of the system, not the system itself.

Use deterministic software wherever deterministic software is better.

---

# 24. First task

Start by examining the repository/environment.

Then:

1. Propose the architecture in `docs/ARCHITECTURE.md`.
2. Create the repository structure.
3. Implement the configuration system.
4. Implement the database schema.
5. Implement the program Markdown workspace.
6. Implement the Scope Engine and tests.
7. Implement the basic durable job abstraction.
8. Implement the LLM provider abstraction.
9. Implement the Kali/MCP integration boundary without granting unrestricted execution.
10. Create Docker Compose for the development environment.
11. Create a fake bug-bounty program fixture.
12. Demonstrate an end-to-end run against ONLY the fake fixture.

Do not jump directly into mass target discovery.

Do not begin autonomous operation against real programs until the scope engine, authorization checks, logging, rate limiting, and kill switch have been tested.

After the MVP works against the fixture, document exactly what remains before enabling real authorized bug-bounty programs.

Finally, initialize Git, create a clean initial commit, and prepare the repository to be pushed to GitHub. Do not expose or commit credentials or tokens.
