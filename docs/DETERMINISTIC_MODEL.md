# Deterministic model contract

## Implemented behavior

Authorization, action selection and follow-up scheduling live in code. Models classify bounded observations; they cannot call tools, expand scope, change policy, verify a finding or submit a report. The worker defaults to the fixture provider/model. Reviewed file manifests and a separately enabled passive HTTPS executor are available. `LLM_PROVIDER=ollama` selects the local model adapter.

## Input and output

`boundedObservation` projects tool output into valid JSON containing status, content type, selected headers, deterministic signals, a short body snippet, body length/hash and capture truncation. Header ordering is stable. Input is at most 3,500 characters; optional fields are removed when necessary instead of cutting JSON mid-string. Prior raw model output and arbitrary extra fields are excluded. Website text remains untrusted, including instructions embedded in snippets.

`AnalysisSchema` in `packages/llm` is the single output contract; `z.toJSONSchema` derives the request grammar from it:

- `label`: `no_signal`, `auth_boundary`, `input_reflection`, `error_detail`, `security_header_gap` or `unknown`.
- `evidence`: up to two exact substrings of the observation input, each 8–200 characters.
- `followUp`: `none` or `human_review`.

The local provider uses `think: false`, `stream: false`, temperature 0, seed 1, top_k 10, num_ctx 4096 and num_predict 192. It requires a configured `sha256:` model digest, allows only loopback HTTP, refuses redirects and bounds each request to 60 seconds. It accepts the assistant-role response envelope, requires `done_reason=stop`, rejects thinking traces and checks reported prompt usage against the context budget. Zod validates the returned object independently of the grammar.

The configured digest is recorded provenance, **not proof that the mutable Ollama tag currently contains those weights**. Registry-based digest verification remains open. Fixed sampling also does not guarantee identical results across hardware, drivers or model/runtime versions.

## Grounding and repair

Evidence must occur verbatim in the exact JSON feature string supplied to the model. One repair attempt receives the original features and a fixed error code, never the previous reply. Repair metadata cannot count as evidence: grounding always compares against the original features. Accepted runs hash the actual prompt used; failed repairs retain the repair input for the same provenance calculation.

Grounding proves only that the quoted text was observed. It does not prove exploitability, severity or authorization. Empty evidence is permitted for a classification; there is no `verified` label.

## Durable separation

1. The gateway returns a tool observation.
2. `Jobs.complete` atomically writes job completion, observation, tool run, capture hash metadata, deterministic observation-level findings, audit event, authorized follow-up jobs and export intent.
3. The model analyzes the projected features after that transaction commits.
4. Accepted analysis and its raw reply, model metadata, sampling options, prompt hash and schema version are written to `agent_runs`; the validated object is linked to the observation in `hypotheses`.
5. Parse failures are recorded separately. They never cause a completed HTTP request to run again.

`RECON.md` contains tool data. `HYPOTHESES.md` exposes accepted model suggestions for operator triage; `followUp=human_review` is currently a triage hint, with no automated promotion service. `FINDINGS.md` contains deterministic posture signals in `OBSERVATION` state. `AUDIT.md` projects execution events. Raw model text never becomes a tool observation or another prompt.

Database checks require `verified_by` for `VERIFIED` and `human_reviewer` for `SUBMITTED`. Authenticated identities and a finding-transition service are still required; a non-null text column alone does not establish who reviewed a finding.

## Deterministic follow-ups

Only a successful 2xx root observation can propose fixed follow-ups. HTML/text can propose `/robots.txt` and `/sitemap.xml`; JSON or OpenAPI/Swagger hints can propose `/.well-known/openapi.json`. Both action and exact path must be in the current reviewed policy. The planner never follows arbitrary links or model suggestions. Keys include program, asset, target, action and policy revision; the original fixture key is retained for upgrade-safe replay.

## Validation and remaining work

Tests cover request options, role envelopes, incomplete/thinking responses, fabricated evidence, one bounded repair, repair-metadata rejection, valid JSON under oversized input, persistence separation, atomic follow-ups and fixture replay. No real model inference or research-target traffic was used for this validation.

Remaining work includes an adversarial evaluation corpus with acceptance metrics, real hardware/model benchmarks, digest verification against installed weights, recovery of model analysis after a crash between observation completion and analysis persistence, model concurrency budgets across workers, authenticated human review and least-privilege database roles. These are explicit limits of the current implementation.
