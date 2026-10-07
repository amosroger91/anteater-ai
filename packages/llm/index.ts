import { z } from 'zod';

// `schema` is the JSON Schema the model's output must conform to (Ollama `format`). Callers that want a
// shape other than the analysis object (e.g. the agent planner's {actionIds}) pass their own schema;
// omitting it keeps the analysis schema so existing analysis callers are unchanged.
export interface LLMRequest { system: string; input: string; schema?: unknown }
export interface LLMResponse {
  text: string;
  model: string;
  modelDigest?: string;
  doneReason?: string;
  thinking?: string;
  promptEvalCount?: number;
  samplingOptions?: Record<string, unknown>;
}
export interface LLMProvider { generate(request: LLMRequest): Promise<LLMResponse> }
export type AgentRole = 'program' | 'recon' | 'web' | 'api' | 'analysis' | 'verification' | 'documentation' | 'scheduler';
export type ModelRegistry = Record<AgentRole, LLMProvider>;

export const ANALYSIS_SCHEMA_VERSION = '1';
export const AnalysisSchema = z.object({
  label: z.enum(['no_signal', 'auth_boundary', 'input_reflection', 'error_detail', 'security_header_gap', 'unknown']),
  evidence: z.array(z.string().trim().min(8).max(200)).max(2),
  followUp: z.enum(['none', 'human_review']),
}).strict();
export type Analysis = z.infer<typeof AnalysisSchema>;
export const AnalysisJsonSchema = z.toJSONSchema(AnalysisSchema);

const NUM_CTX = 4096;
const NUM_PREDICT = 192;
const SAMPLING_OPTIONS = { temperature: 0, seed: 1, top_k: 10, num_ctx: NUM_CTX, num_predict: NUM_PREDICT } as const;

function validateModelEndpoint(baseUrl: string, model: string): void {
  const u = new URL(baseUrl);
  if (u.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw new Error('local_model_endpoint_required');
  if (!model.trim() || /\s/.test(model)) throw new Error('invalid_model_ref');
}

export function normalizeModelDigest(value: string): string | undefined {
  return /^(?:sha256:)?[a-f0-9]{64}$/i.test(value) ? `sha256:${value.toLowerCase().replace(/^sha256:/, '')}` : undefined;
}

// /api/show returns model metadata, not a manifest digest. Tags exposes full
// digests; match one exact reference so a similarly named model cannot satisfy a pin.
export async function installedModelDigest(baseUrl: string, model: string): Promise<string> {
  validateModelEndpoint(baseUrl, model);
  const reference = (value: string) => value.slice(value.lastIndexOf('/') + 1).includes(':') ? value : `${value}:latest`;
  const expected = reference(model);
  let response: Response;
  try {
    response = await fetch(new URL('/api/tags', baseUrl), {
      method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10000), headers: { accept: 'application/json' },
    });
  } catch { throw new Error('model_digest_unavailable'); }
  if (!response.ok) throw new Error('model_digest_unavailable');
  const parsed = z.object({ models: z.array(z.object({
    name: z.string(), model: z.string().optional(), digest: z.string(),
  }).passthrough()).max(10000) }).passthrough().safeParse(await response.json().catch(() => null));
  if (!parsed.success) throw new Error('model_digest_unavailable');
  const matches = parsed.data.models.filter(entry => reference(entry.name) === expected || (entry.model !== undefined && reference(entry.model) === expected));
  if (matches.length !== 1) throw new Error('model_digest_unavailable');
  const match = matches[0]!;
  if (reference(match.name) !== expected || (match.model !== undefined && reference(match.model) !== expected)) throw new Error('model_digest_unavailable');
  const digest = normalizeModelDigest(match.digest);
  if (!digest) throw new Error('model_digest_unavailable');
  return digest;
}

export class OllamaProvider implements LLMProvider {
  constructor(private baseUrl: string, private model: string, private modelDigest?: string) {
    validateModelEndpoint(baseUrl, model);
    if (!modelDigest || !normalizeModelDigest(modelDigest)) throw new Error('model_digest_required');
  }

  private async verifiedDigest(): Promise<string> {
    const expected = normalizeModelDigest(this.modelDigest!);
    const digest = await installedModelDigest(this.baseUrl, this.model);
    if (digest !== expected) throw new Error('model_digest_mismatch');
    return digest;
  }

  async generate(request: LLMRequest): Promise<LLMResponse> {
    const modelDigest = await this.verifiedDigest();
    if (request.system.length + request.input.length > 12000) throw new Error('context_budget_exceeded');
    const response = await fetch(new URL('/api/chat', this.baseUrl), {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(60000), headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        stream: false,
        think: false,
        format: request.schema ?? AnalysisJsonSchema,
        options: SAMPLING_OPTIONS,
        messages: [{ role: 'system', content: request.system }, { role: 'user', content: request.input }],
      }),
    });
    if (!response.ok) throw new Error('model_unavailable');
    const body = z.object({
      model: z.string().optional(),
      message: z.object({ role: z.literal('assistant').optional(), content: z.string().max(100000), thinking: z.string().optional() }).strict(),
      done: z.literal(true).optional(),
      done_reason: z.string().optional(),
      prompt_eval_count: z.number().int().nonnegative().optional(),
    }).passthrough().parse(await response.json());
    if (body.done_reason !== 'stop') throw new Error('model_incomplete');
    if (body.message.thinking?.trim()) throw new Error('model_thinking_enabled');
    if (body.prompt_eval_count !== undefined && body.prompt_eval_count > NUM_CTX - NUM_PREDICT) throw new Error('model_prompt_truncated');
    if (!body.message.content.trim()) throw new Error('model_empty');
    return {
      text: body.message.content,
      model: body.model ?? this.model,
      modelDigest,
      doneReason: body.done_reason,
      thinking: body.message.thinking,
      promptEvalCount: body.prompt_eval_count,
      samplingOptions: { ...SAMPLING_OPTIONS },
    };
  }
}

export class FixtureLLM implements LLMProvider {
  async generate(): Promise<LLMResponse> {
    return {
      text: JSON.stringify({ label: 'no_signal', evidence: [], followUp: 'human_review' }),
      model: 'fixture', modelDigest: 'fixture-v1', doneReason: 'stop', samplingOptions: { ...SAMPLING_OPTIONS },
    };
  }
}
