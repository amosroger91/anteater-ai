import { z } from 'zod';

export interface LLMRequest { system: string; input: string }
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

export class OllamaProvider implements LLMProvider {
  constructor(private baseUrl: string, private model: string, private modelDigest?: string) {
    const u = new URL(baseUrl);
    if (u.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(u.hostname) || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw new Error('local_model_endpoint_required');
    if (!model.trim() || /\s/.test(model)) throw new Error('invalid_model_ref');
    if (!modelDigest || !/^sha256:[a-f0-9]{64}$/i.test(modelDigest)) throw new Error('model_digest_required');
  }

  async generate(request: LLMRequest): Promise<LLMResponse> {
    if (request.system.length + request.input.length > 12000) throw new Error('context_budget_exceeded');
    const response = await fetch(new URL('/api/chat', this.baseUrl), {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(60000), headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: this.model,
        stream: false,
        think: false,
        format: AnalysisJsonSchema,
        options: SAMPLING_OPTIONS,
        messages: [{ role: 'system', content: request.system }, { role: 'user', content: request.input }],
      }),
    });
    if (!response.ok) throw new Error('model_unavailable');
    const body = z.object({
      model: z.string().optional(),
      message: z.object({ content: z.string().max(100000), thinking: z.string().optional() }).strict(),
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
      modelDigest: this.modelDigest,
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
