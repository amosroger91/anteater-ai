import { z } from 'zod';
export interface LLMRequest { system: string; input: string }
export interface LLMResponse { text: string; model: string }
export interface LLMProvider { generate(request: LLMRequest): Promise<LLMResponse> }
export type AgentRole = 'program' | 'recon' | 'web' | 'api' | 'analysis' | 'verification' | 'documentation' | 'scheduler';
export type ModelRegistry = Record<AgentRole, LLMProvider>;
export class OllamaProvider implements LLMProvider {
  constructor(private baseUrl: string, private model: string) {
    const u = new URL(baseUrl);
    if (u.protocol !== 'http:' || !['localhost','127.0.0.1','[::1]'].includes(u.hostname) || u.username || u.password || u.pathname !== '/' || u.search || u.hash) throw new Error('local_model_endpoint_required');
  }
  async generate(request: LLMRequest): Promise<LLMResponse> {
    if (request.system.length + request.input.length > 16000) throw new Error('context_budget_exceeded');
    const response = await fetch(new URL('/api/chat',this.baseUrl), {
      method:'POST', redirect:'error', signal:AbortSignal.timeout(60000), headers:{'content-type':'application/json'},
      body:JSON.stringify({model:this.model,stream:false,options:{num_ctx:4096,num_predict:512},messages:[{role:'system',content:request.system},{role:'user',content:request.input}]}),
    });
    if (!response.ok) throw new Error('model_unavailable');
    const body = z.object({message:z.object({content:z.string().max(100000)})}).parse(await response.json());
    return {text:body.message.content,model:this.model};
  }
}
export class FixtureLLM implements LLMProvider {
  async generate(): Promise<LLMResponse> { return { text:'Synthetic observation only. No vulnerability verified; human review required.', model:'fixture' }; }
}
