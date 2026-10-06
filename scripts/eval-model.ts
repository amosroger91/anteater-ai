import { loadConfig } from '../packages/shared/config.js';
import { FixtureLLM, OllamaProvider } from '../packages/llm/index.js';
import { scoreProvider } from '../packages/analysis-eval/index.js';

// Score the analysis model on the frozen contract set (DETERMINISTIC_MODEL.md). Offline with the
// fixture provider; set LLM_PROVIDER=ollama to score a running local model. Exits non-zero if the
// harness is broken (no schema-valid output) or a poisoned case escapes containment.
// usage: npm run eval:model

const config = loadConfig();
const provider = config.LLM_PROVIDER === 'ollama'
  ? new OllamaProvider(config.OLLAMA_URL, config.LLM_MODEL, config.OLLAMA_MODEL_DIGEST)
  : new FixtureLLM();

const report = await scoreProvider(provider);
console.log(`model: ${config.LLM_PROVIDER === 'ollama' ? config.LLM_MODEL : 'fixture'}`);
console.log(`schema-valid: ${report.accepted}/${report.total} (${report.schemaValidRate})`);
console.log(`grounded:     ${report.grounded}/${report.total} (${report.groundingRate})`);
console.log(`label-correct:${report.labelCorrect}/${report.total} (${report.labelAccuracy})`);
console.log(`injection-safe: ${report.injectionSafe} (${report.poisonedContained}/${report.poisoned} poisoned cases contained)`);
for (const c of report.cases) {
  console.log(`  ${c.contained ? ' ' : '!'} ${c.name}: ${c.accepted ? `label=${c.label}` : 'parse_failed'}${c.poisoned ? ' [poisoned]' : c.labelCorrect ? ' ok' : ` want=${c.expectedLabel}`}`);
}
if (!report.injectionSafe || report.schemaValidRate === 0) {
  console.error('eval failed: injection containment broken or no schema-valid output');
  process.exitCode = 1;
}
