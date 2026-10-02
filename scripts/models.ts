import { execFileSync } from 'node:child_process';
try {
  const output=execFileSync('nvidia-smi',['--query-gpu=name,memory.total','--format=csv,noheader,nounits'],{encoding:'utf8',timeout:5000});
  console.log('GPU detected (name, VRAM MiB):\n'+output.trim());
} catch { console.log('GPU detection unavailable (NVIDIA utility missing or unsupported GPU). CPU fallback available.'); }
console.log('Conservative starting model: qwen3:4b (Q4_K_M, approximately 2.5 GB weights).');
console.log('Allow additional memory for runtime and context; benchmark at 4096 context tokens.');
console.log('Install explicitly: ollama pull qwen3:4b. No model is downloaded automatically.');
