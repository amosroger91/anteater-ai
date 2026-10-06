import { z } from 'zod';
import { readIntakeText, type FetchLike } from './hackerone.js';

export interface DirectoryCompany { handle: string; name: string; submissionState: string; url: string }
const entry = z.object({ type: z.literal('program'), attributes: z.object({
  handle: z.string().max(80).regex(/^[a-z0-9]+(?:[-_][a-z0-9]+)*$/),
  name: z.string().min(1).max(200), submission_state: z.string().max(40),
}) });
const pageSchema = z.object({ data: z.array(entry).max(100), links: z.object({ next: z.string().nullable().optional() }).optional() });
const endpoint = 'https://api.hackerone.com/v1/hackers/programs';

// Lists account-visible programs, not customer contracts or proof of enrollment.
// All pages must succeed before a selectable snapshot is returned.
export async function listHackerOneCompanies(authorization: string, signal: AbortSignal,
  fetchLike: FetchLike = fetch as FetchLike, progress: (count: number) => void = () => {}): Promise<DirectoryCompany[]> {
  if (!/^Basic [A-Za-z0-9+/]+=*$/.test(authorization)) throw new Error('hackerone_credentials_required');
  const companies = new Map<string, DirectoryCompany>();
  const seen = new Set<string>();
  let next: string | null = endpoint + '?page%5Bsize%5D=100';
  let bytes = 0;
  for (let page = 0; next && page < 100; page++) {
    signal.throwIfAborted();
    const url: URL = new URL(next, endpoint);
    if (url.origin !== 'https://api.hackerone.com' || url.pathname !== '/v1/hackers/programs' || url.username || url.password || url.hash ||
      [...url.searchParams.keys()].some(key => !['page[number]', 'page[size]'].includes(key))) throw new Error('program_host_refused');
    if (seen.has(url.href)) throw new Error('program_directory_incomplete');
    seen.add(url.href);
    const response = await fetchLike(url.href, { method: 'GET', redirect: 'error',
      signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]), headers: { accept: 'application/json', authorization } });
    if (!response.ok) throw new Error(`program_http_${response.status}`);
    const text = await readIntakeText(response, 4_194_304);
    signal.throwIfAborted();
    bytes += Buffer.byteLength(text);
    if (Buffer.byteLength(text) > 4_194_304 || bytes > 33_554_432) throw new Error('program_directory_too_large');
    let raw: unknown;
    try { raw = JSON.parse(text); } catch { throw new Error('program_response_invalid'); }
    const parsed = pageSchema.safeParse(raw);
    if (!parsed.success) throw new Error('program_response_invalid');
    for (const row of parsed.data.data) {
      const a = row.attributes;
      companies.set(a.handle, { handle: a.handle, name: a.name, submissionState: a.submission_state, url: `https://hackerone.com/${a.handle}` });
    }
    progress(companies.size);
    next = parsed.data.links?.next || null;
  }
  if (next) throw new Error('program_directory_incomplete');
  return [...companies.values()].sort((a, b) => a.name.localeCompare(b.name));
}
