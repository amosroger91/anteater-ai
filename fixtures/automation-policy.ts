// Synthetic policy text for the automation classifier. These are not copied from a live program.

export const PERMITTED_POLICY = [
  'Automated tools are allowed.',
  'Keep a rate limit of 2 requests per second.',
].join('\n');

export const MANUAL_ONLY_POLICY = [
  'Thank you for testing.',
  'Please keep a reasonable rate limit.',
  'Unusual traffic may be blocked.',
].join('\n');

export const PROHIBITED_POLICY = [
  'Do not use scanners.',
  'No automated scanning is permitted.',
].join('\n');
