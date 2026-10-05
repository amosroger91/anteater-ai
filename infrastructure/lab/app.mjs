import http from 'node:http';

// Minimal seeded lab app for Phase-0 proof. VARIANT=vulnerable|patched selects behavior.
// Deliberately insecure in the vulnerable variant; NEVER expose this to the internet.
// Two seeded users; the IDOR is "a session for user 1 can read user 2's record".
const VARIANT = process.env.VARIANT === 'patched' ? 'patched' : 'vulnerable';
const PORT = Number(process.env.PORT || 3000);
const USERS = {
  '1': { id: '1', email: 'alice@lab.test', secret: 'alice-secret-token' },
  '2': { id: '2', email: 'bob@lab.test', secret: 'bob-secret-token' },
};
const SECURE_HEADERS = {
  'strict-transport-security': 'max-age=63072000',
  'content-security-policy': "default-src 'self'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
};
const sessionUser = req => (req.headers['x-user'] === '2' ? '2' : req.headers['x-user'] === '1' ? '1' : null);

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://lab');
  const send = (status, body, headers = {}) => {
    const base = VARIANT === 'patched' ? { ...SECURE_HEADERS } : {};
    res.writeHead(status, { 'content-type': 'application/json', ...base, ...headers });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  };

  // Seeded: exposed VCS directory.
  if (url.pathname === '/.git/config') {
    if (VARIANT === 'vulnerable') return send(200, '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@lab.test:app.git\n', { 'content-type': 'text/plain' });
    return send(404, { error: 'not_found' });
  }

  // Identity marker (for session validation).
  if (url.pathname === '/me') {
    const u = sessionUser(req);
    return u ? send(200, { account: `user-${u}`, email: USERS[u].email }) : send(401, { error: 'unauthenticated' });
  }

  // Seeded: IDOR / broken object-level authorization.
  const userMatch = /^\/api\/users\/(\d+)$/.exec(url.pathname);
  if (userMatch) {
    const requested = userMatch[1];
    const caller = sessionUser(req);
    if (!caller) return send(401, { error: 'unauthenticated' });
    if (VARIANT === 'patched' && caller !== requested) return send(403, { error: 'forbidden' });
    const record = USERS[requested];
    return record ? send(200, record) : send(404, { error: 'not_found' });
  }

  // Seeded: CORS reflecting any origin with credentials.
  if (url.pathname === '/api/data') {
    const origin = req.headers.origin;
    if (VARIANT === 'vulnerable' && origin) return send(200, { data: 'ok' }, { 'access-control-allow-origin': origin, 'access-control-allow-credentials': 'true' });
    return send(200, { data: 'ok' }, { 'access-control-allow-origin': 'https://lab-patched.anteater.test' });
  }

  // Seeded: open redirect.
  if (url.pathname === '/redirect') {
    const to = url.searchParams.get('to') || '/';
    if (VARIANT === 'vulnerable') return send(302, '', { location: to });
    return send(302, '', { location: to.startsWith('/') ? to : '/' });
  }

  return send(200, { service: 'anteater-lab', variant: VARIANT });
});
server.listen(PORT, () => console.log(`lab ${VARIANT} on :${PORT}`));
