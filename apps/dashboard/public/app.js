const $ = id => document.getElementById(id);
let state = { enabled: false, active: null, assessments: [] };
let selectedId, selectedTarget, lastState = '', toastTimer;
const names = { 'transport.encryption':'HTTPS transport', 'tls.protocol':'TLS protocol audit', 'tls.certificate':'Certificate audit', 'headers.hsts':'Strict transport security', 'headers.csp':'Content security policy', 'headers.baseline':'Security headers', 'headers.disclosure':'Version disclosure', 'cookies.attributes':'Cookie attributes' };
const humanize = value => String(value).replaceAll('_', ' ');
const node = (tag, text, className) => { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; };
function badge(value) { return node('span', humanize(value), `badge ${value}`); }
function toast(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 5000); }
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) throw new Error(humanize(result.error || 'request failed'));
  return result;
}
const date = value => new Date(value).toLocaleString([], { month:'short', day:'numeric', hour:'numeric', minute:'2-digit' });
function current() { return state.assessments.find(run => run.id === selectedId); }
function render() {
  $('history-count').textContent = state.assessments.length;
  $('control-dot').classList.toggle('enabled', state.enabled);
  $('control-label').textContent = state.enabled ? 'Passive requests enabled' : 'Live requests off';
  $('toggle-live').textContent = state.enabled ? 'Disable & stop requests' : 'Enable passive requests';
  $('form-live-status').textContent = state.enabled ? 'Passive requests enabled' : 'Enable passive requests to start';
  $('submit-assessment').disabled = !state.enabled || Boolean(state.active);
  const history = $('history'); history.replaceChildren();
  const picker = $('history-picker'); picker.replaceChildren();
  if (!state.assessments.length) picker.append(node('option', 'No assessments yet'));
  if (!state.assessments.length) history.append(node('p', 'Your assessments will appear here.', 'history-empty'));
  for (const run of state.assessments) {
    const option = node('option', run.name); option.value = run.id; option.selected = selectedId === run.id; picker.append(option);
    const button = node('button', run.name, run.id === selectedId ? 'active' : '');
    button.append(node('small', `${run.demo ? 'DEMO · ' : ''}${humanize(run.status)} · ${run.targets.length} hosts`));
    button.addEventListener('click', () => { selectedId = run.id; selectedTarget = undefined; render(); }); history.append(button);
  }
  const run = current();
  $('empty-state').hidden = Boolean(run); $('assessment-view').hidden = !run;
  $('new-assessment').disabled = Boolean(state.active); $('new-side').disabled = Boolean(state.active); $('demo').disabled = Boolean(state.active);
  if (!run) { $('page-title').textContent = 'Know where you stand.'; return; }
  $('page-title').textContent = run.name;
  $('page-subtitle').textContent = 'Bounded checks. Clear evidence. A reviewable next step.';
  $('run-status').textContent = humanize(run.status); $('run-status').className = `badge ${run.status}`;
  $('run-meta').textContent = `Started ${date(run.createdAt)}`;
  $('demo-notice').hidden = !run.demo;
  $('download-report').href = `/api/assessments/${run.id}/report`;
  $('stop-assessment').hidden = state.active !== run.id;
  const processed = run.targets.filter(target => !['queued','running'].includes(target.status)).length;
  const findings = run.targets.flatMap(target => target.findings.map(finding => ({ ...finding, target:target.url })));
  const checks = run.targets.reduce((total, target) => total + (target.coverage?.executed ?? 0), 0);
  const gaps = run.targets.reduce((total, target) => total + (target.coverage?.gaps ?? 8), 0);
  const percent = Math.round(processed / run.targets.length * 100);
  $('metric-targets').textContent = `${processed} / ${run.targets.length}`;
  $('metric-findings').textContent = findings.length;
  $('metric-checks').textContent = checks;
  $('metric-gaps').textContent = gaps;
  const failed = run.targets.filter(target => target.status === 'failed').length;
  $('metric-progress').textContent = failed ? `${failed} target${failed === 1 ? '' : 's'} need attention` : run.status === 'running' ? 'Assessment in progress' : humanize(run.status);
  $('progress').value = percent; $('progress-label').textContent = `${percent}% · ${processed} of ${run.targets.length} processed`;
  $('target-count').textContent = `${run.targets.length} hosts`;
  if (!run.targets.some(target => target.url === selectedTarget)) selectedTarget = run.targets[0]?.url;
  const list = $('target-list'); list.replaceChildren();
  for (const target of run.targets) {
    const button = node('button', undefined, `target-row${selectedTarget === target.url ? ' selected' : ''}`);
    button.append(node('span', target.status === 'completed' ? '✓' : target.status === 'running' ? '◌' : '◎', 'target-symbol'));
    const label = node('span'); label.append(node('strong', new URL(target.url).hostname), node('small', target.status === 'completed' ? `${target.findings.length} observations · HTTP ${target.httpStatus}` : humanize(target.error || target.status)));
    button.append(label, badge(target.status));
    button.addEventListener('click', () => { selectedTarget = target.url; render(); }); list.append(button);
  }
  const target = run.targets.find(target => target.url === selectedTarget);
  $('detail-title').textContent = target ? new URL(target.url).hostname : 'Select a target';
  $('detail-status').textContent = target ? humanize(target.status) : ''; $('detail-status').className = `badge ${target?.status || ''}`;
  const detail = $('target-detail'); detail.replaceChildren();
  if (target?.coverage) {
    for (const check of target.coverage.checks) { const row = node('div', undefined, 'check-row'); row.append(node('span', names[check.checkId] || check.checkId), badge(check.status)); detail.append(row); }
    if (target.httpStatus >= 300 && target.httpStatus < 400) detail.append(node('p', 'Redirect recorded. The destination was not followed or assessed.', 'detail-message'));
    if (target.bodySha256) detail.append(node('p', `Captured response SHA-256: ${target.bodySha256}`, 'evidence'));
  } else detail.append(node('p', target?.error ? `The target could not be fully assessed: ${humanize(target.error)}. No skipped check counts as a pass.` : target?.status === 'running' ? 'Collecting a bounded HTTPS response. Results will appear here as the request completes.' : 'Checks have not completed for this target.', 'detail-message'));
  const results = $('findings-list'); results.replaceChildren();
  const filtered = findings.filter(finding => $('severity-filter').value === 'all' || finding.severity === $('severity-filter').value);
  if (!filtered.length) results.append(node('p', findings.length ? 'No observations match this filter.' : run.status === 'running' ? 'Observations will appear as checks finish.' : 'No observations were recorded by the completed checks. Review coverage gaps before drawing conclusions.', 'no-findings'));
  for (const finding of filtered) {
    const row = node('article', undefined, 'finding'); const content = node('div');
    content.append(node('h3', humanize(finding.code)), node('small', finding.target), node('p', finding.detail), node('p', `Next step: ${finding.fix}`, 'fix'));
    row.append(badge(finding.severity), content); results.append(row);
  }
  $('scope-description').textContent = `Authorization source: ${run.sourceUrl} · Expires ${date(run.expiresAt)} · Exact listed hosts only.`;
}
async function refresh(force = false) {
  try {
    const next = await api('/api/state');
    $('connection-error').hidden = !next.storageError;
    $('connection-error').textContent = next.storageError || '';
    const serialized = JSON.stringify(next);
    if (force || serialized !== lastState) { state = next; lastState = serialized; if (!selectedId) selectedId = state.assessments[0]?.id; render(); }
  } catch { $('connection-error').textContent = 'Connection lost. Progress may be out of date. Reconnecting…'; $('connection-error').hidden = false; }
}
function openForm() {
  if (state.active) { toast('Stop the current assessment or wait for it to finish.'); return; }
  $('form-error').hidden = true;
  const expiry = new Date(Date.now() + 86400000); expiry.setMinutes(expiry.getMinutes() - expiry.getTimezoneOffset());
  $('assessment-form').elements.expiresAt.value = expiry.toISOString().slice(0,16);
  render(); $('assessment-dialog').showModal();
}
for (const id of ['new-assessment','new-side','start-empty']) $(id).addEventListener('click', openForm);
$('close-dialog').addEventListener('click', () => $('assessment-dialog').close());
$('severity-filter').addEventListener('change', render);
$('history-picker').addEventListener('change', event => { selectedId = event.target.value; selectedTarget = undefined; render(); });
$('toggle-live').addEventListener('click', async () => { try { await api('/api/controls', { enabled: !state.enabled }); await refresh(true); } catch (error) { toast(error.message); } });
$('stop-assessment').addEventListener('click', async () => { try { await api(`/api/assessments/${selectedId}/cancel`, {}); await refresh(true); } catch (error) { toast(error.message); } });
$('demo').addEventListener('click', async () => { $('demo').disabled = true; try { const result = await api('/api/demo', {}); selectedId = result.id; selectedTarget = undefined; await refresh(true); } catch (error) { toast(error.message); $('demo').disabled = false; } });
$('assessment-form').addEventListener('submit', async event => {
  event.preventDefault(); $('submit-assessment').disabled = true; $('form-error').hidden = true;
  const form = event.currentTarget; const data = new FormData(form);
  try {
    const result = await api('/api/assessments', { name: data.get('name'), targets: String(data.get('targets')).split(/\r?\n/).map(value => value.trim()).filter(Boolean), sourceUrl: data.get('sourceUrl'), expiresAt: new Date(String(data.get('expiresAt'))).toISOString(), reviewed: data.get('reviewed') === 'on' });
    selectedId = result.id; selectedTarget = undefined; $('assessment-dialog').close(); form.reset(); await refresh(true);
  } catch (error) { $('form-error').textContent = error.message; $('form-error').hidden = false; $('submit-assessment').disabled = !state.enabled; }
});
await refresh(true);
setInterval(() => { void refresh(); }, 1000);
