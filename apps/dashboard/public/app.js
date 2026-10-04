const $ = id => document.getElementById(id);
let state = { enabled: false, active: null, assessments: [] };
let selectedId, selectedTarget, lastState = '', toastTimer;
let reportSelection, reportRequest = 0, reportMeta, reportDirty = false, reportSaving = false;
let project, draft, previewed = false, submissionKey = crypto.randomUUID(), submitting = false, streamConnected = false;
const names = { 'transport.encryption':'HTTPS transport', 'tls.protocol':'TLS protocol audit', 'tls.certificate':'Certificate audit', 'headers.hsts':'Strict transport security', 'headers.csp':'Content security policy', 'headers.baseline':'Security headers', 'headers.disclosure':'Version disclosure', 'cookies.attributes':'Cookie attributes' };
const humanize = value => String(value).replaceAll('_', ' ');
function nextStep(error) {
  if (/certificate|tls|cert_/i.test(error)) return 'Check the host’s certificate, hostname and expiry. Certificate verification remains required.';
  if (/timeout|deadline/i.test(error)) return 'Check availability and try a fresh assessment after the host responds reliably.';
  if (/dns|enotfound|eai_again/i.test(error)) return 'Verify the hostname and its public DNS records.';
  if (/private|blocked|address|ip_/i.test(error)) return 'Use an authorized public host. Private and reserved network addresses cannot be assessed here.';
  if (/expired|policy/i.test(error)) return 'Review the authorization and expiry, then create a new assessment with the updated scope.';
  if (/truncated/i.test(error)) return 'The response exceeded the capture limit. Review the available header evidence; the body was only partially captured.';
  if (/cancel/i.test(error)) return 'Start a new assessment when you are ready to finish the remaining checks.';
  return 'Verify the host is reachable and the scope is current, then retry in a new assessment.';
}
const node = (tag, text, className) => { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; };
function badge(value) { return node('span', humanize(value), `badge ${value}`); }
function toast(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 5000); }
async function api(path, body, key) {
  const response = await fetch(path, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type':'application/json', ...(key ? { 'Idempotency-Key': key } : {}) }, body: JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) throw Object.assign(new Error(humanize(result.error || 'request failed')), { issues: result.issues || [] });
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
  $('submit-assessment').disabled = !state.enabled || Boolean(state.active) || !previewed || submitting;
  $('service-health').textContent = `Storage ${state.health?.storage || 'ready'} · Executor ${state.health?.execution || 'idle'} · ${state.assessments.length} / 100 history slots · ${streamConnected ? 'Live updates connected' : 'Checking connection'}`;
  syncPickers();
  const query = $('history-search').value.toLowerCase().trim();
  const visible = state.assessments.filter(run => ($('show-archived').checked || !run.archivedAt) && (!$('project-filter').value || run.projectId === $('project-filter').value) && (!query || [run.name, ...run.targets.map(target => target.url)].some(value => value.toLowerCase().includes(query))));
  const history = $('history'); history.replaceChildren();
  const picker = $('history-picker'); picker.replaceChildren();
  if (!visible.length) picker.append(node('option', 'No assessments yet'));
  if (!visible.length) history.append(node('p', 'Your assessments will appear here.', 'history-empty'));
  for (const run of visible) {
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
  const seconds = Math.max(0, Math.floor((Date.parse(run.finishedAt || new Date().toISOString()) - Date.parse(run.createdAt)) / 1000));
  $('run-meta').textContent = `${Math.floor(seconds / 60)}m ${seconds % 60}s · Last activity ${date(run.updatedAt || run.createdAt)}${run.projectName ? ' · ' + run.projectName : ''}`;
  $('archive-assessment').textContent = run.archivedAt ? 'Restore from archive' : 'Archive';
  $('archive-assessment').disabled = state.active === run.id;
  $('demo-notice').hidden = !run.demo;
  $('download-report').href = `/api/assessments/${run.id}/report`;
  $('stop-assessment').hidden = state.active !== run.id;
  const processed = run.targets.filter(target => !['queued','running'].includes(target.status)).length;
  const findings = run.targets.flatMap((target, targetIndex) => target.findings.map((finding, findingIndex) => ({ ...finding, target:target.url, targetIndex, findingIndex })));
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
  if (target?.error) detail.append(node('p', nextStep(target.error), 'detail-message'));
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
    const prepare = node('button', 'Prepare report', 'button secondary small');
    prepare.disabled = ['queued','running','stopping'].includes(run.status);
    prepare.addEventListener('click', () => { reportSelection = { id:run.id, target:finding.targetIndex, finding:finding.findingIndex }; $('report-version').value = ''; reportDirty = false; $('report-dialog').showModal(); void loadReport(); });
    content.append(prepare); row.append(badge(finding.severity), content); results.append(row);
  }
  $('scope-description').textContent = `Authorization source: ${run.sourceUrl} · Expires ${date(run.expiresAt)} · Exact listed hosts only.${run.projectName ? ` Project: ${run.projectName}, revision ${run.projectRevision}.` : ''} Excluded: ${(run.excluded || []).map(url => new URL(url).hostname).join(', ') || 'None'}.`;
}
function acceptState(next, force = false) {
  $('connection-error').hidden = !next.storageError;
  $('connection-error').textContent = next.storageError || '';
  const serialized = JSON.stringify(next);
  if (force || serialized !== lastState) { state = next; lastState = serialized; if (!selectedId) selectedId = state.assessments.find(run => !run.archivedAt)?.id; render(); }
}
async function refresh(force = false) {
  try { acceptState(await api('/api/state'), force); }
  catch { $('connection-error').textContent = 'Connection lost. Progress may be out of date. Reconnecting…'; $('connection-error').hidden = false; }
}
function syncSelect(id, items, first) {
  const select = $(id), value = select.value;
  const signature = JSON.stringify(items);
  if (select.dataset.signature === signature) return;
  select.dataset.signature = signature; select.replaceChildren();
  const blank = node('option', first); blank.value = ''; select.append(blank);
  for (const item of items) { const option = node('option', item.label); option.value = item.id; select.append(option); }
  select.value = value;
}
function syncPickers() {
  const projects = (state.projects || []).map(item => ({ id:item.id, label:item.name }));
  syncSelect('project-picker', projects, 'New scope'); syncSelect('project-filter', projects, 'All projects');
  syncSelect('draft-picker', (state.drafts || []).map(item => ({ id:item.id, label:item.fields.name || 'Untitled draft' })), 'Choose a draft');
}
function invalidatePreview() {
  previewed = false; submissionKey = crypto.randomUUID(); $('scope-preview').hidden = true;
  $('assessment-form').elements.reviewed.checked = false; render();
}
function fields() {
  const form = $('assessment-form').elements;
  return { name:form.name.value, targets:form.targets.value.split(/\r?\n/).map(value => value.trim()),
    excluded:form.excluded.value.split(/\r?\n/).map(value => value.trim()), sourceUrl:form.sourceUrl.value, expiresAt:form.expiresAt.value,
    ...(project ? { projectId:project.id, projectRevision:project.revision } : {}) };
}
function scopeInput() {
  const values = fields();
  if (!values.expiresAt || !Number.isFinite(Date.parse(values.expiresAt))) throw Object.assign(new Error('Choose an authorization expiry.'), { issues:[{ field:'expiresAt', message:'Choose an authorization expiry.' }] });
  return { ...values, expiresAt:new Date(values.expiresAt).toISOString() };
}
function showFormError(error) {
  const box = $('form-error'); box.replaceChildren(node('strong', error.message));
  for (const issue of error.issues || []) {
    const field = issue.field.split('.')[0]; $('assessment-form').elements[field]?.setAttribute('aria-invalid', 'true');
    box.append(node('p', `${humanize(field)}${issue.line ? ' · line ' + issue.line : ''}: ${issue.message}`));
  }
  box.hidden = false;
}
function clearFormError() { $('form-error').hidden = true; for (const element of $('assessment-form').querySelectorAll('[aria-invalid]')) element.removeAttribute('aria-invalid'); }
function fillFields(values) {
  const form = $('assessment-form').elements;
  for (const key of ['name','sourceUrl']) form[key].value = values[key] || '';
  for (const key of ['targets','excluded']) form[key].value = (values[key] || []).join('\n');
  let expiry = values.expiresAt || '';
  if (expiry.endsWith('Z')) { const local = new Date(expiry); local.setMinutes(local.getMinutes() - local.getTimezoneOffset()); expiry = local.toISOString().slice(0,16); }
  form.expiresAt.value = expiry; invalidatePreview();
}
function openForm() {
  if (state.active) { toast('Stop the current assessment or wait for it to finish.'); return; }
  $('assessment-form').reset(); project = undefined; draft = undefined; invalidatePreview(); clearFormError();
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
for (const id of ['history-search','project-filter','show-archived']) $(id).addEventListener('input', render);
$('archive-assessment').addEventListener('click', async () => {
  try { await api(`/api/assessments/${selectedId}/archive`, { archived:!current().archivedAt }); await refresh(true); } catch (error) { toast(error.message); }
});
$('assessment-form').addEventListener('input', event => {
  if (['name','targets','excluded','sourceUrl','expiresAt'].includes(event.target.name)) invalidatePreview();
});
$('project-picker').addEventListener('change', () => {
  project = state.projects.find(item => item.id === $('project-picker').value); draft = undefined; $('draft-picker').value = '';
  $('project-name').value = project?.name || '';
  if (project) fillFields({ name:project.name, ...project.scope }); else invalidatePreview();
});
$('draft-picker').addEventListener('change', () => {
  draft = state.drafts.find(item => item.id === $('draft-picker').value); if (!draft) return;
  const saved = state.projects.find(item => item.id === draft.fields.projectId);
  project = saved ? { ...saved, revision:draft.fields.projectRevision } : undefined;
  $('project-picker').value = project?.id || ''; $('project-name').value = project?.name || ''; fillFields(draft.fields);
});
$('save-project').addEventListener('click', async () => {
  clearFormError();
  try {
    const saved = await api('/api/projects', { ...(project ? { id:project.id, expectedRevision:project.revision } : {}), name:$('project-name').value, scope:scopeInput() });
    project = saved; invalidatePreview(); await refresh(true); $('project-picker').value = saved.id; toast('Project scope saved. Review it before each assessment.');
  } catch (error) { showFormError(error); }
});
$('save-draft').addEventListener('click', async () => {
  clearFormError();
  try {
    draft = await api('/api/drafts', { ...(draft ? { id:draft.id, expectedRevision:draft.revision } : {}), fields:fields() });
    await refresh(true); $('draft-picker').value = draft.id; toast('Draft saved. Authorization will need a fresh review.');
  } catch (error) { showFormError(error); }
});
$('preview-assessment').addEventListener('click', async () => {
  clearFormError(); invalidatePreview();
  try {
    const snapshot = JSON.stringify(scopeInput());
    const result = await api('/api/preview', JSON.parse(snapshot)); if (JSON.stringify(scopeInput()) !== snapshot) return; const box = $('scope-preview'); box.replaceChildren(node('h3', 'Ready for your review'));
    box.append(node('p', result.action), node('strong', 'Included hosts'));
    const hosts = node('ul'); for (const url of result.targets) hosts.append(node('li', new URL(url).hostname)); box.append(hosts);
    box.append(node('p', `Excluded: ${result.excluded.map(url => new URL(url).hostname).join(', ') || 'None'}`));
    box.append(node('p', `At most ${result.maxRequests} requests · 64 KiB per response · ${result.deadlineSeconds}s deadline per request · ${result.minimumDelayMs / 1000}s between targets.`));
    box.append(node('p', `Authorization expires ${date(result.policy.expiresAt)}. Checks cover HTTPS transport, response headers and cookie attributes. Full TLS, authentication and business logic checks are outside this assessment.`));
    for (const warning of result.warnings) box.append(node('p', warning, 'preview-warning'));
    box.hidden = false; previewed = true; render();
  } catch (error) { showFormError(error); }
});
$('assessment-form').addEventListener('submit', async event => {
  event.preventDefault(); if (!previewed || submitting) return; submitting = true; render(); clearFormError();
  try {
    const result = await api('/api/assessments', { ...scopeInput(), reviewed:$('assessment-form').elements.reviewed.checked }, submissionKey);
    selectedId = result.id; selectedTarget = undefined; $('assessment-dialog').close(); await refresh(true);
  } catch (error) { showFormError(error); }
  finally { submitting = false; render(); }
});
await refresh(true);
const events = new EventSource('/api/events');
events.addEventListener('state', event => { try { streamConnected = true; acceptState(JSON.parse(event.data), true); } catch { void refresh(true); } });
events.onerror = () => { streamConnected = false; void refresh(true); };
setInterval(() => { if (!streamConnected) void refresh(); else if (state.active) render(); }, 1000);
// Periodic snapshots also recover if a proxy silently drops an event stream.
setInterval(() => { void refresh(); }, 15000);

async function loadReport() {
  if (!reportSelection) return;
  const request = ++reportRequest; setReportBusy(true);
  const { id, target, finding } = reportSelection;
  const path = `/api/assessments/${id}/reports/${target}/${finding}?profile=${encodeURIComponent($('report-profile').value)}${$('report-version').value ? '&revision=' + $('report-version').value : ''}`;
  reportMeta = undefined; $('save-report-draft').disabled = true; $('report-content').value = 'Generating draft…'; $('report-downloads').replaceChildren(); $('report-checklist').replaceChildren(); $('copy-report').disabled = true;
  try {
    const result = await api(path); if (request !== reportRequest) return;
    $('report-content').value = result.markdown; $('copy-report').disabled = false;
    reportMeta = { expectedRevision:result.latestRevision, sourceSnapshotSha256:result.report.sourceSnapshotSha256 };
    $('report-version').replaceChildren(node('option', 'Latest draft')); $('report-version').firstChild.value = '';
    for (const version of result.versions) { const option = node('option', `Revision ${version.revision} · ${date(version.savedAt)}`); option.value = String(version.revision); $('report-version').append(option); }
    $('report-version').value = new URL(path, location.origin).searchParams.get('revision') || '';
    for (const field of ['title','summary','steps','expected','impact']) $('report-edit-' + field).value = result.draft?.edits[field] || '';
    $('report-custom-fields').replaceChildren(); for (const field of result.draft?.edits.customFields || []) addReportField(field);
    reportDirty = false; $('save-report-draft').disabled = false; $('report-profile').disabled = false; $('report-version').disabled = false;
    $('report-save-status').textContent = result.stale ? 'Source changed. Review these edits before saving a new revision.' : result.draft ? `Showing saved revision ${result.draft.revision}. Exports include these saved edits.` : 'No saved edits. Exports use the automatic draft.';
    for (const blocker of result.report.blockers) $('report-checklist').append(node('li', blocker));
    for (const [format, label] of [['markdown','Markdown (.md)'],['text','Plain text (.txt)'],['html','HTML review copy'],['json','JSON evidence manifest']]) {
      const link = node('a', label, 'button secondary small'); link.href = path + `&format=${format}`; $('report-downloads').append(link);
    }
  } catch (error) { if (request === reportRequest) $('report-content').value = `Unable to generate report: ${error.message}`; }
  finally { if (request === reportRequest) { setReportBusy(false); $('save-report-draft').disabled = !reportMeta; } }
}
$('report-profile').addEventListener('change', () => { $('report-version').value = ''; void loadReport(); });
$('report-version').addEventListener('change', () => { void loadReport(); });
$('close-report').addEventListener('click', () => { if (!reportDirty && !reportSaving) $('report-dialog').close(); else toast('Save this report revision before closing to keep your edits.'); });
$('report-dialog').addEventListener('cancel', event => { if (reportDirty || reportSaving) { event.preventDefault(); toast('Save this report revision before closing to keep your edits.'); } });
$('report-dialog').addEventListener('close', () => { reportRequest++; reportSelection = undefined; });
$('copy-report').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('report-content').value); toast('Draft copied. Review evidence, impact and program requirements before submission.'); }
  catch { $('report-content').focus(); $('report-content').select(); toast('Select and copy the draft using your keyboard.'); }
});

function reportChanged() {
  reportDirty = true; $('report-profile').disabled = true; $('report-version').disabled = true;
  $('report-save-status').textContent = 'Unsaved edits. Save a revision to update the preview and exports.';
  $('report-downloads').replaceChildren(); $('copy-report').disabled = true;
}
function addReportField(field = { name:'', value:'' }) {
  if ($('report-custom-fields').children.length >= 10) { toast('A report can have up to 10 program fields.'); return; }
  const row = node('div', undefined, 'report-custom-field');
  const nameLabel = node('label', 'Program field name'), name = node('input'); name.maxLength = 80; name.value = field.name; name.dataset.field = 'name'; nameLabel.append(name);
  const valueLabel = node('label', 'Program field value'), value = node('textarea'); value.maxLength = 2000; value.rows = 2; value.value = field.value; value.dataset.field = 'value'; valueLabel.append(value);
  const remove = node('button', 'Remove field', 'button secondary small'); remove.type = 'button'; remove.addEventListener('click', () => { row.remove(); reportChanged(); });
  row.append(nameLabel, valueLabel, remove); $('report-custom-fields').append(row);
}
$('add-report-field').addEventListener('click', () => { addReportField(); reportChanged(); });
$('report-editor').addEventListener('input', reportChanged);
$('save-report-draft').addEventListener('click', async () => {
  if (!reportSelection || !reportMeta || reportSaving) return;
  const edits = Object.fromEntries(['title','summary','steps','expected','impact'].map(field => [field, $('report-edit-' + field).value]));
  edits.customFields = [...$('report-custom-fields').children].map(row => ({ name:row.querySelector('[data-field="name"]').value, value:row.querySelector('[data-field="value"]').value }));
  const { id, target, finding } = reportSelection;
  reportSaving = true; setReportBusy(true); $('report-profile').disabled = true; $('report-version').disabled = true;
  try {
    await api(`/api/assessments/${id}/reports/${target}/${finding}?profile=${encodeURIComponent($('report-profile').value)}`, { ...reportMeta, edits });
    reportDirty = false; $('report-version').value = ''; await loadReport(); toast('Report revision saved. Human review is still required before submission.');
  } catch (error) { $('report-save-status').textContent = `Could not save: ${error.message}. Your edits remain in this form.`; }
  finally { reportSaving = false; setReportBusy(false); $('save-report-draft').disabled = !reportMeta; }
});
window.addEventListener('beforeunload', event => { if (reportDirty || reportSaving) { event.preventDefault(); event.returnValue = ''; } });

function setReportBusy(busy) { for (const control of $('report-editor').querySelectorAll('input,textarea,button')) control.disabled = busy; }
$('discard-report-edits').addEventListener('click', () => { if (!reportSaving) { reportDirty = false; $('report-version').value = ''; void loadReport(); } });
