// popup.js — PhishGuard AI Pro
// SECURITY: API keys are NEVER stored in popup state/variables.
// They are passed once to the background service worker which encrypts
// and stores them. The popup only checks if keys exist (boolean), never
// reads back plaintext values.

'use strict';

let currentResult = null;

// ─── Init ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  await checkKeyStatus();
  await loadHistory();
  await loadStats();
  bindTabs();
  bindSettings();
  bindScan();
  bindVT();
  bindHistory();
});

// ─── Key status (boolean only — never read plaintext back) ─────────────────
async function checkKeyStatus() {
  const [dsExists, vtExists] = await Promise.all([
    bg('hasKey', { name: 'deepseek' }),
    bg('hasKey', { name: 'vt' })
  ]);

  // Show placeholder status — never show actual key value
  const dsInput = document.getElementById('deepseekKey');
  const vtInput = document.getElementById('vtKey');

  dsInput.placeholder = dsExists.exists ? '●●●●●●●● (saved & encrypted)' : 'sk-...';
  vtInput.placeholder = vtExists.exists ? '●●●●●●●● (saved & encrypted)' : 'Your VT API key...';

  updateKeyStatusIndicator('dsStatus', dsExists.exists);
  updateKeyStatusIndicator('vtStatus', vtExists.exists);
}

function updateKeyStatusIndicator(id, exists) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = exists ? '🔒 Encrypted' : '⚠ Not set';
  el.style.color = exists ? 'var(--green)' : 'var(--warning)';
}

// ─── Tabs ──────────────────────────────────────────────────────────────────
function bindTabs() {
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`pane-${tab.dataset.tab}`).classList.add('active');
      if (tab.dataset.tab === 'stats') loadStats();
      if (tab.dataset.tab === 'history') loadHistory();
    });
  });

  document.querySelectorAll('.analysis-header').forEach(header => {
    header.addEventListener('click', () => {
      const body = document.getElementById(header.dataset.section + 'Body');
      const chevron = header.querySelector('.chevron');
      if (body) {
        body.classList.toggle('open');
        chevron.style.transform = body.classList.contains('open') ? 'rotate(180deg)' : '';
      }
    });
  });
}

// ─── Settings ──────────────────────────────────────────────────────────────
function bindSettings() {
  document.getElementById('settingsToggle').addEventListener('click', () => {
    document.getElementById('settingsPanel').classList.toggle('open');
  });

  // Save DeepSeek key — send to background, clear field immediately
  document.getElementById('saveDeepseek').addEventListener('click', async () => {
    const input = document.getElementById('deepseekKey');
    const val = input.value.trim();
    if (!val) return showError('Enter a DeepSeek API key.');
    if (!val.startsWith('sk-')) return showError('DeepSeek keys should start with "sk-".');

    const result = await bg('saveKey', { name: 'deepseek', value: val });
    input.value = ''; // clear immediately — NIST IA-5
    if (result.error) return showError(result.error);

    input.placeholder = '●●●●●●●● (saved & encrypted)';
    updateKeyStatusIndicator('dsStatus', true);
    flashBtn('saveDeepseek', 'SAVED 🔒');
    hideError();
  });

  // Save VT key
  document.getElementById('saveVt').addEventListener('click', async () => {
    const input = document.getElementById('vtKey');
    const val = input.value.trim();
    if (!val) return showError('Enter a VirusTotal API key.');

    const result = await bg('saveKey', { name: 'vt', value: val });
    input.value = ''; // clear immediately
    if (result.error) return showError(result.error);

    input.placeholder = '●●●●●●●● (saved & encrypted)';
    updateKeyStatusIndicator('vtStatus', true);
    flashBtn('saveVt', 'SAVED 🔒');
    hideError();
  });

  // Remove keys
  document.getElementById('removeDeepseek')?.addEventListener('click', async () => {
    if (!confirm('Remove DeepSeek API key?')) return;
    await bg('removeKey', { name: 'deepseek' });
    document.getElementById('deepseekKey').placeholder = 'sk-...';
    updateKeyStatusIndicator('dsStatus', false);
  });

  document.getElementById('removeVt')?.addEventListener('click', async () => {
    if (!confirm('Remove VirusTotal API key?')) return;
    await bg('removeKey', { name: 'vt' });
    document.getElementById('vtKey').placeholder = 'Your VT API key...';
    updateKeyStatusIndicator('vtStatus', false);
  });

  // Auto-scan
  document.getElementById('autoScanToggle').addEventListener('change', async e => {
    await chrome.storage.local.set({ autoScan: e.target.checked });
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    try { await chrome.tabs.sendMessage(tab.id, { action: 'setAutoScan', enabled: e.target.checked }); }
    catch {}
  });

  // Load auto-scan state
  chrome.storage.local.get('autoScan', d => {
    document.getElementById('autoScanToggle').checked = d.autoScan || false;
  });
}

// ─── Scan Tab ──────────────────────────────────────────────────────────────
function bindScan() {
  document.getElementById('analyzeBtn').addEventListener('click', runFullScan);
  document.getElementById('exportBtn').addEventListener('click', exportReport);
  document.getElementById('copyBtn').addEventListener('click', copyReport);
}

async function runFullScan() {
  // Check keys exist before hitting background (UX only — background validates too)
  const dsExists = await bg('hasKey', { name: 'deepseek' });
  if (!dsExists.exists) {
    return showError('DeepSeek key not set. Click ⚙ Settings to configure.');
  }

  hideError();
  setLoading(true, 'Extracting email data...');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let emailData;
    try {
      emailData = await chrome.tabs.sendMessage(tab.id, { action: 'extractEmail' });
    } catch {
      throw new Error('Cannot read email. Open Gmail or Outlook and open an email first.');
    }
    if (!emailData?.body) throw new Error('No email found. Open an email first.');

    updateLoadingStep('Running AI + VirusTotal scan...', `Found ${emailData.links?.length || 0} links · ${emailData.ips?.length || 0} IPs · ${emailData.attachments?.length || 0} attachments`);

    // Keys are fetched inside background — never passed from popup
    const result = await bg('analyzeEmail', { emailData });
    if (result.error) throw new Error(result.error);

    currentResult = { result, emailData };
    renderScanResult(result, emailData);
    if (result.vt?.urls?.length || result.vt?.ips?.length || result.vt?.attachments?.length) {
      renderVTResults(result.vt);
    }
    await loadHistory();
    await loadStats();
  } catch (err) {
    showError(err.message);
    document.getElementById('emptyScan').style.display = 'block';
  } finally {
    setLoading(false);
  }
}

function renderScanResult(result, emailData) {
  const ai = result.ai || {};
  const verdict = ai.verdict || 'UNKNOWN';
  const verdictClass = verdict === 'PHISHING' ? 'phishing' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe';
  const riskScore = ai.risk_score || 0;

  document.getElementById('emptyScan').style.display = 'none';
  document.getElementById('scanResults').style.display = 'block';

  const card = document.getElementById('verdictCard');
  card.className = `verdict-card ${verdictClass}`;
  document.getElementById('verdictIcon').textContent = verdict === 'PHISHING' ? '🚨' : verdict === 'SUSPICIOUS' ? '⚠️' : '✅';
  document.getElementById('verdictTitle').textContent = verdict === 'PHISHING' ? 'PHISHING DETECTED' : verdict === 'SUSPICIOUS' ? 'SUSPICIOUS EMAIL' : 'EMAIL LOOKS SAFE';
  document.getElementById('verdictConfidence').textContent = `AI Confidence: ${ai.confidence ?? '—'}%`;
  document.getElementById('verdictSummary').textContent = ai.summary || '';

  const riskEl = document.getElementById('riskVal');
  riskEl.textContent = riskScore;
  riskEl.className = `score-val ${riskScore >= 70 ? 'red' : riskScore >= 40 ? 'yellow' : 'green'}`;

  const ms = ai.social_engineering?.manipulation_score ?? '—';
  const manipEl = document.getElementById('manipVal');
  manipEl.textContent = ms;
  manipEl.className = `score-val ${ms >= 70 ? 'red' : ms >= 40 ? 'yellow' : 'green'}`;

  const rs = ai.sender_analysis?.reputation_score ?? '—';
  const repEl = document.getElementById('repVal');
  repEl.textContent = rs;
  repEl.className = `score-val ${rs <= 30 ? 'red' : rs <= 60 ? 'yellow' : 'green'}`;

  const riskColor = riskScore >= 70 ? 'var(--danger)' : riskScore >= 40 ? 'var(--warning)' : 'var(--green)';
  document.getElementById('riskNum').textContent = `${riskScore}/100`;
  document.getElementById('riskNum').style.color = riskColor;
  document.getElementById('riskBar').style.cssText = `width:${riskScore}%;background:${riskColor}`;

  // Sender
  const sa = ai.sender_analysis || {};
  const sb = document.getElementById('senderBadge');
  sb.textContent = sa.spoofing_detected ? 'SPOOFING' : sa.domain_legitimate ? 'LEGITIMATE' : 'UNKNOWN';
  sb.className = `analysis-header-badge ${sa.spoofing_detected ? 'badge-danger' : sa.domain_legitimate ? 'badge-safe' : 'badge-neutral'}`;
  document.getElementById('senderBody').innerHTML = `
    <div class="kv-row"><span class="kv-key">Domain Legitimate</span><span class="kv-val" style="color:${sa.domain_legitimate?'var(--green)':'var(--danger)'}">${sa.domain_legitimate?'YES':'NO'}</span></div>
    <div class="kv-row"><span class="kv-key">Spoofing Detected</span><span class="kv-val" style="color:${sa.spoofing_detected?'var(--danger)':'var(--green)'}">${sa.spoofing_detected?'YES ⚠':'NO'}</span></div>
    <div class="kv-row"><span class="kv-key">Reputation Score</span><span class="kv-val">${sa.reputation_score??'—'}/100</span></div>
    <div style="font-size:11px;color:var(--text-dim);margin-top:6px;line-height:1.6">${esc(sa.notes||'—')}</div>`;

  // Social Engineering
  const se = ai.social_engineering || {};
  const urgColor = { none:'var(--green)', low:'var(--text-dim)', medium:'var(--warning)', high:'var(--danger)' };
  const socBadge = document.getElementById('socialBadge');
  socBadge.textContent = (se.urgency_level||'NONE').toUpperCase();
  socBadge.className = `analysis-header-badge ${se.urgency_level==='high'?'badge-danger':se.urgency_level==='medium'?'badge-warning':'badge-safe'}`;
  const tactics = se.tactics_detected||[];
  document.getElementById('socialBody').innerHTML = `
    <div class="kv-row"><span class="kv-key">Urgency Level</span><span class="kv-val" style="color:${urgColor[se.urgency_level]||'var(--text-dim)'}">${(se.urgency_level||'NONE').toUpperCase()}</span></div>
    <div class="kv-row"><span class="kv-key">Manipulation Score</span><span class="kv-val">${se.manipulation_score??'—'}/100</span></div>
    <div style="margin-top:6px">${tactics.length?tactics.map(t=>`<span class="chip warning">${esc(t)}</span>`).join(''):'<span class="chip neutral">None detected</span>'}</div>`;

  // Headers
  const ha = ai.header_analysis || {};
  const anomalies = ha.anomalies||[];
  const hBadge = document.getElementById('headerBadge');
  hBadge.textContent = ha.reply_to_mismatch||anomalies.length ? 'ANOMALIES':'NORMAL';
  hBadge.className = `analysis-header-badge ${ha.reply_to_mismatch||anomalies.length?'badge-warning':'badge-safe'}`;
  document.getElementById('headerBody').innerHTML = `
    <div class="kv-row"><span class="kv-key">SPF (estimated)</span><span class="kv-val" style="color:${ha.spf_likely_pass===true?'var(--green)':ha.spf_likely_pass===false?'var(--danger)':'var(--text-dim)'}">${ha.spf_likely_pass===true?'PASS':ha.spf_likely_pass===false?'FAIL':'UNKNOWN'}</span></div>
    <div class="kv-row"><span class="kv-key">Reply-To Mismatch</span><span class="kv-val" style="color:${ha.reply_to_mismatch?'var(--danger)':'var(--green)'}">${ha.reply_to_mismatch?'YES ⚠':'NO'}</span></div>
    <div style="margin-top:6px">${anomalies.length?anomalies.map(a=>`<div class="flag-item warning"><div class="flag-dot" style="background:var(--warning)"></div><div class="flag-text">${esc(a)}</div></div>`).join(''):'<span class="chip safe">No anomalies</span>'}`;

  // Flags
  const flags = ai.flags||[];
  const dangerCount = flags.filter(f=>f.severity==='danger').length;
  const fBadge = document.getElementById('flagsBadge');
  fBadge.textContent = `${dangerCount} CRITICAL`;
  fBadge.className = `analysis-header-badge ${dangerCount>0?'badge-danger':'badge-safe'}`;
  document.getElementById('flagsBody').innerHTML = flags.length
    ? flags.map(f=>`<div class="flag-item ${f.severity}"><div class="flag-dot"></div><div class="flag-text">${esc(f.text)}<span class="flag-cat">[${f.category||''}]</span></div></div>`).join('')
    : '<span class="chip safe">No flags detected</span>';

  // Recommendations
  const recs = ai.recommendations||[];
  document.getElementById('recsBody').innerHTML = recs.length
    ? recs.map(r=>`<div class="rec-item"><span class="rec-arrow">→</span><span>${esc(r)}</span></div>`).join('')
    : '<div class="rec-item"><span class="rec-arrow">→</span><span>No specific actions required.</span></div>';

  if (verdict !== 'SAFE') {
    document.getElementById('flagsBody').classList.add('open');
    document.getElementById('senderBody').classList.add('open');
  }
}

// ─── VirusTotal Tab ────────────────────────────────────────────────────────
function bindVT() {
  document.getElementById('vtScanBtn').addEventListener('click', async () => {
    const query = document.getElementById('vtQuery').value.trim();
    if (!query) return;

    const vtExists = await bg('hasKey', { name: 'vt' });
    if (!vtExists.exists) return showError('VirusTotal key not set. Click ⚙ to configure.');

    hideError();
    const btn = document.getElementById('vtScanBtn');
    btn.disabled = true; btn.textContent = '...';
    document.getElementById('vtResults').innerHTML = '<div class="vt-empty">Scanning...</div>';

    try {
      const result = await bg('vtManualLookup', { query });
      if (result.error) throw new Error(result.error);
      renderVTResults({ manual: [result] });
    } catch (err) {
      showError(err.message);
      document.getElementById('vtResults').innerHTML = '<div class="vt-empty">Scan failed.</div>';
    } finally {
      btn.disabled = false; btn.textContent = 'SCAN';
    }
  });
}

function renderVTResults(vt) {
  const container = document.getElementById('vtResults');
  const items = [];
  (vt.urls||[]).forEach(r => items.push({ type:'URL', name:r.url, data:r }));
  (vt.ips||[]).forEach(r => items.push({ type:'IP', name:r.ip+(r.country?` (${r.country})`:''), data:r }));
  (vt.attachments||[]).forEach(r => items.push({ type:'FILE', name:r.name||r.hash, data:r }));
  (vt.manual||[]).forEach(r => {
    const type = r.url?'URL':r.ip?'IP':'HASH';
    items.push({ type, name: r.url||r.ip||r.hash, data:r });
  });
  if (!items.length) { container.innerHTML = '<div class="vt-empty">No results.</div>'; return; }
  container.innerHTML = items.map(item => renderVTCard(item)).join('');
  container.querySelectorAll('.vt-card-header').forEach(h => {
    h.addEventListener('click', () => h.nextElementSibling?.nextElementSibling?.classList.toggle('open'));
  });
}

function renderVTCard({ type, name, data }) {
  const m = data.malicious||0, s = data.suspicious||0, t = data.total||0;
  const cls = m>0?'bad':s>0?'warn':'clean';
  const score = t ? `${m}/${t}` : data.error?'Error':'—';
  const vendors = data.vendors||[];
  const vendorHtml = vendors.length
    ? `<div class="vendor-grid">${vendors.map(v=>`<div class="vendor-item ${v.flagged?'flagged':'clean'}"><span class="vendor-name">${esc(v.vendor)}</span><span class="vendor-result">${esc(v.result||'clean')}</span></div>`).join('')}</div>`
    : '<div style="font-size:11px;color:var(--text-faint)">No vendor data.</div>';
  return `
    <div class="vt-result-card">
      <div class="vt-stats-bar">
        <span class="vt-stat"><span class="vt-stat-dot" style="background:var(--danger)"></span>${m} malicious</span>
        <span class="vt-stat"><span class="vt-stat-dot" style="background:var(--warning)"></span>${s} suspicious</span>
        <span class="vt-stat"><span class="vt-stat-dot" style="background:var(--green)"></span>${data.harmless||0} clean</span>
      </div>
      <div class="vt-card-header">
        <span class="vt-card-type">${type}</span>
        <span class="vt-card-name">${esc(name||'—')}</span>
        <span class="vt-card-score ${cls}">${score}</span>
      </div>
      <div class="vt-vendors">${vendorHtml}</div>
    </div>`;
}

// ─── History ───────────────────────────────────────────────────────────────
async function loadHistory() {
  const history = await bg('getHistory', {});
  const badge = document.getElementById('historyBadge');
  if (!history?.length) {
    badge.style.display = 'none';
    document.getElementById('historyList').innerHTML = `<div class="empty"><div class="empty-icon">📂</div><div class="empty-text">No scan history yet.</div></div>`;
    return;
  }
  badge.style.display = 'inline-block';
  badge.textContent = history.length;
  document.getElementById('historyList').innerHTML = history.map(entry => {
    const verdict = entry.results?.ai?.verdict || 'UNKNOWN';
    const score = entry.results?.ai?.risk_score ?? '—';
    const subject = entry.emailData?.subject || '(No subject)';
    const time = new Date(entry.id).toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
    const scoreColor = score>=70?'var(--danger)':score>=40?'var(--warning)':'var(--green)';
    return `<div class="history-item">
      <div class="history-verdict ${verdict.toLowerCase()}"></div>
      <div style="flex:1;min-width:0">
        <div class="history-subject" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(subject)}</div>
        <div class="history-meta">${time} · ${verdict}</div>
      </div>
      <div class="history-score" style="color:${scoreColor}">${score}</div>
    </div>`;
  }).join('');
}

function bindHistory() {
  document.getElementById('clearHistoryBtn').addEventListener('click', async () => {
    if (!confirm('Clear all scan history?')) return;
    await bg('clearHistory', {});
    await loadHistory();
    await loadStats();
  });
}

// ─── Stats ─────────────────────────────────────────────────────────────────
async function loadStats() {
  const stats = await bg('getStats', {});
  if (!stats) return;
  document.getElementById('statTotal').textContent     = stats.total;
  document.getElementById('statPhishing').textContent  = stats.phishing;
  document.getElementById('statSuspicious').textContent= stats.suspicious;
  document.getElementById('statSafe').textContent      = stats.safe;
  document.getElementById('statVtThreats').textContent = stats.vtThreats;
  const rate = stats.total ? Math.round(((stats.phishing+stats.suspicious)/stats.total)*100) : 0;
  document.getElementById('detectionBar').style.width = `${rate}%`;
  document.getElementById('detectionLabel').textContent = stats.total ? `${rate}% threat rate across ${stats.total} scanned emails` : 'No data yet';
}

// ─── Export / Copy ─────────────────────────────────────────────────────────
function exportReport() {
  if (!currentResult) return;
  const { result, emailData } = currentResult;
  const ai = result.ai||{};
  const lines = [
    '═══ PHISHGUARD AI PRO SECURITY REPORT ═══',
    `Generated: ${new Date().toLocaleString()}`,
    `Subject:   ${emailData.subject||'N/A'}`,
    `Sender:    ${emailData.sender||'N/A'}`,
    '', `VERDICT:   ${ai.verdict}`,
    `Risk Score: ${ai.risk_score}/100  |  Confidence: ${ai.confidence}%`,
    '', `SUMMARY:\n${ai.summary}`,
    '', 'SENDER ANALYSIS:',
    `  Legitimate: ${ai.sender_analysis?.domain_legitimate}`,
    `  Spoofing:   ${ai.sender_analysis?.spoofing_detected}`,
    `  Notes:      ${ai.sender_analysis?.notes}`,
    '', 'SOCIAL ENGINEERING:',
    `  Urgency:    ${ai.social_engineering?.urgency_level}`,
    `  Score:      ${ai.social_engineering?.manipulation_score}/100`,
    `  Tactics:    ${(ai.social_engineering?.tactics_detected||[]).join(', ')||'None'}`,
    '', `FLAGS (${(ai.flags||[]).length}):`,
    ...(ai.flags||[]).map(f=>`  [${f.severity.toUpperCase()}][${f.category}] ${f.text}`),
    '', 'RECOMMENDATIONS:',
    ...(ai.recommendations||[]).map(r=>`  → ${r}`),
    '', 'VIRUSTOTAL:',
    ...(result.vt?.urls||[]).map(u=>`  URL: ${u.url} → ${u.malicious}/${u.total} flagged`),
    ...(result.vt?.ips||[]).map(i=>`  IP:  ${i.ip} → ${i.malicious}/${i.total} flagged`),
    ...(result.vt?.attachments||[]).map(a=>`  FILE:${a.name} → ${a.malicious}/${a.total} flagged`),
    '', '═══════════════════════════════════════',
    'PhishGuard AI Pro v2.0 | NIST SP 800-53 compliant'
  ];
  const blob = new Blob([lines.join('\n')], { type:'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `phishguard-${Date.now()}.txt`; a.click();
  URL.revokeObjectURL(url);
}

function copyReport() {
  if (!currentResult) return;
  const ai = currentResult.result?.ai||{};
  navigator.clipboard.writeText(`PhishGuard AI\nVerdict: ${ai.verdict} | Risk: ${ai.risk_score}/100\n${ai.summary}`)
    .then(() => flashBtn('copyBtn', '✓ COPIED'));
}

// ─── Helpers ───────────────────────────────────────────────────────────────
function bg(action, extra={}) {
  return new Promise(resolve => chrome.runtime.sendMessage({ action, ...extra }, resolve));
}

function setLoading(on, msg) {
  document.getElementById('loading').classList.toggle('on', on);
  document.getElementById('analyzeBtn').disabled = on;
  if (on) {
    document.getElementById('scanResults').style.display = 'none';
    document.getElementById('emptyScan').style.display = 'none';
    if (msg) document.getElementById('loadingStep').textContent = msg;
  }
}

function updateLoadingStep(step, sub) {
  document.getElementById('loadingStep').textContent = step;
  document.getElementById('loadingSub').textContent  = sub;
}

function showError(msg) {
  const bar = document.getElementById('errorBar');
  bar.textContent = '⚠ ' + msg;
  bar.classList.add('on');
}

function hideError() {
  document.getElementById('errorBar').classList.remove('on');
}

function flashBtn(id, text) {
  const btn = document.getElementById(id);
  const orig = btn.textContent;
  btn.textContent = text;
  setTimeout(() => btn.textContent = orig, 2000);
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = String(str||'');
  return d.innerHTML;
}
