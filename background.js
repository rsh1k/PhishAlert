// background.js — PhishGuard AI Pro · NIST SP 800-53 / SP 800-132 compliant
//
// SECURITY ARCHITECTURE:
//   SC-28  — API keys encrypted at rest (AES-256-GCM)
//   IA-5   — Keys loaded only in service worker, never sent to popup or content scripts
//   AU-2   — Audit log for all scan actions (no PII in logs)
//   SI-10  — Input validation on all incoming messages
//   SC-8   — All external comms over TLS (enforced by HTTPS-only host_permissions)
//   AC-3   — Message sender validation
//   SA-11  — Input sanitized before API calls (truncation, encoding)

'use strict';

// ─── AES-256-GCM Crypto (inline — no ES module needed in MV3 SW) ──────────
const CRYPTO_VERSION  = 1;
const PBKDF2_ITER     = 310000;  // OWASP 2023 / NIST SP 800-132
const SALT_LEN        = 16;      // 128-bit salt
const IV_LEN          = 12;      // 96-bit IV (NIST GCM recommendation)
const KEY_BITS        = 256;     // AES-256

async function _getMasterSecret() {
  const s = await chrome.storage.local.get('_ms');
  if (s._ms) return s._ms;
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const secret = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  await chrome.storage.local.set({ _ms: secret });
  return secret;
}

async function _deriveKey(secret, salt) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptKey(plaintext) {
  const secret = await _getMasterSecret();
  const salt   = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv     = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key    = await _deriveKey(secret, salt);
  const ct     = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  const packed = new Uint8Array(1 + SALT_LEN + IV_LEN + ct.byteLength);
  packed[0] = CRYPTO_VERSION;
  packed.set(salt, 1);
  packed.set(iv, 1 + SALT_LEN);
  packed.set(new Uint8Array(ct), 1 + SALT_LEN + IV_LEN);
  return btoa(String.fromCharCode(...packed));
}

async function decryptKey(b64) {
  const packed  = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  if (packed[0] !== CRYPTO_VERSION) throw new Error('Unknown crypto version');
  const salt    = packed.slice(1, 1 + SALT_LEN);
  const iv      = packed.slice(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
  const ct      = packed.slice(1 + SALT_LEN + IV_LEN);
  const secret  = await _getMasterSecret();
  const key     = await _deriveKey(secret, salt);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch {
    throw new Error('Decryption failed — key may be corrupted');
  }
}

async function saveEncryptedKey(name, value) {
  const enc = await encryptKey(value);
  await chrome.storage.local.set({ [`_ek_${name}`]: enc });
}

async function loadDecryptedKey(name) {
  const s = await chrome.storage.local.get(`_ek_${name}`);
  const enc = s[`_ek_${name}`];
  if (!enc) return null;
  return decryptKey(enc);
}

async function removeKey(name) {
  await chrome.storage.local.remove(`_ek_${name}`);
}

async function hasKey(name) {
  const s = await chrome.storage.local.get(`_ek_${name}`);
  return !!s[`_ek_${name}`];
}

// ─── Allowed actions allowlist (NIST SI-10) ────────────────────────────────
const ALLOWED = new Set([
  'analyzeEmail', 'vtManualLookup',
  'saveKey', 'removeKey', 'hasKey',
  'getHistory', 'clearHistory', 'getStats',
  'getAuditLog', 'ping'
]);

// ─── Message Router ────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // AC-3: Reject messages not from this extension
  if (sender.tab && !sender.url?.startsWith(chrome.runtime.getURL(''))) {
    sendResponse({ error: 'Unauthorized sender' });
    return false;
  }
  if (!msg?.action || !ALLOWED.has(msg.action)) {
    sendResponse({ error: 'Invalid action' });
    return false;
  }
  handle(msg, sendResponse);
  return true;
});

async function handle(msg, respond) {
  try {
    switch (msg.action) {
      case 'ping':         respond({ ok: true }); break;

      case 'saveKey': {
        _validateStr(msg.name, 'name', 20);
        _validateStr(msg.value, 'value', 512);
        await saveEncryptedKey(msg.name, msg.value);
        auditLog('KEY_SAVED', { name: msg.name });
        respond({ ok: true });
        break;
      }
      case 'removeKey': {
        _validateStr(msg.name, 'name', 20);
        await removeKey(msg.name);
        auditLog('KEY_REMOVED', { name: msg.name });
        respond({ ok: true });
        break;
      }
      case 'hasKey': {
        _validateStr(msg.name, 'name', 20);
        respond({ exists: await hasKey(msg.name) });
        break;
      }

      case 'analyzeEmail': {
        const result = await fullEmailScan(msg.emailData);
        respond(result);
        break;
      }
      case 'vtManualLookup': {
        _validateStr(msg.query, 'query', 2048);
        const vtKey = await loadDecryptedKey('vt');
        if (!vtKey) { respond({ error: 'VirusTotal API key not configured.' }); break; }
        respond(await vtManualLookup(msg.query, vtKey));
        break;
      }

      case 'getHistory':   respond(await getHistory()); break;
      case 'clearHistory': await clearHistory(); respond({ ok: true }); break;
      case 'getStats':     respond(await getStats()); break;
      case 'getAuditLog':  respond(await getAuditLog()); break;

      default: respond({ error: 'Unhandled action' });
    }
  } catch (err) {
    auditLog('ERROR', { action: msg.action, error: err.message });
    respond({ error: err.message });
  }
}

// ─── Input validation (NIST SI-10) ────────────────────────────────────────
function _validateStr(v, field, max) {
  if (typeof v !== 'string') throw new Error(`${field} must be a string`);
  if (v.length > max) throw new Error(`${field} exceeds max length`);
}

function sanitizeEmailData(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('Invalid email data');
  return {
    subject:      String(raw.subject      || '').slice(0, 500),
    sender:       String(raw.sender       || '').slice(0, 200),
    senderDomain: String(raw.senderDomain || '').slice(0, 100),
    body:         String(raw.body         || '').slice(0, 8000),
    links:        (Array.isArray(raw.links) ? raw.links : []).slice(0, 20).map(l => String(l).slice(0, 2048)),
    ips:          (Array.isArray(raw.ips)   ? raw.ips   : []).slice(0, 10).map(i => String(i).slice(0, 45)),
    attachments:  (Array.isArray(raw.attachments) ? raw.attachments : []).slice(0, 10)
      .map(a => ({ name: String(a?.name || '').slice(0, 255), hash: a?.hash ? String(a.hash).slice(0, 64) : null })),
    headers:      (raw.headers && typeof raw.headers === 'object') ? raw.headers : {}
  };
}

// ─── Full Email Scan ───────────────────────────────────────────────────────
async function fullEmailScan(rawEmailData) {
  // IA-5: Keys fetched internally — NEVER passed through messages
  const [deepseekKey, vtKey] = await Promise.all([
    loadDecryptedKey('deepseek'),
    loadDecryptedKey('vt')
  ]);
  if (!deepseekKey) throw new Error('DeepSeek API key not configured. Click ⚙ to set up.');

  const emailData = sanitizeEmailData(rawEmailData);
  const results = { ai: null, vt: { urls: [], ips: [], attachments: [] }, timestamp: Date.now() };

  const tasks = [
    analyzeWithDeepSeek(emailData, deepseekKey)
      .then(r => { results.ai = r; })
      .catch(e => { results.ai = { error: e.message }; })
  ];

  if (vtKey) {
    emailData.links.slice(0, 5).forEach(url =>
      tasks.push(vtScanUrl(url, vtKey).then(r => results.vt.urls.push(r)).catch(() => {}))
    );
    emailData.ips.slice(0, 3).forEach(ip =>
      tasks.push(vtScanIp(ip, vtKey).then(r => results.vt.ips.push(r)).catch(() => {}))
    );
    emailData.attachments.filter(a => a.hash).forEach(att =>
      tasks.push(vtScanHash(att.hash, vtKey).then(r => results.vt.attachments.push({ ...r, name: att.name })).catch(() => {}))
    );
  }

  await Promise.all(tasks);

  // AU-2: Audit — no email content logged, no keys ever logged
  auditLog('SCAN_COMPLETE', {
    verdict: results.ai?.verdict,
    riskScore: results.ai?.risk_score,
    linksScanned: results.vt.urls.length,
    ipsScanned: results.vt.ips.length,
    attachmentsScanned: results.vt.attachments.length
  });

  // Store minimal metadata in history (no full body)
  await saveToHistory({
    emailData: { subject: emailData.subject, sender: emailData.sender },
    results
  });

  return results;
}

// ─── DeepSeek AI Analysis ──────────────────────────────────────────────────
async function analyzeWithDeepSeek(emailData, apiKey) {
  const { subject, sender, senderDomain, body, links, headers, attachments } = emailData;

  const prompt = `You are an elite cybersecurity analyst specializing in email threat intelligence. Perform a comprehensive phishing and social engineering analysis.

EMAIL METADATA:
Subject: ${subject || 'N/A'}
From: ${sender || 'N/A'}
Domain: ${senderDomain || 'N/A'}
Headers: ${JSON.stringify(headers)}
Links: ${links.length ? links.join(', ') : 'None'}
Attachments: ${attachments.length ? attachments.map(a => a.name).join(', ') : 'None'}

EMAIL BODY:
${body || 'N/A'}

Analyze: phishing indicators, sender reputation, social engineering tactics, link patterns, header anomalies, attachment risks, language patterns.

Respond ONLY with valid JSON (no markdown):
{
  "verdict": "PHISHING"|"SUSPICIOUS"|"SAFE",
  "risk_score": <0-100>,
  "confidence": <0-100>,
  "summary": "<2-3 sentences>",
  "sender_analysis": {
    "domain_legitimate": <bool>,
    "spoofing_detected": <bool>,
    "reputation_score": <0-100>,
    "notes": "<string>"
  },
  "social_engineering": {
    "urgency_level": "none"|"low"|"medium"|"high",
    "tactics_detected": ["<tactic>"],
    "manipulation_score": <0-100>
  },
  "header_analysis": {
    "spf_likely_pass": <bool|null>,
    "reply_to_mismatch": <bool>,
    "anomalies": ["<anomaly>"]
  },
  "flags": [
    {"text":"<finding>","severity":"danger"|"warning"|"safe","category":"sender"|"link"|"content"|"header"|"attachment"}
  ],
  "recommendations": ["<action>"]
}`;

  const response = await fetch('https://api.deepseek.com/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({
      model: 'deepseek-chat', max_tokens: 1500, temperature: 0.1,
      messages: [{ role: 'user', content: prompt }]
    })
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    if (response.status === 401) throw new Error('Invalid DeepSeek API key.');
    if (response.status === 429) throw new Error('Rate limit hit. Wait a moment.');
    throw new Error(err.error?.message || `DeepSeek error ${response.status}`);
  }

  const data = await response.json();
  const raw  = data.choices?.[0]?.message?.content || '';
  let parsed;
  try { parsed = JSON.parse(raw.replace(/```json|```/g, '').trim()); }
  catch { throw new Error('Could not parse AI response.'); }

  // SI-10: Validate AI response
  if (!['PHISHING','SUSPICIOUS','SAFE'].includes(parsed.verdict)) throw new Error('Invalid verdict');
  if (typeof parsed.risk_score !== 'number') throw new Error('Invalid risk score');
  return parsed;
}

// ─── VirusTotal ────────────────────────────────────────────────────────────
async function vtScanUrl(url, apiKey) {
  const sub = await fetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `url=${encodeURIComponent(url)}`
  });
  if (!sub.ok) return { url, error: `VT submit error ${sub.status}` };
  const id = (await sub.json()).data?.id;
  if (!id) return { url, error: 'No analysis ID' };
  await sleep(2000);
  const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, { headers: { 'x-apikey': apiKey } });
  if (!res.ok) return { url, error: `VT result error ${res.status}` };
  const d = await res.json();
  const stats = d.data?.attributes?.stats || {};
  return { url, ...vtStats(stats), vendors: parseVendors(d.data?.attributes?.results || {}) };
}

async function vtScanHash(hash, apiKey) {
  const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, { headers: { 'x-apikey': apiKey } });
  if (res.status === 404) return { hash, error: 'Not in VT database' };
  if (!res.ok) return { hash, error: `VT error ${res.status}` };
  const d = await res.json();
  const a = d.data?.attributes || {};
  return { hash, name: a.meaningful_name || hash.slice(0,16)+'…', type: a.type_description, size: a.size, ...vtStats(a.last_analysis_stats || {}), vendors: parseVendors(a.last_analysis_results || {}), reputation: a.reputation };
}

async function vtScanIp(ip, apiKey) {
  const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, { headers: { 'x-apikey': apiKey } });
  if (!res.ok) return { ip, error: `VT error ${res.status}` };
  const d = await res.json();
  const a = d.data?.attributes || {};
  return { ip, country: a.country, asOwner: a.as_owner, ...vtStats(a.last_analysis_stats || {}), vendors: parseVendors(a.last_analysis_results || {}), reputation: a.reputation };
}

async function vtManualLookup(query, apiKey) {
  const q = query.trim();
  if (/^[a-fA-F0-9]{32,64}$/.test(q))                                     return vtScanHash(q, apiKey);
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q))                                  return vtScanIp(q, apiKey);
  if (q.startsWith('http') || q.includes('.'))                              return vtScanUrl(q.startsWith('http') ? q : 'https://'+q, apiKey);
  throw new Error('Cannot detect type. Enter URL, IP, or hash.');
}

function vtStats(s) {
  return { malicious: s.malicious||0, suspicious: s.suspicious||0, harmless: s.harmless||0, undetected: s.undetected||0, total: Object.values(s).reduce((a,b)=>a+b,0) };
}

function parseVendors(results) {
  return Object.entries(results)
    .map(([vendor, d]) => ({ vendor, category: d.category, result: d.result||d.category, flagged: ['malicious','phishing','suspicious','spam'].includes(d.category) }))
    .sort((a, b) => b.flagged - a.flagged).slice(0, 40);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Audit Log (NIST AU-2) ─────────────────────────────────────────────────
async function auditLog(event, meta = {}) {
  const { auditLog: log = [] } = await chrome.storage.local.get('auditLog');
  log.unshift({ event, meta, ts: Date.now() });
  if (log.length > 200) log.splice(200);
  await chrome.storage.local.set({ auditLog: log });
}

async function getAuditLog() {
  const { auditLog: log = [] } = await chrome.storage.local.get('auditLog');
  return log;
}

// ─── History & Stats ───────────────────────────────────────────────────────
async function saveToHistory(entry) {
  const { history = [] } = await chrome.storage.local.get('history');
  history.unshift({ ...entry, id: Date.now() });
  if (history.length > 50) history.splice(50);
  await chrome.storage.local.set({ history });
}

async function getHistory() {
  const { history = [] } = await chrome.storage.local.get('history');
  return history;
}

async function clearHistory() {
  await chrome.storage.local.set({ history: [] });
  auditLog('HISTORY_CLEARED');
}

async function getStats() {
  const { history = [] } = await chrome.storage.local.get('history');
  return {
    total:      history.length,
    phishing:   history.filter(h => h.results?.ai?.verdict === 'PHISHING').length,
    suspicious: history.filter(h => h.results?.ai?.verdict === 'SUSPICIOUS').length,
    safe:       history.filter(h => h.results?.ai?.verdict === 'SAFE').length,
    vtThreats:  history.reduce((acc, h) => acc + (h.results?.vt?.urls||[]).filter(u => u.malicious > 0).length, 0)
  };
}
