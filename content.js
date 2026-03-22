// content.js — PhishGuard AI Pro — Email extractor + auto-scan

let lastScannedUrl = '';
let autoScanEnabled = false;
let observer = null;

// ─── Message handler ───────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'extractEmail') {
    sendResponse(extractEmailData());
  }
  if (msg.action === 'setAutoScan') {
    autoScanEnabled = msg.enabled;
    if (autoScanEnabled) initAutoScan();
    else stopAutoScan();
    sendResponse({ ok: true });
  }
  if (msg.action === 'autoScan') {
    handleAutoScan();
  }
  return true;
});

// ─── Auto-scan: watch for email open ──────────────────────────────────────
function initAutoScan() {
  if (observer) observer.disconnect();
  observer = new MutationObserver(() => {
    const url = window.location.href;
    if (url !== lastScannedUrl) {
      lastScannedUrl = url;
      setTimeout(handleAutoScan, 1500); // wait for DOM to settle
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

function stopAutoScan() {
  if (observer) { observer.disconnect(); observer = null; }
}

async function handleAutoScan() {
  const data = extractEmailData();
  if (!data?.body || data.body.length < 20) return;

  const { keys, autoScan } = await chrome.storage.local.get(['keys', 'autoScan']);
  if (!autoScan || !keys?.deepseek) return;

  chrome.runtime.sendMessage({ action: 'analyzeEmail', emailData: data, keys }, result => {
    if (result && !result.error) {
      showInPageBadge(result.ai?.verdict || 'UNKNOWN');
    }
  });
}

// ─── Email Extraction ──────────────────────────────────────────────────────
function extractEmailData() {
  const host = window.location.hostname;
  if (host === 'mail.google.com') return extractGmail();
  if (host.includes('outlook')) return extractOutlook();
  return null;
}

function extractGmail() {
  const subject = document.querySelector('h2[data-legacy-thread-id], .hP')?.textContent?.trim() || '';
  const senderEl = document.querySelector('.gD');
  const sender = senderEl?.getAttribute('email') || senderEl?.textContent?.trim() || '';
  const senderDomain = extractDomain(sender);

  // Body
  const bodyEls = document.querySelectorAll('.a3s.aiL, .ii.gt .a3s');
  let body = '';
  bodyEls.forEach(el => body += el.innerText + '\n');

  // Links
  const links = extractLinks('.a3s.aiL a, .ii.gt a');

  // IPs from body
  const ips = extractIPs(body);

  // Headers (Gmail shows some in expanded view)
  const headers = extractGmailHeaders();

  // Attachments
  const attachments = extractGmailAttachments();

  return { subject, sender, senderDomain, body: body.trim(), links, ips, headers, attachments };
}

function extractOutlook() {
  const subject = document.querySelector('[aria-label*="Subject"], .f6')?.textContent?.trim() || '';
  const senderEl = document.querySelector('.f5, [title*="@"]');
  const sender = senderEl?.textContent?.trim() || '';
  const senderDomain = extractDomain(sender);

  const bodyEl = document.querySelector('[aria-label*="Message body"], .XbIp4');
  const body = bodyEl?.innerText?.trim() || '';

  const links = extractLinks('[aria-label*="Message body"] a, .XbIp4 a');
  const ips = extractIPs(body);
  const headers = {};
  const attachments = extractOutlookAttachments();

  return { subject, sender, senderDomain, body, links, ips, headers, attachments };
}

// ─── Extraction helpers ────────────────────────────────────────────────────
function extractLinks(selector) {
  const seen = new Set();
  const links = [];
  document.querySelectorAll(selector).forEach(a => {
    const href = a.href;
    if (href && !href.startsWith('mailto:') && !seen.has(href)) {
      seen.add(href);
      links.push(href);
    }
  });
  return links;
}

function extractIPs(text) {
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const matches = text.match(ipRegex) || [];
  // Filter out common false positives
  return [...new Set(matches)].filter(ip => !ip.startsWith('127.') && !ip.startsWith('192.168.') && !ip.startsWith('10.'));
}

function extractDomain(email) {
  const match = email.match(/@([^>)\s]+)/);
  return match ? match[1].toLowerCase() : '';
}

function extractGmailHeaders() {
  const headers = {};
  // Gmail shows "Show original" data — try to get visible header info
  const fromEl = document.querySelector('.gD');
  if (fromEl) headers['from'] = fromEl.getAttribute('email') || fromEl.textContent;
  const replyToEl = document.querySelector('[data-tooltip*="Reply-To"]');
  if (replyToEl) headers['reply-to'] = replyToEl.textContent?.trim();
  return headers;
}

function extractGmailAttachments() {
  const attachments = [];
  document.querySelectorAll('.aZo, .aV3').forEach(el => {
    const name = el.querySelector('.aV3, .aBf')?.textContent?.trim();
    if (name) attachments.push({ name, hash: null }); // hash requires file download
  });
  return attachments;
}

function extractOutlookAttachments() {
  const attachments = [];
  document.querySelectorAll('[aria-label*="attachment"], .attachmentItem').forEach(el => {
    const name = el.textContent?.trim();
    if (name) attachments.push({ name, hash: null });
  });
  return attachments;
}

// ─── In-page badge ─────────────────────────────────────────────────────────
function showInPageBadge(verdict) {
  document.querySelectorAll('.phishguard-badge').forEach(el => el.remove());

  const subjectEl = document.querySelector('h2[data-legacy-thread-id], .hP, .f6');
  if (!subjectEl) return;

  const badge = document.createElement('span');
  badge.className = `phishguard-badge ${verdict.toLowerCase()}`;
  badge.innerHTML = `<span class="badge-dot"></span>${verdict === 'PHISHING' ? '🚨 PHISHING' : verdict === 'SUSPICIOUS' ? '⚠️ SUSPICIOUS' : '✅ SAFE'}`;
  badge.title = 'PhishGuard AI — Click extension for details';
  subjectEl.appendChild(badge);
}
