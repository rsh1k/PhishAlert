# 🛡️ PhishGuard AI Pro

> **An advanced Chrome extension that uses DeepSeek AI and VirusTotal to detect phishing emails, scan malicious links, analyze file hashes, and protect you from social engineering attacks — with NIST-compliant encrypted API key storage.**

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Manifest](https://img.shields.io/badge/manifest-v3-green)
![Security](https://img.shields.io/badge/security-NIST%20SP%20800--53-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 📋 Table of Contents

- [What It Does](#-what-it-does)
- [How It Works](#-how-it-works)
- [Features](#-features)
- [Security Architecture](#-security-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [How to Use](#-how-to-use)
- [File Structure](#-file-structure)
- [Privacy](#-privacy)
- [Limitations](#-limitations)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 What It Does

PhishGuard AI Pro is a Chrome browser extension that sits silently in your browser and springs into action when you're reading emails. When you click **Scan**, it simultaneously:

1. **Sends the email content to DeepSeek AI** for a comprehensive phishing and social engineering analysis
2. **Submits every link in the email to VirusTotal** to check against 90+ antivirus and threat intelligence engines
3. **Checks any IP addresses** found in the email body against VirusTotal's IP reputation database
4. **Scans attachment hashes** (if available) to see if any files are known malware

Within seconds, you get a clear verdict — **PHISHING**, **SUSPICIOUS**, or **SAFE** — along with a detailed breakdown of exactly what was found and why.

### Who Is This For?

- **Security-conscious individuals** who want a second opinion on suspicious emails
- **IT and security teams** who want a quick triage tool without leaving their inbox
- **Developers and researchers** learning about phishing detection techniques
- **Anyone** who regularly receives emails from unknown senders

---

## ⚙️ How It Works

Here is the full data flow from the moment you click **Scan**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR BROWSER                             │
│                                                                 │
│  Gmail / Outlook                                                │
│       │                                                         │
│       │ 1. content.js reads the open email from the DOM         │
│       │    Extracts: subject, sender, body, links, IPs,         │
│       │    attachments, and header hints                        │
│       │                                                         │
│       ▼                                                         │
│  background.js (Service Worker)                                 │
│       │                                                         │
│       │ 2. Decrypts your API keys from AES-256-GCM storage      │
│       │                                                         │
│       │ 3. Runs these tasks IN PARALLEL:                        │
│       │                                                         │
│       ├──▶ DeepSeek API (deepseek.com)                         |
│       │      - Full AI phishing analysis                        │
│       │      - Social engineering detection                     │
│       │      - Sender reputation assessment                     │
│       │      - Header anomaly detection                         │
│       │                                                         │
│       ├──▶ VirusTotal API (virustotal.com)                     │
│       │      - Each link scanned against 90+ AV engines         │
│       │      - Each IP checked for malicious reputation         │
│       │      - Each file hash checked for known malware         │
│       │                                                         │
│       │ 4. Results are merged and returned to popup.js          │
│       │                                                         │
│       ▼                                                         │
│  popup.html / popup.js                                          │
│       │                                                         │
│       │ 5. Renders verdict, scores, flags, and VT results       │
│       │    Saves minimal metadata to local history              │
│       │    Writes audit log entry (no PII, no keys)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

**Why does the background service worker handle everything?**
Chrome extensions have three isolated contexts: the popup, content scripts, and the background service worker. By keeping all API calls and key decryption exclusively in the service worker, your API keys are never exposed to web page content or the popup UI. The popup only ever knows whether a key exists (a boolean) — it never sees the actual key value.

**Why parallel scanning?**
DeepSeek AI analysis and VirusTotal URL scans are independent operations. Running them simultaneously means you get results from both in roughly the same time it would take to run just one, typically 3–6 seconds.

**How does the AI phishing analysis work?**
The email content (subject, sender, body, links, attachment names, and any available headers) is sent to DeepSeek's `deepseek-chat` model with a detailed cybersecurity prompt. The model is instructed to analyze the email across seven dimensions — phishing indicators, sender reputation, social engineering tactics, link patterns, header anomalies, attachment risk, and language patterns — and return a structured JSON response. The extension validates this response before displaying it.

---

## ✨ Features

### 4-Tab Interface

#### Tab 1 — SCAN
The main tab. Opens the current email and runs the full AI + VirusTotal analysis.

- **Verdict card** — PHISHING / SUSPICIOUS / SAFE with color coding
- **Three score cards** — Risk score (0–100), Manipulation score (0–100), Sender reputation score (0–100)
- **Risk bar** — Visual indicator of overall threat level
- **Collapsible analysis sections:**
  - 👤 **Sender Analysis** — Domain legitimacy, spoofing detection, reputation score, AI notes
  - 🧠 **Social Engineering** — Urgency level, detected manipulation tactics (fear, authority, scarcity, etc.)
  - 📋 **Header Analysis** — SPF estimation, reply-to mismatch detection, routing anomalies
  - 🚩 **Detected Signals** — Per-flag breakdown with severity (danger / warning / safe) and category (sender / link / content / header / attachment)
  - 💡 **Recommendations** — Specific actions to take based on findings
- **Export Report** — Download a full `.txt` report
- **Copy** — Copy a summary to clipboard
- **Auto-scan** — Optionally scan emails automatically as you open them (configurable in Settings)

#### Tab 2 — VIRUSTOTAL
Manual threat lookup. Enter any URL, IP address, or file hash and scan it directly.

- Auto-detects input type (URL vs IP vs MD5/SHA256 hash)
- Shows per-vendor results from all VirusTotal engines
- Color-coded: malicious (red), suspicious (yellow), clean (green)
- Expandable vendor list showing what each engine found

#### Tab 3 — HISTORY
Log of the last 50 email scans.

- Verdict indicator dot (red/yellow/green)
- Email subject and sender
- Timestamp
- Risk score
- Clear all history button

#### Tab 4 — STATS
Aggregate statistics across all scans.

- Total emails scanned
- Phishing emails found
- Suspicious emails
- Safe emails
- VirusTotal threats caught
- Overall threat detection rate bar

---

## 🔐 Security Architecture

PhishGuard AI Pro is designed to follow NIST SP 800-53 security controls. Here is what that means in practice:

### API Key Encryption — SC-28 / NIST SP 800-132

Your API keys are **never stored in plaintext**. When you save a key, this is what happens:

```
Your API Key (plaintext)
        │
        ▼
┌───────────────────────────────────┐
│  PBKDF2-SHA-256 Key Derivation    │
│  Iterations: 310,000 (OWASP 2023) │
│  Salt: 128-bit CSPRNG (unique)    │
│  Output: AES-256 key              │
└───────────────┬───────────────────┘
                │
                ▼
┌───────────────────────────────────┐
│  AES-256-GCM Encryption           │
│  IV: 96-bit CSPRNG (unique)       │
│  Provides: confidentiality +      │
│            tamper detection       │
└───────────────┬───────────────────┘
                │
                ▼
     Stored as Base64 blob
     in chrome.storage.local
```

The master secret used to derive the encryption key is itself a 256-bit random value generated once at install time, stored separately from the encrypted keys. An attacker with only a Chrome storage dump cannot decrypt your keys without also having the master secret.

### Key Isolation — IA-5 / AC-3

- The popup UI **never reads your API keys back**. It only calls `hasKey()` which returns true/false
- When you type a key and click Save, the popup sends it to the background worker once, which encrypts it immediately. The popup input field is cleared right after
- All API calls are made from the background service worker only, which fetches keys from encrypted storage internally
- Content scripts (which run in the Gmail/Outlook page) never have access to any keys

### Input Validation — SI-10

- All incoming messages to the service worker are checked against an **allowlist** of permitted actions. Unknown actions are rejected
- All email data is sanitized and length-limited before being sent to any external API:
  - Subject: 500 chars max
  - Body: 8,000 chars max
  - Per-link: 2,048 chars max
  - Max 20 links, 10 IPs, 10 attachments per scan
- The AI response is structurally validated before being displayed (verdict must be one of three known values, risk score must be a number in range 0–100, etc.)

### Audit Logging — AU-2

Every significant action is logged with a timestamp: scans, key saves/deletions, errors. **No email content, no API keys, and no personally identifiable information is ever written to the audit log.** Only metadata such as verdict, risk score, and number of links scanned is recorded.

### Transport Security — SC-8

All external HTTP requests go to `https://` endpoints only. The `host_permissions` in `manifest.json` are scoped to specific HTTPS domains — the extension cannot make requests to any other domain.

### NIST Control Summary

| Control | Implementation |
|---|---|
| SC-28 (Protection at Rest) | AES-256-GCM with PBKDF2-SHA-256 (310k iterations) |
| IA-5 (Authenticator Management) | Keys non-extractable, isolated to service worker |
| AU-2 (Audit Events) | Tamper-evident local audit log, no PII |
| SI-10 (Information Input Validation) | Allowlist + sanitization on all inputs |
| SC-8 (Transmission Confidentiality) | HTTPS-only host permissions |
| AC-3 (Access Enforcement) | Sender origin validation on all messages |
| SA-11 (Developer Testing) | Input sanitization before all API calls |

---

## 📋 Prerequisites

Before installing, you need:

1. **Google Chrome** (or any Chromium-based browser: Edge, Brave, Arc, etc.)
2. **A DeepSeek API key** — free to get, 5 million tokens included
3. **A VirusTotal API key** — free tier available, 4 requests/minute
4. **Gmail or Outlook** in your browser (the extension currently supports these two)

---

## 🚀 Installation

### Step 1 — Download the Extension

**Option A — Clone this repository:**
```bash
git clone https://github.com/yourusername/phishguard-ai-pro.git
```

**Option B — Download the ZIP:**
Click the green **Code** button → **Download ZIP**, then extract it somewhere permanent (do not put it in your Downloads folder or it may get deleted).

---

### Step 2 — Open Chrome Extensions

Open Google Chrome and navigate to:
```
chrome://extensions/
```

Or go to the Chrome menu (three dots) → **More Tools** → **Extensions**.

---

### Step 3 — Enable Developer Mode

In the top-right corner of the Extensions page, toggle **Developer mode** ON.

You will see three new buttons appear: *Load unpacked*, *Pack extension*, and *Update*.

---

### Step 4 — Load the Extension

Click **Load unpacked**.

In the file picker that opens, navigate to and select the `phishing-detector` folder — the one that directly contains `manifest.json`. Do **not** select a parent folder.

Your folder structure should look like this:
```
phishing-detector/          ← SELECT THIS FOLDER
├── manifest.json           ← must be directly inside
├── background.js
├── content.js
├── content.css
├── popup.html
├── popup.js
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

Click **Select Folder**.

---

### Step 5 — Confirm Installation

You should now see **PhishGuard AI Pro** appear on the Extensions page with a blue shield icon.

Click the puzzle piece icon in your Chrome toolbar, find PhishGuard AI Pro, and click the pin icon to keep it visible in your toolbar.

---

## 🔑 Configuration

### Step 1 — Get a DeepSeek API Key

1. Go to [platform.deepseek.com](https://platform.deepseek.com)
2. Create a free account
3. Navigate to **API Keys** in the dashboard
4. Click **Create new API key**
5. Copy the key (it starts with `sk-`)

> **Free tier:** New accounts receive 5 million tokens at no cost, valid for 30 days. After that, DeepSeek is extremely affordable — approximately $0.28 per million input tokens.

---

### Step 2 — Get a VirusTotal API Key

1. Go to [virustotal.com](https://www.virustotal.com)
2. Create a free account
3. Click your profile icon → **API Key**
4. Copy your API key

> **Free tier:** 4 lookups per minute, 500 per day. This is enough for personal use.

---

### Step 3 — Enter Your Keys in the Extension

1. Click the PhishGuard AI Pro icon in your Chrome toolbar
2. Click the **⚙ gear icon** in the top-right corner to open Settings
3. Paste your DeepSeek key into the **DeepSeek API Key** field and click **SAVE 🔒**
4. Paste your VirusTotal key into the **VirusTotal API Key** field and click **SAVE 🔒**

The field will clear immediately and show **🔒 Encrypted** — this confirms the key has been encrypted and stored. You will never see your key again in the UI (by design).

To remove a key, click the red **✕** button next to the field.

---

### Step 4 — (Optional) Enable Auto-Scan

In the Settings panel, toggle **Auto-scan emails** ON. When enabled, the extension will automatically scan each email as you open it in Gmail or Outlook, and inject a small badge next to the subject line showing the verdict.

---

## 📖 How to Use

### Scanning an Email

1. Open **Gmail** (`mail.google.com`) or **Outlook** (`outlook.live.com` or `outlook.office.com`) in Chrome
2. **Click on any email** to open it — make sure the email body is fully visible
3. Click the **PhishGuard AI Pro** icon in your Chrome toolbar
4. Click **SCAN CURRENT EMAIL**
5. Wait 3–8 seconds while the AI and VirusTotal scans run in parallel
6. Review your results

---

### Reading Your Results

#### The Verdict Card
The top card shows your verdict in one of three states:

- 🚨 **PHISHING DETECTED** (red) — The email shows strong indicators of a phishing attack. Do not click any links, do not reply, do not provide any information.
- ⚠️ **SUSPICIOUS EMAIL** (yellow) — The email has some concerning signals but is not definitively malicious. Proceed with caution.
- ✅ **EMAIL LOOKS SAFE** (green) — No significant threats detected. Normal caution still applies.

The card also shows the AI's **confidence percentage** for its verdict.

#### The Score Cards
Three scores are shown at a glance:

- **RISK SCORE** — Overall threat level from 0 to 100. Below 30 is generally safe, 30–70 is suspicious, above 70 is likely phishing.
- **MANIPULATION** — How aggressively the email uses social engineering tactics (urgency, fear, authority) on a 0–100 scale.
- **SENDER REP** — The AI's assessment of the sender's legitimacy from 0 to 100. Higher is better.

#### The Collapsible Sections
Click any section header to expand it:

**👤 Sender Analysis**
Shows whether the sender's domain appears legitimate, whether spoofing is detected (e.g., the display name says "PayPal" but the email domain is `paypa1-secure.ru`), and the AI's detailed notes on the sender.

**🧠 Social Engineering**
Shows the detected urgency level and lists specific manipulation tactics found in the email, such as "false urgency — threatens account suspension", "authority impersonation — claims to be from IT department", or "artificial scarcity — limited time offer".

**📋 Header Analysis**
Shows an SPF pass/fail estimate (Gmail only), whether the Reply-To address differs from the sender address (a common phishing tactic), and any other header anomalies the AI detected.

**🚩 Detected Signals**
A full list of every red flag found, each tagged with its severity level (critical danger, warning, or safe indicator) and category (sender, link, content, header, or attachment).

**💡 Recommendations**
Specific actions the AI recommends based on what it found — for example, "Do not click the link in this email", "Report to your IT security team", or "Verify the sender via a separate communication channel".

---

### Manual VirusTotal Lookup

Switch to the **VIRUSTOTAL** tab to scan any URL, IP address, or file hash without needing to open an email.

1. Type or paste your input into the lookup field:
   - **URL:** `https://suspicious-site.com` or just `suspicious-site.com`
   - **IP address:** `185.234.56.78`
   - **File hash:** Any MD5 (32 chars), SHA-1 (40 chars), or SHA-256 (64 chars) hash
2. The extension auto-detects the input type
3. Click **SCAN**
4. Expand the result card to see the full vendor-by-vendor breakdown

---

### Exporting a Report

From the **SCAN** tab, after a scan:

- Click **⬇ EXPORT REPORT** to download a `.txt` file with the full analysis
- Click **⎘ COPY** to copy a short summary to your clipboard

Reports are useful for sharing with your IT or security team, or for filing a phishing report.

---

### Scan History

Switch to the **HISTORY** tab to see your last 50 scans. Each entry shows:
- A colored dot (red = phishing, yellow = suspicious, green = safe)
- The email subject
- The date and time of the scan
- The risk score

Click **🗑 CLEAR ALL** to wipe the history.

---

### Statistics

Switch to the **STATS** tab to see aggregate numbers across all your scans, including the total number of threats caught by VirusTotal and your overall threat detection rate.

---

## 📁 File Structure

```
phishing-detector/
│
├── manifest.json       Chrome Extension Manifest v3 configuration.
│                       Declares permissions, host permissions, and
│                       registers the service worker and content scripts.
│
├── background.js       The core service worker. Handles all API calls,
│                       key encryption/decryption, input validation,
│                       message routing, history, stats, and audit logging.
│                       This is the only place API keys are ever decrypted.
│
├── popup.html          The HTML shell of the extension popup UI.
│                       Defines the 4-tab layout, settings panel,
│                       scan results structure, and all UI components.
│
├── popup.js            The popup's interaction logic. Handles tab switching,
│                       settings saves (sends key to background, clears field),
│                       rendering scan results, history, and stats.
│                       Never stores or reads back any API key value.
│
├── content.js          Runs inside Gmail and Outlook tabs. Extracts email
│                       data (subject, sender, body, links, IPs, attachments,
│                       headers) from the DOM. Also handles auto-scan and
│                       renders the in-page verdict badge.
│
├── content.css         Styles for the in-page verdict badge injected into
│                       Gmail and Outlook by content.js.
│
└── icons/
    ├── icon16.png      Toolbar icon (16×16)
    ├── icon48.png      Extensions page icon (48×48)
    └── icon128.png     Chrome Web Store icon (128×128)
```

---

## 🔒 Privacy

**Your email content is sent to external APIs.** This is necessary for the extension to work. Here is exactly where your data goes:

| Data | Sent To | Why |
|---|---|---|
| Email subject, body, sender, links, attachments | DeepSeek API (`api.deepseek.com`) | AI phishing analysis |
| URLs found in email | VirusTotal (`virustotal.com`) | Malicious URL scanning |
| IPs found in email | VirusTotal (`virustotal.com`) | IP reputation check |
| File hashes | VirusTotal (`virustotal.com`) | Malware hash lookup |
| Your manually entered URLs/IPs/hashes | VirusTotal (`virustotal.com`) | Manual lookup |

**What stays on your device:**
- Your API keys (encrypted in Chrome local storage)
- Scan history (subject and sender only, not the full body)
- Audit log
- Statistics

**The extension does NOT:**
- Send any data to any server we operate
- Collect analytics or telemetry
- Share data between users
- Store email content beyond the current session

Please review the privacy policies of [DeepSeek](https://www.deepseek.com/privacy) and [VirusTotal](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy) if you handle sensitive or confidential email.

---

## ⚠️ Limitations

**Email client support:** Currently supports Gmail (`mail.google.com`) and Outlook web (`outlook.live.com`, `outlook.office.com`). Desktop email clients (Outlook app, Apple Mail, Thunderbird) are not supported.

**DOM dependency:** The extension reads email content from the page's HTML structure. Gmail and Outlook occasionally update their DOM layouts, which can break extraction. If scans return no content, the CSS selectors in `content.js` may need updating.

**VirusTotal free tier rate limits:** The free VT API allows 4 requests per minute. If an email contains many links, some may not be scanned to avoid hitting this limit. The extension scans up to 5 links, 3 IPs, and 5 attachment hashes per email.

**AI accuracy:** The AI analysis is probabilistic, not deterministic. It can produce false positives (flagging legitimate emails as suspicious) and false negatives (missing sophisticated phishing attacks). Always use your own judgment alongside the tool's output.

**Attachment hash scanning:** The extension can only scan attachment hashes if the hash is already known to VirusTotal. It does not upload or download attachment files. If a hash has never been seen by VirusTotal, it will return "not in database".

**Header data:** Full email headers (which contain the most reliable SPF/DKIM/DMARC data) are not fully accessible through the Gmail and Outlook web UIs. The header analysis is based on partial data and AI inference, and should not be treated as authoritative.

---

## 🤝 Contributing

Contributions are welcome. Here are some areas that would benefit from improvement:

- Support for additional email clients (Yahoo Mail, Proton Mail)
- Better DOM selectors that are more resilient to Gmail/Outlook UI updates
- Full email header extraction (requires the Gmail API for complete data)
- Unit tests for the crypto module and input sanitization functions
- Internationalization / multi-language support

To contribute, fork the repository, make your changes in a feature branch, and open a pull request with a clear description of what you changed and why.

---

## 📄 License

MIT License — free to use, modify, and distribute. See `LICENSE` for the full text.

---

## 🙏 Acknowledgements

- [DeepSeek](https://www.deepseek.com) — AI model powering the email analysis
- [VirusTotal](https://www.virustotal.com) — Threat intelligence for URL, IP, and hash scanning
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) — Security and Privacy Controls for Information Systems
- [NIST SP 800-132](https://csrc.nist.gov/publications/detail/sp/800-132/final) — Recommendation for Password-Based Key Derivation
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — PBKDF2 iteration count recommendations
