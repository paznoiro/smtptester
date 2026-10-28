import { testSmtp, type SmtpTestRequest } from "./smtp";

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SMTP Tester — Free SMTP Diagnostics, TLS &amp; OAuth2 Email Test Tool</title>
<meta name="description" content="Free SMTP Tester with step-by-step diagnostics — DNS, TCP, STARTTLS/SSL, AUTH PLAIN/LOGIN/XOAUTH2, OAuth2 client_credentials auto-fetch. Test Gmail, Outlook Office365, SendGrid, SES, Mailgun, Zoho & any SMTP server with raw transcript.">
<meta name="keywords" content="SMTP tester, SMTP test, test SMTP server, SMTP diagnostics, XOAUTH2, OAuth2 SMTP, STARTTLS tester, email delivery test, Gmail SMTP test, Office365 SMTP test, SendGrid, SES, Mailgun, Brevo, Zoho, iCloud">
<meta name="author" content="SMTP Tester">
<meta name="robots" content="index, follow, max-image-preview:large">
<meta name="theme-color" content="#0f172a">
<link rel="canonical" href="https://smtptester.authkeystone.com/">
<meta property="og:title" content="SMTP Tester — Free SMTP Diagnostics &amp; Email Delivery Test">
<meta property="og:description" content="Diagnose any SMTP server in seconds — DNS, TLS, AUTH, MAIL FROM/RCPT TO, DATA with detailed failure explanations. Supports PLAIN, LOGIN, XOAUTH2 with OAuth2 token fetch.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://smtptester.authkeystone.com/">
<meta property="og:image" content="https://smtptester.authkeystone.com/og.png">
<meta property="og:site_name" content="SMTP Tester">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="SMTP Tester — Free SMTP Diagnostics Tool">
<meta name="twitter:description" content="Step-by-step SMTP diagnostics with OAuth2 support — test Gmail, Outlook, SendGrid, SES instantly.">
<meta name="twitter:image" content="https://smtptester.authkeystone.com/og.png">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📧</text></svg>">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebApplication","name":"SMTP Tester","url":"https://smtptester.authkeystone.com/","description":"Free SMTP diagnostics tool — DNS, TCP, TLS, AUTH PLAIN/LOGIN/XOAUTH2, OAuth2 auto-fetch, raw transcript. Test Gmail, Outlook, SendGrid, SES, Mailgun and any SMTP server.","applicationCategory":"DeveloperApplication","operatingSystem":"Any","offers":{"@type":"Offer","price":"0","priceCurrency":"USD"},"featureList":["DNS & TCP connect","STARTTLS/SSL","AUTH PLAIN","AUTH LOGIN","XOAUTH2 OAuth2","OAuth2 client_credentials auto-fetch","MAIL FROM","RCPT TO","DATA delivery","Raw transcript"]}</script>
<style>
:root { --bg:#0f172a; --card:#1e293b; --muted:#94a3b8; --border:#334155; --accent:#38bdf8; --accent2:#818cf8; --pass:#22c55e; --fail:#ef4444; --warn:#f59e0b; --skip:#64748b; }
* { box-sizing:border-box; }
body { margin:0; font-family: ui-sans-system, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color:#e2e8f0; min-height:100vh; }
a { color: var(--accent); }
header { padding:24px 20px 12px; max-width:1280px; margin:0 auto; }
.header-top { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.github-link { color:var(--muted); display:inline-flex; align-items:center; justify-content:center; width:36px; height:36px; border-radius:8px; border:1px solid var(--border); background:#0f172a; flex-shrink:0; transition: color 0.15s, border-color 0.15s; }
.github-link:hover { color:var(--accent); border-color:var(--accent); }
.github-link svg { width:20px; height:20px; display:block; }
header h1 { margin:0; font-size:28px; letter-spacing:-0.02em; display:flex; align-items:center; gap:10px; }
header h1 span.logo { background: linear-gradient(135deg, var(--accent), var(--accent2)); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
header p { margin:8px 0 0; color:var(--muted); font-size:14px; }
.container { max-width:1280px; margin:0 auto; padding:16px 20px 40px; display:grid; grid-template-columns: 460px 1fr; gap:20px; }
@media(max-width: 960px){ .container{ grid-template-columns:1fr; } }
.card { background: var(--card); border:1px solid var(--border); border-radius:14px; padding:18px; box-shadow: 0 4px 24px rgba(0,0,0,0.25); }
.card h2 { margin:0 0 14px; font-size:16px; letter-spacing:-0.01em; display:flex; align-items:center; justify-content:space-between; }
.card h2 small { color:var(--muted); font-weight:400; font-size:12px; }
label { display:block; font-size:12px; color:var(--muted); margin:12px 0 6px; font-weight:600; letter-spacing:0.02em; text-transform:uppercase; }
input, select, textarea { width:100%; background:#0f172a; border:1px solid var(--border); color:#e2e8f0; border-radius:8px; padding:10px 12px; font-size:14px; outline:none; transition:border 0.15s; }
input:focus, select:focus, textarea:focus { border-color: var(--accent); box-shadow:0 0 0 3px rgba(56,189,248,0.15); }
textarea { resize:vertical; min-height:84px; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
.row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.row3 { display:grid; grid-template-columns: 1.6fr 0.8fr 1fr; gap:12px; }
.hint { font-size:11px; color:var(--muted); margin-top:4px; line-height:1.4; }
.preset-banner { background: linear-gradient(135deg, rgba(56,189,248,0.15), rgba(129,140,248,0.15)); border:1px solid rgba(56,189,248,0.2); border-radius:10px; padding:12px; margin-bottom:14px; font-size:12px; line-height:1.5; }
.preset-banner strong { color:#e2e8f0; }
.btn { appearance:none; border:none; border-radius:10px; padding:12px 16px; font-weight:700; font-size:14px; cursor:pointer; transition: all 0.15s; display:inline-flex; align-items:center; justify-content:center; gap:8px; width:100%; }
.btn-primary { background: linear-gradient(135deg, var(--accent), var(--accent2)); color:#0f172a; box-shadow:0 4px 16px rgba(56,189,248,0.35); }
.btn-primary:hover { transform:translateY(-1px); box-shadow:0 8px 24px rgba(56,189,248,0.4); }
.btn-primary:disabled { opacity:0.6; cursor:not-allowed; transform:none; }
.btn-ghost { background: transparent; border:1px solid var(--border); color:var(--muted); padding:8px 12px; font-size:13px; width:auto; }
.btn-ghost:hover { border-color: var(--accent); color: var(--accent); }
.auth-box { background:#0f172a; border:1px dashed var(--border); border-radius:10px; padding:12px; margin-top:8px; }
.pill { display:inline-flex; align-items:center; gap:6px; font-size:11px; font-weight:600; padding:4px 8px; border-radius:999px; border:1px solid var(--border); background:#0f172a; color:var(--muted); }
.pill.pass { border-color: rgba(34,197,94,0.3); color: var(--pass); background: rgba(34,197,94,0.08); }
.pill.fail { border-color: rgba(239,68,68,0.3); color: var(--fail); background: rgba(239,68,68,0.08); }
.pill.skip { color: var(--skip); }
.results-empty { text-align:center; padding:40px 20px; color:var(--muted); }
.results-empty .icon { font-size:36px; margin-bottom:12px; }
.checklist { display:flex; flex-direction:column; gap:10px; margin:14px 0; }
.check-item { display:flex; gap:12px; align-items:flex-start; background:#0f172a; border:1px solid var(--border); border-radius:10px; padding:12px; }
.check-icon { width:28px; height:28px; border-radius:999px; display:flex; align-items:center; justify-content:center; font-size:14px; flex-shrink:0; font-weight:800; }
.check-icon.pass { background: rgba(34,197,94,0.15); color: var(--pass); border:1px solid rgba(34,197,94,0.3); }
.check-icon.fail { background: rgba(239,68,68,0.15); color: var(--fail); border:1px solid rgba(239,68,68,0.3); }
.check-icon.skip { background: rgba(100,116,139,0.1); color: var(--skip); }
.check-icon.running { background: rgba(245,158,11,0.15); color: var(--warn); animation:pulse 1.2s infinite; }
.check-icon.pending { background: rgba(100,116,139,0.1); color: var(--skip); }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }
.check-main { flex:1; min-width:0; }
.check-title { font-weight:600; font-size:13px; }
.check-detail { font-size:12px; color:var(--muted); margin-top:4px; word-break:break-word; white-space:pre-wrap; }
.check-explain { margin-top:8px; background: rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.15); border-radius:8px; padding:10px; font-size:12px; line-height:1.5; }
.check-explain.pass { background: rgba(34,197,94,0.06); border-color: rgba(34,197,94,0.15); }
.summary-box { border-radius:12px; padding:16px; border:1px solid var(--border); margin-bottom:16px; }
.summary-box.success { background: rgba(34,197,94,0.08); border-color: rgba(34,197,94,0.25); }
.summary-box.fail { background: rgba(239,68,68,0.08); border-color: rgba(239,68,68,0.25); }
.summary-title { font-weight:800; font-size:15px; }
.summary-sub { font-size:12px; color:var(--muted); margin-top:6px; }
.log-toolbar { display:flex; gap:8px; flex-wrap:wrap; margin:12px 0; align-items:center; }
.log-filter { display:flex; gap:6px; }
.log-filter button { padding:6px 10px; border-radius:8px; border:1px solid var(--border); background:#0f172a; color:var(--muted); font-size:12px; cursor:pointer; }
.log-filter button.active { background: var(--accent); color:#0f172a; border-color: var(--accent); font-weight:700; }
.logs { background:#020617; border:1px solid var(--border); border-radius:10px; overflow:hidden; max-height:520px; overflow-y:auto; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }
.log-line { display:grid; grid-template-columns: 90px 36px 1fr; gap:8px; padding:8px 12px; border-bottom:1px solid rgba(51,65,85,0.5); align-items:start; }
.log-line:last-child{ border-bottom:none; }
.log-ts { color:#64748b; font-size:11px; white-space:nowrap; }
.log-dir { font-weight:800; text-align:center; border-radius:4px; padding:2px 0; font-size:11px; }
.log-dir.C { background: rgba(56,189,248,0.15); color: var(--accent); }
.log-dir.S { background: rgba(34,197,94,0.12); color: var(--pass); }
.log-dir.INFO { background: rgba(129,140,248,0.15); color: var(--accent2); }
.log-dir.ERROR { background: rgba(239,68,68,0.15); color: var(--fail); }
.log-msg { white-space:pre-wrap; word-break:break-all; color:#cbd5e1; }
.badge { display:inline-block; padding:2px 6px; border-radius:6px; font-size:11px; font-weight:700; }
.badge-plain { background: rgba(56,189,248,0.15); color: var(--accent); }
.footer { max-width:1280px; margin:0 auto; padding:0 20px 40px; color:var(--muted); font-size:12px; line-height:1.6; }
code.inline { background:#0f172a; border:1px solid var(--border); padding:2px 6px; border-radius:6px; font-size:12px; }
details { background:#0f172a; border:1px solid var(--border); border-radius:10px; padding:12px; margin-top:12px; }
details summary { cursor:pointer; font-weight:600; font-size:13px; }
</style>
</head>
<body>
<header>
  <div class="header-top">
    <h1>📧 <span class="logo">SMTP Tester</span></h1>
    <a class="github-link" href="https://github.com/paznoiro/smtptester" target="_blank" rel="noopener noreferrer" title="View source on GitHub" aria-label="View source on GitHub">
      <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
    </a>
  </div>
  <p>Diagnose SMTP servers with step-by-step checklist — DNS, TCP, TLS, AUTH, MAIL/FROM — plus raw transcript and failure explanations. Supports <code class="inline">PLAIN</code>, <code class="inline">LOGIN</code> and <code class="inline">XOAUTH2</code> with automatic OAuth2 token fetch.</p>
</header>

<div class="container">
  <div class="card" id="formCard">
    <h2>SMTP Configuration <small>presets fill but remain editable</small></h2>

    <div class="preset-banner" id="presetBanner">
      <strong>Preset:</strong> <span id="presetDesc">Choose a provider to auto-fill host/port/encryption/auth, then tweak as needed.</span>
    </div>

    <label for="preset">Preset</label>
    <select id="preset">
      <option value="custom">Custom</option>
      <option value="gmail">Gmail (smtp.gmail.com)</option>
      <option value="outlook">Outlook / Office365 (smtp.office365.com)</option>
      <option value="yahoo">Yahoo (smtp.mail.yahoo.com)</option>
      <option value="sendgrid">SendGrid (smtp.sendgrid.net)</option>
      <option value="ses">Amazon SES (email-smtp.us-east-1.amazonaws.com)</option>
      <option value="mailgun">Mailgun (smtp.mailgun.org)</option>
      <option value="brevo">Brevo (smtp-relay.brevo.com)</option>
      <option value="zoho">Zoho (smtp.zoho.com)</option>
      <option value="icloud">iCloud (smtp.mail.me.com)</option>
    </select>

    <div class="row3">
      <div>
        <label for="host">SMTP Host</label>
        <input id="host" placeholder="smtp.example.com" value="smtp.office365.com">
      </div>
      <div>
        <label for="port">Port</label>
        <input id="port" type="number" value="587" min="1" max="65535">
      </div>
      <div>
        <label for="encryption">Encryption</label>
        <select id="encryption">
          <option value="auto">Auto (by port)</option>
          <option value="starttls" selected>STARTTLS</option>
          <option value="ssl">SSL / TLS (implicit)</option>
          <option value="none">None (plain)</option>
        </select>
      </div>
    </div>
    <div class="hint">587 → STARTTLS, 465 → SSL, 25/2525 → STARTTLS or None. Use Auto to pick by port.</div>

    <label for="authType">Auth Type</label>
    <select id="authType">
      <option value="plain">PLAIN</option>
      <option value="login">LOGIN</option>
      <option value="xoauth2" selected>XOAUTH2 (OAuth 2.0)</option>
      <option value="none">None (no auth)</option>
    </select>
    <div class="hint" id="authHint">XOAUTH2: <code class="inline">AUTH XOAUTH2 base64(user=...\\x01auth=Bearer ...)</code> — OAuth2 bearer token.</div>

    <div id="authPlainBox" class="auth-box" style="display:none;">
      <label for="username">Username (often full email)</label>
      <input id="username" placeholder="user@example.com" autocomplete="username">
      <label for="password">Password / App Password</label>
      <div style="display:flex; gap:8px;">
        <input id="password" type="password" placeholder="••••••••" autocomplete="current-password" style="flex:1">
        <button type="button" class="btn-ghost" id="togglePass" style="white-space:nowrap">Show</button>
      </div>
      <div class="hint">For Gmail: create App Password at myaccount.google.com → Security → 2-Step → App passwords (if using PLAIN). For XOAUTH2 use OAuth2 fields below.</div>
    </div>

    <div id="authXoauthBox" class="auth-box">
      <label for="oauthUser">User (XOAUTH2 identity) *</label>
      <input id="oauthUser" placeholder="user@example.com" value="">
      <div class="hint">This becomes <code class="inline">user=</code> in XOAUTH2 blob. Must match authenticated mailbox.</div>

      <div style="background: rgba(56,189,248,0.08); border:1px solid rgba(56,189,248,0.2); border-radius:8px; padding:10px; margin-top:12px;">
        <div style="font-weight:700; font-size:12px; margin-bottom:8px; color:var(--accent);">OAuth2 Client Credentials (auto token fetch)</div>
        <div class="hint" style="margin:0 0 8px;">If you fill <b>Token Endpoint + Client ID + Client Secret</b>, the tester will fetch an access token automatically before SMTP. Leave secret empty to use a pasted token below instead.</div>
        <label for="oauthTokenEndpoint">Token Endpoint *</label>
        <input id="oauthTokenEndpoint" placeholder="https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" value="">
        <label for="oauthScope">Scopes (comma separated) *</label>
        <input id="oauthScope" placeholder="https://outlook.office365.com/.default" value="">
        <div class="hint">For Microsoft, use <code class="inline">https://outlook.office365.com/.default</code>. For Google, <code class="inline">https://mail.google.com/</code>. Comma separated values become space-separated for token request.</div>
        <div class="row">
          <div>
            <label for="oauthClientId">Client ID *</label>
            <input id="oauthClientId" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value="">
          </div>
          <div>
            <label for="oauthClientSecret">Client Secret *</label>
            <input id="oauthClientSecret" type="password" placeholder="••••••••">
          </div>
        </div>
        <div style="display:flex; gap:8px; margin-top:10px;">
          <button type="button" class="btn-ghost" id="fetchTokenBtn" style="flex:1;">🔑 Fetch Token Now</button>
          <button type="button" class="btn-ghost" id="toggleSecretBtn">Show secret</button>
        </div>
        <div id="oauthFetchResult" class="hint" style="margin-top:8px; display:none; white-space:pre-wrap; background:#020617; border:1px solid var(--border); border-radius:6px; padding:8px;"></div>
      </div>

      <label for="oauthToken" style="margin-top:14px;">Or paste Access Token directly (Bearer)</label>
      <textarea id="oauthToken" rows="3" placeholder="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs... or ya29.a0..."></textarea>
      <div class="hint">
        Direct token mode: paste an existing access token. If client credentials above are filled, token will be fetched automatically and this field is ignored. XOAUTH2 format: <code class="inline">user=email\\x01auth=Bearer token\\x01\\x01</code> base64-encoded as <code class="inline">AUTH XOAUTH2 &lt;blob&gt;</code>.
      </div>
    </div>

    <div class="row">
      <div>
        <label for="from">Mail From</label>
        <input id="from" placeholder="sender@example.com" value="">
      </div>
      <div>
        <label for="to">Rcpt To (test recipient)</label>
        <input id="to" placeholder="recipient@example.com" value="">
      </div>
    </div>
    <div class="hint">Many servers require <code class="inline">From</code> to match authenticated user or verified alias, else <code class="inline">553 / 550 relay denied</code>.</div>

    <label for="subject">Subject</label>
    <input id="subject" value="SMTP Tester — Test Email">

    <label for="body">Body</label>
    <textarea id="body" rows="4">Hello from SMTP Tester 👋

This is a test email sent via SMTP Tester.
If you received this, SMTP delivery is working!

Timestamp: {{now}}</textarea>

    <div class="row">
      <div>
        <label for="timeout">Timeout (ms)</label>
        <input id="timeout" type="number" value="12000" min="3000" max="30000" step="1000">
      </div>
      <div style="display:flex; align-items:flex-end;">
        <button id="testBtn" class="btn btn-primary" style="margin-top:12px;">▶ Run SMTP Test</button>
      </div>
    </div>
    <div style="display:flex; gap:8px; margin-top:10px;">
      <button type="button" class="btn-ghost" id="copyCurlBtn">Copy as cURL</button>
      <button type="button" class="btn-ghost" id="saveBtn">Save config</button>
      <button type="button" class="btn-ghost" id="loadBtn">Load</button>
    </div>

    <details style="margin-top:16px;">
      <summary>🔧 Local setup & error glossary</summary>
      <div style="font-size:12px; line-height:1.6; color:var(--muted); margin-top:10px;">
        <p><b>Run locally:</b> <code class="inline">npm install && npm run dev</code> → opens at <code class="inline">http://localhost:8787</code>. Uses secure TCP sockets — works locally. Deploy with <code class="inline">npm run deploy</code>.</p>
        <p><b>Error examples:</b><br>
        • <code class="inline">DNS_FAILED</code> — host typo / not resolvable.<br>
        • <code class="inline">CONNECTION_REFUSED / TCP_TIMEOUT</code> — port blocked, firewall, ISP blocks 25.<br>
        • <code class="inline">TLS_HANDSHAKE_FAILED</code> — wrong encryption (STARTTLS vs SSL), old TLS version.<br>
        • <code class="inline">STARTTLS_NOT_SUPPORTED</code> — server plaintext only.<br>
        • <code class="inline">AUTH_FAILED (535)</code> — bad user/pass, need App Password, or wrong AUTH method.<br>
        • <code class="inline">OAUTH_FAILED / XOAUTH2_FAILED (334 + JSON)</code> — token expired/scope wrong/client secret invalid.<br>
        • <code class="inline">RELAY_DENIED (550)</code> — FROM not allowed, recipient policy.<br>
        </p>
      </div>
    </details>
  </div>

  <div class="card" id="resultsCard">
    <h2>Test Report <span id="reportMeta" class="pill" style="display:none;"></span></h2>
    <div id="resultsEmpty" class="results-empty">
      <div class="icon">🧪</div>
      <div style="font-weight:600;">No test yet</div>
      <div style="font-size:12px; max-width:420px; margin:8px auto 0; line-height:1.5;">Fill credentials on the left and click <b>Run SMTP Test</b>. You'll get a step checklist (what passed / what failed), an explanation for each failure, and a full raw transcript.</div>
      <div style="margin-top:16px; display:inline-flex; gap:8px; flex-wrap:wrap; justify-content:center;">
        <span class="pill">DNS & TCP</span><span class="pill">OAuth2</span><span class="pill">TLS</span><span class="pill">AUTH PLAIN</span><span class="pill">XOAUTH2</span><span class="pill">MAIL FROM</span><span class="pill">DATA</span>
      </div>
    </div>

    <div id="resultsContent" style="display:none;">
      <div id="summaryBox" class="summary-box"></div>

      <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
        <h3 style="margin:0; font-size:14px;">Checklist — what was tested</h3>
        <span id="timings" style="font-size:11px; color:var(--muted);"></span>
      </div>
      <div id="checklist" class="checklist"></div>

      <div id="oauthBox" style="display:none; background: rgba(56,189,248,0.06); border:1px solid rgba(56,189,248,0.2); border-radius:10px; padding:12px; margin:12px 0;">
        <div style="font-weight:700; font-size:13px; color:var(--accent);">OAuth2 Details</div>
        <div id="oauthDetail" style="font-size:12px; margin-top:6px; line-height:1.6; white-space:pre-wrap;"></div>
      </div>

      <div id="errorBox" style="display:none; background: rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.2); border-radius:10px; padding:12px; margin:12px 0;">
        <div style="font-weight:700; font-size:13px; color:var(--fail);">Failure Analysis</div>
        <div id="errorDetail" style="font-size:12px; margin-top:6px; line-height:1.6;"></div>
      </div>

      <div style="display:flex; align-items:center; justify-content:space-between; margin-top:16px;">
        <h3 style="margin:0; font-size:14px;">Raw Transcript & Logs</h3>
        <div style="display:flex; gap:8px;">
          <button class="btn-ghost" id="copyLogsBtn">Copy logs</button>
          <button class="btn-ghost" id="downloadBtn">Download JSON</button>
        </div>
      </div>
      <div class="log-toolbar">
        <div class="log-filter" id="logFilter">
          <button data-filter="all" class="active">All</button>
          <button data-filter="C">C → S</button>
          <button data-filter="S">S → C</button>
          <button data-filter="INFO">Info</button>
          <button data-filter="ERROR">Errors</button>
        </div>
        <span id="logCount" style="font-size:11px; color:var(--muted); margin-left:auto;"></span>
      </div>
      <div id="logs" class="logs"></div>
      <div class="hint" style="margin-top:8px;">C = client sent, S = server replied, INFO = tester notes, ERROR = failure. Credentials are redacted in logs. Click any line to copy.</div>
    </div>
  </div>
</div>

<div class="footer">
  <b>Tips:</b> If you get <code class="inline">535 5.7.8 Authentication failed</code> on Gmail with PLAIN, you need an App Password (16-char) not your normal password. For OAuth2, Client Credentials flow needs admin consent for <code class="inline">https://outlook.office365.com/.default</code> in Entra ID. For service mailboxes, ensure the app has <code class="inline">SMTP.Send</code> application permission (not delegated). Port 25 is often blocked by providers/ISPs — prefer 587/465/2525.<br>
  Built for local run with <code class="inline">npm run dev</code> and deploy with <code class="inline">npm run deploy</code>. Uses secure TCP sockets (STARTTLS / SSL / plain).
</div>

<script>
const presets = {
  custom: { host:"", port:587, encryption:"auto", authType:"plain", desc:"Custom server — fill manually." },
  gmail: { host:"smtp.gmail.com", port:587, encryption:"starttls", authType:"xoauth2", oauth:{ tokenEndpoint:"https://oauth2.googleapis.com/token", scope:"https://mail.google.com/" }, desc:"Gmail: 587 STARTTLS (preferred) or 465 SSL. XOAUTH2 selected. Note: Google does not support client_credentials for SMTP — paste an access token (user consent / refresh-token flow). PLAIN needs an App Password." },
  outlook: { host:"smtp.office365.com", port:587, encryption:"starttls", authType:"xoauth2", oauth:{ tokenEndpoint:"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", scope:"https://outlook.office365.com/.default" }, desc:"Outlook/Office365: 587 STARTTLS. AUTH XOAUTH2 with client_credentials (Token Endpoint + Client ID/Secret + scope https://outlook.office365.com/.default)." },
  yahoo: { host:"smtp.mail.yahoo.com", port:587, encryption:"starttls", authType:"plain", desc:"Yahoo: 587 STARTTLS or 465 SSL. Generate App Password at account security." },
  sendgrid: { host:"smtp.sendgrid.net", port:587, encryption:"starttls", authType:"plain", desc:"SendGrid: 587 STARTTLS, username=apikey, password=SG.* API key. Often also 2525." },
  ses: { host:"email-smtp.us-east-1.amazonaws.com", port:587, encryption:"starttls", authType:"plain", desc:"Amazon SES: host varies by region (us-east-1, eu-west-1, etc.). 587 STARTTLS or 2587 TLS wrapper / 465 SSL." },
  mailgun: { host:"smtp.mailgun.org", port:587, encryption:"starttls", authType:"plain", desc:"Mailgun: 587 STARTTLS, username from domain settings, password from Mailgun." },
  brevo: { host:"smtp-relay.brevo.com", port:587, encryption:"starttls", authType:"plain", desc:"Brevo (Sendinblue): 587 STARTTLS, login = your Brevo login, password = SMTP key." },
  zoho: { host:"smtp.zoho.com", port:587, encryption:"starttls", authType:"plain", desc:"Zoho: 587 STARTTLS or 465 SSL. For EU use smtp.zoho.eu." },
  icloud: { host:"smtp.mail.me.com", port:587, encryption:"starttls", authType:"plain", desc:"iCloud: 587 STARTTLS, use app-specific password." },
};

const el = id => document.getElementById(id);
let lastResult = null;
let currentLogFilter = "all";

function applyPreset(key){
  const p = presets[key];
  if(!p) return;
  el("presetDesc").textContent = p.desc;
  if(key!=="custom"){
    el("host").value = p.host;
    el("port").value = p.port;
    el("encryption").value = p.encryption;
    el("authType").value = p.authType;
    if(p.oauth){
      if(p.oauth.tokenEndpoint) el("oauthTokenEndpoint").value = p.oauth.tokenEndpoint;
      if(p.oauth.scope) el("oauthScope").value = p.oauth.scope;
      if(p.oauth.clientId) el("oauthClientId").value = p.oauth.clientId;
      if(p.oauth.user){ el("oauthUser").value = p.oauth.user; el("from").value = p.oauth.user; }
    } else {
      ["oauthTokenEndpoint","oauthScope","oauthClientId","oauthClientSecret","oauthToken"].forEach(id=> el(id).value = "");
    }
    if(key==="gmail") el("oauthUser").value = "";
  }
  updateAuthUI();
}

function updateAuthUI(){
  const at = el("authType").value;
  const isX = at==="xoauth2";
  const isNone = at==="none";
  el("authPlainBox").style.display = isX || isNone ? "none" : "block";
  el("authXoauthBox").style.display = isX ? "block" : "none";
  if(at==="plain") el("authHint").innerHTML = 'PLAIN: <code class="inline">AUTH PLAIN base64(\\\\0user\\\\0pass)</code> — most servers. Needs TLS (STARTTLS/SSL) or server may return 534.';
  else if(at==="login") el("authHint").innerHTML = 'LOGIN: <code class="inline">AUTH LOGIN</code> then 334 challenges for user/pass base64. Older clients, same creds as PLAIN.';
  else if(at==="xoauth2") el("authHint").innerHTML = 'XOAUTH2: <code class="inline">AUTH XOAUTH2 base64(user=...\\\\x01auth=Bearer ...)</code> — OAuth2 bearer token. Fill Client Credentials above to auto-fetch, or paste token directly.';
  else el("authHint").innerHTML = 'No AUTH — will try to send without authentication (open relay test, usually fails with 530).';
  if(isX && !el("oauthUser").value && el("username").value) el("oauthUser").value = el("username").value;
}

el("preset").addEventListener("change", e=> applyPreset(e.target.value));
el("authType").addEventListener("change", updateAuthUI);
el("togglePass").addEventListener("click", ()=>{
  const p = el("password");
  const isPass = p.type==="password";
  p.type = isPass ? "text" : "password";
  el("togglePass").textContent = isPass ? "Hide" : "Show";
});
el("toggleSecretBtn").addEventListener("click", ()=>{
  const p = el("oauthClientSecret");
  const isPass = p.type==="password";
  p.type = isPass ? "text" : "password";
  el("toggleSecretBtn").textContent = isPass ? "Hide secret" : "Show secret";
});
el("host").addEventListener("input", ()=> el("preset").value="custom");
el("port").addEventListener("input", ()=> {});

el("fetchTokenBtn").addEventListener("click", async ()=>{
  const endpoint = el("oauthTokenEndpoint").value.trim();
  const clientId = el("oauthClientId").value.trim();
  const secret = el("oauthClientSecret").value;
  const scope = el("oauthScope").value.trim();
  if(!endpoint || !clientId || !secret) return alert("Fill Token Endpoint, Client ID and Client Secret first");
  const btn = el("fetchTokenBtn");
  const orig = btn.textContent;
  btn.disabled=true; btn.textContent="⏳ Fetching…";
  el("oauthFetchResult").style.display="block";
  el("oauthFetchResult").textContent="Requesting token from " + endpoint + " ...";
  try{
    const res = await fetch("/api/oauth/token", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ tokenEndpoint:endpoint, clientId, clientSecret:secret, scope }) });
    const data = await res.json();
    if(!res.ok) throw new Error(data.error?.message || JSON.stringify(data));
    el("oauthToken").value = data.access_token;
    el("oauthFetchResult").innerHTML = "✅ Token acquired in " + (data.fetchedMs||"?") + "ms\\nType: " + (data.token_type||"Bearer") + " Expires: " + (data.expires_in||"?")+"s\\nPreview: " + data.access_token.slice(0,16)+"..."+data.access_token.slice(-6)+" (len="+data.access_token.length+")";
    el("oauthFetchResult").style.color="var(--pass)";
  }catch(e){
    el("oauthFetchResult").textContent = "❌ Failed: " + e.message;
    el("oauthFetchResult").style.color="var(--fail)";
  } finally{ btn.disabled=false; btn.textContent=orig; }
});

// Save/load
el("saveBtn").addEventListener("click", ()=>{
  const cfg = collectConfig();
  localStorage.setItem("smtpTesterConfig", JSON.stringify(cfg));
  alert("Config saved to localStorage");
});
el("loadBtn").addEventListener("click", ()=>{
  try{
    const cfg = JSON.parse(localStorage.getItem("smtpTesterConfig")||"");
    if(!cfg) return alert("No saved config");
    if(cfg.host) el("host").value=cfg.host;
    if(cfg.port) el("port").value=cfg.port;
    if(cfg.encryption) el("encryption").value=cfg.encryption;
    if(cfg.authType) el("authType").value=cfg.authType;
    if(cfg.username) el("username").value=cfg.username;
    if(cfg.password) el("password").value=cfg.password;
    if(cfg.oauthUser) el("oauthUser").value=cfg.oauthUser;
    if(cfg.oauthTokenEndpoint) el("oauthTokenEndpoint").value=cfg.oauthTokenEndpoint;
    if(cfg.oauthScope) el("oauthScope").value=cfg.oauthScope;
    if(cfg.oauthClientId) el("oauthClientId").value=cfg.oauthClientId;
    if(cfg.oauthToken) el("oauthToken").value=cfg.oauthToken;
    if(cfg.from) el("from").value=cfg.from;
    if(cfg.to) el("to").value=cfg.to;
    if(cfg.subject) el("subject").value=cfg.subject;
    if(cfg.body) el("body").value=cfg.body;
    updateAuthUI();
    alert("Loaded");
  }catch(e){ alert("Load failed: "+e.message); }
});
el("copyCurlBtn").addEventListener("click", ()=>{
  const cfg = collectConfigForApi();
  const curl = 'curl -X POST ' + location.origin + '/api/test \\\n  -H "Content-Type: application/json" \\\n  -d \\'' + JSON.stringify(cfg, null, 2).replace(/'/g, "'\\\\''") + '\\'';
  navigator.clipboard.writeText(curl).then(()=> alert("cURL copied"), ()=> prompt("Copy cURL:", curl));
});

function collectConfig(){
  return {
    preset: el("preset").value,
    host: el("host").value.trim(),
    port: parseInt(el("port").value,10),
    encryption: el("encryption").value,
    authType: el("authType").value,
    username: el("username").value.trim(),
    password: el("password").value,
    oauthUser: el("oauthUser").value.trim(),
    oauthTokenEndpoint: el("oauthTokenEndpoint").value.trim(),
    oauthScope: el("oauthScope").value.trim(),
    oauthClientId: el("oauthClientId").value.trim(),
    oauthClientSecret: el("oauthClientSecret").value,
    oauthToken: el("oauthToken").value.trim(),
    from: el("from").value.trim(),
    to: el("to").value.trim(),
    subject: el("subject").value,
    body: el("body").value,
    timeout: parseInt(el("timeout").value,10),
  };
}
function collectConfigForApi(){
  const c = collectConfig();
  const body = c.body.replace("{{now}}", new Date().toISOString());
  let authUser = c.username;
  let xoauth2Token = undefined;
  if(c.authType==="xoauth2"){
    authUser = c.oauthUser || c.username || c.from;
    xoauth2Token = c.oauthToken || undefined;
  }
  return {
    host: c.host,
    port: c.port,
    encryption: c.encryption,
    authType: c.authType,
    username: authUser,
    password: c.password,
    xoauth2Token,
    oauthTokenEndpoint: c.oauthTokenEndpoint || undefined,
    oauthClientId: c.oauthClientId || undefined,
    oauthClientSecret: c.oauthClientSecret || undefined,
    oauthScope: c.oauthScope || undefined,
    from: c.from || authUser,
    to: c.to,
    subject: c.subject,
    body: body,
    timeoutMs: c.timeout,
  };
}

function renderChecklist(checklist){
  const c = el("checklist");
  c.innerHTML="";
  for(const item of checklist){
    const iconCls = item.status;
    const iconChar = item.status==="pass" ? "✓" : item.status==="fail" ? "✕" : item.status==="skip" ? "–" : item.status==="running" ? "◷" : "○";
    const div = document.createElement("div");
    div.className="check-item";
    div.innerHTML = \`
      <div class="check-icon \${iconCls}">\${iconChar}</div>
      <div class="check-main">
        <div class="check-title">\${escapeHtml(item.label)} <span class="pill \${item.status}" style="margin-left:8px; font-size:10px;">\${item.status.toUpperCase()}\${item.durationMs? ' · '+item.durationMs+'ms':''}</span> \${item.errorCode? '<span class="badge badge-plain" style="margin-left:6px;">'+escapeHtml(item.errorCode)+'</span>':''}</div>
        \${item.detail? '<div class="check-detail">'+escapeHtml(item.detail)+'</div>':''}
        \${item.explanation? '<div class="check-explain '+(item.status==="pass"?'pass':'')+'"><b>Why:</b> '+escapeHtml(item.explanation)+'</div>':''}
      </div>
    \`;
    c.appendChild(div);
  }
}

function renderLogs(logs){
  const container = el("logs");
  let filtered = logs;
  if(currentLogFilter!=="all") filtered = logs.filter(l=> l.direction===currentLogFilter);
  container.innerHTML="";
  for(const l of filtered){
    const div = document.createElement("div");
    div.className="log-line";
    div.innerHTML = \`<span class="log-ts">\${new Date(l.ts).toLocaleTimeString()}.\${String(new Date(l.ts).getMilliseconds()).padStart(3,'0')}</span><span class="log-dir \${l.direction}">\${l.direction}</span><span class="log-msg">\${escapeHtml(l.message)}</span>\`;
    div.title="Click to copy";
    div.style.cursor="pointer";
    div.addEventListener("click", ()=> {
      navigator.clipboard.writeText(l.raw || l.message);
      div.style.background="rgba(56,189,248,0.08)";
      setTimeout(()=> div.style.background="", 400);
    });
    container.appendChild(div);
  }
  el("logCount").textContent = \`\${filtered.length} / \${logs.length} lines\`;
}

function escapeHtml(s){
  if(!s) return "";
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

document.querySelectorAll("#logFilter button").forEach(b=>{
  b.addEventListener("click", ()=>{
    document.querySelectorAll("#logFilter button").forEach(x=>x.classList.remove("active"));
    b.classList.add("active");
    currentLogFilter = b.dataset.filter;
    if(lastResult) renderLogs(lastResult.logs);
  });
});

el("copyLogsBtn").addEventListener("click", ()=>{
  if(!lastResult) return;
  const text = lastResult.logs.map(l=> \`[\${l.ts}] \${l.direction} \${l.message}\`).join("\\n");
  navigator.clipboard.writeText(text).then(()=> alert("Logs copied"));
});
el("downloadBtn").addEventListener("click", ()=>{
  if(!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult,null,2)], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const a=document.createElement("a"); a.href=url; a.download="smtp-test-" + Date.now() + ".json"; a.click(); URL.revokeObjectURL(url);
});

async function runTest(){
  const cfg = collectConfigForApi();
  if(!cfg.host) return alert("Host required");
  if(!cfg.port) return alert("Port required");
  if(!cfg.to) return alert("Recipient (To) required");
  if(!cfg.from) cfg.from = cfg.username || "tester@example.com";
  if(cfg.authType!=="none" && cfg.authType!=="xoauth2" && (!cfg.username || !cfg.password)) {
    if(!confirm("Username/password empty for auth "+cfg.authType+" — continue?")) return;
  }
  if(cfg.authType==="xoauth2"){
    const hasCredentials = !!(cfg.oauthTokenEndpoint && cfg.oauthClientId && cfg.oauthClientSecret);
    if(!cfg.xoauth2Token && !hasCredentials) return alert("XOAUTH2 requires either Access Token or OAuth2 Client Credentials (Token Endpoint + Client ID + Secret)");
  }

  const btn = el("testBtn");
  const orig = btn.innerHTML;
  btn.disabled=true; btn.innerHTML="⏳ Testing… please wait";
  el("resultsEmpty").style.display="none";
  el("resultsContent").style.display="block";
  el("summaryBox").innerHTML='<div style="color:var(--muted); font-size:13px;">Running checklist… this may take up to '+(cfg.timeoutMs/1000)+'s. Watch logs below for live transcript (logs appear after completion).</div>';
  el("checklist").innerHTML='<div class="check-item"><div class="check-icon running">◷</div><div class="check-main"><div class="check-title">Connecting to '+escapeHtml(cfg.host)+':'+cfg.port+'</div><div class="check-detail">Establishing TCP connection, waiting for 220 greeting…</div></div></div>';
  el("logs").innerHTML='<div style="padding:20px; color:var(--muted); text-align:center;">⏳ Running — transcript will appear when test completes…</div>';
  el("oauthBox").style.display="none";
  el("errorBox").style.display="none";

  try{
    const res = await fetch("/api/test", { method:"POST", headers:{ "Content-Type":"application/json" }, body: JSON.stringify(cfg) });
    const data = await res.json();
    if(!res.ok){
      throw new Error(data.error?.message || data.message || "Request failed with "+res.status);
    }
    lastResult = data;
    renderResult(data);
  }catch(e){
    el("summaryBox").className="summary-box fail";
    el("summaryBox").innerHTML='<div class="summary-title">❌ Test Request Failed</div><div class="summary-sub">'+escapeHtml(e.message)+'</div><div style="margin-top:8px; font-size:11px; color:var(--muted);">This is a frontend/fetch error, not SMTP. Check tester logs, CORS, or network. If running locally, ensure dev server is up on port 8787.</div>';
    el("checklist").innerHTML="";
    el("logs").innerHTML="";
  } finally{
    btn.disabled=false; btn.innerHTML=orig;
  }
}

function renderResult(data){
  const box = el("summaryBox");
  box.className = "summary-box " + (data.success ? "success" : "fail");
  const icon = data.success ? "✅" : "❌";
  box.innerHTML = \`
    <div class="summary-title">\${icon} \${escapeHtml(data.summary)}</div>
    <div class="summary-sub">Host <b>\${escapeHtml(data.host)}:\${data.port}</b> · Encryption <b>\${escapeHtml(data.encryption)}</b> · Auth <b>\${escapeHtml(data.authType)}</b> · Total \${data.timings.totalMs}ms</div>
    \${data.success ? '<div style="margin-top:8px; font-size:12px;">Message was accepted by server (250 after DATA). Check recipient inbox (and spam folder). Some providers delay delivery.</div>' : ''}
  \`;
  el("reportMeta").style.display="inline-flex";
  el("reportMeta").textContent = (data.success ? "PASS" : "FAIL") + " · " + data.checklist.filter(c=>c.status==="pass").length + "/" + data.checklist.length + " passed";
  el("reportMeta").className = "pill " + (data.success ? "pass" : "fail");
  el("timings").textContent = "Total " + data.timings.totalMs + "ms" + (data.timings.connectMs? " · connect "+data.timings.connectMs+"ms":"") + (data.timings.oauthMs? " · oauth "+data.timings.oauthMs+"ms":"") + (data.timings.tlsMs? " · tls "+data.timings.tlsMs+"ms":"") + (data.timings.authMs? " · auth "+data.timings.authMs+"ms":"");

  renderChecklist(data.checklist);

  const oauthBox = el("oauthBox");
  if(data.oauth && data.oauth.attempted){
    oauthBox.style.display="block";
    const o = data.oauth;
    if(o.success){
      el("oauthDetail").innerHTML = \`<span class="pill pass">PASS</span> <b>Token Endpoint:</b> \${escapeHtml(o.tokenEndpoint||"")} <br><b>Client ID:</b> \${escapeHtml(o.clientId||"")} <br><b>Scope:</b> \${escapeHtml(o.scope||"")} <br><b>Token:</b> \${escapeHtml(o.tokenPreview||"")} <br><b>Expires In:</b> \${o.expiresIn||"?"}s <b>Type:</b> \${escapeHtml(o.tokenType||"Bearer")} <br><span style="color:var(--pass);">✓ OAuth2 token fetched successfully and used for SMTP XOAUTH2.</span>\`;
      el("oauthDetail").style.color="#cbd5e1";
    } else {
      el("oauthDetail").innerHTML = \`<span class="pill fail">FAIL</span> <b>Token Endpoint:</b> \${escapeHtml(o.tokenEndpoint||"")} <br><b>Scope:</b> \${escapeHtml(o.scope||"")} <br><b>Error:</b> \${escapeHtml(o.error||"")} <br><b>Code:</b> \${escapeHtml(o.errorCode||"")} <br><div class="check-explain" style="margin-top:8px;"><b>Why:</b> \${escapeHtml(o.explanation||"")}</div>\`;
    }
  } else {
    oauthBox.style.display="none";
  }

  const errBox = el("errorBox");
  if(data.error){
    errBox.style.display="block";
    el("errorDetail").innerHTML = \`
      <div><b>Code:</b> <code class="inline">\${escapeHtml(data.error.code)}</code> &nbsp; <b>Message:</b> \${escapeHtml(data.error.message)}</div>
      <div style="margin-top:6px;"><b>Why it failed:</b> \${escapeHtml(data.error.explanation)}</div>
      \${data.error.remediation? '<div style="margin-top:6px;"><b>How to fix:</b> '+escapeHtml(data.error.remediation)+'</div>':''}
    \`;
  } else {
    errBox.style.display="none";
  }

  renderLogs(data.logs);
}

el("testBtn").addEventListener("click", runTest);

// Initialize
applyPreset("outlook");
try{
  const qs = new URLSearchParams(location.search);
  if(qs.get("host")) el("host").value=qs.get("host");
  if(qs.get("port")) el("port").value=qs.get("port");
  if(qs.get("user")) { el("username").value=qs.get("user"); el("oauthUser").value=qs.get("user"); }
  if(qs.get("from")) el("from").value=qs.get("from");
  if(qs.get("to")) el("to").value=qs.get("to");
}catch{}

document.addEventListener("keydown", e=>{
  if(e.key==="Enter" && (e.metaKey||e.ctrlKey)) runTest();
});
</script>
</body>
</html>`;

export default {
  async fetch(request: Request, env: any, ctx: any): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (url.pathname === "/api/oauth/token" && method === "POST") {
      try {
        const body: any = await request.json();
        const tokenEndpoint = body.tokenEndpoint || body.token_endpoint || body.endpoint;
        const clientId = body.clientId || body.client_id;
        const clientSecret = body.clientSecret || body.client_secret;
        const scope = body.scope;
        if (!tokenEndpoint || !clientId || !clientSecret) {
          return jsonResponse({ error: { code: "BAD_REQUEST", message: "tokenEndpoint, clientId, clientSecret are required" } }, 400);
        }
        const start = Date.now();
        // Reuse same logic as smtp token fetch - inline minimal
        let normalizedScope = (scope || "https://outlook.office365.com/.default").trim();
        if (normalizedScope.includes(",")) normalizedScope = normalizedScope.split(",").map((s:string)=>s.trim()).filter(Boolean).join(" ");
        const params = new URLSearchParams();
        params.set("grant_type", "client_credentials");
        params.set("client_id", clientId);
        params.set("client_secret", clientSecret);
        params.set("scope", normalizedScope);
        const controller = new AbortController();
        const t = setTimeout(()=>controller.abort(), 10000);
        let resp: Response;
        try{
          resp = await fetch(tokenEndpoint, { method:"POST", headers:{ "Content-Type":"application/x-www-form-urlencoded", "Accept":"application/json" }, body: params.toString(), signal: controller.signal });
        } finally{ clearTimeout(t); }
        const text = await resp.text();
        let json:any=null; try{ json=JSON.parse(text);}catch{}
        if(!resp.ok){
          const errMsg = json ? (json.error_description || json.error || text).slice(0,800) : text.slice(0,800);
          return jsonResponse({ error: { code: json?.error || "OAUTH_FAILED", message: errMsg, raw:text.slice(0,1000) } }, 400);
        }
        if(!json || !json.access_token) return jsonResponse({ error:{ code:"OAUTH_NO_TOKEN", message:"No access_token in response: "+text.slice(0,500)}}, 400);
        return jsonResponse({ access_token: json.access_token, token_type: json.token_type, expires_in: json.expires_in, scope: json.scope, fetchedMs: Date.now()-start }, 200);
      } catch(e:any){
        return jsonResponse({ error:{ code: e.code || "INTERNAL", message: e.message || String(e) } }, 500);
      }
    }

    if (url.pathname === "/api/test" && method === "POST") {
      try {
        const body = (await request.json()) as SmtpTestRequest;
        if (!body.host || !body.port || !body.from || !body.to) {
          return jsonResponse({ error: { code: "BAD_REQUEST", message: "host, port, from, to are required" } }, 400);
        }
        if (!body.encryption) body.encryption = "auto";
        if (!body.authType) body.authType = "plain";
        if (!body.timeoutMs) body.timeoutMs = 12000;
        body.port = Number(body.port);
        if (isNaN(body.port) || body.port < 1 || body.port > 65535) {
          return jsonResponse({ error: { code: "BAD_PORT", message: "Invalid port" } }, 400);
        }
        body.timeoutMs = Math.min(Math.max(Number(body.timeoutMs) || 12000, 3000), 30000);

        const result = await testSmtp(body);
        return jsonResponse(result, 200);
      } catch (e: any) {
        console.error("API error", e);
        return jsonResponse({ error: { code: e.code || "INTERNAL", message: e.message || String(e), explanation: e.explanation }, stack: e.stack }, 500);
      }
    }

    if (url.pathname === "/api/health") {
      return jsonResponse({ ok: true, time: new Date().toISOString() });
    }

    if (url.pathname === "/api/presets") {
      return jsonResponse({
        gmail: { host: "smtp.gmail.com", port: 587, encryption: "starttls", authType: "xoauth2" },
        outlook: { host: "smtp.office365.com", port: 587, encryption: "starttls", authType: "xoauth2" },
      });
    }

    if (method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      return new Response(HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...corsHeaders() },
      });
    }

    if (url.pathname.startsWith("/api/")) {
      return jsonResponse({ error: { code: "NOT_FOUND", message: "Not found: " + url.pathname } }, 404);
    }

    return new Response(HTML, {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...corsHeaders() },
    });
  },
} satisfies ExportedHandler;

function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function jsonResponse(data: any, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders() },
  });
}
