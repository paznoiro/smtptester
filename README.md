# SMTP Tester

UI to test any SMTP server with **step-by-step diagnostics** and **clear failure explanations**. Supports `PLAIN`, `LOGIN`, `XOAUTH2` (OAuth 2.0) with automatic token fetch, and shows a checklist of what passed / failed plus a full raw transcript.

**Live app:** [https://smtptester.authkeystone.com/](https://smtptester.authkeystone.com/)

## Features
- **Checklist**: OAuth2 token fetch → DNS/TCP connect → Greeting (220) → EHLO → STARTTLS/TLS → AUTH → MAIL FROM → RCPT TO → DATA → QUIT — each with pass/fail/skip, duration, error code and human explanation
- **Detailed errors**: DNS failed, connection refused/timeout, TLS handshake failed, cert invalid, STARTTLS not supported, auth failed (535), OAuth fetch failed, XOAUTH2 token expired, relay denied (550), etc. with remediation
- **Logs**: timestamped `C` (client) / `S` (server) / `INFO` / `ERROR` transcript, filterable, copyable, downloadable as JSON
- **Presets**: Gmail, Outlook/Office365, Yahoo, SendGrid, SES, Mailgun, Brevo, Zoho, iCloud — auto-fills host/port/encryption/auth but fully editable
- **Auth**: `AUTH PLAIN` (`\0user\0pass` base64), `AUTH LOGIN` (334 challenges), `XOAUTH2` (`user=…\x01auth=Bearer …\x01\x01` base64)
- **OAuth2 auto-fetch**: Provide Token Endpoint, Client ID, Client Secret, Scopes (comma separated) + User email; tester does `client_credentials` grant and uses the token for XOAUTH2. Details shown in report.
- **Encryption**: `None`, `STARTTLS`, `SSL/TLS` (implicit), `Auto` (by port: 465→SSL, 587/25/2525→STARTTLS)
- **Runs locally** via `npm run dev` and deploys via `npm run deploy` using secure TCP sockets (`secureTransport: "on" | "starttls" | "off"` + `startTls()`)

## Quick start (local)

```bash
npm install
npm run dev
# → http://localhost:8787
```

Deploy:

```bash
npm run deploy
# → production: https://smtptester.authkeystone.com/
```

## XOAUTH2 — Outlook/Office365 example

Fill **User**, **Token Endpoint**, **Scopes**, **Client ID**, **Client Secret** and click **🔑 Fetch Token Now** to test token acquisition alone, or directly click **Run SMTP Test** — the tester will fetch the token first (shown as `OAuth2 Token Acquire` in checklist) then do SMTP XOAUTH2. Report includes OAuth2 details on success/failure (endpoint, scope, token preview, expires_in).

Example values for Microsoft 365:

- User: `user@example.com`
- Token Endpoint: `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token`
- Scopes: `https://outlook.office365.com/.default`
- Client ID: `your-client-id`
- Client Secret: *(you fill)*

You can also paste an existing access token in **Or paste Access Token directly** field — if client credentials are empty, the pasted token is used.

Generic `client_credentials` request made by tester:

```
POST {tokenEndpoint}
Content-Type: application/x-www-form-urlencoded
grant_type=client_credentials&client_id=xxx&client_secret=yyy&scope=https://outlook.office365.com/.default
```

Scopes comma-separated in UI become space-separated for the request.

## API

### POST /api/test
Test SMTP and return checklist + logs. For XOAUTH2 you can either provide `xoauth2Token` directly or provide `oauthTokenEndpoint` + `oauthClientId` + `oauthClientSecret` + `oauthScope` for auto-fetch.

```bash
curl -X POST http://localhost:8787/api/test \
  -H "Content-Type: application/json" \
  -d '{
    "host": "smtp.office365.com",
    "port": 587,
    "encryption": "starttls",
    "authType": "xoauth2",
    "username": "user@example.com",
    "oauthTokenEndpoint": "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token",
    "oauthClientId": "YOUR_CLIENT_ID",
    "oauthClientSecret": "YOUR_SECRET",
    "oauthScope": "https://outlook.office365.com/.default",
    "from": "user@example.com",
    "to": "recipient@example.com",
    "subject": "Hello",
    "body": "Test body",
    "timeoutMs": 12000
  }'
```

XOAUTH2 with direct token:

```json
{
  "host": "smtp.office365.com",
  "port": 587,
  "encryption": "starttls",
  "authType": "xoauth2",
  "username": "user@example.com",
  "xoauth2Token": "eyJ0eXAiOiJKV1QiLC...",
  "from": "user@example.com",
  "to": "recipient@example.com"
}
```

PLAIN example:

```json
{
  "host": "smtp.gmail.com",
  "port": 587,
  "encryption": "starttls",
  "authType": "plain",
  "username": "user@gmail.com",
  "password": "abcd efgh ijkl mnop",
  "from": "user@gmail.com",
  "to": "recipient@example.com"
}
```

### POST /api/oauth/token
Fetch OAuth2 token only (used by UI Fetch Token button).

```bash
curl -X POST http://localhost:8787/api/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "tokenEndpoint": "https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token",
    "clientId": "YOUR_CLIENT_ID",
    "clientSecret": "YOUR_SECRET",
    "scope": "https://outlook.office365.com/.default"
  }'
```

Response:

```json
{
  "success": false,
  "summary": "❌ Failed at auth after 1234ms. Passed 5/10 checks. Failed: Authentication (XOAUTH2)",
  "checklist": [
    { "id": "oauth", "label": "OAuth2 Token Acquire", "status": "pass", "detail": "Token acquired in 412ms type=Bearer expires_in=3599 len=1232 preview=eyJ0e...IUzI1Ni (len=1232)" },
    { "id": "dns", "label": "DNS & TCP Connect to smtp.office365.com:587", "status": "pass" },
    { "id": "auth", "label": "Authentication (XOAUTH2)", "status": "fail", "errorCode": "XOAUTH2_FAILED", "explanation": "..." }
  ],
  "oauth": {
    "attempted": true,
    "success": true,
    "tokenEndpoint": "https://login.microsoftonline.com/.../oauth2/v2.0/token",
    "scope": "https://outlook.office365.com/.default",
    "clientId": "YOUR_CLIENT_ID",
    "tokenPreview": "eyJ0eXAiOi...cCI6IkpXVCJ (len=1232)",
    "expiresIn": 3599,
    "tokenType": "Bearer"
  },
  "logs": [ { "ts": "...", "direction": "INFO", "message": "OAuth2: token acquired ..." } ],
  "timings": { "totalMs": 2345, "oauthMs": 412, "connectMs": 120 }
}
```

### GET /api/health
Health check.

### GET /
Serves the UI.

## Presets

| Preset | Host | Port | Encryption | Auth |
|--------|------|------|------------|------|
| Gmail | smtp.gmail.com | 587 (or 465) | STARTTLS | XOAUTH2 / PLAIN (App Password) |
| Outlook | smtp.office365.com | 587 | STARTTLS | XOAUTH2 (client_credentials) |
| Yahoo | smtp.mail.yahoo.com | 587 | STARTTLS | PLAIN |
| SendGrid | smtp.sendgrid.net | 587 | STARTTLS | PLAIN (apikey) |
| SES | email-smtp.us-east-1.amazonaws.com | 587 | STARTTLS | PLAIN |
| Mailgun | smtp.mailgun.org | 587 | STARTTLS | PLAIN |
| Brevo | smtp-relay.brevo.com | 587 | STARTTLS | PLAIN |
| Zoho | smtp.zoho.com | 587 | STARTTLS | PLAIN |
| iCloud | smtp.mail.me.com | 587 | STARTTLS | PLAIN |

Change any field after selecting preset.

## Failure glossary (shown in UI)

- **DNS_FAILED** — hostname typo / no DNS record → check spelling, `dig`
- **CONNECTION_REFUSED / TCP_TIMEOUT** — firewall, port blocked, ISP blocks 25 → try 587/465/2525, `telnet host port`, `openssl s_client`
- **TLS_HANDSHAKE_FAILED / TLS_CERT_INVALID** — wrong encryption mode or expired/self-signed cert → swap STARTTLS↔SSL, test with `openssl s_client -starttls smtp -connect host:port`
- **STARTTLS_NOT_SUPPORTED** — server plaintext only → use `none` or `auto`
- **OAUTH_FAILED / OAUTH_INVALID_CLIENT / OAUTH_INVALID_SCOPE** — token endpoint, client ID/secret, or scope wrong → check tenant ID in URL, scope `.default`, secret expiry, admin consent
- **AUTH_FAILED 535/534** — bad creds, need App Password, or TLS required → check user=full email, generate App Password, ensure STARTTLS before AUTH
- **XOAUTH2_FAILED 334 + JSON** — token expired (1h), wrong scope, user mismatch
- **RELAY_DENIED 550/553** — FROM not allowed or relay denied → ensure FROM matches auth user

## Project structure

```
src/
  index.ts  — Worker fetch handler + UI HTML
  smtp.ts   — SMTP engine (TCP sockets, checklist, logs, OAuth2 fetch)
wrangler.jsonc
package.json
tsconfig.json
```

## Tech notes

- Uses `connect()` with `secureTransport: "on" | "starttls" | "off"` for SMTP. For STARTTLS: `connect(..., {secureTransport:"starttls"})` → `EHLO` → `STARTTLS` → `socket.startTls()` → `EHLO` again.
- Line reader buffers `ReadableStream<Uint8Array>` and parses SMTP multi-line responses (`250-` vs `250 `).
- Passwords/tokens/secrets redacted in logs (`<credentials hidden>` / `<token hidden>`).
- OAuth2 `client_credentials` flow: `grant_type=client_credentials` + `client_id` + `client_secret` + `scope` (comma→space normalized).

## License

MIT
