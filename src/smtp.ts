import { connect } from "cloudflare:sockets";

export type EncryptionMode = "none" | "starttls" | "ssl" | "auto";
export type AuthType = "none" | "plain" | "login" | "xoauth2" | "cram-md5";

export interface SmtpTestRequest {
  host: string;
  port: number;
  encryption: EncryptionMode;
  authType: AuthType;
  username?: string;
  password?: string;
  xoauth2Token?: string;
  // OAuth2 client credentials - if provided, tester will fetch token automatically
  oauthTokenEndpoint?: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthScope?: string; // comma separated or single scope
  from: string;
  to: string;
  subject?: string;
  body?: string;
  timeoutMs?: number; // default 10000
}

export interface LogEntry {
  ts: string;
  direction: "C" | "S" | "INFO" | "ERROR";
  message: string;
  raw?: string;
}

export interface ChecklistItem {
  id: string;
  label: string;
  status: "pending" | "pass" | "fail" | "skip" | "running";
  detail?: string;
  errorCode?: string;
  explanation?: string;
  durationMs?: number;
}

export interface OAuthResult {
  attempted: boolean;
  success: boolean;
  tokenEndpoint?: string;
  scope?: string;
  clientId?: string;
  tokenPreview?: string;
  expiresIn?: number;
  tokenType?: string;
  error?: string;
  errorCode?: string;
  explanation?: string;
}

export interface SmtpTestResult {
  success: boolean;
  summary: string;
  host: string;
  port: number;
  encryption: string;
  authType: string;
  checklist: ChecklistItem[];
  logs: LogEntry[];
  capabilities?: string[];
  oauth?: OAuthResult;
  error?: {
    code: string;
    message: string;
    explanation: string;
    remediation?: string;
  };
  timings: {
    totalMs: number;
    connectMs?: number;
    tlsMs?: number;
    authMs?: number;
    oauthMs?: number;
  };
}

// Helper for base64
function b64encode(str: string): string {
  // Workers have btoa, Node has Buffer. Use both.
  if (typeof btoa !== "undefined") {
    // btoa expects binary string; handle utf8 via TextEncoder + fromCharCode
    const bytes = new TextEncoder().encode(str);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
  } else {
    // @ts-ignore
    return Buffer.from(str, "utf-8").toString("base64");
  }
}

function b64decode(str: string): string {
  if (typeof atob !== "undefined") {
    const binary = atob(str);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } else {
    // @ts-ignore
    return Buffer.from(str, "base64").toString("utf-8");
  }
}

function b64UrlDecode(str: string): string {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad) b64 += "=".repeat(4 - pad);
  return b64decode(b64);
}

function decodeJwtPayload(token: string): any | null {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const payload = b64UrlDecode(parts[1]);
    return JSON.parse(payload);
  } catch { return null; }
}

class SmtpSocket {
  private socket: any;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private decoder = new TextDecoder();
  private encoder = new TextEncoder();
  private buffer = "";
  private closed = false;

  constructor(socket: any) {
    this.socket = socket;
    this.attach(socket);
  }

  private attach(socket: any) {
    this.socket = socket;
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
  }

  async startTls(): Promise<void> {
    // Need to release reader/writer before upgrade - old socket closed, get new socket via startTls()
    try {
      // Release locks if possible
      try { this.reader?.releaseLock(); } catch {}
      try { this.writer?.releaseLock(); } catch {}
    } catch {}
    const secure = this.socket.startTls();
    this.attach(secure);
    // Optionally wait for opened? The new socket's opened may already be resolved since TLS handshake happens.
    // But we still want to await if available.
    if (secure.opened) {
      try { await secure.opened; } catch (e) { /* handshake failed will throw */ }
    }
  }

  async writeLine(line: string): Promise<void> {
    if (!this.writer) throw new Error("Writer not initialized");
    const data = this.encoder.encode(line);
    await this.writer.write(data);
  }

  async readLine(timeoutMs: number): Promise<string> {
    const start = Date.now();
    while (true) {
      const newlineIdx = this.buffer.indexOf("\r\n");
      if (newlineIdx !== -1) {
        const line = this.buffer.slice(0, newlineIdx);
        this.buffer = this.buffer.slice(newlineIdx + 2);
        return line;
      }
      if (Date.now() - start > timeoutMs) {
        throw new Error(`READ_TIMEOUT: Timed out waiting for server response after ${timeoutMs}ms`);
      }
      if (!this.reader) throw new Error("Reader not initialized");
      // Race read with timeout remaining
      const remaining = timeoutMs - (Date.now() - start);
      const result = await Promise.race([
        this.reader.read(),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("READ_TIMEOUT")), remaining > 0 ? remaining : 0)),
      ]) as ReadableStreamReadResult<Uint8Array>;
      if (result.done) {
        if (this.buffer.length > 0) {
          const line = this.buffer;
          this.buffer = "";
          return line;
        }
        throw new Error("CONNECTION_CLOSED: Server closed connection unexpectedly");
      }
      if (result.value) {
        this.buffer += this.decoder.decode(result.value, { stream: true });
      }
    }
  }

  // Reads SMTP multi-line response. Returns { code, lines, raw }
  async readResponse(timeoutMs: number): Promise<{ code: number; lines: string[]; raw: string; isPositive: boolean }> {
    const lines: string[] = [];
    let raw = "";
    while (true) {
      const line = await this.readLine(timeoutMs);
      raw += line + "\r\n";
      lines.push(line);
      if (line.length < 4) {
        throw new Error(`INVALID_RESPONSE: Malformed SMTP response: "${line}"`);
      }
      const codeStr = line.substring(0, 3);
      const sep = line[3];
      const code = parseInt(codeStr, 10);
      if (isNaN(code)) throw new Error(`INVALID_RESPONSE: Invalid SMTP code in "${line}"`);
      if (sep === " ") {
        return {
          code,
          lines,
          raw,
          isPositive: code >= 200 && code < 400,
        };
      } else if (sep === "-") {
        continue;
      } else {
        throw new Error(`INVALID_RESPONSE: Unexpected separator "${sep}" in "${line}"`);
      }
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    try { this.reader?.releaseLock(); } catch {}
    try { this.writer?.releaseLock(); } catch {}
    try { await this.socket.close(); } catch {}
  }

  get rawSocket(): any { return this.socket; }
}

function nowIso(): string {
  return new Date().toISOString();
}

function classifyError(err: any, context: string): { code: string; explanation: string; remediation?: string } {
  const msg = (err?.message || String(err)).toLowerCase();
  const rawMsg = err?.message || String(err);

  // DNS
  if (msg.includes("dns") || msg.includes("getaddrinfo") || msg.includes("enotfound") || msg.includes("name not resolved") || msg.includes("failed to resolve") || msg.includes("could not resolve")) {
    return {
      code: "DNS_FAILED",
      explanation: `DNS resolution failed for host. The hostname "${context}" could not be resolved to an IP address. This means the SMTP server address is incorrect, typo, or DNS is not propagating.`,
      remediation: "Verify hostname spelling. Try using IP directly. Check DNS with dig/nslookup. Ensure the tester can resolve external host."
    };
  }
  if (msg.includes("proxy request failed") || msg.includes("cannot connect to the specified address") || msg.includes("failed to connect")) {
    // Worker proxy error - covers DNS, TLS mismatch, firewall, etc.
    const isTlsMismatchHint = context.includes("587") || context.includes("465") || context.includes("25");
    return {
      code: "CONNECTION_FAILED",
      explanation: `TCP connection failed: ${rawMsg}. Tester could not establish TCP to ${context}. ${isTlsMismatchHint ? "Common cause is TLS mode mismatch: trying implicit SSL (secureTransport=on) on a STARTTLS port (587/25) or vice-versa. Also possible firewall blocks port or host is wrong." : "Host may be unreachable, DNS failed, or port blocked."}`,
      remediation: "Check host/port. For Gmail: 587 → STARTTLS, 465 → SSL/TLS. For Office365: 587 STARTTLS. Test with openssl s_client -connect host:port and -starttls smtp. If host is *.invalid, it's intentionally unresolvable for testing. Verify encryption dropdown matches port."
    };
  }
  if (msg.includes("timed out") || msg.includes("timeout") || msg.includes("read_timeout")) {
    if (context.includes("connect") || context.includes("tcp")) {
      return {
        code: "TCP_TIMEOUT",
        explanation: `TCP connection timed out. Server at ${context} did not respond within timeout. Port may be blocked, firewall dropping packets, or server is overloaded.`,
        remediation: "Check port is correct (587/465/25/2525). Verify firewall/security groups allow outbound. Try telnet/nc to test reachability. Some ISPs block port 25."
      };
    }
    return {
      code: "RESPONSE_TIMEOUT",
      explanation: `Server timed out waiting for response during ${context}. Server is reachable but not responding to SMTP commands. Possibly overloaded or requiring different protocol.`,
      remediation: "Try increasing timeout. Check server logs. Verify you are speaking SMTP to correct port (e.g., not HTTP port)."
    };
  }
  if (msg.includes("connection refused") || msg.includes("econnrefused") || msg.includes("refused")) {
    return {
      code: "CONNECTION_REFUSED",
      explanation: `TCP connection was actively refused. The server is reachable but no service is listening on that port, or firewall is rejecting.`,
      remediation: "Double-check host and port. For Gmail use 587/465, not 25. Ensure server accepts external connections. Check if provider requires VPN or whitelist."
    };
  }
  if (msg.includes("connection closed") || msg.includes("econnreset") || msg.includes("reset") || msg.includes("closed")) {
    return {
      code: "CONNECTION_CLOSED",
      explanation: `Connection was closed abruptly by remote host during ${context}. Likely TLS mismatch, protocol error, or server policy (e.g., IP blocked).`,
      remediation: "If using STARTTLS on 465, switch to SSL/TLS. If using SSL on 587, switch to STARTTLS. Check server requires specific TLS version."
    };
  }
  if (msg.includes("tls") || msg.includes("ssl") || msg.includes("handshake") || msg.includes("certificate") || msg.includes("secure")) {
    if (msg.includes("certificate") || msg.includes("cert")) {
      return {
        code: "TLS_CERT_INVALID",
        explanation: `TLS handshake failed due to certificate issue: ${rawMsg}. Server presented invalid/self-signed/expired certificate or hostname mismatch.`,
        remediation: "Verify hostname matches certificate CN/SAN. For self-signed, some servers use custom CA. Check if server requires SNI or has expired cert via openssl s_client."
      };
    }
    return {
      code: "TLS_HANDSHAKE_FAILED",
      explanation: `TLS handshake failed: ${rawMsg}. Encryption negotiation failed - possibly unsupported TLS version, cipher mismatch, or server expects different encryption mode.`,
      remediation: "Try switching between STARTTLS and SSL/TLS. Ensure server supports TLS 1.2+. Test with openssl s_client -starttls smtp -connect host:port. Some old servers only support TLS 1.0."
    };
  }
  if (msg.includes("auth") || msg.includes("535") || msg.includes("534") || msg.includes("334")) {
    return {
      code: "AUTH_FAILED",
      explanation: `Authentication failed: ${rawMsg}. Username/password or OAuth token rejected by server. For OAuth, token may be expired or missing required scope.`,
      remediation: "Verify credentials. For Gmail/Outlook OAuth2, ensure token has https://mail.google.com/ or SMTP.Send scope. For PLAIN/LOGIN, check username is full email and app-password if 2FA enabled. Check server supports chosen AUTH method via EHLO caps."
    };
  }
  if (msg.includes("starttls") || msg.includes("tls not supported")) {
    return {
      code: "STARTTLS_NOT_SUPPORTED",
      explanation: `Server does not advertise STARTTLS capability but client requested it, or STARTTLS command failed.`,
      remediation: "Check EHLO response for STARTTLS keyword. If missing, server may only support implicit TLS on 465 or plain on 25. Try encryption=none or SSL."
    };
  }
  if (msg.includes("relay") || msg.includes("550") || msg.includes("551") || msg.includes("553")) {
    return {
      code: "RELAY_DENIED",
      explanation: `Mail relay denied or mailbox unavailable: ${rawMsg}. Server refuses to send to recipient address or sender not authorized.`,
      remediation: "Verify FROM is authenticated user or allowed alias. Some servers require FROM == username. Check RCPT TO domain is allowed, and you are authenticated before sending."
    };
  }
  return {
    code: "SMTP_ERROR",
    explanation: `Error during ${context}: ${rawMsg}`,
    remediation: "Check logs for exact SMTP code. 4xx = temporary failure (retry), 5xx = permanent (fix config). Consult server documentation for code meaning."
  };
}

async function fetchOAuth2Token(params: {
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  username?: string;
  log: (dir: LogEntry["direction"], msg: string, raw?: string) => void;
  timeoutMs?: number;
}): Promise<{ access_token: string; expires_in?: number; token_type?: string; scope?: string; raw: any }> {
  const { tokenEndpoint, clientId, clientSecret, scope, log, timeoutMs = 10000 } = params;
  // Normalize scope: split by comma or space, rejoin with space (OAuth2 spec uses space-separated scopes)
  let normalizedScope = scope?.trim() || "";
  if (normalizedScope.includes(",")) {
    normalizedScope = normalizedScope.split(",").map(s => s.trim()).filter(Boolean).join(" ");
  }
  // For Microsoft, default scope if not provided
  if (!normalizedScope) normalizedScope = "https://outlook.office365.com/.default";

  const bodyParams = new URLSearchParams();
  bodyParams.set("grant_type", "client_credentials");
  bodyParams.set("client_id", clientId);
  bodyParams.set("client_secret", clientSecret);
  bodyParams.set("scope", normalizedScope);

  log("INFO", `OAuth2: requesting token from ${tokenEndpoint}`);
  log("INFO", `OAuth2: client_id=${clientId.slice(0, 8)}...${clientId.slice(-4)} scope="${normalizedScope}" grant_type=client_credentials`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const resp = await fetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
      body: bodyParams.toString(),
      signal: controller.signal,
    });

    const text = await resp.text();
    let json: any = null;
    try { json = JSON.parse(text); } catch {}
    if (!resp.ok) {
      const errMsg = json ? `${json.error || resp.statusText}: ${json.error_description || json.error || text}`.slice(0, 500) : `${resp.status} ${resp.statusText}: ${text.slice(0, 500)}`;
      log("ERROR", `OAuth2 token request failed: ${resp.status} ${errMsg}`, text);
      const lower = errMsg.toLowerCase();
      let code = "OAUTH_FAILED";
      let explanation = `OAuth2 token fetch failed: ${errMsg}`;
      let remediation = `Check Token Endpoint, Client ID/Secret, and Scopes. For Azure AD, Tenant ID in URL must match app registration. Scopes should be like https://outlook.office365.com/.default (single, space-separated). Secret may have expired.`;
      if (lower.includes("invalid_client")) {
        code = "OAUTH_INVALID_CLIENT";
        explanation = `OAuth2 invalid_client: ${errMsg}. Client ID or Secret is wrong, or app not found in tenant.`;
      } else if (lower.includes("unauthorized_client")) {
        code = "OAUTH_UNAUTHORIZED_CLIENT";
        explanation = `OAuth2 unauthorized_client: ${errMsg}. App not authorized for client_credentials or tenant admin consent missing.`;
      } else if (lower.includes("invalid_scope") || lower.includes("scope")) {
        code = "OAUTH_INVALID_SCOPE";
        explanation = `OAuth2 invalid_scope: ${errMsg}. For Outlook, use exactly https://outlook.office365.com/.default (no extra spaces, .default required).`;
      } else if (lower.includes("invalid_grant")) {
        code = "OAUTH_INVALID_GRANT";
        explanation = `OAuth2 invalid_grant: ${errMsg}. Grant type may not be allowed for this app.`;
      }
      const err: any = new Error(errMsg);
      err.code = code;
      err.explanation = explanation;
      err.remediation = remediation;
      throw err;
    }

    if (!json || !json.access_token) {
      const msg = `OAuth2 response missing access_token: ${text.slice(0, 500)}`;
      log("ERROR", msg, text);
      const err: any = new Error(msg);
      err.code = "OAUTH_NO_TOKEN";
      err.explanation = msg;
      throw err;
    }

    const preview = json.access_token.length > 20 ? `${json.access_token.slice(0, 12)}...${json.access_token.slice(-6)}` : "***";
    log("INFO", `OAuth2: token acquired successfully type=${json.token_type || "Bearer"} expires_in=${json.expires_in || "?"} preview=${preview}`, `access_token length=${json.access_token.length} token_type=${json.token_type} expires_in=${json.expires_in}`);

    return {
      access_token: json.access_token,
      expires_in: json.expires_in ? Number(json.expires_in) : undefined,
      token_type: json.token_type,
      scope: json.scope,
      raw: json,
    };
  } catch (e: any) {
    if (e.name === "AbortError") {
      const msg = `OAuth2 token request timed out after ${timeoutMs}ms to ${tokenEndpoint}`;
      log("ERROR", msg);
      const err: any = new Error(msg);
      err.code = "OAUTH_TIMEOUT";
      err.explanation = msg + ". Token endpoint may be unreachable or slow.";
      err.remediation = "Check Token Endpoint URL (tenant ID), network, and increase timeout. Try curl from local.";
      throw err;
    }
    throw e;
  } finally {
    clearTimeout(timeout);
  }
}

export async function testSmtp(req: SmtpTestRequest): Promise<SmtpTestResult> {
  const startMs = Date.now();
  const timeoutMs = req.timeoutMs ?? 12000;
  const perStepTimeout = Math.min(timeoutMs, 10000);

  const logs: LogEntry[] = [];
  const checklist: ChecklistItem[] = [];
  const timings: any = {};

  function log(direction: LogEntry["direction"], message: string, raw?: string) {
    logs.push({ ts: nowIso(), direction, message, raw });
  }

  function addCheck(item: ChecklistItem) {
    checklist.push(item);
    return item;
  }

  function updateCheck(id: string, patch: Partial<ChecklistItem>) {
    const c = checklist.find(x => x.id === id);
    if (c) Object.assign(c, patch);
  }

  // Validation
  if (!req.host) throw new Error("Host is required");
  if (!req.port) throw new Error("Port is required");
  if (!req.from || !req.to) throw new Error("From and To are required");

  // Decide secureTransport
  let secureTransport: "off" | "on" | "starttls" = "off";
  let needStartTls = false;
  let isImplicitTls = false;

  if (req.encryption === "ssl") {
    secureTransport = "on";
    isImplicitTls = true;
  } else if (req.encryption === "starttls") {
    secureTransport = "starttls";
    needStartTls = true;
  } else if (req.encryption === "none") {
    secureTransport = "off";
  } else if (req.encryption === "auto") {
    // Auto-detect by port
    if (req.port === 465) {
      secureTransport = "on";
      isImplicitTls = true;
    } else if (req.port === 587 || req.port === 25 || req.port === 2525) {
      secureTransport = "starttls";
      needStartTls = true; // but opportunistic: will try if advertised
    } else {
      secureTransport = "off";
    }
  }

  log("INFO", `Starting SMTP test to ${req.host}:${req.port} encryption=${req.encryption} (resolved secureTransport=${secureTransport}) auth=${req.authType}`);

  const dnsItem = addCheck({ id: "dns", label: `DNS & TCP Connect to ${req.host}:${req.port}`, status: "pending" });
  const greetItem = addCheck({ id: "greeting", label: "Server Greeting (220)", status: "pending" });
  const ehloItem = addCheck({ id: "ehlo", label: "EHLO Handshake", status: "pending" });
  const tlsItem = addCheck({
    id: "tls",
    label: isImplicitTls ? "TLS Handshake (Implicit SSL on connect)" : needStartTls ? "STARTTLS Upgrade" : "TLS (none - plaintext)",
    status: needStartTls || isImplicitTls ? "pending" : "skip",
    detail: needStartTls || isImplicitTls ? undefined : "Plaintext connection as requested"
  });
  // OAuth checklist will be inserted here before auth if needed (order: oauth before auth)
  const authItem = addCheck({
    id: "auth",
    label: `Authentication (${req.authType.toUpperCase()})`,
    status: req.authType === "none" ? "skip" : "pending",
    detail: req.authType === "none" ? "No authentication requested" : undefined
  });
  const mailFromItem = addCheck({ id: "mailfrom", label: `MAIL FROM:<${req.from}>`, status: "pending" });
  const rcptToItem = addCheck({ id: "rcptto", label: `RCPT TO:<${req.to}>`, status: "pending" });
  const dataItem = addCheck({ id: "data", label: "DATA & Message Delivery", status: "pending" });
  const quitItem = addCheck({ id: "quit", label: "QUIT", status: "pending" });

  let smtp: SmtpSocket | null = null;
  let capabilities: string[] = [];
  let authMechanisms: string[] = [];
  let overallSuccess = false;
  let finalError: any = null;
  let oauthResult: OAuthResult | undefined = undefined;
  let effectiveXoauth2Token = req.xoauth2Token;

  const connectStart = Date.now();

  try {
    // === OAUTH2 TOKEN FETCH (if XOAUTH2 with client credentials) ===
    const shouldFetchOAuth = req.authType === "xoauth2" && !!(req.oauthTokenEndpoint && req.oauthClientId && req.oauthClientSecret);
    if (shouldFetchOAuth) {
      const oauthScopeDisplay = (req.oauthScope || "https://outlook.office365.com/.default").slice(0, 80);
      const oauthCheck: ChecklistItem = {
        id: "oauth",
        label: `OAuth2 Token Acquire`,
        status: "running",
        detail: `POST ${req.oauthTokenEndpoint} client=${req.oauthClientId?.slice(0, 8)}... scope=${oauthScopeDisplay}`,
      };
      const authIdx = checklist.findIndex(c => c.id === "auth");
      if (authIdx !== -1) checklist.splice(authIdx, 0, oauthCheck);
      else checklist.push(oauthCheck);

      const oauthStart = Date.now();
      log("INFO", `OAuth2: starting client_credentials flow for user ${req.username || req.from}`);
      try {
        const tokenResp = await fetchOAuth2Token({
          tokenEndpoint: req.oauthTokenEndpoint!,
          clientId: req.oauthClientId!,
          clientSecret: req.oauthClientSecret!,
          scope: req.oauthScope,
          username: req.username,
          log,
          timeoutMs: Math.min(perStepTimeout + 2000, 10000),
        });
        effectiveXoauth2Token = tokenResp.access_token;
        const oauthMs = Date.now() - oauthStart;
        (timings as any).oauthMs = oauthMs;
        const preview = effectiveXoauth2Token.length > 24 ? `${effectiveXoauth2Token.slice(0, 12)}...${effectiveXoauth2Token.slice(-6)} (len=${effectiveXoauth2Token.length})` : `len=${effectiveXoauth2Token.length}`;
        oauthResult = {
          attempted: true,
          success: true,
          tokenEndpoint: req.oauthTokenEndpoint,
          scope: req.oauthScope || tokenResp.scope,
          clientId: req.oauthClientId,
          tokenPreview: preview,
          expiresIn: tokenResp.expires_in,
          tokenType: tokenResp.token_type,
        };
        const o = checklist.find(c => c.id === "oauth");
        if (o) {
          o.status = "pass";
          o.detail = `Token acquired in ${oauthMs}ms type=${tokenResp.token_type || "Bearer"} expires_in=${tokenResp.expires_in || "?"} ${preview}`;
          o.durationMs = oauthMs;
        }
        log("INFO", `OAuth2: token ready, will use for XOAUTH2 (user=${req.username || req.from})`);
      } catch (e: any) {
        const oauthMs = Date.now() - oauthStart;
        const errMsg = e.message || String(e);
        const code = e.code || "OAUTH_FAILED";
        const explanation = e.explanation || errMsg;
        oauthResult = {
          attempted: true,
          success: false,
          tokenEndpoint: req.oauthTokenEndpoint,
          scope: req.oauthScope,
          clientId: req.oauthClientId,
          error: errMsg,
          errorCode: code,
          explanation,
        };
        const o = checklist.find(c => c.id === "oauth");
        if (o) {
          o.status = "fail";
          o.detail = errMsg;
          o.errorCode = code;
          o.explanation = explanation;
          o.durationMs = oauthMs;
        }
        log("ERROR", `OAuth2 failed: ${errMsg}`);
        throw Object.assign(new Error(errMsg), { code, explanation, remediation: e.remediation, stage: "oauth" });
      }
    } else if (req.authType === "xoauth2" && req.oauthTokenEndpoint) {
      log("INFO", "OAuth2: token endpoint provided but missing clientId/secret — using direct token if supplied");
    }

    // === CONNECT ===
    updateCheck("dns", { status: "running" });
    log("INFO", `Connecting with secureTransport=${secureTransport} to ${req.host}:${req.port} ...`);
    let socket: any;
    try {
      socket = connect({ hostname: req.host, port: req.port }, { secureTransport } as any);
      // Wait for opened with timeout
      if (socket.opened) {
        await Promise.race([
          socket.opened,
          new Promise((_, reject) => setTimeout(() => reject(new Error("TCP_TIMEOUT: Connection timed out after " + perStepTimeout + "ms")), perStepTimeout)),
        ]);
      } else {
        // Fallback small delay to catch immediate errors
        await new Promise(r => setTimeout(r, 200));
      }
      smtp = new SmtpSocket(socket);
      const connectMs = Date.now() - connectStart;
      timings.connectMs = connectMs;
      updateCheck("dns", { status: "pass", detail: `Connected in ${connectMs}ms (secureTransport=${secureTransport})`, durationMs: connectMs });
      log("INFO", `TCP connected in ${connectMs}ms`);
    } catch (e: any) {
      const connectMs = Date.now() - connectStart;
      const cls = classifyError(e, `connect ${req.host}:${req.port}`);
      updateCheck("dns", {
        status: "fail",
        detail: e.message || String(e),
        errorCode: cls.code,
        explanation: cls.explanation,
        durationMs: connectMs
      });
      log("ERROR", `Connect failed: ${e.message}`, e.message);
      throw Object.assign(new Error(e.message), { code: cls.code, explanation: cls.explanation, remediation: cls.remediation, stage: "dns" });
    }

    // === GREETING ===
    const greetStart = Date.now();
    updateCheck("greeting", { status: "running" });
    log("INFO", "Waiting for server greeting (220) ...");
    try {
      const resp = await smtp!.readResponse(perStepTimeout);
      log("S", resp.raw.trim(), resp.raw);
      if (resp.code !== 220) {
        throw new Error(`Expected 220 greeting but got ${resp.code}: ${resp.lines.join(" | ")}`);
      }
      updateCheck("greeting", { status: "pass", detail: resp.lines.join(" | "), durationMs: Date.now() - greetStart });
      log("INFO", `Greeting OK: ${resp.lines[0]}`);
    } catch (e: any) {
      const cls = classifyError(e, "greeting");
      updateCheck("greeting", { status: "fail", detail: e.message, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - greetStart });
      log("ERROR", `Greeting failed: ${e.message}`);
      throw Object.assign(e, { code: cls.code, explanation: cls.explanation, remediation: cls.remediation, stage: "greeting" });
    }

    // === EHLO ===
    const ehloStart = Date.now();
    updateCheck("ehlo", { status: "running" });
    const ehloHost = "tester.local";
    log("C", `EHLO ${ehloHost}`, `EHLO ${ehloHost}\r\n`);
    await smtp!.writeLine(`EHLO ${ehloHost}\r\n`);
    try {
      const resp = await smtp!.readResponse(perStepTimeout);
      log("S", resp.raw.trim(), resp.raw);
      if (resp.code !== 250) {
        // Try HELO fallback
        log("INFO", `EHLO failed with ${resp.code}, trying HELO`);
        await smtp!.writeLine(`HELO ${ehloHost}\r\n`);
        log("C", `HELO ${ehloHost}`);
        const heloResp = await smtp!.readResponse(perStepTimeout);
        log("S", heloResp.raw.trim(), heloResp.raw);
        if (heloResp.code !== 250) throw new Error(`EHLO/HELO failed: ${resp.code} ${resp.lines.join(" | ")} then ${heloResp.code} ${heloResp.lines.join(" | ")}`);
        capabilities = heloResp.lines.slice(1).map(l => l.replace(/^250[ -]/, "").trim());
      } else {
        capabilities = resp.lines.map(l => l.replace(/^250[ -]/, "").trim());
        // First line is greeting, rest are caps
        // Remove first element which contains hostname greeting
        if (capabilities.length > 0) {
          // Keep all but first? Actually first is like "mail.example.com Hello"
          // Keep rest for parsing
        }
      }
      // Parse capabilities for AUTH
      const authLine = capabilities.find(c => c.toUpperCase().startsWith("AUTH"));
      if (authLine) {
        authMechanisms = authLine.split(/\s+/).slice(1).map(s => s.toUpperCase());
        log("INFO", `Server AUTH mechanisms: ${authMechanisms.join(", ")}`);
      } else {
        log("INFO", `No AUTH line in EHLO, capabilities: ${capabilities.join(" | ")}`);
      }
      // Check for STARTTLS
      const hasStartTLS = capabilities.some(c => c.toUpperCase() === "STARTTLS");
      log("INFO", `Server capabilities: ${capabilities.join(" | ")} | STARTTLS=${hasStartTLS} | ImplicitTLS=${isImplicitTls}`);
      if (isImplicitTls) {
        updateCheck("tls", { status: "pass", detail: `Implicit TLS already active (secureTransport=on). Cipher negotiated on connect.`, durationMs: timings.connectMs });
        log("INFO", "Implicit TLS active - no STARTTLS needed");
      } else if (hasStartTLS) {
        log("INFO", "Server supports STARTTLS");
      } else {
        if (needStartTls) log("INFO", "Server does NOT advertise STARTTLS but client requested STARTTLS - will attempt and likely fail");
      }

      updateCheck("ehlo", { status: "pass", detail: capabilities.join(" | "), durationMs: Date.now() - ehloStart });

      // === STARTTLS ===
      if (needStartTls) {
        const tlsStart = Date.now();
        updateCheck("tls", { status: "running" });
        if (!hasStartTLS) {
          // If server doesn't advertise STARTTLS, we treat as fail if encryption=starttls, but if auto we skip?
          if (req.encryption === "starttls") {
            const msg = "STARTTLS not advertised by server (EHLO missing STARTTLS). Server may only support plaintext or implicit SSL.";
            updateCheck("tls", { status: "fail", detail: msg, errorCode: "STARTTLS_NOT_SUPPORTED", explanation: msg, durationMs: Date.now() - tlsStart });
            log("ERROR", msg);
            throw Object.assign(new Error(msg), { code: "STARTTLS_NOT_SUPPORTED", explanation: msg, remediation: "Use encryption=none if server is plaintext, or encryption=ssl if server uses port 465.", stage: "tls" });
          } else {
            // auto mode - skip TLS upgrade if not advertised
            updateCheck("tls", { status: "skip", detail: "Server does not support STARTTLS, continuing plaintext (auto mode)" });
            log("INFO", "Skipping STARTTLS in auto mode since not advertised");
          }
        } else {
          log("C", "STARTTLS", "STARTTLS\r\n");
          await smtp!.writeLine("STARTTLS\r\n");
          const respSTARTTLS = await smtp!.readResponse(perStepTimeout);
          log("S", respSTARTTLS.raw.trim(), respSTARTTLS.raw);
          if (respSTARTTLS.code !== 220) {
            const msg = `STARTTLS failed: ${respSTARTTLS.code} ${respSTARTTLS.lines.join(" | ")}`;
            const cls = classifyError(new Error(msg), "starttls");
            updateCheck("tls", { status: "fail", detail: msg, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - tlsStart });
            throw Object.assign(new Error(msg), { code: cls.code, explanation: cls.explanation, remediation: cls.remediation, stage: "tls" });
          }
          // Upgrade
          log("INFO", "Upgrading socket to TLS via startTls()...");
          const tlsUpgradeStart = Date.now();
          try {
            await smtp!.startTls();
            const tlsMs = Date.now() - tlsUpgradeStart;
            timings.tlsMs = tlsMs;
            updateCheck("tls", { status: "pass", detail: `TLS handshake succeeded in ${tlsMs}ms. Connection now encrypted.`, durationMs: Date.now() - tlsStart });
            log("INFO", `TLS upgrade succeeded in ${tlsMs}ms`);

            // Must EHLO again after TLS per RFC
            log("INFO", "Re-issuing EHLO after TLS as required by RFC 3207");
            log("C", `EHLO ${ehloHost}`, `EHLO ${ehloHost}\r\n`);
            await smtp!.writeLine(`EHLO ${ehloHost}\r\n`);
            const resp2 = await smtp!.readResponse(perStepTimeout);
            log("S", resp2.raw.trim(), resp2.raw);
            if (resp2.code !== 250) throw new Error(`Post-TLS EHLO failed: ${resp2.code} ${resp2.lines.join(" | ")}`);
            capabilities = resp2.lines.map(l => l.replace(/^250[ -]/, "").trim());
            const authLine2 = capabilities.find(c => c.toUpperCase().startsWith("AUTH"));
            if (authLine2) authMechanisms = authLine2.split(/\s+/).slice(1).map(s => s.toUpperCase());
            log("INFO", `Post-TLS capabilities: ${capabilities.join(" | ")}`);
            // Update EHLO check detail with new caps?
          } catch (e: any) {
            const cls = classifyError(e, "tls handshake");
            updateCheck("tls", { status: "fail", detail: e.message, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - tlsStart });
            log("ERROR", `TLS upgrade failed: ${e.message}`);
            throw Object.assign(e, { code: cls.code, explanation: cls.explanation, remediation: cls.remediation, stage: "tls" });
          }
        }
      } else {
        // No TLS needed, but if isImplicitTls we already handled
        if (!isImplicitTls && !needStartTls) {
          // keep as skip or pass? Already skip
        }
      }

    } catch (e: any) {
      if (e.stage) throw e;
      const cls = classifyError(e, "ehlo");
      updateCheck("ehlo", { status: "fail", detail: e.message, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - ehloStart });
      log("ERROR", `EHLO failed: ${e.message}`);
      throw Object.assign(e, { code: cls.code, explanation: cls.explanation, remediation: cls.remediation, stage: "ehlo" });
    }

    // === AUTH ===
    if (req.authType !== "none") {
      const authStart = Date.now();
      updateCheck("auth", { status: "running" });
      const username = req.username || "";
      const password = req.password || "";
      const token = effectiveXoauth2Token || "";

      // Validate required fields
      if (req.authType === "xoauth2" && !token) {
        const msg = "XOAUTH2 token missing: xoauth2 requires a valid OAuth2 access token. Provide either 'Access Token' directly or fill Token Endpoint + Client ID + Client Secret to auto-fetch (client_credentials flow).";
        updateCheck("auth", { status: "fail", detail: msg, errorCode: "AUTH_MISSING_TOKEN", explanation: msg });
        throw Object.assign(new Error(msg), { code: "AUTH_MISSING_TOKEN", explanation: msg, stage: "auth" });
      }
      if ((req.authType === "plain" || req.authType === "login") && (!username || !password)) {
        const msg = `AUTH ${req.authType.toUpperCase()} requires username and password.`;
        updateCheck("auth", { status: "fail", detail: msg, errorCode: "AUTH_MISSING_CREDENTIALS", explanation: msg });
        throw Object.assign(new Error(msg), { code: "AUTH_MISSING_CREDENTIALS", explanation: msg, stage: "auth" });
      }

      // Check if mechanism supported (but allow try anyway with warning)
      const mechanismMap: Record<string, string> = { plain: "PLAIN", login: "LOGIN", xoauth2: "XOAUTH2", "cram-md5": "CRAM-MD5" };
      const neededMech = mechanismMap[req.authType];
      if (authMechanisms.length > 0 && neededMech && !authMechanisms.includes(neededMech)) {
        log("INFO", `Warning: Server EHLO does not list ${neededMech}. Advertised: ${authMechanisms.join(", ") || "none"}. Attempting anyway - may fail.`);
      }

      try {
        if (req.authType === "plain") {
          // AUTH PLAIN <base64>
          const authStr = `\0${username}\0${password}`;
          const b64 = b64encode(authStr);
          const cmd = `AUTH PLAIN ${b64}\r\n`;
          log("C", `AUTH PLAIN <credentials hidden, len=${b64.length}>`, `AUTH PLAIN ${b64}\r\n`);
          await smtp!.writeLine(cmd);
          const resp = await smtp!.readResponse(perStepTimeout);
          log("S", resp.raw.trim(), resp.raw);
          if (resp.code !== 235) {
            // 535, 534 etc
            const detail = `${resp.code} ${resp.lines.join(" | ")}`;
            let explanation = `AUTH PLAIN failed: ${detail}. `;
            if (resp.code === 535) explanation += "Authentication credentials invalid. For Gmail/Office365, use App Password if 2FA enabled, or ensure username is full email.";
            else if (resp.code === 534) explanation += "Authentication mechanism requires TLS or stronger encryption. You may need STARTTLS first.";
            else explanation += "Server rejected AUTH PLAIN - check username/password and that server supports PLAIN over current TLS state.";
            throw Object.assign(new Error(detail), { code: "AUTH_FAILED", explanation });
          }
          log("INFO", "AUTH PLAIN succeeded (235)");
        } else if (req.authType === "login") {
          log("C", "AUTH LOGIN", "AUTH LOGIN\r\n");
          await smtp!.writeLine("AUTH LOGIN\r\n");
          let resp = await smtp!.readResponse(perStepTimeout);
          log("S", resp.raw.trim(), resp.raw);
          if (resp.code !== 334) throw new Error(`AUTH LOGIN expected 334 challenge but got ${resp.code}: ${resp.lines.join(" | ")}`);
          // Decode challenge to verify it's username prompt, but send username anyway
          log("INFO", `AUTH LOGIN challenge 1: ${resp.lines[0]} (decoded: ${b64decode(resp.lines[0].substring(4)).trim()})`);
          const userB64 = b64encode(username);
          log("C", "AUTH LOGIN username <hidden>", `${userB64}\r\n`);
          await smtp!.writeLine(`${userB64}\r\n`);
          resp = await smtp!.readResponse(perStepTimeout);
          log("S", resp.raw.trim(), resp.raw);
          if (resp.code !== 334) throw new Error(`Expected second 334 for password but got ${resp.code}: ${resp.lines.join(" | ")}`);
          log("INFO", `AUTH LOGIN challenge 2: ${resp.lines[0]} (decoded: ${b64decode(resp.lines[0].substring(4)).trim()})`);
          const passB64 = b64encode(password);
          log("C", "AUTH LOGIN password <hidden>", `${passB64}\r\n`);
          await smtp!.writeLine(`${passB64}\r\n`);
          resp = await smtp!.readResponse(perStepTimeout);
          log("S", resp.raw.trim(), resp.raw);
          if (resp.code !== 235) {
            const detail = `${resp.code} ${resp.lines.join(" | ")}`;
            throw Object.assign(new Error(detail), { code: "AUTH_FAILED", explanation: `AUTH LOGIN failed: ${detail}` });
          }
          log("INFO", "AUTH LOGIN succeeded");
        } else if (req.authType === "xoauth2") {
          // XOAUTH2: user=... auth=Bearer ... \x01\x01
          // token is access token, username is email
          // Analyze token for debugging before sending
          let tokenPayload: any = null;
          try {
            tokenPayload = decodeJwtPayload(token);
            if (tokenPayload) {
              const aud = tokenPayload.aud || tokenPayload.audience || "?";
              const roles = Array.isArray(tokenPayload.roles) ? tokenPayload.roles.join(",") : tokenPayload.roles || tokenPayload.scp || "?";
              const appid = tokenPayload.appid || tokenPayload.azp || "?";
              const oid = tokenPayload.oid || "?";
              const tid = tokenPayload.tid || "?";
              const exp = tokenPayload.exp ? new Date(tokenPayload.exp * 1000).toISOString() : "?";
              const iss = tokenPayload.iss || "?";
              const iat = tokenPayload.iat ? new Date(tokenPayload.iat * 1000).toISOString() : "?";
              log("INFO", `XOAUTH2 token analysis: aud=${aud} iss=${iss} appid=${appid} oid=${oid} tid=${tid} roles=[${roles}] exp=${exp} iat=${iat} user=${username}`);
              if (typeof aud === "string" && !aud.includes("outlook.office365.com") && !aud.includes("outlook.office.com") && req.host.includes("office365")) {
                log("INFO", `XOAUTH2 token aud mismatch: token aud=${aud} but SMTP host is ${req.host}. For Office365, aud should be https://outlook.office365.com and scope should be https://outlook.office365.com/.default`);
              }
              if (Array.isArray(tokenPayload.roles) && tokenPayload.roles.length > 0) {
                const hasSmtp = tokenPayload.roles.includes("SMTP.SendAsApp") || tokenPayload.roles.includes("full_access_as_app") || tokenPayload.roles.includes("SMTP.SendAsApp") || tokenPayload.roles.includes("Mail.Send");
                if (!hasSmtp) log("INFO", `XOAUTH2 token roles do not include obvious SMTP permission: [${roles}] — may need SMTP.SendAsApp with admin consent`);
              }
            } else {
              log("INFO", `XOAUTH2 token: unable to decode JWT payload (token may not be JWT or malformed) len=${token.length}`);
            }
          } catch (e) {
            log("INFO", `XOAUTH2 token analysis failed: ${(e as Error).message}`);
          }

          const xoauth2Str = `user=${username}\x01auth=Bearer ${token}\x01\x01`;
          const b64 = b64encode(xoauth2Str);
          const cmd = `AUTH XOAUTH2 ${b64}\r\n`;
          log("C", `AUTH XOAUTH2 <token hidden, user=${username}>`, `AUTH XOAUTH2 ${b64}\r\n`);
          await smtp!.writeLine(cmd);
          const resp = await smtp!.readResponse(perStepTimeout);
          log("S", resp.raw.trim(), resp.raw);
          if (resp.code !== 235) {
            // For XOAUTH2, server may respond with 334 and base64 JSON error
            let decoded = "";
            try {
              if (resp.code === 334) {
                const challengeB64 = resp.lines[0].substring(4).trim();
                decoded = b64decode(challengeB64);
                log("INFO", `XOAUTH2 challenge decoded: ${decoded}`);
              }
            } catch {}
            const detail = `${resp.code} ${resp.lines.join(" | ")} ${decoded}`.trim();
            // Specific handling for Exchange Online 535 5.7.3
            if (detail.includes("535") && detail.includes("5.7.3")) {
              let explanation = `XOAUTH2 535 5.7.3 Authentication unsuccessful: ${detail}. `;
              explanation += `Token was valid (OAuth succeeded) but Exchange Online rejected SMTP AUTH for user ${username}. `;
              explanation += `This is typical for Office365 client_credentials when Service Principal is not configured in Exchange. Causes:`;
              explanation += ` 1) Service Principal missing in EXO: run Get-ServicePrincipal | Where-Object {$_.AppId -eq '${tokenPayload?.appid || "YOUR_APP_ID"}'} — if not found, create via New-ServicePrincipal -AppId ${tokenPayload?.appid || "YOUR_APP_ID"} -ObjectId ${tokenPayload?.oid || "OBJECT_ID"} -DisplayName "SMTP Tester".`;
              explanation += ` 2) No permission for mailbox ${username}: need Add-MailboxPermission or ApplicationAccessPolicy. Without this, even valid token is rejected.`;
              explanation += ` 3) SmtpClientAuthenticationDisabled is True at org or mailbox level: check Get-TransportConfig | fl SmtpClientAuthenticationDisabled and Get-CASMailbox -Identity ${username} | fl SmtpClientAuthenticationDisabled — both must be False (or not set). Fix with Set-TransportConfig -SmtpClientAuthenticationDisabled $false and Set-CASMailbox -Identity ${username} -SmtpClientAuthenticationDisabled $false.`;
              explanation += ` 4) App permissions: token roles [${tokenPayload?.roles ? tokenPayload.roles.join(",") : "?"}] — for client_credentials need SMTP.SendAsApp (or full_access_as_app) with Admin Consent granted in Entra ID. Mail.Send alone may not suffice for SMTP.`;
              explanation += ` 5) User mismatch: XOAUTH2 user=${username} must be the mailbox the service principal is authorized for. Token oid=${tokenPayload?.oid || "?"} tid=${tokenPayload?.tid || "?"}.`;
              explanation += ` 6) Also verify FROM header equals authenticated user (${req.from} vs ${username}) — some policies require exact match.`;
              const remediation = `Remediation for 535 5.7.3: 1) Connect-ExchangeOnline; 2) Get-ServicePrincipal -Identity ${tokenPayload?.appid || "APP_ID"}; if missing New-ServicePrincipal -AppId ${tokenPayload?.appid || "APP_ID"} -ObjectId ${tokenPayload?.oid || "OID"}; 3) Check SmtpClientAuthenticationDisabled at org/mailbox; 4) Ensure ApplicationAccessPolicy allows this app for ${username} (Get-ApplicationAccessPolicy); 5) Confirm admin consent for SMTP.SendAsApp in Entra ID > App registrations > API permissions. Docs: https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth`;
              const err: any = new Error(detail);
              err.code = "XOAUTH2_535_5_7_3";
              err.explanation = explanation;
              err.remediation = remediation;
              throw err;
            }
            let explanation = `XOAUTH2 failed: ${detail}. `;
            explanation += "Common causes: token expired (1h lifetime), wrong scope (need https://mail.google.com/ for Gmail or https://outlook.office365.com/SMTP.Send for Outlook), user mismatch, or Google 'Less Secure Apps' vs OAuth2 confusion. For Gmail, ensure token is OAuth2 access token, not API key.";
            throw Object.assign(new Error(detail), { code: "XOAUTH2_FAILED", explanation });
          }
          log("INFO", "AUTH XOAUTH2 succeeded");
        } else if (req.authType === "cram-md5") {
          log("C", "AUTH CRAM-MD5", "AUTH CRAM-MD5\r\n");
          await smtp!.writeLine("AUTH CRAM-MD5\r\n");
          const resp = await smtp!.readResponse(perStepTimeout);
          log("S", resp.raw.trim(), resp.raw);
          if (resp.code !== 334) throw new Error(`CRAM-MD5 expected 334 but got ${resp.code}`);
          // Need to compute HMAC-MD5 - simplified failure as not fully implemented without crypto
          throw new Error("CRAM-MD5 not fully implemented in this tester - use PLAIN/LOGIN/XOAUTH2");
        }

        const authMs = Date.now() - authStart;
        timings.authMs = authMs;
        updateCheck("auth", { status: "pass", detail: `Authenticated as ${username} via ${req.authType.toUpperCase()} in ${authMs}ms (235 OK)`, durationMs: authMs });
      } catch (e: any) {
        const cls: any = e.code ? { code: e.code, explanation: e.explanation, remediation: (e as any).remediation } : classifyError(e, "auth");
        const authMs = Date.now() - authStart;
        updateCheck("auth", {
          status: "fail",
          detail: e.message,
          errorCode: cls.code,
          explanation: cls.explanation || e.message,
          durationMs: authMs
        });
        log("ERROR", `AUTH failed: ${e.message}`);
        throw Object.assign(e, { code: cls.code, explanation: cls.explanation || e.message, remediation: cls.remediation, stage: "auth" });
      }
    } else {
      log("INFO", "Skipping AUTH (none)");
    }

    // === MAIL FROM ===
    const mailFromStart = Date.now();
    updateCheck("mailfrom", { status: "running" });
    log("C", `MAIL FROM:<${req.from}>`, `MAIL FROM:<${req.from}>\r\n`);
    await smtp!.writeLine(`MAIL FROM:<${req.from}>\r\n`);
    try {
      const resp = await smtp!.readResponse(perStepTimeout);
      log("S", resp.raw.trim(), resp.raw);
      if (resp.code !== 250) {
        const msg = `MAIL FROM rejected: ${resp.code} ${resp.lines.join(" | ")}`;
        const cls = classifyError(new Error(msg), "mail from");
        // Provide detailed explanation
        let explanation = msg + ". ";
        if (resp.code === 530) explanation += "530 means authentication required before sending mail - you must AUTH first or enable auth.";
        else if (resp.code === 550) explanation += "Sender address rejected - may be spoofing protection. Ensure FROM matches authenticated user.";
        else if (resp.code === 553) explanation += "Mailbox name not allowed - check FROM syntax.";
        else explanation += "Server rejects sender address.";
        updateCheck("mailfrom", { status: "fail", detail: msg, errorCode: cls.code, explanation, durationMs: Date.now() - mailFromStart });
        throw Object.assign(new Error(msg), { code: cls.code, explanation, stage: "mailfrom" });
      }
      updateCheck("mailfrom", { status: "pass", detail: `${resp.code} ${resp.lines.join(" | ")}`, durationMs: Date.now() - mailFromStart });
      log("INFO", "MAIL FROM accepted");
    } catch (e: any) {
      if (e.stage) throw e;
      const cls = classifyError(e, "mail from");
      updateCheck("mailfrom", { status: "fail", detail: e.message, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - mailFromStart });
      throw Object.assign(e, { code: cls.code, explanation: cls.explanation, stage: "mailfrom" });
    }

    // === RCPT TO ===
    const rcptStart = Date.now();
    updateCheck("rcptto", { status: "running" });
    log("C", `RCPT TO:<${req.to}>`, `RCPT TO:<${req.to}>\r\n`);
    await smtp!.writeLine(`RCPT TO:<${req.to}>\r\n`);
    try {
      const resp = await smtp!.readResponse(perStepTimeout);
      log("S", resp.raw.trim(), resp.raw);
      if (resp.code !== 250 && resp.code !== 251) {
        const msg = `RCPT TO rejected: ${resp.code} ${resp.lines.join(" | ")}`;
        let explanation = msg + ". ";
        if (resp.code === 550) explanation += "Recipient mailbox unavailable or relay denied. Check recipient address spelling, or server requires you to be authenticated and sender domain is not allowed to relay to external domain.";
        else if (resp.code === 551) explanation += "User not local, please try forward path.";
        else if (resp.code === 552) explanation += "Mailbox full or storage allocation exceeded.";
        else if (resp.code === 553) explanation += "Mailbox name not allowed.";
        else if (resp.code === 530) explanation += "Authentication required.";
        else explanation += "Server rejects recipient.";
        const cls = classifyError(new Error(msg), "rcpt to");
        updateCheck("rcptto", { status: "fail", detail: msg, errorCode: cls.code, explanation, durationMs: Date.now() - rcptStart });
        throw Object.assign(new Error(msg), { code: cls.code, explanation, stage: "rcptto" });
      }
      updateCheck("rcptto", { status: "pass", detail: `${resp.code} ${resp.lines.join(" | ")}`, durationMs: Date.now() - rcptStart });
      log("INFO", "RCPT TO accepted");
    } catch (e: any) {
      if (e.stage) throw e;
      const cls = classifyError(e, "rcpt to");
      updateCheck("rcptto", { status: "fail", detail: e.message, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - rcptStart });
      throw Object.assign(e, { code: cls.code, explanation: cls.explanation, stage: "rcptto" });
    }

    // === DATA ===
    const dataStart = Date.now();
    updateCheck("data", { status: "running" });
    log("C", "DATA", "DATA\r\n");
    await smtp!.writeLine("DATA\r\n");
    try {
      const resp = await smtp!.readResponse(perStepTimeout);
      log("S", resp.raw.trim(), resp.raw);
      if (resp.code !== 354) {
        const msg = `DATA command rejected: ${resp.code} ${resp.lines.join(" | ")} (expected 354)`;
        const cls = classifyError(new Error(msg), "data");
        updateCheck("data", { status: "fail", detail: msg, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - dataStart });
        throw Object.assign(new Error(msg), { code: cls.code, explanation: cls.explanation, stage: "data" });
      }
      // Build email
      const subject = req.subject || "SMTP Tester - Test Email";
      const body = req.body || "This is a test email from SMTP Tester.\n\nIf you received this, SMTP is working correctly.\n\nTimestamp: " + new Date().toISOString();
      const dateStr = new Date().toUTCString();
      const messageId = `<${Date.now()}.${Math.random().toString(36).slice(2)}@tester.local>`;
      // Escape body for SMTP dot-stuffing and ensure CRLF
      let normalizedBody = body.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n/g, "\r\n");
      // Dot-stuffing: lines starting with . need extra .
      normalizedBody = normalizedBody.split("\r\n").map(l => l.startsWith(".") ? "." + l : l).join("\r\n");

      const emailContent =
        `From: ${req.from}\r\n` +
        `To: ${req.to}\r\n` +
        `Subject: ${subject}\r\n` +
        `Date: ${dateStr}\r\n` +
        `Message-ID: ${messageId}\r\n` +
        `MIME-Version: 1.0\r\n` +
        `Content-Type: text/plain; charset=utf-8\r\n` +
        `Content-Transfer-Encoding: 7bit\r\n` +
        `X-Mailer: SMTP Tester\r\n` +
        `\r\n` +
        `${normalizedBody}\r\n` +
        `.\r\n`;

      log("C", `Sending email headers + body (${emailContent.length} bytes) + <CRLF>.<CRLF>`, emailContent.replace(req.from, "<from>").replace(req.to, "<to>").substring(0, 2000) + (emailContent.length > 2000 ? "...[truncated]" : ""));
      await smtp!.writeLine(emailContent);
      const dataResp = await smtp!.readResponse(perStepTimeout);
      log("S", dataResp.raw.trim(), dataResp.raw);
      if (dataResp.code !== 250) {
        const msg = `Message not accepted: ${dataResp.code} ${dataResp.lines.join(" | ")}`;
        let explanation = msg + ". ";
        const rawLower = dataResp.lines.join(" | ").toLowerCase();
        if (dataResp.code === 430 || rawLower.includes("430") || rawLower.includes("storagedrv") || rawLower.includes("mailbox logon failure") || rawLower.includes("authenticationcontext has no rights")) {
          explanation += "430 4.2.0 STOREDRV mailbox logon failure: AUTH XOAUTH2 succeeded but Exchange cannot open the mailbox for submission. ";
          explanation += `For Office365 app-only flow (client_credentials) this is ALWAYS ApplicationAccessPolicy. You created ServicePrincipal ${req.oauthClientId || "YOUR_APP_ID"} but have not granted it rights to mailbox ${req.from}. `;
          explanation += `Fix in Exchange Online PowerShell (AccessRight must be RestrictAccess, not Allow): New-ApplicationAccessPolicy -AppId ${req.oauthClientId || "b43e4b73-dc21-46c0-9b6d-9b5b44b0fd24"} -PolicyScopeGroupId "${req.from}" -AccessRight RestrictAccess -Description "Allow SMTP Tester for ${req.from}" . `;
          explanation += `This restricts the app to ONLY that mailbox (recommended). For quick test, same command with RestrictAccess is the allow-list. Verify with: Test-ApplicationAccessPolicy -Identity ${req.from} -AppId ${req.oauthClientId || "APP_ID"} (should return Granted) and re-test after 5-10 min replication. Also ensure mailbox ${req.from} exists, licensed, and not hidden. Diagnostic shows "AuthenticationContext has no rights on this session" — classic missing policy. If you previously tried Allow, it fails because valid values are RestrictAccess/DenyAccess.`;
          const err: any = new Error(msg);
          err.code = "DATA_430_MAILBOX_LOGON_FAILURE";
          err.explanation = explanation;
          err.remediation = `Run: New-ApplicationAccessPolicy -AppId ${req.oauthClientId || "YOUR_APP_ID"} -PolicyScopeGroupId "${req.from}" -AccessRight RestrictAccess`;
          updateCheck("data", { status: "fail", detail: msg, errorCode: err.code, explanation, durationMs: Date.now() - dataStart });
          throw Object.assign(err, { stage: "data" });
        } else if (dataResp.code === 552) explanation += "Message exceeds server size limit or quota.";
        else if (dataResp.code === 550) explanation += "Message rejected due to policy (spam filter, SPF/DKIM failure, blacklisted).";
        else explanation += "Server failed to queue message after DATA.";
        updateCheck("data", { status: "fail", detail: msg, errorCode: "DATA_FAILED", explanation, durationMs: Date.now() - dataStart });
        throw Object.assign(new Error(msg), { code: "DATA_FAILED", explanation, stage: "data" });
      }
      updateCheck("data", { status: "pass", detail: `Message queued: ${dataResp.lines.join(" | ")} (${emailContent.length} bytes)`, durationMs: Date.now() - dataStart });
      log("INFO", `Message delivered: ${dataResp.lines.join(" | ")}`);
    } catch (e: any) {
      if (e.stage) throw e;
      const cls = classifyError(e, "data");
      updateCheck("data", { status: "fail", detail: e.message, errorCode: cls.code, explanation: cls.explanation, durationMs: Date.now() - dataStart });
      throw Object.assign(e, { code: cls.code, explanation: cls.explanation, stage: "data" });
    }

    // === QUIT ===
    const quitStart = Date.now();
    updateCheck("quit", { status: "running" });
    log("C", "QUIT", "QUIT\r\n");
    try {
      await smtp!.writeLine("QUIT\r\n");
      const resp = await smtp!.readResponse(3000);
      log("S", resp.raw.trim(), resp.raw);
      updateCheck("quit", { status: "pass", detail: `${resp.code} ${resp.lines.join(" | ")}`, durationMs: Date.now() - quitStart });
    } catch (e: any) {
      // QUIT failure is not critical
      log("INFO", `QUIT response ignored: ${e.message}`);
      updateCheck("quit", { status: "pass", detail: "QUIT sent (response ignored)", durationMs: Date.now() - quitStart });
    }

    overallSuccess = true;
    log("INFO", "SMTP test completed successfully");

  } catch (e: any) {
    finalError = e;
    log("ERROR", `Stage ${e.stage || "unknown"} failed: ${e.message}`);
    // Mark remaining pending as skip?
    for (const c of checklist) {
      if (c.status === "pending") {
        c.status = "skip";
        c.detail = "Skipped due to earlier failure";
      } else if (c.status === "running") {
        c.status = "fail";
      }
    }
  } finally {
    if (smtp) {
      try { await smtp.close(); } catch {}
    }
  }

  const totalMs = Date.now() - startMs;
  timings.totalMs = totalMs;

  // Build summary and error
  let summary = "";
  let error: any = undefined;
  if (overallSuccess) {
    summary = `✅ All checks passed in ${totalMs}ms. Email successfully queued to ${req.to}.`;
  } else {
    const failed = checklist.filter(c => c.status === "fail");
    const passed = checklist.filter(c => c.status === "pass").length;
    const failedIds = failed.map(f => f.label).join(", ");
    summary = `❌ Failed at ${finalError?.stage || "unknown"} after ${totalMs}ms. Passed ${passed}/${checklist.length} checks. Failed: ${failedIds}`;
    const primaryFail = failed[0];
    error = {
      code: finalError?.code || primaryFail?.errorCode || "UNKNOWN",
      message: finalError?.message || primaryFail?.detail || "Unknown error",
      explanation: finalError?.explanation || primaryFail?.explanation || "No explanation",
      remediation: finalError?.remediation,
    };
    if (finalError?.remediation) error.remediation = finalError.remediation;
  }

  return {
    success: overallSuccess,
    summary,
    host: req.host,
    port: req.port,
    encryption: req.encryption,
    authType: req.authType,
    checklist,
    logs,
    capabilities,
    oauth: oauthResult,
    error,
    timings,
  };
}
