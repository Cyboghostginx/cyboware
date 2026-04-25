/* ═══ CYBOWARE — Sidepanel v3 ═══ */

let activeTabId = null, activeTabUrl = '', activeTabDomain = '';
let pinnedTabId = null, scopeDomains = [], notes = {}, diffStore = { a: null, b: null };
let liveActive = false, liveTargetDomain = '', liveFindings = [];
const liveSeenItems = new Set(); // dedup: skip already-found items
const liveDomainData = {}; // domain → { findings, seenItems, feedHTML }
const cache = {};
const browseHistory = {}; // domain → [{url, title, timestamp}]

const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'high' },
  { name: 'AWS Secret Key', regex: /(?:aws_secret|secret_key|SecretAccessKey)['":\s]*([A-Za-z0-9/+=]{40})/gi, severity: 'high' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
  { name: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9_]{36,255}/g, severity: 'high' },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9A-Za-z-]+/g, severity: 'high' },
  { name: 'Stripe Secret', regex: /sk_live_[0-9a-zA-Z]{24,99}/g, severity: 'high' },
  { name: 'Stripe Publishable', regex: /pk_live_[0-9a-zA-Z]{24,99}/g, severity: 'medium' },
  { name: 'Twilio API Key', regex: /SK[0-9a-fA-F]{32}/g, severity: 'high' },
  { name: 'SendGrid', regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, severity: 'high' },
  { name: 'Private Key', regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'high' },
  { name: 'Bearer Token', regex: /[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*/g, severity: 'medium' },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: 'medium' },
  { name: 'Generic Secret', regex: /(?:secret|password|passwd|token|api_key|apikey|api-key|auth)[\s]*[=:]["'][^\s"']{8,}/gi, severity: 'medium' },
  { name: 'IP Address', regex: /(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/g, severity: 'low' },
  { name: 'Firebase', regex: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g, severity: 'high' },
  { name: 'Mailgun', regex: /key-[0-9a-zA-Z]{32}/g, severity: 'high' },
  { name: 'Basic Auth', regex: /[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}/g, severity: 'medium' },
];
const ENDPOINT_PATTERNS = [
  /["'](\/api\/[^"']{2,})["']/g, /["'](\/v[0-9]+\/[^"']{2,})["']/g,
  /["'](\/graphql[^"']*)["']/g, /["'](\/rest\/[^"']{2,})["']/g,
  /["'](https?:\/\/[^"'\s]{6,})["']/g, /["'](wss?:\/\/[^"'\s]+)["']/g,
  /\.(?:get|post|put|patch|delete|fetch)\s*\(\s*["']([^"']+)["']/g,
];

// ═══ INIT ═══
document.addEventListener('DOMContentLoaded', async () => {
  log('Cyboware v3 initialized');
  const stored = await chrome.storage.local.get(['scopeDomains', 'notes', 'scratchpad', 'browseHistory']);
  scopeDomains = stored.scopeDomains || [];
  notes = stored.notes || {};
  if (stored.browseHistory) Object.assign(browseHistory, stored.browseHistory);
  const sp = document.getElementById('scratchpad');
  if (sp) sp.value = stored.scratchpad || '';

  setupGroupToggles(); setupToolButtons(); setupPinButton(); setupDebugLog();
  setupRefreshButton(); setupScratchpad(); setupLiveBrowse();

  await updateActiveTab();
  // Track tab changes
  chrome.tabs.onActivated.addListener(() => { if (!pinnedTabId) updateActiveTab(); });
  chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
    if (info.status === 'complete') {
      // Record browse history for ALL domains
      if (tab.url && !tab.url.startsWith('chrome') && !tab.url.startsWith('about:')) {
        try {
          const domain = getRootDomain(new URL(tab.url).hostname);
          if (domain) {
            if (!browseHistory[domain]) browseHistory[domain] = [];
            if (!browseHistory[domain].some(e => e.url === tab.url)) {
              browseHistory[domain].push({ url: tab.url, title: tab.title || '', timestamp: Date.now() });
              if (browseHistory[domain].length > 200) browseHistory[domain] = browseHistory[domain].slice(-200);
              chrome.storage.local.set({ browseHistory });
            }
          }
        } catch {}
      }
      if (tabId === activeTabId || tabId === pinnedTabId) updateActiveTab();
      // Live Browse passive scan — with redirect handling
      if (liveActive && tab.url && !tab.url.startsWith('chrome')) {
        try {
          const host = new URL(tab.url).hostname;
          const targetRoot = getRootDomain(liveTargetDomain);
          const pageRoot = getRootDomain(host);
          // Match same root domain (catches subdomains and redirects within the target)
          if (pageRoot === targetRoot) {
            // Small delay for content script injection after redirects
            setTimeout(() => liveScanPage(tabId, tab.url, tab.title || ''), 600);
          }
        } catch {}
      }
    }
  });
});

let lastDomain = '';
const visitedDomains = new Set();
const domainPanels = {}; // rootDomain -> { groupName: panelHTML }

// ═══ TAB TRACKING ═══
async function updateActiveTab() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || !tabs.length) { log('No active tab found', 'warn'); return; }
    const tab = tabs[0];

    if (pinnedTabId) {
      try { const pt = await chrome.tabs.get(pinnedTabId); activeTabId = pt.id; activeTabUrl = pt.url || ''; }
      catch { pinnedTabId = null; document.getElementById('btn-pin').classList.remove('pinned'); document.getElementById('btn-pin').textContent = 'PIN'; activeTabId = tab.id; activeTabUrl = tab.url || ''; }
    } else {
      activeTabId = tab.id;
      activeTabUrl = tab.url || '';
    }

    try { activeTabDomain = new URL(activeTabUrl).hostname; } catch { activeTabDomain = ''; }

    // Show full URL in context bar
    document.getElementById('tab-url').textContent = activeTabUrl || '—';
    document.getElementById('tab-url').title = activeTabUrl;

    const currentHost = activeTabDomain; // Full hostname — algo.elko.is ≠ elko.is

    // ── Domain switch: save current → restore new ──
    if (lastDomain && currentHost !== lastDomain) {
      // Save current domain's open panels
      domainPanels[lastDomain] = {};
      document.querySelectorAll('.results-panel.active').forEach(p => {
        const group = p.id.replace('results-', '');
        domainPanels[lastDomain][group] = p.innerHTML;
      });
      // Save live browse data for current domain
      if (liveFindings.length || liveSeenItems.size) {
        liveDomainData[lastDomain] = { findings: [...liveFindings], seenItems: new Set(liveSeenItems), feedHTML: document.getElementById('live-feed')?.innerHTML || '' };
      }

      // Clear all panels
      document.querySelectorAll('.results-panel').forEach(p => { p.classList.remove('active'); p.innerHTML = ''; });
      document.querySelectorAll('.badge').forEach(b => b.classList.add('hidden'));

      // Restore live browse for new domain
      if (liveDomainData[currentHost]) {
        const ld = liveDomainData[currentHost];
        liveFindings = ld.findings; liveSeenItems.clear(); ld.seenItems.forEach(s => liveSeenItems.add(s));
        const feed = document.getElementById('live-feed');
        if (feed) feed.innerHTML = ld.feedHTML;
        const totalItems = liveFindings.reduce((s, f) => s + f.items.length, 0);
        document.getElementById('live-count').textContent = totalItems + ' findings';
        if (totalItems > 0) { const badge = document.getElementById('badge-live'); badge.textContent = totalItems; badge.classList.remove('hidden'); }
      } else {
        liveFindings = []; liveSeenItems.clear();
        const feed = document.getElementById('live-feed');
        if (feed) feed.innerHTML = '<div class="text-muted text-sm" style="padding:12px;text-align:center">Click Start to begin</div>';
        document.getElementById('live-count').textContent = '0 findings';
      }

      // Restore panels for new domain if we have them
      if (domainPanels[currentHost]) {
        Object.entries(domainPanels[currentHost]).forEach(([group, html]) => {
          const panel = document.getElementById('results-' + group);
          if (panel && html) {
            panel.innerHTML = html;
            panel.classList.add('active');
            wireResultsClose(panel);
            wireResultsCopyJson(panel);
            // Open the parent group
            panel.closest('.feat-group')?.classList.add('open');
          }
        });
        log('Restored session for ' + currentHost);
      } else {
        log('New domain: ' + currentHost);
      }
    }
    lastDomain = currentHost;

    if (activeTabDomain) visitedDomains.add(activeTabDomain);
    updateScopeIndicator();
    renderDomainPills();
  } catch (e) {
    log('Tab update error: ' + e.message, 'error');
  }
}

function renderDomainPills() {
  const bar = document.getElementById('domain-sessions');
  if (!bar) return;
  const domainsWithData = Object.keys(domainPanels).filter(d => Object.keys(domainPanels[d]).length > 0);
  const currentHost = activeTabDomain;
  const allDomains = new Set([...domainsWithData, currentHost].filter(Boolean));
  if (allDomains.size <= 1) { bar.innerHTML = ''; return; }

  bar.innerHTML = [...allDomains].map(d => {
    const isActive = d === currentHost;
    const hasData = domainPanels[d] && Object.keys(domainPanels[d]).length > 0;
    return `<button class="domain-pill ${isActive ? 'active' : ''}" data-domain="${esc(d)}">${hasData ? '<span class="pill-dot"></span>' : ''}${esc(d)}</button>`;
  }).join('');

  bar.querySelectorAll('.domain-pill').forEach(pill => {
    pill.addEventListener('click', async () => {
      const domain = pill.dataset.domain;
      if (domain === currentHost) return;
      // Find a tab with this domain
      const tabs = await chrome.tabs.query({ currentWindow: true });
      const match = tabs.find(t => { try { return new URL(t.url).hostname === domain; } catch { return false; } });
      if (match) {
        await chrome.tabs.update(match.id, { active: true }); // Switch to that tab
      } else {
        // No tab found — just restore the cached session
        // Save current first
        if (lastDomain) {
          domainPanels[lastDomain] = {};
          document.querySelectorAll('.results-panel.active').forEach(p => {
            domainPanels[lastDomain][p.id.replace('results-', '')] = p.innerHTML;
          });
        }
        document.querySelectorAll('.results-panel').forEach(p => { p.classList.remove('active'); p.innerHTML = ''; });
        if (domainPanels[domain]) {
          Object.entries(domainPanels[domain]).forEach(([group, html]) => {
            const panel = document.getElementById('results-' + group);
            if (panel && html) { panel.innerHTML = html; panel.classList.add('active'); wireResultsClose(panel); wireResultsCopyJson(panel); panel.closest('.feat-group')?.classList.add('open'); }
          });
        }
        activeTabDomain = domain; lastDomain = domain;
        document.getElementById('tab-url').textContent = domain + ' (cached session)';
        renderDomainPills();
        log('Loaded cached session: ' + domain);
      }
    });
  });
}

function updateScopeIndicator() {
  const dot = document.getElementById('scope-indicator');
  if (!activeTabDomain || !scopeDomains.length) { dot.className = 'scope-dot'; return; }
  const inScope = scopeDomains.some(d => activeTabDomain === d || activeTabDomain.endsWith('.' + d));
  dot.className = 'scope-dot ' + (inScope ? 'in-scope' : 'out-scope');
}

// ═══ GUARD: safe message to content script ═══
async function msgTab(msg) {
  if (!activeTabId) { log('No active tab', 'warn'); return { ok: false, error: 'No active tab' }; }
  if (activeTabUrl.startsWith('chrome://') || activeTabUrl.startsWith('chrome-extension://') || activeTabUrl.startsWith('about:')) {
    return { ok: false, error: 'Cannot access this page type' };
  }
  try { return await chrome.tabs.sendMessage(activeTabId, msg); }
  catch (e) { log('Content script error: ' + e.message, 'error'); return { ok: false, error: e.message }; }
}

// ═══ UI SETUP ═══
function setupGroupToggles() { document.querySelectorAll('.feat-group-header').forEach(h => h.addEventListener('click', () => h.parentElement.classList.toggle('open'))); }
function setupPinButton() {
  const btn = document.getElementById('btn-pin');
  btn.addEventListener('click', async () => {
    if (pinnedTabId) { pinnedTabId = null; btn.classList.remove('pinned'); btn.textContent = 'PIN'; await updateActiveTab(); }
    else { pinnedTabId = activeTabId; btn.classList.add('pinned'); btn.textContent = '📌 ' + activeTabDomain; }
  });
}
function setupRefreshButton() {
  document.getElementById('btn-refresh').addEventListener('click', () => { Object.keys(cache).forEach(k => delete cache[k]); updateActiveTab(); });
  // Reset button — close all panels, clear cache for current domain
  document.getElementById('btn-reset')?.addEventListener('click', () => {
    const currentRoot = getRootDomain(activeTabDomain);
    // Clear domain-keyed caches
    Object.keys(cache).forEach(k => { if (k.startsWith(activeTabDomain + ':')) delete cache[k]; });
    if (currentRoot) delete domainPanels[currentRoot];
    document.querySelectorAll('.results-panel').forEach(p => { p.classList.remove('active'); p.innerHTML = ''; });
    document.querySelectorAll('.badge').forEach(b => b.classList.add('hidden'));
    renderDomainPills();
    log('Reset: ' + (currentRoot || 'all'), 'success');
  });
  // Collapse / Expand all sections
  document.getElementById('btn-collapse')?.addEventListener('click', () => {
    const groups = document.querySelectorAll('.feat-group');
    const anyOpen = [...groups].some(g => g.classList.contains('open'));
    groups.forEach(g => { if (anyOpen) g.classList.remove('open'); else g.classList.add('open'); });
    document.getElementById('btn-collapse').textContent = anyOpen ? '△' : '▽';
  });
  // Domain selector — switch context when user picks a previously visited domain
  // (removed — now auto-adapts to current tab)
  document.getElementById('btn-copy-all')?.addEventListener('click', () => {
    // Build human-readable report
    let report = `${'═'.repeat(40)}\nCYBOWARE REPORT\n${'═'.repeat(40)}\nTarget: ${activeTabDomain}\nURL: ${activeTabUrl}\nDate: ${new Date().toISOString()}\n\n`;
    // Collect from all visible panels
    const sections = [];
    document.querySelectorAll('.results-panel.active').forEach(panel => {
      const title = panel.querySelector('.results-title')?.textContent || '';
      const items = [...panel.querySelectorAll('.result-item')].map(el => {
        const label = el.querySelector('.result-label')?.textContent?.trim() || '';
        const value = el.querySelector('.result-value')?.textContent?.trim() || el.textContent.trim();
        return { label, value };
      });
      if (items.length) sections.push({ title, items });
    });
    // Also from domain cache
    Object.entries(cache).forEach(([key, html]) => {
      if (!key.startsWith(activeTabDomain + ':')) return;
      const title = key.split(':').slice(1).join(':');
      if (sections.some(s => s.title === title)) return;
      const div = document.createElement('div'); div.innerHTML = html;
      const items = [...div.querySelectorAll('.result-item')].map(el => ({
        label: el.querySelector('.result-label')?.textContent?.trim() || '',
        value: el.querySelector('.result-value')?.textContent?.trim() || el.textContent.trim()
      }));
      if (items.length) sections.push({ title, items });
    });
    sections.forEach(s => {
      report += `── ${s.title} ${'─'.repeat(Math.max(1, 34 - s.title.length))}\n`;
      s.items.forEach(i => { report += i.label ? `  [${i.label}] ${i.value}\n` : `  ${i.value}\n`; });
      report += '\n';
    });
    report += `${'─'.repeat(40)}\nGenerated by Cyboware · github.com/Cyboghostginx\n`;
    copyText(report);
    log('Full report copied (' + sections.length + ' sections)', 'success');
  });
}
function setupDebugLog() {
  document.getElementById('toggle-log').addEventListener('click', () => { const el = document.getElementById('debug-log'); el.classList.toggle('visible'); document.getElementById('toggle-log').textContent = el.classList.contains('visible') ? 'Log ▴' : 'Log ▾'; });
  document.getElementById('clear-log').addEventListener('click', () => { document.getElementById('debug-log-entries').innerHTML = ''; });
}
function setupToolButtons() { document.querySelectorAll('.tool-btn').forEach(b => b.addEventListener('click', () => runTool(b.dataset.tool))); }
function setupScratchpad() {
  const sp = document.getElementById('scratchpad'); if (!sp) return;
  let t; sp.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => chrome.storage.local.set({ scratchpad: sp.value }), 500); });
  document.getElementById('btn-scratch-copy')?.addEventListener('click', () => copyText(sp.value));
  document.getElementById('btn-scratch-clear')?.addEventListener('click', () => { sp.value = ''; chrome.storage.local.set({ scratchpad: '' }); });
  document.getElementById('btn-scratch-download')?.addEventListener('click', () => downloadText(sp.value, 'cyboware-scratchpad.txt'));
}

// ═══ RESULTS PANEL — always fresh, no dead event listeners ═══
function showResults(groupName, title, loading) {
  const panel = document.getElementById('results-' + groupName);
  panel.classList.add('active');
  panel.innerHTML = `<div class="results-header"><span class="results-title">${esc(title)}</span><div class="results-actions"><button class="ra-copy" title="Copy">Copy</button><button class="ra-json" title="JSON">JSON</button></div><button class="results-close">✕</button></div><div class="results-body">${loading ? '<div class="loading-text"><span class="spinner"></span> Working…</div>' : ''}</div>`;
  wireResultsClose(panel);
  return panel.querySelector('.results-body');
}
function finalizeResults(gn) {
  const p = document.getElementById('results-' + gn);
  const title = p.querySelector('.results-title')?.textContent || '';
  cache[activeTabDomain + ':' + title] = p.querySelector('.results-body')?.innerHTML || '';
  wireResultsCopyJson(p);
}
function wireResultsClose(p) { p.querySelector('.results-close')?.addEventListener('click', () => p.classList.remove('active')); }
function wireResultsCopyJson(p) {
  p.querySelector('.ra-copy')?.addEventListener('click', () => {
    const items = [...p.querySelectorAll('.results-body .result-item')];
    if (!items.length) { copyText(p.querySelector('.results-body')?.textContent || ''); return; }
    const lines = items.map(el => {
      const label = el.querySelector('.result-label')?.textContent?.trim() || '';
      const value = el.querySelector('.result-value')?.textContent?.trim() || el.textContent.trim();
      return label ? `[${label}] ${value}` : value;
    });
    copyText(lines.join('\n'));
  });
  p.querySelector('.ra-json')?.addEventListener('click', () => {
    const items = [...p.querySelectorAll('.results-body .result-item')].map(el => ({
      label: el.querySelector('.result-label')?.textContent?.trim() || '',
      value: el.querySelector('.result-value')?.textContent?.trim() || el.textContent.trim()
    }));
    copyText(JSON.stringify(items, null, 2));
  });
}

// ═══ DISPATCHER ═══
async function runTool(tool) {
  log('Running: ' + tool);
  try {
    switch (tool) {
      case 'tech-stack': await toolTechStack(); break;
      case 'headers-audit': await toolHeadersAudit(); break;
      case 'cookies': await toolCookies(); break;
      case 'subdomains': await toolSubdomains(); break;
      case 'reqresp': await toolReqResp(); break;
      case 'dns': await toolDns(); break;
      case 'wpplugins': await toolWpPlugins(); break;
      case 'secrets': await toolSecrets(); break;
      case 'endpoints': await toolEndpoints(); break;
      case 'hidden': await toolHidden(); break;
      case 'links': await toolLinks(); break;
      case 'replayer': await toolReplayer(); break;
      case 'cors': await toolCors(); break;
      case 'redirect': await toolRedirect(); break;
      case 'codec': toolCodec(); break;
      case 'paramfuzz': await toolParamFuzz(); break;
      case 'bypass403': await tool403Bypass(); break;
      case 'methodtest': await toolMethodTest(); break;
      case 'jwteditor': toolJwtEditor(); break;
      case 'dirbrute': await toolDirBrute(); break;
      case 'idor': await toolIdor(); break;
      case 'jsbeautify': await toolJsBeautify(); break;
      case 'cspeval': await toolCspEval(); break;
      case 'takeover': await toolTakeover(); break;
      case 'scope': toolScope(); break;
      case 'notes': toolNotes(); break;
      case 'history': toolHistory(); break;
      case 'screenshot': await toolScreenshot(); break;
      case 'passive': await toolPassive(); break;
      case 'wayback': await toolWayback(); break;
      case 'diff': toolDiff(); break;
    }
  } catch (e) { log('Error: ' + e.message, 'error'); }
}

// ═══ TOOLS ═══
async function toolTechStack() {
  const b = showResults('recon', 'Tech Stack', true);
  const res = await msgTab({ type: 'ANALYZE_TECH_STACK' });
  const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
  const srv = [];
  if (hRes.headers?.responseHeaders) hRes.headers.responseHeaders.forEach(h => {
    if (h.name.toLowerCase()==='server') srv.push({name:h.value,category:'Server',confidence:'high'});
    if (h.name.toLowerCase()==='x-powered-by') srv.push({name:h.value,category:'Backend',confidence:'high'});
  });
  const all = [...(res?.data||[]), ...srv];
  b.innerHTML = all.length===0?'<div class="text-muted text-sm">No tech detected</div>':all.map(t=>`<div class="result-item info"><div class="result-label">${esc(t.category)}</div><div class="result-value">${esc(t.name)}</div></div>`).join('');
  finalizeResults('recon');
}

async function toolHeadersAudit() {
  const b = showResults('recon', 'Headers Audit', true);
  const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
  if (!hRes.headers) { b.innerHTML = errMsg('No headers. Reload page first.'); return; }
  const hd = {}; hRes.headers.responseHeaders.forEach(h => { hd[h.name.toLowerCase()] = h.value; });
  const checks = [
    {name:'Content-Security-Policy',key:'content-security-policy',critical:true},{name:'Strict-Transport-Security',key:'strict-transport-security',critical:true},
    {name:'X-Content-Type-Options',key:'x-content-type-options'},{name:'X-Frame-Options',key:'x-frame-options'},
    {name:'Referrer-Policy',key:'referrer-policy'},{name:'Permissions-Policy',key:'permissions-policy'},
    {name:'COOP',key:'cross-origin-opener-policy'},{name:'CORP',key:'cross-origin-resource-policy'},
  ];
  let score = 0;
  const results = checks.map(c => { const v=hd[c.key]; if(v) score += c.critical?15:10; return{...c,value:v,present:!!v}; });
  const leaked = []; ['server','x-powered-by','x-aspnet-version'].forEach(k=>{if(hd[k])leaked.push(k+': '+hd[k])});
  const grade = score>=80?'A':score>=60?'B':score>=40?'C':score>=20?'D':'F';
  b.innerHTML = `<div style="display:flex;align-items:center;margin-bottom:8px"><span class="header-grade grade-${grade.toLowerCase()}">${grade}</span><span class="text-sm">Score: ${score}/100</span></div>`+results.map(r=>`<div class="result-item ${r.present?'info':(r.critical?'high':'medium')}"><div class="result-label"><span class="result-tag ${r.present?'tag-safe':(r.critical?'tag-high':'tag-medium')}">${r.present?'✓':'✗'}</span>${esc(r.name)}</div><div class="result-value">${r.present?esc(r.value).slice(0,120):'Missing'}</div></div>`).join('')+(leaked.length?`<div class="result-item medium mt-6"><div class="result-label">⚠ Info Disclosure</div><div class="result-value">${leaked.map(esc).join('<br>')}</div></div>`:'');
  finalizeResults('recon');
}

async function toolCookies() {
  const b = showResults('recon', 'Cookies', true);
  const res = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', domain: activeTabDomain });
  if (!res.ok||!res.cookies.length) { b.innerHTML = '<div class="text-muted text-sm">No cookies</div>'; finalizeResults('recon'); return; }
  const cookies = res.cookies;
  b.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${cookies.length} cookies</span></div>
    <div style="overflow-x:auto"><table class="cookie-table">
    <tr><th>Name</th><th>Value</th><th></th></tr>
    ${cookies.map((c, i) => `<tr>
      <td title="${esc(c.name)}" style="font-weight:600;color:var(--text)">${esc(c.name)}</td>
      <td title="${esc(c.value)}" style="max-width:140px">${esc(c.value.slice(0, 45))}</td>
      <td style="white-space:nowrap"><button class="btn-sm cookie-cp" data-ci="${i}" style="padding:2px 6px;font-size:9px">Copy</button></td>
    </tr>`).join('')}
    </table></div>
    <div class="tool-input-row mt-6">
      <button class="btn-sm primary" id="ck-header">Copy as Header</button>
      <button class="btn-sm" id="ck-json">Copy JSON</button>
      <button class="btn-sm" id="ck-all">Copy All (name=val)</button>
    </div>`;
  // Per-cookie copy
  b.querySelectorAll('.cookie-cp').forEach(btn => {
    btn.addEventListener('click', () => {
      const c = cookies[parseInt(btn.dataset.ci)];
      copyText(c.name + '=' + c.value);
    });
  });
  // Copy as Cookie header
  b.querySelector('#ck-header')?.addEventListener('click', () => {
    copyText('Cookie: ' + cookies.map(c => c.name + '=' + c.value).join('; '));
  });
  // Copy JSON
  b.querySelector('#ck-json')?.addEventListener('click', () => {
    copyText(JSON.stringify(cookies.map(c => ({ name: c.name, value: c.value, domain: c.domain, path: c.path, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite })), null, 2));
  });
  // Copy all name=value
  b.querySelector('#ck-all')?.addEventListener('click', () => {
    copyText(cookies.map(c => c.name + '=' + c.value).join('\n'));
  });
  finalizeResults('recon');
}

async function toolSubdomains() {
  const b = showResults('recon', 'Subdomains', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Querying crt.sh…</div>';
  const root = getRootDomain(activeTabDomain);
  const res = await chrome.runtime.sendMessage({ type: 'ENUM_SUBDOMAINS', domain: root });
  if (!res.ok) { b.innerHTML = errMsg(res.error); return; }
  const subs = res.subdomains.filter(s => !s.startsWith('*'));
  b.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${subs.length} subdomains for ${esc(root)}</span></div>`+subs.map(s=>`<div class="result-item info"><div class="result-value">${esc(s)}</div></div>`).join('');
  finalizeResults('recon');
}

async function toolReqResp() {
  const b = showResults('recon', 'Req / Resp', true);
  const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
  const cookieRes = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', domain: activeTabDomain });
  const h = hRes.headers;
  const cookies = cookieRes.ok ? cookieRes.cookies : [];
  const cookieStr = cookies.map(c => c.name + '=' + c.value).join('; ');

  // Build request string — combine captured headers + cookies
  const u = new URL(activeTabUrl);
  let reqStr = `GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.hostname}\r\n`;
  if (h && h.requestHeaders && h.requestHeaders.length) {
    // Use captured headers (includes Referer, User-Agent, Accept, etc.)
    h.requestHeaders.forEach(rh => { reqStr += `${rh.name}: ${rh.value}\r\n`; });
    // If Cookie wasn't captured, add it from cookies API
    if (!h.requestHeaders.some(rh => rh.name.toLowerCase() === 'cookie') && cookieStr) {
      reqStr += `Cookie: ${cookieStr}\r\n`;
    }
  } else {
    // No captured headers — build synthetic from what we know
    reqStr += `User-Agent: Mozilla/5.0\r\n`;
    reqStr += `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n`;
    reqStr += `Referer: ${u.origin}/\r\n`;
    if (cookieStr) reqStr += `Cookie: ${cookieStr}\r\n`;
  }
  reqStr += '\r\n';

  // Build response string
  let resStr = '';
  if (h) {
    resStr = `HTTP/1.1 ${h.statusCode}\r\n`;
    h.responseHeaders.forEach(rh => { resStr += `${rh.name}: ${rh.value}\r\n`; });
  }

  const stale = h && h.url !== activeTabUrl;
  b.innerHTML =
    (stale ? `<div class="result-item medium mb-4"><div class="result-value">⚠ Headers from ${esc(new URL(h.url).pathname)} — current: ${esc(u.pathname)}</div></div>` : '') +
    `<div class="result-label mb-4">Request (${cookies.length} cookies attached)</div>
    <pre class="result-value" style="max-height:180px;overflow:auto;white-space:pre-wrap;margin-bottom:8px">${esc(reqStr)}</pre>
    <div class="result-label mb-4">Response Headers</div>
    <pre class="result-value" style="max-height:160px;overflow:auto;white-space:pre-wrap">${esc(resStr || '(reload page to capture)')}</pre>
    <div class="tool-input-row mt-6">
      <button class="btn-sm primary" id="rr-req">Copy Req</button>
      <button class="btn-sm primary" id="rr-res">Copy Resp</button>
      <button class="btn-sm" id="rr-both">Copy Both</button>
    </div>
    <div class="result-label mt-8 mb-4">Re-fetch with Editor</div>
    <div class="tool-input-row">
      <select class="tool-select" id="rr-method" style="width:80px"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>OPTIONS</option><option>HEAD</option></select>
    </div>
    <input class="tool-input mb-4" id="rr-url" value="${esc(activeTabUrl)}">
    <textarea class="tool-input mb-4" id="rr-edit-headers" rows="4" style="font-size:10px" placeholder="Edit headers…">${esc(JSON.stringify({ 'User-Agent': 'Mozilla/5.0', 'Cookie': cookieStr || '', 'Accept': '*/*' }, null, 2))}</textarea>
    <textarea class="tool-input mb-4" id="rr-edit-body" rows="2" placeholder="Request body (POST/PUT)"></textarea>
    <div class="tool-input-row">
      <button class="btn-sm primary" id="rr-send">Send Request</button>
      <button class="btn-sm" id="rr-curl">Copy as cURL</button>
    </div>
    <pre class="result-value mt-6" id="rr-response" style="max-height:200px;overflow:auto;white-space:pre-wrap;font-size:10px"></pre>`;

  b.querySelector('#rr-req')?.addEventListener('click', () => copyText(reqStr));
  b.querySelector('#rr-res')?.addEventListener('click', () => copyText(resStr));
  b.querySelector('#rr-both')?.addEventListener('click', () => copyText('=== REQUEST ===\n' + reqStr + '\n=== RESPONSE ===\n' + resStr));

  b.querySelector('#rr-send')?.addEventListener('click', async () => {
    const url = b.querySelector('#rr-url').value;
    const method = b.querySelector('#rr-method').value;
    let headers = {}; try { headers = JSON.parse(b.querySelector('#rr-edit-headers').value); } catch {}
    const body = b.querySelector('#rr-edit-body').value || undefined;
    const out = b.querySelector('#rr-response');
    out.textContent = 'Sending…';
    const r = await chrome.runtime.sendMessage({ type: 'REPLAY_REQUEST', url, method, headers, body });
    if (r.ok) {
      let respText = `HTTP/1.1 ${r.status} ${r.statusText}\r\n`;
      Object.entries(r.headers).forEach(([k,v]) => { respText += `${k}: ${v}\r\n`; });
      respText += `\r\n${r.text.slice(0, 3000)}`;
      out.textContent = respText;
    } else {
      out.textContent = 'Error: ' + r.error;
    }
  });

  b.querySelector('#rr-curl')?.addEventListener('click', () => {
    const m = b.querySelector('#rr-method').value;
    const url = b.querySelector('#rr-url').value;
    let headers = {}; try { headers = JSON.parse(b.querySelector('#rr-edit-headers').value); } catch {}
    const body = b.querySelector('#rr-edit-body').value;
    let curl = `curl -X ${m}`;
    Object.entries(headers).forEach(([k,v]) => { if (v) curl += ` -H '${k}: ${v}'`; });
    if (body) curl += ` -d '${body}'`;
    curl += ` '${url}'`;
    copyText(curl);
  });

  finalizeResults('recon');
}

async function toolDns() {
  const b = showResults('recon', 'DNS Lookup', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Resolving…</div>';
  const res = await chrome.runtime.sendMessage({ type: 'DNS_LOOKUP', domain: activeTabDomain });
  if (!res.ok) { b.innerHTML = errMsg(res.error); return; }
  b.innerHTML = Object.entries(res.records).map(([t,r])=>`<div class="result-item info"><div class="result-label">${t}</div><div class="result-value">${r.map(esc).join('<br>')}</div></div>`).join('')||'<div class="text-muted text-sm">No records</div>';
  finalizeResults('recon');
}

async function toolWpPlugins() {
  const b = showResults('recon', 'WP Plugins', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Scanning for WordPress…</div>';
  const res = await chrome.runtime.sendMessage({ type: 'DETECT_WP_PLUGINS', url: activeTabUrl });
  if (!res.ok) { b.innerHTML = errMsg(res.error); return; }
  if (!res.plugins.length && !res.themes.length && !res.wpVersion) {
    b.innerHTML = '<div class="text-muted text-sm">No WordPress detected on this page</div>';
    finalizeResults('recon'); return;
  }
  let html = '';
  if (res.wpVersion) html += `<div class="result-item info"><div class="result-label">WordPress Version</div><div class="result-value">${esc(res.wpVersion)}</div></div>`;
  if (res.themes.length) {
    html += `<div class="result-label mt-6 mb-4">Themes (${res.themes.length})</div>`;
    html += res.themes.map(t => `<div class="result-item info"><div class="result-value">${esc(t)}</div></div>`).join('');
  }
  if (res.plugins.length) {
    html += `<div class="result-label mt-6 mb-4">Plugins (${res.plugins.length})</div>`;
    html += res.plugins.map(p => `<div class="result-item ${p.version?'medium':'info'}"><div class="result-value">${esc(p.name)}${p.version?' <span class="result-tag tag-medium">v'+esc(p.version)+'</span>':''}</div></div>`).join('');
  }
  b.innerHTML = html;
  finalizeResults('recon');
}

async function toolSecrets() {
  const b = showResults('analysis', 'Secrets', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Scanning JS…</div>';
  const sr = await msgTab({ type: 'GET_SCRIPT_URLS' });
  if (!sr?.ok) { b.innerHTML = errMsg(sr?.error||'Cannot access page'); return; }
  const findings = [];
  for (const url of sr.data.external.slice(0,20)) { try { const r = await chrome.runtime.sendMessage({type:'FETCH_JS',url}); if(r.ok) scanSecrets(r.text,url,findings); } catch{} }
  sr.data.inline.slice(0,10).forEach((txt,i) => scanSecrets(txt,'[inline-'+i+']',findings));
  if (findings.length) { const bd=document.getElementById('badge-analysis'); bd.textContent=findings.length; bd.classList.remove('hidden'); }
  b.innerHTML = findings.length===0?'<div class="text-muted text-sm">No secrets detected</div>':findings.slice(0,50).map(f=>`<div class="result-item ${f.severity}"><div class="result-label"><span class="result-tag tag-${f.severity}">${f.severity}</span>${esc(f.name)}</div><div class="result-value">${esc(f.match.slice(0,80))}</div><div class="text-xs text-muted">${esc(f.source.split('/').pop())}</div></div>`).join('');
  finalizeResults('analysis');
}
function scanSecrets(text,source,findings){for(const p of SECRET_PATTERNS){const re=new RegExp(p.regex.source,p.regex.flags);let m;while((m=re.exec(text))!==null){const v=m[1]||m[0];if(v.length<8)continue;if(p.name==='IP Address'&&(v.startsWith('0.')||v.startsWith('127.')))continue;if(!findings.some(f=>f.match===v))findings.push({name:p.name,match:v,severity:p.severity,source})}}}

async function toolEndpoints() {
  const b = showResults('analysis', 'Endpoints', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Extracting…</div>';
  const sr = await msgTab({ type: 'GET_SCRIPT_URLS' });
  if (!sr?.ok) { b.innerHTML = errMsg(sr?.error||'Cannot access page'); return; }
  const eps = new Set();
  const proc = t => { for(const p of ENDPOINT_PATTERNS){const re=new RegExp(p.source,p.flags);let m;while((m=re.exec(t))!==null){const ep=m[1]||m[0];if(ep.length>4&&!/\.(js|css|png|jpg|svg|woff)$/.test(ep))eps.add(ep)}} };
  for(const url of sr.data.external.slice(0,20)){try{const r=await chrome.runtime.sendMessage({type:'FETCH_JS',url});if(r.ok)proc(r.text)}catch{}}
  sr.data.inline.forEach(proc);
  const sorted = [...eps].sort();
  b.innerHTML = sorted.length===0?'<div class="text-muted text-sm">No endpoints</div>':`<div class="text-sm mb-6">${sorted.length} endpoints</div>`+sorted.map(ep=>`<div class="result-item info"><div class="result-value">${esc(ep)}</div></div>`).join('');
  finalizeResults('analysis');
}

async function toolHidden() {
  const b = showResults('analysis', 'Hidden', true);
  const res = await msgTab({ type: 'FIND_HIDDEN_ELEMENTS' });
  const comments = await msgTab({ type: 'FIND_COMMENTS' });
  if (!res?.ok) { b.innerHTML = errMsg(res?.error||'Cannot access page'); return; }
  const d = res.data; const total = d.hiddenInputs.length+d.hiddenDivs.length+d.disabledInputs.length+d.dataAttrs.length+(comments.data?.length||0);
  let html = `<div class="flex-between mb-6"><span class="text-sm">${total} hidden items</span><button class="btn-sm primary" id="btn-reveal">Reveal All</button></div>`;
  if(d.hiddenInputs.length) html += d.hiddenInputs.map(h=>`<div class="result-item medium"><div class="result-value">${esc(h.name)} = ${esc(h.value)}</div></div>`).join('');
  if(d.dataAttrs.length) html += d.dataAttrs.map(a=>`<div class="result-item low"><div class="result-value">${esc(a.attr)} = ${esc(a.value)}</div></div>`).join('');
  if(comments.data?.length) html += comments.data.slice(0,20).map(c=>`<div class="result-item info"><div class="result-value">${esc(c)}</div></div>`).join('');
  b.innerHTML = html;
  b.querySelector('#btn-reveal')?.addEventListener('click', async()=>{await msgTab({type:'REVEAL_HIDDEN'});log('Revealed','success')});
  finalizeResults('analysis');
}

async function toolLinks() {
  const b = showResults('analysis', 'Links', true);
  const res = await msgTab({ type: 'EXTRACT_LINKS' });
  if (!res?.ok) { b.innerHTML = errMsg(res?.error||'Cannot access page'); return; }
  const d = res.data;
  b.innerHTML = `<div class="codec-row mb-6"><button class="btn-sm" data-lk="internal">Internal (${d.internal.length})</button><button class="btn-sm" data-lk="external">External (${d.external.length})</button><button class="btn-sm" data-lk="interesting">Files (${d.interesting.length})</button><button class="btn-sm" data-lk="emails">Emails (${d.emails.length})</button></div><div id="lk-c"></div>`;
  const show = type => { const c=b.querySelector('#lk-c'); const items=type==='emails'?d.emails:d[type].map(l=>l.url||l);
    c.innerHTML=items.slice(0,60).map(i=>`<div class="result-item ${type==='interesting'?'medium':'info'}"><div class="result-value">${esc(i)}</div></div>`).join('')+`<div class="mt-6"><button class="btn-sm" id="cp-lk">Copy All (${items.length})</button></div>`;
    c.querySelector('#cp-lk')?.addEventListener('click',()=>copyText(items.join('\n'))); };
  b.querySelectorAll('[data-lk]').forEach(btn=>btn.addEventListener('click',()=>show(btn.dataset.lk)));
  show('internal'); finalizeResults('analysis');
}

async function toolReplayer() {
  const b = showResults('active', 'Replayer', true);
  const res = await chrome.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS', tabId: activeTabId });
  const reqs = res.requests||[];
  if(!reqs.length){ b.innerHTML='<div class="text-muted text-sm">No requests captured. Browse first.</div>'; return; }
  const display = reqs.slice(-15).reverse();
  b.innerHTML = `<div class="text-sm mb-6">${reqs.length} captured</div>`+display.map((r,i)=>{const u=new URL(r.url);return`<div class="result-item info" style="cursor:pointer" data-ri="${i}"><div class="result-label"><span class="result-tag tag-info">${r.method||'GET'}</span>${r.statusCode||'?'}</div><div class="result-value">${esc(u.pathname+u.search).slice(0,70)}</div></div>`}).join('')+
  `<div class="mt-8" id="rp-det" style="display:none"><div class="tool-input-row"><select class="tool-select" id="rp-m" style="width:80px"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>OPTIONS</option></select></div><input class="tool-input mb-6" id="rp-u"><textarea class="tool-input mb-6" id="rp-h" rows="2" placeholder="Headers JSON">{}</textarea><textarea class="tool-input mb-6" id="rp-b" rows="2" placeholder="Body"></textarea><div class="tool-input-row"><button class="btn-sm primary" id="rp-send">Send</button><button class="btn-sm" id="rp-curl">cURL</button></div><pre class="result-value mt-6" id="rp-out" style="max-height:200px;overflow:auto;white-space:pre-wrap"></pre></div>`;
  b.querySelectorAll('[data-ri]').forEach(el=>el.addEventListener('click',()=>{const r=display[+el.dataset.ri];b.querySelector('#rp-det').style.display='block';b.querySelector('#rp-m').value=r.method||'GET';b.querySelector('#rp-u').value=r.url}));
  b.querySelector('#rp-send')?.addEventListener('click',async()=>{let h={};try{h=JSON.parse(b.querySelector('#rp-h').value)}catch{};const r=await chrome.runtime.sendMessage({type:'REPLAY_REQUEST',url:b.querySelector('#rp-u').value,method:b.querySelector('#rp-m').value,headers:h,body:b.querySelector('#rp-b').value||undefined});b.querySelector('#rp-out').textContent=r.ok?`HTTP ${r.status}\n${JSON.stringify(r.headers,null,2)}\n\n${r.text.slice(0,2000)}`:'Error: '+r.error});
  b.querySelector('#rp-curl')?.addEventListener('click',()=>{copyText(`curl -X ${b.querySelector('#rp-m').value} '${b.querySelector('#rp-u').value}'`)});
  finalizeResults('active');
}

async function toolCors() {
  const b = showResults('active','CORS',false);
  b.innerHTML=`<div class="tool-input-row mb-6"><input class="tool-input" id="cors-u" value="${esc(activeTabUrl)}"><button class="btn-sm primary" id="cors-go">Test</button></div><div id="cors-o"></div>`;
  b.querySelector('#cors-go').addEventListener('click',async()=>{const url=b.querySelector('#cors-u').value,o=b.querySelector('#cors-o');o.innerHTML='<div class="loading-text"><span class="spinner"></span></div>';const r=await chrome.runtime.sendMessage({type:'TEST_CORS',url,targetOrigin:new URL(url).origin});if(!r.ok){o.innerHTML=errMsg('Failed');return}o.innerHTML=r.results.map(x=>{const v=x.acao&&(x.acao==='*'||x.acao===x.origin)&&x.acac==='true';return`<div class="result-item ${v?'high':'info'}"><div class="result-label">${x.type||'OPTIONS'} Origin: ${esc(x.origin||'?')}</div><div class="result-value">ACAO: ${esc(x.acao||'none')} | ACAC: ${esc(x.acac||'none')}</div>${v?'<div class="text-xs text-accent" style="font-weight:600">⚠ CORS misconfiguration!</div>':''}</div>`}).join('');finalizeResults('active')});
}

async function toolRedirect() {
  const b = showResults('active','Redirect',true);
  const r = await msgTab({ type: 'CHECK_PASSIVE_VULNS' });
  const rf = (r?.data||[]).filter(f=>f.type==='Potential Open Redirect');
  b.innerHTML = rf.length?rf.map(f=>`<div class="result-item medium"><div class="result-label"><span class="result-tag tag-medium">POTENTIAL</span>${esc(f.type)}</div><div class="result-value">${esc(f.detail)}</div></div>`).join(''):'<div class="text-muted text-sm">No redirect params</div>';
  finalizeResults('active');
}

function toolCodec() {
  const b = showResults('active','Codec',false);
  b.innerHTML=`<textarea class="tool-input mb-6" id="ci" rows="3" placeholder="Input…"></textarea><div class="codec-row"><button class="btn-sm" data-e="b64e">B64 Enc</button><button class="btn-sm" data-e="b64d">B64 Dec</button><button class="btn-sm" data-e="urle">URL Enc</button><button class="btn-sm" data-e="urld">URL Dec</button><button class="btn-sm" data-e="htmle">HTML Ent</button><button class="btn-sm" data-e="htmld">HTML Dec</button><button class="btn-sm" data-e="hex">Hex</button><button class="btn-sm" data-e="unhex">Unhex</button><button class="btn-sm" data-e="jwt">JWT</button><button class="btn-sm" data-e="rot13">ROT13</button><button class="btn-sm" data-e="len">Length</button></div><textarea class="tool-input mt-6" id="co" rows="3" readonly placeholder="Output…"></textarea><div class="mt-6"><button class="btn-sm" id="cc-cp">Copy</button> <button class="btn-sm" id="cc-sw">↕ Swap</button></div>`;
  const i=b.querySelector('#ci'),o=b.querySelector('#co');
  b.querySelectorAll('[data-e]').forEach(btn=>btn.addEventListener('click',()=>{const v=i.value;try{switch(btn.dataset.e){case'b64e':o.value=btoa(unescape(encodeURIComponent(v)));break;case'b64d':o.value=decodeURIComponent(escape(atob(v)));break;case'urle':o.value=encodeURIComponent(v);break;case'urld':o.value=decodeURIComponent(v);break;case'htmle':o.value=v.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));break;case'htmld':{const d=document.createElement('div');d.innerHTML=v;o.value=d.textContent;break}case'hex':o.value=[...v].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');break;case'unhex':o.value=v.replace(/\s/g,'').match(/.{2}/g)?.map(x=>String.fromCharCode(parseInt(x,16))).join('')||'';break;case'jwt':{const p=v.split('.');o.value=JSON.stringify({header:JSON.parse(atob(p[0].replace(/-/g,'+').replace(/_/g,'/'))),payload:JSON.parse(atob(p[1].replace(/-/g,'+').replace(/_/g,'/')))},null,2);break}case'rot13':o.value=v.replace(/[a-zA-Z]/g,c=>String.fromCharCode(c.charCodeAt(0)+(c.toLowerCase()<'n'?13:-13)));break;case'len':o.value=`${v.length} chars, ${new Blob([v]).size} bytes`;break}}catch(e){o.value='Error: '+e.message}}));
  b.querySelector('#cc-cp')?.addEventListener('click',()=>copyText(o.value));
  b.querySelector('#cc-sw')?.addEventListener('click',()=>{i.value=o.value;o.value=''});
}

function toolScope() {
  const b = showResults('workflow','Scope',false);
  const render = () => {
    b.innerHTML=`<div class="tool-input-row mb-6"><input class="tool-input" id="sc-i" placeholder="Add domain"><button class="btn-sm primary" id="sc-a">Add</button></div><div class="flex-between mb-6"><span class="text-sm">${scopeDomains.length} in scope</span><button class="btn-sm" id="sc-ac">+ Current</button></div><ul class="scope-list">${scopeDomains.map((d,i)=>`<li class="scope-item"><button class="remove-scope" data-idx="${i}">✕</button><span>${esc(d)}</span></li>`).join('')}</ul>`;
    b.querySelector('#sc-a')?.addEventListener('click',()=>{const v=b.querySelector('#sc-i').value.trim();if(v&&!scopeDomains.includes(v)){scopeDomains.push(v);chrome.storage.local.set({scopeDomains});updateScopeIndicator();render()}});
    b.querySelector('#sc-ac')?.addEventListener('click',()=>{const r=getRootDomain(activeTabDomain);if(r&&!scopeDomains.includes(r)){scopeDomains.push(r);chrome.storage.local.set({scopeDomains});updateScopeIndicator();render()}});
    b.querySelectorAll('.remove-scope').forEach(x=>x.addEventListener('click',()=>{scopeDomains.splice(+x.dataset.idx,1);chrome.storage.local.set({scopeDomains});updateScopeIndicator();render()}));
  };
  render();
}

function toolNotes() {
  const b = showResults('workflow','Notes',false);
  const key = getRootDomain(activeTabDomain)||'global';
  b.innerHTML=`<textarea class="notes-editor" id="nt" placeholder="Notes for ${key}…">${esc(notes[key]||'')}</textarea><div class="tool-input-row mt-6"><button class="btn-sm primary" id="ns">Save</button><button class="btn-sm" id="nc">Copy</button><button class="btn-sm" id="ne">Export</button></div>`;
  b.querySelector('#ns')?.addEventListener('click',()=>{notes[key]=b.querySelector('#nt').value;chrome.storage.local.set({notes});log('Saved: '+key,'success')});
  b.querySelector('#nc')?.addEventListener('click',()=>copyText(b.querySelector('#nt').value));
  b.querySelector('#ne')?.addEventListener('click',()=>downloadText(b.querySelector('#nt').value,'cyboware-notes-'+key+'.txt'));
}

// ═══ BROWSE HISTORY ═══
function toolHistory() {
  const b = showResults('workflow','Browse History',false);
  const root = getRootDomain(activeTabDomain);
  const entries = browseHistory[root] || [];
  if (!entries.length) {
    b.innerHTML = `<div class="text-muted text-sm">No history yet for ${esc(root||'this domain')}.</div><div class="text-xs text-muted mt-4">History auto-records when a domain is in your Scope.</div>`;
    return;
  }
  const sorted = [...entries].sort((a,c) => c.timestamp - a.timestamp);
  b.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${sorted.length} URLs for ${esc(root)}</span><button class="btn-sm" id="bh-copy">Copy All</button></div><div class="tool-input-row"><button class="btn-sm" id="bh-clear">Clear History</button><button class="btn-sm" id="bh-json">Export JSON</button></div><div class="mt-6">${sorted.map(e => {
    const d = new Date(e.timestamp);
    return `<div class="result-item info"><div class="result-label">${d.toLocaleTimeString()} ${d.toLocaleDateString()}</div><div class="result-value">${esc(e.url)}</div><div class="text-xs text-muted">${esc(e.title)}</div></div>`;
  }).join('')}</div>`;
  b.querySelector('#bh-copy')?.addEventListener('click',()=>copyText(sorted.map(e=>e.url).join('\n')));
  b.querySelector('#bh-json')?.addEventListener('click',()=>copyText(JSON.stringify(sorted,null,2)));
  b.querySelector('#bh-clear')?.addEventListener('click',()=>{delete browseHistory[root];chrome.storage.local.set({browseHistory});toolHistory()});
}

async function toolScreenshot() {
  const b = showResults('workflow','Screenshot',true);
  const res = await chrome.runtime.sendMessage({ type: 'TAKE_SCREENSHOT' });
  if (!res.ok) { b.innerHTML = errMsg(res.error); return; }
  b.innerHTML=`<img src="${res.dataUrl}" style="max-width:100%;border:1px solid var(--border);border-radius:var(--radius)"><div class="tool-input-row mt-6"><button class="btn-sm primary" id="ss-dl">Download</button></div>`;
  b.querySelector('#ss-dl')?.addEventListener('click',()=>{const a=document.createElement('a');a.href=res.dataUrl;a.download=`cyboware-${activeTabDomain}-${Date.now()}.png`;a.click()});
  finalizeResults('workflow');
}

async function toolPassive() {
  const b = showResults('smart','Vuln Hints',true);
  const r = await msgTab({ type: 'CHECK_PASSIVE_VULNS' });
  const f = r?.data||[];
  if(f.length){const bd=document.getElementById('badge-smart');bd.textContent=f.length;bd.classList.remove('hidden')}
  b.innerHTML = f.length===0?'<div class="text-muted text-sm">No passive findings</div>':f.map(x=>`<div class="result-item ${x.severity}"><div class="result-label"><span class="result-tag tag-${x.severity}">${x.severity}</span>${esc(x.type)}</div><div class="result-value">${esc(x.detail)}</div></div>`).join('');
  finalizeResults('smart');
}

async function toolWayback() {
  const b = showResults('smart','Wayback',true);
  b.innerHTML='<div class="loading-text"><span class="spinner"></span> Querying…</div>';
  const r = await chrome.runtime.sendMessage({ type: 'WAYBACK_LOOKUP', url: activeTabUrl });
  if(!r.ok){b.innerHTML=errMsg(r.error);return}
  b.innerHTML=!r.snapshots.length?'<div class="text-muted text-sm">No snapshots</div>':`<div class="text-sm mb-6">${r.snapshots.length} snapshots</div>`+r.snapshots.map(s=>{const d=s[0].slice(0,4)+'-'+s[0].slice(4,6)+'-'+s[0].slice(6,8);return`<div class="result-item info"><a href="https://web.archive.org/web/${s[0]}/${s[1]}" target="_blank" style="color:var(--accent);text-decoration:none"><div class="result-label">${d}</div><div class="result-value">${esc(s[1]).slice(0,60)} (${s[2]})</div></a></div>`}).join('');
  finalizeResults('smart');
}

function toolDiff() {
  const b = showResults('smart','Diff',false);
  b.innerHTML=`<div class="text-sm mb-6">Fetch same URL with different headers</div><div class="tool-input-row"><input class="tool-input" id="df-u" value="${esc(activeTabUrl)}"></div><textarea class="tool-input mb-6" id="df-h" rows="2" placeholder='{"Cookie":"a=1"}'>{}</textarea><div class="tool-input-row mb-6"><button class="btn-sm primary" id="df-a">→ A</button><button class="btn-sm primary" id="df-b">→ B</button><button class="btn-sm success" id="df-c" ${!diffStore.a||!diffStore.b?'disabled':''}>Compare</button></div><div class="text-xs mb-6">A: ${diffStore.a?'✓ '+diffStore.a.status:'—'} | B: ${diffStore.b?'✓ '+diffStore.b.status:'—'}</div><pre class="result-value" id="df-o" style="max-height:250px;overflow:auto;white-space:pre-wrap;font-size:10px"></pre>`;
  const fetch_ = async s=>{let h={};try{h=JSON.parse(b.querySelector('#df-h').value)}catch{};const r=await chrome.runtime.sendMessage({type:'FETCH_URL',url:b.querySelector('#df-u').value,headers:h});diffStore[s]={text:r.text||'',status:r.status};toolDiff()};
  b.querySelector('#df-a')?.addEventListener('click',()=>fetch_('a'));
  b.querySelector('#df-b')?.addEventListener('click',()=>fetch_('b'));
  b.querySelector('#df-c')?.addEventListener('click',()=>{if(!diffStore.a||!diffStore.b)return;const la=diffStore.a.text.split('\n'),lb=diffStore.b.text.split('\n');let d=`--- A (${diffStore.a.status})\n+++ B (${diffStore.b.status})\n\n`,n=0;for(let i=0;i<Math.max(la.length,lb.length);i++){if((la[i]||'')!==(lb[i]||'')){d+=`@@ ${i+1} @@\n- ${la[i]||''}\n+ ${lb[i]||''}\n`;n++;if(n>100){d+='\n[truncated]';break}}}if(!n)d+='(No differences)';b.querySelector('#df-o').textContent=d});
}

// ═══ PARAMETER FUZZER ═══
async function toolParamFuzz() {
  const b = showResults('active', 'Param Fuzzer', false);
  const u = new URL(activeTabUrl);
  const params = [...u.searchParams.keys()];
  b.innerHTML = `<div class="text-sm mb-6">${params.length ? params.length + ' params detected: ' + params.map(esc).join(', ') : 'No URL params — paste a URL with parameters'}</div>
    <div class="tool-input-row"><input class="tool-input" id="fz-url" value="${esc(activeTabUrl)}" placeholder="URL with params"></div>
    <div class="codec-row mb-6">
      <button class="btn-sm primary" data-fzcat="xss">XSS</button>
      <button class="btn-sm" data-fzcat="sqli">SQLi</button>
      <button class="btn-sm" data-fzcat="ssti">SSTI</button>
      <button class="btn-sm" data-fzcat="path">Path Traversal</button>
    </div>
    <div id="fz-out"></div>`;
  b.querySelectorAll('[data-fzcat]').forEach(btn => btn.addEventListener('click', async () => {
    const out = b.querySelector('#fz-out');
    const url = b.querySelector('#fz-url').value;
    const cat = btn.dataset.fzcat;
    out.innerHTML = `<div class="loading-text"><span class="spinner"></span> Fuzzing ${cat.toUpperCase()} payloads…</div>`;
    const r = await chrome.runtime.sendMessage({ type: 'PARAM_FUZZ', url, category: cat });
    if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
    if (r.message) { out.innerHTML = `<div class="text-muted text-sm">${esc(r.message)}</div>`; return; }
    const critical = r.results.filter(x => x.severity === 'high');
    const warnings = r.results.filter(x => x.severity === 'medium' || x.severity === 'low');
    out.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${r.results.length} tests${r.baselineLen ? ' · baseline: ' + r.baselineLen + 'b' : ''}</span><span class="text-sm"><span class="${critical.length ? 'text-accent' : 'text-muted'}" style="font-weight:700">${critical.length} critical</span>, ${warnings.length} warnings</span></div>` +
      r.results.map(x => {
        const sevColor = x.severity === 'high' ? 'high' : x.severity === 'medium' ? 'medium' : x.severity === 'low' ? 'low' : 'info';
        const tagClass = x.severity === 'high' ? 'tag-high' : x.severity === 'medium' ? 'tag-medium' : x.severity === 'low' ? 'tag-low' : 'tag-safe';
        const tagText = x.severity === 'high' ? 'VULN' : x.severity === 'medium' ? 'WARN' : x.severity === 'low' ? 'NOTE' : 'SAFE';
        return `<div class="result-item ${sevColor}">
          <div class="result-label"><span class="result-tag ${tagClass}">${tagText}</span> ${esc(x.param)}</div>
          <div class="result-value" style="margin-bottom:3px">${esc(x.payload)}</div>
          <div class="text-xs" style="color:var(--text-secondary);margin-bottom:2px">${esc(x.analysis)}</div>
          ${x.status ? `<div class="text-xs text-muted">HTTP ${x.status} · ${x.bodyLen} bytes</div>` : ''}
          ${x.context ? `<div style="margin-top:4px;padding:4px 6px;background:${x.severity==='high'?'var(--danger-soft)':'var(--surface-hover)'};border-radius:3px;font-family:var(--font-mono);font-size:9px;word-break:break-all;max-height:70px;overflow:auto">${esc(x.context)}</div>` : ''}
        </div>`;
      }).join('');
    finalizeResults('active');
    log(`Fuzz: ${critical.length} critical, ${warnings.length} warnings (${cat})`, critical.length ? 'warn' : 'success');
  }));
}

// ═══ JS BEAUTIFIER ═══
async function toolJsBeautify() {
  const b = showResults('analysis', 'JS Beautifier', false);
  const sr = await msgTab({ type: 'GET_SCRIPT_URLS' });
  const scripts = sr?.ok ? sr.data.external : [];
  b.innerHTML = `<div class="text-sm mb-6">${scripts.length} external JS files</div>
    <select class="tool-select mb-6" id="jb-select" style="font-size:10px">
      <option value="">Select a JS file…</option>
      ${scripts.slice(0, 30).map((s, i) => `<option value="${esc(s)}">${esc(s.split('/').pop() || s).slice(0, 50)}</option>`).join('')}
    </select>
    <div class="tool-input-row mb-6"><button class="btn-sm primary" id="jb-go">Beautify</button><button class="btn-sm" id="jb-copy">Copy</button><button class="btn-sm" id="jb-dl">Download</button></div>
    <textarea class="tool-input" id="jb-out" rows="12" readonly style="font-size:10px;min-height:200px" placeholder="Beautified output…"></textarea>`;
  let beautified = '';
  b.querySelector('#jb-go')?.addEventListener('click', async () => {
    const url = b.querySelector('#jb-select').value;
    if (!url) return;
    b.querySelector('#jb-out').value = 'Loading & beautifying…';
    const r = await chrome.runtime.sendMessage({ type: 'FETCH_JS', url });
    if (!r.ok) { b.querySelector('#jb-out').value = 'Error: ' + r.error; return; }
    beautified = jsBeautify(r.text);
    b.querySelector('#jb-out').value = beautified;
    log('Beautified: ' + url.split('/').pop(), 'success');
  });
  b.querySelector('#jb-copy')?.addEventListener('click', () => copyText(beautified || b.querySelector('#jb-out').value));
  b.querySelector('#jb-dl')?.addEventListener('click', () => { if (beautified) downloadText(beautified, 'beautified.js'); });
}

function jsBeautify(code) {
  // Simple but effective JS beautifier
  let out = '', indent = 0, inStr = false, strChar = '', escaped = false;
  const addNewline = () => { out += '\n' + '  '.repeat(Math.max(0, indent)); };
  for (let i = 0; i < code.length; i++) {
    const c = code[i], prev = code[i - 1], next = code[i + 1];
    if (escaped) { out += c; escaped = false; continue; }
    if (c === '\\') { out += c; escaped = true; continue; }
    if (inStr) { out += c; if (c === strChar) inStr = false; continue; }
    if (c === '"' || c === "'" || c === '`') { out += c; inStr = true; strChar = c; continue; }
    if (c === '{' || c === '[') { out += c; indent++; addNewline(); continue; }
    if (c === '}' || c === ']') { indent--; addNewline(); out += c; continue; }
    if (c === ';') { out += c; if (next !== '}' && next !== ']') addNewline(); continue; }
    if (c === ',') { out += c; if (indent > 0) addNewline(); continue; }
    out += c;
  }
  return out;
}

// ═══ CSP EVALUATOR ═══
async function toolCspEval() {
  const b = showResults('smart', 'CSP Evaluator', true);
  const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
  let csp = null;
  if (hRes.headers?.responseHeaders) {
    const cspH = hRes.headers.responseHeaders.find(h => h.name.toLowerCase() === 'content-security-policy');
    if (cspH) csp = cspH.value;
  }
  if (!csp) {
    b.innerHTML = '<div class="result-item medium"><div class="result-label">No CSP Header</div><div class="result-value">This page has no Content-Security-Policy header — all resources allowed from any origin.</div></div>';
    finalizeResults('smart'); return;
  }
  const r = await chrome.runtime.sendMessage({ type: 'EVALUATE_CSP', csp });
  if (!r.ok) { b.innerHTML = errMsg(r.error); return; }
  const gradeClass = 'grade-' + r.grade.toLowerCase();
  b.innerHTML = `<div style="display:flex;align-items:center;margin-bottom:8px"><span class="header-grade ${gradeClass}">${r.grade}</span><span class="text-sm">${r.findings.length} finding${r.findings.length===1?'':'s'}</span></div>` +
    `<div class="result-item info mb-6"><div class="result-label">Raw CSP</div><div class="result-value" style="font-size:9px;word-break:break-all">${esc(r.raw)}</div></div>` +
    r.findings.map(f => `<div class="result-item ${f.severity}"><div class="result-label"><span class="result-tag tag-${f.severity}">${f.severity}</span>${esc(f.directive)}: ${esc(f.issue)}</div><div class="result-value">${esc(f.detail)}</div></div>`).join('');
  finalizeResults('smart');
  log('CSP: Grade ' + r.grade + ' (' + r.findings.length + ' findings)', r.grade <= 'B' ? 'success' : 'warn');
}

// ═══ SUBDOMAIN TAKEOVER ═══
async function toolTakeover() {
  const b = showResults('smart', 'Takeover Check', true);
  // First get subdomains
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Step 1: Enumerating subdomains…</div>';
  const root = getRootDomain(activeTabDomain);
  const subRes = await chrome.runtime.sendMessage({ type: 'ENUM_SUBDOMAINS', domain: root });
  if (!subRes.ok) { b.innerHTML = errMsg('Need subdomains first: ' + (subRes.error||'enum failed')); return; }
  const subs = subRes.subdomains.filter(s => !s.startsWith('*')).slice(0, 30);
  b.innerHTML = `<div class="loading-text"><span class="spinner"></span> Step 2: Checking ${subs.length} subdomains for dangling CNAMEs…</div>`;
  const r = await chrome.runtime.sendMessage({ type: 'CHECK_TAKEOVER', subdomains: subs });
  if (!r.ok) { b.innerHTML = errMsg(r.error); return; }
  if (!r.results.length) {
    b.innerHTML = `<div class="text-muted text-sm">No dangling CNAMEs found across ${subs.length} subdomains</div>`;
    finalizeResults('smart'); return;
  }
  const vulns = r.results.filter(x => x.vulnerable);
  b.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${r.results.length} CNAME matches, <span class="${vulns.length?'text-accent':'text-muted'}" style="font-weight:700">${vulns.length} potentially vulnerable</span></span></div>` +
    r.results.map(x => `<div class="result-item ${x.vulnerable ? 'high' : 'low'}">
      <div class="result-label"><span class="result-tag ${x.vulnerable ? 'tag-high' : 'tag-low'}">${x.vulnerable ? 'VULN' : 'OK'}</span>${esc(x.service)}</div>
      <div class="result-value">${esc(x.subdomain)} → ${esc(x.cname)}</div>
    </div>`).join('');
  finalizeResults('smart');
  log(`Takeover: ${vulns.length} vulnerable of ${r.results.length} checked`, vulns.length ? 'warn' : 'success');
}

// ═══ 403 BYPASS TESTER ═══
async function tool403Bypass() {
  const b = showResults('active', '403 Bypass', true);
  b.innerHTML = `<div class="tool-input-row mb-6"><input class="tool-input" id="bp-url" value="${esc(activeTabUrl)}"><button class="btn-sm primary" id="bp-go">Test 17 Bypasses</button></div><div id="bp-out"></div>`;
  b.querySelector('#bp-go').addEventListener('click', async () => {
    const out = b.querySelector('#bp-out');
    out.innerHTML = '<div class="loading-text"><span class="spinner"></span> Testing bypass techniques…</div>';
    const r = await chrome.runtime.sendMessage({ type: 'BYPASS_403', url: b.querySelector('#bp-url').value });
    if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
    const bypasses = r.results.filter(x => x.bypass);
    out.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">Baseline: HTTP ${r.baseStatus}</span><span class="text-sm ${bypasses.length?'text-accent':''}" style="font-weight:700">${bypasses.length} bypass${bypasses.length===1?'':'es'} found</span></div>` +
      r.results.filter(x=>x.type!=='baseline').map(x => `<div class="result-item ${x.bypass?'high':x.status===200?'medium':'info'}">
        <div class="result-label"><span class="result-tag ${x.bypass?'tag-high':'tag-info'}">${x.status}</span> ${esc(x.type)}</div>
        <div class="result-value">${esc(x.technique)}</div>
        ${x.bypass?'<div class="text-xs text-accent" style="font-weight:600">⚠ BYPASS — got '+x.status+' instead of '+r.baseStatus+'!</div>':''}
      </div>`).join('');
    finalizeResults('active');
    log(`403 bypass: ${bypasses.length} found`, bypasses.length ? 'warn' : 'success');
  });
}

// ═══ HTTP METHOD TESTER ═══
async function toolMethodTest() {
  const b = showResults('active', 'Method Tester', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Testing 8 HTTP methods…</div>';
  const r = await chrome.runtime.sendMessage({ type: 'METHOD_TEST', url: activeTabUrl });
  if (!r.ok) { b.innerHTML = errMsg(r.error); return; }
  const baseline = r.results[0]; // GET
  b.innerHTML = `<div class="text-sm mb-6">${esc(activeTabUrl)}<br><span class="text-xs text-muted">Baseline GET: ${baseline.status} · ${baseline.bodyLen}b</span></div>` +
    r.results.map(x => {
      let sev = 'info', verdict = '';
      if (x.error) { sev = 'info'; verdict = x.error; }
      else if (x.baseline) { verdict = 'Baseline reference'; }
      else if (x.realDanger) { sev = 'high'; verdict = `⚠ ${x.method} returns DIFFERENT response (${x.bodyDiff}b diff) — likely processed! Investigate.`; }
      else if (x.fakeAccept) { sev = 'info'; verdict = `Same page as GET (±${x.bodyDiff}b) — server ignores method, not a real finding`; }
      else if (x.status === 405) { verdict = 'Method not allowed (expected)'; }
      else if (x.status !== baseline.status) { sev = 'low'; verdict = `Different status than GET (${baseline.status})  — worth investigating`; }
      else { verdict = 'Same as GET'; }
      return `<div class="result-item ${sev}">
        <div class="result-label"><span class="result-tag tag-${sev === 'high' ? 'high' : sev === 'low' ? 'low' : 'info'}">${x.status}</span> ${x.method}</div>
        <div class="result-value">${x.bodyLen !== undefined ? x.bodyLen + 'b' : ''} ${x.allow ? '· Allow: ' + esc(x.allow) : ''}</div>
        <div class="text-xs" style="color:var(--text-secondary)">${verdict}</div>
        ${x.preview ? `<div style="margin-top:4px;padding:4px 6px;background:var(--danger-soft);border-radius:3px;font-family:var(--font-mono);font-size:9px;max-height:50px;overflow:auto">${esc(x.preview)}</div>` : ''}
      </div>`;
    }).join('');
  finalizeResults('active');
}

// ═══ JWT EDITOR ═══
function toolJwtEditor() {
  const b = showResults('active', 'JWT Editor', false);
  b.innerHTML = `<div class="text-sm mb-6">Paste a JWT token or auto-detect from cookies</div>
    <div class="tool-input-row"><textarea class="tool-input" id="jwt-in" rows="3" placeholder="eyJhbGciOiJIUzI1NiIs…"></textarea></div>
    <div class="codec-row mb-6">
      <button class="btn-sm primary" id="jwt-decode">Decode</button>
      <button class="btn-sm" id="jwt-detect">Auto-detect from cookies</button>
    </div>
    <div id="jwt-out"></div>`;

  b.querySelector('#jwt-detect')?.addEventListener('click', async () => {
    const cookies = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', domain: activeTabDomain });
    if (!cookies.ok) return;
    const jwtCookie = cookies.cookies.find(c => /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(c.value));
    if (jwtCookie) { b.querySelector('#jwt-in').value = jwtCookie.value; log('Found JWT in cookie: ' + jwtCookie.name, 'success'); }
    else { log('No JWT found in cookies', 'warn'); }
  });

  b.querySelector('#jwt-decode')?.addEventListener('click', () => {
    const token = b.querySelector('#jwt-in').value.trim();
    const out = b.querySelector('#jwt-out');
    try {
      const parts = token.split('.');
      if (parts.length !== 3) { out.innerHTML = errMsg('Invalid JWT — need 3 dot-separated parts'); return; }
      const header = JSON.parse(atob(parts[0].replace(/-/g,'+').replace(/_/g,'/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
      const expiry = payload.exp ? new Date(payload.exp * 1000).toISOString() : 'none';
      const expired = payload.exp ? payload.exp * 1000 < Date.now() : false;

      out.innerHTML = `<div class="result-item ${expired?'medium':'info'}"><div class="result-label">Header (alg: ${esc(header.alg)})</div><div class="result-value"><pre style="white-space:pre-wrap">${esc(JSON.stringify(header,null,2))}</pre></div></div>
        <div class="result-item info"><div class="result-label">Payload${expired?' — EXPIRED':''}</div><div class="result-value"><pre style="white-space:pre-wrap">${esc(JSON.stringify(payload,null,2))}</pre></div><div class="text-xs text-muted">Expires: ${expiry}</div></div>
        <div class="result-label mt-6 mb-4">Edit & Re-encode</div>
        <textarea class="tool-input mb-4" id="jwt-edit" rows="6" style="font-size:10px">${esc(JSON.stringify(payload,null,2))}</textarea>
        <div class="codec-row">
          <button class="btn-sm primary" id="jwt-none">alg:none (no sig)</button>
          <button class="btn-sm" id="jwt-resign">Re-encode (keep alg)</button>
          <button class="btn-sm" id="jwt-copy">Copy token</button>
        </div>
        <textarea class="tool-input mt-6" id="jwt-result" rows="2" readonly placeholder="Modified token…"></textarea>`;

      const b64url = (s) => btoa(s).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
      out.querySelector('#jwt-none')?.addEventListener('click', () => {
        try {
          const newPayload = JSON.parse(out.querySelector('#jwt-edit').value);
          const newHeader = { alg: 'none', typ: 'JWT' };
          const token = b64url(JSON.stringify(newHeader)) + '.' + b64url(JSON.stringify(newPayload)) + '.';
          out.querySelector('#jwt-result').value = token;
        } catch (e) { out.querySelector('#jwt-result').value = 'Error: ' + e.message; }
      });
      out.querySelector('#jwt-resign')?.addEventListener('click', () => {
        try {
          const newPayload = JSON.parse(out.querySelector('#jwt-edit').value);
          const token = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(newPayload)) + '.' + parts[2];
          out.querySelector('#jwt-result').value = token;
        } catch (e) { out.querySelector('#jwt-result').value = 'Error: ' + e.message; }
      });
      out.querySelector('#jwt-copy')?.addEventListener('click', () => { copyText(out.querySelector('#jwt-result').value); });
    } catch (e) { out.innerHTML = errMsg('JWT decode failed: ' + e.message); }
  });
}

// ═══ DIRECTORY BRUTEFORCER ═══
async function toolDirBrute() {
  const b = showResults('recon', 'Dir Brute', false);
  b.innerHTML = `<div class="text-sm mb-6">Scan for sensitive paths on ${esc(getRootDomain(activeTabDomain))}</div>
    <div class="tool-input-row mb-6">
      <select class="tool-select" id="db-cat" style="font-size:10px">
        <option value="common">Common (17 paths)</option>
        <option value="wordpress">WordPress (17)</option>
        <option value="php_laravel">PHP / Laravel (14)</option>
        <option value="java_spring">Java / Spring (14)</option>
        <option value="node_js">Node.js (13)</option>
        <option value="dotnet">.NET / ASP (11)</option>
        <option value="devops">DevOps / VCS (14)</option>
        <option value="backups">Backups (12)</option>
        <option value="all">All categories (~100)</option>
      </select>
      <button class="btn-sm primary" id="db-go">Scan</button>
    </div>
    <div id="db-out"></div>`;
  b.querySelector('#db-go').addEventListener('click', async () => {
    const cat = b.querySelector('#db-cat').value;
    const out = b.querySelector('#db-out');
    out.innerHTML = `<div class="loading-text"><span class="spinner"></span> Scanning ${cat === 'all' ? '~100' : ''} paths (parallel)…</div>`;
    const r = await chrome.runtime.sendMessage({ type: 'DIR_BRUTE', url: activeTabUrl, category: cat });
    if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
    if (!r.results.length) {
      out.innerHTML = `<div class="text-muted text-sm">Nothing found across ${r.total} paths (${cat})</div>`;
      finalizeResults('recon'); return;
    }
    out.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${r.results.length} found / ${r.total} tested</span></div>` +
      r.results.map(x => {
        const sev = x.status === 200 ? 'high' : x.status === 403 || x.status === 401 ? 'medium' : 'low';
        const statusLabel = x.status === 200 ? 'OPEN' : x.status === 403 ? 'FORBIDDEN' : x.status === 401 ? 'AUTH REQ' : x.status;
        return `<div class="result-item ${sev}">
          <div class="result-label"><span class="result-tag tag-${sev}">${statusLabel}</span> ${esc(x.path)}</div>
          ${x.preview ? `<div class="result-value" style="font-size:9px;max-height:50px;overflow:hidden;margin-top:3px">${esc(x.preview.slice(0,180))}</div>` : ''}
        </div>`;
      }).join('');
    finalizeResults('recon');
    log(`Dir brute [${cat}]: ${r.results.length}/${r.total}`, r.results.length ? 'warn' : 'success');
  });
}

// ═══ IDOR DETECTOR ═══
async function toolIdor() {
  const b = showResults('smart', 'IDOR Detector', true);
  // Analyze current URL and captured XHR for numeric/UUID params
  const u = new URL(activeTabUrl);
  const findings = [];
  // URL params
  u.searchParams.forEach((v, k) => {
    if (/^\d+$/.test(v)) findings.push({ source: 'URL param', param: k, value: v, type: 'numeric', suggest: [String(+v-1), String(+v+1), '0', '1'] });
    else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) findings.push({ source: 'URL param', param: k, value: v, type: 'UUID', suggest: ['Try another user UUID'] });
    else if (/^[0-9a-f]{24}$/i.test(v)) findings.push({ source: 'URL param', param: k, value: v, type: 'MongoDB ObjectId', suggest: ['Try incrementing last chars'] });
  });
  // Path segments
  u.pathname.split('/').forEach((seg, i) => {
    if (/^\d+$/.test(seg) && seg.length < 10) findings.push({ source: 'URL path', param: `segment[${i}]`, value: seg, type: 'numeric', suggest: [String(+seg-1), String(+seg+1), '0'] });
    else if (/^[0-9a-f]{8}-[0-9a-f]{4}/i.test(seg)) findings.push({ source: 'URL path', param: `segment[${i}]`, value: seg, type: 'UUID', suggest: ['Try another UUID'] });
  });
  // Check captured XHR requests
  const reqs = await chrome.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS', tabId: activeTabId });
  (reqs.requests || []).slice(-20).forEach(r => {
    try {
      const ru = new URL(r.url);
      ru.searchParams.forEach((v, k) => {
        if (/^\d+$/.test(v) && !findings.some(f => f.param === k && f.value === v))
          findings.push({ source: 'XHR ' + r.method, param: k, value: v, type: 'numeric', suggest: [String(+v-1), String(+v+1)] });
      });
    } catch {}
  });

  if (!findings.length) {
    b.innerHTML = '<div class="text-muted text-sm">No numeric or UUID parameters detected in URL or recent XHR requests</div>';
    finalizeResults('smart'); return;
  }
  b.innerHTML = `<div class="text-sm mb-6">${findings.length} potential IDOR parameters</div>` +
    findings.map(f => `<div class="result-item medium">
      <div class="result-label"><span class="result-tag tag-medium">${esc(f.type)}</span> ${esc(f.source)}</div>
      <div class="result-value">${esc(f.param)} = ${esc(f.value)}</div>
      <div class="text-xs text-muted mt-4">Try: ${f.suggest.map(s => `<code style="background:var(--surface-hover);padding:1px 4px;border-radius:2px">${esc(s)}</code>`).join(' ')}</div>
    </div>`).join('');
  finalizeResults('smart');
}

// ═══ LIVE BROWSE ═══
function setupLiveBrowse() {
  const btn = document.getElementById('btn-live-toggle');
  btn?.addEventListener('click', () => {
    if (liveActive) {
      liveActive = false;
      btn.textContent = 'Start Monitoring';
      btn.classList.remove('success'); btn.classList.add('primary');
      log('Live Browse stopped', 'warn');
    } else {
      liveActive = true;
      liveTargetDomain = activeTabDomain;
      document.getElementById('live-target').textContent = 'Target: ' + liveTargetDomain + ' (+ subdomains)';
      btn.textContent = '■ Stop';
      btn.classList.remove('primary'); btn.classList.add('success');
      document.querySelector('[data-group="live"]')?.classList.add('open');
      log('Live Browse started on ' + liveTargetDomain, 'success');
      // Initial scan of current page
      liveScanPage(activeTabId, activeTabUrl, '');
    }
  });
  document.getElementById('btn-live-copy')?.addEventListener('click', () => {
    const lines = liveFindings.map(f => `[${f.time}] [${f.type}] ${f.url}\n  ${f.items.map(i => '  ' + i).join('\n  ')}`);
    copyText(`CYBOWARE LIVE BROWSE REPORT\nTarget: ${liveTargetDomain}\n${'─'.repeat(40)}\n\n${lines.join('\n\n')}`);
  });
  document.getElementById('btn-live-json')?.addEventListener('click', () => {
    copyText(JSON.stringify({ target: liveTargetDomain, findings: liveFindings }, null, 2));
  });
  document.getElementById('btn-live-clear')?.addEventListener('click', () => {
    liveFindings = []; liveSeenItems.clear();
    document.getElementById('live-feed').innerHTML = '<div class="text-muted text-sm" style="padding:12px;text-align:center">Cleared</div>';
    document.getElementById('live-count').textContent = '0 findings';
    const badge = document.getElementById('badge-live'); badge.textContent = '0'; badge.classList.add('hidden');
  });
}

async function liveScanPage(tabId, url, title) {
  const feed = document.getElementById('live-feed');
  const ts = new Date().toLocaleTimeString();
  const pathname = new URL(url).pathname;
  const entry = { time: ts, url, type: 'scan', items: [] };

  // Scanning indicator
  const scanDiv = document.createElement('div');
  scanDiv.style.cssText = 'padding:6px 10px;border-bottom:1px solid var(--border);font-size:10.5px;';
  scanDiv.innerHTML = `<div style="display:flex;justify-content:space-between"><span class="text-mono" style="color:var(--accent)">${esc(ts)}</span><span class="text-xs text-muted">${esc(pathname)}</span></div><div class="loading-text" style="padding:4px 0"><span class="spinner"></span> Scanning…</div>`;
  if (feed.firstChild?.classList?.contains('text-muted')) feed.innerHTML = '';
  feed.prepend(scanDiv);

  const newItems = [];
  try {
    // 1. Secrets
    try {
      const sr = await chrome.tabs.sendMessage(tabId, { type: 'GET_SCRIPT_URLS' });
      if (sr?.ok) {
        const findings = [];
        for (const jsUrl of sr.data.external.slice(0, 10)) {
          try { const r = await chrome.runtime.sendMessage({ type: 'FETCH_JS', url: jsUrl }); if (r.ok) scanSecrets(r.text, jsUrl, findings); } catch {}
        }
        sr.data.inline.slice(0, 5).forEach((txt, i) => scanSecrets(txt, '[inline]', findings));
        findings.forEach(f => {
          const key = 'secret:' + f.match;
          if (!liveSeenItems.has(key)) { liveSeenItems.add(key); newItems.push({ type: 'secrets', icon: '🔑', text: `[${f.severity}] ${f.name}: ${f.match.slice(0, 60)}` }); }
        });
      }
    } catch {}

    // 2. Endpoints
    try {
      const sr = await chrome.tabs.sendMessage(tabId, { type: 'GET_SCRIPT_URLS' });
      if (sr?.ok) {
        const eps = new Set();
        const proc = t => { for (const p of ENDPOINT_PATTERNS) { const re = new RegExp(p.source, p.flags); let m; while ((m = re.exec(t)) !== null) { const ep = m[1] || m[0]; if (ep.length > 4 && !/\.(js|css|png|jpg|svg)$/.test(ep)) eps.add(ep); } } };
        for (const u of sr.data.external.slice(0, 8)) { try { const r = await chrome.runtime.sendMessage({ type: 'FETCH_JS', url: u }); if (r.ok) proc(r.text); } catch {} }
        sr.data.inline.forEach(proc);
        eps.forEach(ep => {
          const key = 'ep:' + ep;
          if (!liveSeenItems.has(key)) { liveSeenItems.add(key); newItems.push({ type: 'endpoints', icon: '🔗', text: ep }); }
        });
      }
    } catch {}

    // 3. Passive vulns
    try {
      const vr = await chrome.tabs.sendMessage(tabId, { type: 'CHECK_PASSIVE_VULNS' });
      (vr?.data || []).forEach(v => {
        const key = 'vuln:' + v.type + ':' + v.detail;
        if (!liveSeenItems.has(key)) { liveSeenItems.add(key); newItems.push({ type: 'vulns', icon: '⚡', text: `[${v.severity}] ${v.type}: ${v.detail}` }); }
      });
    } catch {}

    // 4. Forms (login, upload, admin)
    try {
      const fr = await chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_FORMS' });
      (fr?.data || []).forEach(f => {
        const hasPassword = f.fields.some(fi => fi.type === 'password');
        const hasFile = f.fields.some(fi => fi.type === 'file');
        const key = 'form:' + (f.action || pathname);
        if (!liveSeenItems.has(key)) {
          liveSeenItems.add(key);
          const label = hasPassword ? 'Login form' : hasFile ? 'File upload' : `Form (${f.fields.length} fields)`;
          newItems.push({ type: 'forms', icon: '📝', text: `${label} → ${f.method?.toUpperCase()||'GET'} ${f.action||'(self)'}` });
        }
      });
    } catch {}

    // 5. New cookies
    try {
      const cr = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', domain: new URL(url).hostname });
      (cr?.cookies || []).forEach(c => {
        const key = 'cookie:' + c.name;
        if (!liveSeenItems.has(key)) {
          liveSeenItems.add(key);
          const flags = [];
          if (!c.httpOnly) flags.push('!HttpOnly');
          if (!c.secure) flags.push('!Secure');
          if (c.sameSite === 'unspecified') flags.push('!SameSite');
          if (flags.length) newItems.push({ type: 'cookies', icon: '🍪', text: `${c.name} — ${flags.join(', ')}` });
        }
      });
    } catch {}

    // 6. URL params (potential injection points)
    try {
      const u = new URL(url);
      u.searchParams.forEach((v, k) => {
        const key = 'param:' + k;
        if (!liveSeenItems.has(key)) { liveSeenItems.add(key); newItems.push({ type: 'params', icon: '🎯', text: `URL param: ${k}=${v.slice(0, 40)}` }); }
      });
    } catch {}

    // 7. Interesting headers
    try {
      const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId });
      (hRes.headers?.responseHeaders || []).forEach(h => {
        const n = h.name.toLowerCase();
        if (['server','x-powered-by','x-debug','x-debug-token','x-aspnet-version','x-runtime'].includes(n)) {
          const key = 'hdr:' + n + ':' + h.value;
          if (!liveSeenItems.has(key)) { liveSeenItems.add(key); newItems.push({ type: 'headers', icon: '📋', text: `${h.name}: ${h.value}` }); }
        }
      });
    } catch {}

    // 8. Source maps (.js.map files)
    try {
      const sr = await chrome.tabs.sendMessage(tabId, { type: 'GET_SCRIPT_URLS' });
      if (sr?.ok) {
        for (const jsUrl of sr.data.external.slice(0, 5)) {
          const mapUrl = jsUrl + '.map';
          const key = 'srcmap:' + mapUrl;
          if (!liveSeenItems.has(key)) {
            try {
              const r = await chrome.runtime.sendMessage({ type: 'FETCH_URL', url: mapUrl, method: 'HEAD' });
              if (r.ok && r.status === 200) { liveSeenItems.add(key); newItems.push({ type: 'srcmap', icon: '🗺', text: `Source map exposed: ${mapUrl.split('/').pop()}` }); }
              else { liveSeenItems.add(key); }
            } catch { liveSeenItems.add(key); }
          }
        }
      }
    } catch {}

  } catch (e) { log('Live scan error: ' + e.message, 'error'); }

  // Only show if we have NEW findings
  entry.items = newItems.map(i => `${i.icon} ${i.text}`);
  if (newItems.length === 0) {
    scanDiv.innerHTML = `<div style="display:flex;justify-content:space-between"><span class="text-mono" style="color:var(--text-tertiary)">${esc(ts)}</span><span class="text-xs text-muted">${esc(pathname)} — nothing new</span></div>`;
  } else {
    let html = `<div style="display:flex;justify-content:space-between;margin-bottom:4px"><span class="text-mono" style="color:var(--accent)">${esc(ts)}</span><span class="text-xs" style="color:var(--accent);font-weight:600">${newItems.length} new · ${esc(pathname)}</span></div>`;
    newItems.forEach(item => {
      const color = item.type === 'secrets' ? 'var(--danger)' : item.type === 'vulns' ? 'var(--warning)' : 'var(--text-secondary)';
      html += `<div style="padding:2px 0;font-size:10px;font-family:var(--font-mono);color:${color}">${item.icon} ${esc(item.text)}</div>`;
    });
    scanDiv.innerHTML = html;
  }

  liveFindings.push(entry);
  const totalItems = liveFindings.reduce((s, f) => s + f.items.length, 0);
  document.getElementById('live-count').textContent = totalItems + ' findings, ' + liveSeenItems.size + ' unique';
  if (totalItems > 0) { const badge = document.getElementById('badge-live'); badge.textContent = totalItems; badge.classList.remove('hidden'); }
}

// ═══ HELPERS ═══
function esc(s){if(!s)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}
function errMsg(e){return`<div class="result-item high"><div class="result-value">${esc(typeof e==='string'?e:e?.message||'Unknown error')}</div></div>`}
function getRootDomain(h){if(!h)return'';const p=h.split('.');return p.length<=2?h:p.slice(-2).join('.')}
function copyText(t){navigator.clipboard.writeText(t).then(()=>{const e=document.getElementById('copy-toast');e.classList.add('show');setTimeout(()=>e.classList.remove('show'),1200)}).catch(()=>log('Copy failed','error'))}
function downloadText(t,f){const b=new Blob([t],{type:'text/plain'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=f;a.click();URL.revokeObjectURL(u)}
function log(msg,level='info'){const el=document.getElementById('debug-log-entries');const e=document.createElement('div');e.className='log-entry '+(level||'');e.textContent=`[${new Date().toLocaleTimeString()}] ${msg}`;el.appendChild(e);el.scrollTop=el.scrollHeight;while(el.children.length>100)el.removeChild(el.firstChild)}
