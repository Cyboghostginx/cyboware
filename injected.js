/* ═══════════════════════════════════════════════════════════════
   CYBOWARE — Injected Script v4 (main world — access page JS globals)
   Enhanced: SPA route detection, DOM mutations, framework globals
   ═══════════════════════════════════════════════════════════════ */
(() => {
  const SRC = 'CYBOWARE_INJECTED';

  // Hook fetch
  const origFetch = window.fetch;
  window.fetch = async function(...args) {
    const url = typeof args[0] === 'string' ? args[0] : args[0]?.url;
    const method = args[1]?.method || 'GET';
    try {
      window.postMessage({ source: SRC, payload: { type: 'fetch', url, method, timestamp: Date.now() } }, '*');
    } catch {}
    return origFetch.apply(this, args);
  };

  // Hook XMLHttpRequest
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function(method, url) {
    this._cybo = { method, url: String(url) };
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function(body) {
    if (this._cybo) {
      try { window.postMessage({ source: SRC, payload: { type: 'xhr', ...this._cybo, timestamp: Date.now() } }, '*'); } catch {}
    }
    return origSend.apply(this, arguments);
  };

  // ═══ SPA ROUTE CHANGE DETECTION ═══
  const origPush = history.pushState;
  const origReplace = history.replaceState;
  history.pushState = function() {
    const result = origPush.apply(this, arguments);
    try { window.postMessage({ source: SRC, payload: { type: 'spa_navigate', url: location.href, method: 'pushState', timestamp: Date.now() } }, '*'); } catch {}
    return result;
  };
  history.replaceState = function() {
    const result = origReplace.apply(this, arguments);
    try { window.postMessage({ source: SRC, payload: { type: 'spa_navigate', url: location.href, method: 'replaceState', timestamp: Date.now() } }, '*'); } catch {}
    return result;
  };
  window.addEventListener('popstate', () => {
    try { window.postMessage({ source: SRC, payload: { type: 'spa_navigate', url: location.href, method: 'popstate', timestamp: Date.now() } }, '*'); } catch {}
  });
  window.addEventListener('hashchange', () => {
    try { window.postMessage({ source: SRC, payload: { type: 'spa_navigate', url: location.href, method: 'hashchange', timestamp: Date.now() } }, '*'); } catch {}
  });

  // ═══ DOM MUTATION OBSERVER ═══
  let mutationTimer = null;
  const mutationBatch = { forms: 0, scripts: 0, iframes: 0 };
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.tagName === 'FORM' || node.querySelector?.('form')) mutationBatch.forms++;
        if (node.tagName === 'SCRIPT' || node.querySelector?.('script[src]')) mutationBatch.scripts++;
        if (node.tagName === 'IFRAME' || node.querySelector?.('iframe')) mutationBatch.iframes++;
      }
    }
    if (mutationTimer) clearTimeout(mutationTimer);
    mutationTimer = setTimeout(() => {
      const { forms, scripts, iframes } = mutationBatch;
      if (forms || scripts || iframes) {
        try { window.postMessage({ source: SRC, payload: { type: 'dom_mutation', forms, scripts, iframes, url: location.href, timestamp: Date.now() } }, '*'); } catch {}
      }
      mutationBatch.forms = 0; mutationBatch.scripts = 0; mutationBatch.iframes = 0;
    }, 800);
  });
  if (document.body) observer.observe(document.body, { childList: true, subtree: true });
  else document.addEventListener('DOMContentLoaded', () => { if (document.body) observer.observe(document.body, { childList: true, subtree: true }); });

  // ═══ FRAMEWORK GLOBALS DETECTION ═══
  window.addEventListener('message', (e) => {
    if (e.source !== window || e.data?.source !== 'CYBOWARE_CONTENT' || e.data?.type !== 'DETECT_GLOBALS') return;
    const globals = [];
    if (window.__NEXT_DATA__) globals.push({ name: 'Next.js', detail: window.__NEXT_DATA__?.buildId || '', confidence: 'high' });
    if (window.__NUXT__) globals.push({ name: 'Nuxt.js', confidence: 'high' });
    if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) globals.push({ name: 'React', confidence: 'high' });
    if (window.Vue) globals.push({ name: 'Vue.js', confidence: 'high' });
    if (window.angular || window.ng) globals.push({ name: 'Angular', confidence: 'high' });
    if (window.Ember) globals.push({ name: 'Ember.js', confidence: 'high' });
    if (window.jQuery || window.$?.fn?.jquery) globals.push({ name: 'jQuery', detail: window.jQuery?.fn?.jquery || window.$?.fn?.jquery || '', confidence: 'high' });
    if (window.__GATSBY) globals.push({ name: 'Gatsby', confidence: 'high' });
    if (window.__remixContext) globals.push({ name: 'Remix', confidence: 'high' });
    if (window.Shopify) globals.push({ name: 'Shopify', confidence: 'high' });
    if (window.wp || window.wpApiSettings) globals.push({ name: 'WordPress', confidence: 'high' });
    if (window.dataLayer) globals.push({ name: 'Google Tag Manager', confidence: 'high' });
    window.postMessage({ source: SRC, payload: { type: 'globals_detected', globals } }, '*');
  });
})();
