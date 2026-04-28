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
    // Meta-frameworks
    if (window.__NEXT_DATA__) globals.push({ name: 'Next.js', detail: window.__NEXT_DATA__?.buildId || '', confidence: 'high' });
    if (window.__NUXT__) globals.push({ name: 'Nuxt.js', confidence: 'high' });
    if (window.__GATSBY) globals.push({ name: 'Gatsby', confidence: 'high' });
    if (window.__remixContext || window.__remixManifest) globals.push({ name: 'Remix', confidence: 'high' });
    if (window.__sveltekit_payload || document.querySelector('script[type="module"][src*="_app/"]')) globals.push({ name: 'SvelteKit', confidence: 'high' });
    if (window.__ASTRO__ || document.querySelector('astro-island')) globals.push({ name: 'Astro', confidence: 'high' });
    if (window.SolidJS || window.__SOLID__) globals.push({ name: 'SolidJS', confidence: 'high' });
    if (window.qwikloader$ || document.querySelector('script[q\\:base]')) globals.push({ name: 'Qwik', confidence: 'high' });
    // Core libs
    if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) globals.push({ name: 'React', detail: window.React?.version || '', confidence: 'high' });
    if (window.Vue) globals.push({ name: 'Vue.js', detail: window.Vue?.version || '', confidence: 'high' });
    if (window.angular || window.ng) globals.push({ name: 'Angular', detail: window.angular?.version?.full || '', confidence: 'high' });
    if (window.Ember) globals.push({ name: 'Ember.js', confidence: 'high' });
    if (window.jQuery || window.$?.fn?.jquery) globals.push({ name: 'jQuery', detail: window.jQuery?.fn?.jquery || window.$?.fn?.jquery || '', confidence: 'high' });
    if (window.htmx) globals.push({ name: 'htmx', confidence: 'high' });
    if (window.Alpine) globals.push({ name: 'Alpine.js', detail: window.Alpine?.version || '', confidence: 'high' });
    if (window.Stimulus) globals.push({ name: 'Stimulus', confidence: 'high' });
    // Auth & state
    if (window.firebase) globals.push({ name: 'Firebase', detail: window.firebase?.SDK_VERSION || '', confidence: 'high' });
    if (window.supabase) globals.push({ name: 'Supabase', confidence: 'high' });
    if (window.Auth0Lock || window.auth0) globals.push({ name: 'Auth0', confidence: 'high' });
    if (window.Clerk) globals.push({ name: 'Clerk', confidence: 'high' });
    if (window.__APOLLO_CLIENT__) globals.push({ name: 'Apollo Client (GraphQL)', confidence: 'high' });
    if (window.__RELAY_DEVTOOLS_HOOK__ || window.__RELAY_PAYLOADS__) globals.push({ name: 'Relay (GraphQL)', confidence: 'high' });
    // CMS / commerce
    if (window.Shopify) globals.push({ name: 'Shopify', detail: window.Shopify?.shop || '', confidence: 'high' });
    if (window.wp || window.wpApiSettings) globals.push({ name: 'WordPress', detail: window.wpApiSettings?.versionString || '', confidence: 'high' });
    if (window.Drupal) globals.push({ name: 'Drupal', confidence: 'high' });
    if (window.Joomla) globals.push({ name: 'Joomla', confidence: 'high' });
    // Analytics & tag managers
    if (window.dataLayer) globals.push({ name: 'Google Tag Manager', confidence: 'high' });
    if (window.gtag) globals.push({ name: 'Google Analytics 4', confidence: 'high' });
    if (window.fbq) globals.push({ name: 'Facebook Pixel', confidence: 'high' });
    if (window.posthog) globals.push({ name: 'PostHog', confidence: 'high' });
    if (window.mixpanel) globals.push({ name: 'Mixpanel', confidence: 'high' });
    if (window.amplitude) globals.push({ name: 'Amplitude', confidence: 'high' });
    if (window.heap) globals.push({ name: 'Heap Analytics', confidence: 'high' });
    if (window.LogRocket) globals.push({ name: 'LogRocket (session replay)', confidence: 'high' });
    if (window.FS) globals.push({ name: 'FullStory (session replay)', confidence: 'high' });
    // Error tracking
    if (window.Sentry) globals.push({ name: 'Sentry', detail: window.Sentry?.SDK_VERSION || '', confidence: 'high' });
    if (window.Rollbar) globals.push({ name: 'Rollbar', confidence: 'high' });
    if (window.Bugsnag) globals.push({ name: 'Bugsnag', confidence: 'high' });
    // Payments
    if (window.Stripe) globals.push({ name: 'Stripe', confidence: 'high' });
    if (window.paypal) globals.push({ name: 'PayPal', confidence: 'high' });
    // Bot management (visible in JS context)
    if (window.DD_RUM || document.cookie.includes('datadome=')) globals.push({ name: 'DataDome (bot mgmt)', confidence: 'high' });
    if (window._pxAppId || window._pxParam1) globals.push({ name: 'PerimeterX (bot mgmt)', confidence: 'high' });
    window.postMessage({ source: SRC, payload: { type: 'globals_detected', globals } }, '*');
  });
})();
