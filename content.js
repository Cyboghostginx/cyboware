/* ═══════════════════════════════════════════════════════════════
   CYBOWARE — Content Script v4
   Enhanced: SPA events, DOM mutations, framework globals bridge
   ═══════════════════════════════════════════════════════════════ */
(() => {
  const s = document.createElement('script');
  s.src = chrome.runtime.getURL('injected.js');
  s.onload = () => s.remove();
  (document.head || document.documentElement).appendChild(s);
})();

window.addEventListener('message', (e) => {
  if (e.source !== window || e.data?.source !== 'CYBOWARE_INJECTED') return;
  const p = e.data.payload;
  // Forward all injected events to service worker / sidepanel
  if (p.type === 'fetch' || p.type === 'xhr') {
    chrome.runtime.sendMessage({ type: 'INTERCEPTED_REQUEST', payload: p });
  } else if (p.type === 'spa_navigate') {
    chrome.runtime.sendMessage({ type: 'SPA_NAVIGATE', payload: p });
  } else if (p.type === 'dom_mutation') {
    chrome.runtime.sendMessage({ type: 'DOM_MUTATION', payload: p });
  } else if (p.type === 'globals_detected') {
    chrome.runtime.sendMessage({ type: 'GLOBALS_DETECTED', payload: p });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  try {
    const fn = contentHandlers[msg.type];
    if (fn) {
      const result = fn(msg);
      // Handle promise returns
      if (result && typeof result.then === 'function') {
        result.then(data => sendResponse({ ok: true, data })).catch(err => sendResponse({ ok: false, error: err.message }));
        return true;
      }
      sendResponse({ ok: true, data: result });
    }
    else sendResponse({ ok: false, error: 'Unknown type' });
  } catch (e) { sendResponse({ ok: false, error: e.message }); }
  return true;
});

const contentHandlers = {
  ANALYZE_TECH_STACK: () => {
    const tech = [];
    const gen = document.querySelector('meta[name="generator"]');
    if (gen) tech.push({ name: gen.content, category: 'CMS', confidence: 'high' });
    const checks = [
      [() => !!document.querySelector('[data-reactroot],[data-reactid]'), 'React', 'Framework'],
      [() => !!document.querySelector('[ng-app],[ng-controller],[data-ng-app]'), 'Angular', 'Framework'],
      [() => !!document.querySelector('[data-v-],[v-cloak]'), 'Vue.js', 'Framework'],
      [() => !!document.querySelector('[data-svelte-h]'), 'Svelte', 'Framework'],
      [() => !!document.getElementById('__next'), 'Next.js', 'Framework'],
      [() => !!document.getElementById('__nuxt'), 'Nuxt.js', 'Framework'],
      [() => !!document.querySelector('script[src*="wp-content"],link[href*="wp-content"]'), 'WordPress', 'CMS'],
      [() => !!document.querySelector('script[src*="shopify"]'), 'Shopify', 'Platform'],
      [() => !!document.querySelector('link[href*="bootstrap"]'), 'Bootstrap', 'CSS'],
      [() => {
        // Better Tailwind detection: check for actual Tailwind utility classes
        const el = document.querySelector('[class*="flex "],[class*="grid "],[class*="bg-"],[class*="text-"],[class*="p-"],[class*="m-"],[class*="rounded"]');
        return !!el || !!document.querySelector('link[href*="tailwind"]');
      }, 'Tailwind CSS', 'CSS'],
      [() => !!document.querySelector('script[src*="gtag"],script[src*="googletagmanager"]'), 'Google Analytics/GTM', 'Analytics'],
      [() => !!document.querySelector('script[src*="cloudflare"]'), 'Cloudflare', 'CDN'],
      [() => !!document.querySelector('script[src*="recaptcha"],div.g-recaptcha'), 'reCAPTCHA', 'Security'],
      [() => !!document.querySelector('script[src*="hcaptcha"]'), 'hCaptcha', 'Security'],
      [() => !!document.querySelector('script[src*="stripe"]'), 'Stripe', 'Payment'],
      [() => !!document.querySelector('script[src*="jquery"]'), 'jQuery', 'Library'],
      [() => !!document.querySelector('link[href*="font-awesome"],link[href*="fontawesome"]'), 'Font Awesome', 'Icons'],
      [() => !!document.querySelector('script[src*="hotjar"]'), 'Hotjar', 'Analytics'],
      [() => !!document.querySelector('script[src*="sentry"]'), 'Sentry', 'Monitoring'],
      [() => !!document.querySelector('script[src*="segment"]'), 'Segment', 'Analytics'],
      [() => !!document.querySelector('script[src*="alpine"]'), 'Alpine.js', 'Framework'],
      [() => !!document.querySelector('script[src*="htmx"]'), 'HTMX', 'Framework'],
      [() => !!document.querySelector('meta[name="csrf-token"]'), 'Rails CSRF', 'Security'],
      [() => !!document.querySelector('script[src*="livewire"]'), 'Laravel Livewire', 'Framework'],
    ];
    for (const [test, name, cat] of checks) { try { if (test()) tech.push({ name, category: cat, confidence: 'medium' }); } catch {} }
    return tech;
  },

  // Request framework globals from injected (main world) script
  DETECT_GLOBALS: () => {
    return new Promise((resolve) => {
      const handler = (e) => {
        if (e.source !== window || e.data?.source !== 'CYBOWARE_INJECTED' || e.data?.payload?.type !== 'globals_detected') return;
        window.removeEventListener('message', handler);
        resolve(e.data.payload.globals);
      };
      window.addEventListener('message', handler);
      window.postMessage({ source: 'CYBOWARE_CONTENT', type: 'DETECT_GLOBALS' }, '*');
      // Timeout fallback
      setTimeout(() => { window.removeEventListener('message', handler); resolve([]); }, 1500);
    });
  },

  EXTRACT_LINKS: () => {
    const links = { internal: [], external: [], interesting: [], emails: [] };
    const host = location.hostname;
    document.querySelectorAll('a[href]').forEach(a => {
      const href = a.href;
      if (!href || href.startsWith('javascript:')) return;
      if (href.startsWith('mailto:')) { links.emails.push(href.replace('mailto:', '')); return; }
      try {
        const u = new URL(href);
        const entry = { url: href, text: a.textContent.trim().slice(0, 60) };
        if (u.hostname === host || u.hostname.endsWith('.' + host)) links.internal.push(entry);
        else links.external.push(entry);
        if (/\.(env|git|bak|sql|config|log|xml|json|yml|yaml|key|pem|csv|backup|old|swp|DS_Store)$/i.test(u.pathname))
          links.interesting.push(entry);
      } catch {}
    });
    return {
      internal: [...new Map(links.internal.map(l => [l.url, l])).values()],
      external: [...new Map(links.external.map(l => [l.url, l])).values()],
      interesting: links.interesting,
      emails: [...new Set(links.emails)]
    };
  },

  FIND_HIDDEN_ELEMENTS: () => {
    const r = { hiddenInputs: [], hiddenDivs: [], disabledInputs: [], dataAttrs: [] };
    document.querySelectorAll('input[type="hidden"]').forEach(el =>
      r.hiddenInputs.push({ name: el.name, value: el.value, form: el.form?.action || '' }));
    document.querySelectorAll('[style*="display: none"],[style*="display:none"],[style*="visibility: hidden"],[style*="visibility:hidden"],.hidden,.d-none,.sr-only,.visually-hidden,[hidden],[aria-hidden="true"]').forEach(el => {
      const t = el.textContent?.trim().slice(0, 100);
      if (t && t.length > 1) r.hiddenDivs.push({ tag: el.tagName, id: el.id || '', class: (el.className?.toString() || '').slice(0, 50), text: t });
    });
    document.querySelectorAll('input[disabled],select[disabled],textarea[disabled]').forEach(el =>
      r.disabledInputs.push({ tag: el.tagName, name: el.name, value: el.value, type: el.type }));
    document.querySelectorAll('[data-api],[data-url],[data-endpoint],[data-token],[data-key],[data-secret],[data-config]').forEach(el => {
      for (const attr of el.attributes)
        if (attr.name.startsWith('data-') && /api|url|endpoint|token|key|secret|config/i.test(attr.name))
          r.dataAttrs.push({ attr: attr.name, value: attr.value.slice(0, 120), tag: el.tagName });
    });
    return r;
  },

  REVEAL_HIDDEN: () => {
    document.body.classList.add('cyboware-revealed');
    document.querySelectorAll('[style*="display: none"],[style*="display:none"],[style*="visibility: hidden"],[style*="visibility:hidden"],.hidden,.d-none,.sr-only,.visually-hidden,[hidden],[aria-hidden="true"]').forEach(el => {
      el.dataset.cyboOrigStyle = el.getAttribute('style') || '';
      el.dataset.cyboOrigHidden = el.hasAttribute('hidden') ? '1' : '';
      el.style.setProperty('display', 'block', 'important');
      el.style.setProperty('visibility', 'visible', 'important');
      el.style.setProperty('opacity', '1', 'important');
      el.removeAttribute('hidden');
      el.style.outline = '2px dashed #C4392D';
      el.dataset.cyboRevealed = '1';
    });
    document.querySelectorAll('input[type="hidden"]').forEach(el => { el.dataset.cyboOrigType = 'hidden'; el.type = 'text'; el.style.cssText = 'border:2px dashed #C4392D;padding:4px;margin:2px;background:#fff3f3'; });
    document.querySelectorAll('input[disabled],select[disabled],textarea[disabled]').forEach(el => { el.dataset.cyboWasDisabled = '1'; el.disabled = false; el.style.outline = '2px dashed #2D7D46'; });
    return true;
  },
  UNREVEAL_HIDDEN: () => {
    document.body.classList.remove('cyboware-revealed');
    document.querySelectorAll('[data-cybo-orig-type="hidden"]').forEach(el => { el.type = 'hidden'; el.style.cssText = ''; delete el.dataset.cyboOrigType; });
    document.querySelectorAll('[data-cybo-revealed="1"]').forEach(el => {
      const origStyle = el.dataset.cyboOrigStyle;
      if (origStyle) el.setAttribute('style', origStyle);
      else el.removeAttribute('style');
      if (el.dataset.cyboOrigHidden === '1') el.setAttribute('hidden', '');
      delete el.dataset.cyboRevealed;
      delete el.dataset.cyboOrigStyle;
      delete el.dataset.cyboOrigHidden;
    });
    document.querySelectorAll('[data-cybo-was-disabled="1"]').forEach(el => { el.disabled = true; el.style.outline = ''; delete el.dataset.cyboWasDisabled; });
    return true;
  },

  GET_SCRIPT_URLS: () => {
    const urls = []; document.querySelectorAll('script[src]').forEach(s => urls.push(s.src));
    const inline = []; document.querySelectorAll('script:not([src])').forEach(s => { if (s.textContent.trim().length > 10) inline.push(s.textContent); });
    return { external: urls, inline };
  },

  EXTRACT_FORMS: () => {
    const forms = [];
    document.querySelectorAll('form').forEach(f => {
      const fields = [];
      f.querySelectorAll('input,select,textarea').forEach(el => fields.push({ tag: el.tagName, name: el.name, type: el.type, value: el.value?.slice(0, 50), autocomplete: el.autocomplete || '' }));
      forms.push({ action: f.action, method: f.method, fields, id: f.id || '', enctype: f.enctype || '' });
    });

    // Detect standalone inputs NOT inside any <form> (SPA search bars, AJAX inputs, React components)
    const standaloneInputs = [];
    document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]),textarea,select').forEach(el => {
      if (el.closest('form')) return;
      const name = el.name || el.id || (el.getAttribute('aria-label') || '').replace(/\s+/g, '_').toLowerCase() || '';
      if (!name) return;
      const type = el.type || 'text';
      const placeholder = el.placeholder || '';
      const role = el.getAttribute('role') || '';
      const parentClasses = (el.closest('div,section,nav,header')?.className || '').toString();
      const isSearch = type === 'search' || role === 'searchbox' || role === 'combobox' ||
        /search/i.test(placeholder) || /search/i.test(el.className) || /search/i.test(parentClasses);
      standaloneInputs.push({ tag: el.tagName, name, type, value: el.value?.slice(0, 50) || '', autocomplete: el.autocomplete || '', isSearch, placeholder });
    });

    if (standaloneInputs.length) {
      forms.push({
        action: location.href,
        method: 'GET',
        fields: standaloneInputs,
        id: '__standalone__',
        enctype: '',
        isVirtual: true,
        virtualLabel: standaloneInputs.some(f => f.isSearch) ? 'Dynamic Search / AJAX Inputs' : 'Standalone Inputs (no <form> tag)'
      });
    }

    return forms;
  },

  GET_PAGE_META: () => {
    const metas = {};
    document.querySelectorAll('meta').forEach(m => { const k = m.name || m.httpEquiv || m.getAttribute('property'); if (k) metas[k] = m.content; });
    return { title: document.title, url: location.href, domain: location.hostname, metas };
  },

  FIND_COMMENTS: () => {
    const comments = [];
    const w = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    while (w.nextNode()) { const t = w.currentNode.textContent.trim(); if (t.length > 3) comments.push(t.slice(0, 200)); }
    return comments;
  },

  CHECK_PASSIVE_VULNS: () => {
    const findings = [];
    const url = new URL(location.href);
    url.searchParams.forEach((v, k) => {
      if (document.body.innerHTML.includes(v) && v.length > 2) findings.push({ type: 'Reflected Parameter', detail: `${k}=${v}`, severity: 'medium' });
    });
    const redirParams = ['url', 'redirect', 'redirect_uri', 'next', 'return', 'returnTo', 'goto', 'dest', 'destination', 'redir', 'return_url', 'continue'];
    url.searchParams.forEach((v, k) => { if (redirParams.includes(k.toLowerCase())) findings.push({ type: 'Potential Open Redirect', detail: `Parameter: ${k}`, severity: 'medium' }); });
    document.querySelectorAll('script[src*="callback="]').forEach(s => findings.push({ type: 'JSONP Endpoint', detail: s.src, severity: 'low' }));
    const gen = document.querySelector('meta[name="generator"]');
    if (gen) findings.push({ type: 'Version Disclosure', detail: gen.content, severity: 'info' });
    document.querySelectorAll('script:not([src])').forEach(s => {
      if (s.textContent.includes('addEventListener') && s.textContent.includes('message'))
        findings.push({ type: 'postMessage Listener', detail: 'Page listens for postMessage events', severity: 'low' });
    });
    return findings;
  },
  GET_META_CSP: () => {
    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return { ok: true, csp: meta ? meta.getAttribute('content') : null };
  },
  GET_STORAGE: () => {
    const data = { localStorage: {}, sessionStorage: {} };
    try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); data.localStorage[k] = localStorage.getItem(k)?.slice(0, 500); } } catch {}
    try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); data.sessionStorage[k] = sessionStorage.getItem(k)?.slice(0, 500); } } catch {}
    return { ok: true, data };
  }
};
