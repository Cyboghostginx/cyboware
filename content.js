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

    // Tabnabbing — target=_blank without rel=noopener (or noreferrer) on cross-origin links
    const externalBlankLinks = [];
    document.querySelectorAll('a[target="_blank"]').forEach(a => {
      const rel = (a.rel || '').toLowerCase();
      if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
        try {
          const linkOrigin = new URL(a.href, location.href).origin;
          if (linkOrigin && linkOrigin !== location.origin) externalBlankLinks.push(a.href);
        } catch {}
      }
    });
    if (externalBlankLinks.length) {
      findings.push({ type: 'Reverse Tabnabbing', detail: `${externalBlankLinks.length} external link(s) with target="_blank" missing rel="noopener" — opened tabs can navigate this window. Example: ${externalBlankLinks[0].slice(0, 120)}`, severity: 'low' });
    }

    // Inline scripts containing DOM XSS sources (location.hash, document.referrer, name, location.search)
    // mapped to dangerous sinks (innerHTML, document.write, eval, setTimeout-string, location)
    const sources = ['location.hash', 'location.search', 'document.referrer', 'window.name', 'document.URL', 'document.documentURI', 'postMessage'];
    const sinks = ['innerHTML', 'outerHTML', 'document.write', 'document.writeln', 'eval(', 'setTimeout(', 'setInterval(', 'Function(', 'insertAdjacentHTML', 'location.href', 'location.replace', 'jQuery.html', '.html('];
    document.querySelectorAll('script:not([src])').forEach((s, idx) => {
      const txt = s.textContent;
      if (txt.length < 20) return;
      const foundSources = sources.filter(src => txt.includes(src));
      const foundSinks = sinks.filter(sink => txt.includes(sink));
      if (foundSources.length && foundSinks.length) {
        findings.push({ type: 'DOM XSS Candidate', detail: `Inline script #${idx+1}: source [${foundSources.join(', ')}] + sink [${foundSinks.join(', ')}] — flow analysis needed to confirm taint`, severity: 'medium' });
      }
      // Plain postMessage listener — flag separately
      if (txt.includes('addEventListener') && /addEventListener\s*\(\s*['"]message['"]/.test(txt)) {
        // Check if it validates event.origin — common mistake is omitting the check
        const hasOriginCheck = /event\.origin|e\.origin|\.origin\s*[=!]==?/.test(txt);
        if (!hasOriginCheck) {
          findings.push({ type: 'postMessage No Origin Check', detail: `Inline script #${idx+1}: postMessage listener with no origin validation — accepts messages from any frame`, severity: 'medium' });
        } else {
          findings.push({ type: 'postMessage Listener', detail: `Inline script #${idx+1}: handler validates origin (review the check carefully — substring matches are exploitable)`, severity: 'low' });
        }
      }
      // Prototype pollution sinks — recursive merge / Object.assign with user input keys
      if (/Object\.assign\s*\(\s*[a-zA-Z_$][\w$]*\s*,/.test(txt) || /\$\.extend\s*\(\s*true\s*,/.test(txt) || /lodash\.merge|_\.merge\s*\(/.test(txt)) {
        findings.push({ type: 'Prototype Pollution Sink', detail: `Inline script #${idx+1}: deep-merge or Object.assign pattern — vulnerable to prototype pollution if any operand is user-controlled`, severity: 'low' });
      }
    });

    // Dangling markup injection candidate — single-quoted attributes with user input pre-context
    const formsToOtherOrigins = [];
    document.querySelectorAll('form[action]').forEach(f => {
      try {
        const a = new URL(f.action, location.href);
        if (a.origin !== location.origin) formsToOtherOrigins.push(a.href);
      } catch {}
    });
    if (formsToOtherOrigins.length) {
      findings.push({ type: 'Cross-Origin Form Action', detail: `${formsToOtherOrigins.length} form(s) submit to other origins. Example: ${formsToOtherOrigins[0]} — verify action URL isn't user-controlled`, severity: 'low' });
    }

    // Mixed content — HTTP resources on HTTPS page
    if (location.protocol === 'https:') {
      const mixed = [];
      document.querySelectorAll('script[src^="http://"], link[href^="http://"], img[src^="http://"], iframe[src^="http://"]').forEach(el => {
        mixed.push(el.tagName + ': ' + (el.src || el.href));
      });
      if (mixed.length) findings.push({ type: 'Mixed Content', detail: `${mixed.length} HTTP resource(s) on HTTPS page — can be MITM'd. Example: ${mixed[0].slice(0,150)}`, severity: 'medium' });
    }

    // Suspicious iframes — sandboxed without restrictions, or with allow-* permissions
    document.querySelectorAll('iframe').forEach(f => {
      const sb = (f.getAttribute('sandbox') || '').toLowerCase();
      if (sb && sb.includes('allow-scripts') && sb.includes('allow-same-origin')) {
        findings.push({ type: 'iframe sandbox bypass', detail: `iframe with sandbox="allow-scripts allow-same-origin" — same-origin iframe can remove its own sandbox`, severity: 'low' });
      }
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
