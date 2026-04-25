/* ═══════════════════════════════════════════════════════════════
   CYBOWARE — Content Script v2
   ═══════════════════════════════════════════════════════════════ */
(() => {
  const s = document.createElement('script');
  s.src = chrome.runtime.getURL('injected.js');
  s.onload = () => s.remove();
  (document.head || document.documentElement).appendChild(s);
})();

window.addEventListener('message', (e) => {
  if (e.source !== window || e.data?.source !== 'CYBOWARE_INJECTED') return;
  chrome.runtime.sendMessage({ type: 'INTERCEPTED_REQUEST', payload: e.data.payload });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  try {
    const fn = contentHandlers[msg.type];
    if (fn) sendResponse({ ok: true, data: fn() });
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
      [() => !!document.querySelector('[class*="tw-"],link[href*="tailwind"]'), 'Tailwind CSS', 'CSS'],
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
    ];
    for (const [test, name, cat] of checks) { try { if (test()) tech.push({ name, category: cat, confidence: 'medium' }); } catch {} }
    return tech;
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
    document.querySelectorAll('[style*="display: none"],[style*="display:none"],[style*="visibility: hidden"],[style*="visibility:hidden"],.hidden,[hidden]').forEach(el => {
      const t = el.textContent?.trim().slice(0, 100);
      if (t && t.length > 2) r.hiddenDivs.push({ tag: el.tagName, id: el.id, class: el.className?.toString().slice(0, 50), text: t });
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
    document.querySelectorAll('[style*="display: none"],[style*="display:none"],[style*="visibility: hidden"],[style*="visibility:hidden"],.hidden,[hidden]').forEach(el => {
      el.style.setProperty('display', 'block', 'important');
      el.style.setProperty('visibility', 'visible', 'important');
      el.style.setProperty('opacity', '1', 'important');
      el.removeAttribute('hidden');
      el.style.outline = '2px dashed #C4392D';
    });
    document.querySelectorAll('input[type="hidden"]').forEach(el => { el.type = 'text'; el.style.cssText = 'border:2px dashed #C4392D;padding:4px;margin:2px;background:#fff3f3'; });
    document.querySelectorAll('input[disabled],select[disabled],textarea[disabled]').forEach(el => { el.disabled = false; el.style.outline = '2px dashed #2D7D46'; });
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
      f.querySelectorAll('input,select,textarea').forEach(el => fields.push({ tag: el.tagName, name: el.name, type: el.type, value: el.value?.slice(0, 50) }));
      forms.push({ action: f.action, method: f.method, fields });
    });
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
