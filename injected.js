/* ═══════════════════════════════════════════════════════════════
   CYBOWARE — Injected Script (main world — access page JS globals)
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
    this._cybo = { method, url };
    return origOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(body) {
    if (this._cybo) {
      try {
        window.postMessage({ source: SRC, payload: { type: 'xhr', ...this._cybo, timestamp: Date.now() } }, '*');
      } catch {}
    }
    return origSend.apply(this, arguments);
  };
})();
