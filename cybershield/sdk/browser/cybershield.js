/**
 * CyberShield Universal — Browser Analytics Snippet v2.0
 *
 * Drop-in snippet that captures browser telemetry and streams it
 * to CyberShield for threat analysis.
 *
 * Usage:
 *   <script
 *     src="cybershield.js"
 *     data-api-key="cs_live_..."
 *     data-endpoint="https://your-cybershield-server.com"
 *     data-mode="passive"
 *   ></script>
 *
 * Modes:
 *   passive  — analytics only, never blocks (default)
 *   active   — can block via overlay if action == 'block'
 */

(function (window, document) {
  'use strict';

  // ── Config from script tag attributes ──────────────────────────────────────
  const _script = document.currentScript || (function () {
    const scripts = document.getElementsByTagName('script');
    return scripts[scripts.length - 1];
  })();

  const API_KEY = _script.getAttribute('data-api-key') || '';
  const ENDPOINT = (_script.getAttribute('data-endpoint') || 'http://localhost:5000').replace(/\/$/, '');
  const MODE = _script.getAttribute('data-mode') || 'passive';
  const SAMPLE_RATE = parseFloat(_script.getAttribute('data-sample-rate') || '1.0');
  const BEACON_INTERVAL = parseInt(_script.getAttribute('data-interval') || '5000', 10);

  if (!API_KEY) {
    console.warn('[CyberShield] data-api-key not set. Snippet inactive.');
    return;
  }

  // ── Session & fingerprint ──────────────────────────────────────────────────
  function _getOrCreateSession() {
    const KEY = '__cs_sid';
    let sid = sessionStorage.getItem(KEY);
    if (!sid) {
      sid = Math.random().toString(36).slice(2) + Date.now().toString(36);
      sessionStorage.setItem(KEY, sid);
    }
    return sid;
  }

  function _getFingerprint() {
    const parts = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || 0,
      navigator.deviceMemory || 0,
      !!window.chrome,
      !!window.safari,
    ];
    // Simple non-crypto hash
    let hash = 0;
    const str = parts.join('|');
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
    }
    return (hash >>> 0).toString(16);
  }

  // ── Telemetry payload builder ──────────────────────────────────────────────
  function _buildPayload(extra) {
    return {
      ip: '',                          // server-side resolved
      user_agent: navigator.userAgent,
      path: window.location.pathname + window.location.search,
      method: 'GET',
      payload: {
        referrer: document.referrer || '',
        title: document.title || '',
        url: window.location.href,
        fingerprint: _getFingerprint(),
        screen: screen.width + 'x' + screen.height,
        language: navigator.language,
        cookies_enabled: navigator.cookieEnabled,
        do_not_track: navigator.doNotTrack === '1',
        ...(extra || {}),
      },
      headers: {
        'x-cs-origin': window.location.origin,
      },
      session_id: _getOrCreateSession(),
      timestamp: new Date().toISOString(),
    };
  }

  // ── Send via Beacon API (preferred) or XHR fallback ───────────────────────
  function _send(payload) {
    if (Math.random() > SAMPLE_RATE) return;   // sampling

    const url = `${ENDPOINT}/api/ingest`;
    const body = JSON.stringify(payload);
    const headers = { 'Content-Type': 'application/json', 'X-CS-API-Key': API_KEY };

    // Prefer Beacon for unload events (fire-and-forget)
    if (navigator.sendBeacon && document.visibilityState === 'hidden') {
      const blob = new Blob([body], { type: 'application/json' });
      navigator.sendBeacon(url, blob);
      return;
    }

    // Use fetch with timeout
    const ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), 5000) : null;

    fetch(url, {
      method: 'POST',
      headers,
      body,
      signal: ctrl ? ctrl.signal : undefined,
      keepalive: true,
    })
      .then(res => {
        if (timer) clearTimeout(timer);
        if (MODE === 'active') {
          return res.json().then(result => {
            if (result.action === 'block') {
              _showBlockOverlay(result);
            }
          });
        }
      })
      .catch(() => { if (timer) clearTimeout(timer); });
  }

  // ── Active mode block overlay ──────────────────────────────────────────────
  function _showBlockOverlay(result) {
    if (document.getElementById('__cs_block_overlay')) return;
    const div = document.createElement('div');
    div.id = '__cs_block_overlay';
    div.style.cssText = [
      'position:fixed', 'top:0', 'left:0', 'width:100%', 'height:100%',
      'background:rgba(15,15,25,0.97)', 'z-index:2147483647',
      'display:flex', 'align-items:center', 'justify-content:center',
      'font-family:system-ui,sans-serif', 'color:#fff',
    ].join(';');
    div.innerHTML = `
      <div style="text-align:center;max-width:400px;padding:2rem">
        <div style="font-size:3rem;margin-bottom:1rem">🛡️</div>
        <h1 style="font-size:1.5rem;margin:0 0 0.5rem">Access Blocked</h1>
        <p style="color:#94a3b8;margin:0">
          This request was blocked by CyberShield security.<br>
          Threat: <strong style="color:#f87171">${result.attack_type || 'Suspicious Activity'}</strong>
        </p>
      </div>`;
    document.body.appendChild(div);
  }

  // ── Page navigation tracking (SPA-aware) ───────────────────────────────────
  let _lastPath = window.location.pathname;

  function _trackNavigation() {
    const current = window.location.pathname;
    if (current !== _lastPath) {
      _lastPath = current;
      _send(_buildPayload({ event: 'navigation', previous_path: _lastPath }));
    }
  }

  // ── Event listeners ────────────────────────────────────────────────────────

  // Initial page load
  _send(_buildPayload({ event: 'pageview' }));

  // Visibility change (tab switch / close)
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') {
      _send(_buildPayload({ event: 'visibility_hidden' }));
    }
  });

  // Periodic beacon for long sessions
  setInterval(function () {
    _trackNavigation();
    _send(_buildPayload({ event: 'heartbeat' }));
  }, BEACON_INTERVAL);

  // History API navigation (React Router, Next.js, etc.)
  const _origPushState = history.pushState.bind(history);
  history.pushState = function (...args) {
    _origPushState(...args);
    _trackNavigation();
  };

  window.addEventListener('popstate', _trackNavigation);

  // Expose minimal API
  window.CyberShield = {
    track: function (eventName, data) {
      _send(_buildPayload({ event: eventName, ...(data || {}) }));
    },
    sessionId: _getOrCreateSession(),
    fingerprint: _getFingerprint(),
    version: '2.0.0',
  };

})(window, document);
