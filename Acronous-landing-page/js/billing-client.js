/* Acronous billing client — Razorpay checkout for the whole ecosystem.
 *
 * SECURITY MODEL (read before touching):
 * - The browser NEVER sees RAZORPAY_KEY_SECRET. It only receives a public
 *   key_id + a server-created order_id from api.acronous.com.
 * - Flow: POST /v1/billing/order {plan} (Bearer JWT) -> open Razorpay
 *   Checkout (UPI / cards / netbanking / wallets / international) ->
 *   POST /v1/billing/verify {order, payment, signature, plan} (Bearer JWT)
 *   -> worker checks HMAC-SHA256(order|payment) with the secret and grants
 *   the subscription in KV. Forged verify calls fail signature check.
 * - No QR codes, no bank account numbers anywhere in client code.
 */
(function () {
  'use strict';

  // Same-origin first: the landing server (server.js) and the edge worker
  // (_worker.js) proxy /v1/billing/* → https://api.acronous.com, so the
  // browser never needs to know the backend host. No secrets, no internal
  // URLs (brain/ollama/VPS) ever appear in frontend code — only this
  // same-origin path + Razorpay's public checkout.js.
  var API_BASE = '';
  var CENTRAL_FALLBACK = 'https://api.acronous.com';
  try {
    var h = window.location.hostname || '';
    // Local dev without the proxy (file:// or a bare static server):
    // allow an explicit override, else talk straight to central.
    if (!h || h === 'localhost' || h === '127.0.0.1' || h.endsWith('.localhost')) {
      if (!window.__ACRONOUS_API_BASE__) {
        // Probe: if same-origin /v1/billing/entitlements answers, stay
        // same-origin (empty base). Otherwise fall back to central below
        // on first failed call (see api()).
        API_BASE = '';
      } else {
        API_BASE = window.__ACRONOUS_API_BASE__;
      }
    }
  } catch (e) {}

  function getToken() {
    try {
      // Native/mobile apps open checkout as /pricing.html?token=JWT —
      // persist once, then strip from the URL (same pattern as dashboard).
      var q = new URLSearchParams(window.location.search);
      var qt = q.get('token');
      if (qt) {
        try { localStorage.setItem('acronous_token', qt); } catch (e) {}
        q.delete('token');
        var clean = window.location.pathname + (q.toString() ? '?' + q.toString() : '') + window.location.hash;
        window.history.replaceState({}, document.title, clean);
        return qt;
      }
      // HttpOnly cookie is not readable from JS — but the browser sends it
      // automatically with credentials:'include'. For Bearer-header flows
      // (native apps, API clients), fall back to localStorage.
      var stored = localStorage.getItem('acronous_token') || localStorage.getItem('equyvo_cognito_token');
      if (stored) return stored;
      // Last resort: try reading the cookie (works if not HttpOnly, e.g. dev)
      var m = document.cookie.match(/(?:^|;\s*)acronous_token=([^;]+)/);
      if (m) return decodeURIComponent(m[1]);
      return null;
    } catch (e) { return null; }
  }

  function authHeaders() {
    var t = getToken();
    var h = { 'Content-Type': 'application/json' };
    if (t) h['Authorization'] = 'Bearer ' + t;
    return h;
  }

  function api(path, opts) {
    opts = opts || {};
    opts.headers = authHeaders();
    // httpOnly cookie auth: the session cookie (set by /api/auth/*) is sent
    // automatically. Bearer fallback covers native/webview callers.
    opts.credentials = 'include';
    if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
    function doFetch(base) {
      return fetch(base + path, opts).then(function (r) {
        return r.json().catch(function () { return { error: 'bad_response' }; }).then(function (j) {
          if (!r.ok) {
            var err = new Error((j && (j.response || j.error)) || ('Request failed (' + r.status + ')'));
            err.status = r.status; err.body = j;
            throw err;
          }
          return j;
        });
      });
    }
    // Same-origin first (hides backend host). If the static host has no
    // billing proxy (e.g. file:// preview), retry once against central.
    return doFetch(API_BASE).catch(function (e) {
      if (API_BASE === '' && (e instanceof TypeError || e.status === 404)) {
        return doFetch(CENTRAL_FALLBACK);
      }
      throw e;
    });
  }

  function loadRazorpay() {
    if (window.Razorpay) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = 'https://checkout.razorpay.com/v1/checkout.js';
      s.onload = resolve;
      s.onerror = function () { reject(new Error('Could not load Razorpay Checkout. Check your connection and retry.')); };
      document.head.appendChild(s);
    });
  }

  function status(product) {
    var p = product ? ('?product=' + encodeURIComponent(product)) : '';
    return api('/v1/billing/status' + p, { method: 'GET' });
  }

  // Buy a subscription plan or an API credit pack. `plan` is a catalog id
  // like 'ai_plus_monthly', 'nav_ai_plus', 'eq_creator', 'acronous_one',
  // 'api_pack_499'. Resolves to the verify response on success.
  function buy(plan, opts) {
    opts = opts || {};
    if (!getToken()) {
      // Remember the plan so checkout resumes automatically after sign-in
      // instead of dropping the user on a generic page.
      try { sessionStorage.setItem('acronous_pending_plan', plan); } catch (e) {}
      var next = opts.loginNext || (window.location.pathname + window.location.search);
      window.location.href = '/login?redirect=' + encodeURIComponent(next);
      return Promise.reject(new Error('signin_required'));
    }
    setBusy(opts, true);
    return api('/v1/billing/order', { method: 'POST', body: { plan: plan } })
      .then(function (order) { return loadRazorpay().then(function () { return order; }); })
      .then(function (order) {
        return new Promise(function (resolve, reject) {
          var rzp = new window.Razorpay({
            key: order.key_id,
            amount: order.amount,
            currency: order.currency || 'INR',
            name: 'Acronous',
            description: planLabel(plan),
            order_id: order.order_id,
            // UPI, cards, netbanking, wallets, EMI + international cards are
            // enabled in the Razorpay dashboard (see RAZORPAY_SETUP.md).
            theme: { color: '#6366f1' },
            modal: { ondismiss: function () { setBusy(opts, false); reject(new Error('payment_cancelled')); } },
            handler: function (resp) { resolve({ order: order, resp: resp }); },
          });
          rzp.on('payment.failed', function (r) {
            setBusy(opts, false);
            reject(new Error((r && r.error && r.error.description) || 'Payment failed. No money was deducted for a failed payment.'));
          });
          rzp.open();
        });
      })
      .then(function (both) {
        return api('/v1/billing/verify', {
          method: 'POST',
          body: {
            razorpay_order_id: both.resp.razorpay_order_id,
            razorpay_payment_id: both.resp.razorpay_payment_id,
            razorpay_signature: both.resp.razorpay_signature,
            plan: plan,
          },
        });
      })
      .then(function (v) { setBusy(opts, false); return v; })
      .catch(function (e) { setBusy(opts, false); throw e; });
  }

  // Notify the whole page + dashboard listeners that entitlements changed.
  function emitPlanActive(detail) {
    try { localStorage.setItem('acronous_last_plan', JSON.stringify({ plan: detail && (detail.plan || detail), at: new Date().toISOString() })); } catch (e) {}
    try {
      document.dispatchEvent(new CustomEvent('acronous:plan-active', { detail: detail }));
    } catch (e) {}
  }

  function planLabel(plan) {
    var map = {
      ai_starter_monthly: 'Acronous AI — Starter (₹149/mo)',
      ai_plus_monthly: 'Acronous AI — Plus (₹449/mo)',
      ai_pro_monthly: 'Acronous AI — Pro (₹999/mo)',
      ai_ultra_monthly: 'Acronous AI — Ultra (₹2,499/mo)',
      nav_ai_starter: 'Navigwiz — AI Starter (₹99/mo)',
      nav_ai_plus: 'Navigwiz — AI Plus (₹299/mo)',
      nav_ai_pro: 'Navigwiz — AI Pro (₹699/mo)',
      nav_ai_ultra: 'Navigwiz — AI Ultra (₹1,499/mo)',
      eq_plus: 'Equyvo — Plus (₹49/mo)',
      eq_premium: 'Equyvo — Premium (₹149/mo)',
      eq_creator: 'Equyvo — Creator (₹399/mo)',
      eq_creator_pro: 'Equyvo — Creator Pro (₹799/mo)',
      acronous_one: 'Acronous One (₹699/mo)',
      api_pack_99: 'API Starter — 1,000 credits (₹99)',
      api_pack_499: 'API Growth — 6,000 credits (₹499)',
      api_pack_999: 'API Scale — 14,000 credits (₹999)',
      api_pack_2499: 'API Business — 40,000 credits (₹2,499)',
    };
    return map[plan] || plan;
  }

  function setBusy(opts, busy) {
    if (opts && opts.button) {
      try {
        opts.button.disabled = !!busy;
        if (busy) { opts.button.dataset.label = opts.button.textContent; opts.button.textContent = 'Processing…'; }
        else if (opts.button.dataset.label) { opts.button.textContent = opts.button.dataset.label; }
      } catch (e) {}
    }
  }

  function toast(msg, ok) {
    var t = document.getElementById('billing-toast');
    if (!t) {
      t = document.createElement('div');
      t.id = 'billing-toast';
      t.style.cssText = 'position:fixed;left:50%;bottom:24px;transform:translateX(-50%);max-width:min(92vw,520px);padding:12px 18px;border-radius:12px;font-size:14px;z-index:9999;transition:opacity .3s;box-shadow:0 8px 32px rgba(0,0,0,.45)';
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.style.background = ok ? '#065f46' : '#7f1d1d';
    t.style.color = '#fff';
    t.style.opacity = '1';
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.style.opacity = '0'; }, 5000);
  }

  // Wire every [data-buy="plan_id"] button on the page.
  function wireButtons(root) {
    (root || document).querySelectorAll('[data-buy]').forEach(function (btn) {
      if (btn._acronousWired) return;
      btn._acronousWired = true;
      btn.addEventListener('click', function (ev) {
        ev.preventDefault();
        var plan = btn.getAttribute('data-buy');
        toast('Opening secure Razorpay checkout…', true);
        buy(plan, { button: btn }).then(function (v) {
          toast('Payment verified. Your plan is active.', true);
          emitPlanActive(v && v.plan ? v : { plan: plan, verify: v });
        }).catch(function (e) {
          if (e && e.message === 'payment_cancelled') { toast('Payment window closed. No charge was made.'); return; }
          if (e && e.message === 'signin_required') return;
          toast(e && e.message ? e.message : 'Payment failed. Please try again.');
        });
      });
    });
  }

  // ── Paywall: every 402 in the ecosystem redirects to pricing ──────────
  // Backend contract: HTTP 402 + {type:'paywall'} or {error:
  // 'quota_exceeded'|'out_of_credits'|'QUOTA_*'} with optional
  // {upgrade_url, product, plan}. Call handlePaywall(err) after ANY API
  // call; it returns the upgrade URL when it handled the error, else null.
  var PRODUCT_TAB = { acronous_ai: 'ai', navigwiz: 'nav', equyvo: 'eq', bundle: 'one', api: 'api' };

  function isPaywall(err) {
    if (!err) return false;
    if (err.status === 402) return true;
    var b = err.body || err;
    if (b && (b.type === 'paywall' || b.error === 'out_of_credits' || b.error === 'quota_exceeded')) return true;
    var code = b && (b.code || b.error);
    if (typeof code === 'string' && code.indexOf('QUOTA_') === 0) return true;
    return false;
  }

  function upgradeUrl(err, fallbackProduct) {
    var b = (err && err.body) || {};
    if (b.upgrade_url) return b.upgrade_url;
    var product = b.product || fallbackProduct || 'acronous_ai';
    var map = {
      acronous_ai: 'https://acronous.com/pricing.html#ai',
      navigwiz: 'https://acronous.com/pricing.html#nav',
      equyvo: 'https://acronous.com/pricing.html#eq',
      bundle: 'https://acronous.com/pricing.html#one',
      api: 'https://acronous.com/api.html#packs',
    };
    if (b.api_credits) return map.api;
    return map[product] || map.acronous_ai;
  }

  function redirectToPricing(err, fallbackProduct) {
    var url = upgradeUrl(err, fallbackProduct);
    try {
      // Same-site navigation keeps the pending-plan resume working.
      window.location.href = url;
    } catch (e) {}
    return url;
  }

  function handlePaywall(err, opts) {
    if (!isPaywall(err)) return null;
    opts = opts || {};
    try {
      document.dispatchEvent(new CustomEvent('acronous:paywall', { detail: { body: err.body || null, status: err.status || 402 } }));
    } catch (e) {}
    if (opts.noRedirect) return upgradeUrl(err, opts.product);
    // Small delay so the caller can toast the reason first.
    var url = upgradeUrl(err, opts.product);
    setTimeout(function () {
      try { window.location.href = url; } catch (e) {}
    }, opts.delayMs != null ? opts.delayMs : 1200);
    return url;
  }

  window.AcronousBilling = { buy: buy, status: status, wireButtons: wireButtons, toast: toast, planLabel: planLabel, getApiBase: function () { return API_BASE; }, isPaywall: isPaywall, upgradeUrl: upgradeUrl, redirectToPricing: redirectToPricing, handlePaywall: handlePaywall, productTab: PRODUCT_TAB };
  document.addEventListener('DOMContentLoaded', function () {
    wireButtons(document);
    // Resume a purchase that was interrupted by the sign-in redirect.
    try {
      var pending = sessionStorage.getItem('acronous_pending_plan');
      if (pending && getToken()) {
        sessionStorage.removeItem('acronous_pending_plan');
        toast('Resuming your checkout…', true);
        buy(pending).then(function () {
          toast('Payment verified. Your plan is active.', true);
          try { document.dispatchEvent(new CustomEvent('acronous:plan-active', { detail: { plan: pending } })); } catch (e) {}
        }).catch(function (e) {
          if (e && e.message !== 'payment_cancelled' && e.message !== 'signin_required') {
            toast(e && e.message ? e.message : 'Payment failed. Please try again.');
          }
        });
      }
    } catch (e) {}
  });
})();
