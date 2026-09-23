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

  var API_BASE = 'https://api.acronous.com';
  try {
    var h = window.location.hostname || '';
    // Local dev: the auth-server (port 3001) serves billing alongside auth.
    // Override with window.__ACRONOUS_API_BASE__ to target any other backend
    // (e.g. the Navigwiz FastAPI dev server on :8000, or wrangler dev).
    if (h === 'localhost' || h === '127.0.0.1' || h.endsWith('.localhost')) {
      API_BASE = window.__ACRONOUS_API_BASE__ || 'http://127.0.0.1:3001';
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
      var m = document.cookie.match(/(?:^|;\s*)acronous_token=([^;]+)/);
      if (m) return decodeURIComponent(m[1]);
      return localStorage.getItem('acronous_token') || localStorage.getItem('equyvo_cognito_token') || null;
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
    if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
    return fetch(API_BASE + path, opts).then(function (r) {
      return r.json().catch(function () { return { error: 'bad_response' }; }).then(function (j) {
        if (!r.ok) {
          var err = new Error((j && j.error) || ('Request failed (' + r.status + ')'));
          err.status = r.status; err.body = j;
          throw err;
        }
        return j;
      });
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
          try {
            document.dispatchEvent(new CustomEvent('acronous:plan-active', { detail: v }));
          } catch (e) {}
        }).catch(function (e) {
          if (e && e.message === 'payment_cancelled') { toast('Payment window closed. No charge was made.'); return; }
          if (e && e.message === 'signin_required') return;
          toast(e && e.message ? e.message : 'Payment failed. Please try again.');
        });
      });
    });
  }

  window.AcronousBilling = { buy: buy, status: status, wireButtons: wireButtons, toast: toast, planLabel: planLabel, getApiBase: function () { return API_BASE; } };
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
