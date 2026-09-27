require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.AUTH_PORT || 3001;
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is required');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;
const TOKEN_NAME = 'acronous_token';
const USERS_FILE = path.join(__dirname, 'users.json');

// ── CORS allowlist: only Acronous first-party origins (never reflect any Origin) ──
const ALLOWED_ORIGINS = new Set([
  'https://acronous.com',
  'https://www.acronous.com',
  'https://ai.acronous.com',
  'https://equyvo.acronous.com',
  'https://navigwiz.acronous.com',
  'https://dashboard.acronous.com',
  'https://api.acronous.com',
  'http://127.0.0.1:8080',
  'http://localhost:8080',
  'http://127.0.0.1:3001',
  'http://localhost:3001',
]);
const corsOptions = {
  origin(origin, cb) {
    // Allow same-origin / non-browser (no Origin header) requests.
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.has(origin)) return cb(null, origin);
    return cb(new Error('CORS blocked'));
  },
  credentials: true,
};

app.use(cors(corsOptions));
app.use(cookieParser());
// Capture raw body for Razorpay webhook HMAC (needs exact bytes).
app.use(express.json({
  verify(req, _res, buf) {
    try { req.rawBody = buf ? buf.toString('utf8') : ''; } catch { req.rawBody = ''; }
  },
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
    }
  } catch (e) {
    console.error('Error loading users:', e.message);
  }
  return [];
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function setAuthCookie(res, token) {
  res.cookie(TOKEN_NAME, token, {
    domain: '.acronous.com',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    // httpOnly: JS can no longer steal the session via XSS. Frontends
    // authenticate with `credentials: 'include'` (cookie sent automatically)
    // or the Bearer token returned at login for native apps.
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
  });
}

function clearAuthCookie(res) {
  res.clearCookie(TOKEN_NAME, {
    domain: '.acronous.com',
    path: '/',
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies?.[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
  req.user = decoded;
  next();
}

app.get('/api/auth/verify', (req, res) => {
  const token = req.cookies?.[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.json({ valid: false });
  }
  return res.json({ valid: true, user: { id: decoded.id, email: decoded.email, name: decoded.name } });
});

app.get('/api/auth/me', (req, res) => {
  const token = req.cookies?.[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.json({ user: { id: decoded.id, email: decoded.email, name: decoded.name } });
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const users = loadUsers();
    if (users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: crypto.randomUUID(),
      email: email.toLowerCase(),
      name: name || email.split('@')[0],
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    saveUsers(users);

    const token = generateToken(newUser);
    setAuthCookie(res, token);

    return res.json({ success: true, token, user: { id: newUser.id, email: newUser.email, name: newUser.name } });
  } catch (e) {
    console.error('Signup error:', e);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/auth/signup-redirect', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const users = loadUsers();
    if (users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: crypto.randomUUID(),
      email: email.toLowerCase(),
      name: name || email.split('@')[0],
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    saveUsers(users);

    const token = generateToken(newUser);
    setAuthCookie(res, token);

    const redirect = req.body.redirect || '/';
    const target = `${redirect}${redirect.includes('?') ? '&' : '?'}token=${token}`;
    return res.json({ success: true, redirectUrl: target, token });
  } catch (e) {
    console.error('Signup error:', e);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const users = loadUsers();
    const user = users.find(u => u.email === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateToken(user);
    setAuthCookie(res, token);

    return res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/auth/login-redirect', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const users = loadUsers();
    const user = users.find(u => u.email === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = generateToken(user);
    setAuthCookie(res, token);

    const redirect = req.body.redirect || '/';
    const target = `${redirect}${redirect.includes('?') ? '&' : '?'}token=${token}`;
    return res.json({ success: true, redirectUrl: target, token });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  return res.json({ success: true });
});

app.get('/', (req, res) => {
  const token = req.cookies?.[TOKEN_NAME];
  if (token && verifyToken(token)) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  const token = req.cookies?.[TOKEN_NAME];
  if (token) {
    const decoded = verifyToken(token);
    if (decoded) {
      const redirect = req.query.redirect || '/';
      return res.redirect(redirect);
    }
  }
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
  const token = req.cookies?.[TOKEN_NAME];
  if (token) {
    const decoded = verifyToken(token);
    if (decoded) {
      const redirect = req.query.redirect || '/';
      return res.redirect(redirect);
    }
  }
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/logout', (req, res) => {
  clearAuthCookie(res);
  res.redirect('/login');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', users: loadUsers().length });
});

// ── Razorpay Standard Checkout (local dev + self-host fallback) ──────────
// Production traffic uses the central billing worker (api.acronous.com) with
// the same paths. The KEY_SECRET never leaves this server: browsers receive
// only key_id + order_id, then return payment_id + signature for verification.
//   POST /api/create-order  {plan}            (plan REQUIRED — no raw amounts)
//   POST /api/verify-payment {razorpay_order_id, razorpay_payment_id, razorpay_signature, plan}
//   POST /v1/billing/webhook (Razorpay safety net, HMAC of raw body)
//   GET  /v1/billing/status (public catalog + caller's own ledger entries)
//   GET  /v1/billing/entitlements (public tier limits, no auth)
// Aliases /v1/billing/order and /v1/billing/verify behave identically.
const Razorpay = require('razorpay');
const PAYMENTS_LEDGER = path.join(__dirname, 'verified-payments.json');

// Simple in-memory rate limiter for billing endpoints (per IP).
const _rateBuckets = new Map();
function billingRateLimit(req, res, next) {
  try {
    const ip = (req.headers['cf-connecting-ip'] || req.ip || req.socket?.remoteAddress || 'x').toString();
    const now = Date.now();
    const b = _rateBuckets.get(ip) || { n: 0, reset: now + 60000 };
    if (now > b.reset) { b.n = 0; b.reset = now + 60000; }
    b.n += 1;
    _rateBuckets.set(ip, b);
    if (b.n > 30) return res.status(429).json({ error: 'Too many billing requests. Please wait a minute.' });
  } catch {}
  next();
}

function billingKeys() {
  const keyId = (process.env.RAZORPAY_KEY_ID || '').trim();
  const keySecret = (process.env.RAZORPAY_KEY_SECRET || '').trim();
  if (!keyId || !keySecret) return null;
  return { keyId, keySecret };
}

// Single source of truth: Acronous-landing-page/billing/plans.json.
// Returns price in INR, 0 for free plans, null for custom/unknown.
function planPriceInr(planId) {
  try {
    const catalog = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'billing', 'plans.json'), 'utf-8'));
    if (catalog.bundle && catalog.bundle.id === planId) return catalog.bundle.price_inr;
    for (const product of Object.values(catalog.products || {})) {
      const found = (product.plans || []).find((p) => p.id === planId);
      if (found) return found.price_inr;
    }
    const pack = ((catalog.api_packs || {}).packs || []).find((p) => p.id === planId);
    if (pack) return pack.price_inr;
  } catch (e) {
    console.error('Billing catalog read error:', e.message);
  }
  return null;
}

// Public entitlement contract: billing/entitlements.json (tier limits).
// Served at GET /v1/billing/entitlements so every app uses one source.
function readEntitlements() {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'billing', 'entitlements.json'), 'utf-8'));
  } catch {
    return { version: 0, upgrade_urls: {} };
  }
}

function readLedger() {
  try {
    if (fs.existsSync(PAYMENTS_LEDGER)) return JSON.parse(fs.readFileSync(PAYMENTS_LEDGER, 'utf-8'));
  } catch (e) {
    console.error('Payments ledger read error:', e.message);
  }
  return [];
}

function ledgerHasOrder(orderId) {
  return readLedger().some((e) => e && e.order_id === orderId);
}

function ledgerAppend(entry) {
  try {
    const ledger = readLedger();
    ledger.push(entry);
    fs.writeFileSync(PAYMENTS_LEDGER, JSON.stringify(ledger.slice(-2000), null, 2));
  } catch (e) {
    console.error('Payments ledger write error:', e.message);
  }
}

function userKeyOf(user) {
  return (user && (user.email || user.id)) || '';
}

function billingAuth(req, res, next) {
  const token = req.cookies?.[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Please sign in to continue.' });
  }
  req.user = decoded;
  next();
}

app.post(['/api/create-order', '/v1/billing/order'], billingAuth, billingRateLimit, async (req, res) => {
  try {
    const keys = billingKeys();
    if (!keys) {
      return res.status(503).json({ error: 'Billing is not configured yet. Please try again later.' });
    }
    // STRICT: a catalog plan is required. Raw client-supplied amounts are
    // rejected — the price always comes from plans.json (prevents ₹1-for-Ultra).
    const { plan, currency = 'INR', receipt: rawReceipt } = req.body || {};
    if (typeof plan !== 'string' || !plan) {
      return res.status(400).json({ error: 'A plan id is required.' });
    }
    const planId = plan.slice(0, 64);
    const priceInr = planPriceInr(planId);
    if (priceInr === null) {
      return res.status(400).json({ error: 'Unknown plan.' });
    }
    if (!priceInr || priceInr <= 0) {
      return res.status(400).json({ error: 'That plan is free or custom — no online payment needed.' });
    }
    const amount = Math.round(priceInr * 100);
    const receipt = String(rawReceipt || `acro_${Date.now().toString(36)}`).slice(0, 40);
    const rzp = new Razorpay({ key_id: keys.keyId, key_secret: keys.keySecret });
    const order = await rzp.orders.create({
      amount,
      currency: String(currency || 'INR').toUpperCase().slice(0, 3) || 'INR',
      receipt,
      // notes bind this order to this user + plan; verify/webhook enforce it.
      notes: { user: userKeyOf(req.user), plan: planId },
    });
    return res.json({ order_id: order.id, amount: order.amount, currency: order.currency, key_id: keys.keyId, plan: planId });
  } catch (e) {
    const status = e && (e.statusCode || e.status);
    if (status === 401 || status === 403) {
      console.error('Razorpay auth failure:', e.message);
      return res.status(401).json({ error: 'Billing authentication failed.' });
    }
    console.error('Create-order error:', e && e.message);
    return res.status(500).json({ error: 'Could not create a payment order. Please try again.' });
  }
});

app.post(['/api/verify-payment', '/v1/billing/verify'], billingAuth, billingRateLimit, async (req, res) => {
  const keys = billingKeys();
  if (!keys) {
    return res.status(503).json({ error: 'Billing is not configured yet. Please try again later.' });
  }
  const { razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature, plan } = req.body || {};
  if (!orderId || !paymentId || !signature) {
    return res.status(400).json({ ok: false, error: 'Missing payment fields.' });
  }
  const expected = crypto
    .createHmac('sha256', keys.keySecret)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(String(signature), 'utf8');
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!match) {
    // Signature mismatch: do NOT record anything as paid.
    return res.status(400).json({ ok: false, error: 'Signature mismatch.' });
  }
  // Idempotency: same order verified twice returns the original grant.
  if (ledgerHasOrder(String(orderId))) {
    const prior = readLedger().find((e) => e.order_id === String(orderId));
    return res.json({ ok: true, plan: (prior && prior.plan) || plan || null, duplicate: true });
  }
  // Bind order → amount/plan/user via Razorpay (prevents replaying a ₹99
  // payment as Ultra, or one user's payment as another user's grant).
  try {
    const rzp = new Razorpay({ key_id: keys.keyId, key_secret: keys.keySecret });
    const rzOrder = await rzp.orders.fetch(String(orderId));
    const claimedPlan = typeof plan === 'string' && plan ? plan.slice(0, 64) : null;
    const notePlan = rzOrder && rzOrder.notes && typeof rzOrder.notes.plan === 'string' ? rzOrder.notes.plan : null;
    const noteUser = rzOrder && rzOrder.notes && typeof rzOrder.notes.user === 'string' ? rzOrder.notes.user : null;
    const planId = claimedPlan || notePlan;
    if (!planId || planPriceInr(planId) === null) {
      return res.status(400).json({ ok: false, error: 'Unknown plan for this order.' });
    }
    if (claimedPlan && notePlan && claimedPlan !== notePlan) {
      return res.status(400).json({ ok: false, error: 'Plan does not match this order.' });
    }
    const wantPaise = Math.round((planPriceInr(planId) || 0) * 100);
    if (Number(rzOrder.amount) !== wantPaise) {
      return res.status(400).json({ ok: false, error: 'Amount does not match this plan.' });
    }
    if (noteUser && noteUser !== userKeyOf(req.user)) {
      return res.status(403).json({ ok: false, error: 'This order belongs to a different account.' });
    }
    ledgerAppend({
      order_id: String(orderId),
      payment_id: String(paymentId),
      plan: planId,
      amount: Number(rzOrder.amount),
      currency: rzOrder.currency || 'INR',
      user: userKeyOf(req.user),
      ts: new Date().toISOString(),
    });
    const ent = readEntitlements();
    return res.json({ ok: true, plan: planId, upgrade_urls: ent.upgrade_urls || {} });
  } catch (e) {
    console.error('Verify order-fetch error:', e && e.message);
    // Signature was valid (money moved). Record minimally so the webhook or
    // a retry can reconcile, but tell the client to retry verification.
    ledgerAppend({
      order_id: String(orderId),
      payment_id: String(paymentId),
      plan: (typeof plan === 'string' && plan) || null,
      user: userKeyOf(req.user),
      ts: new Date().toISOString(),
      pending_reconcile: true,
    });
    return res.status(202).json({ ok: true, pending: true, error: 'Verified, grant pending. It will activate shortly.' });
  }
});

// Razorpay webhook safety net: grants even if the user closes the browser
// before /verify runs. Configure in Razorpay Dashboard → Webhooks:
//   URL: https://api.acronous.com/v1/billing/webhook (prod worker)
//   Local:  http://127.0.0.1:3001/v1/billing/webhook
//   Events: payment.captured, order.paid
app.post(['/v1/billing/webhook', '/api/billing-webhook'], async (req, res) => {
  try {
    const secret = (process.env.RAZORPAY_WEBHOOK_SECRET || '').trim();
    if (!secret) return res.status(503).json({ error: 'Webhook not configured.' });
    const raw = req.rawBody || JSON.stringify(req.body || {});
    const sig = req.headers['x-razorpay-signature'] || '';
    const expected = crypto.createHmac('sha256', secret).update(raw).digest('hex');
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(String(sig), 'utf8');
    if (!(a.length === b.length && crypto.timingSafeEqual(a, b))) {
      return res.status(401).json({ error: 'Bad webhook signature.' });
    }
    const evt = req.body || {};
    const type = String(evt.event || '');
    if (type === 'payment.captured' || type === 'order.paid') {
      const entity = (evt.payload && (evt.payload.payment?.entity || evt.payload.order?.entity)) || {};
      const notes = entity.notes || {};
      const planId = String(notes.plan || '');
      const orderUser = String(notes.user || '');
      const paymentId = String(entity.id || '');
      if (planId && planPriceInr(planId) !== null && !ledgerHasOrder(String(entity.order_id || paymentId))) {
        ledgerAppend({
          order_id: String(entity.order_id || ''),
          payment_id: paymentId,
          plan: planId,
          amount: Number(entity.amount) || null,
          currency: entity.currency || 'INR',
          user: orderUser,
          via: 'webhook',
          ts: new Date().toISOString(),
        });
      }
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error('Webhook error:', e && e.message);
    return res.status(500).json({ error: 'Webhook handling failed.' });
  }
});

// Public entitlement contract (no auth): every app fetches ONE source.
app.get(['/v1/billing/entitlements', '/api/billing-entitlements'], (_req, res) => {
  return res.json(readEntitlements());
});

// Billing status: public catalog/entitlements + the caller's own verified
// payments (from this server's ledger). The central worker remains the
// entitlement authority in production; this endpoint keeps local dev honest.
app.get(['/v1/billing/status', '/api/billing-status'], (req, res) => {
  try {
    const token = req.cookies?.[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
    const decoded = verifyToken(token);
    const me = decoded ? userKeyOf(decoded) : null;
    const mine = me ? readLedger().filter((e) => e.user === me).slice(-20) : [];
    return res.json({
      entitlements: readEntitlements(),
      payments: mine,
      signed_in: !!decoded,
    });
  } catch (e) {
    console.error('Billing status error:', e && e.message);
    return res.status(500).json({ error: 'Could not load billing status.' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Acronous Auth Server running on http://localhost:${PORT}`);
  console.log(`Login: http://localhost:${PORT}/login`);
});
