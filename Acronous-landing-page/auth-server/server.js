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

app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json());
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
    httpOnly: false,
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
//   POST /api/create-order  {plan} | {amount (paise), currency?, receipt?}
//   POST /api/verify-payment {razorpay_order_id, razorpay_payment_id, razorpay_signature}
const Razorpay = require('razorpay');
const PAYMENTS_LEDGER = path.join(__dirname, 'verified-payments.json');

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

function billingAuth(req, res, next) {
  const token = req.cookies?.[TOKEN_NAME] || req.headers.authorization?.replace('Bearer ', '');
  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ error: 'Please sign in to continue.' });
  }
  req.user = decoded;
  next();
}

app.post(['/api/create-order', '/v1/billing/order'], billingAuth, async (req, res) => {
  try {
    const keys = billingKeys();
    if (!keys) {
      return res.status(503).json({ error: 'Billing is not configured yet. Please try again later.' });
    }
    const { plan, amount: rawAmount, currency = 'INR', receipt: rawReceipt } = req.body || {};
    let amount;
    let planLabel = typeof plan === 'string' ? plan.slice(0, 64) : 'one_time';
    if (plan) {
      const priceInr = planPriceInr(plan);
      if (priceInr === null) {
        return res.status(400).json({ error: 'Unknown plan.' });
      }
      if (!priceInr || priceInr <= 0) {
        return res.status(400).json({ error: 'That plan is free or custom — no online payment needed.' });
      }
      amount = Math.round(priceInr * 100);
    } else {
      amount = Math.floor(Number(rawAmount));
      if (!Number.isFinite(amount) || amount < 100) {
        return res.status(400).json({ error: 'Amount must be an integer >= 100 paise.' });
      }
    }
    const receipt = String(rawReceipt || `acro_${Date.now().toString(36)}`).slice(0, 40);
    const rzp = new Razorpay({ key_id: keys.keyId, key_secret: keys.keySecret });
    const order = await rzp.orders.create({
      amount,
      currency: String(currency || 'INR').toUpperCase().slice(0, 3) || 'INR',
      receipt,
      notes: { user: req.user.email || req.user.id, plan: planLabel },
    });
    return res.json({ order_id: order.id, amount: order.amount, currency: order.currency, key_id: keys.keyId });
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

app.post(['/api/verify-payment', '/v1/billing/verify'], billingAuth, (req, res) => {
  const keys = billingKeys();
  if (!keys) {
    return res.status(503).json({ error: 'Billing is not configured yet. Please try again later.' });
  }
  const { razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature } = req.body || {};
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
  try {
    const ledger = fs.existsSync(PAYMENTS_LEDGER) ? JSON.parse(fs.readFileSync(PAYMENTS_LEDGER, 'utf-8')) : [];
    ledger.push({ order_id: orderId, payment_id: paymentId, user: req.user.email || req.user.id, ts: new Date().toISOString() });
    fs.writeFileSync(PAYMENTS_LEDGER, JSON.stringify(ledger, null, 2));
  } catch (e) {
    console.error('Payments ledger write error:', e.message);
  }
  return res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Acronous Auth Server running on http://localhost:${PORT}`);
  console.log(`Login: http://localhost:${PORT}/login`);
});
