// Acronous Cloudflare Worker
// Routes subdomains + handles centralized auth server

const TOKEN_NAME = 'acronous_token';

// Subdomain origins — proxy static content to each subdomain's Pages deployment.
// API routes on these subdomains are handled by their respective Workers directly
// (via Cloudflare route matching), bypassing this proxy.
const SUBDOMAIN_ORIGINS = {
  'ai.acronous.com':        { spa: 'https://acronous-ai.pages.dev', api: 'https://api.acronous.com' },
  'equyvo.acronous.com':    { spa: 'https://equyvo.pages.dev', api: '' },
  // navigwiz.acronous.com now has its own dedicated auth worker
  // 'navigwiz.acronous.com':  { spa: 'https://navigwiz.pages.dev', api: '' },
};

// Central billing authority. Same-origin /v1/billing/* + /v1/api/* on
// acronous.com are proxied here so frontend JS never hardcodes a backend
// host and secrets stay server-side.
const CENTRAL_BILLING = 'https://api.acronous.com';
const BILLING_PREFIXES = ['/v1/billing/', '/v1/api/', '/api/create-order', '/api/verify-payment'];

// First-party origins allowed to call billing/auth with credentials.
const ALLOWED_ORIGINS = new Set([
  'https://acronous.com',
  'https://www.acronous.com',
  'https://ai.acronous.com',
  'https://equyvo.acronous.com',
  'https://navigwiz.acronous.com',
  'https://dashboard.acronous.com',
]);

function allowedOrigin(req) {
  const o = req.headers.get('Origin');
  if (!o) return 'https://acronous.com';
  return ALLOWED_ORIGINS.has(o) ? o : 'https://acronous.com';
}

const API_PREFIXES = ['/v1/', '/api/', '/health'];

const LANDING_HOSTS = new Set(['acronous.com', 'www.acronous.com']);

// ── Auth Helpers (KV-persisted) ─────────────────────────────────────────

function base64Url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

function textEncode(s) { return new TextEncoder().encode(s); }
function textDecode(b) { return new TextDecoder().decode(b); }

async function createJWT(payload, secret) {
  const header = base64Url(textEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const now = Math.floor(Date.now() / 1000);
  const body = base64Url(textEncode(JSON.stringify({ ...payload, iat: now, exp: now + 604800 })));
  const data = header + '.' + body;
  const key = await crypto.subtle.importKey('raw', textEncode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, textEncode(data));
  return data + '.' + base64Url(sig);
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const key = await crypto.subtle.importKey('raw', textEncode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, base64UrlDecode(parts[2]), textEncode(parts[0] + '.' + parts[1]));
    if (!valid) return null;
    const payload = JSON.parse(textDecode(base64UrlDecode(parts[1])));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

async function hashPw(password, salt) {
  const hash = await crypto.subtle.digest('SHA-256', textEncode(password + salt));
  return base64Url(hash);
}

function userKey(email) { return `user:${email.toLowerCase()}`; }

async function getUser(email, env) {
  const raw = await env.AUTH_USERS.get(userKey(email));
  return raw ? JSON.parse(raw) : null;
}

async function saveUser(user, env) {
  await env.AUTH_USERS.put(userKey(user.email), JSON.stringify(user));
}

function corsResponse(body, status = 200, origin) {
  const headers = { 'Content-Type': 'application/json' };
  // Never reflect arbitrary origins with credentials — allowlist only.
  const o = typeof origin === 'string' && ALLOWED_ORIGINS.has(origin) ? origin : 'https://acronous.com';
  headers['Access-Control-Allow-Origin'] = o;
  headers['Access-Control-Allow-Credentials'] = 'true';
  return new Response(JSON.stringify(body), { status, headers });
}

function redirectResponse(location) {
  return new Response(null, { status: 302, headers: { Location: location } });
}

function setCookie(token, hostname) {
  const domain = hostname?.endsWith('acronous.com') ? 'Domain=.acronous.com; ' : '';
  // HttpOnly: session cookie is never readable via document.cookie (XSS-safe).
  // First-party apps authenticate with credentials:include or the ?token=
  // Bearer handoff persisted to app storage at login.
  return `${TOKEN_NAME}=${token}; ${domain}Path=/; Max-Age=604800; SameSite=Lax; Secure; HttpOnly`;
}

function clearCookie(hostname) {
  const domain = hostname?.endsWith('acronous.com') ? 'Domain=.acronous.com; ' : '';
  return `${TOKEN_NAME}=; ${domain}Path=/; Max-Age=0`;
}

function getTokenFromReq(req) {
  const auth = req.headers.get('Authorization');
  if (auth?.startsWith('Bearer ')) return auth.slice(7);
  const cookie = req.headers.get('Cookie');
  if (cookie) {
    const m = cookie.match(new RegExp(`${TOKEN_NAME}=([^;]+)`));
    if (m) return decodeURIComponent(m[1]);
  }
  return null;
}

// ── Auth HTML Pages (inline, self-contained) ────────────────────────────

const AUTH_STYLE = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#08080c;--surface:#0f0f16;--surface-2:#181822;--border:#22223a;--text:#e0e0f0;--text-muted:#7878a0;--primary:#6366f1;--primary-hover:#5558e6;--primary-glow:rgba(99,102,241,0.12);--accent-1:#22d3ee;--accent-2:#a78bfa;--error:#f87171;--success:#34d399;--radius:16px}
html{font-size:16px}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
.bg-glow{position:fixed;inset:0;pointer-events:none;overflow:hidden;z-index:0}
.bg-glow::before{content:'';position:absolute;top:-30%;left:-10%;width:50%;height:60%;background:radial-gradient(circle,var(--primary-glow) 0%,transparent 70%);border-radius:50%}
.bg-glow::after{content:'';position:absolute;bottom:-30%;right:-10%;width:50%;height:60%;background:radial-gradient(circle,rgba(168,85,247,0.08) 0%,transparent 70%);border-radius:50%}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:2.5rem;width:100%;max-width:420px;position:relative;z-index:1;backdrop-filter:blur(24px)}
.logo{width:72px;height:72px;margin:0 auto 1.25rem;border-radius:18px;overflow:hidden;display:flex;align-items:center;justify-content:center;background:#0a0a0f;border:1px solid var(--border)}
.logo svg{width:40px;height:40px}
h1{font-size:1.35rem;font-weight:700;text-align:center;margin-bottom:0.2rem;letter-spacing:-0.01em}
.subtitle{text-align:center;color:var(--text-muted);margin-bottom:1.75rem;font-size:0.875rem}
.form-group{margin-bottom:1rem}
label{display:block;font-size:0.8rem;font-weight:500;margin-bottom:0.35rem;color:var(--text-muted);letter-spacing:0.01em;text-transform:uppercase}
input{width:100%;padding:0.75rem 1rem;background:var(--surface-2);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:0.925rem;outline:none;transition:all 0.2s;font-family:inherit}
input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,0.1)}
input::placeholder{color:var(--text-muted);opacity:0.4}
.btn{width:100%;padding:0.8rem;border:none;border-radius:10px;font-size:0.95rem;font-weight:600;cursor:pointer;transition:all 0.2s;background:linear-gradient(135deg,var(--primary),#818cf8);color:white;font-family:inherit}
.btn:hover{opacity:0.92;transform:translateY(-1px);box-shadow:0 4px 20px rgba(99,102,241,0.25)}
.btn:active{transform:translateY(0)}
.btn:disabled{opacity:0.4;cursor:not-allowed;transform:none;box-shadow:none}
.btn-loading{display:flex;align-items:center;justify-content:center;gap:0.5rem}
.spinner{width:18px;height:18px;border:2px solid rgba(255,255,255,0.2);border-top-color:white;border-radius:50%;animation:spin 0.6s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.error{background:rgba(248,113,113,0.08);border:1px solid rgba(248,113,113,0.15);border-radius:10px;padding:0.65rem 0.85rem;color:var(--error);font-size:0.85rem;margin-bottom:1rem;display:none;line-height:1.4}
.error.show{display:block}
.footer-text{text-align:center;margin-top:1.5rem;font-size:0.85rem;color:var(--text-muted)}
.footer-text a{color:var(--accent-2);text-decoration:none;font-weight:600}
.footer-text a:hover{text-decoration:underline;color:var(--primary)}
.divider{display:flex;align-items:center;gap:1rem;margin:1.25rem 0;color:var(--text-muted);font-size:0.8rem}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
.back-link{display:inline-flex;align-items:center;gap:0.4rem;color:var(--text-muted);text-decoration:none;font-size:0.85rem;margin-bottom:1.5rem;transition:color 0.2s}
.back-link:hover{color:var(--text)}
`;

function loginPage(redirect) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Sign In - Acronous</title><style>${AUTH_STYLE}</style></head><body><div class="bg-glow"></div><div class="card"><div class="logo"><svg viewBox="0 0 80 80" fill="none"><rect width="80" height="80" rx="18" fill="#0a0a0f" stroke="#22223a" stroke-width="1"/><text x="40" y="50" text-anchor="middle" font-size="34" font-weight="800" fill="#6366f1" font-family="sans-serif">A</text></svg></div><h1>Welcome back</h1><p class="subtitle">Sign in to your Acronous account</p><div id="error" class="error"></div><form id="loginForm" novalidate><div class="form-group"><label for="email">Email</label><input id="email" type="email" placeholder="you@example.com" required autocomplete="email" autocapitalize="off" spellcheck="false"></div><div class="form-group"><label for="password">Password</label><input id="password" type="password" placeholder="&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;" required autocomplete="current-password" minlength="6"></div><button type="submit" class="btn" id="submitBtn">Sign In</button></form><p class="footer-text">Don't have an account? <a href="/signup${redirect ? '?redirect='+encodeURIComponent(redirect) : ''}">Create one</a></p></div><script>
(function(){var e=document.getElementById('loginForm'),t=document.getElementById('email'),n=document.getElementById('password'),o=document.getElementById('error'),i=document.getElementById('submitBtn'),r=new URLSearchParams(location.search).get('redirect')||'/';e.addEventListener('submit',async function(a){a.preventDefault();o.classList.remove('show');i.disabled=true;i.innerHTML='<div class="spinner"></div> Signing in...';try{var d=await fetch('/api/auth/login-redirect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:t.value.trim(),password:n.value,redirect:r})}),s=await d.json();if(s.redirectUrl){window.location.href=s.redirectUrl}else{o.textContent=s.error||'Invalid email or password';o.classList.add('show');i.disabled=false;i.textContent='Sign In'}}catch(c){o.textContent='Connection error. Please try again.';o.classList.add('show');i.disabled=false;i.textContent='Sign In'}})})();
</script></body></html>`;
}

function signupPage(redirect) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Sign Up - Acronous</title><style>${AUTH_STYLE}</style></head><body><div class="bg-glow"></div><div class="card"><div class="logo"><svg viewBox="0 0 80 80" fill="none"><rect width="80" height="80" rx="18" fill="#0a0a0f" stroke="#22223a" stroke-width="1"/><text x="40" y="50" text-anchor="middle" font-size="34" font-weight="800" fill="#6366f1" font-family="sans-serif">A</text></svg></div><h1>Create your account</h1><p class="subtitle">One account for all Acronous products</p><div id="error" class="error"></div><form id="signupForm" novalidate><div class="form-group"><label for="name">Full Name</label><input id="name" type="text" placeholder="John Doe" autocomplete="name" autocapitalize="words"></div><div class="form-group"><label for="email">Email</label><input id="email" type="email" placeholder="you@example.com" required autocomplete="email" autocapitalize="off" spellcheck="false"></div><div class="form-group"><label for="password">Password</label><input id="password" type="password" placeholder="&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;&#xb7;" required minlength="6" autocomplete="new-password"></div><button type="submit" class="btn" id="submitBtn">Create Account</button></form><p class="footer-text">Already have an account? <a href="/login${redirect ? '?redirect='+encodeURIComponent(redirect) : ''}">Sign in</a></p></div><script>
(function(){var e=document.getElementById('signupForm'),t=document.getElementById('name'),n=document.getElementById('email'),o=document.getElementById('password'),i=document.getElementById('error'),r=document.getElementById('submitBtn'),a=new URLSearchParams(location.search).get('redirect')||'/';e.addEventListener('submit',async function(d){d.preventDefault();i.classList.remove('show');r.disabled=true;r.innerHTML='<div class="spinner"></div> Creating account...';try{var s=await fetch('/api/auth/signup-redirect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:n.value.trim(),password:o.value,name:t.value.trim()||n.value.split('@')[0],redirect:a})}),u=await s.json();if(u.redirectUrl){window.location.href=u.redirectUrl}else{i.textContent=u.error||'Sign up failed';i.classList.add('show');r.disabled=false;r.textContent='Create Account'}}catch(c){i.textContent='Connection error. Please try again.';i.classList.add('show');r.disabled=false;r.textContent='Create Account'}})})();
</script></body></html>`;
}

function dashboardPage(user, token) {
  const tokenParam = token ? `?token=${token}` : '';
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Dashboard - Acronous</title><style>${AUTH_STYLE}.back-link{margin-bottom:1rem}.apps-grid{display:grid;grid-template-columns:1fr;gap:0.75rem;margin-top:1.25rem}@media(min-width:600px){.apps-grid{grid-template-columns:1fr 1fr}}.app-card{background:var(--surface-2);border:1px solid var(--border);border-radius:14px;padding:1.25rem;text-decoration:none;color:var(--text);transition:all 0.2s;display:flex;align-items:center;gap:1rem}.app-card:hover{border-color:var(--primary);transform:translateY(-2px);box-shadow:0 4px 24px var(--primary-glow)}.app-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.2rem;font-weight:700;color:white;flex-shrink:0}.app-icon.ai{background:linear-gradient(135deg,#6366f1,#22d3ee)}.app-icon.eq{background:linear-gradient(135deg,#ec4899,#a78bfa)}.app-icon.nw{background:linear-gradient(135deg,#f59e0b,#f87171)}.app-info h3{font-size:0.95rem;font-weight:600;margin-bottom:0.15rem}.app-info p{font-size:0.8rem;color:var(--text-muted)}.user-info{display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;padding-bottom:1.25rem;border-bottom:1px solid var(--border)}.user-details span{display:block}.user-details .name{font-weight:600;font-size:1rem}.user-details .email{font-size:0.8rem;color:var(--text-muted);margin-top:0.1rem}.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text);padding:0.45rem 1rem;border-radius:8px;cursor:pointer;font-size:0.8rem;transition:all 0.2s;font-family:inherit}.btn-outline:hover{border-color:var(--error);color:var(--error)}
</style></head><body><div class="bg-glow"></div><div class="card" style="max-width:520px"><div class="logo"><svg viewBox="0 0 80 80" fill="none"><rect width="80" height="80" rx="18" fill="#0a0a0f" stroke="#22223a" stroke-width="1"/><text x="40" y="50" text-anchor="middle" font-size="34" font-weight="800" fill="#6366f1" font-family="sans-serif">A</text></svg></div><h1>Acronous Apps</h1><div class="user-info"><div class="user-details"><span class="name">${escapeHtml(user.name)}</span><span class="email">${escapeHtml(user.email)}</span></div><button class="btn-outline" id="logoutBtn">Sign Out</button></div><p class="subtitle" style="text-align:left;margin-bottom:0">Choose an app to launch</p><div class="apps-grid"><a class="app-card" href="https://ai.acronous.com${tokenParam}"><div class="app-icon ai">AI</div><div class="app-info"><h3>Acronous AI</h3><p>AI-powered chat &amp; assistance</p></div></a><a class="app-card" href="https://equyvo.acronous.com${tokenParam}"><div class="app-icon eq">Eq</div><div class="app-info"><h3>Equyvo</h3><p>Social content &amp; discovery</p></div></a><a class="app-card" href="https://navigwiz.acronous.com${tokenParam}" style="grid-column:1/-1"><div class="app-icon nw">Nw</div><div class="app-info"><h3>Navigwiz</h3><p>AI-powered browser &amp; workspace</p></div></a></div></div><script>
(function(){document.getElementById('logoutBtn').addEventListener('click',async function(){await fetch('/api/auth/logout',{method:'POST'});window.location.href='/login'});var e=new URLSearchParams(location.search).get('token');if(e){document.querySelectorAll('.app-card').forEach(function(t){var n=new URL(t.href);n.searchParams.set('token',e);t.href=n.toString()})}})();
</script></body></html>`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

const NO_CACHE = { 'Cache-Control': 'private, no-cache, no-store, must-revalidate', 'Pragma': 'no-cache' };

// ── Auth Request Handler ────────────────────────────────────────────────

async function handleAuthRequest(request, url, env) {
  const path = url.pathname;
  const method = request.method;
  const origin = request.headers.get('Origin') || 'https://acronous.com';
  const hostname = url.hostname;
  if (!env?.JWT_SECRET) {
    return corsResponse({ error: 'Authentication not configured' }, 500, origin);
  }
  const jwtSecret = env.JWT_SECRET;

  // API routes
  if (path === '/api/auth/signup' && method === 'POST') {
    try {
      const { email, password, name } = await request.json();
      if (!email || !password) return corsResponse({ error: 'Email and password are required' }, 400, origin);
      if (password.length < 6) return corsResponse({ error: 'Password must be at least 6 characters' }, 400, origin);
      if (await getUser(email, env)) return corsResponse({ error: 'An account with this email already exists' }, 409, origin);

      const salt = crypto.randomUUID();
      const hashed = await hashPw(password, salt);
      const user = { id: crypto.randomUUID(), email: email.toLowerCase(), name: name || email.split('@')[0], salt, password: hashed, createdAt: new Date().toISOString() };
      await saveUser(user, env);

      const token = await createJWT({ id: user.id, email: user.email, name: user.name }, jwtSecret);
      const res = corsResponse({ success: true, token, user: { id: user.id, email: user.email, name: user.name } }, 200, origin);
      res.headers.append('Set-Cookie', setCookie(token, hostname));
      return res;
    } catch { return corsResponse({ error: 'Something went wrong. Please try again.' }, 500, origin); }
  }

  if (path === '/api/auth/signup-redirect' && method === 'POST') {
    try {
      const { email, password, name, redirect } = await request.json();
      if (!email || !password) return corsResponse({ error: 'Email and password are required' }, 400, origin);
      if (password.length < 6) return corsResponse({ error: 'Password must be at least 6 characters' }, 400, origin);
      if (await getUser(email, env)) return corsResponse({ error: 'An account with this email already exists' }, 409, origin);

      const salt = crypto.randomUUID();
      const hashed = await hashPw(password, salt);
      const user = { id: crypto.randomUUID(), email: email.toLowerCase(), name: name || email.split('@')[0], salt, password: hashed, createdAt: new Date().toISOString() };
      await saveUser(user, env);

      const token = await createJWT({ id: user.id, email: user.email, name: user.name }, jwtSecret);
      const target = (redirect || '/') + ((redirect || '').includes('?') ? '&' : '?') + 'token=' + token;
      const res = corsResponse({ success: true, redirectUrl: target, token }, 200, origin);
      res.headers.append('Set-Cookie', setCookie(token, hostname));
      return res;
    } catch { return corsResponse({ error: 'Authentication failed. Please try again.' }, 500, origin); }
  }

  if (path === '/api/auth/login' && method === 'POST') {
    try {
      const { email, password } = await request.json();
      if (!email || !password) return corsResponse({ error: 'Email and password are required' }, 400, origin);

      const user = await getUser(email, env);
      if (!user) return corsResponse({ error: 'Invalid email or password' }, 401, origin);

      const hashed = await hashPw(password, user.salt);
      if (hashed !== user.password) return corsResponse({ error: 'Invalid email or password' }, 401, origin);

      const token = await createJWT({ id: user.id, email: user.email, name: user.name }, jwtSecret);
      const res = corsResponse({ success: true, token, user: { id: user.id, email: user.email, name: user.name } }, 200, origin);
      res.headers.append('Set-Cookie', setCookie(token, hostname));
      return res;
    } catch { return corsResponse({ error: 'Something went wrong. Please try again.' }, 500, origin); }
  }

  if (path === '/api/auth/login-redirect' && method === 'POST') {
    try {
      const { email, password, redirect } = await request.json();
      if (!email || !password) return corsResponse({ error: 'Email and password are required' }, 400, origin);

      const user = await getUser(email, env);
      if (!user) return corsResponse({ error: 'Invalid email or password' }, 401, origin);

      const hashed = await hashPw(password, user.salt);
      if (hashed !== user.password) return corsResponse({ error: 'Invalid email or password' }, 401, origin);

      const token = await createJWT({ id: user.id, email: user.email, name: user.name }, jwtSecret);
      const target = (redirect || '/') + ((redirect || '').includes('?') ? '&' : '?') + 'token=' + token;
      const res = corsResponse({ success: true, redirectUrl: target, token }, 200, origin);
      res.headers.append('Set-Cookie', setCookie(token, hostname));
      return res;
    } catch { return corsResponse({ error: 'Something went wrong. Please try again.' }, 500, origin); }
  }

  if (path === '/api/auth/logout' && method === 'POST') {
    const res = corsResponse({ success: true }, 200, origin);
    res.headers.append('Set-Cookie', clearCookie(hostname));
    return res;
  }

  if (path === '/api/auth/verify') {
    const token = getTokenFromReq(request);
    if (!token) return corsResponse({ valid: false }, 200, origin);
    const decoded = await verifyJWT(token, jwtSecret);
    if (!decoded) return corsResponse({ valid: false }, 200, origin);
    return corsResponse({ valid: true, user: { id: decoded.id, email: decoded.email, name: decoded.name } }, 200, origin);
  }

  if (path === '/api/auth/me') {
    const token = getTokenFromReq(request);
    if (!token) return corsResponse({ error: 'Not authenticated' }, 401, origin);
    const decoded = await verifyJWT(token, jwtSecret);
    if (!decoded) return corsResponse({ error: 'Not authenticated' }, 401, origin);
    return corsResponse({ user: { id: decoded.id, email: decoded.email, name: decoded.name } }, 200, origin);
  }

  // HTML pages
  function redirectWithToken(base, token) {
    const sep = base.includes('?') ? '&' : '?';
    return base + sep + 'token=' + token;
  }

  function htmlResponse(body) {
    return new Response(body, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...NO_CACHE } });
  }

  if (path === '/login' || path === '/login.html') {
    const token = getTokenFromReq(request);
    if (token) {
      const decoded = await verifyJWT(token, jwtSecret);
      if (decoded) return redirectResponse(redirectWithToken(url.searchParams.get('redirect') || '/', token));
    }
    return htmlResponse(loginPage(url.searchParams.get('redirect') || ''));
  }

  if (path === '/signup' || path === '/signup.html') {
    const token = getTokenFromReq(request);
    if (token) {
      const decoded = await verifyJWT(token, jwtSecret);
      if (decoded) return redirectResponse(redirectWithToken(url.searchParams.get('redirect') || '/', token));
    }
    return htmlResponse(signupPage(url.searchParams.get('redirect') || ''));
  }

  if (path === '/dashboard' || path === '/dashboard.html') {
    const token = getTokenFromReq(request);
    if (!token) return redirectResponse('/login?redirect=' + encodeURIComponent(url.pathname));
    const decoded = await verifyJWT(token, jwtSecret);
    if (!decoded) return redirectResponse('/login?redirect=' + encodeURIComponent(url.pathname));
    return htmlResponse(dashboardPage(decoded, token));
  }

  if (path === '/logout') {
    const res = redirectResponse('/login');
    res.headers.append('Set-Cookie', clearCookie(hostname));
    return res;
  }

  if (path === '/health') {
    return corsResponse({ status: 'ok' }, 200, origin);
  }

  // Static assets: try from landing page assets
  if (env?.ASSETS) {
    try {
      const assetReq = new Request(request);
      const res = await env.ASSETS.fetch(assetReq);
      if (res.status !== 404) return res;
    } catch {}
  }

  return new Response('Not Found', { status: 404 });
}

// ── Main Handler ────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const host = url.hostname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      const origin = allowedOrigin(request);
      return new Response(null, { headers: {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
      }});
    }

    // Same-origin billing proxy → central worker (hides backend host,
    // keeps RAZORPAY_KEY_SECRET server-side). Authenticated via the
    // caller's own Authorization/cookie headers, forwarded untouched.
    const isBilling = BILLING_PREFIXES.some(p => url.pathname === p || url.pathname.startsWith(p));
    if (isBilling && (LANDING_HOSTS.has(host) || host.endsWith('.acronous.com'))) {
      const target = CENTRAL_BILLING + url.pathname + url.search;
      const fwd = new Headers(request.headers);
      fwd.set('Host', 'api.acronous.com');
      try {
        const resp = await fetch(new Request(target, {
          method: request.method,
          headers: fwd,
          body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        }));
        const out = new Headers(resp.headers);
        out.set('Access-Control-Allow-Origin', allowedOrigin(request));
        out.set('Access-Control-Allow-Credentials', 'true');
        return new Response(resp.body, { status: resp.status, headers: out });
      } catch {
        return corsResponse({ error: 'Billing service unreachable. Please try again.' }, 502, allowedOrigin(request));
      }
    }

    // Auth routes — handle on ANY subdomain (before proxying)
    if (url.pathname.startsWith('/api/auth/') || url.pathname === '/login' || url.pathname === '/login.html' || url.pathname === '/signup' || url.pathname === '/signup.html' || url.pathname === '/dashboard' || url.pathname === '/dashboard.html' || url.pathname === '/logout' || url.pathname === '/health') {
      return handleAuthRequest(request, url, env);
    }

    // www → bare domain redirect
    if (host === 'www.acronous.com') {
      url.hostname = 'acronous.com';
      return redirect(url);
    }

    // Subdomain proxy
    const sub = SUBDOMAIN_ORIGINS[host];
    if (sub) {
      const isApi = API_PREFIXES.some(p => url.pathname === p || url.pathname.startsWith(p));
      const targetOrigin = (isApi && sub.api) ? sub.api : sub.spa;
      const targetUrl = targetOrigin + url.pathname + url.search;
      const token = getTokenFromReq(request);
      const headers = new Headers(request.headers);
      if (token) {
        headers.set('X-Acro-Token', token);
      }
      const proxyReq = new Request(targetUrl, {
        method: request.method,
        headers,
        body: request.body,
      });
      try {
        const response = await fetch(proxyReq);
        if (response.status === 404 && !isApi) {
          const indexRes = await fetch(sub.spa + '/index.html');
          return new Response(indexRes.body, {
            status: 200,
            headers: indexRes.headers,
          });
        }
        return new Response(response.body, {
          status: response.status,
          headers: response.headers,
        });
      } catch {
        return new Response('Subdomain proxy error', { status: 502 });
      }
    }

    // Unknown host → redirect to acronous.com
    if (!LANDING_HOSTS.has(host)) {
      url.hostname = 'acronous.com';
      return redirect(url);
    }

    // acronous.com — serve landing page with SPA fallback
    try {
      const response = await env.ASSETS.fetch(request);
      if (response.status === 404) {
        const indexResponse = await env.ASSETS.fetch(
          new Request(new URL('/index.html', request.url), request)
        );
        return new Response(indexResponse.body, {
          status: 200,
          headers: indexResponse.headers,
        });
      }
      return response;
    } catch {
      return new Response('Not Found', { status: 404 });
    }
  },
};

function redirect(url, status = 301) {
  return new Response(null, { status, headers: { Location: url.toString() } });
}
