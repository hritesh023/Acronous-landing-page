const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8080;
const ROOT = __dirname;
const AUTH_PORT = 3001;

// Map subdomains to local file directories
const SITES = {
  'acronous.com':         path.join(ROOT),
  'ai.acronous.com':      path.join(ROOT, '..', 'Acronous Ai', 'build', 'web'),
  'equyvo.acronous.com':  path.join(ROOT, '..', 'Equyvo', 'dist'),
  'navigwiz.acronous.com': path.join(ROOT, '..', 'Navigwiz', 'build', 'web'),
};

// Auth routes that should be proxied to the auth server on ANY hostname
const AUTH_ROUTES = ['/api/auth/', '/login', '/signup', '/dashboard', '/logout', '/health'];
// Billing routes served same-origin (hides the backend host from frontend
// JS). Locally they hit the auth-server fallback; in production _worker.js
// proxies them to the central billing worker (api.acronous.com).
const BILLING_ROUTES = ['/v1/billing/', '/v1/api/', '/api/create-order', '/api/verify-payment', '/api/billing-webhook', '/api/billing-entitlements', '/api/billing-status'];

// Always redirect these hosts to acronous.com
const REDIRECT_HOSTS = new Set([
  'www.acronous.com',
  'acronous.ai.com',
]);

const MIME = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.wasm': 'application/wasm',
};

function serveFile(siteRoot, req, res) {
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';
  let filePath = path.join(siteRoot, urlPath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      filePath = path.join(siteRoot, 'index.html');
    }
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME[ext] || 'application/octet-stream';
    fs.readFile(filePath, (err2, data) => {
      if (err2) {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(data);
    });
  });
}

function proxyToAuth(req, res) {
  const options = {
    hostname: '127.0.0.1',
    port: AUTH_PORT,
    path: req.url,
    method: req.method,
    headers: req.headers,
  };

  const proxyReq = http.request(options, (proxyRes) => {
    // Forward cookies from auth server (needed for cross-subdomain cookie setting)
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', () => {
    res.writeHead(502, { 'Content-Type': 'text/html' });
    res.end('<html><body><h2>Auth server is not running</h2><p>Start it with: <code>node auth-server/server.js</code></p></body></html>');
  });

  req.pipe(proxyReq);
}

http.createServer((req, res) => {
  const host = req.headers.host?.split(':')[0] || 'acronous.com';

  // ── Auth routes — proxy to auth server for ANY hostname ────────────
  // (same behavior as Cloudflare Worker in production)
  const reqPath = req.url.split('?')[0];
  const isAuthRoute = AUTH_ROUTES.some(route =>
    reqPath === route || reqPath.startsWith(route)
  );
  const isBillingRoute = BILLING_ROUTES.some(route =>
    reqPath === route || reqPath.startsWith(route)
  );
  if (isAuthRoute || isBillingRoute) {
    return proxyToAuth(req, res);
  }

  // ── Redirect known aliases to acronous.com ───────────────────────────
  if (REDIRECT_HOSTS.has(host)) {
    const url = new URL(req.url, `http://acronous.com:${PORT}`);
    res.writeHead(301, { Location: url.toString() });
    res.end();
    return;
  }

  // ── Unknown host → redirect to acronous.com ──────────────────────────
  const siteRoot = SITES[host];
  if (!siteRoot) {
    const url = new URL(req.url, `http://acronous.com:${PORT}`);
    res.writeHead(301, { Location: url.toString() });
    res.end();
    return;
  }

  // ── Serve files with SPA fallback ────────────────────────────────────
  serveFile(siteRoot, req, res);
}).listen(PORT, '0.0.0.0', () => {
  console.log(`\n  Acronous Dev Server running on port ${PORT}\n`);
  console.log(`  Routes by hostname:\n`);
  console.log(`  acronous.com         → Landing Page`);
  console.log(`  auth.acronous.com    → Auth Server (proxied to :${AUTH_PORT})`);
  console.log(`  www.acronous.com     → 301 → acronous.com`);
  console.log(`  acronous.ai.com      → 301 → acronous.com`);
  console.log(`  ai.acronous.com      → Acronous AI`);
  console.log(`  equyvo.acronous.com  → Equyvo`);
  console.log(`  navigwiz.acronous.com→ Navigwiz`);
  console.log(`  *                    → 301 → acronous.com`);
  console.log(`\n  To use locally, add to C:\\Windows\\System32\\drivers\\etc\\hosts (as admin):\n`);
  console.log(`  127.0.0.1  acronous.com`);
  console.log(`  127.0.0.1  auth.acronous.com`);
  console.log(`  127.0.0.1  ai.acronous.com`);
  console.log(`  127.0.0.1  www.acronous.com`);
  console.log(`  127.0.0.1  acronous.ai.com`);
  console.log(`  127.0.0.1  equyvo.acronous.com`);
  console.log(`  127.0.0.1  navigwiz.acronous.com`);
  console.log(``);
});
