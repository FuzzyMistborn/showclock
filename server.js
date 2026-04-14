const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const Database = require('better-sqlite3');

const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

// ── Operator secret (set via env var, cryptographically random fallback) ───────
const OPERATOR_SECRET = process.env.OPERATOR_SECRET || (() => {
  const s = crypto.randomBytes(32).toString('hex');
  console.log(`[showclock] No OPERATOR_SECRET set — using random: ${s}`);
  return s;
})();

// ── Password auth (optional — only active if OPERATOR_PASSWORD is set) ────────
const OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || null;
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const sessions = new Map(); // token → { expiresAt, operatorSecret }

// ── Login brute-force protection ──────────────────────────────────────────────
const loginAttempts = new Map(); // ip → { count, firstAttempt }
const LOGIN_WINDOW_MS    = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 10;

function getClientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function isLoginRateLimited(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > LOGIN_WINDOW_MS) { loginAttempts.delete(ip); return false; }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordFailedLogin(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || Date.now() - entry.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
  } else { entry.count++; }
}

function clearLoginAttempts(ip) { loginAttempts.delete(ip); }

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) {
    if (now - entry.firstAttempt > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000);

function generateToken() { return crypto.randomBytes(32).toString('hex'); }
function generateCsrfToken() { return crypto.randomBytes(24).toString('hex'); }

const csrfTokens = new Map(); // token → expiresAt

function isValidSession(token) {
  if (!OPERATOR_PASSWORD) return true;
  if (!token) return false;
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expiresAt) { sessions.delete(token); return false; }
  return true;
}

function getSessionOperatorSecret(token) {
  if (!OPERATOR_PASSWORD) return OPERATOR_SECRET;
  const session = sessions.get(token);
  return session ? session.operatorSecret : null;
}

function getSessionToken(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)sc_session=([^;]+)/);
  return match ? match[1] : null;
}

function requireAuth(req, res, next) {
  if (!OPERATOR_PASSWORD) return next();
  if (isValidSession(getSessionToken(req))) return next();
  res.redirect(`/login?next=${encodeURIComponent(req.path)}`);
}

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) { if (now > session.expiresAt) sessions.delete(token); }
  for (const [token, exp] of csrfTokens) { if (now > exp) csrfTokens.delete(token); }
}, 60 * 60 * 1000);

const wss = new WebSocket.Server({
  server,
  maxPayload: 512 * 1024,
  verifyClient: ({ req }, done) => {
    const origin = req.headers.origin;
    if (!origin) return done(true);
    try {
      const originUrl = new URL(origin);
      const hostHeader = req.headers.host || '';
      if (originUrl.host === hostHeader) return done(true);
      if (originUrl.hostname === hostHeader.split(':')[0]) return done(true);
    } catch (e) {}
    console.warn(`[showclock] Rejected WebSocket from origin: ${origin}`);
    done(false, 403, 'Forbidden');
  },
});

app.use(express.json({ limit: '512kb' }));

// ── Serve client-side libs and fonts from node_modules ────────────────────────
app.get('/lib/marked.min.js', (req, res) => {
  res.type('application/javascript').sendFile(
    path.join(__dirname, 'node_modules/marked/lib/marked.umd.js')
  );
});
app.get('/lib/purify.min.js', (req, res) => {
  res.type('application/javascript').sendFile(
    path.join(__dirname, 'node_modules/dompurify/dist/purify.min.js')
  );
});
app.use('/fonts/jetbrains-mono', express.static(path.join(__dirname, 'node_modules/@fontsource/jetbrains-mono')));
app.use('/fonts/syne', express.static(path.join(__dirname, 'node_modules/@fontsource/syne')));

// ── Security headers ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",
    "connect-src 'self' ws: wss:",
    "img-src 'self' data:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (TRUST_PROXY) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Intercept operator.html before static middleware
app.use((req, res, next) => {
  if (req.path === '/operator.html') return requireAuth(req, res, next);
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false, limit: '4kb' }));

// ── Auth routes ───────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (!OPERATOR_PASSWORD) return res.redirect('/operator.html');
  if (isValidSession(getSessionToken(req))) return res.redirect(req.query.next || '/operator.html');
  const next = req.query.next ? `?next=${encodeURIComponent(req.query.next)}` : '';
  const error = req.query.error ? '<p class="error">Incorrect password. Try again.</p>' : '';
  const rateLimited = req.query.ratelimit ? '<p class="error">Too many attempts. Try again later.</p>' : '';
  const csrf = generateCsrfToken();
  csrfTokens.set(csrf, Date.now() + 10 * 60 * 1000);
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShowClock — Login</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  body{background:#050608;color:#f0f2f8;font-family:'Segoe UI',system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .box{background:#0e1014;border:1px solid #1e2230;border-radius:16px;padding:40px 36px;width:min(380px,90vw);display:flex;flex-direction:column;gap:20px}
  .logo{display:flex;align-items:center;gap:10px;font-size:18px;font-weight:700;letter-spacing:0.04em}
  .logo img{width:32px;height:32px;border-radius:6px}
  h1{font-size:15px;font-weight:600;color:#6b7280}
  label{font-size:12px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#6b7280}
  input[type=password]{width:100%;background:#050608;border:1px solid #1e2230;border-radius:8px;color:#f0f2f8;font-size:15px;padding:10px 14px;outline:none;transition:border-color 0.15s}
  input[type=password]:focus{border-color:#6366f1}
  button{background:#6366f1;border:none;border-radius:8px;color:#fff;cursor:pointer;font-size:15px;font-weight:700;padding:12px;transition:opacity 0.15s;width:100%}
  button:hover{opacity:0.85}
  .error{color:#ef4444;font-size:13px;text-align:center}
</style>
</head>
<body>
<div class="box">
  <div class="logo"><img src="/showclock.png" alt="">ShowClock</div>
  <h1>Operator login</h1>
  ${error}${rateLimited}
  <form method="POST" action="/login${next}">
    <input type="hidden" name="_csrf" value="${csrf}">
    <div style="display:flex;flex-direction:column;gap:8px">
      <label for="pw">Password</label>
      <input type="password" id="pw" name="password" autofocus autocomplete="current-password">
    </div>
    <div style="margin-top:16px"><button type="submit">Sign in</button></div>
  </form>
</div>
</body></html>`);
});

app.post('/login', (req, res) => {
  if (!OPERATOR_PASSWORD) return res.redirect('/operator.html');
  const csrf = String(req.body._csrf || '');
  const csrfValid = csrfTokens.has(csrf) && csrfTokens.get(csrf) > Date.now();
  csrfTokens.delete(csrf);
  if (!csrfValid) {
    const next = req.query.next ? `&next=${encodeURIComponent(req.query.next)}` : '';
    return res.redirect(`/login?error=1${next}`);
  }
  const ip = getClientIp(req);
  if (isLoginRateLimited(ip)) return res.redirect('/login?ratelimit=1');
  const supplied = String(req.body.password || '');
  const a = Buffer.from(supplied.padEnd(64));
  const b = Buffer.from(OPERATOR_PASSWORD.padEnd(64));
  const match = a.length === b.length && crypto.timingSafeEqual(a, b) && supplied === OPERATOR_PASSWORD;
  if (!match) {
    recordFailedLogin(ip);
    const next = req.query.next ? `&next=${encodeURIComponent(req.query.next)}` : '';
    return res.redirect(`/login?error=1${next}`);
  }
  clearLoginAttempts(ip);
  const token = generateToken();
  const sessionOperatorSecret = crypto.randomBytes(16).toString('hex');
  const SESSION_TTL = parseInt(process.env.SESSION_TTL_HOURS || '24') * 60 * 60 * 1000;
  sessions.set(token, { expiresAt: Date.now() + SESSION_TTL, operatorSecret: sessionOperatorSecret });
  const next = req.query.next || '/operator.html';
  const securePart = TRUST_PROXY ? ' Secure;' : '';
  res.setHeader('Set-Cookie', `sc_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000};${securePart}`);
  res.redirect(next);
});

app.get('/logout', (req, res) => {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);
  const securePart = TRUST_PROXY ? ' Secure;' : '';
  res.setHeader('Set-Cookie', `sc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0;${securePart}`);
  res.redirect('/login');
});

// ── Protected operator routes ─────────────────────────────────────────────────
app.get('/operator.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'operator.html'));
});

app.get('/api/operator-token', requireAuth, (req, res) => {
  const sessionToken = getSessionToken(req);
  const secret = getSessionOperatorSecret(sessionToken);
  if (!secret) return res.status(401).json({ error: 'invalid session' });
  res.json({ token: secret });
});

// ── Database ──────────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || '/data/showclock.db';
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS timers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    name       TEXT    NOT NULL DEFAULT 'New Timer',
    duration   INTEGER NOT NULL DEFAULT 300,
    message    TEXT    NOT NULL DEFAULT '',
    yellow_at  INTEGER NOT NULL DEFAULT 60,
    red_at     INTEGER NOT NULL DEFAULT 30,
    flash_at   INTEGER NOT NULL DEFAULT 30,
    flash_rate INTEGER NOT NULL DEFAULT 1000
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS subtimers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id  INTEGER NOT NULL REFERENCES timers(id) ON DELETE CASCADE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    name       TEXT    NOT NULL DEFAULT 'Part',
    duration   INTEGER NOT NULL DEFAULT 60,
    yellow_at  INTEGER NOT NULL DEFAULT 60,
    red_at     INTEGER NOT NULL DEFAULT 30,
    flash_at   INTEGER NOT NULL DEFAULT 30,
    flash_rate INTEGER NOT NULL DEFAULT 1000
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )
`);

// ── Default settings ──────────────────────────────────────────────────────────
const SETTING_DEFAULTS = {
  default_duration:  '300',
  default_yellow_at: '60',
  default_red_at:    '30',
  default_flash_at:  '30',
  default_flash_rate:'1000',
  auto_start:        'false',
  subtimers_expanded:'true',
  presets:           '[]',
};

const stmts = {
  all:            db.prepare('SELECT * FROM timers ORDER BY sort_order ASC, id ASC'),
  insert:         db.prepare('INSERT INTO timers (sort_order, name, duration, message, yellow_at, red_at, flash_at, flash_rate) VALUES (@sort_order, @name, @duration, @message, @yellow_at, @red_at, @flash_at, @flash_rate)'),
  update:         db.prepare('UPDATE timers SET name=@name, duration=@duration, message=@message, yellow_at=@yellow_at, red_at=@red_at, flash_at=@flash_at, flash_rate=@flash_rate WHERE id=@id'),
  updateOrder:    db.prepare('UPDATE timers SET sort_order=@sort_order WHERE id=@id'),
  updateDuration: db.prepare('UPDATE timers SET duration=@duration WHERE id=@id'),
  delete:         db.prepare('DELETE FROM timers WHERE id=?'),
  getSetting:     db.prepare('SELECT value FROM settings WHERE key=?'),
  setSetting:     db.prepare('INSERT INTO settings (key,value) VALUES (@key,@value) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
  allSettings:    db.prepare('SELECT key,value FROM settings'),
  subAll:         db.prepare('SELECT * FROM subtimers WHERE parent_id=@parent_id ORDER BY sort_order ASC, id ASC'),
  subInsert:      db.prepare('INSERT INTO subtimers (parent_id, sort_order, name, duration, yellow_at, red_at, flash_at, flash_rate) VALUES (@parent_id, @sort_order, @name, @duration, @yellow_at, @red_at, @flash_at, @flash_rate)'),
  subUpdate:      db.prepare('UPDATE subtimers SET name=@name, duration=@duration, yellow_at=@yellow_at, red_at=@red_at, flash_at=@flash_at, flash_rate=@flash_rate WHERE id=@id'),
  subUpdateOrder: db.prepare('UPDATE subtimers SET sort_order=@sort_order WHERE id=@id'),
  subDelete:      db.prepare('DELETE FROM subtimers WHERE id=?'),
  subDeleteAll:   db.prepare('DELETE FROM subtimers WHERE parent_id=?'),
  subCount:       db.prepare('SELECT COUNT(*) as n FROM subtimers WHERE parent_id=@parent_id'),
};

function loadSettings() {
  const rows = stmts.allSettings.all();
  const s = { ...SETTING_DEFAULTS };
  rows.forEach(r => { s[r.key] = r.value; });
  return s;
}
function saveSetting(key, value) { stmts.setSetting.run({ key, value: String(value) }); }

// ── DB helpers ────────────────────────────────────────────────────────────────
function dbRowToSubtimer(row) {
  return { id: row.id, parentId: row.parent_id, name: row.name, duration: row.duration, remaining: row.duration, yellowAt: row.yellow_at, redAt: row.red_at, flashAt: row.flash_at, flashRate: row.flash_rate, status: 'idle' };
}
function dbRowToTimer(row) {
  const subtimers = stmts.subAll.all({ parent_id: row.id }).map(dbRowToSubtimer);
  return { id: row.id, name: row.name, duration: row.duration, remaining: row.duration, message: row.message, yellowAt: row.yellow_at, redAt: row.red_at, flashAt: row.flash_at, flashRate: row.flash_rate, status: 'idle', subtimers };
}
function saveTimerOrder() {
  const tx = db.transaction(() => { timers.forEach((t, i) => stmts.updateOrder.run({ sort_order: i, id: t.id })); });
  tx();
}
function saveSubtimerOrder(parentId) {
  const t = timers.find(t => t.id === parentId);
  if (!t) return;
  const tx = db.transaction(() => { t.subtimers.forEach((s, i) => stmts.subUpdateOrder.run({ sort_order: i, id: s.id })); });
  tx();
}
function recalcParentDuration(parentId) {
  const t = timers.find(t => t.id === parentId);
  if (!t) return;
  if (!t.subtimers.length) return;
  const total = t.subtimers.reduce((sum, s) => sum + s.duration, 0);
  t.duration = total;
  if (t.status !== 'running' && t.status !== 'paused') t.remaining = total;
  stmts.updateDuration.run({ duration: total, id: parentId });
}

// ── In-memory state ───────────────────────────────────────────────────────────
let timers = [];
let activeTimerIndex = null;
let activeSubtimerIndex = null;
let timerInterval = null;
let settings = loadSettings();

// ── Hand-raise queue ──────────────────────────────────────────────────────────
const MAX_HAND_QUEUE_SIZE = 50;
let handQueue = [];

// ── WebSocket rate limiting ───────────────────────────────────────────────────
const WS_RATE_LIMIT_WINDOW = 1000;
const WS_RATE_LIMIT_MAX = 20;

// Actions requiring operator privileges
const OPERATOR_ACTIONS = new Set([
  'create', 'update', 'update_notes', 'delete', 'duplicate', 'reorder',
  'create_subtimer', 'update_subtimer', 'delete_subtimer', 'reorder_subtimer',
  'select', 'select_subtimer', 'play', 'pause', 'reset', 'scrub', 'add30',
  'prev', 'next', 'save_settings', 'clear_queue', 'clear_all_timers',
  'save_preset', 'delete_preset',
]);

function loadFromDb() {
  const rows = stmts.all.all();
  if (rows.length === 0) {
    const s = settings;
    const seeds = [
      { name: 'Welcome & Intro', duration: 300,  message: '', yellow_at: +s.default_yellow_at, red_at: +s.default_red_at, flash_at: +s.default_flash_at, flash_rate: +s.default_flash_rate },
      { name: 'Presentation',    duration: 1200, message: '', yellow_at: 120, red_at: 60, flash_at: 60, flash_rate: 1000 },
      { name: 'Q&A Session',     duration: 600,  message: '', yellow_at: +s.default_yellow_at, red_at: +s.default_red_at, flash_at: +s.default_flash_at, flash_rate: +s.default_flash_rate },
    ];
    const tx = db.transaction(() => { seeds.forEach((seed, i) => stmts.insert.run({ sort_order: i, ...seed })); });
    tx();
  }
  timers = stmts.all.all().map(dbRowToTimer);
  console.log(`Loaded ${timers.length} timer(s) from database.`);
}
loadFromDb();

// ── Helpers ───────────────────────────────────────────────────────────────────
function getActiveTimer() { return activeTimerIndex !== null ? timers[activeTimerIndex] : null; }
function getActiveSubtimer() {
  const t = getActiveTimer();
  if (!t || !t.subtimers.length || activeSubtimerIndex === null) return null;
  return t.subtimers[activeSubtimerIndex] || null;
}
function computeParentRemaining(t) {
  if (!t.subtimers.length) return t.remaining;
  return t.subtimers.reduce((sum, s) => sum + s.remaining, 0);
}

// ── Input validation helpers ──────────────────────────────────────────────────
function safeInt(val, fallback, min = 0, max = 86400) {
  const n = Math.floor(Number(val));
  return isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}
function safeName(val, fallback = 'Untitled', maxLen = 200) {
  const s = String(val ?? fallback).trim();
  return s.slice(0, maxLen) || fallback;
}

// ── Timer engine ──────────────────────────────────────────────────────────────
function startInterval() {
  if (timerInterval) return;
  timerInterval = setInterval(() => {
    try {
      const t = getActiveTimer();
      if (!t) return;
      const sub = getActiveSubtimer();
      if (sub) {
        if (sub.status !== 'running') return;
        sub.remaining = Math.max(0, sub.remaining - 1);
        t.remaining = computeParentRemaining(t);
        if (sub.remaining === 0) {
          sub.status = 'finished';
          const nextIdx = activeSubtimerIndex + 1;
          if (nextIdx < t.subtimers.length) { activeSubtimerIndex = nextIdx; t.subtimers[nextIdx].status = 'running'; }
          else { t.status = 'finished'; activeSubtimerIndex = null; stopInterval(); }
        }
      } else {
        if (t.status !== 'running') return;
        t.remaining = Math.max(0, t.remaining - 1);
        if (t.remaining === 0) { t.status = 'finished'; stopInterval(); }
      }
      broadcast({ type: 'tick', timers, activeTimerIndex, activeSubtimerIndex });
    } catch (err) { console.error('Tick error:', err); stopInterval(); }
  }, 1000);
}
function stopInterval() { if (timerInterval) { clearInterval(timerInterval); timerInterval = null; } }
function autoStart() {
  if (settings.auto_start !== 'true') return;
  const t = getActiveTimer();
  if (!t || t.status === 'finished') return;
  if (t.subtimers.length && activeSubtimerIndex !== null) t.subtimers[activeSubtimerIndex].status = 'running';
  else if (!t.subtimers.length) t.status = 'running';
  startInterval();
}
function broadcast(msg) {
  const data = JSON.stringify(msg);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(data); });
}
function broadcastState() { broadcast({ type: 'state', timers, activeTimerIndex, activeSubtimerIndex, settings }); }
function resetTimerState(t) {
  t.status = 'idle'; t.remaining = t.duration;
  t.subtimers.forEach(s => { s.status = 'idle'; s.remaining = s.duration; });
}
function broadcastHandQueue() { broadcast({ type: 'hand_queue', queue: handQueue }); }
function broadcastOperatorCount() {
  let count = 0;
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN && c._isOperator) count++; });
  broadcast({ type: 'operator_count', count });
}

// ── REST endpoints ────────────────────────────────────────────────────────────
app.get('/api/identity', (req, res) => {
  const displayName = req.headers['tailscale-user-name'] || null;
  const email       = req.headers['tailscale-user-login'] || null;
  const name        = displayName || email || null;
  res.json({ name, source: name ? (displayName ? 'tailscale' : 'email') : 'none' });
});

app.get('/api/export', requireAuth, (req, res) => {
  const rows = stmts.all.all();
  const exported = rows.map(row => {
    const subs = stmts.subAll.all({ parent_id: row.id });
    return {
      name: row.name, duration: row.duration, message: row.message,
      yellowAt: row.yellow_at, redAt: row.red_at, flashAt: row.flash_at, flashRate: row.flash_rate,
      subtimers: subs.map(s => ({ name: s.name, duration: s.duration, yellowAt: s.yellow_at, redAt: s.red_at, flashAt: s.flash_at, flashRate: s.flash_rate })),
    };
  });
  const filename = `showclock-export-${new Date().toISOString().slice(0,10)}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.json({ version: 1, exportedAt: new Date().toISOString(), timers: exported });
});

app.post('/api/import', requireAuth, express.json({ limit: '1mb' }), (req, res) => {
  const body = req.body;
  if (!body || !Array.isArray(body.timers)) return res.status(400).json({ error: 'Invalid import format' });
  const s = settings;
  let imported = 0;
  const tx = db.transaction(() => {
    // Wipe all existing timers first
    const existing = stmts.all.all();
    existing.forEach(t => { stmts.subDeleteAll.run(t.id); stmts.delete.run(t.id); });
    body.timers.forEach(t => {
      if (typeof t !== 'object' || !t) return;
      const info = stmts.insert.run({
        sort_order: imported,
        name:       safeName(t.name, 'Imported Timer'),
        duration:   safeInt(t.duration, +s.default_duration, 1, 86400),
        message:    String(t.message ?? '').slice(0, 50000),
        yellow_at:  safeInt(t.yellowAt, +s.default_yellow_at, 0, 86400),
        red_at:     safeInt(t.redAt,    +s.default_red_at,    0, 86400),
        flash_at:   safeInt(t.flashAt,  +s.default_flash_at,  0, 86400),
        flash_rate: safeInt(t.flashRate,+s.default_flash_rate, 100, 10000),
      });
      if (Array.isArray(t.subtimers)) {
        t.subtimers.forEach((sub, i) => {
          if (typeof sub !== 'object' || !sub) return;
          stmts.subInsert.run({
            parent_id: info.lastInsertRowid, sort_order: i,
            name:       safeName(sub.name, 'Part'),
            duration:   safeInt(sub.duration, 60, 1, 86400),
            yellow_at:  safeInt(sub.yellowAt, +s.default_yellow_at, 0, 86400),
            red_at:     safeInt(sub.redAt,    +s.default_red_at,    0, 86400),
            flash_at:   safeInt(sub.flashAt,  +s.default_flash_at,  0, 86400),
            flash_rate: safeInt(sub.flashRate,+s.default_flash_rate, 100, 10000),
          });
        });
      }
      imported++;
    });
  });
  tx();
  stopInterval();
  activeTimerIndex = null;
  activeSubtimerIndex = null;
  timers = stmts.all.all().map(row => dbRowToTimer(row));
  broadcastState();
  res.json({ imported });
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', ws => {
  ws._rateCount = 0;
  ws._rateWindowStart = Date.now();

  ws.send(JSON.stringify({ type: 'state', timers, activeTimerIndex, activeSubtimerIndex }));
  ws.send(JSON.stringify({ type: 'hand_queue', queue: handQueue }));

  ws.on('message', raw => {
    const now = Date.now();
    if (now - ws._rateWindowStart > WS_RATE_LIMIT_WINDOW) { ws._rateCount = 0; ws._rateWindowStart = now; }
    ws._rateCount++;
    if (ws._rateCount > WS_RATE_LIMIT_MAX) return;

    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    try {

    if (OPERATOR_ACTIONS.has(msg.action) && !ws._isOperator) return;

    switch (msg.action) {

      case 'create': {
        const s = settings; const o = msg.timer || {};
        stmts.insert.run({
          sort_order: timers.length,
          name:       safeName(o.name, 'New Timer'),
          duration:   safeInt(o.duration,  +s.default_duration,  1, 86400),
          message:    String(o.message ?? '').slice(0, 50000),
          yellow_at:  safeInt(o.yellowAt,  +s.default_yellow_at, 0, 86400),
          red_at:     safeInt(o.redAt,     +s.default_red_at,    0, 86400),
          flash_at:   safeInt(o.flashAt,   +s.default_flash_at,  0, 86400),
          flash_rate: safeInt(o.flashRate, +s.default_flash_rate, 100, 10000),
        });
        timers = stmts.all.all().map(row => { const ex = timers.find(t => t.id === row.id); return ex || dbRowToTimer(row); });
        broadcastState(); break;
      }

      case 'update_notes': {
        const idx = timers.findIndex(t => t.id === msg.id); if (idx === -1) break;
        timers[idx].message = String(msg.message ?? '').slice(0, 50000);
        stmts.update.run({ id: timers[idx].id, name: timers[idx].name, duration: timers[idx].duration, message: timers[idx].message, yellow_at: timers[idx].yellowAt, red_at: timers[idx].redAt, flash_at: timers[idx].flashAt, flash_rate: timers[idx].flashRate });
        broadcastState(); break;
      }

      case 'update': {
        const idx = timers.findIndex(t => t.id === msg.id); if (idx === -1) break;
        const timer = timers[idx];
        const wasRunning = idx === activeTimerIndex && timer.status === 'running';
        const wasPartiallyRun = timer.remaining < timer.duration;
        const oldDuration = timer.duration;
        const o = msg.timer;
        const hasSubs = timer.subtimers.length > 0;
        const newDuration  = hasSubs ? timer.duration : safeInt(o.duration, timer.duration, 1, 86400);
        const newName      = safeName(o.name, timer.name);
        const newMessage   = String(o.message ?? timer.message).slice(0, 50000);
        const newYellow    = safeInt(o.yellowAt,  timer.yellowAt,  0, 86400);
        const newRed       = safeInt(o.redAt,     timer.redAt,     0, 86400);
        const newFlashAt   = safeInt(o.flashAt,   timer.flashAt,   0, 86400);
        const newFlashRate = safeInt(o.flashRate, timer.flashRate, 100, 10000);
        stmts.update.run({ id: msg.id, name: newName, duration: newDuration, message: newMessage, yellow_at: newYellow, red_at: newRed, flash_at: newFlashAt, flash_rate: newFlashRate });
        const durationChanged = newDuration !== oldDuration;
        Object.assign(timer, { name: newName, duration: newDuration, message: newMessage, yellowAt: newYellow, redAt: newRed, flashAt: newFlashAt, flashRate: newFlashRate });
        if (!wasRunning && !wasPartiallyRun) timer.remaining = timer.duration;
        else if (!wasRunning && durationChanged) timer.remaining = timer.duration;
        broadcastState(); break;
      }

      case 'duplicate': {
        const src = timers.find(t => t.id === msg.id); if (!src) break;
        const info = stmts.insert.run({
          sort_order: timers.length,
          name:       safeName(src.name + ' (copy)', 'Timer'),
          duration:   src.duration, message: src.message,
          yellow_at:  src.yellowAt, red_at: src.redAt, flash_at: src.flashAt, flash_rate: src.flashRate,
        });
        if (src.subtimers.length > 0) {
          src.subtimers.forEach((s, i) => stmts.subInsert.run({
            parent_id: info.lastInsertRowid, sort_order: i,
            name: s.name, duration: s.duration, yellow_at: s.yellowAt, red_at: s.redAt, flash_at: s.flashAt, flash_rate: s.flashRate,
          }));
        }
        timers = stmts.all.all().map(row => { const ex = timers.find(t => t.id === row.id); return ex || dbRowToTimer(row); });
        broadcastState(); break;
      }

      case 'delete': {
        const idx = timers.findIndex(t => t.id === msg.id); if (idx === -1) break;
        stmts.subDeleteAll.run(msg.id); stmts.delete.run(msg.id);
        if (idx === activeTimerIndex) { stopInterval(); activeTimerIndex = null; activeSubtimerIndex = null; }
        else if (activeTimerIndex !== null && idx < activeTimerIndex) activeTimerIndex--;
        timers.splice(idx, 1); saveTimerOrder(); broadcastState(); break;
      }

      case 'clear_all_timers': {
        stopInterval(); activeTimerIndex = null; activeSubtimerIndex = null;
        const tx = db.transaction(() => { timers.forEach(t => { stmts.subDeleteAll.run(t.id); stmts.delete.run(t.id); }); });
        tx(); timers = []; broadcastState(); break;
      }

      case 'reorder': {
        const { from, to } = msg;
        if (from < 0 || to < 0 || from >= timers.length || to >= timers.length || from === to) break;
        const [moved] = timers.splice(from, 1); timers.splice(to, 0, moved);
        if (activeTimerIndex !== null) {
          if (activeTimerIndex === from) activeTimerIndex = to;
          else if (from < activeTimerIndex && to >= activeTimerIndex) activeTimerIndex--;
          else if (from > activeTimerIndex && to <= activeTimerIndex) activeTimerIndex++;
        }
        saveTimerOrder(); broadcastState(); break;
      }

      case 'create_subtimer': {
        const t = timers.find(t => t.id === msg.parentId); if (!t) break;
        const s = settings;
        stmts.subInsert.run({
          parent_id: msg.parentId, sort_order: t.subtimers.length,
          name:       safeName(msg.subtimer?.name, 'Part'),
          duration:   safeInt(msg.subtimer?.duration,  60,                  1, 86400),
          yellow_at:  safeInt(msg.subtimer?.yellowAt,  +s.default_yellow_at, 0, 86400),
          red_at:     safeInt(msg.subtimer?.redAt,     +s.default_red_at,    0, 86400),
          flash_at:   safeInt(msg.subtimer?.flashAt,   +s.default_flash_at,  0, 86400),
          flash_rate: safeInt(msg.subtimer?.flashRate, +s.default_flash_rate, 100, 10000),
        });
        const existingSubs = t.subtimers;
        t.subtimers = stmts.subAll.all({ parent_id: msg.parentId }).map(row => { const ex = existingSubs.find(s => s.id === row.id); return ex || dbRowToSubtimer(row); });
        recalcParentDuration(msg.parentId); broadcastState(); break;
      }

      case 'update_subtimer': {
        const t = timers.find(t => t.id === msg.parentId); if (!t) break;
        const sIdx = t.subtimers.findIndex(s => s.id === msg.id); if (sIdx === -1) break;
        const o = msg.subtimer;
        const subName      = safeName(o.name, t.subtimers[sIdx].name);
        const subDuration  = safeInt(o.duration,  t.subtimers[sIdx].duration,  1, 86400);
        const subYellow    = safeInt(o.yellowAt,  t.subtimers[sIdx].yellowAt,  0, 86400);
        const subRed       = safeInt(o.redAt,     t.subtimers[sIdx].redAt,     0, 86400);
        const subFlashAt   = safeInt(o.flashAt,   t.subtimers[sIdx].flashAt,   0, 86400);
        const subFlashRate = safeInt(o.flashRate, t.subtimers[sIdx].flashRate, 100, 10000);
        stmts.subUpdate.run({ id: msg.id, name: subName, duration: subDuration, yellow_at: subYellow, red_at: subRed, flash_at: subFlashAt, flash_rate: subFlashRate });
        Object.assign(t.subtimers[sIdx], { name: subName, duration: subDuration, yellowAt: subYellow, redAt: subRed, flashAt: subFlashAt, flashRate: subFlashRate });
        const isActiveSub = activeTimerIndex !== null && timers[activeTimerIndex].id === msg.parentId && activeSubtimerIndex === sIdx;
        if (!isActiveSub) t.subtimers[sIdx].remaining = t.subtimers[sIdx].duration;
        recalcParentDuration(msg.parentId); broadcastState(); break;
      }

      case 'delete_subtimer': {
        const t = timers.find(t => t.id === msg.parentId); if (!t) break;
        const sIdx = t.subtimers.findIndex(s => s.id === msg.id); if (sIdx === -1) break;
        stmts.subDelete.run(msg.id); t.subtimers.splice(sIdx, 1);
        if (activeTimerIndex !== null && timers[activeTimerIndex].id === msg.parentId) {
          if (t.subtimers.length === 0) { stopInterval(); activeSubtimerIndex = null; t.status = 'idle'; }
          else if (activeSubtimerIndex === sIdx) { stopInterval(); activeSubtimerIndex = 0; t.subtimers[0].status = 'idle'; t.status = 'idle'; }
          else if (activeSubtimerIndex !== null && activeSubtimerIndex > sIdx) activeSubtimerIndex--;
        }
        saveSubtimerOrder(msg.parentId); recalcParentDuration(msg.parentId); broadcastState(); break;
      }

      case 'reorder_subtimer': {
        const t = timers.find(t => t.id === msg.parentId); if (!t) break;
        const { from, to } = msg;
        if (from < 0 || to < 0 || from >= t.subtimers.length || to >= t.subtimers.length || from === to) break;
        const [moved] = t.subtimers.splice(from, 1); t.subtimers.splice(to, 0, moved);
        if (activeTimerIndex !== null && timers[activeTimerIndex].id === msg.parentId) {
          if (activeSubtimerIndex === from) activeSubtimerIndex = to;
          else if (from < activeSubtimerIndex && to >= activeSubtimerIndex) activeSubtimerIndex--;
          else if (from > activeSubtimerIndex && to <= activeSubtimerIndex) activeSubtimerIndex++;
        }
        saveSubtimerOrder(msg.parentId); broadcastState(); break;
      }

      case 'select': {
        const idx = timers.findIndex(t => t.id === msg.id); if (idx === -1) break;
        if (activeTimerIndex === idx) {
          stopInterval();
          const t = timers[idx];
          if (t.status === 'running') t.status = 'idle';
          t.subtimers.forEach(s => { if (s.status === 'running') s.status = 'idle'; });
          activeTimerIndex = null; activeSubtimerIndex = null; broadcastState(); break;
        }
        stopInterval();
        if (activeTimerIndex !== null && timers[activeTimerIndex]) {
          const prev = timers[activeTimerIndex];
          if (prev.status === 'running') prev.status = 'idle';
          prev.subtimers.forEach(s => { if (s.status === 'running') s.status = 'idle'; });
        }
        activeTimerIndex = idx;
        const newT = timers[idx];
        if (newT.subtimers.length > 0) {
          const firstUnfinished = newT.subtimers.findIndex(s => s.status !== 'finished');
          activeSubtimerIndex = firstUnfinished !== -1 ? firstUnfinished : newT.subtimers.length - 1;
        } else { activeSubtimerIndex = null; }
        if (newT.status !== 'finished') newT.status = 'idle';
        autoStart(); broadcastState(); break;
      }

      case 'select_subtimer': {
        const t = timers.find(t => t.id === msg.parentId); if (!t) break;
        const idx = timers.indexOf(t);
        const sIdx = t.subtimers.findIndex(s => s.id === msg.id); if (sIdx === -1) break;
        const wasRunning = activeTimerIndex === idx && activeSubtimerIndex !== null && t.subtimers[activeSubtimerIndex]?.status === 'running';
        if (wasRunning) t.subtimers[activeSubtimerIndex].status = 'idle';
        if (activeTimerIndex !== idx) { stopInterval(); if (activeTimerIndex !== null && timers[activeTimerIndex]) resetTimerState(timers[activeTimerIndex]); activeTimerIndex = idx; }
        activeSubtimerIndex = sIdx;
        t.status = wasRunning ? 'running' : 'idle';
        if (wasRunning) { t.subtimers[sIdx].status = 'running'; startInterval(); } else { t.subtimers[sIdx].status = 'idle'; }
        t.remaining = computeParentRemaining(t); broadcastState(); break;
      }

      case 'play': {
        const t = getActiveTimer(); if (!t) break;
        const sub = getActiveSubtimer();
        if (sub) { if (sub.status === 'finished') break; sub.status = 'running'; t.status = 'running'; }
        else { if (t.status === 'finished') break; t.status = 'running'; }
        startInterval(); broadcastState(); break;
      }

      case 'pause': {
        const t = getActiveTimer(); if (!t) break;
        const sub = getActiveSubtimer();
        if (sub) sub.status = 'paused';
        t.status = 'paused'; stopInterval(); broadcastState(); break;
      }

      case 'reset': {
        const t = getActiveTimer(); if (!t) break;
        stopInterval(); resetTimerState(t);
        activeSubtimerIndex = t.subtimers.length > 0 ? 0 : null;
        broadcastState(); break;
      }

      case 'scrub': {
        const t = getActiveTimer(); if (!t) break;
        const sub = getActiveSubtimer(); const target = sub || t;
        target.remaining = Math.max(0, Math.min(target.duration, Math.round(msg.remaining)));
        if (sub) {
          t.remaining = computeParentRemaining(t);
          if (target.remaining === 0) { target.status = 'finished'; stopInterval(); }
          else if (target.status === 'finished') target.status = 'idle';
        } else {
          if (target.remaining === 0) { target.status = 'finished'; stopInterval(); }
          else if (target.status === 'finished') target.status = 'idle';
        }
        broadcast({ type: 'tick', timers, activeTimerIndex, activeSubtimerIndex }); break;
      }

      case 'add30': {
        const t = getActiveTimer(); if (!t) break;
        const sub = getActiveSubtimer(); const target = sub || t;
        target.remaining += 30;
        if (sub) t.remaining = computeParentRemaining(t);
        if (target.status === 'finished') { target.status = 'idle'; if (sub) t.status = 'idle'; }
        broadcast({ type: 'tick', timers, activeTimerIndex, activeSubtimerIndex }); break;
      }

      case 'prev': {
        stopInterval(); const t = getActiveTimer();
        if (t && activeSubtimerIndex !== null && activeSubtimerIndex > 0) {
          t.subtimers[activeSubtimerIndex].status = 'idle'; activeSubtimerIndex--;
          t.subtimers[activeSubtimerIndex].status = 'idle';
          t.subtimers[activeSubtimerIndex].remaining = t.subtimers[activeSubtimerIndex].duration;
          t.remaining = computeParentRemaining(t); t.status = 'idle';
        } else {
          if (t) resetTimerState(t);
          if (activeTimerIndex === null) activeTimerIndex = 0;
          else activeTimerIndex = Math.max(0, activeTimerIndex - 1);
          const newT = timers[activeTimerIndex]; resetTimerState(newT);
          activeSubtimerIndex = newT.subtimers.length > 0 ? 0 : null;
        }
        autoStart(); broadcastState(); break;
      }

      case 'next': {
        stopInterval(); const t = getActiveTimer();
        if (t && activeSubtimerIndex !== null && activeSubtimerIndex < t.subtimers.length - 1) {
          t.subtimers[activeSubtimerIndex].status = 'idle'; activeSubtimerIndex++;
          t.subtimers[activeSubtimerIndex].status = 'idle';
          t.subtimers[activeSubtimerIndex].remaining = t.subtimers[activeSubtimerIndex].duration;
          t.remaining = computeParentRemaining(t); t.status = 'idle';
        } else {
          if (t) resetTimerState(t);
          if (activeTimerIndex === null) activeTimerIndex = 0;
          else activeTimerIndex = Math.min(timers.length - 1, activeTimerIndex + 1);
          const newT = timers[activeTimerIndex]; resetTimerState(newT);
          activeSubtimerIndex = newT.subtimers.length > 0 ? 0 : null;
        }
        autoStart(); broadcastState(); break;
      }

      case 'save_settings': {
        const allowed = ['default_duration','default_yellow_at','default_red_at','default_flash_at','default_flash_rate','auto_start','subtimers_expanded'];
        const tx = db.transaction(() => {
          allowed.forEach(k => {
            if (msg.settings[k] === undefined) return;
            let v = msg.settings[k];
            if (k === 'auto_start' || k === 'subtimers_expanded') v = (v === 'true' || v === true) ? 'true' : 'false';
            else { const min = k === 'default_flash_rate' ? 100 : 0; const max = k === 'default_flash_rate' ? 10000 : 86400; v = String(safeInt(v, +SETTING_DEFAULTS[k], min, max)); }
            saveSetting(k, v);
          });
        });
        tx(); settings = loadSettings(); broadcastState(); break;
      }

      case 'save_preset': {
        const presetName = safeName(msg.name, '', 100); if (!presetName) break;
        const existing = JSON.parse(stmts.getSetting.get('presets')?.value || '[]');
        const filtered = existing.filter(p => p.name !== presetName);
        filtered.push({ name: presetName, duration: safeInt(msg.duration, 300, 1, 86400), yellowAt: safeInt(msg.yellowAt, 60, 0, 86400), redAt: safeInt(msg.redAt, 30, 0, 86400), flashAt: safeInt(msg.flashAt, 30, 0, 86400), flashRate: safeInt(msg.flashRate, 1000, 100, 10000) });
        saveSetting('presets', JSON.stringify(filtered));
        settings = loadSettings(); broadcastState(); break;
      }

      case 'delete_preset': {
        const presetName = safeName(msg.name, '', 100); if (!presetName) break;
        const existing = JSON.parse(stmts.getSetting.get('presets')?.value || '[]');
        saveSetting('presets', JSON.stringify(existing.filter(p => p.name !== presetName)));
        settings = loadSettings(); broadcastState(); break;
      }

      case 'raise_hand': {
        const name = String(msg.name || '').trim().slice(0, 100); if (!name) break;
        if (handQueue.find(e => e.name.toLowerCase() === name.toLowerCase())) break;
        if (handQueue.length >= MAX_HAND_QUEUE_SIZE) break;
        handQueue.push({ name, raisedAt: Date.now() });
        ws._handRaiseName = name; broadcastHandQueue(); break;
      }

      case 'lower_hand': {
        const name = String(msg.name || '').trim().slice(0, 100); if (!name) break;
        const ownHand = ws._handRaiseName && ws._handRaiseName.toLowerCase() === name.toLowerCase();
        const isOperator = ws._isOperator === true;
        if (!ownHand && !isOperator) break;
        const prevLen = handQueue.length;
        handQueue = handQueue.filter(e => e.name.toLowerCase() !== name.toLowerCase());
        if (ownHand) ws._handRaiseName = null;
        if (handQueue.length !== prevLen) broadcastHandQueue(); break;
      }

      case 'clear_queue': {
        if (!ws._isOperator) break;
        handQueue = []; broadcastHandQueue(); break;
      }

      case 'identify_operator': {
        if (msg.secret === OPERATOR_SECRET) {
          ws._isOperator = true;
        } else if (msg.secret) {
          for (const [, session] of sessions) {
            if (session.operatorSecret && session.operatorSecret === msg.secret && Date.now() <= session.expiresAt) {
              ws._isOperator = true; break;
            }
          }
        }
        ws.send(JSON.stringify({ type: 'auth_result', ok: !!ws._isOperator }));
        if (ws._isOperator) {
          ws.send(JSON.stringify({ type: 'state', timers, activeTimerIndex, activeSubtimerIndex, settings }));
          broadcastOperatorCount();
        }
        break;
      }

    } // end switch
    } catch (err) { console.error('WS message handler error:', err); }
  });

  ws.on('close', () => { if (ws._isOperator) broadcastOperatorCount(); });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`ShowClock running at http://localhost:${PORT}`);
  console.log(`  Operator: http://localhost:${PORT}/operator.html`);
  console.log(`  Display:  http://localhost:${PORT}/display.html`);
  console.log(`  Database: ${DB_PATH}`);
});