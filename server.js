const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const Database = require('better-sqlite3');

const crypto = require('crypto');

const app = express();
const server = http.createServer(app);

// ── Operator secret (set via env var, random fallback) ────────────────────────
const OPERATOR_SECRET = process.env.OPERATOR_SECRET || (() => {
  const s = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  console.log(`[showclock] No OPERATOR_SECRET set — using random: ${s}`);
  return s;
})();

// ── Password auth (optional — only active if OPERATOR_PASSWORD is set) ────────
const OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || null;
const sessions = new Map(); // token → expiresAt

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function isValidSession(token) {
  if (!OPERATOR_PASSWORD) return true; // auth disabled
  if (!token) return false;
  const exp = sessions.get(token);
  if (!exp) return false;
  if (Date.now() > exp) { sessions.delete(token); return false; }
  return true;
}

function getSessionToken(req) {
  // Check cookie
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)sc_session=([^;]+)/);
  return match ? match[1] : null;
}

function requireAuth(req, res, next) {
  if (!OPERATOR_PASSWORD) return next();
  if (isValidSession(getSessionToken(req))) return next();
  // Redirect to login, preserving the intended destination
  res.redirect(`/login?next=${encodeURIComponent(req.path)}`);
}

// Periodically clean up expired sessions
setInterval(() => {
  const now = Date.now();
  for (const [token, exp] of sessions) {
    if (now > exp) sessions.delete(token);
  }
}, 60 * 60 * 1000); // every hour

const wss = new WebSocket.Server({
  server,
  maxPayload: 512 * 1024, // 512KB max WS message size
});

app.use(express.json({ limit: '512kb' }));

// ── Serve client-side libs and fonts from node_modules ────────────────────────
// Registered before auth/security middleware so they're always accessible

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

app.use('/fonts/jetbrains-mono', express.static(
  path.join(__dirname, 'node_modules/@fontsource/jetbrains-mono')
));
app.use('/fonts/syne', express.static(
  path.join(__dirname, 'node_modules/@fontsource/syne')
));

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
  next();
});

// Intercept operator.html before static middleware can serve it
app.use((req, res, next) => {
  if (req.path === '/operator.html') {
    return requireAuth(req, res, next);
  }
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
  ${error}
  <form method="POST" action="/login${next}">
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
  const supplied = String(req.body.password || '');
  // Constant-time comparison to prevent timing attacks
  const a = Buffer.from(supplied.padEnd(64));
  const b = Buffer.from(OPERATOR_PASSWORD.padEnd(64));
  const match = a.length === b.length && crypto.timingSafeEqual(a, b) && supplied === OPERATOR_PASSWORD;
  if (!match) {
    const next = req.query.next ? `&next=${encodeURIComponent(req.query.next)}` : '';
    return res.redirect(`/login?error=1${next}`);
  }
  const token = generateToken();
  const SESSION_TTL = parseInt(process.env.SESSION_TTL_HOURS || '24') * 60 * 60 * 1000;
  sessions.set(token, Date.now() + SESSION_TTL);
  const next = req.query.next || '/operator.html';
  res.setHeader('Set-Cookie', `sc_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL / 1000}`);
  res.redirect(next);
});

app.get('/logout', (req, res) => {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', 'sc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.redirect('/login');
});

// ── Protected operator routes ─────────────────────────────────────────────────
app.get('/operator.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'operator.html'));
});

app.get('/api/operator-token', requireAuth, (req, res) => {
  res.json({ token: OPERATOR_SECRET });
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
};

const stmts = {
  all:              db.prepare('SELECT * FROM timers ORDER BY sort_order ASC, id ASC'),
  insert:           db.prepare('INSERT INTO timers (sort_order, name, duration, message, yellow_at, red_at, flash_at, flash_rate) VALUES (@sort_order, @name, @duration, @message, @yellow_at, @red_at, @flash_at, @flash_rate)'),
  update:           db.prepare('UPDATE timers SET name=@name, duration=@duration, message=@message, yellow_at=@yellow_at, red_at=@red_at, flash_at=@flash_at, flash_rate=@flash_rate WHERE id=@id'),
  updateOrder:      db.prepare('UPDATE timers SET sort_order=@sort_order WHERE id=@id'),
  updateDuration:   db.prepare('UPDATE timers SET duration=@duration WHERE id=@id'),
  delete:           db.prepare('DELETE FROM timers WHERE id=?'),
  getSetting:       db.prepare('SELECT value FROM settings WHERE key=?'),
  setSetting:       db.prepare('INSERT INTO settings (key,value) VALUES (@key,@value) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
  allSettings:      db.prepare('SELECT key,value FROM settings'),
  subAll:           db.prepare('SELECT * FROM subtimers WHERE parent_id=@parent_id ORDER BY sort_order ASC, id ASC'),
  subInsert:        db.prepare('INSERT INTO subtimers (parent_id, sort_order, name, duration, yellow_at, red_at, flash_at, flash_rate) VALUES (@parent_id, @sort_order, @name, @duration, @yellow_at, @red_at, @flash_at, @flash_rate)'),
  subUpdate:        db.prepare('UPDATE subtimers SET name=@name, duration=@duration, yellow_at=@yellow_at, red_at=@red_at, flash_at=@flash_at, flash_rate=@flash_rate WHERE id=@id'),
  subUpdateOrder:   db.prepare('UPDATE subtimers SET sort_order=@sort_order WHERE id=@id'),
  subDelete:        db.prepare('DELETE FROM subtimers WHERE id=?'),
  subDeleteAll:     db.prepare('DELETE FROM subtimers WHERE parent_id=?'),
  subCount:         db.prepare('SELECT COUNT(*) as n FROM subtimers WHERE parent_id=@parent_id'),
};

function loadSettings() {
  const rows = stmts.allSettings.all();
  const s = { ...SETTING_DEFAULTS };
  rows.forEach(r => { s[r.key] = r.value; });
  return s;
}

function saveSetting(key, value) {
  stmts.setSetting.run({ key, value: String(value) });
}

// ── DB helpers ────────────────────────────────────────────────────────────────
function dbRowToSubtimer(row) {
  return {
    id:        row.id,
    parentId:  row.parent_id,
    name:      row.name,
    duration:  row.duration,
    remaining: row.duration,
    yellowAt:  row.yellow_at,
    redAt:     row.red_at,
    flashAt:   row.flash_at,
    flashRate: row.flash_rate,
    status:    'idle',
  };
}

function dbRowToTimer(row) {
  const subtimers = stmts.subAll.all({ parent_id: row.id }).map(dbRowToSubtimer);
  return {
    id:        row.id,
    name:      row.name,
    duration:  row.duration,
    remaining: row.duration,
    message:   row.message,
    yellowAt:  row.yellow_at,
    redAt:     row.red_at,
    flashAt:   row.flash_at,
    flashRate: row.flash_rate,
    status:    'idle',
    subtimers,
  };
}

function saveTimerOrder() {
  const tx = db.transaction(() => {
    timers.forEach((t, i) => stmts.updateOrder.run({ sort_order: i, id: t.id }));
  });
  tx();
}

function saveSubtimerOrder(parentId) {
  const t = timers.find(t => t.id === parentId);
  if (!t) return;
  const tx = db.transaction(() => {
    t.subtimers.forEach((s, i) => stmts.subUpdateOrder.run({ sort_order: i, id: s.id }));
  });
  tx();
}

function recalcParentDuration(parentId) {
  const t = timers.find(t => t.id === parentId);
  if (!t) return;
  if (!t.subtimers.length) {
    // No subtimers — restore duration to whatever is in the DB
    const row = stmts.all.all().find(r => r.id === parentId);
    // Just leave duration as-is; user will edit it manually
    return;
  }
  const total = t.subtimers.reduce((sum, s) => sum + s.duration, 0);
  t.duration = total;
  if (t.status !== 'running' && t.status !== 'paused') t.remaining = total;
  stmts.updateDuration.run({ duration: total, id: parentId });
}

// ── In-memory state ───────────────────────────────────────────────────────────
let timers = [];
let activeTimerIndex = null;
let activeSubtimerIndex = null; // index within active timer's subtimers array
let timerInterval = null;
let settings = loadSettings();

function loadFromDb() {
  const rows = stmts.all.all();
  if (rows.length === 0) {
    const s = settings;
    const seeds = [
      { name: 'Welcome & Intro', duration: 300,  message: '', yellow_at: +s.default_yellow_at, red_at: +s.default_red_at, flash_at: +s.default_flash_at, flash_rate: +s.default_flash_rate },
      { name: 'Presentation',    duration: 1200, message: '', yellow_at: 120, red_at: 60, flash_at: 60, flash_rate: 1000 },
      { name: 'Q&A Session',     duration: 600,  message: '', yellow_at: +s.default_yellow_at, red_at: +s.default_red_at, flash_at: +s.default_flash_at, flash_rate: +s.default_flash_rate },
    ];
    const tx = db.transaction(() => {
      seeds.forEach((seed, i) => stmts.insert.run({ sort_order: i, ...seed }));
    });
    tx();
  }
  timers = stmts.all.all().map(dbRowToTimer);
  console.log(`Loaded ${timers.length} timer(s) from database.`);
}

loadFromDb();

// ── Helpers ───────────────────────────────────────────────────────────────────
function getActiveTimer() {
  return activeTimerIndex !== null ? timers[activeTimerIndex] : null;
}

function getActiveSubtimer() {
  const t = getActiveTimer();
  if (!t || !t.subtimers.length || activeSubtimerIndex === null) return null;
  return t.subtimers[activeSubtimerIndex] || null;
}

function getActiveTick() {
  // Returns whichever entity is currently counting down
  return getActiveSubtimer() || getActiveTimer();
}

// Compute overall parent remaining as sum of subtimer remainings
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
          if (nextIdx < t.subtimers.length) {
            activeSubtimerIndex = nextIdx;
            t.subtimers[nextIdx].status = 'running';
          } else {
            t.status = 'finished';
            activeSubtimerIndex = null;
            stopInterval();
          }
        }
      } else {
        if (t.status !== 'running') return;
        t.remaining = Math.max(0, t.remaining - 1);
        if (t.remaining === 0) {
          t.status = 'finished';
          stopInterval();
        }
      }

      broadcast({ type: 'tick', timers, activeTimerIndex, activeSubtimerIndex });
    } catch (err) {
      console.error('Tick error:', err);
      stopInterval();
    }
  }, 1000);
}

function stopInterval() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
}

function autoStart() {
  if (settings.auto_start !== 'true') return;
  const t = getActiveTimer();
  if (!t || t.status === 'finished') return;
  if (t.subtimers.length && activeSubtimerIndex !== null) {
    t.subtimers[activeSubtimerIndex].status = 'running';
  } else if (!t.subtimers.length) {
    t.status = 'running';
  }
  startInterval();
}

function broadcast(msg) {
  const data = JSON.stringify(msg);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(data); });
}

function broadcastState() {
  broadcast({ type: 'state', timers, activeTimerIndex, activeSubtimerIndex, settings });
}

function resetTimerState(t) {
  t.status = 'idle';
  t.remaining = t.duration;
  t.subtimers.forEach(s => { s.status = 'idle'; s.remaining = s.duration; });
}

// ── Hand-raise queue ──────────────────────────────────────────────────────────
let handQueue = []; // [{ name, raisedAt }]

function broadcastHandQueue() {
  broadcast({ type: 'hand_queue', queue: handQueue });
}

// REST endpoint for Tailscale identity check
app.get('/api/identity', (req, res) => {
  const displayName = req.headers['tailscale-user-name'] || null;
  const email       = req.headers['tailscale-user-login'] || null;
  const name        = displayName || email || null;
  res.json({ name, source: name ? (displayName ? 'tailscale' : 'email') : 'none' });
});

// REST endpoint — operator page fetches this to get the shared secret
app.get('/api/operator-token', (req, res) => {
  res.json({ token: OPERATOR_SECRET });
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', ws => {
  ws.send(JSON.stringify({ type: 'state', timers, activeTimerIndex, activeSubtimerIndex, settings }));
  ws.send(JSON.stringify({ type: 'hand_queue', queue: handQueue }));

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    try {

    switch (msg.action) {

      // ── Timer CRUD ──────────────────────────────────────────────────────────
      case 'create': {
        const s = settings;
        const o = msg.timer || {};
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
        timers = stmts.all.all().map((row) => {
          const existing = timers.find(t => t.id === row.id);
          return existing || dbRowToTimer(row);
        });
        broadcastState();
        break;
      }

      case 'update_notes': {
        const idx = timers.findIndex(t => t.id === msg.id);
        if (idx === -1) break;
        timers[idx].message = String(msg.message ?? '').slice(0, 50000);
        stmts.update.run({ id: timers[idx].id, name: timers[idx].name, duration: timers[idx].duration, message: timers[idx].message, yellow_at: timers[idx].yellowAt, red_at: timers[idx].redAt, flash_at: timers[idx].flashAt, flash_rate: timers[idx].flashRate });
        broadcastState();
        break;
      }

      case 'update': {
        const idx = timers.findIndex(t => t.id === msg.id);
        if (idx === -1) break;
        const wasRunning = idx === activeTimerIndex && timers[idx].status === 'running';
        const wasPartiallyRun = timers[idx].remaining < timers[idx].duration;
        const o = msg.timer;
        const hasSubs = timers[idx].subtimers.length > 0;
        const newDuration = hasSubs ? timers[idx].duration : safeInt(o.duration, timers[idx].duration, 1, 86400);
        const newName     = safeName(o.name, timers[idx].name);
        const newMessage  = String(o.message ?? timers[idx].message).slice(0, 50000);
        const newYellow   = safeInt(o.yellowAt,  timers[idx].yellowAt,  0, 86400);
        const newRed      = safeInt(o.redAt,     timers[idx].redAt,     0, 86400);
        const newFlashAt  = safeInt(o.flashAt,   timers[idx].flashAt,   0, 86400);
        const newFlashRate= safeInt(o.flashRate, timers[idx].flashRate, 100, 10000);
        stmts.update.run({ id: msg.id, name: newName, duration: newDuration, message: newMessage, yellow_at: newYellow, red_at: newRed, flash_at: newFlashAt, flash_rate: newFlashRate });
        Object.assign(timers[idx], { name: newName, duration: newDuration, message: newMessage, yellowAt: newYellow, redAt: newRed, flashAt: newFlashAt, flashRate: newFlashRate });
        // Only reset remaining if not running AND duration actually changed AND timer hasn't been partially run
        const durationChanged = o.duration !== undefined && o.duration !== timers[idx].duration;
        if (!wasRunning && !wasPartiallyRun) timers[idx].remaining = timers[idx].duration;
        else if (!wasRunning && durationChanged) timers[idx].remaining = timers[idx].duration;
        broadcastState();
        break;
      }

      case 'delete': {
        const idx = timers.findIndex(t => t.id === msg.id);
        if (idx === -1) break;
        stmts.subDeleteAll.run(msg.id);
        stmts.delete.run(msg.id);
        if (idx === activeTimerIndex) { stopInterval(); activeTimerIndex = null; activeSubtimerIndex = null; }
        else if (activeTimerIndex !== null && idx < activeTimerIndex) activeTimerIndex--;
        timers.splice(idx, 1);
        saveTimerOrder();
        broadcastState();
        break;
      }

      case 'reorder': {
        const { from, to } = msg;
        if (from < 0 || to < 0 || from >= timers.length || to >= timers.length) break;
        [timers[from], timers[to]] = [timers[to], timers[from]];
        if (activeTimerIndex === from) activeTimerIndex = to;
        else if (activeTimerIndex === to) activeTimerIndex = from;
        saveTimerOrder();
        broadcastState();
        break;
      }

      // ── Subtimer CRUD ───────────────────────────────────────────────────────
      case 'create_subtimer': {
        const t = timers.find(t => t.id === msg.parentId);
        if (!t) break;
        const s = settings;
        const info = stmts.subInsert.run({
          parent_id:  msg.parentId,
          sort_order: t.subtimers.length,
          name:       safeName(msg.subtimer?.name, 'Part'),
          duration:   safeInt(msg.subtimer?.duration,  60,                 1, 86400),
          yellow_at:  safeInt(msg.subtimer?.yellowAt,  +s.default_yellow_at, 0, 86400),
          red_at:     safeInt(msg.subtimer?.redAt,     +s.default_red_at,    0, 86400),
          flash_at:   safeInt(msg.subtimer?.flashAt,   +s.default_flash_at,  0, 86400),
          flash_rate: safeInt(msg.subtimer?.flashRate, +s.default_flash_rate, 100, 10000),
        });
        // Reload subtimers for this parent — preserving runtime state of existing ones
        const existingSubs = t.subtimers;
        t.subtimers = stmts.subAll.all({ parent_id: msg.parentId }).map(row => {
          const existing = existingSubs.find(s => s.id === row.id);
          return existing || dbRowToSubtimer(row);
        });
        recalcParentDuration(msg.parentId);
        broadcastState();
        break;
      }

      case 'update_subtimer': {
        const t = timers.find(t => t.id === msg.parentId);
        if (!t) break;
        const sIdx = t.subtimers.findIndex(s => s.id === msg.id);
        if (sIdx === -1) break;
        const o = msg.subtimer;
        const subName      = safeName(o.name, t.subtimers[sIdx].name);
        const subDuration  = safeInt(o.duration,  t.subtimers[sIdx].duration,  1, 86400);
        const subYellow    = safeInt(o.yellowAt,  t.subtimers[sIdx].yellowAt,  0, 86400);
        const subRed       = safeInt(o.redAt,     t.subtimers[sIdx].redAt,     0, 86400);
        const subFlashAt   = safeInt(o.flashAt,   t.subtimers[sIdx].flashAt,   0, 86400);
        const subFlashRate = safeInt(o.flashRate, t.subtimers[sIdx].flashRate, 100, 10000);
        stmts.subUpdate.run({ id: msg.id, name: subName, duration: subDuration, yellow_at: subYellow, red_at: subRed, flash_at: subFlashAt, flash_rate: subFlashRate });
        Object.assign(t.subtimers[sIdx], { name: subName, duration: subDuration, yellowAt: subYellow, redAt: subRed, flashAt: subFlashAt, flashRate: subFlashRate });
        // Only reset remaining if not currently running
        const isActiveSub = activeTimerIndex !== null && timers[activeTimerIndex].id === msg.parentId && activeSubtimerIndex === sIdx;
        if (!isActiveSub) t.subtimers[sIdx].remaining = t.subtimers[sIdx].duration;
        recalcParentDuration(msg.parentId);
        broadcastState();
        break;
      }

      case 'delete_subtimer': {
        const t = timers.find(t => t.id === msg.parentId);
        if (!t) break;
        const sIdx = t.subtimers.findIndex(s => s.id === msg.id);
        if (sIdx === -1) break;
        stmts.subDelete.run(msg.id);
        t.subtimers.splice(sIdx, 1);

        // Fix activeSubtimerIndex after deletion
        if (activeTimerIndex !== null && timers[activeTimerIndex].id === msg.parentId) {
          if (t.subtimers.length === 0) {
            // No subtimers left — stop interval, clear subtimer index
            stopInterval();
            activeSubtimerIndex = null;
            t.status = 'idle';
          } else if (activeSubtimerIndex === sIdx) {
            // Deleted the active subtimer — go to first
            stopInterval();
            activeSubtimerIndex = 0;
            t.subtimers[0].status = 'idle';
            t.status = 'idle';
          } else if (activeSubtimerIndex !== null && activeSubtimerIndex > sIdx) {
            activeSubtimerIndex--;
          }
        }

        saveSubtimerOrder(msg.parentId);
        recalcParentDuration(msg.parentId);
        broadcastState();
        break;
      }

      case 'reorder_subtimer': {
        const t = timers.find(t => t.id === msg.parentId);
        if (!t) break;
        const { from, to } = msg;
        if (from < 0 || to < 0 || from >= t.subtimers.length || to >= t.subtimers.length) break;
        [t.subtimers[from], t.subtimers[to]] = [t.subtimers[to], t.subtimers[from]];
        if (activeTimerIndex !== null && timers[activeTimerIndex].id === msg.parentId) {
          if (activeSubtimerIndex === from) activeSubtimerIndex = to;
          else if (activeSubtimerIndex === to) activeSubtimerIndex = from;
        }
        saveSubtimerOrder(msg.parentId);
        broadcastState();
        break;
      }

      // ── Playback ────────────────────────────────────────────────────────────
      case 'select': {
        const idx = timers.findIndex(t => t.id === msg.id);
        if (idx === -1) break;
        // Toggle off if already active
        if (activeTimerIndex === idx) {
          stopInterval();
          const t = timers[idx];
          if (t.status === 'running') t.status = 'idle';
          t.subtimers.forEach(s => { if (s.status === 'running') s.status = 'idle'; });
          activeTimerIndex = null;
          activeSubtimerIndex = null;
          broadcastState();
          break;
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
        } else {
          activeSubtimerIndex = null;
        }
        if (newT.status !== 'finished') newT.status = 'idle';
        autoStart();
        broadcastState();
        break;
      }

      case 'select_subtimer': {
        const t = timers.find(t => t.id === msg.parentId);
        if (!t) break;
        const idx = timers.indexOf(t);
        const sIdx = t.subtimers.findIndex(s => s.id === msg.id);
        if (sIdx === -1) break;
        const wasRunning = activeTimerIndex === idx &&
          activeSubtimerIndex !== null &&
          t.subtimers[activeSubtimerIndex]?.status === 'running';
        // Stop the currently ticking subtimer
        if (wasRunning) t.subtimers[activeSubtimerIndex].status = 'idle';
        // Make parent active if it isn't
        if (activeTimerIndex !== idx) {
          stopInterval();
          if (activeTimerIndex !== null && timers[activeTimerIndex]) resetTimerState(timers[activeTimerIndex]);
          activeTimerIndex = idx;
        }
        activeSubtimerIndex = sIdx;
        t.status = wasRunning ? 'running' : 'idle';
        // If was running, keep running from the new subtimer
        if (wasRunning) {
          t.subtimers[sIdx].status = 'running';
          startInterval();
        } else {
          t.subtimers[sIdx].status = 'idle';
        }
        t.remaining = computeParentRemaining(t);
        broadcastState();
        break;
      }

      case 'play': {
        const t = getActiveTimer();
        if (!t) break;
        const sub = getActiveSubtimer();
        if (sub) {
          if (sub.status === 'finished') break;
          sub.status = 'running';
          t.status = 'running';
        } else {
          if (t.status === 'finished') break;
          t.status = 'running';
        }
        startInterval();
        broadcastState();
        break;
      }

      case 'pause': {
        const t = getActiveTimer();
        if (!t) break;
        const sub = getActiveSubtimer();
        if (sub) sub.status = 'paused';
        t.status = 'paused';
        stopInterval();
        broadcastState();
        break;
      }

      case 'reset': {
        const t = getActiveTimer();
        if (!t) break;
        stopInterval();
        resetTimerState(t);
        activeSubtimerIndex = t.subtimers.length > 0 ? 0 : null;
        broadcastState();
        break;
      }

      case 'scrub': {
        const t = getActiveTimer();
        if (!t) break;
        const sub = getActiveSubtimer();
        const target = sub || t;
        target.remaining = Math.max(0, Math.min(target.duration, Math.round(msg.remaining)));
        if (sub) {
          t.remaining = computeParentRemaining(t);
          if (target.remaining === 0) { target.status = 'finished'; stopInterval(); }
          else if (target.status === 'finished') target.status = 'idle';
        } else {
          if (target.remaining === 0) { target.status = 'finished'; stopInterval(); }
          else if (target.status === 'finished') target.status = 'idle';
        }
        broadcast({ type: 'tick', timers, activeTimerIndex, activeSubtimerIndex });
        break;
      }

      case 'add30': {
        const t = getActiveTimer();
        if (!t) break;
        const sub = getActiveSubtimer();
        const target = sub || t;
        target.remaining = Math.min(target.duration, target.remaining + 30);
        if (sub) t.remaining = computeParentRemaining(t);
        broadcast({ type: 'tick', timers, activeTimerIndex, activeSubtimerIndex });
        break;
      }

      case 'prev': {
        stopInterval();
        const t = getActiveTimer();
        if (t && activeSubtimerIndex !== null && activeSubtimerIndex > 0) {
          // Go to previous subtimer within same parent
          t.subtimers[activeSubtimerIndex].status = 'idle';
          activeSubtimerIndex--;
          t.subtimers[activeSubtimerIndex].status = 'idle';
          t.subtimers[activeSubtimerIndex].remaining = t.subtimers[activeSubtimerIndex].duration;
          t.remaining = computeParentRemaining(t);
          t.status = 'idle';
        } else {
          // Go to previous parent timer
          if (t) resetTimerState(t);
          if (activeTimerIndex === null) activeTimerIndex = 0;
          else activeTimerIndex = Math.max(0, activeTimerIndex - 1);
          const newT = timers[activeTimerIndex];
          resetTimerState(newT);
          activeSubtimerIndex = newT.subtimers.length > 0 ? 0 : null;
        }
        autoStart();
        broadcastState();
        break;
      }

      case 'next': {
        stopInterval();
        const t = getActiveTimer();
        if (t && activeSubtimerIndex !== null && activeSubtimerIndex < t.subtimers.length - 1) {
          // Go to next subtimer within same parent
          t.subtimers[activeSubtimerIndex].status = 'idle';
          activeSubtimerIndex++;
          t.subtimers[activeSubtimerIndex].status = 'idle';
          t.subtimers[activeSubtimerIndex].remaining = t.subtimers[activeSubtimerIndex].duration;
          t.remaining = computeParentRemaining(t);
          t.status = 'idle';
        } else {
          // Go to next parent timer
          if (t) resetTimerState(t);
          if (activeTimerIndex === null) activeTimerIndex = 0;
          else activeTimerIndex = Math.min(timers.length - 1, activeTimerIndex + 1);
          const newT = timers[activeTimerIndex];
          resetTimerState(newT);
          activeSubtimerIndex = newT.subtimers.length > 0 ? 0 : null;
        }
        autoStart();
        broadcastState();
        break;
      }

      case 'save_settings': {
        const allowed = ['default_duration','default_yellow_at','default_red_at','default_flash_at','default_flash_rate','auto_start','subtimers_expanded'];
        const tx = db.transaction(() => {
          allowed.forEach(k => {
            if (msg.settings[k] === undefined) return;
            let v = msg.settings[k];
            if (k === 'auto_start' || k === 'subtimers_expanded') {
              v = (v === 'true' || v === true) ? 'true' : 'false';
            } else {
              const min = k === 'default_flash_rate' ? 100 : 0;
              const max = k === 'default_flash_rate' ? 10000 : 86400;
              v = String(safeInt(v, +SETTING_DEFAULTS[k], min, max));
            }
            saveSetting(k, v);
          });
        });
        tx();
        settings = loadSettings();
        broadcastState();
        break;
      }
      case 'raise_hand': {
        const name = String(msg.name || '').trim().slice(0, 100);
        if (!name) break;
        if (handQueue.find(e => e.name.toLowerCase() === name.toLowerCase())) break;
        handQueue.push({ name, raisedAt: Date.now() });
        ws._handRaiseName = name; // track on this connection for lower_hand auth
        broadcastHandQueue();
        break;
      }

      case 'lower_hand': {
        const name = String(msg.name || '').trim().slice(0, 100);
        if (!name) break;
        // Only allow lowering your own hand (matched by WS connection) OR operator clear
        // Operator sends lower_hand without a name match — we check ws._isOperator
        const ownHand = ws._handRaiseName && ws._handRaiseName.toLowerCase() === name.toLowerCase();
        const isOperator = ws._isOperator === true;
        if (!ownHand && !isOperator) break;
        handQueue = handQueue.filter(e => e.name.toLowerCase() !== name.toLowerCase());
        if (ownHand) ws._handRaiseName = null;
        broadcastHandQueue();
        break;
      }

      case 'clear_queue': {
        if (!ws._isOperator) break; // only operator can clear all
        handQueue = [];
        broadcastHandQueue();
        break;
      }

      case 'identify_operator': {
        if (msg.secret === OPERATOR_SECRET) {
          ws._isOperator = true;
        }
        break;
      }

    } // end switch
    } catch (err) {
      console.error('WS message handler error:', err);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`ShowClock running at http://localhost:${PORT}`);
  console.log(`  Operator: http://localhost:${PORT}/operator.html`);
  console.log(`  Display:  http://localhost:${PORT}/display.html`);
  console.log(`  Database: ${DB_PATH}`);
});