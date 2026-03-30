const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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
};

const stmts = {
  all:          db.prepare('SELECT * FROM timers ORDER BY sort_order ASC, id ASC'),
  insert:       db.prepare('INSERT INTO timers (sort_order, name, duration, message, yellow_at, red_at, flash_at, flash_rate) VALUES (@sort_order, @name, @duration, @message, @yellow_at, @red_at, @flash_at, @flash_rate)'),
  update:       db.prepare('UPDATE timers SET name=@name, duration=@duration, message=@message, yellow_at=@yellow_at, red_at=@red_at, flash_at=@flash_at, flash_rate=@flash_rate WHERE id=@id'),
  updateOrder:  db.prepare('UPDATE timers SET sort_order=@sort_order WHERE id=@id'),
  delete:       db.prepare('DELETE FROM timers WHERE id=?'),
  getSetting:   db.prepare('SELECT value FROM settings WHERE key=?'),
  setSetting:   db.prepare('INSERT INTO settings (key,value) VALUES (@key,@value) ON CONFLICT(key) DO UPDATE SET value=excluded.value'),
  allSettings:  db.prepare('SELECT key,value FROM settings'),
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
function dbRowToTimer(row) {
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
  };
}

function saveOrder() {
  const tx = db.transaction(() => {
    timers.forEach((t, i) => stmts.updateOrder.run({ sort_order: i, id: t.id }));
  });
  tx();
}

// ── In-memory state ───────────────────────────────────────────────────────────
let timers = [];
let activeTimerIndex = null;
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

// ── Timer engine ──────────────────────────────────────────────────────────────
function startInterval() {
  if (timerInterval) return;
  timerInterval = setInterval(() => {
    if (activeTimerIndex === null) return;
    const t = timers[activeTimerIndex];
    if (!t || t.status !== 'running') return;
    t.remaining = Math.max(0, t.remaining - 1);
    if (t.remaining === 0) {
      t.status = 'finished';
      clearInterval(timerInterval);
      timerInterval = null;
    }
    broadcast({ type: 'tick', timers, activeTimerIndex, settings });
  }, 1000);
}

function stopInterval() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
}

function autoStart() {
  if (settings.auto_start !== 'true') return;
  if (activeTimerIndex === null) return;
  const t = timers[activeTimerIndex];
  if (!t || t.status === 'finished') return;
  t.status = 'running';
  startInterval();
}

function broadcast(msg) {
  const data = JSON.stringify(msg);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(data); });
}

function broadcastState() {
  broadcast({ type: 'state', timers, activeTimerIndex, settings });
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', ws => {
  ws.send(JSON.stringify({ type: 'state', timers, activeTimerIndex, settings }));

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.action) {

      case 'create': {
        const s = settings;
        const o = msg.timer || {};
        stmts.insert.run({
          sort_order: timers.length,
          name:       o.name      ?? 'New Timer',
          duration:   o.duration  ?? +s.default_duration,
          message:    o.message   ?? '',
          yellow_at:  o.yellowAt  ?? +s.default_yellow_at,
          red_at:     o.redAt     ?? +s.default_red_at,
          flash_at:   o.flashAt   ?? +s.default_flash_at,
          flash_rate: o.flashRate ?? +s.default_flash_rate,
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
        timers[idx].message = msg.message ?? '';
        stmts.update.run({ id: timers[idx].id, name: timers[idx].name, duration: timers[idx].duration, message: timers[idx].message, yellow_at: timers[idx].yellowAt, red_at: timers[idx].redAt, flash_at: timers[idx].flashAt, flash_rate: timers[idx].flashRate });
        broadcastState();
        break;
      }

      case 'update': {
        const idx = timers.findIndex(t => t.id === msg.id);
        if (idx === -1) break;
        const wasRunning = idx === activeTimerIndex && timers[idx].status === 'running';
        const o = msg.timer;
        stmts.update.run({ id: msg.id, name: o.name ?? timers[idx].name, duration: o.duration ?? timers[idx].duration, message: o.message ?? timers[idx].message, yellow_at: o.yellowAt ?? timers[idx].yellowAt, red_at: o.redAt ?? timers[idx].redAt, flash_at: o.flashAt ?? timers[idx].flashAt, flash_rate: o.flashRate ?? timers[idx].flashRate });
        Object.assign(timers[idx], { name: o.name ?? timers[idx].name, duration: o.duration ?? timers[idx].duration, message: o.message ?? timers[idx].message, yellowAt: o.yellowAt ?? timers[idx].yellowAt, redAt: o.redAt ?? timers[idx].redAt, flashAt: o.flashAt ?? timers[idx].flashAt, flashRate: o.flashRate ?? timers[idx].flashRate });
        if (!wasRunning) timers[idx].remaining = timers[idx].duration;
        broadcastState();
        break;
      }

      case 'delete': {
        const idx = timers.findIndex(t => t.id === msg.id);
        if (idx === -1) break;
        stmts.delete.run(msg.id);
        if (idx === activeTimerIndex) { stopInterval(); activeTimerIndex = null; }
        else if (activeTimerIndex !== null && idx < activeTimerIndex) activeTimerIndex--;
        timers.splice(idx, 1);
        saveOrder();
        broadcastState();
        break;
      }

      case 'scrub': {
        if (activeTimerIndex === null) break;
        const t = timers[activeTimerIndex];
        t.remaining = Math.max(0, Math.min(t.duration, Math.round(msg.remaining)));
        if (t.remaining === 0) { t.status = 'finished'; stopInterval(); }
        else if (t.status === 'finished') t.status = 'idle';
        broadcast({ type: 'tick', timers, activeTimerIndex, settings });
        break;
      }

      case 'reorder': {
        const { from, to } = msg;
        if (from < 0 || to < 0 || from >= timers.length || to >= timers.length) break;
        [timers[from], timers[to]] = [timers[to], timers[from]];
        if (activeTimerIndex === from) activeTimerIndex = to;
        else if (activeTimerIndex === to) activeTimerIndex = from;
        saveOrder();
        broadcastState();
        break;
      }

      case 'select': {
        const idx = timers.findIndex(t => t.id === msg.id);
        if (idx === -1) break;
        stopInterval();
        if (activeTimerIndex !== null && timers[activeTimerIndex] && activeTimerIndex !== idx) {
          timers[activeTimerIndex].status = 'idle';
        }
        activeTimerIndex = idx;
        if (timers[idx].status !== 'finished') timers[idx].status = 'idle';
        autoStart();
        broadcastState();
        break;
      }

      case 'play': {
        if (activeTimerIndex === null) break;
        const t = timers[activeTimerIndex];
        if (t.status === 'finished') break;
        t.status = 'running';
        startInterval();
        broadcastState();
        break;
      }

      case 'pause': {
        if (activeTimerIndex === null) break;
        timers[activeTimerIndex].status = 'paused';
        stopInterval();
        broadcastState();
        break;
      }

      case 'reset': {
        if (activeTimerIndex === null) break;
        const t = timers[activeTimerIndex];
        stopInterval();
        t.remaining = t.duration;
        t.status = 'idle';
        broadcastState();
        break;
      }

      case 'prev': {
        stopInterval();
        if (activeTimerIndex !== null && timers[activeTimerIndex]) {
          timers[activeTimerIndex].status = 'idle';
        }
        if (activeTimerIndex === null) activeTimerIndex = 0;
        else activeTimerIndex = Math.max(0, activeTimerIndex - 1);
        if (timers[activeTimerIndex].status !== 'finished') timers[activeTimerIndex].status = 'idle';
        autoStart();
        broadcastState();
        break;
      }

      case 'next': {
        stopInterval();
        if (activeTimerIndex !== null && timers[activeTimerIndex]) {
          timers[activeTimerIndex].status = 'idle';
        }
        if (activeTimerIndex === null) activeTimerIndex = 0;
        else activeTimerIndex = Math.min(timers.length - 1, activeTimerIndex + 1);
        if (timers[activeTimerIndex].status !== 'finished') timers[activeTimerIndex].status = 'idle';
        autoStart();
        broadcastState();
        break;
      }

      case 'save_settings': {
        const allowed = ['default_duration','default_yellow_at','default_red_at','default_flash_at','default_flash_rate','auto_start'];
        const tx = db.transaction(() => {
          allowed.forEach(k => {
            if (msg.settings[k] !== undefined) saveSetting(k, msg.settings[k]);
          });
        });
        tx();
        settings = loadSettings();
        broadcastState();
        break;
      }
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
