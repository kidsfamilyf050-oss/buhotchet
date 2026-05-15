'use strict';

require('dotenv').config();

const path    = require('path');
const express = require('express');
const cors    = require('cors');
const db      = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;

let dbReady = false;

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '25mb' }));

// ── helpers ──────────────────────────────────────────────────────────────────
function requireDb(req, res, next) {
  if (!dbReady) return res.status(503).json({ ok:false, error:'database_unavailable' });
  next();
}

async function requireAuth(req, res, next) {
  if (!dbReady) return res.status(503).json({ ok:false, error:'database_unavailable' });
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  const user  = await db.validateSession(token);
  if (!user) return res.status(401).json({ ok:false, error:'unauthorized' });
  req.user = user;
  next();
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ ok:false, error:'forbidden' });
    next();
  });
}

// ── AUTH ─────────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ ok:true, db:dbReady, time:new Date().toISOString() });
});

app.post('/api/auth/login', requireDb, async (req, res) => {
  const { login, password } = req.body || {};
  if (!login||!password) return res.status(400).json({ ok:false, error:'missing_fields' });
  try {
    const result = await db.loginUser(login, password);
    res.json(result);
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/register', requireDb, async (req, res) => {
  try {
    const result = await db.registerUser(req.body || {});
    res.json(result);
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/logout', requireDb, async (req, res) => {
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  try { await db.logoutSession(token); } catch(e) {}
  res.json({ ok:true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok:true, user: req.user });
});

// ── ADMIN ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/users/pending', requireAdmin, async (req, res) => {
  try { res.json({ ok:true, users: await db.getPendingUsers() }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try { res.json({ ok:true, users: await db.getAllUsers() }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/approve', requireAdmin, async (req, res) => {
  try {
    await db.approveUser(parseInt(req.params.id), req.body?.tariff || 'all');
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/tariff', requireAdmin, async (req, res) => {
  try {
    await db.updateUserTariff(parseInt(req.params.id), req.body?.tariff || 'all');
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/block', requireAdmin, async (req, res) => {
  try { await db.blockUser(parseInt(req.params.id)); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/unblock', requireAdmin, async (req, res) => {
  try { await db.unblockUser(parseInt(req.params.id)); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try { await db.deleteUser(parseInt(req.params.id)); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── COMPANIES ─────────────────────────────────────────────────────────────────
app.get('/api/companies', requireAuth, async (req, res) => {
  try {
    const list = await db.getUserCompanies(req.user.id);
    res.json({ ok:true, companies:list });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.put('/api/companies', requireAuth, async (req, res) => {
  try {
    await db.saveUserCompanies(req.user.id, req.body?.companies || []);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── KV ────────────────────────────────────────────────────────────────────────
app.get('/api/kv/:key', requireAuth, async (req, res) => {
  try {
    const value = await db.getKv(req.user.id, req.params.key);
    res.json({ ok:true, key:req.params.key, value });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.put('/api/kv/:key', requireAuth, async (req, res) => {
  try {
    await db.putKv(req.user.id, req.params.key, req.body?.value ?? null);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/kv/bulk', requireAuth, async (req, res) => {
  try {
    await db.bulkPutKv(req.user.id, req.body?.items || {});
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── STATIC ────────────────────────────────────────────────────────────────────
app.use(express.static(ROOT, { index: false }));

// Все неизвестные маршруты → портал
app.get('*', (_req, res) => {
  res.sendFile(path.join(ROOT, 'buhotchet_portal.html'));
});

async function start() {
  try {
    dbReady = await db.initDb();
    console.log(dbReady ? '[db] PostgreSQL готов' : '[db] Работаем без БД');
  } catch(e) {
    console.error('[db] Ошибка:', e.message);
    dbReady = false;
  }
  app.listen(PORT, () => console.log(`[server] http://0.0.0.0:${PORT}`));
}

start();
