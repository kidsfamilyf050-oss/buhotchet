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

// ── FORGOT PASSWORD ───────────────────────────────────────────────────────────
app.post('/api/auth/forgot', requireDb, async (req, res) => {
  const { login } = req.body || {};
  if (!login) return res.status(400).json({ ok:false, error:'missing_fields' });
  try {
    const result = await db.createResetToken(login.trim().toLowerCase());
    if (!result) return res.json({ ok:false, error:'not_found' });
    // Отправить email
    const html_forgot = `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:24px">
      <img src="https://kidsfamilyf050-oss.github.io/buhotchet/logo.png" alt="БухОтчет" style="height:40px;margin-bottom:20px" onerror="this.style.display='none'">
      <h2 style="color:#1a2e6e">Сброс пароля</h2>
      <p>Здравствуйте, <b>${result.name}</b>!</p>
      <p>Ваш временный пароль:</p>
      <div style="background:#f0f4ff;border-radius:8px;padding:16px;font-size:24px;font-weight:bold;letter-spacing:4px;color:#1a2e6e;text-align:center;margin:16px 0">${result.tempPass}</div>
      <p>Войдите и смените пароль в настройках профиля.</p>
      <a href="https://kidsfamilyf050-oss.github.io/buhotchet/buhotchet_portal.html" style="display:inline-block;background:#1a4d8f;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold">Войти в БухОтчет</a>
      <p style="margin-top:24px;font-size:12px;color:#666">Если вы не запрашивали сброс пароля — проигнорируйте это письмо.</p>
    </div>`;
    await sendEmail(result.email, 'Сброс пароля — БухОтчет',
      `Здравствуйте, ${result.name}!\n\nВаш временный пароль: ${result.tempPass}\n\nВойдите на портал: https://kidsfamilyf050-oss.github.io/buhotchet/buhotchet_portal.html`,
      html_forgot);
    res.json({ ok:true });
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── EMAIL через Resend ────────────────────────────────────────────────────────
async function sendEmail(to, subject, text, html) {
  const apiKey = process.env.RESEND_API_KEY;
  const from   = process.env.RESEND_FROM || 'БухОтчет <noreply@buhotchet.site>';
  if (!apiKey) {
    console.log(`[email-noapikey] To: ${to} | ${subject}`);
    return false;
  }
  try {
    const body = {
      from,
      to: Array.isArray(to) ? to : [to],
      subject,
      text,
      ...(html ? { html } : {})
    };
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (res.ok) {
      console.log('[email] ✓ Отправлено на', to, '| id:', data.id);
      return true;
    } else {
      console.error('[email] ✗ Ошибка Resend:', data);
      return false;
    }
  } catch(e) {
    console.error('[email] ✗ fetch error:', e.message);
    return false;
  }
}

// ── EMAIL NOTIFICATION ON REGISTER (call from register route) ─────────────────
const _origRegister = app._router.stack.find(l => l.route && l.route.path === '/api/auth/register');

// Уведомление админу о новой заявке
app.post('/api/auth/notify-admin', requireDb, async (req, res) => {
  const { userName, userLogin, userEmail } = req.body || {};
  const adminEmail = process.env.ADMIN_EMAIL || '';
  if (adminEmail) {
    const html_reg = `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:24px">
      <h2 style="color:#1a2e6e">Новая заявка на регистрацию</h2>
      <table style="width:100%;border-collapse:collapse">
        <tr><td style="padding:8px;color:#666;width:100px">Имя:</td><td style="padding:8px;font-weight:bold">${userName}</td></tr>
        <tr style="background:#f8f9fa"><td style="padding:8px;color:#666">Логин:</td><td style="padding:8px;font-family:monospace">${userLogin}</td></tr>
        <tr><td style="padding:8px;color:#666">Email:</td><td style="padding:8px">${userEmail}</td></tr>
      </table>
      <a href="https://kidsfamilyf050-oss.github.io/buhotchet/buhotchet_portal.html" style="display:inline-block;background:#1a4d8f;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin-top:16px">Открыть AdminPanel</a>
    </div>`;
    await sendEmail(adminEmail, '🆕 Новая заявка — БухОтчет',
      `Новая заявка:\nИмя: ${userName}\nЛогин: ${userLogin}\nEmail: ${userEmail}`,
      html_reg);
  }
  res.json({ ok:true });
});

// Уведомить пользователя об одобрении
app.post('/api/admin/users/:id/notify', requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.pool.query(
      `SELECT full_name, email, login, tariff FROM users WHERE id=$1`,
      [parseInt(req.params.id)]
    );
    if (rows.length && rows[0].email) {
      const u = rows[0];
      const tariffNames = { all:'все формы (ФНО 200 + ФНО 300)', fno200:'ФНО 200 (ИПН/ОПВ)', fno300:'ФНО 300 (НДС)', none:'без доступа к формам' };
      const tariffColors = { all:'#1d6b45', fno200:'#1a4d8f', fno300:'#9a5f0a', none:'#666' };
      const html_approve = `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:24px">
        <h2 style="color:#1a2e6e">✅ Ваш аккаунт одобрен!</h2>
        <p>Здравствуйте, <b>${u.full_name}</b>!</p>
        <p>Ваша заявка на доступ к порталу <b>БухОтчет</b> одобрена.</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
          <tr style="background:#f8f9fa"><td style="padding:8px;color:#666;width:100px">Логин:</td><td style="padding:8px;font-family:monospace;font-weight:bold">${u.login}</td></tr>
          <tr><td style="padding:8px;color:#666">Доступ:</td><td style="padding:8px;font-weight:bold;color:${tariffColors[u.tariff]||'#333'}">${tariffNames[u.tariff]||u.tariff}</td></tr>
        </table>
        <a href="https://kidsfamilyf050-oss.github.io/buhotchet/buhotchet_portal.html" style="display:inline-block;background:#1a4d8f;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px">Войти в БухОтчет →</a>
        <p style="margin-top:24px;font-size:12px;color:#666">Портал бухгалтерской отчётности Казахстан 2026 · buhotchet.site</p>
      </div>`;
      await sendEmail(u.email, '✅ Доступ к БухОтчет открыт',
        `Здравствуйте, ${u.full_name}!\n\nВаша заявка одобрена.\nЛогин: ${u.login}\nДоступ: ${tariffNames[u.tariff]||u.tariff}\n\nВойдите: https://kidsfamilyf050-oss.github.io/buhotchet/buhotchet_portal.html`,
        html_approve);
    }
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false }); }
});
