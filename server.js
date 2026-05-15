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

// ══════════════════════════════════════════════════════════════════════════════
// БЕЗОПАСНОСТЬ — ЗАГОЛОВКИ (Helmet)
// ══════════════════════════════════════════════════════════════════════════════
try {
  const helmet = require('helmet');
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:    ["'self'"],
        scriptSrc:     ["'self'", "'unsafe-inline'", "'unsafe-eval'",
                        "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc:       ["'self'", "https://fonts.gstatic.com", "data:"],
        imgSrc:        ["'self'", "data:", "https:", "blob:"],
        connectSrc:    ["'self'",
                        "https://buhotchet.site",
                        "https://buhotchet-production.up.railway.app",
                        "https://*.railway.app",
                        "https://api.resend.com",
                        "https://kidsfamilyf050-oss.github.io"],
        frameSrc:      ["'self'", "https://kidsfamilyf050-oss.github.io"],
        objectSrc:     ["'none'"],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));
  console.log('[security] Helmet активирован');
} catch(e) { console.warn('[security] Helmet не установлен:', e.message); }

// ══════════════════════════════════════════════════════════════════════════════
// RATE LIMITING — защита от брутфорса и DDoS
// ══════════════════════════════════════════════════════════════════════════════
function makeRateLimit(windowMs, max, message) {
  try {
    const rateLimit = require('express-rate-limit');
    return rateLimit({
      windowMs,
      max,
      message: { ok:false, error: message },
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => req.ip === '127.0.0.1' || req.ip === '::1'
    });
  } catch(e) { return (req,res,next) => next(); }
}

// Строгий лимит для авторизации: 10 попыток за 15 минут
const authLimiter    = makeRateLimit(15 * 60 * 1000, 10, 'too_many_attempts');
// Общий лимит API: 200 запросов в минуту
const generalLimiter = makeRateLimit(60 * 1000, 200, 'rate_limit_exceeded');
// Строгий лимит для регистрации: 5 за час
const registerLimiter = makeRateLimit(60 * 60 * 1000, 5, 'too_many_registrations');

app.use('/api/', generalLimiter);

// ══════════════════════════════════════════════════════════════════════════════
// CORS
// ══════════════════════════════════════════════════════════════════════════════
const ALLOWED_ORIGINS = [
  'https://buhotchet.site',
  'https://www.buhotchet.site',
  'https://kidsfamilyf050-oss.github.io',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(express.json({ limit: '10mb' })); // Уменьшили с 25mb

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════════════════
function requireDb(req, res, next) {
  if (!dbReady) return res.status(503).json({ ok:false, error:'database_unavailable' });
  next();
}

async function requireAuth(req, res, next) {
  if (!dbReady) return res.status(503).json({ ok:false, error:'database_unavailable' });
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  if (!token) return res.status(401).json({ ok:false, error:'unauthorized' });
  const user = await db.validateSession(token);
  if (!user) return res.status(401).json({ ok:false, error:'unauthorized' });
  req.user  = user;
  req.token = token;
  next();
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ ok:false, error:'forbidden' });
    next();
  });
}

function getIP(req) {
  return req.headers['cf-connecting-ip'] ||
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.ip;
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/health', (_req, res) => {
  res.json({ ok:true, db:dbReady, time:new Date().toISOString() });
});

app.post('/api/auth/login', requireDb, authLimiter, async (req, res) => {
  const { login, password } = req.body || {};
  if (!login||!password) return res.status(400).json({ ok:false, error:'missing_fields' });
  // Санитизация
  if (login.length > 64 || password.length > 128)
    return res.status(400).json({ ok:false, error:'invalid_input' });
  try {
    const result = await db.loginUser(login, password, getIP(req), req.headers['user-agent']);
    if (!result.ok) {
      // Не раскрываем детали ошибки в заголовках
      res.status(result.error === 'locked' ? 429 : 401).json(result);
    } else {
      res.json(result);
    }
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/register', requireDb, registerLimiter, async (req, res) => {
  const { full_name, login, email, phone, password } = req.body || {};
  // Санитизация входных данных
  if (!full_name || !login || !password)
    return res.status(400).json({ ok:false, error:'missing_fields' });
  if (full_name.length > 100 || login.length > 32 || password.length > 128)
    return res.status(400).json({ ok:false, error:'invalid_input' });
  try {
    const result = await db.registerUser({ full_name, login, email, phone, password });
    res.json(result);
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/logout', requireDb, async (req, res) => {
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  try { if (token) await db.logoutSession(token); } catch(e) {}
  res.json({ ok:true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  // Не возвращаем лишние данные
  const { id, login, name, role, tariff } = req.user;
  res.json({ ok:true, user:{ id, login, name, role, tariff } });
});

app.post('/api/auth/change-password', requireAuth, requireDb, async (req, res) => {
  const { old_password, new_password } = req.body || {};
  if (!old_password || !new_password)
    return res.status(400).json({ ok:false, error:'missing_fields' });
  try {
    const result = await db.changePassword(req.user.id, old_password, new_password);
    res.json(result);
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/forgot', requireDb, authLimiter, async (req, res) => {
  const { login } = req.body || {};
  if (!login) return res.status(400).json({ ok:false, error:'missing_fields' });
  try {
    const result = await db.createResetToken(login.trim().toLowerCase());
    if (!result) {
      // Всегда возвращаем ok:true — не раскрываем существование логина
      return res.json({ ok:true });
    }
    await sendEmail(result.email, 'Сброс пароля — БухОтчет',
      `Здравствуйте, ${result.name}!\n\nВаш временный пароль: ${result.tempPass}\n\nВойдите и смените пароль.\n\nБухОтчет`,
      buildEmailHtml('Сброс пароля', `
        <p>Здравствуйте, <b>${result.name}</b>!</p>
        <p>Ваш временный пароль:</p>
        <div style="background:#f0f4ff;border-radius:8px;padding:16px;font-size:24px;font-weight:bold;letter-spacing:4px;color:#1a2e6e;text-align:center;margin:16px 0">${result.tempPass}</div>
        <p>После входа немедленно смените пароль.</p>
        <a href="https://buhotchet.site" style="display:inline-block;background:#1a4d8f;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold">Войти в БухОтчет →</a>
        <p style="margin-top:16px;font-size:12px;color:#999">Если вы не запрашивали сброс — проигнорируйте письмо.</p>
      `)
    );
    res.json({ ok:true });
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'server_error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════════════════════════════
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
    const uid = parseInt(req.params.id);
    if (isNaN(uid)) return res.status(400).json({ ok:false });
    await db.approveUser(uid, req.body?.tariff||'all');
    await db.audit(req.user.id, 'user_approved', getIP(req), { target_id: uid });
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/tariff', requireAdmin, async (req, res) => {
  try {
    await db.updateUserTariff(parseInt(req.params.id), req.body?.tariff||'all');
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/block', requireAdmin, async (req, res) => {
  try {
    const uid = parseInt(req.params.id);
    await db.blockUser(uid);
    await db.audit(req.user.id, 'user_blocked', getIP(req), { target_id: uid });
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/unblock', requireAdmin, async (req, res) => {
  try { await db.unblockUser(parseInt(req.params.id)); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    await db.deleteUser(parseInt(req.params.id));
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/notify', requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.pool.query(
      `SELECT full_name,email,login,tariff FROM users WHERE id=$1`,
      [parseInt(req.params.id)]
    );
    if (rows.length && rows[0].email) {
      const u = rows[0];
      const tariffNames = { all:'все формы (ФНО 200 + ФНО 300)', fno200:'ФНО 200', fno300:'ФНО 300', none:'без доступа' };
      await sendEmail(u.email, '✅ Доступ к БухОтчет открыт',
        `Здравствуйте, ${u.full_name}! Заявка одобрена. Логин: ${u.login}. Доступ: ${tariffNames[u.tariff]||u.tariff}`,
        buildEmailHtml('Доступ открыт!', `
          <p>Здравствуйте, <b>${u.full_name}</b>!</p>
          <p>Ваша заявка на доступ к порталу <b>БухОтчет</b> одобрена.</p>
          <table style="width:100%;border-collapse:collapse;margin:16px 0">
            <tr style="background:#f8f9fa"><td style="padding:8px;color:#666;width:100px">Логин:</td>
              <td style="padding:8px;font-family:monospace;font-weight:bold">${u.login}</td></tr>
            <tr><td style="padding:8px;color:#666">Доступ:</td>
              <td style="padding:8px;font-weight:bold;color:#1d6b45">${tariffNames[u.tariff]||u.tariff}</td></tr>
          </table>
          <a href="https://buhotchet.site" style="display:inline-block;background:#1a4d8f;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px">Войти в БухОтчет →</a>
        `)
      );
    }
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false }); }
});

app.post('/api/auth/notify-admin', requireDb, async (req, res) => {
  const { userName, userLogin, userEmail } = req.body || {};
  const adminEmail = process.env.ADMIN_EMAIL||'';
  if (adminEmail && userName) {
    await sendEmail(adminEmail, '🆕 Новая заявка — БухОтчет',
      `Новая заявка: ${userName} (${userLogin}) ${userEmail}`,
      buildEmailHtml('Новая заявка на регистрацию', `
        <p>Поступила новая заявка на регистрацию:</p>
        <table style="width:100%;border-collapse:collapse;margin:16px 0">
          <tr><td style="padding:8px;color:#666;width:80px">Имя:</td><td style="padding:8px;font-weight:bold">${userName}</td></tr>
          <tr style="background:#f8f9fa"><td style="padding:8px;color:#666">Логин:</td><td style="padding:8px;font-family:monospace">${userLogin}</td></tr>
          <tr><td style="padding:8px;color:#666">Email:</td><td style="padding:8px">${userEmail||'—'}</td></tr>
        </table>
        <a href="https://buhotchet.site" style="display:inline-block;background:#1a4d8f;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold">Открыть AdminPanel →</a>
      `)
    );
  }
  res.json({ ok:true });
});

// ══════════════════════════════════════════════════════════════════════════════
// COMPANIES & KV
// ══════════════════════════════════════════════════════════════════════════════
app.get('/api/companies', requireAuth, async (req, res) => {
  try { res.json({ ok:true, companies: await db.getUserCompanies(req.user.id) }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.put('/api/companies', requireAuth, async (req, res) => {
  try {
    await db.saveUserCompanies(req.user.id, req.body?.companies||[]);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.get('/api/kv/:key', requireAuth, async (req, res) => {
  try {
    const value = await db.getKv(req.user.id, req.params.key);
    res.json({ ok:true, key:req.params.key, value });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.put('/api/kv/:key', requireAuth, async (req, res) => {
  try {
    await db.putKv(req.user.id, req.params.key, req.body?.value??null);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/kv/bulk', requireAuth, async (req, res) => {
  try {
    await db.bulkPutKv(req.user.id, req.body?.items||{});
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// EMAIL (Resend)
// ══════════════════════════════════════════════════════════════════════════════
function buildEmailHtml(title, body) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
  <style>body{font-family:Arial,sans-serif;background:#f4f6fb;margin:0;padding:0}
  .wrap{max-width:520px;margin:32px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.08)}
  .head{background:linear-gradient(135deg,#0d2a5c,#1a4d8f);padding:24px 32px;text-align:center}
  .head-title{color:#fff;font-size:20px;font-weight:bold;margin-top:8px}
  .body{padding:24px 32px}
  .foot{background:#f8f9fa;padding:16px 32px;font-size:11px;color:#999;text-align:center}
  </style></head><body>
  <div class="wrap">
    <div class="head">
      <div style="font-size:28px;font-weight:900;color:#fff;letter-spacing:-1px">БухОтчет</div>
      <div class="head-title">${title}</div>
    </div>
    <div class="body">${body}</div>
    <div class="foot">Портал бухгалтерской отчётности · Казахстан 2026 · buhotchet.site<br>
    Это автоматическое письмо, не отвечайте на него.</div>
  </div>
  </body></html>`;
}

async function sendEmail(to, subject, text, html) {
  const apiKey = process.env.RESEND_API_KEY;
  const from   = process.env.RESEND_FROM || 'БухОтчет <noreply@buhotchet.site>';
  if (!apiKey) { console.log(`[email-skip] ${to} | ${subject}`); return false; }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization':'Bearer '+apiKey, 'Content-Type':'application/json' },
      body: JSON.stringify({
        from, to: Array.isArray(to)?to:[to], subject, text,
        ...(html ? { html } : {})
      })
    });
    const data = await res.json();
    if (res.ok) { console.log('[email] ✓', to); return true; }
    console.error('[email] ✗', data);
    return false;
  } catch(e) { console.error('[email] error:', e.message); return false; }
}

// ══════════════════════════════════════════════════════════════════════════════
// STATIC + FALLBACK
// ══════════════════════════════════════════════════════════════════════════════
app.use(express.static(ROOT, {
  index: false,
  setHeaders(res, filePath) {
    // Кешируем статику кроме HTML
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    }
  }
}));

app.get('*', (_req, res) => {
  res.sendFile(path.join(ROOT, 'buhotchet_portal.html'));
});

// ══════════════════════════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════════════════════════
async function start() {
  try {
    dbReady = await db.initDb();
    console.log(dbReady ? '[db] ✓ PostgreSQL готов' : '[db] ✗ Без БД');
  } catch(e) {
    console.error('[db] Ошибка:', e.message);
    dbReady = false;
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] ✓ https://buhotchet.site (port ${PORT})`);
  });
}

start();

// ── CHANGE PASSWORD ───────────────────────────────────────────────────────────
app.post('/api/auth/change-password', requireAuth, requireDb, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ ok:false, error:'missing_fields' });
  if (newPassword.length < 6) return res.status(400).json({ ok:false, error:'too_short' });
  try {
    const result = await db.changePassword(req.user.id, oldPassword, newPassword);
    res.json(result);
  } catch(e) { console.error(e); res.status(500).json({ ok:false, error:'server_error' }); }
});
