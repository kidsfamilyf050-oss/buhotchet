'use strict';
require('dotenv').config();

const path    = require('path');
const express = require('express');
const cors    = require('cors');
const db      = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const SITE = process.env.SITE_URL || 'https://buhotchet.site';

let dbReady = false;

// ── HELMET ────────────────────────────────────────────────────────────────────
try {
  const helmet = require('helmet');
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:    ["'self'"],
        scriptSrc:     ["'self'", "'unsafe-inline'", "'unsafe-eval'",
                        "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
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
    hsts: { maxAge: 31536000, includeSubDomains: true },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));
  console.log('[security] ✓ Helmet');
} catch(e) { console.warn('[security] Helmet не установлен:', e.message); }

// ── RATE LIMITING ─────────────────────────────────────────────────────────────
try {
  const rateLimit = require('express-rate-limit');
  const authLimiter = rateLimit({ windowMs:15*60*1000, max:20, message:{ok:false,error:'too_many_requests'} });
  app.use('/api/auth/login', authLimiter);
  app.use('/api/auth/register', authLimiter);
  console.log('[security] ✓ Rate limiter');
} catch(e) { console.warn('[security] Rate limiter не установлен'); }

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '25mb' }));

// ── HELPERS ───────────────────────────────────────────────────────────────────
function requireDb(req, res, next) {
  if (!dbReady) return res.status(503).json({ ok:false, error:'database_unavailable' });
  next();
}

async function requireAuth(req, res, next) {
  if (!dbReady) return res.status(503).json({ ok:false, error:'database_unavailable' });
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  const user  = await db.validateSession(token).catch(()=>null);
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

// ── EMAIL (Resend) ─────────────────────────────────────────────────────────────
function emailHtml(title, bodyHtml) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Arial,sans-serif;background:#f4f6fb;margin:0;padding:0}
.wrap{max-width:560px;margin:32px auto;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.1)}
.head{background:linear-gradient(135deg,#0d2244,#1a4d8f);padding:28px 32px;text-align:center}
.logo{font-size:26px;font-weight:900;color:#fff;letter-spacing:-1px}
.logo span{color:#C9A227}
.head-title{color:rgba(255,255,255,.8);font-size:14px;margin-top:6px}
.body{padding:28px 32px;font-size:15px;color:#1a1a1a;line-height:1.6}
.highlight{background:#EAF2FF;border-left:4px solid #1A4D8F;padding:14px 18px;border-radius:8px;margin:16px 0;font-size:14px}
.btn{display:inline-block;background:linear-gradient(135deg,#1a4d8f,#2e6bc4);color:#fff !important;text-decoration:none;padding:13px 28px;border-radius:10px;font-weight:bold;font-size:15px;margin:18px 0}
.foot{background:#f8f9fa;padding:16px 32px;font-size:11px;color:#999;text-align:center;line-height:1.6}
</style></head><body>
<div class="wrap">
  <div class="head">
    <div class="logo">Бух<span>Отчет</span></div>
    <div class="head-title">Портал бухгалтерской отчётности · Казахстан 2026</div>
  </div>
  <div class="body">${bodyHtml}</div>
  <div class="foot">
    buhotchet.site · Казахстан 2026<br>
    Это автоматическое письмо. Не отвечайте на него.
  </div>
</div></body></html>`;
}

async function sendEmail(to, subject, bodyHtml) {
  const apiKey = process.env.RESEND_API_KEY;
  const from   = process.env.RESEND_FROM || 'БухОтчет <noreply@buhotchet.site>';
  const html   = emailHtml(subject, bodyHtml);
  const text   = bodyHtml.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim();

  if (!apiKey) {
    console.log(`[email-skip] No RESEND_API_KEY\nTo: ${to}\nSubject: ${subject}`);
    return false;
  }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization':'Bearer '+apiKey, 'Content-Type':'application/json' },
      body: JSON.stringify({ from, to:[to], subject, html, text })
    });
    const data = await r.json();
    if (r.ok) { console.log('[email] ✓ Sent to', to); return true; }
    console.error('[email] ✗', JSON.stringify(data));
    return false;
  } catch(e) { console.error('[email] Error:', e.message); return false; }
}

// ── AUTH ROUTES ────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ ok:true, db:dbReady, time:new Date().toISOString() });
});

app.post('/api/auth/login', requireDb, async (req, res) => {
  const { login, password } = req.body||{};
  if (!login || !password) return res.status(400).json({ ok:false, error:'missing_fields' });
  try {
    const result = await db.loginUser(login, password);
    res.json(result);
  } catch(e) { console.error('[login]', e); res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/register', requireDb, async (req, res) => {
  try {
    const result = await db.registerUser(req.body||{});
    if (result.ok) {
      const { login, full_name, email } = req.body;
      // 1. Письмо пользователю о регистрации
      await sendEmail(email,
        'Регистрация на портале БухОтчет',
        `<p>Здравствуйте, <strong>${full_name}</strong>!</p>
        <p>Вы успешно зарегистрировались на портале <strong>БухОтчет</strong>.</p>
        <div class="highlight">
          <strong>Ваши данные для входа:</strong><br>
          Логин: <strong>${login}</strong><br>
          Пароль: указан при регистрации<br>
          Сайт: <a href="${SITE}">${SITE}</a>
        </div>
        <p>Ваша заявка передана на рассмотрение администратору. Как только доступ будет открыт — вы получите письмо.</p>
        <p>Ориентировочное время активации: <strong>1 рабочий день</strong>.</p>`
      );
      // 2. Письмо администратору
      const adminEmail = process.env.ADMIN_EMAIL||'';
      const desiredTariff = req.body?.desired_tariff || 'all';
      const tariffNames = { all:'Pro — 40 000 ₸/год', fno200:'Базовый ФНО 200 — 25 000 ₸/год', fno300:'Базовый ФНО 300 — 25 000 ₸/год' };
      if (adminEmail) {
        await sendEmail(adminEmail,
          '🆕 Новая заявка — БухОтчет',
          `<p>Новая заявка на регистрацию:</p>
          <div class="highlight">
            ФИО: <strong>${full_name}</strong><br>
            Логин: <strong>${login}</strong><br>
            Email: <strong>${email}</strong><br>
            Тел: <strong>${phone||'—'}</strong><br>
            Желаемый тариф: <strong>${tariffNames[desiredTariff]||desiredTariff}</strong>
          </div>
          <p>Тарифы:<br>
          • Базовый — 25 000 ₸/год (ФНО 200 или 300 + ФНО 910 + ФНО 100)<br>
          • Pro — 40 000 ₸/год (все формы)<br>
          • Доп. пользователь — +10 000 ₸/год</p>
          <a class="btn" href="${SITE}">Открыть AdminPanel →</a>`
        );
      }
    }
    res.json(result);
  } catch(e) { console.error('[register]', e); res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = (req.headers['authorization']||'').replace('Bearer ','').trim();
  try { await db.logoutSession(token); } catch(e){}
  res.json({ ok:true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ ok:true, user:req.user });
});

app.post('/api/auth/change-password', requireAuth, requireDb, async (req, res) => {
  const { oldPassword, newPassword } = req.body||{};
  if (!oldPassword || !newPassword) return res.status(400).json({ ok:false, error:'missing_fields' });
  if (newPassword.length < 6) return res.status(400).json({ ok:false, error:'password_too_short' });
  try {
    const result = await db.changePassword(req.user.id, oldPassword, newPassword);
    res.json(result);
  } catch(e) { console.error('[change-pass]', e); res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── FORGOT PASSWORD (ссылка на сброс) ─────────────────────────────────────────
app.post('/api/auth/forgot', requireDb, async (req, res) => {
  const { login } = req.body||{};
  if (!login) return res.status(400).json({ ok:false, error:'missing_fields' });
  try {
    const info = await db.createResetLink(login);
    if (!info) return res.json({ ok:false, error:'not_found' });
    const resetUrl = `${SITE}/reset-password?token=${info.token}`;
    await sendEmail(info.email,
      'Сброс пароля — БухОтчет',
      `<p>Здравствуйте, <strong>${info.name}</strong>!</p>
      <p>Мы получили запрос на сброс пароля для вашего аккаунта <strong>${info.login}</strong>.</p>
      <p>Нажмите кнопку ниже чтобы задать новый пароль:</p>
      <a class="btn" href="${resetUrl}">🔑 Сбросить пароль</a>
      <p>Ссылка действует <strong>1 час</strong>. Если вы не запрашивали сброс — проигнорируйте это письмо.</p>`
    );
    res.json({ ok:true });
  } catch(e) { console.error('[forgot]', e); res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── RESET PASSWORD (по токену из ссылки) ──────────────────────────────────────
app.get('/api/auth/reset-check', requireDb, async (req, res) => {
  const { token } = req.query;
  if (!token) return res.json({ ok:false, error:'missing_token' });
  try {
    const user = await db.getResetUser(token);
    if (!user) return res.json({ ok:false, error:'invalid_token' });
    res.json({ ok:true, login:user.login, name:user.full_name });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/auth/reset-password', requireDb, async (req, res) => {
  const { token, newPassword } = req.body||{};
  if (!token || !newPassword) return res.status(400).json({ ok:false, error:'missing_fields' });
  if (newPassword.length < 6) return res.status(400).json({ ok:false, error:'password_too_short' });
  try {
    const result = await db.resetPasswordByToken(token, newPassword);
    if (!result.ok) return res.json(result);
    // Письмо об успешной смене пароля
    if (result.user?.email) {
      await sendEmail(result.user.email,
        '✅ Пароль успешно изменён — БухОтчет',
        `<p>Здравствуйте, <strong>${result.user.full_name}</strong>!</p>
        <p>Ваш пароль на портале <strong>БухОтчет</strong> был успешно изменён.</p>
        <div class="highlight">
          <strong>Данные для входа:</strong><br>
          Логин: <strong>${result.user.login}</strong><br>
          Пароль: новый (указан при сбросе)
        </div>
        <a class="btn" href="${SITE}">Войти на портал</a>
        <p>Если вы не меняли пароль — немедленно обратитесь к администратору.</p>`
      );
    }
    res.json({ ok:true });
  } catch(e) { console.error('[reset]', e); res.status(500).json({ ok:false, error:'server_error' }); }
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
    const u = await db.approveUser(parseInt(req.params.id), req.body?.tariff||'all');
    // Письмо пользователю об одобрении
    if (u?.email) {
      const tariffNames = { all:'Pro (ФНО 200 + ФНО 300)', fno200:'Базовый (ФНО 200)', fno300:'Базовый (ФНО 300)', none:'—' };
      const tariff = req.body?.tariff||'all';
      await sendEmail(u.email,
        '🎉 Ваш аккаунт активирован — БухОтчет',
        `<p>Здравствуйте, <strong>${u.full_name}</strong>!</p>
        <p>Ваша заявка на доступ к порталу <strong>БухОтчет</strong> одобрена!</p>
        <div class="highlight">
          <strong>Данные для входа:</strong><br>
          Логин: <strong>${u.login}</strong><br>
          Пароль: указан при регистрации<br>
          Тариф: <strong>${tariffNames[tariff]||tariff}</strong>
        </div>
        <a class="btn" href="${SITE}">Войти на портал →</a>
        <p>Добро пожаловать в БухОтчет! Если возникнут вопросы — свяжитесь с администратором.</p>`
      );
    }
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/admin/users/:id/tariff', requireAdmin, async (req, res) => {
  try { await db.updateUserTariff(parseInt(req.params.id), req.body?.tariff||'all'); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
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
app.get('/api/companies', requireAuth, requireDb, async (req, res) => {
  try { res.json({ ok:true, companies: await db.getUserCompanies(req.user.id) }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.put('/api/companies', requireAuth, requireDb, async (req, res) => {
  try { await db.saveUserCompanies(req.user.id, req.body?.companies||[]); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── KV ────────────────────────────────────────────────────────────────────────
app.get('/api/kv/:key', requireAuth, requireDb, async (req, res) => {
  try { res.json({ ok:true, value: await db.getKv(req.user.id, req.params.key) }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.put('/api/kv/:key', requireAuth, requireDb, async (req, res) => {
  try { await db.putKv(req.user.id, req.params.key, req.body?.value??null); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── SUB USERS ─────────────────────────────────────────────────────────────────
app.get('/api/sub-users', requireAuth, requireDb, async (req, res) => {
  try { res.json({ ok:true, users: await db.getSubUsers(req.user.id) }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.post('/api/sub-users', requireAuth, requireDb, async (req, res) => {
  try { res.json(await db.addSubUser(req.user.id, req.body?.login||'')); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

app.delete('/api/sub-users/:userId', requireAuth, requireDb, async (req, res) => {
  try { await db.removeSubUser(req.user.id, parseInt(req.params.userId)); res.json({ ok:true }); }
  catch(e) { res.status(500).json({ ok:false, error:'server_error' }); }
});

// ── STATIC ────────────────────────────────────────────────────────────────────
app.use(express.static(ROOT, {
  index: false,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control','no-cache,no-store,must-revalidate');
    else res.setHeader('Cache-Control','public,max-age=86400');
  }
}));

// Страница сброса пароля — отдаём portal (он сам разберётся по ?token=)
app.get('/reset-password', (_req, res) => {
  res.sendFile(path.join(ROOT, 'buhotchet_portal.html'));
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(ROOT, 'buhotchet_portal.html'));
});

// ── START ─────────────────────────────────────────────────────────────────────
async function start() {
  try {
    dbReady = await db.initDb();
    console.log(dbReady ? '[db] ✓ PostgreSQL готов' : '[db] ✗ Без БД');
  } catch(e) {
    console.error('[db] Ошибка:', e.message);
    dbReady = false;
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] ✓ ${SITE} (port ${PORT})`);
  });
}

start();
