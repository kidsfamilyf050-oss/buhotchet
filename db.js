'use strict';

const { Pool } = require('pg');
const crypto   = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

// ── ХЕШИРОВАНИЕ ПАРОЛЕЙ (bcrypt через нативный crypto PBKDF2) ────────────────
// Используем PBKDF2 — криптографически стойкий KDF, не требует нативных модулей
async function hashPassword(password) {
  const salt   = crypto.randomBytes(32).toString('hex');
  const hash   = await pbkdf2(password, salt);
  return salt + ':' + hash;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) {
    // Legacy SHA-256 — принимаем старый формат при первом входе
    const legacyHash = crypto.createHash('sha256')
      .update(password + 'buhotchet_salt_2026').digest('hex');
    return stored === legacyHash;
  }
  const [salt, hash] = stored.split(':');
  const attempt = await pbkdf2(password, salt);
  // Constant-time compare
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
}

function pbkdf2(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, 310000, 32, 'sha256', (err, key) => {
      if (err) reject(err);
      else resolve(key.toString('hex'));
    });
  });
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

// ── ИНИЦИАЛИЗАЦИЯ БД ──────────────────────────────────────────────────────────
async function initDb() {
  if (!process.env.DATABASE_URL) {
    console.warn('[db] DATABASE_URL не задан');
    return false;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      login         TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name     TEXT NOT NULL DEFAULT '',
      email         TEXT NOT NULL DEFAULT '',
      phone         TEXT NOT NULL DEFAULT '',
      role          TEXT NOT NULL DEFAULT 'user',
      status        TEXT NOT NULL DEFAULT 'pending',
      tariff        TEXT NOT NULL DEFAULT 'none',
      failed_logins INTEGER NOT NULL DEFAULT 0,
      locked_until  TIMESTAMPTZ,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      approved_at   TIMESTAMPTZ,
      last_login    TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token         TEXT PRIMARY KEY,
      user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      ip            TEXT,
      user_agent    TEXT,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days',
      last_used     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS companies (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      data       JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS kv_store (
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      storage_key TEXT NOT NULL,
      value       JSONB NOT NULL,
      updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (user_id, storage_key)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id         SERIAL PRIMARY KEY,
      user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action     TEXT NOT NULL,
      ip         TEXT,
      details    JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expires  ON sessions (expires_at);
    CREATE INDEX IF NOT EXISTS idx_sessions_user     ON sessions (user_id);
    CREATE INDEX IF NOT EXISTS idx_kv_user           ON kv_store (user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user        ON audit_log (user_id, created_at DESC);
  `);

  // Создать/обновить admin
  const adminLogin = (process.env.ADMIN_LOGIN || 'admin01').toLowerCase();
  const adminPass  = process.env.ADMIN_PASSWORD || 'PmS@t2026PmS@t2026';
  const { rows } = await pool.query(`SELECT id, password_hash FROM users WHERE login=$1`, [adminLogin]);
  if (!rows.length) {
    const hash = await hashPassword(adminPass);
    await pool.query(
      `INSERT INTO users (login,password_hash,full_name,role,status,tariff)
       VALUES ($1,$2,'Администратор','admin','approved','all')`,
      [adminLogin, hash]
    );
    console.log('[db] Admin создан');
  } else if (rows[0].password_hash && !rows[0].password_hash.includes(':')) {
    // Обновить legacy hash до PBKDF2
    const hash = await hashPassword(adminPass);
    await pool.query(`UPDATE users SET password_hash=$1 WHERE login=$2`, [hash, adminLogin]);
    console.log('[db] Admin hash обновлён до PBKDF2');
  }
  return true;
}

// ── AUTH ─────────────────────────────────────────────────────────────────────
async function loginUser(login, password, ip, userAgent) {
  const ln = login.trim().toLowerCase();
  const { rows } = await pool.query(
    `SELECT id,login,full_name,role,status,tariff,password_hash,failed_logins,locked_until
     FROM users WHERE login=$1`,
    [ln]
  );
  if (!rows.length) {
    // Фиктивная задержка чтобы не раскрывать существование логина
    await new Promise(r => setTimeout(r, 300 + Math.random() * 200));
    return { ok:false, error:'wrong_credentials' };
  }
  const u = rows[0];

  // Проверка блокировки после неверных попыток
  if (u.locked_until && new Date(u.locked_until) > new Date()) {
    const mins = Math.ceil((new Date(u.locked_until) - new Date()) / 60000);
    return { ok:false, error:'locked', mins };
  }

  if (u.status === 'pending') return { ok:false, error:'pending_approval' };
  if (u.status === 'blocked')  return { ok:false, error:'blocked' };

  const valid = await verifyPassword(password, u.password_hash);
  if (!valid) {
    const fails = u.failed_logins + 1;
    const lockUntil = fails >= 5
      ? new Date(Date.now() + 15 * 60000) // блок 15 мин после 5 попыток
      : null;
    await pool.query(
      `UPDATE users SET failed_logins=$1, locked_until=$2 WHERE id=$3`,
      [fails, lockUntil, u.id]
    );
    await audit(u.id, 'login_failed', ip, { login: ln, attempt: fails });
    return { ok:false, error:'wrong_credentials' };
  }

  // Сброс счётчика неудач
  await pool.query(
    `UPDATE users SET failed_logins=0, locked_until=NULL, last_login=NOW() WHERE id=$1`,
    [u.id]
  );

  const token = generateToken();
  await pool.query(
    `INSERT INTO sessions (token,user_id,ip,user_agent) VALUES ($1,$2,$3,$4)`,
    [token, u.id, ip||null, userAgent||null]
  );
  await audit(u.id, 'login_success', ip, { login: ln });

  // Если был legacy hash — обновить до PBKDF2
  if (!u.password_hash.includes(':')) {
    const newHash = await hashPassword(password);
    await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [newHash, u.id]);
  }

  return { ok:true, token, user:{ id:u.id, login:u.login, name:u.full_name, role:u.role, tariff:u.tariff } };
}

async function validateSession(token) {
  if (!token || token.length < 64) return null;
  const { rows } = await pool.query(
    `SELECT u.id,u.login,u.full_name AS name,u.role,u.tariff,u.status
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.token=$1 AND s.expires_at>NOW()`,
    [token]
  );
  if (!rows.length) return null;
  if (rows[0].status !== 'approved' && rows[0].role !== 'admin') return null;
  // Обновить last_used
  pool.query(`UPDATE sessions SET last_used=NOW() WHERE token=$1`, [token]).catch(()=>{});
  return rows[0];
}

async function logoutSession(token) {
  await pool.query(`DELETE FROM sessions WHERE token=$1`, [token]);
}

async function logoutAllSessions(userId) {
  await pool.query(`DELETE FROM sessions WHERE user_id=$1`, [userId]);
}

async function registerUser(data) {
  const { login, password, full_name, email, phone } = data;
  if (!login||!password||!full_name) return { ok:false, error:'missing_fields' };
  if (password.length < 8) return { ok:false, error:'password_too_short' };

  const ln = login.trim().toLowerCase();
  if (!/^[a-z0-9_]{3,32}$/.test(ln)) return { ok:false, error:'invalid_login' };

  const { rows:ex } = await pool.query(`SELECT id FROM users WHERE login=$1`, [ln]);
  if (ex.length) return { ok:false, error:'login_taken' };

  const hash = await hashPassword(password);
  await pool.query(
    `INSERT INTO users (login,password_hash,full_name,email,phone) VALUES ($1,$2,$3,$4,$5)`,
    [ln, hash, full_name.trim(), email||'', phone||'']
  );
  return { ok:true };
}

async function changePassword(userId, oldPass, newPass) {
  if (!newPass || newPass.length < 8) return { ok:false, error:'password_too_short' };
  const { rows } = await pool.query(`SELECT password_hash FROM users WHERE id=$1`, [userId]);
  if (!rows.length) return { ok:false, error:'not_found' };
  const valid = await verifyPassword(oldPass, rows[0].password_hash);
  if (!valid) return { ok:false, error:'wrong_password' };
  const hash = await hashPassword(newPass);
  await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, userId]);
  await logoutAllSessions(userId);
  return { ok:true };
}

// ── AUDIT LOG ─────────────────────────────────────────────────────────────────
async function audit(userId, action, ip, details) {
  try {
    await pool.query(
      `INSERT INTO audit_log (user_id,action,ip,details) VALUES ($1,$2,$3,$4::jsonb)`,
      [userId||null, action, ip||null, JSON.stringify(details||{})]
    );
  } catch(e) { /* не критично */ }
}

// ── ADMIN ─────────────────────────────────────────────────────────────────────
async function getPendingUsers() {
  const { rows } = await pool.query(
    `SELECT id,login,full_name,email,phone,created_at FROM users WHERE status='pending' ORDER BY created_at DESC`
  );
  return rows;
}

async function getAllUsers() {
  const { rows } = await pool.query(
    `SELECT id,login,full_name,email,phone,role,status,tariff,created_at,approved_at,last_login,failed_logins
     FROM users ORDER BY created_at DESC`
  );
  return rows;
}

async function approveUser(userId, tariff) {
  const t = ['fno200','fno300','all'].includes(tariff) ? tariff : 'all';
  await pool.query(
    `UPDATE users SET status='approved',tariff=$1,approved_at=NOW(),failed_logins=0,locked_until=NULL WHERE id=$2`,
    [t, userId]
  );
}

async function updateUserTariff(userId, tariff) {
  const t = ['none','fno200','fno300','all'].includes(tariff) ? tariff : 'all';
  await pool.query(`UPDATE users SET tariff=$1 WHERE id=$2`, [t, userId]);
}

async function blockUser(userId) {
  await pool.query(`UPDATE users SET status='blocked' WHERE id=$1 AND role!='admin'`, [userId]);
  await logoutAllSessions(userId);
}

async function unblockUser(userId) {
  await pool.query(
    `UPDATE users SET status='approved',failed_logins=0,locked_until=NULL WHERE id=$1`,
    [userId]
  );
}

async function deleteUser(userId) {
  await pool.query(`DELETE FROM users WHERE id=$1 AND role!='admin'`, [userId]);
}

// ── FORGOT PASSWORD ───────────────────────────────────────────────────────────
async function createResetToken(login) {
  const { rows } = await pool.query(
    `SELECT id,full_name,email FROM users WHERE login=$1 AND status='approved'`,
    [login.toLowerCase()]
  );
  if (!rows.length) return null;
  const u = rows[0];
  if (!u.email) return null;
  // Генерируем случайный временный пароль
  const tempPass = crypto.randomBytes(6).toString('hex').toUpperCase();
  const hash = await hashPassword(tempPass);
  await pool.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, u.id]);
  await logoutAllSessions(u.id);
  await audit(u.id, 'password_reset', null, {});
  return { email:u.email, name:u.full_name, tempPass };
}

// ── COMPANIES ─────────────────────────────────────────────────────────────────
async function getUserCompanies(userId) {
  const { rows } = await pool.query(
    `SELECT id,data FROM companies WHERE user_id=$1 ORDER BY id`,
    [userId]
  );
  return rows.map(r => ({ ...r.data, _db_id:r.id }));
}

async function saveUserCompanies(userId, arr) {
  await pool.query(`DELETE FROM companies WHERE user_id=$1`, [userId]);
  for (const c of (arr||[])) {
    const { _db_id, ...data } = c;
    await pool.query(
      `INSERT INTO companies (user_id,data) VALUES ($1,$2::jsonb)`,
      [userId, JSON.stringify(data)]
    );
  }
}

// ── KV ────────────────────────────────────────────────────────────────────────
async function getKv(userId, key) {
  const { rows } = await pool.query(
    `SELECT value FROM kv_store WHERE user_id=$1 AND storage_key=$2`,
    [userId, key]
  );
  return rows.length ? rows[0].value : null;
}

async function putKv(userId, key, value) {
  await pool.query(
    `INSERT INTO kv_store (user_id,storage_key,value,updated_at) VALUES ($1,$2,$3::jsonb,NOW())
     ON CONFLICT (user_id,storage_key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`,
    [userId, key, JSON.stringify(value)]
  );
}

async function bulkPutKv(userId, items) {
  for (const [key,value] of Object.entries(items||{})) {
    if (key && value !== undefined) await putKv(userId, key, value);
  }
}

module.exports = {
  pool, initDb, audit,
  loginUser, validateSession, logoutSession, registerUser, changePassword,
  getPendingUsers, getAllUsers, approveUser, updateUserTariff,
  blockUser, unblockUser, deleteUser, createResetToken,
  getUserCompanies, saveUserCompanies,
  getKv, putKv, bulkPutKv
};
