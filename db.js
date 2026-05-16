'use strict';
const { Pool } = require('pg');
const crypto = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false } : false
});

// ── ПАРОЛИ ────────────────────────────────────────────────────────────────────
function pbkdf2(password, salt) {
  return new Promise((res, rej) => {
    crypto.pbkdf2(String(password), salt, 100000, 32, 'sha256', (err, key) =>
      err ? rej(err) : res(key.toString('hex'))
    );
  });
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await pbkdf2(password, salt);
  return 'pbkdf2:' + salt + ':' + hash;
}

async function verifyPassword(password, stored) {
  if (!stored) return false;
  try {
    if (stored.startsWith('pbkdf2:')) {
      const parts = stored.split(':');  // ['pbkdf2', salt, hash]
      const salt = parts[1], hash = parts[2];
      const attempt = await pbkdf2(password, salt);
      return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(attempt,'hex'));
    }
    // Старый формат SHA-256 (legacy)
    const old = crypto.createHash('sha256').update(String(password) + 'buhotchet_salt_2026').digest('hex');
    return old === stored;
  } catch(e) { console.error('[auth] verifyPassword error:', e.message); return false; }
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

// ── RESET TOKEN ───────────────────────────────────────────────────────────────
// Для сброса пароля по ссылке
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ── INIT DB ───────────────────────────────────────────────────────────────────
async function initDb() {
  if (!process.env.DATABASE_URL) {
    console.warn('[db] DATABASE_URL не задан');
    return false;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id              SERIAL PRIMARY KEY,
      login           TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      full_name       TEXT NOT NULL DEFAULT '',
      email           TEXT NOT NULL DEFAULT '',
      phone           TEXT NOT NULL DEFAULT '',
      role            TEXT NOT NULL DEFAULT 'user',
      status          TEXT NOT NULL DEFAULT 'pending',
      tariff          TEXT NOT NULL DEFAULT 'none',
      desired_tariff  TEXT NOT NULL DEFAULT '',
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      approved_at     TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token       TEXT PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '30 days'
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
    CREATE TABLE IF NOT EXISTS sub_users (
      id         SERIAL PRIMARY KEY,
      owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(owner_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS reset_tokens (
      token      TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour',
      used       BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    -- Add desired_tariff column if not exists (safe migration)
    ALTER TABLE users ADD COLUMN IF NOT EXISTS desired_tariff TEXT NOT NULL DEFAULT '';
    CREATE INDEX IF NOT EXISTS idx_kv_user ON kv_store(user_id);
    CREATE INDEX IF NOT EXISTS idx_reset_tokens ON reset_tokens(expires_at);
  `);

  // ВСЕГДА обновляем пароль admin при старте — гарантированно свежий хеш
  const adminLogin = (process.env.ADMIN_LOGIN || 'admin01').toLowerCase();
  const adminPass  = process.env.ADMIN_PASSWORD || 'PmS@t2026PmS@t2026';
  const adminHash  = await hashPassword(adminPass);

  await pool.query(`
    INSERT INTO users (login, password_hash, full_name, role, status, tariff)
    VALUES ($1, $2, 'Администратор', 'admin', 'approved', 'all')
    ON CONFLICT (login) DO UPDATE
      SET password_hash = $2, role = 'admin', status = 'approved', tariff = 'all'
  `, [adminLogin, adminHash]);

  console.log(`[db] ✓ Admin "${adminLogin}" готов`);
  return true;
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
async function loginUser(login, password) {
  const ln = String(login||'').trim().toLowerCase();
  const { rows } = await pool.query(
    `SELECT id, login, full_name, role, status, tariff, password_hash FROM users WHERE login = $1`,
    [ln]
  );
  if (!rows.length) {
    console.log(`[auth] Login not found: ${ln}`);
    return { ok:false, error:'wrong_credentials' };
  }
  const u = rows[0];
  const ok = await verifyPassword(password, u.password_hash);
  if (!ok) {
    console.log(`[auth] Wrong password for: ${ln}, hash_prefix: ${u.password_hash.substring(0,20)}`);
    return { ok:false, error:'wrong_credentials' };
  }
  if (u.status === 'pending') return { ok:false, error:'pending_approval' };
  if (u.status === 'blocked')  return { ok:false, error:'blocked' };
  const token = generateToken();
  await pool.query(`INSERT INTO sessions(token, user_id) VALUES($1, $2)`, [token, u.id]);
  return {
    ok: true, token,
    user: { id:u.id, login:u.login, name:u.full_name, role:u.role, tariff:u.tariff }
  };
}

async function validateSession(token) {
  if (!token) return null;
  const { rows } = await pool.query(
    `SELECT u.id, u.login, u.full_name AS name, u.role, u.tariff, u.status
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = $1 AND s.expires_at > NOW()`,
    [token]
  );
  if (!rows.length) return null;
  const u = rows[0];
  if (u.status !== 'approved' && u.role !== 'admin') return null;
  return u;
}

async function logoutSession(token) {
  await pool.query(`DELETE FROM sessions WHERE token = $1`, [token]);
}

async function registerUser(data) {
  const { login, password, full_name, email, phone } = data;
  if (!login || !password || !full_name || !email)
    return { ok:false, error:'missing_fields' };
  if (password.length < 6) return { ok:false, error:'password_too_short' };
  const ln = String(login).trim().toLowerCase();
  if (!/^[a-z0-9_]+$/.test(ln)) return { ok:false, error:'invalid_login' };
  const { rows:ex } = await pool.query(`SELECT id FROM users WHERE login = $1`, [ln]);
  if (ex.length) return { ok:false, error:'login_taken' };
  const hash = await hashPassword(password);
  const desired = String(data.desired_tariff||'').trim().substring(0,50);
  await pool.query(
    `INSERT INTO users(login, password_hash, full_name, email, phone, desired_tariff)
     VALUES($1, $2, $3, $4, $5, $6)`,
    [ln, hash, full_name.trim(), email.trim(), phone||'', desired]
  );
  return { ok:true };
}

async function changePassword(userId, oldPassword, newPassword) {
  const { rows } = await pool.query(
    `SELECT password_hash FROM users WHERE id = $1`, [userId]
  );
  if (!rows.length) return { ok:false, error:'not_found' };
  const ok = await verifyPassword(oldPassword, rows[0].password_hash);
  if (!ok) return { ok:false, error:'wrong_password' };
  const hash = await hashPassword(newPassword);
  await pool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [hash, userId]);
  return { ok:true };
}

// ── FORGOT PASSWORD ───────────────────────────────────────────────────────────
async function createResetLink(login) {
  const ln = String(login||'').trim().toLowerCase();
  const { rows } = await pool.query(
    `SELECT id, full_name, email, login FROM users WHERE login = $1`,
    [ln]
  );
  if (!rows.length) return null;
  const u = rows[0];
  if (!u.email) return null;
  const token = generateResetToken();
  // Удалить старые токены этого пользователя
  await pool.query(`DELETE FROM reset_tokens WHERE user_id = $1`, [u.id]);
  await pool.query(
    `INSERT INTO reset_tokens(token, user_id) VALUES($1, $2)`, [token, u.id]
  );
  return { email:u.email, name:u.full_name, login:u.login, token };
}

async function resetPasswordByToken(token, newPassword) {
  const { rows } = await pool.query(
    `SELECT user_id FROM reset_tokens
     WHERE token = $1 AND expires_at > NOW() AND used = FALSE`,
    [token]
  );
  if (!rows.length) return { ok:false, error:'invalid_token' };
  const userId = rows[0].user_id;
  const hash = await hashPassword(newPassword);
  await pool.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [hash, userId]);
  await pool.query(`UPDATE reset_tokens SET used = TRUE WHERE token = $1`, [token]);
  // Получить email и логин для подтверждения
  const { rows:ur } = await pool.query(
    `SELECT email, login, full_name FROM users WHERE id = $1`, [userId]
  );
  return { ok:true, user: ur[0]||null };
}

async function getResetUser(token) {
  const { rows } = await pool.query(
    `SELECT u.email, u.login, u.full_name
     FROM reset_tokens rt JOIN users u ON u.id = rt.user_id
     WHERE rt.token = $1 AND rt.expires_at > NOW() AND rt.used = FALSE`,
    [token]
  );
  return rows[0]||null;
}

// ── ADMIN ─────────────────────────────────────────────────────────────────────
async function getPendingUsers() {
  const { rows } = await pool.query(
    `SELECT id, login, full_name, email, phone, created_at
     FROM users WHERE status = 'pending' ORDER BY created_at DESC`
  );
  return rows;
}

async function getAllUsers() {
  const { rows } = await pool.query(
    `SELECT id, login, full_name, email, phone, role, status, tariff, created_at, approved_at
     FROM users ORDER BY created_at DESC`
  );
  return rows;
}

async function approveUser(userId, tariff) {
  const t = ['fno200','fno300','all'].includes(tariff) ? tariff : 'all';
  await pool.query(
    `UPDATE users SET status = 'approved', tariff = $1, approved_at = NOW() WHERE id = $2`,
    [t, userId]
  );
  const { rows } = await pool.query(
    `SELECT email, login, full_name FROM users WHERE id = $1`, [userId]
  );
  return rows[0]||null;
}

async function updateUserTariff(userId, tariff) {
  const t = ['none','fno200','fno300','all'].includes(tariff) ? tariff : 'all';
  await pool.query(`UPDATE users SET tariff = $1 WHERE id = $2`, [t, userId]);
}

async function blockUser(userId) {
  await pool.query(
    `UPDATE users SET status = 'blocked' WHERE id = $1 AND role != 'admin'`, [userId]
  );
}

async function unblockUser(userId) {
  await pool.query(`UPDATE users SET status = 'approved' WHERE id = $1`, [userId]);
}

async function deleteUser(userId) {
  await pool.query(`DELETE FROM users WHERE id = $1 AND role != 'admin'`, [userId]);
}

// ── COMPANIES ─────────────────────────────────────────────────────────────────
async function getUserCompanies(userId) {
  const { rows } = await pool.query(
    `SELECT id, data FROM companies WHERE user_id = $1 ORDER BY id`, [userId]
  );
  return rows.map(r => ({ ...r.data, _db_id: r.id }));
}

async function saveUserCompanies(userId, arr) {
  await pool.query(`DELETE FROM companies WHERE user_id = $1`, [userId]);
  for (const c of (arr||[])) {
    const { _db_id, ...data } = c;
    await pool.query(
      `INSERT INTO companies(user_id, data) VALUES($1, $2::jsonb)`,
      [userId, JSON.stringify(data)]
    );
  }
}

// ── KV ────────────────────────────────────────────────────────────────────────
async function getKv(userId, key) {
  const { rows } = await pool.query(
    `SELECT value FROM kv_store WHERE user_id = $1 AND storage_key = $2`,
    [userId, key]
  );
  return rows.length ? rows[0].value : null;
}

async function putKv(userId, key, value) {
  await pool.query(
    `INSERT INTO kv_store(user_id, storage_key, value, updated_at)
     VALUES($1, $2, $3::jsonb, NOW())
     ON CONFLICT(user_id, storage_key)
     DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [userId, key, JSON.stringify(value)]
  );
}

async function bulkPutKv(userId, items) {
  for (const [key, value] of Object.entries(items||{})) {
    if (key && value !== undefined) await putKv(userId, key, value);
  }
}

// ── SUB USERS ─────────────────────────────────────────────────────────────────
async function getSubUsers(ownerId) {
  const { rows } = await pool.query(
    `SELECT u.id, u.login, u.full_name, u.email, u.status, u.tariff, s.created_at AS added_at
     FROM sub_users s JOIN users u ON u.id = s.user_id
     WHERE s.owner_id = $1 ORDER BY s.created_at`,
    [ownerId]
  );
  return rows;
}

async function addSubUser(ownerId, userLogin) {
  const { rows } = await pool.query(
    `SELECT id FROM users WHERE login = $1`, [userLogin.trim().toLowerCase()]
  );
  if (!rows.length) return { ok:false, error:'user_not_found' };
  const userId = rows[0].id;
  if (userId === ownerId) return { ok:false, error:'cannot_add_self' };
  try {
    await pool.query(
      `INSERT INTO sub_users(owner_id, user_id) VALUES($1, $2) ON CONFLICT DO NOTHING`,
      [ownerId, userId]
    );
    return { ok:true };
  } catch(e) { return { ok:false, error:'server_error' }; }
}

async function removeSubUser(ownerId, userId) {
  await pool.query(
    `DELETE FROM sub_users WHERE owner_id = $1 AND user_id = $2`, [ownerId, userId]
  );
}

module.exports = {
  pool, initDb,
  loginUser, validateSession, logoutSession, registerUser,
  changePassword, createResetLink, resetPasswordByToken, getResetUser,
  getPendingUsers, getAllUsers, approveUser, updateUserTariff,
  blockUser, unblockUser, deleteUser,
  getUserCompanies, saveUserCompanies,
  getKv, putKv, bulkPutKv,
  getSubUsers, addSubUser, removeSubUser
};
