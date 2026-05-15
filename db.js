'use strict';

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false } : false
});

function hashPassword(password) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(password + 'buhotchet_salt_2026').digest('hex');
}
function generateToken() {
  return require('crypto').randomBytes(32).toString('hex');
}

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
      created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      approved_at   TIMESTAMPTZ
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
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);
    CREATE INDEX IF NOT EXISTS idx_kv_user ON kv_store (user_id);
  `);
  const adminLogin = process.env.ADMIN_LOGIN || 'admin01';
  const adminHash  = hashPassword(process.env.ADMIN_PASSWORD || 'PmS@t2026PmS@t2026');
  await pool.query(`
    INSERT INTO users (login,password_hash,full_name,role,status,tariff)
    VALUES ($1,$2,'Администратор','admin','approved','all')
    ON CONFLICT (login) DO UPDATE SET password_hash=$2, role='admin', status='approved', tariff='all'
  `, [adminLogin, adminHash]);
  return true;
}

async function loginUser(login, password) {
  const hash = hashPassword(password);
  const { rows } = await pool.query(
    `SELECT id,login,full_name,role,status,tariff FROM users WHERE login=$1 AND password_hash=$2`,
    [login.trim().toLowerCase(), hash]
  );
  if (!rows.length) return { ok:false, error:'wrong_credentials' };
  const u = rows[0];
  if (u.status==='pending') return { ok:false, error:'pending_approval' };
  if (u.status==='blocked')  return { ok:false, error:'blocked' };
  const token = generateToken();
  await pool.query(`INSERT INTO sessions (token,user_id) VALUES ($1,$2)`, [token, u.id]);
  return { ok:true, token, user:{ id:u.id, login:u.login, name:u.full_name, role:u.role, tariff:u.tariff } };
}

async function validateSession(token) {
  if (!token) return null;
  const { rows } = await pool.query(
    `SELECT u.id,u.login,u.full_name AS name,u.role,u.tariff,u.status
     FROM sessions s JOIN users u ON u.id=s.user_id
     WHERE s.token=$1 AND s.expires_at>NOW()`,
    [token]
  );
  if (!rows.length) return null;
  if (rows[0].status!=='approved' && rows[0].role!=='admin') return null;
  return rows[0];
}

async function logoutSession(token) {
  await pool.query(`DELETE FROM sessions WHERE token=$1`, [token]);
}

async function registerUser(data) {
  const { login, password, full_name, email, phone } = data;
  if (!login||!password||!full_name) return { ok:false, error:'missing_fields' };
  const ln = login.trim().toLowerCase();
  const { rows:ex } = await pool.query(`SELECT id FROM users WHERE login=$1`, [ln]);
  if (ex.length) return { ok:false, error:'login_taken' };
  const hash = hashPassword(password);
  await pool.query(
    `INSERT INTO users (login,password_hash,full_name,email,phone) VALUES ($1,$2,$3,$4,$5)`,
    [ln, hash, full_name.trim(), email||'', phone||'']
  );
  return { ok:true };
}

async function getPendingUsers() {
  const { rows } = await pool.query(
    `SELECT id,login,full_name,email,phone,created_at FROM users WHERE status='pending' ORDER BY created_at DESC`
  );
  return rows;
}

async function getAllUsers() {
  const { rows } = await pool.query(
    `SELECT id,login,full_name,email,phone,role,status,tariff,created_at,approved_at FROM users ORDER BY created_at DESC`
  );
  return rows;
}

async function approveUser(userId, tariff) {
  const t = ['fno200','fno300','all'].includes(tariff) ? tariff : 'all';
  await pool.query(
    `UPDATE users SET status='approved',tariff=$1,approved_at=NOW() WHERE id=$2`,
    [t, userId]
  );
}

async function updateUserTariff(userId, tariff) {
  const t = ['none','fno200','fno300','all'].includes(tariff) ? tariff : 'all';
  await pool.query(`UPDATE users SET tariff=$1 WHERE id=$2`, [t, userId]);
}

async function blockUser(userId) {
  await pool.query(`UPDATE users SET status='blocked' WHERE id=$1 AND role!='admin'`, [userId]);
}

async function unblockUser(userId) {
  await pool.query(`UPDATE users SET status='approved' WHERE id=$1`, [userId]);
}

async function deleteUser(userId) {
  await pool.query(`DELETE FROM users WHERE id=$1 AND role!='admin'`, [userId]);
}

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
    await pool.query(`INSERT INTO companies (user_id,data) VALUES ($1,$2::jsonb)`, [userId, JSON.stringify(data)]);
  }
}

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
    if (key && value!==undefined) await putKv(userId, key, value);
  }
}

module.exports = {
  pool, initDb, hashPassword,
  loginUser, validateSession, logoutSession, registerUser,
  getPendingUsers, getAllUsers, approveUser, updateUserTariff, blockUser, unblockUser, deleteUser,
  getUserCompanies, saveUserCompanies,
  getKv, putKv, bulkPutKv
};
