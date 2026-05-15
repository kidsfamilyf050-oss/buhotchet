/**
 * Клиент API БухОтчет — синхронизация localStorage ↔ PostgreSQL (Railway).
 * На GitHub Pages: <meta name="buhotchet-api" content="https://ваш-проект.up.railway.app">
 */
(function (global) {
  const DEVICE_KEY = 'buhotchet_device_id';
  const MIGRATED_KEY = 'buhotchet_api_migrated';

  let apiBase = null;
  let online = false;
  let initPromise = null;

  function getDeviceId() {
    let id = localStorage.getItem(DEVICE_KEY);
    if (!id) {
      id = 'd_' + (crypto.randomUUID ? crypto.randomUUID() : Date.now() + '_' + Math.random().toString(36).slice(2));
      localStorage.setItem(DEVICE_KEY, id);
    }
    return id;
  }

  function resolveApiBase() {
    const meta = document.querySelector('meta[name="buhotchet-api"]');
    if (meta && meta.content) return meta.content.replace(/\/$/, '');
    if (location.hostname.includes('railway.app') || location.hostname === 'localhost') return '';
    return null;
  }

  async function apiFetch(path, options) {
    const base = apiBase === null ? '' : apiBase;
    const headers = Object.assign(
      { 'Content-Type': 'application/json', 'X-Device-Id': getDeviceId() },
      (options && options.headers) || {}
    );
    const res = await fetch(base + path, Object.assign({}, options, { headers }));
    if (!res.ok) throw new Error('api_' + res.status);
    return res.json();
  }

  async function init() {
    if (initPromise) return initPromise;
    initPromise = (async () => {
      apiBase = resolveApiBase();
      if (apiBase === null) {
        online = false;
        return false;
      }
      try {
        const health = await apiFetch('/api/health');
        online = !!(health && health.ok && health.db);
        if (online && !localStorage.getItem(MIGRATED_KEY)) {
          await migrateLocalToServer();
          localStorage.setItem(MIGRATED_KEY, '1');
        }
        return online;
      } catch (e) {
        online = false;
        return false;
      }
    })();
    return initPromise;
  }

  function isOnline() {
    return online;
  }

  async function getPortal() {
    if (!online) return null;
    return apiFetch('/api/portal');
  }

  async function savePortal(companies, active) {
    if (!online) return false;
    await apiFetch('/api/portal', {
      method: 'PUT',
      body: JSON.stringify({ companies, active })
    });
    return true;
  }

  async function getKv(key) {
    if (!online) return null;
    const r = await apiFetch('/api/kv/' + encodeURIComponent(key));
    return r.value;
  }

  async function putKv(key, value) {
    if (!online) return false;
    await apiFetch('/api/kv/' + encodeURIComponent(key), {
      method: 'PUT',
      body: JSON.stringify({ value })
    });
    return true;
  }

  async function migrateLocalToServer() {
    const companies = JSON.parse(localStorage.getItem('buhotchet_companies') || '[]');
    const active = JSON.parse(localStorage.getItem('buhotchet_active_company') || 'null');
    await savePortal(companies, active);

    const items = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key) continue;
      if (
        key.startsWith('fno300_data_') ||
        key.startsWith('payroll-kz-') ||
        key === 'payrollKZ_users_v2' ||
        key === 'payrollKZ_session_v2' ||
        key.startsWith('fno300_')
      ) {
        try {
          items[key] = JSON.parse(localStorage.getItem(key));
        } catch (e) {
          items[key] = localStorage.getItem(key);
        }
      }
    }
    if (Object.keys(items).length) {
      await apiFetch('/api/kv/bulk', { method: 'POST', body: JSON.stringify({ items }) });
    }
  }

  /** Подтянуть KV с сервера в localStorage (для iframe ФНО). */
  async function pullKvToLocal(key) {
    if (!online) return false;
    const val = await getKv(key);
    if (val === null || val === undefined) return false;
    localStorage.setItem(key, typeof val === 'string' ? val : JSON.stringify(val));
    return true;
  }

  global.BuhotchetAPI = {
    init,
    isOnline,
    getDeviceId,
    getPortal,
    savePortal,
    getKv,
    putKv,
    pullKvToLocal,
    migrateLocalToServer
  };
})(typeof window !== 'undefined' ? window : global);
