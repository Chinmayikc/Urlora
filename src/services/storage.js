const HISTORY_KEY_PREFIX = 'urlora.scanHistory:';
const ACCOUNT_KEY_PREFIX = 'urlora.account:';
const USER_KEY = 'urlora.session';

function readJson(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

export function getScanHistory() {
  const user = getUser();
  return user?.id ? readJson(`${HISTORY_KEY_PREFIX}${user.id}`, []) : [];
}

export function saveScan(result) {
  const user = getUser();
  if (!user?.id) return [];
  const history = [result, ...getScanHistory()].slice(0, 50);
  localStorage.setItem(`${HISTORY_KEY_PREFIX}${user.id}`, JSON.stringify(history));
  return history;
}

export function getUser() {
  try {
    return JSON.parse(sessionStorage.getItem(USER_KEY)) ?? null;
  } catch {
    return null;
  }
}

export function saveUser(user) {
  sessionStorage.setItem(USER_KEY, JSON.stringify(user));
  return user;
}

export function clearUser() {
  sessionStorage.removeItem(USER_KEY);
}

function accountKey(email) {
  return `${ACCOUNT_KEY_PREFIX}${email.trim().toLowerCase()}`;
}

export function getAccount(email) {
  return readJson(accountKey(email), null);
}

export function saveAccount(account) {
  localStorage.setItem(accountKey(account.email), JSON.stringify(account));
  return account;
}

export async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: encoder.encode(salt), iterations: 120000, hash: 'SHA-256' }, key, 256);
  return Array.from(new Uint8Array(bits)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function clearScanHistory(userId = getUser()?.id) {
  if (userId) localStorage.removeItem(`${HISTORY_KEY_PREFIX}${userId}`);
}
