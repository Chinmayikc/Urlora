const HISTORY_KEY = 'urlora.scanHistory';
const USER_KEY = 'urlora.user';

function readJson(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key)) ?? fallback;
  } catch {
    return fallback;
  }
}

export function getScanHistory() {
  return readJson(HISTORY_KEY, []);
}

export function saveScan(result) {
  const history = [result, ...getScanHistory()].slice(0, 50);
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  return history;
}

export function getUser() {
  return readJson(USER_KEY, null);
}

export function saveUser(user) {
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  return user;
}

export function clearUser() {
  localStorage.removeItem(USER_KEY);
}
