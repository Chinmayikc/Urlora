const suspiciousKeywords = [
  'login', 'signin', 'verify', 'verification', 'secure', 'account', 'update',
  'password', 'bank', 'bonus', 'free', 'wallet', 'confirm', 'paypal',
  'payment', 'unlock', 'credential',
];

function isIpAddress(hostname) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
}

export function extractFeatures(rawUrl) {
  const url = rawUrl.trim();
  const normalized = /^[a-z][a-z\d+.-]*:\/\//i.test(url) ? url : `http://${url}`;
  let parsed;

  try {
    parsed = new URL(normalized);
  } catch {
    parsed = { hostname: '', pathname: '', search: '', protocol: '' };
  }

  const lower = url.toLowerCase();
  return {
    urlLength: url.length,
    hostnameLength: parsed.hostname.length,
    pathLength: parsed.pathname.length,
    queryLength: parsed.search.length,
    dots: (url.match(/\./g) || []).length,
    hyphens: (url.match(/-/g) || []).length,
    slashes: (url.match(/\//g) || []).length,
    digits: (url.match(/\d/g) || []).length,
    atSymbol: url.includes('@') ? 1 : 0,
    https: parsed.protocol === 'https:' ? 1 : 0,
    ipAddress: isIpAddress(parsed.hostname) ? 1 : 0,
    suspiciousKeywords: suspiciousKeywords.filter((word) => lower.includes(word)),
  };
}

export function explainUrl(url, features = extractFeatures(url)) {
  const signals = [];
  if (features.ipAddress) signals.push('The hostname is a raw IP address');
  if (features.atSymbol) signals.push('The URL uses an @ symbol to obscure the destination');
  if (!features.https) signals.push('The address does not use HTTPS');
  if (features.suspiciousKeywords.length) {
    signals.push(`${features.suspiciousKeywords.length} security or credential keyword(s) detected`);
  }
  if (features.urlLength > 75) signals.push('The URL is unusually long');
  if (features.dots >= 4) signals.push('The URL contains many dot-separated sections');
  return signals.length ? signals : ['No high-signal lexical warning was found'];
}

export function scanUrl(url) {
  const features = extractFeatures(url);
  let risk = 0.03;
  risk += features.https ? 0 : 0.12;
  risk += features.ipAddress ? 0.3 : 0;
  risk += features.atSymbol ? 0.22 : 0;
  risk += Math.min(features.suspiciousKeywords.length * 0.1, 0.45);
  risk += features.urlLength > 75 ? 0.08 : 0;
  risk += features.dots >= 4 ? 0.06 : 0;
  risk = Math.max(0.01, Math.min(0.99, risk));

  return {
    id: crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`,
    url: url.trim(),
    risk,
    prediction: risk >= 0.5 ? 1 : 0,
    label: risk >= 0.5 ? 'PHISHING URL' : 'LIKELY SAFE',
    signals: explainUrl(url, features),
    features,
    scannedAt: new Date().toISOString(),
  };
}
