const configuredApiUrl = (import.meta.env.VITE_API_URL || '').trim().replace(/\/+$/, '');

function getApiBaseUrl() {
  if (configuredApiUrl && /^https?:\/\//i.test(configuredApiUrl)) return configuredApiUrl;
  if (typeof window !== 'undefined' && !['localhost', '127.0.0.1'].includes(window.location.hostname)) {
    return '/api';
  }
  return 'http://localhost:8000';
}

function validateUrl(rawUrl) {
  const url = rawUrl.trim();
  if (!url) throw new Error('Enter a URL to inspect.');
  if (url.length > 4096) throw new Error('URL is too long; maximum length is 4096 characters.');
  if (/\s/.test(url)) throw new Error('URL cannot contain whitespace.');
  const schemeMatch = url.match(/^([a-z][a-z\d+.-]*):/i);
  if (schemeMatch && !['http', 'https'].includes(schemeMatch[1].toLowerCase())) {
    throw new Error('Only HTTP and HTTPS URLs are supported.');
  }
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(url) ? url : `http://${url}`;
  let parsed;
  try { parsed = new URL(candidate); } catch { throw new Error('Enter a valid URL with a hostname.'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only HTTP and HTTPS URLs are supported.');
  if (!parsed.hostname) throw new Error('Enter a valid URL with a hostname.');
  return url;
}

export async function predictUrl(url) {
  const normalizedUrl = validateUrl(url);
  let response;
  try {
    response = await fetch(`${getApiBaseUrl()}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: normalizedUrl }),
    });
  } catch {
    throw new Error('Unable to reach the Urlora backend. Check that the API is deployed and VITE_API_URL is correct.');
  }

  let body;
  try {
    body = await response.json();
  } catch {
    body = {};
  }
  if (!response.ok) throw new Error(body.detail || `Prediction request failed (${response.status}).`);
  return body;
}

export function normalizePrediction(result) {
  const phishing = result.prediction === 'Phishing' || result.prediction === 1;
  return {
    ...result,
    prediction: phishing ? 1 : 0,
    label: phishing ? 'PHISHING URL' : 'LIKELY SAFE',
    risk: typeof result.risk_score === 'number' ? result.risk_score / 100 : result.risk,
    signals: result.reasons || result.signals || [],
    scannedAt: result.created_at || result.scannedAt || new Date().toISOString(),
  };
}
