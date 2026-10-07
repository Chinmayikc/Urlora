const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function predictUrl(url, userId) {
  const response = await fetch(`${API_BASE_URL}/predict`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(userId ? { 'X-User-Id': userId } : {}),
    },
    body: JSON.stringify({ url }),
  });

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
