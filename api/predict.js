import { predictUrl } from './runtime.js';

const WINDOW_MS = 60_000;
const MAX_REQUESTS = 30;
const requestsByClient = new Map();

function clientKey(req) {
  return (req.headers?.['x-forwarded-for'] || req.headers?.['x-real-ip'] || 'unknown').split(',')[0].trim();
}

function rateLimitExceeded(req) {
  const now = Date.now();
  for (const [key, entry] of requestsByClient) {
    if (entry.resetAt <= now) requestsByClient.delete(key);
  }
  const key = clientKey(req);
  const entry = requestsByClient.get(key);
  if (!entry || entry.resetAt <= now) {
    requestsByClient.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_REQUESTS;
}

export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ detail: 'Method not allowed.' });
  if (rateLimitExceeded(req)) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ detail: 'Too many scans. Please try again in a minute.' });
  }
  try {
    const payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!payload || typeof payload.url !== 'string') return res.status(422).json({ detail: 'URL is required.' });
    return res.status(200).json(predictUrl(payload.url));
  } catch (error) {
    const status = error instanceof SyntaxError || /URL|hostname|HTTP|whitespace|long/.test(error.message) ? 422 : 500;
    return res.status(status).json({ detail: error.message });
  }
};
