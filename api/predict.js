import { predictUrl } from './runtime.js';

export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ detail: 'Method not allowed.' });
  try {
    const payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!payload || typeof payload.url !== 'string') return res.status(422).json({ detail: 'URL is required.' });
    return res.status(200).json(predictUrl(payload.url));
  } catch (error) {
    const status = /URL|hostname|HTTP|whitespace|long/.test(error.message) ? 422 : 500;
    return res.status(status).json({ detail: error.message });
  }
};
