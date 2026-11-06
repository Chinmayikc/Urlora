import { isModelReady } from './runtime.js';

export default function handler(_req, res) {
  const modelReady = isModelReady();
  res.status(modelReady ? 200 : 503).json({ status: modelReady ? 'ok' : 'degraded', model_ready: modelReady, runtime: 'xgboost-json' });
};
