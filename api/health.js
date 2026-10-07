export default function handler(_req, res) {
  res.status(200).json({ status: 'ok', model_ready: true, runtime: 'xgboost-json' });
};
