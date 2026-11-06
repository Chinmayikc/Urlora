import test from 'node:test';
import assert from 'node:assert/strict';
import { extractFeatures, isModelReady, predictUrl } from './runtime.js';
import { readFileSync } from 'node:fs';

const cases = JSON.parse(readFileSync(new URL('../backend/tests/feature_golden.json', import.meta.url), 'utf8'));

test('Vercel runtime matches canonical feature golden cases', () => {
  for (const { url, expected } of cases) {
    const { values } = extractFeatures(url);
    for (const [name, value] of Object.entries(expected)) assert.equal(values[name], value, `${url}: ${name}`);
  }
});

test('exported trained model is usable even without best_iteration metadata', () => {
  assert.equal(isModelReady(), true);
  const result = predictUrl('https://example.com/');
  assert.equal(result.prediction, 'Safe');
  assert.equal(result.features.path_length, 0);
  const phishing = predictUrl('http://192.168.1.5/login/verify?password=1');
  assert.equal(phishing.prediction, 'Phishing');
  assert.equal(Number.isFinite(phishing.risk_score), true);
});
