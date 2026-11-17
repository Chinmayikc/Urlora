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

test('verified clean page can override a lexical false positive without changing the model artifact', () => {
  const result = predictUrl('https://www.flipkart.com/', {
    status: 'verified',
    domain_reputation: 'not_configured',
    page_content: 'verified',
    signals: ['Page content was fetched and matched the hostname'],
  });
  assert.equal(result.prediction, 'Safe');
  assert.equal(result.assessment, 'verified_page');
  assert.equal(result.risk_score, 5);
});
