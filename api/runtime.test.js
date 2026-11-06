import test from 'node:test';
import assert from 'node:assert/strict';
import { extractFeatures } from './runtime.js';
import { readFileSync } from 'node:fs';

const cases = JSON.parse(readFileSync(new URL('../backend/tests/feature_golden.json', import.meta.url), 'utf8'));

test('Vercel runtime matches canonical feature golden cases', () => {
  for (const { url, expected } of cases) {
    const { values } = extractFeatures(url);
    for (const [name, value] of Object.entries(expected)) assert.equal(values[name], value, `${url}: ${name}`);
  }
});
