import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';

const model = JSON.parse(readFileSync(new URL('./model.json', import.meta.url), 'utf8'));
const learner = model.learner;
const booster = learner.gradient_booster.model;
const featureNames = learner.feature_names;
const trees = booster.trees.slice(0, Number(learner.attributes.best_iteration) + 1);
const suspiciousKeywords = [
  'login', 'signin', 'verify', 'verification', 'secure', 'account', 'update',
  'password', 'bank', 'bonus', 'free', 'wallet', 'confirm', 'paypal',
  'payment', 'unlock', 'credential',
];
const shortenerHosts = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy']);
const suspiciousSymbols = new Set(['@', '%', '$', '!', '?', '=', ';', '{', '}', '[', ']', '<', '>']);

function normalizeUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) throw new Error('URL cannot be empty.');
  const url = rawUrl.trim();
  if (url.length > 4096) throw new Error('URL is too long; maximum length is 4096 characters.');
  if (/\s/.test(url)) throw new Error('URL cannot contain whitespace.');
  const scheme = url.match(/^([a-z][a-z\d+.-]*):/i);
  if (scheme && !['http', 'https'].includes(scheme[1].toLowerCase())) throw new Error('Only HTTP and HTTPS URLs are supported.');
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(url) ? url : `http://${url}`;
  let parsed;
  try { parsed = new URL(candidate); } catch { throw new Error('Enter a valid URL with a hostname.'); }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error('Enter a valid URL with a hostname.');
  return { url, parsed };
}

function extractFeatures(rawUrl) {
  const { url, parsed } = normalizeUrl(rawUrl);
  const hostname = parsed.hostname || '';
  const lowerUrl = url.toLowerCase();
  const chars = Array.from(url);
  const pathname = parsed.pathname === '/' ? '' : parsed.pathname;
  const specialCount = chars.filter((character) => suspiciousSymbols.has(character) || (!/[A-Za-z0-9]/.test(character) && !':/.-_'.includes(character))).length;
  const subdomainCount = isIP(hostname) ? 0 : Math.max(0, hostname.split('.').length - 2);
  const queryParameters = parsed.search ? Array.from(new URLSearchParams(parsed.search)).length : 0;
  const values = {
    url_length: chars.length,
    hostname_length: Array.from(hostname).length,
    path_length: Array.from(pathname).length,
    number_of_dots: (url.match(/\./g) || []).length,
    number_of_hyphens: (url.match(/-/g) || []).length,
    number_of_underscores: (url.match(/_/g) || []).length,
    number_of_digits: (url.match(/\d/g) || []).length,
    number_of_special_characters: specialCount,
    number_of_subdirectories: pathname.split('/').filter(Boolean).length,
    number_of_query_parameters: queryParameters,
    number_of_fragments: parsed.hash ? 1 : 0,
    number_of_subdomains: subdomainCount,
    uses_https: parsed.protocol === 'https:' ? 1 : 0,
    contains_ip_address: isIP(hostname) ? 1 : 0,
    contains_at_symbol: url.includes('@') ? 1 : 0,
    contains_suspicious_symbol: chars.some((character) => suspiciousSymbols.has(character)) ? 1 : 0,
    uses_url_shortener: shortenerHosts.has(hostname.toLowerCase()) ? 1 : 0,
    suspicious_keyword_count: suspiciousKeywords.filter((word) => lowerUrl.includes(word)).length,
    digit_ratio: (url.match(/\d/g) || []).length / Math.max(chars.length, 1),
    special_character_ratio: specialCount / Math.max(chars.length, 1),
  };
  return { url, values };
}

function explain(features) {
  const reasons = [];
  if (features.contains_ip_address) reasons.push('Hostname is a raw IP address');
  if (features.contains_at_symbol) reasons.push('@ symbol can obscure the destination');
  if (!features.uses_https) reasons.push('Address does not use HTTPS');
  if (features.uses_url_shortener) reasons.push('URL shortening service detected');
  if (features.suspicious_keyword_count) reasons.push('Suspicious login, credential, payment, or verification keyword detected');
  if (features.url_length > 75) reasons.push('Unusually long URL');
  if (features.number_of_subdomains >= 3) reasons.push('Multiple subdomains detected');
  if (features.contains_suspicious_symbol) reasons.push('Suspicious URL symbol pattern detected');
  return reasons.length ? reasons : ['No high-signal lexical warning was found'];
}

function treeScore(tree, vector) {
  let node = 0;
  while (tree.left_children[node] !== -1) {
    const feature = vector[tree.split_indices[node]];
    if (!Number.isFinite(feature)) {
      node = tree.default_left[node] ? tree.left_children[node] : tree.right_children[node];
    } else {
      node = feature < tree.split_conditions[node] ? tree.left_children[node] : tree.right_children[node];
    }
  }
  return tree.base_weights[node];
}

function predictUrl(rawUrl) {
  const { url, values } = extractFeatures(rawUrl);
  const vector = featureNames.map((name) => values[name]);
  const baseScore = Number(learner.learner_model_param.base_score);
  let margin = Math.log(baseScore / (1 - baseScore));
  for (const tree of trees) margin += treeScore(tree, vector);
  const probability = 1 / (1 + Math.exp(-margin));
  const phishing = probability >= 0.5;
  return {
    url,
    prediction: phishing ? 'Phishing' : 'Safe',
    confidence: Number((phishing ? probability : 1 - probability).toFixed(4)),
    risk_score: Math.round(probability * 100),
    reasons: explain(values),
    features: values,
    created_at: new Date().toISOString(),
  };
}

export { predictUrl };
