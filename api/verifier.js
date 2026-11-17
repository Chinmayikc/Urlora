import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const MAX_PAGE_BYTES = 1_000_000;
const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 4_000;
const threatTypes = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];

function isPublicAddress(address) {
  if (isIP(address) === 4) {
    const octets = address.split('.').map(Number);
    const [a, b] = octets;
    return a !== 0 && a !== 10 && a !== 127 && a !== 169
      && !(a === 172 && b >= 16 && b <= 31)
      && !(a === 192 && b === 168)
      && !(a === 100 && b >= 64 && b <= 127)
      && !(a === 198 && b >= 18 && b <= 19)
      && a < 224;
  }
  const value = address.toLowerCase();
  return value !== '::' && value !== '::1' && !value.startsWith('fc') && !value.startsWith('fd')
    && !value.startsWith('fe8') && !value.startsWith('fe9') && !value.startsWith('fea') && !value.startsWith('feb');
}

async function assertPublicHost(hostname) {
  if (isIP(hostname)) {
    if (!isPublicAddress(hostname)) throw new Error('Private, local, or reserved destinations are not scanned.');
    return;
  }
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
    throw new Error('Private, local, or reserved destinations are not scanned.');
  }
}

function safeTarget(rawUrl) {
  const parsed = new URL(rawUrl);
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) throw new Error('Only HTTP and HTTPS URLs with a hostname can be verified.');
  if (parsed.username || parsed.password) throw new Error('URLs containing embedded credentials are not scanned.');
  return parsed;
}

async function checkedTarget(rawUrl) {
  const parsed = safeTarget(rawUrl);
  await assertPublicHost(parsed.hostname);
  parsed.hash = '';
  return parsed;
}

function baseDomain(hostname) {
  const labels = hostname.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  return labels.slice(-2).join('.');
}

async function readLimited(response) {
  if (!response.body) return response.text();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (total <= MAX_PAGE_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
    chunks.push(chunk);
    total += chunk.byteLength;
    if (total > MAX_PAGE_BYTES) {
      await reader.cancel();
      break;
    }
  }
  const joined = new Uint8Array(Math.min(total, MAX_PAGE_BYTES));
  let offset = 0;
  for (const chunk of chunks) {
    const length = Math.min(chunk.byteLength, joined.length - offset);
    if (length <= 0) break;
    joined.set(chunk.subarray(0, length), offset);
    offset += length;
  }
  return new TextDecoder().decode(joined);
}

function pageSignals(source, hostname) {
  const lower = source.toLowerCase();
  const titleMatch = source.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = (titleMatch?.[1] || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160);
  const text = source.replace(/<[^>]+>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/\s+/g, ' ').toLowerCase();
  const label = baseDomain(hostname).split('.')[0];
  const brandMatch = label.length >= 4 && new RegExp(`(^|[^a-z0-9])${label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`, 'i').test(text);
  const passwordForm = /<input[^>]+type\s*=\s*["']?password/i.test(lower);
  const credentialTerms = ['login', 'sign in', 'signin', 'verify', 'verification', 'password', 'credential', 'payment']
    .reduce((count, term) => count + (text.split(term).length - 1), 0);
  const signals = [];
  if (passwordForm) signals.push('Page contains a password input form');
  if (credentialTerms >= 3) signals.push('Page contains multiple login, verification, or payment terms');
  if (!brandMatch) signals.push('Page content does not clearly match the hostname');
  const externalForm = [...source.matchAll(/<form[^>]+action\s*=\s*["']([^"']+)/gi)].some((match) => {
    try { return baseDomain(new URL(match[1], `https://${hostname}/`).hostname) !== baseDomain(hostname); } catch { return false; }
  });
  if (externalForm) signals.push('A form submits to a different domain');
  const suspicious = externalForm || (passwordForm && credentialTerms >= 4 && !brandMatch);
  return {
    status: suspicious ? 'suspicious' : brandMatch ? 'verified' : 'inspected',
    signals: signals.length ? signals : ['Page content was fetched and matched the hostname'],
    title,
    brand_match: brandMatch,
  };
}

async function safeBrowsingCheck(url) {
  const key = (process.env.GOOGLE_SAFE_BROWSING_API_KEY || '').trim();
  if (!key) return { status: 'not_configured', provider: 'google_safe_browsing', detail: 'Reputation provider is not configured.' };
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'urlora', clientVersion: '1.0' },
        threatInfo: { threatTypes, platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }] },
      }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await response.json();
    return body.matches
      ? { status: 'malicious', provider: 'google_safe_browsing', detail: 'Reputation provider reported a threat.' }
      : { status: 'clean', provider: 'google_safe_browsing', detail: 'Reputation provider found no listed threat.' };
  } catch {
    return { status: 'unavailable', provider: 'google_safe_browsing', detail: 'Reputation check was unavailable.' };
  }
}

export async function verifyUrl(rawUrl) {
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`;
  const reputation = await safeBrowsingCheck(candidate);
  const result = {
    status: 'unverified',
    domain_reputation: reputation.status,
    page_content: 'unavailable',
    provider: reputation.provider,
    signals: [],
  };
  if (reputation.status === 'malicious') {
    return { ...result, status: 'malicious', signals: ['Domain reputation provider reported this URL as malicious.'] };
  }

  let current;
  try { current = await checkedTarget(candidate); } catch (error) {
    return { ...result, status: 'blocked', signals: [error.message] };
  }
  const originalHost = current.hostname;
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    let response;
    try {
      response = await fetch(current, {
        redirect: 'manual',
        headers: { accept: 'text/html,application/xhtml+xml', 'user-agent': 'UrloraSecurityScanner/1.0' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (error) {
      return { ...result, signals: [`Page could not be fetched: ${error.message || 'network error'}`] };
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) break;
      try { current = await checkedTarget(new URL(location, current).toString()); } catch (error) {
        return { ...result, status: 'suspicious', signals: [`Redirect target was blocked: ${error.message}`] };
      }
      continue;
    }
    const contentType = (response.headers.get('content-type') || '').split(';', 1)[0].toLowerCase();
    const base = { ...result, http_status: response.status, final_url: current.toString(), page_content_type: contentType };
    if (response.status < 200 || response.status >= 400) return { ...base, signals: [`Page returned HTTP ${response.status}; content was not treated as verified.`] };
    if (!['text/html', 'application/xhtml+xml'].includes(contentType)) return { ...base, page_content: 'non_html', status: 'inspected', signals: [`Page returned ${contentType || 'non-HTML'} content; HTML identity checks were skipped.`] };
    const page = pageSignals(await readLimited(response), current.hostname);
    const sameDomain = baseDomain(originalHost) === baseDomain(current.hostname);
    const signals = [...page.signals];
    if (!sameDomain) signals.unshift('Page redirected to a different registrable domain');
    return { ...base, status: !sameDomain || page.status === 'suspicious' ? 'suspicious' : page.status, page_content: page.status, page_title: page.title, brand_match: page.brand_match, signals };
  }
  return { ...result, signals: ['The URL exceeded the redirect limit.'] };
}
