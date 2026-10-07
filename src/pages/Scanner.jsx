import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';

export default function Scanner({ initialUrl = '', onScan, isScanning = false, error: apiError = '' }) {
  const [url, setUrl] = useState(initialUrl);
  const [error, setError] = useState('');

  function submit(event) {
    event.preventDefault();
    if (!url.trim()) return setError('Enter a URL to inspect.');
    setError('');
    onScan(url.trim());
  }

  return <main className="shell page-content"><div className="eyebrow">URL SCANNER / 01</div><h2>Inspect an address before you trust it</h2><p className="page-intro">Urlora analyzes the URL text only. It never visits the destination, follows redirects, or sends the address to a third-party service.</p>
    <form className="scanner-panel" onSubmit={submit}><label htmlFor="scanner-url">Address under review</label><div className="scanner-input"><input id="scanner-url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/account" /><button className="primary-button" type="submit" disabled={isScanning}><ShieldCheck size={17} /> {isScanning ? 'Analyzing…' : 'Run safe scan'}</button></div>{(error || apiError) && <div className="error-message">{error || apiError}</div>}</form>
    <div className="card-grid three"><article className="info-card"><span className="step-number">01</span><h3>Structure</h3><p>Length, dots, hyphens, slashes, digits, and query characters.</p></article><article className="info-card"><span className="step-number">02</span><h3>Identity</h3><p>Hostname shape, raw IP addresses, and user-info tricks like @.</p></article><article className="info-card"><span className="step-number">03</span><h3>Language</h3><p>Credential, payment, login, and verification words that raise risk.</p></article></div>
  </main>;
}
