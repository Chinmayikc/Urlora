import { AlertTriangle, CheckCircle2 } from 'lucide-react';

export default function ResultCard({ result, compact = false }) {
  const phishing = result.prediction === 1;
  return (
    <article className={phishing ? 'result-card phishing' : 'result-card'}>
      <div className="result-url">{result.url}</div>
      <div className="result-layout">
        <div>
          <div className="eyebrow">Random Forest verdict</div>
          <div className={phishing ? 'result-value danger' : 'result-value safe'}>{phishing ? <AlertTriangle size={25} /> : <CheckCircle2 size={25} />}{result.label}</div>
          <div className="risk-label">phishing risk · {(result.risk * 100).toFixed(1)}%</div>
          <div className="risk-meter"><div className={phishing ? 'risk-fill phishing' : 'risk-fill'} style={{ width: `${Math.max(4, result.risk * 100)}%` }} /></div>
          {!compact && <small>Scanned {new Date(result.scannedAt).toLocaleString()}</small>}
        </div>
        <div><div className="eyebrow">Signal trace</div><div className="signal-list">{result.signals.map((signal) => <div key={signal}>• {signal}</div>)}</div></div>
      </div>
    </article>
  );
}
