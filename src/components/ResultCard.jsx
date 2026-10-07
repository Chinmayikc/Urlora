import { AlertTriangle, CheckCircle2 } from 'lucide-react';

export default function ResultCard({ result, compact = false }) {
  const phishing = result.prediction === 1;
  const risk = typeof result.risk_score === 'number' ? result.risk_score / 100 : result.risk;
  const confidence = typeof result.confidence === 'number' ? result.confidence : 1 - risk;
  const signals = result.reasons || result.signals || [];
  return (
    <article className={phishing ? 'result-card phishing' : 'result-card'}>
      <div className="result-url">{result.url}</div>
      <div className="result-layout">
        <div>
          <div className="eyebrow">Random Forest verdict</div>
          <div className={phishing ? 'result-value danger' : 'result-value safe'}>{phishing ? <AlertTriangle size={25} /> : <CheckCircle2 size={25} />}{result.label}</div>
          <div className="risk-label">phishing risk · {(risk * 100).toFixed(1)}% · confidence {(confidence * 100).toFixed(1)}%</div>
          <div className="risk-meter"><div className={phishing ? 'risk-fill phishing' : 'risk-fill'} style={{ width: `${Math.max(4, risk * 100)}%` }} /></div>
          {!compact && <small>Scanned {new Date(result.scannedAt).toLocaleString()}</small>}
        </div>
        <div><div className="eyebrow">Signal trace</div><div className="signal-list">{signals.map((signal) => <div key={signal}>• {signal}</div>)}</div></div>
      </div>
    </article>
  );
}
