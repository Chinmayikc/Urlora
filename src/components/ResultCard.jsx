import { AlertTriangle, CheckCircle2, SearchCheck } from 'lucide-react';

export default function ResultCard({ result, compact = false }) {
  const phishing = result.prediction === 1;
  const review = result.prediction === 2;
  const risk = typeof result.risk_score === 'number' ? result.risk_score / 100 : result.risk;
  const confidence = typeof result.confidence === 'number' ? result.confidence : 1 - risk;
  const signals = result.reasons || result.signals || [];
  const assessment = result.assessment || '';
  const knownSafe = result.assessment === 'known_safe_domain';
  const heuristicOnly = result.assessment === 'heuristic_only';
  const displayLabel = assessment === 'verified_page' ? 'VERIFIED PAGE · LIKELY SAFE' : assessment === 'verified_suspicious' ? 'PHISHING SIGNALS · PAGE VERIFIED' : assessment === 'needs_review' ? 'NEEDS REVIEW · VERIFICATION INCOMPLETE' : knownSafe ? 'KNOWN-SAFE DOMAIN · SCREENING ONLY' : heuristicOnly ? `${phishing ? 'PHISHING SIGNALS' : 'LIKELY SAFE'} · HEURISTIC ONLY` : result.label;
  return (
    <article className={phishing ? 'result-card phishing' : review ? 'result-card review' : 'result-card'}>
      <div className="result-url">{result.url}</div>
      <div className="result-layout">
        <div>
          <div className="eyebrow">XGBoost verdict</div>
          <div className={phishing ? 'result-value danger' : review ? 'result-value review-value' : 'result-value safe'}>{phishing ? <AlertTriangle size={25} /> : review ? <SearchCheck size={25} /> : <CheckCircle2 size={25} />}{displayLabel}</div>
          <div className="risk-label">screening risk · {(risk * 100).toFixed(1)}% · confidence (not accuracy) {(confidence * 100).toFixed(1)}%</div>
          <div className="risk-meter"><div className={phishing ? 'risk-fill phishing' : review ? 'risk-fill review-fill' : 'risk-fill'} style={{ width: `${Math.max(4, risk * 100)}%` }} /></div>
          {!compact && <p className="calibration-note">{result.calibrationNote || 'Verification status is shown below; do not treat an inconclusive result as safe.'}</p>}
          {!compact && <small>Scanned {new Date(result.scannedAt).toLocaleString()}</small>}
        </div>
        <div><div className="eyebrow">Signal trace</div><div className="signal-list">{signals.map((signal) => <div key={signal}>• {signal}</div>)}{result.verification?.signals?.map((signal) => <div key={`verification-${signal}`}>• {signal}</div>)}</div></div>
      </div>
    </article>
  );
}
