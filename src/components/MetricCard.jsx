export default function MetricCard({ label, value, accent = false }) {
  return <div className={accent ? 'metric-card accent' : 'metric-card'}><span>{label}</span><strong>{value}</strong></div>;
}
