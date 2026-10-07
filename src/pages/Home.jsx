import { ArrowUpRight, Fingerprint, ScanLine } from 'lucide-react';
import MetricCard from '../components/MetricCard';

export default function Home({ onNavigate, history }) {
  return <main>
    <section className="hero shell">
      <div className="eyebrow teal">⌁ URLORA / URL INTELLIGENCE</div>
      <h1>Make the address<br /><em>earn your trust.</em></h1>
      <p>Urlora reads the structure of a URL before a page is opened. Get a quick risk readout, understand the signals, and slow down before you click.</p>
      <div className="hero-meta"><span>01 / lexical inspection</span><span>02 / explainable signals</span><span>03 / risk readout</span></div>
    </section>
    <section className="shell section-block">
      <div className="eyebrow">START HERE</div><h2>A calmer way to check a link</h2>
      <div className="card-grid three">
        <article className="info-card"><ScanLine className="card-icon" /><h3>Scan before you click</h3><p>Paste any address into the Urlora scanner and get a clear first-pass risk readout.</p><button className="inline-link" onClick={() => onNavigate('scanner')}>Open scanner <ArrowUpRight size={14} /></button></article>
        <article className="info-card"><Fingerprint className="card-icon" /><h3>Understand the signal</h3><p>See the lexical clues behind a prediction instead of receiving a black-box label.</p><button className="inline-link" onClick={() => onNavigate('about')}>How it works <ArrowUpRight size={14} /></button></article>
        <article className="info-card dark-card"><div className="eyebrow">LIVE STATUS</div><strong>Ready to screen</strong><p>Local demo scanner · no page visits · no third-party requests.</p></article>
      </div>
      <div className="metrics-row"><MetricCard label="Scans this session" value={history.length} /><MetricCard label="Signal families" value="04" /><MetricCard label="Models compared" value="03" accent /></div>
    </section>
  </main>;
}
