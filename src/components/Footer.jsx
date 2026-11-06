export default function Footer({ onNavigate }) {
  const link = (page, label) => <button className="footer-link" onClick={() => onNavigate(page)}>{label}</button>;
  return (
    <footer className="site-footer">
      <div className="footer-grid shell">
        <div><div className="footer-brand">⌁ URLORA / URL INTELLIGENCE</div><p>A clear first line of defense for suspicious links, built to explain the signal behind every verdict.</p></div>
        <div><span className="footer-label">Product</span>{link('scanner', 'URL inspector')}{link('dashboard', 'Model bench')}{link('about', 'Risk signals')}</div>
        <div><span className="footer-label">Resources</span>{link('about', 'Dataset guide')}{link('about', 'Documentation')}{link('about', 'Safety notes')}</div>
        <div><span className="footer-label">Connect</span><a href="mailto:support@urlora.local">Contact support</a>{link('about', 'Privacy')}{link('about', 'Terms')}</div>
      </div>
      <div className="footer-bottom shell"><span>URLORA / URL SECURITY LAB</span><span>Explainable screening · the destination is never opened</span></div>
    </footer>
  );
}
