export default function Footer() {
  return (
    <footer className="site-footer">
      <div className="footer-grid shell">
        <div><div className="footer-brand">⌁ URLORA / URL INTELLIGENCE</div><p>A clear first line of defense for suspicious links, built to explain the signal behind every verdict.</p></div>
        <div><span className="footer-label">Product</span><a href="#scanner">URL inspector</a><a href="#dashboard">Model bench</a><a href="#about">Risk signals</a></div>
        <div><span className="footer-label">Resources</span><a href="#about">Dataset guide</a><a href="#about">Documentation</a><a href="#about">Safety notes</a></div>
        <div><span className="footer-label">Connect</span><a href="mailto:support@urlora.local">Contact support</a><a href="#privacy">Privacy</a><a href="#terms">Terms</a></div>
      </div>
      <div className="footer-bottom shell"><span>URLORA / URL SECURITY LAB</span><span>Explainable screening · the destination is never opened</span></div>
    </footer>
  );
}
