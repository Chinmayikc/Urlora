import { useState } from 'react';
import { Bell, CircleHelp, Download, LogIn, Search, UserPlus } from 'lucide-react';

export default function Header({ page, onNavigate, onScanRequest, user }) {
  const [query, setQuery] = useState('');

  function submitSearch(event) {
    event.preventDefault();
    if (query.trim()) onScanRequest(query.trim());
  }

  return (
    <>
      <header className="topbar shell">
        <button className="brand-button" onClick={() => onNavigate('home')} aria-label="Go to Urlora home">
          <span className="brand-mark">⌁</span><span>URLORA</span>
        </button>
        <form className="header-search" onSubmit={submitSearch}>
          <Search size={17} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search or paste a URL to inspect" aria-label="Search URL" />
        </form>
        <button className="icon-button" onClick={submitSearch} title="Inspect URL" aria-label="Inspect URL"><Search size={17} /></button>
        <button className="icon-button" onClick={() => onNavigate('dashboard')} title="Download files" aria-label="Download files"><Download size={17} /></button>
        <button className="icon-button" onClick={() => window.alert('No new Urlora notifications.')} title="View notifications" aria-label="View notifications"><Bell size={17} /></button>
        <button className="icon-button" onClick={() => window.alert('Support: review the Urlora README for setup guidance.')} title="Contact support" aria-label="Contact support"><CircleHelp size={17} /></button>
        {user ? (
          <button className="text-button" onClick={() => onNavigate('dashboard')}>{user.name.split(' ')[0]}</button>
        ) : (
          <>
            <button className="text-button" onClick={() => onNavigate('auth')}><LogIn size={15} /> Sign in</button>
            <button className="primary-button compact" onClick={() => onNavigate('auth')}><UserPlus size={15} /> Sign up</button>
          </>
        )}
      </header>
      <nav className="navrow shell" aria-label="Primary navigation">
        {[['home', 'Home'], ['scanner', 'URL Scanner'], ['result', 'Result'], ['dashboard', 'Dashboard'], ['about', 'About / How it works']].map(([key, label]) => (
          <button key={key} className={page === key ? 'nav-link active' : 'nav-link'} onClick={() => onNavigate(key)}>{label}</button>
        ))}
      </nav>
    </>
  );
}
