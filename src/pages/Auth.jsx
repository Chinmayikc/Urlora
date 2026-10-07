import { useState } from 'react';

export default function Auth({ onAuth }) {
  const [mode, setMode] = useState('signin');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  function submit(event) {
    event.preventDefault();
    if (!email.trim() || !password.trim() || (mode === 'signup' && !name.trim())) return setError('Complete all fields to continue.');
    onAuth({ name: mode === 'signup' ? name.trim() : email.split('@')[0], email: email.trim() });
  }

  return <main className="shell page-content narrow"><div className="eyebrow">ACCOUNT ACCESS</div><h2>Keep your scans close</h2><p className="page-intro">Create a demo Urlora account to keep scan history and view personal statistics.</p><div className="auth-card"><div className="auth-tabs"><button className={mode === 'signin' ? 'active' : ''} onClick={() => setMode('signin')}>Sign in</button><button className={mode === 'signup' ? 'active' : ''} onClick={() => setMode('signup')}>Sign up</button></div><form onSubmit={submit}>{mode === 'signup' && <label>Name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Your name" /></label>}<label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Your password" /></label>{error && <div className="error-message">{error}</div>}<button className="primary-button full" type="submit">{mode === 'signup' ? 'Create demo account' : 'Sign in to Urlora'}</button></form></div><small>Demo note: account data is stored in your browser. Add a database and password hashing before production use.</small></main>;
}
