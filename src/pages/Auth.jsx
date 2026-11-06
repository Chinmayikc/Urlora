import { useState } from 'react';
import { getAccount, hashPassword, saveAccount } from '../services/storage';

export default function Auth({ onAuth }) {
  const [mode, setMode] = useState('signin');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  async function submit(event) {
    event.preventDefault();
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail || !password || (mode === 'signup' && !name.trim())) return setError('Complete all fields to continue.');
    if (password.length < 8) return setError('Use a password with at least 8 characters.');
    setError('');
    const existing = getAccount(normalizedEmail);
    if (mode === 'signup') {
      if (existing) return setError('An account already exists for this email. Sign in instead.');
      const salt = crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`;
      saveAccount({ id: crypto.randomUUID?.() || `${Date.now()}`, name: name.trim(), email: normalizedEmail, salt, passwordHash: await hashPassword(password, salt) });
      return onAuth({ name: name.trim(), email: normalizedEmail, id: getAccount(normalizedEmail).id });
    }
    if (!existing || existing.passwordHash !== await hashPassword(password, existing.salt)) return setError('Email or password is incorrect.');
    onAuth({ name: existing.name, email: existing.email, id: existing.id });
  }

  return <main className="shell page-content narrow"><div className="eyebrow">ACCOUNT ACCESS</div><h2>Keep your scans close</h2><p className="page-intro">Create a local Urlora account to keep scan history private to this browser profile.</p><div className="auth-card"><div className="auth-tabs"><button type="button" className={mode === 'signin' ? 'active' : ''} onClick={() => setMode('signin')}>Sign in</button><button type="button" className={mode === 'signup' ? 'active' : ''} onClick={() => setMode('signup')}>Sign up</button></div><form onSubmit={submit}>{mode === 'signup' && <label>Name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Your name" /></label>}<label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" /></label><label>Password<input type="password" minLength="8" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 8 characters" /></label>{error && <div className="error-message">{error}</div>}<button className="primary-button full" type="submit">{mode === 'signup' ? 'Create local account' : 'Sign in to Urlora'}</button></form></div><small>This browser-only account stores a salted password hash, never the password itself. Use a real identity provider before production deployment.</small></main>;
}
