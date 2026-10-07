import { useState } from 'react';
import Header from './components/Header';
import Footer from './components/Footer';
import Home from './pages/Home';
import Scanner from './pages/Scanner';
import Result from './pages/Result';
import Auth from './pages/Auth';
import Dashboard from './pages/Dashboard';
import About from './pages/About';
import { scanUrl } from './services/urlScanner';
import { clearUser, getScanHistory, getUser, saveScan, saveUser } from './services/storage';

export default function App() {
  const [page, setPage] = useState('home');
  const [user, setUser] = useState(getUser);
  const [history, setHistory] = useState(getScanHistory);
  const [lastResult, setLastResult] = useState(null);
  const [pendingUrl, setPendingUrl] = useState('');

  function navigate(nextPage) {
    setPage(nextPage);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function handleScan(url) {
    const result = scanUrl(url);
    setLastResult(result);
    setHistory(saveScan(result));
    navigate('result');
  }

  function handleHeaderScan(url) {
    setPendingUrl(url);
    navigate('scanner');
  }

  function handleAuth(nextUser) {
    const saved = saveUser(nextUser);
    setUser(saved);
    navigate('dashboard');
  }

  function handleSignOut() {
    clearUser();
    setUser(null);
    navigate('home');
  }

  const content = {
    home: <Home onNavigate={navigate} history={history} />,
    scanner: <Scanner initialUrl={pendingUrl} onScan={handleScan} />,
    result: <Result result={lastResult} onNavigate={navigate} />,
    auth: <Auth onAuth={handleAuth} />,
    dashboard: <Dashboard user={user} history={history} onNavigate={navigate} onSignOut={handleSignOut} />,
    about: <About />,
  }[page];

  return <div className="app-shell"><Header page={page} onNavigate={navigate} onScanRequest={handleHeaderScan} user={user} />{content}<Footer /></div>;
}
