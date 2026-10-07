import { useState } from 'react';
import Header from './components/Header';
import Footer from './components/Footer';
import Home from './pages/Home';
import Scanner from './pages/Scanner';
import Result from './pages/Result';
import Auth from './pages/Auth';
import Dashboard from './pages/Dashboard';
import About from './pages/About';
import { normalizePrediction, predictUrl } from './services/api';
import { clearUser, getScanHistory, getUser, saveScan, saveUser } from './services/storage';

export default function App() {
  const [page, setPage] = useState('home');
  const [user, setUser] = useState(getUser);
  const [history, setHistory] = useState(getScanHistory);
  const [lastResult, setLastResult] = useState(null);
  const [pendingUrl, setPendingUrl] = useState('');
  const [scanError, setScanError] = useState('');
  const [isScanning, setIsScanning] = useState(false);

  function navigate(nextPage) {
    setPage(nextPage);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  async function handleScan(url) {
    setScanError('');
    setIsScanning(true);
    try {
      const result = normalizePrediction(await predictUrl(url, user?.id));
      setLastResult(result);
      setHistory(saveScan(result));
      navigate('result');
    } catch (error) {
      setScanError(error.message);
    } finally {
      setIsScanning(false);
    }
  }

  function handleHeaderScan(url) {
    setPendingUrl(url);
    navigate('scanner');
  }

  function handleAuth(nextUser) {
    const saved = saveUser({ ...nextUser, id: nextUser.id || crypto.randomUUID?.() || `${Date.now()}` });
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
    scanner: <Scanner initialUrl={pendingUrl} onScan={handleScan} isScanning={isScanning} error={scanError} />,
    result: <Result result={lastResult} onNavigate={navigate} />,
    auth: <Auth onAuth={handleAuth} />,
    dashboard: <Dashboard user={user} history={history} onNavigate={navigate} onSignOut={handleSignOut} />,
    about: <About />,
  }[page];

  return <div className="app-shell"><Header page={page} onNavigate={navigate} onScanRequest={handleHeaderScan} user={user} />{content}<Footer /></div>;
}
