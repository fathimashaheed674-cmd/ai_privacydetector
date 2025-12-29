import { useState, useEffect, useMemo } from 'react';
import Tesseract from 'tesseract.js';
import RiskSummary from './components/RiskSummary';
import Auth from './components/Auth';
import ScanHistory from './components/ScanHistory';
import CustomPatternModal from './components/CustomPatternModal';
import BulkProcessor from './components/BulkProcessor';
import './App.css';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [user, setUser] = useState(localStorage.getItem('user'));

  // Dynamic API URL for deployment
  const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000' : '');

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [ocrProgress, setOcrProgress] = useState(null);
  const [historyKey, setHistoryKey] = useState(0);
  const [activeTab, setActiveTab] = useState('scanner');
  const [copySuccess, setCopySuccess] = useState(false);
  const [customPatterns, setCustomPatterns] = useState({});
  const [isPatternModalOpen, setIsPatternModalOpen] = useState(false);
  const [ocrWorker, setOcrWorker] = useState(null);

  // Initialize OCR Worker on mount for performance optimization
  useEffect(() => {
    let worker;
    const initWorker = async () => {
      worker = await Tesseract.createWorker();
      await worker.loadLanguage('eng');
      await worker.initialize('eng');
      setOcrWorker(worker);
    };
    initWorker();

    return () => {
      if (worker) {
        worker.terminate();
      }
    };
  }, []);

  useEffect(() => {
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
  }, []);

  const sendNotification = (title, message) => {
    if ("Notification" in window && Notification.permission === "granted") {
      new Notification(title, { body: message, icon: "/shield-logo.png" });
    }
  };

  const handleLogin = (accessToken, username) => {
    localStorage.setItem('token', accessToken);
    localStorage.setItem('user', username);
    setToken(accessToken);
    setUser(username);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
    setResult(null);
    setInputText('');
  };

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const response = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          text: inputText,
          custom_patterns: customPatterns
        }),
      });

      if (response.status === 401) {
        handleLogout();
        throw new Error('Session expired. Please login again.');
      }

      if (!response.ok) {
        throw new Error('Failed to connect to the server');
      }

      const data = await response.json();
      setResult(data);
      setHistoryKey(prev => prev + 1);

      if (data.detected_pii.length > 0) {
        sendNotification("PII Detected", `Sentinel found ${data.detected_pii.length} sensitive vectors in your stream.`);
      } else {
        sendNotification("Scan Complete", "No high-risk entities detected in this stream.");
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleClear = () => {
    setInputText('');
    setResult(null);
    setError(null);
  };

  const handleCopy = () => {
    if (result) {
      navigator.clipboard.writeText(result.redacted_text);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    if (file.type.startsWith('image/')) {
      setError(null);
      setOcrProgress('Warming up Neural Engine...');
      try {
        if (!ocrWorker) {
          throw new Error('Neural OCR Engine is initializing. Please wait a moment.');
        }

        const { data: { text } } = await ocrWorker.recognize(file, {}, {
          logger: m => {
            if (m.status === 'recognizing text') {
              setOcrProgress(`Neural Scan: ${Math.round(m.progress * 100)}%`);
            }
          }
        });

        setInputText(text);
        setOcrProgress(null);
        sendNotification("OCR Complete", "Metadata successfully extracted from image.");
      } catch (err) {
        setError("Neural Scan Failed: " + err.message);
        setOcrProgress(null);
      }
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      setInputText(e.target.result);
    };
    reader.readAsText(file);
  };

  const downloadFile = (content, filename, type) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadText = () => {
    if (result) {
      downloadFile(result.redacted_text, 'redacted_output.txt', 'text/plain');
    }
  };

  const handleDownloadReport = () => {
    if (result) {
      const report = {
        timestamp: new Date().toISOString(),
        scan_summary: result.detected_pii,
        risk_score: 100 - (result.detected_pii.length * 5),
        total_pii: result.detected_pii.length
      };
      downloadFile(JSON.stringify(report, null, 2), 'pii_risk_report.json', 'application/json');
    }
  };

  const handleSaveDraft = () => {
    if (!inputText) return;
    const draft = {
      text: inputText,
      result: result,
      timestamp: new Date().toISOString()
    };
    localStorage.setItem(`sentinel_draft_${user}`, JSON.stringify(draft));
    sendNotification("Draft Saved", "Vault session state successfully cached.");
  };

  const handleLoadDraft = () => {
    const savedDraft = localStorage.getItem(`sentinel_draft_${user}`);
    if (savedDraft) {
      const { text, result: savedResult } = JSON.parse(savedDraft);
      setInputText(text);
      setResult(savedResult);
      sendNotification("Draft Loaded", "Previous vault session successfully restored.");
    } else {
      setError("No saved drafts found for this user.");
    }
  };

  if (!token) {
    return <Auth onLogin={handleLogin} />;
  }

  return (
    <div className="container">
      <header className="header">
        <div className="header-brand">
          <h1>🛡️ Sentinel <span className="highlight">AI</span></h1>
          <nav className="main-nav">
            <button
              className={`nav-link ${activeTab === 'scanner' ? 'active' : ''}`}
              onClick={() => setActiveTab('scanner')}
            >
              Neural Scanner
              <span className="nav-subtitle">Live Privacy Shield</span>
            </button>
            <button
              className={`nav-link ${activeTab === 'radar' ? 'active' : ''}`}
              onClick={() => setActiveTab('radar')}
            >
              Identity Radar
              <span className="nav-subtitle">History & Analytics</span>
            </button>
            <button
              className={`nav-link ${activeTab === 'bulk' ? 'active' : ''}`}
              onClick={() => setActiveTab('bulk')}
            >
              Bulk Node
              <span className="nav-subtitle">Batch Data Cleaner</span>
            </button>
          </nav>
        </div>
        <div className="user-controls">
          <div className="user-info">
            <span className="user-badge">SECURE SESSION</span>
            <span className="user-name">{user}</span>
          </div>
          <button onClick={handleLogout} className="logout-btn">Logout</button>
        </div>
      </header>

      <main className="main-content">
        {activeTab === 'scanner' ? (
          <div className="scanner-view animate-fade-in">
            <section className="input-section">
              <div className="section-header">
                <h3><span className="icon">📡</span> Data Input Stream</h3>
                <p className="section-helper">Paste text, logs, or code below to automatically detect and hide sensitive information.</p>
                <div className="header-actions-inline">
                  <button className="text-action-btn secondary" title="Save your current work to finish later" onClick={handleSaveDraft}>
                    💾 Save Draft
                  </button>
                  <button className="text-action-btn secondary" title="Restore your last saved work" onClick={handleLoadDraft}>
                    📂 Load Draft
                  </button>
                  <button className="text-action-btn secondary" title="Define your own custom PII detection rules" onClick={() => setIsPatternModalOpen(true)}>
                    🛠️ Custom Rules
                  </button>
                  <button className="text-action-btn" onClick={handleClear}>Clear All</button>
                </div>
              </div>
              <textarea
                className="text-input"
                placeholder="Synchronize data stream... (Paste anything from emails to credit card numbers here)"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                rows={10}
              />
              <div className="actions">
                <input
                  type="file"
                  id="file-upload"
                  accept=".txt,.csv,.json,.md,.log,.png,.jpg,.jpeg,.bmp"
                  style={{ display: 'none' }}
                  onChange={handleFileUpload}
                />
                <label htmlFor="file-upload" className="upload-btn">
                  {ocrProgress ? '⏳ Processing...' : '📂 Upload Source'}
                </label>
                <button className="scan-btn" onClick={handleScan} disabled={loading || !inputText || ocrProgress}>
                  {loading ? 'Analyzing...' : 'DETECT PII'}
                </button>
              </div>
              {ocrProgress && <div className="ocr-status">📷 {ocrProgress}</div>}
            </section>

            {error && <div className="error-message">⚠️ {error}</div>}

            {result && (
              <section className="results-wrapper animate-slide-up">
                <div className="report-header">
                  <h3>Analysis Result</h3>
                  <div className="report-actions">
                    <button className="download-btn secondary" onClick={handleDownloadReport}>
                      📊 Export Audit
                    </button>
                    <button className="download-btn primary" onClick={handleDownloadText}>
                      💾 Save Redacted
                    </button>
                  </div>
                </div>

                <RiskSummary
                  detectedEntities={result.detected_pii}
                  riskLevel={result.risk_level}
                />

                <div className="results-grid">
                  <div className="result-card">
                    <div className="card-header-actions">
                      <h3>Secure Redaction Output</h3>
                      <button className="copy-btn" onClick={handleCopy}>
                        {copySuccess ? '✅ Copied' : '📋 Copy'}
                      </button>
                    </div>
                    <pre className="redacted-text">{result.redacted_text}</pre>
                  </div>

                  <div className="result-card">
                    <h3>Detected Data Vectors</h3>
                    {result.detected_pii.length === 0 ? (
                      <div className="no-results">
                        <span className="no-icon">✅</span>
                        <p>No high-risk entities detected in this stream.</p>
                      </div>
                    ) : (
                      <ul className="stats-list">
                        {result.detected_pii.map((item, index) => (
                          <li key={index} className="stat-item">
                            <span className="stat-type">{item.type}</span>
                            <span className="stat-value">{item.value}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </section>
            )}
          </div>
        ) : activeTab === 'bulk' ? (
          <BulkProcessor
            token={token}
            onScanComplete={() => setHistoryKey(prev => prev + 1)}
          />
        ) : (
          <div className="radar-view animate-fade-in">
            <div className="view-header">
              <h2>Identity Radar</h2>
              <p>Global analysis of your historical PII detection cycles.</p>
            </div>
            <ScanHistory key={historyKey} token={token} />
          </div>
        )}
      </main>

      <footer className="app-footer">
        <p>&copy;  Sentinel AI Security Systems | End-to-End Encrypted Data Processing</p>
      </footer>

      <CustomPatternModal
        isOpen={isPatternModalOpen}
        onClose={() => setIsPatternModalOpen(false)}
        onAdd={(name, regex) => {
          setCustomPatterns(prev => ({ ...prev, [name]: regex }));
        }}
        patterns={customPatterns}
      />
    </div>
  );
}

export default App;
