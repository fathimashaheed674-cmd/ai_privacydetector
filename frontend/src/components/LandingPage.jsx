import React from 'react';
import './LandingPage.css';

const LandingPage = ({ onGetStarted }) => {
    return (
        <div className="landing-container">
            <div className="landing-background">
                <div className="grid-overlay"></div>
                <div className="glow-orb orb-1"></div>
                <div className="glow-orb orb-2"></div>
                <div className="scan-line"></div>
            </div>

            <nav className="landing-nav">
                <div className="nav-brand">
                    <span className="brand-icon">🛡️</span>
                    <span className="brand-name">Sentinel <span className="highlight">AI</span></span>
                </div>
                <button className="nav-login-btn" onClick={onGetStarted}>
                    Access Portal
                </button>
            </nav>

            <main className="landing-hero">
                <div className="hero-content">
                    <div className="badge-row">
                        <span className="hero-badge">🔐 Enterprise-Grade Security</span>
                        <span className="hero-badge">🇮🇳 India Compliant</span>
                    </div>

                    <h1 className="hero-title">
                        <span className="title-line">Tactical</span>
                        <span className="title-line gradient-text">PII Neutralization</span>
                        <span className="title-line">Platform</span>
                    </h1>

                    <p className="hero-description">
                        Automatically detect, redact, and secure sensitive personal information
                        across text, images, and documents. Protect Aadhaar, PAN, passports,
                        credit cards, and more with military-grade precision.
                    </p>

                    <div className="hero-actions">
                        <button className="primary-cta" onClick={onGetStarted}>
                            <span className="cta-icon">🚀</span>
                            Launch Console
                        </button>
                        <a href="#features" className="secondary-cta">
                            <span className="cta-icon">📖</span>
                            Learn More
                        </a>
                    </div>

                    <div className="trust-indicators">
                        <div className="trust-item">
                            <span className="trust-number">10K+</span>
                            <span className="trust-label">Scans Protected</span>
                        </div>
                        <div className="trust-divider"></div>
                        <div className="trust-item">
                            <span className="trust-number">99.9%</span>
                            <span className="trust-label">Detection Rate</span>
                        </div>
                        <div className="trust-divider"></div>
                        <div className="trust-item">
                            <span className="trust-number">0</span>
                            <span className="trust-label">Data Stored</span>
                        </div>
                    </div>
                </div>

                <div className="hero-visual">
                    <div className="terminal-window">
                        <div className="terminal-header">
                            <span className="terminal-dot red"></span>
                            <span className="terminal-dot yellow"></span>
                            <span className="terminal-dot green"></span>
                            <span className="terminal-title">sentinel_scan.exe</span>
                        </div>
                        <div className="terminal-body">
                            <div className="terminal-line">
                                <span className="prompt">$</span> Initializing neural scanner...
                            </div>
                            <div className="terminal-line success">
                                <span className="prompt">✓</span> Connected to Sentinel AI Core
                            </div>
                            <div className="terminal-line">
                                <span className="prompt">$</span> Scanning input stream...
                            </div>
                            <div className="terminal-line warning">
                                <span className="prompt">⚠</span> AADHAAR detected: ****-****-4523
                            </div>
                            <div className="terminal-line warning">
                                <span className="prompt">⚠</span> PAN detected: ***PK****M
                            </div>
                            <div className="terminal-line success">
                                <span className="prompt">✓</span> 2 entities neutralized
                            </div>
                            <div className="terminal-line blink">
                                <span className="prompt">$</span> Ready for next scan_
                            </div>
                        </div>
                    </div>
                </div>
            </main>

            <section id="features" className="features-section">
                <h2 className="section-title">Core Capabilities</h2>
                <div className="features-grid">
                    <div className="feature-card">
                        <div className="feature-icon">📡</div>
                        <h3>Neural Scanner</h3>
                        <p>Real-time detection of 15+ PII types including Aadhaar, PAN, passports, and financial data.</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">📷</div>
                        <h3>Image OCR</h3>
                        <p>Extract and scan text from images, screenshots, and scanned documents.</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">📦</div>
                        <h3>Bulk Processing</h3>
                        <p>Upload entire folders and cleanse hundreds of files in parallel.</p>
                    </div>
                    <div className="feature-card">
                        <div className="feature-icon">📊</div>
                        <h3>Audit Reports</h3>
                        <p>Generate professional PDF compliance reports for legal records.</p>
                    </div>
                </div>
            </section>

            <footer className="landing-footer">
                <p>© 2024 Sentinel AI Security Systems | End-to-End Encrypted Processing</p>
            </footer>
        </div>
    );
};

export default LandingPage;
