import React, { useState } from 'react';
import './Auth.css';

const Auth = ({ onLogin, onBack }) => {
    const [isLogin, setIsLogin] = useState(true);
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);

        const endpoint = isLogin ? '/token' : '/register';
        const cleanUsername = username.trim();
        const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000/api' : '/api');

        try {
            let body;
            let headers = { 'Content-Type': 'application/json' };

            if (isLogin) {
                body = new URLSearchParams();
                body.append('username', cleanUsername);
                body.append('password', password);
                headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
            } else {
                body = JSON.stringify({ username: cleanUsername, password });
            }

            const response = await fetch(`${API_URL}${endpoint}`, {
                method: 'POST',
                headers: headers,
                body: body,
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || 'Authentication failed');
            }

            onLogin(data.access_token, data.username || cleanUsername);

        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-background-effects">
                <div className="effect-circle c1"></div>
                <div className="effect-circle c2"></div>
                <div className="scan-line"></div>
            </div>

            <div className="auth-card">
                {onBack && (
                    <button className="back-btn" onClick={onBack}>
                        ← Back to Home
                    </button>
                )}

                <div className="auth-brand">
                    <span className="brand-icon">🛡️</span>
                    <h1>Sentinel <span className="highlight">AI</span></h1>
                </div>

                <div className="auth-header">
                    <h2 className="auth-title">
                        {isLogin ? 'Security Access' : 'Initialize Protocol'}
                    </h2>
                    <p className="auth-subtitle">
                        {isLogin
                            ? 'Synchronize credentials to establish secure connection'
                            : 'Register new neural profile for PII neutralization'}
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="auth-form">
                    <div className="form-group">
                        <label htmlFor="username">
                            <span className="label-icon">👤</span> Identity Tag
                        </label>
                        <input
                            type="text"
                            id="username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            placeholder="OPERATOR_CODE"
                            autoComplete="off"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="password">
                            <span className="label-icon">🔑</span> Security Hash
                        </label>
                        <input
                            type="password"
                            id="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            placeholder="••••••••••••"
                        />
                    </div>

                    {error && (
                        <div className="auth-error">
                            <span className="error-icon">⚠️</span> {error}
                        </div>
                    )}

                    <button type="submit" className="auth-btn" disabled={loading}>
                        <span className="btn-glimmer"></span>
                        {loading ? 'Decrypting...' : (isLogin ? 'Establish Connection' : 'Register Profile')}
                    </button>
                </form>

                <div className="auth-footer">
                    <p>
                        {isLogin ? "New to Sentinel? " : "Already registered? "}
                        <button
                            type="button"
                            className="toggle-auth-btn"
                            onClick={() => setIsLogin(!isLogin)}
                        >
                            {isLogin ? 'Create New Account' : 'Back to Login'}
                        </button>
                    </p>
                </div>

                <div className="security-badges">
                    <span className="badge-item">🔒 AES-256</span>
                    <span className="badge-item">🛰️ ENCRYPTED</span>
                    <span className="badge-item">🧬 NEURAL</span>
                </div>
            </div>
        </div>
    );
};

export default Auth;
