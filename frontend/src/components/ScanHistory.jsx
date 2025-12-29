import React, { useState, useEffect, useCallback, useMemo } from 'react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import './ScanHistory.css';

const ScanHistory = ({ token }) => {
    const [history, setHistory] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [selectedItem, setSelectedItem] = useState(null);

    const fetchHistory = useCallback(async () => {
        setLoading(true);
        setError(null);
        const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000/api' : '/api');
        try {
            const response = await fetch(`${API_URL}/history`, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) {
                if (response.status === 401) throw new Error('Session expired');
                throw new Error('Failed to fetch history');
            }
            const data = await response.json();
            setHistory(data);
        } catch (err) {
            setError(err.message);
            console.error('History fetch error:', err);
        } finally {
            setLoading(false);
        }
    }, [token]);

    useEffect(() => {
        fetchHistory();
    }, [fetchHistory]);

    const globalStats = useMemo(() => {
        if (history.length === 0) return { totalScans: 0, totalEntities: 0, entityTypes: {}, trend: 0 };

        const totalEntities = history.reduce((acc, item) => acc + item.detected_pii.length, 0);
        const entityTypes = {};
        history.forEach(item => {
            item.detected_pii.forEach(pii => {
                entityTypes[pii.type] = (entityTypes[pii.type] || 0) + 1;
            });
        });

        // Calculate trend (last 3 scans vs previous 3)
        const recent = history.slice(0, 3).reduce((acc, item) => acc + item.detected_pii.length, 0);
        const previous = history.slice(3, 6).reduce((acc, item) => acc + item.detected_pii.length, 0);
        let trend = 0;
        if (previous > 0) {
            trend = Math.round(((recent - (previous / 3 * 3)) / (previous / 3 * 3)) * 100);
        } else if (recent > 0) {
            trend = 100;
        }

        // Hourly distribution for heatmap
        const hourlyDist = new Array(24).fill(0);
        history.forEach(item => {
            const hour = new Date(item.timestamp).getHours();
            hourlyDist[hour] += item.detected_pii.length;
        });

        const maxHourly = Math.max(...hourlyDist, 1);

        return { totalScans: history.length, totalEntities, entityTypes, trend, hourlyDist, maxHourly };
    }, [history]);

    const generateAuditPDF = () => {
        if (history.length === 0) return;

        const doc = new jsPDF();
        const timestamp = new Date().toLocaleString();

        // Header
        doc.setFillColor(15, 23, 42);
        doc.rect(0, 0, 210, 40, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(24);
        doc.setFont('helvetica', 'bold');
        doc.text('SENTINEL AI', 15, 20);
        doc.setFontSize(14);
        doc.text('Security Audit Compliance Report', 15, 30);
        doc.setFontSize(10);
        doc.text(`Generated: ${timestamp}`, 140, 30);

        // Section 1: Executive Summary
        doc.setTextColor(15, 23, 42);
        doc.setFontSize(16);
        doc.text('I. Executive Summary', 15, 55);

        autoTable(doc, {
            startY: 60,
            head: [['Metric', 'Value', 'Context']],
            body: [
                ['Total Audit Cycles', globalStats.totalScans.toString(), 'Number of independent scans processed'],
                ['Entities Neutralized', globalStats.totalEntities.toString(), 'Total PII instances across all documents'],
                ['Security Coverage', Object.keys(globalStats.entityTypes).length.toString(), 'Unique PII species detected'],
                ['Current Trend', `${globalStats.trend > 0 ? '+' : ''}${globalStats.trend}%`, 'Net security trajectory']
            ],
            theme: 'striped',
            headStyles: { fillColor: [59, 130, 246] }
        });

        // Section 2: Distribution
        doc.setFontSize(16);
        doc.text('II. Threat Vector Distribution', 15, doc.lastAutoTable.finalY + 15);

        const distributionData = Object.entries(globalStats.entityTypes)
            .sort((a, b) => b[1] - a[1])
            .map(([type, count]) => [type, count, `${((count / globalStats.totalEntities) * 100).toFixed(1)}%`]);

        autoTable(doc, {
            startY: doc.lastAutoTable.finalY + 20,
            head: [['Entity Type', 'Detection Count', 'Concentration']],
            body: distributionData,
            theme: 'grid',
            headStyles: { fillColor: [74, 222, 128], textColor: [0, 0, 0] }
        });

        // Section 3: Detailed Logs
        doc.addPage();
        doc.setFontSize(16);
        doc.text('III. Detailed Audit Inventory', 15, 20);

        const tableData = history.map(item => [
            new Date(item.timestamp).toLocaleString(),
            item.risk_level || 'NONE',
            item.detected_pii.length.toString(),
            item.redacted_text.substring(0, 50) + '...'
        ]);

        autoTable(doc, {
            startY: 25,
            head: [['Timestamp', 'Risk Level', 'Entity Count', 'Content Preview']],
            body: tableData,
            styles: { fontSize: 8 },
            headStyles: { fillColor: [15, 23, 42] }
        });

        // Footer for all pages
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.setTextColor(150);
            doc.text(`Page ${i} of ${pageCount} | Confidential - Sentinel AI Intelligence Protocol`, 105, 285, { align: 'center' });
        }

        doc.save(`sentinel_audit_${new Date().getTime()}.pdf`);
    };

    const openDetails = (item) => {
        setSelectedItem(item);
    };

    const closeDetails = () => {
        setSelectedItem(null);
    };

    return (
        <div className="history-container">
            {history.length > 0 && (
                <div className="analytics-overview">
                    <div className="global-stats-grid">
                        <div className="stat-card">
                            <span className="stat-label">Total Audit Cycles</span>
                            <p className="stat-helper">Total scans performed</p>
                            <div className="stat-value-group">
                                <span className="stat-value">{globalStats.totalScans}</span>
                            </div>
                        </div>
                        <div className="stat-card">
                            <span className="stat-label">Neutralized Entities</span>
                            <p className="stat-helper">Total sensitive items hidden</p>
                            <div className="stat-value-group">
                                <span className="stat-value">{globalStats.totalEntities}</span>
                                {globalStats.trend !== 0 && (
                                    <span className={`trend-badge ${globalStats.trend > 0 ? 'up' : 'down'}`}>
                                        {globalStats.trend > 0 ? '↑' : '↓'} {Math.abs(globalStats.trend)}%
                                    </span>
                                )}
                            </div>
                        </div>
                        <div className="stat-card">
                            <span className="stat-label">Security Coverage</span>
                            <p className="stat-helper">Types of info detected</p>
                            <div className="stat-value-group">
                                <span className="stat-value">{Object.keys(globalStats.entityTypes).length}</span>
                                <span className="stat-unit">Vectors</span>
                            </div>
                        </div>
                    </div>

                    <div className="analytics-grid">
                        <div className="entity-distribution-chart">
                            <h4>Threat Vector Distribution</h4>
                            <div className="chart-bars">
                                {Object.entries(globalStats.entityTypes)
                                    .sort((a, b) => b[1] - a[1])
                                    .slice(0, 5)
                                    .map(([type, count]) => {
                                        const percentage = (count / globalStats.totalEntities) * 100;
                                        return (
                                            <div key={type} className="chart-row">
                                                <span className="chart-label">{type}</span>
                                                <div className="chart-bar-bg">
                                                    <div
                                                        className="chart-bar-fill"
                                                        style={{ width: `${percentage}%` }}
                                                    >
                                                        <span className="bar-value">{count}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        );
                                    })}
                            </div>
                        </div>

                        <div className="temporal-heatmap">
                            <h4>Temporal Risk Heatmap (24h)</h4>
                            <div className="heatmap-grid">
                                {globalStats.hourlyDist.map((count, hour) => {
                                    const intensity = count / globalStats.maxHourly;
                                    return (
                                        <div
                                            key={hour}
                                            className="heatmap-cell"
                                            style={{
                                                backgroundColor: count > 0 ? `rgba(59, 130, 246, ${0.1 + intensity * 0.9})` : 'rgba(255,255,255,0.03)',
                                                border: count > 0 ? '1px solid var(--primary)' : '1px solid transparent'
                                            }}
                                            title={`${hour}:00 - ${count} entities`}
                                        >
                                            <span className="cell-hour">{hour}h</span>
                                        </div>
                                    );
                                })}
                            </div>
                            <p className="heatmap-legend">This grid shows which hours of the day you scan the most.</p>
                        </div>
                    </div>
                </div>
            )}

            <div className="history-header">
                <h3>📜 Audit Logs</h3>
                <div className="header-actions">
                    {history.length > 0 && (
                        <button className="export-radar-btn" onClick={generateAuditPDF}>
                            📄 Generate Audit PDF
                        </button>
                    )}
                    <button
                        className="refresh-btn"
                        onClick={fetchHistory}
                        disabled={loading}
                    >
                        {loading ? '...' : '🔄 Resync Vault'}
                    </button>
                </div>
            </div>

            {loading && history.length === 0 && (
                <div className="history-status">Establishing secure connection...</div>
            )}

            {error && (
                <div className="history-status error">
                    ⚠️ {error}
                </div>
            )}

            {!loading && !error && history.length === 0 && (
                <div className="no-history-box">
                    <p className="no-history">Your scanning vault is empty. Try scanning some text in the Neural Scanner!</p>
                </div>
            )}

            {history.length > 0 && (
                <div className="history-list">
                    {history.map((item) => (
                        <div key={item.id} className="history-item" onClick={() => openDetails(item)}>
                            <div className="history-meta">
                                <span className="history-date">
                                    📅 {new Date(item.timestamp).toLocaleString()}
                                </span>
                                <span className={`history-risk ${item.risk_level?.toLowerCase()}`}>
                                    {item.risk_level || 'None'}
                                </span>
                                <span className="history-entities">
                                    🔍 {item.detected_pii.length} Entities
                                </span>
                            </div>
                            <div className="history-preview">
                                {item.redacted_text.substring(0, 150)}...
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {selectedItem && (
                <div className="modal-overlay" onClick={closeDetails}>
                    <div className="modal-content" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3>Scan Details - {new Date(selectedItem.timestamp).toLocaleString()}</h3>
                            <button className="close-btn" onClick={closeDetails}>&times;</button>
                        </div>
                        <div className="modal-body">
                            <div className="detail-section">
                                <h4>Redacted Output Profile</h4>
                                <pre className="history-full-text">{selectedItem.redacted_text}</pre>
                            </div>
                            <div className="detail-section">
                                <h4>Data Vectors Neutralized</h4>
                                <div className="history-entities-list">
                                    {selectedItem.detected_pii.map((pii, idx) => (
                                        <div key={idx} className="pii-tag">
                                            <span className="pii-type">{pii.type}</span>
                                            <span className="pii-value">{pii.value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default ScanHistory;
