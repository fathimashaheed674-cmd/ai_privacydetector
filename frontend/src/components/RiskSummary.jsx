import React, { useMemo } from 'react';
import './RiskSummary.css';

const WEIGHTS = {
    AADHAAR: 20,
    PAN: 20,
    PASSPORT: 20,
    PHONE: 10,
    EMAIL: 5,
    DEFAULT: 5
};

const RiskSummary = ({ detectedEntities, riskLevel }) => {
    const { score, distribution } = useMemo(() => {
        let totalPenalty = 0;
        const dist = {};

        detectedEntities.forEach(item => {
            const type = item.type.toUpperCase();
            const penalty = WEIGHTS[type] || WEIGHTS.DEFAULT;
            totalPenalty += penalty;
            dist[type] = (dist[type] || 0) + 1;
        });

        const calculatedScore = Math.max(0, 100 - totalPenalty);

        return { score: calculatedScore, distribution: dist };
    }, [detectedEntities]);

    // Map backend risk levels to styles
    const riskStatus = riskLevel?.toLowerCase() || 'none';
    const displayLevel = riskLevel || 'None';

    return (
        <div className={`risk-summary-container ${riskStatus}-border`}>
            <div className="risk-header">
                <h3>🛡️ Identity Radar</h3>
                <span className={`risk-badge ${riskStatus}`}>{displayLevel} Risk</span>
            </div>

            <div className="score-section">
                <div className="score-circle">
                    <svg viewBox="0 0 36 36" className="circular-chart">
                        <path className="circle-bg"
                            d="M18 2.0845
                a 15.9155 15.9155 0 0 1 0 31.831
                a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                        <path className={`circle ${riskLevel.toLowerCase()}-stroke`}
                            strokeDasharray={`${score}, 100`}
                            d="M18 2.0845
                a 15.9155 15.9155 0 0 1 0 31.831
                a 15.9155 15.9155 0 0 1 0 -31.831"
                        />
                        <text x="18" y="20.35" className="percentage">{score}%</text>
                    </svg>
                    <p className="score-label">Privacy Score</p>
                </div>

                <div className="distribution-list">
                    <h4>Threat Breakdown</h4>
                    {Object.entries(distribution).length === 0 ? (
                        <p className="no-threats">No PII Detected</p>
                    ) : (
                        <ul>
                            {Object.entries(distribution).map(([type, count]) => (
                                <li key={type}>
                                    <span className="dist-type">{type}</span>
                                    <div className="dist-bar-container">
                                        <div
                                            className="dist-bar"
                                            style={{ width: `${Math.min(count * 20, 100)}%` }}
                                        ></div>
                                    </div>
                                    <span className="dist-count">{count}</span>
                                </li>
                            ))}
                        </ul>
                    )}
                </div>
            </div>
        </div>
    );
};

export default RiskSummary;
