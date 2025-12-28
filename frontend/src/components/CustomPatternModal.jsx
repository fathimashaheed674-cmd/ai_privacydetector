import React, { useState } from 'react';
import './CustomPatternModal.css';

const CustomPatternModal = ({ isOpen, onClose, onAdd, patterns }) => {
    const [name, setName] = useState('');
    const [regex, setRegex] = useState('');
    const [error, setError] = useState('');

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        setError('');

        if (!name || !regex) {
            setError('Both fields are required');
            return;
        }

        try {
            new RegExp(regex);
        } catch (e) {
            setError('Invalid Regular Expression');
            return;
        }

        onAdd(name.toUpperCase(), regex);
        setName('');
        setRegex('');
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content custom-pattern-modal" onClick={e => e.stopPropagation()}>
                <div className="modal-header">
                    <h3>🛠️ Custom Intelligence Vectors</h3>
                    <button className="close-btn" onClick={onClose}>&times;</button>
                </div>

                <div className="modal-body">
                    <p className="description">
                        Add custom regex patterns to detect specific internal data formats (e.g., Employee IDs, Project Codes).
                    </p>

                    <form onSubmit={handleSubmit} className="pattern-form">
                        <div className="input-group">
                            <label>Vector Name</label>
                            <input
                                type="text"
                                placeholder="e.g. EMPLOYEE_ID"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                            />
                        </div>
                        <div className="input-group">
                            <label>Regex Pattern</label>
                            <input
                                type="text"
                                placeholder="e.g. EMP-[0-9]{5}"
                                value={regex}
                                onChange={(e) => setRegex(e.target.value)}
                                className="code-input"
                            />
                        </div>
                        {error && <p className="error-text">{error}</p>}
                        <button type="submit" className="add-pattern-btn">Inject Vector</button>
                    </form>

                    <div className="active-patterns">
                        <h4>Active Custom Vectors</h4>
                        {Object.keys(patterns).length === 0 ? (
                            <p className="no-patterns">No custom vectors active.</p>
                        ) : (
                            <div className="pattern-tags">
                                {Object.entries(patterns).map(([n, r]) => (
                                    <div key={n} className="pattern-tag">
                                        <span className="p-name">{n}</span>
                                        <span className="p-regex">{r}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CustomPatternModal;
