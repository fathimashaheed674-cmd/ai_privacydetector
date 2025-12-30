import React, { useState } from 'react';
import JSZip from 'jszip';
import './BulkProcessor.css';

const BulkProcessor = ({ token, onScanComplete }) => {
    const [files, setFiles] = useState([]);
    const [processing, setProcessing] = useState(false);
    const [progress, setProgress] = useState({ current: 0, total: 0 });
    const [results, setResults] = useState([]);

    const handleFileSelection = (e) => {
        const selectedFiles = Array.from(e.target.files);
        setFiles(selectedFiles.map(f => ({ file: f, status: 'pending', id: Math.random().toString(36).substr(2, 9) })));
        setResults([]);
        setProgress({ current: 0, total: 0 });
    };

    const processFiles = async () => {
        if (files.length === 0) return;
        setProcessing(true);
        setProgress({ current: 0, total: files.length });
        const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:8000/api' : '/api');

        const processedResults = [];

        for (let i = 0; i < files.length; i++) {
            const fileItem = files[i];
            updateFileStatus(fileItem.id, 'processing');

            try {
                let text = '';
                if (fileItem.file.type.startsWith('text/') || fileItem.file.name.endsWith('.md') || fileItem.file.name.endsWith('.json')) {
                    text = await fileItem.file.text();
                } else {
                    // Skip images for now in bulk to keep it fast, or could integrate Tesseract here
                    throw new Error('Unsupported format in bulk mode');
                }

                const response = await fetch(`${API_URL}/scan`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token || localStorage.getItem('token')}`
                    },
                    body: JSON.stringify({ text }),
                });


                if (!response.ok) throw new Error('Network error');

                const data = await response.json();
                processedResults.push({ name: fileItem.file.name, data });
                updateFileStatus(fileItem.id, 'completed', data.detected_pii.length);
            } catch (err) {
                updateFileStatus(fileItem.id, 'error', 0, err.message);
            }

            setProgress(prev => ({ ...prev, current: i + 1 }));
        }

        setResults(processedResults);
        setProcessing(false);
        if (onScanComplete) onScanComplete();

        const totalPII = processedResults.reduce((acc, r) => acc + r.data.detected_pii.length, 0);
        if ("Notification" in window && Notification.permission === "granted") {
            new Notification("Bulk Protocol Complete", {
                body: `Analyzed ${processedResults.length} files. Neutralized ${totalPII} sensitive entities.`
            });
        }
    };

    const updateFileStatus = (id, status, count = 0, error = null) => {
        setFiles(prev => prev.map(f => f.id === id ? { ...f, status, piiCount: count, error } : f));
    };

    const downloadAllRedacted = async () => {
        const zip = new JSZip();
        results.forEach(res => {
            zip.file(`redacted_${res.name}`, res.data.redacted_text);
        });
        const content = await zip.generateAsync({ type: 'blob' });
        const url = URL.createObjectURL(content);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sentinel_bulk_redacted_${new Date().getTime()}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    };

    return (
        <div className="bulk-container animate-fade-in">
            <div className="bulk-header">
                <h2>Sentinel Bulk Node</h2>
                <p>Industrial scale PII extraction and redaction. Cleanse entire folders of logs or datasets in seconds.</p>
            </div>

            <div className="bulk-upload-zone">
                <input
                    type="file"
                    id="bulk-upload"
                    multiple
                    webkitdirectory="true" // Optional: allow folder upload
                    onChange={handleFileSelection}
                    className="hidden-input"
                />
                <label htmlFor="bulk-upload" className="droppanel">
                    <span className="upload-icon">📦</span>
                    <span className="upload-text">Drop a directory or select multiple logs</span>
                    <span className="upload-sub">TXT, JSON, MD, LOG files supported</span>
                </label>
            </div>

            {files.length > 0 && (
                <div className="bulk-workbench">
                    <div className="workbench-actions">
                        <div className="progress-info">
                            <span>Ready to process {files.length} streams</span>
                            {processing && (
                                <div className="progress-bar-container">
                                    <div className="progress-bar-fill" style={{ width: `${(progress.current / progress.total) * 100}%` }}></div>
                                </div>
                            )}
                        </div>
                        <button
                            className="process-btn"
                            onClick={processFiles}
                            disabled={processing}
                        >
                            {processing ? 'Processing All Files...' : 'Start Batch Cleaning'}
                        </button>
                    </div>

                    <div className="file-grid">
                        {files.map(f => (
                            <div key={f.id} className={`file-card ${f.status}`}>
                                <div className="file-info">
                                    <span className="file-name">{f.file.name}</span>
                                    <span className="file-size">{(f.file.size / 1024).toFixed(1)} KB</span>
                                </div>
                                <div className="file-status">
                                    {f.status === 'pending' && <span className="status-tag">Ready</span>}
                                    {f.status === 'processing' && <span className="status-tag pulse">Cleaning...</span>}
                                    {f.status === 'completed' && <span className="status-tag success">Done ({f.piiCount} hidden)</span>}
                                    {f.status === 'error' && <span className="status-tag error">Error</span>}
                                </div>
                            </div>
                        ))}
                    </div>

                    {results.length > 0 && (
                        <div className="bulk-footer">
                            <button className="download-all-btn" onClick={downloadAllRedacted}>
                                📥 Download Redacted Vault (.ZIP)
                            </button>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default BulkProcessor;
