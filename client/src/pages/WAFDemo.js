import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  RefreshCw,
  Trash2,
  Copy,
  ExternalLink,
  Terminal,
  Activity
} from 'lucide-react';

const WAFDemo = () => {
  const [mode, setMode] = useState('GET');
  const [openCategories, setOpenCategories] = useState(new Set(['sql']));
  const [securityEvents, setSecurityEvents] = useState([]);
  const [wafStatus, setWafStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchWAFStatus();
    fetchSecurityEvents();
  }, []);

  const fetchWAFStatus = async () => {
    try {
      const response = await fetch('/api/security/status');
      const data = await response.json();
      setWafStatus(data);
    } catch (error) {
      console.error('Failed to fetch WAF status:', error);
    }
  };

  const fetchSecurityEvents = async () => {
    setLoading(true);
    try {
      const adminKey = localStorage.getItem('adminKey') || 'your-admin-key';
      const response = await fetch('/api/security/events?limit=20', {
        headers: {
          'x-admin-key': adminKey
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setSecurityEvents(data.events || []);
      }
    } catch (error) {
      console.error('Failed to fetch security events:', error);
    } finally {
      setLoading(false);
    }
  };

  const clearEvents = async () => {
    try {
      const adminKey = localStorage.getItem('adminKey') || 'your-admin-key';
      const response = await fetch('/api/security/events', {
        method: 'DELETE',
        headers: {
          'x-admin-key': adminKey
        }
      });
      
      if (response.ok) {
        setSecurityEvents([]);
      }
    } catch (error) {
      console.error('Failed to clear events:', error);
    }
  };

  const toggleCategory = (id) => {
    setOpenCategories(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    } catch (err) {
      console.error('Copy failed', err);
    }
  };

  const makeCurl = (example) => {
    const target = window.location.origin;
    try {
      const url = new URL(example);
      const path = url.pathname + url.search;
      
      if (mode === 'GET') {
        return `curl -i "${target}${path}"`;
      }
      if (mode === 'POST') {
        const params = new URLSearchParams(url.search);
        let body = '';
        if ([...params].length > 0) {
          const [k] = [...params][0];
          body = `${k}=${encodeURIComponent(params.get(k))}`;
        } else {
          body = `data=${encodeURIComponent(url.pathname + url.search)}`;
        }
        return `curl -i -X POST "${target}${url.pathname}" -H "Content-Type: application/x-www-form-urlencoded" -d "${body}"`;
      }
      return `curl -i "${target}${url.pathname}${url.search}" -H "User-Agent: ${example.replace(/"/g, '\\"')}"`;
    } catch (e) {
      return `curl -i "${example}"`;
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleString('vi-VN', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const categories = [
    {
      id: 'sql',
      title: 'SQL Injection',
      icon: '💉',
      severity: 'high',
      examples: [
        "http://localhost/?id=1' OR '1'='1",
        "http://localhost/?id=1' OR 1=1--",
        "http://localhost/?user=admin'--",
        "http://localhost/?name=' OR 'a'='a",
        "http://localhost/search?q=1' UNION SELECT NULL--",
        "http://localhost/product?id=1'; DROP TABLE users--",
      ]
    },
    {
      id: 'xss',
      title: 'XSS (Cross-Site Scripting)',
      icon: '🔴',
      severity: 'high',
      examples: [
        "http://localhost/?search=<script>alert(1)</script>",
        "http://localhost/?name=<script>alert('XSS')</script>",
        "http://localhost/?q=<script>alert(document.cookie)</script>",
        "http://localhost/?input=<img src=x onerror=alert(1)>",
      ]
    },
    {
      id: 'traversal',
      title: 'Path Traversal',
      icon: '📁',
      severity: 'high',
      examples: [
        'http://localhost/download?file=../../../etc/passwd',
        'http://localhost/view?path=../../../etc/shadow',
        'http://localhost/read?file=../../../../etc/hosts',
      ]
    },
    {
      id: 'command',
      title: 'Command Injection',
      icon: '💻',
      severity: 'high',
      examples: [
        'http://localhost/ping?host=127.0.0.1; ls -la',
        'http://localhost/ping?host=127.0.0.1 && cat /etc/passwd',
        'http://localhost/exec?cmd=whoami',
      ]
    },
    {
      id: 'lfi',
      title: 'Local File Inclusion',
      icon: '📄',
      severity: 'medium',
      examples: [
        'http://localhost/?page=../../../../etc/passwd',
        'http://localhost/include?file=/etc/shadow',
        'http://localhost/view?doc=/proc/self/environ',
      ]
    },
    {
      id: 'ssrf',
      title: 'Server-Side Request Forgery',
      icon: '🌐',
      severity: 'medium',
      examples: [
        'http://localhost/fetch?url=http://127.0.0.1',
        'http://localhost/get?url=http://169.254.169.254/latest/meta-data/',
      ]
    },
    {
      id: 'redirect',
      title: 'Open Redirect',
      icon: '↗️',
      severity: 'low',
      examples: [
        'http://localhost/redirect?url=http://evil.com',
        'http://localhost/goto?next=//evil.com',
      ]
    },
    {
      id: 'header',
      title: 'HTTP Header Injection',
      icon: '📋',
      severity: 'medium',
      examples: [
        'http://localhost/page?url=%0d%0aSet-Cookie:%20admin=true',
        'http://localhost/redirect?to=%0d%0aLocation:%20http://evil.com',
      ]
    }
  ];

  return (
    <div className="waf-container">
      <div className="waf-header">
        <motion.h1
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <Shield size={32} /> WAF Security Testing Dashboard
        </motion.h1>
        <p className="subtitle">
          Interactive security testing interface for ModSecurity WAF
        </p>
        <div className="warning">
          <AlertTriangle size={20} />
          <span>Development/Testing Environment Only - Do Not Use in Production</span>
        </div>
      </div>

      {/* WAF Status Overview */}
      {wafStatus && (
        <motion.div
          className="card"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
        >
          <h2><Activity size={24} /> WAF Protection Status</h2>
          <div className="status-badges">
            <div className={`status-badge ${wafStatus.helmet ? 'enabled' : 'disabled'}`}>
              {wafStatus.helmet ? <CheckCircle size={16} /> : <XCircle size={16} />}
              Helmet Security Headers
            </div>
            <div className={`status-badge ${wafStatus.rateLimit ? 'enabled' : 'disabled'}`}>
              {wafStatus.rateLimit ? <CheckCircle size={16} /> : <XCircle size={16} />}
              Rate Limiting
            </div>
            <div className={`status-badge ${wafStatus.mongoSanitize ? 'enabled' : 'disabled'}`}>
              {wafStatus.mongoSanitize ? <CheckCircle size={16} /> : <XCircle size={16} />}
              MongoDB Sanitization
            </div>
            <div className={`status-badge ${wafStatus.xssClean ? 'enabled' : 'disabled'}`}>
              {wafStatus.xssClean ? <CheckCircle size={16} /> : <XCircle size={16} />}
              XSS Protection
            </div>
            <div className={`status-badge ${wafStatus.securityEnabled ? 'enabled' : 'disabled'}`}>
              {wafStatus.securityEnabled ? <CheckCircle size={16} /> : <XCircle size={16} />}
              Security Enabled
            </div>
          </div>
        </motion.div>
      )}

      <div className="grid">
        {/* Attack Payloads */}
        <motion.div
          className="card"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <h2><Terminal size={24} /> Attack Payloads</h2>
          
          <div className="mode-selector">
            <button 
              className={`mode-button ${mode === 'GET' ? 'active' : ''}`}
              onClick={() => setMode('GET')}
            >
              GET Request
            </button>
            <button 
              className={`mode-button ${mode === 'POST' ? 'active' : ''}`}
              onClick={() => setMode('POST')}
            >
              POST Request
            </button>
            <button 
              className={`mode-button ${mode === 'HEADER' ? 'active' : ''}`}
              onClick={() => setMode('HEADER')}
            >
              Header Injection
            </button>
          </div>

          <div className="payloads-container">
            {categories.map((category) => (
              <div key={category.id} className="category-card">
                <div className="category-header" onClick={() => toggleCategory(category.id)}>
                  <h3>
                    <span>{category.icon}</span>
                    {category.title}
                  </h3>
                  <div className="count">{category.examples.length}</div>
                </div>

                <AnimatePresence>
                  {openCategories.has(category.id) && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.3 }}
                    >
                      {category.examples.map((example, idx) => (
                        <div key={idx} className="payload-item">
                          <pre className="payload-code">{example}</pre>
                          <div className="button-group">
                            <button 
                              className="action-button"
                              onClick={() => copyToClipboard(example)}
                            >
                              <Copy size={14} /> Copy URL
                            </button>
                            <button 
                              className="action-button"
                              onClick={() => window.open(example, '_blank')}
                            >
                              <ExternalLink size={14} /> Test
                            </button>
                            <button 
                              className="action-button"
                              onClick={() => copyToClipboard(makeCurl(example))}
                            >
                              <Terminal size={14} /> Copy cURL
                            </button>
                          </div>
                        </div>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Security Events Monitor */}
        <motion.div
          className="card"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <div className="events-header">
            <h2><Shield size={24} /> Security Events Monitor</h2>
            <div className="header-buttons">
              <button 
                className="refresh-button"
                onClick={fetchSecurityEvents}
                disabled={loading}
              >
                <RefreshCw size={14} className={loading ? 'spinning' : ''} />
                Refresh
              </button>
              <button className="action-button" onClick={clearEvents}>
                <Trash2 size={14} /> Clear All
              </button>
            </div>
          </div>

          <div className="events-container">
            {securityEvents.length === 0 ? (
              <div className="empty-state">
                <CheckCircle size={48} />
                <p>No security events detected</p>
                <p className="empty-subtitle">
                  Try testing some payloads to see events here
                </p>
              </div>
            ) : (
              <AnimatePresence>
                {securityEvents.map((event, idx) => (
                  <motion.div
                    key={event._id || idx}
                    className={`security-event severity-${event.severity || 'medium'}`}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    transition={{ duration: 0.3, delay: idx * 0.05 }}
                  >
                    <div className="event-header-row">
                      <div className="event-type">
                        {event.type || 'Security Event'}
                      </div>
                      <div className="event-time">
                        {formatTime(event.createdAt || event.timestamp)}
                      </div>
                    </div>
                    <div className="event-details">
                      {event.message || event.details || 'No details available'}
                    </div>
                    {event.ip && (
                      <div className="event-ip">IP: {event.ip}</div>
                    )}
                  </motion.div>
                ))}
              </AnimatePresence>
            )}
          </div>
        </motion.div>
      </div>

      <style jsx>{`
        .waf-container {
          padding: 100px 20px 60px;
          max-width: 1400px;
          margin: 0 auto;
          color: #333;
          min-height: 100vh;
          background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }

        [data-theme='dark'] .waf-container {
          color: #f0f2f5;
          background: linear-gradient(135deg, #1a1d23 0%, #2d3139 100%);
        }

        .waf-header {
          text-align: center;
          margin-bottom: 40px;
        }

        .waf-header h1 {
          font-size: 2.8rem;
          margin-bottom: 10px;
          font-weight: 700;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 15px;
        }

        .subtitle {
          opacity: 0.7;
          font-size: 1.1rem;
          margin-bottom: 20px;
        }

        .warning {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          background: rgba(255, 152, 0, 0.1);
          border: 1px solid rgba(255, 152, 0, 0.3);
          padding: 12px 20px;
          border-radius: 10px;
          color: #ff9800;
          font-size: 0.95rem;
          font-weight: 500;
        }

        .card {
          background: rgba(255, 255, 255, 0.9);
          border: 1px solid rgba(0, 0, 0, 0.1);
          border-radius: 12px;
          padding: 25px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          transition: all 0.3s ease;
          margin-bottom: 30px;
        }

        [data-theme='dark'] .card {
          background: rgba(40, 44, 54, 0.9);
          border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .card:hover {
          box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
          border-color: #667eea;
        }

        .card h2 {
          font-size: 1.5rem;
          margin-bottom: 20px;
          color: #667eea;
          font-weight: 600;
          display: flex;
          align-items: center;
          gap: 10px;
          padding-bottom: 15px;
          border-bottom: 2px solid #667eea;
        }

        .status-badges {
          display: flex;
          gap: 15px;
          flex-wrap: wrap;
        }

        .status-badge {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 6px 12px;
          border-radius: 20px;
          font-size: 0.85rem;
          font-weight: 600;
          border: 1px solid;
        }

        .status-badge.enabled {
          background: rgba(76, 175, 80, 0.1);
          color: #4caf50;
          border-color: rgba(76, 175, 80, 0.3);
        }

        .status-badge.disabled {
          background: rgba(244, 67, 54, 0.1);
          color: #f44336;
          border-color: rgba(244, 67, 54, 0.3);
        }

        .grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 30px;
        }

        @media (max-width: 1200px) {
          .grid {
            grid-template-columns: 1fr;
          }
        }

        .mode-selector {
          display: flex;
          gap: 10px;
          margin-bottom: 25px;
          flex-wrap: wrap;
        }

        .mode-button {
          padding: 10px 20px;
          border: 1px solid rgba(0, 0, 0, 0.1);
          border-radius: 8px;
          background: transparent;
          color: #333;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        [data-theme='dark'] .mode-button {
          color: #f0f2f5;
          border-color: rgba(255, 255, 255, 0.1);
        }

        .mode-button.active {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          border-color: transparent;
        }

        .mode-button:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }

        .payloads-container {
          max-height: 600px;
          overflow-y: auto;
          padding-right: 10px;
        }

        .category-card {
          background: rgba(255, 255, 255, 0.5);
          border: 1px solid rgba(0, 0, 0, 0.1);
          border-radius: 10px;
          padding: 15px;
          margin-bottom: 15px;
          transition: all 0.2s ease;
        }

        [data-theme='dark'] .category-card {
          background: rgba(255, 255, 255, 0.05);
          border-color: rgba(255, 255, 255, 0.1);
        }

        .category-card:hover {
          background: rgba(255, 255, 255, 0.7);
        }

        [data-theme='dark'] .category-card:hover {
          background: rgba(255, 255, 255, 0.08);
        }

        .category-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          cursor: pointer;
          user-select: none;
        }

        .category-header h3 {
          font-size: 1.2rem;
          font-weight: 600;
          display: flex;
          align-items: center;
          gap: 10px;
          margin: 0;
        }

        .count {
          background: #667eea;
          color: white;
          padding: 4px 12px;
          border-radius: 20px;
          font-size: 0.85rem;
          font-weight: 600;
        }

        .payload-item {
          display: flex;
          flex-direction: column;
          gap: 10px;
          padding: 12px;
          background: rgba(0, 0, 0, 0.03);
          border-radius: 8px;
          margin-top: 10px;
          border: 1px solid rgba(0, 0, 0, 0.1);
        }

        [data-theme='dark'] .payload-item {
          background: rgba(0, 0, 0, 0.2);
          border-color: rgba(255, 255, 255, 0.1);
        }

        .payload-code {
          margin: 0;
          padding: 12px;
          background: rgba(0, 0, 0, 0.05);
          border: 1px solid rgba(0, 0, 0, 0.1);
          border-radius: 6px;
          font-size: 0.9rem;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }

        [data-theme='dark'] .payload-code {
          background: rgba(0, 0, 0, 0.3);
          border-color: rgba(255, 255, 255, 0.1);
        }

        .button-group {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
        }

        .action-button {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 8px 14px;
          background: transparent;
          border: 1px solid rgba(0, 0, 0, 0.1);
          border-radius: 6px;
          color: #333;
          font-size: 0.9rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        [data-theme='dark'] .action-button {
          color: #f0f2f5;
          border-color: rgba(255, 255, 255, 0.1);
        }

        .action-button:hover {
          background: #667eea;
          color: white;
          transform: translateY(-1px);
        }

        .refresh-button {
          display: flex;
          align-items: center;
          gap: 6px;
          padding: 8px 14px;
          background: #667eea;
          border: none;
          border-radius: 6px;
          color: white;
          font-size: 0.9rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        .refresh-button:hover {
          background: #764ba2;
        }

        .refresh-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .events-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }

        .events-header h2 {
          margin: 0;
          padding: 0;
          border: none;
        }

        .header-buttons {
          display: flex;
          gap: 10px;
        }

        .events-container {
          max-height: 600px;
          overflow-y: auto;
          padding-right: 10px;
        }

        .empty-state {
          text-align: center;
          padding: 40px 20px;
          opacity: 0.6;
        }

        .empty-state svg {
          margin-bottom: 15px;
          opacity: 0.5;
        }

        .empty-state p {
          font-size: 1rem;
          margin: 5px 0;
        }

        .empty-subtitle {
          font-size: 0.9rem;
          opacity: 0.7;
        }

        .security-event {
          background: rgba(255, 255, 255, 0.5);
          border: 1px solid rgba(0, 0, 0, 0.1);
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 12px;
        }

        [data-theme='dark'] .security-event {
          background: rgba(255, 255, 255, 0.05);
          border-color: rgba(255, 255, 255, 0.1);
        }

        .security-event.severity-high {
          border-left: 4px solid #f44336;
        }

        .security-event.severity-medium {
          border-left: 4px solid #ff9800;
        }

        .security-event.severity-low {
          border-left: 4px solid #4caf50;
        }

        .event-header-row {
          display: flex;
          justify-content: space-between;
          align-items: start;
          margin-bottom: 10px;
        }

        .event-type {
          font-weight: 600;
          font-size: 1rem;
        }

        .severity-high .event-type {
          color: #f44336;
        }

        .severity-medium .event-type {
          color: #ff9800;
        }

        .severity-low .event-type {
          color: #4caf50;
        }

        .event-time {
          font-size: 0.85rem;
          opacity: 0.7;
        }

        .event-details {
          font-size: 0.9rem;
          opacity: 0.8;
          margin-top: 8px;
        }

        .event-ip {
          display: inline-block;
          background: rgba(0, 0, 0, 0.1);
          padding: 4px 8px;
          border-radius: 4px;
          font-family: monospace;
          font-size: 0.85rem;
          margin-top: 8px;
        }

        .spinning {
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        @media (max-width: 768px) {
          .waf-container {
            padding: 80px 15px 40px;
          }

          .waf-header h1 {
            font-size: 2rem;
            flex-direction: column;
          }

          .events-header {
            flex-direction: column;
            gap: 15px;
            align-items: flex-start;
          }

          .header-buttons {
            width: 100%;
          }

          .refresh-button,
          .action-button {
            flex: 1;
          }
        }
      `}</style>
    </div>
  );
};

export default WAFDemo;