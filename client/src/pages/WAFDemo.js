import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  RefreshCw,
  Trash2,
  Terminal,
  Activity,
  Zap
} from 'lucide-react';

const WAFDemo = () => {
  const [openCategories, setOpenCategories] = useState(new Set(['sql']));
  const [securityEvents, setSecurityEvents] = useState([]);
  const [wafStatus, setWafStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);

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
      const adminKey = localStorage.getItem('adminKey') || 'dev-admin-key-change-in-production';
      const response = await fetch('/api/security/events?limit=50', {
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
      const adminKey = localStorage.getItem('adminKey') || 'dev-admin-key-change-in-production';
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

  const WAF_BASE_URL = 'http://localhost'; // đi qua Docker WAF

const testPayload = async (url, description) => {
  setTesting(true);
  try {
    const response = await fetch(WAF_BASE_URL + url);  // bỏ method/headers

    setTimeout(() => {
      fetchSecurityEvents();
    }, 1000);

    if (response.status === 403 || response.status === 406) {
      alert(`✅ Attack blocked successfully!\n${description}`);
    } else {
      alert(`⚠️ Request went through (status: ${response.status})\nCheck if WAF is running properly.`);
    }
  } catch (error) {
    console.error('Test error:', error);
    alert('❌ Test failed: ' + error.message);
  } finally {
    setTesting(false);
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

  // Real attack payloads targeting YOUR actual APIs
  const categories = [
    {
      id: 'sql',
      title: 'SQL Injection Attacks',
      icon: '💉',
      severity: 'high',
      examples: [
        {
          url: "/api/weather/search?q=Hanoi' OR '1'='1",
          description: "SQL Injection into weather search - attempts to bypass query filters"
        },
        {
          url: "/api/weather/search?q=1' UNION SELECT NULL--",
          description: "UNION-based SQL injection to extract database data"
        },
        {
          url: "/api/weather/current?lat=21.0285&lon=105.8542' OR 1=1--",
          description: "SQL injection in coordinate parameters"
        },
        {
          url: "/api/user/favorites/abc' OR '1'='1",
          description: "SQL injection in favorite city deletion"
        }
      ]
    },
    {
      id: 'xss',
      title: 'XSS (Cross-Site Scripting)',
      icon: '🔴',
      severity: 'high',
      examples: [
        {
          url: "/api/weather/search?q=<script>alert('XSS')</script>",
          description: "Reflected XSS via city search"
        },
        {
          url: "/api/weather/search?q=<img src=x onerror=alert(1)>",
          description: "Image-based XSS injection"
        },
        {
          url: "/api/user/search-history?city=<script>document.cookie</script>",
          description: "XSS targeting search history"
        }
      ]
    },
    {
      id: 'traversal',
      title: 'Path Traversal',
      icon: '📁',
      severity: 'high',
      examples: [
        {
          url: "/api/weather/../../../etc/passwd",
          description: "Directory traversal to access system files"
        },
        {
          url: "/api/user/../../config/database.json",
          description: "Attempts to read database configuration"
        },
        {
          url: "/api/auth/../../../../etc/shadow",
          description: "Tries to access password hashes"
        }
      ]
    },
    {
      id: 'command',
      title: 'Command Injection',
      icon: '💻',
      severity: 'critical',
      examples: [
        {
          url: "/api/weather/search?q=Hanoi; ls -la",
          description: "Command injection via search query"
        },
        {
          url: "/api/weather/search?q=`whoami`",
          description: "Backtick command execution attempt"
        },
        {
          url: "/api/user/favorites?name=test$(cat /etc/passwd)",
          description: "Command substitution attack"
        }
      ]
    },
    {
      id: 'auth',
      title: 'Authentication Bypass',
      icon: '🔓',
      severity: 'critical',
      examples: [
        {
          url: "/api/auth/login?email=admin'--&password=anything",
          description: "SQL injection for auth bypass"
        },
        {
          url: "/api/auth/me?userId=1' OR '1'='1",
          description: "Attempts to access any user profile"
        }
      ]
    },
    {
      id: 'nosql',
      title: 'NoSQL Injection',
      icon: '🗄️',
      severity: 'high',
      examples: [
        {
          url: "/api/user/favorites?cityId[$ne]=null",
          description: "MongoDB operator injection"
        },
        {
          url: "/api/auth/login?email[$regex]=.*&password[$ne]=null",
          description: "MongoDB regex injection for auth bypass"
        }
      ]
    },
    {
      id: 'header',
      title: 'HTTP Header Injection',
      icon: '📋',
      severity: 'medium',
      examples: [
        {
          url: "/api/weather/current?lat=21.0285&lon=105.8542%0d%0aSet-Cookie:%20admin=true",
          description: "CRLF injection to set malicious cookies"
        },
        {
          url: "/api/user/preferences?lang=%0d%0aLocation:%20http://evil.com",
          description: "Header injection for redirect"
        }
      ]
    },
    {
      id: 'api',
      title: 'API Abuse',
      icon: '⚡',
      severity: 'medium',
      examples: [
        {
          url: "/api/weather/search?q=" + "A".repeat(10000),
          description: "Buffer overflow attempt with large payload"
        },
        {
          url: "/api/user/favorites?lat=9999999&lon=9999999",
          description: "Invalid coordinate parameters"
        }
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
          Real attack testing against your Weather App APIs
        </p>
        <div className="warning">
          <AlertTriangle size={20} />
          <span>⚠️ This tests REAL attacks on YOUR APIs - Use only in development!</span>
        </div>
      </div>

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
              Helmet Security
            </div>
            <div className={`status-badge ${wafStatus.rateLimit ? 'enabled' : 'disabled'}`}>
              {wafStatus.rateLimit ? <CheckCircle size={16} /> : <XCircle size={16} />}
              Rate Limiting
            </div>
            <div className={`status-badge ${wafStatus.modsecurity ? 'enabled' : 'disabled'}`}>
              {wafStatus.modsecurity ? <CheckCircle size={16} /> : <XCircle size={16} />}
              ModSecurity WAF
            </div>
            <div className={`status-badge enabled`}>
              <CheckCircle size={16} />
              {wafStatus.eventsLast24h || 0} events (24h)
            </div>
          </div>
        </motion.div>
      )}

      <div className="grid">
        <motion.div
          className="card"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
        >
          <h2><Terminal size={24} /> Attack Payloads</h2>
          
          <div className="info-box">
            <p>Click <strong>"Test Attack"</strong> to send real malicious requests to your APIs.</p>
            <p>ModSecurity should block them and log the events. ✅</p>
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
                          <div className="payload-description">
                            {example.description}
                          </div>
                          <pre className="payload-code">{example.url}</pre>
                          <button 
                            className="test-button"
                            onClick={() => testPayload(example.url, example.description)}
                            disabled={testing}
                          >
                            <Zap size={14} />
                            {testing ? 'Testing...' : 'Test Attack'}
                          </button>
                        </div>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}
          </div>
        </motion.div>

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
                  Click "Test Attack" on the left to see blocking in action!
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
                      <strong>{event.message}</strong>
                      <div className="event-path">{event.method} {event.path}</div>
                      {event.query && <div className="event-query">Query: {event.query.substring(0, 100)}</div>}
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

        .info-box {
          background: rgba(33, 150, 243, 0.1);
          border: 1px solid rgba(33, 150, 243, 0.3);
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 20px;
          color: #2196f3;
        }

        .info-box p {
          margin: 5px 0;
          font-size: 0.95rem;
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
          padding: 15px;
          background: rgba(0, 0, 0, 0.03);
          border-radius: 8px;
          margin-top: 10px;
          border: 1px solid rgba(0, 0, 0, 0.1);
        }

        [data-theme='dark'] .payload-item {
          background: rgba(0, 0, 0, 0.2);
          border-color: rgba(255, 255, 255, 0.1);
        }

        .payload-description {
          font-size: 0.9rem;
          color: #666;
          font-style: italic;
        }

        [data-theme='dark'] .payload-description {
          color: #aaa;
        }

        .payload-code {
          margin: 0;
          padding: 12px;
          background: rgba(0, 0, 0, 0.05);
          border: 1px solid rgba(0, 0, 0, 0.1);
          border-radius: 6px;
          font-size: 0.85rem;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }

        [data-theme='dark'] .payload-code {
          background: rgba(0, 0, 0, 0.3);
          border-color: rgba(255, 255, 255, 0.1);
        }

        .test-button {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          padding: 10px 20px;
          background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%);
          border: none;
          border-radius: 6px;
          color: white;
          font-size: 0.9rem;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s ease;
        }

        .test-button:hover:not(:disabled) {
          transform: translateY(-2px);
          box-shadow: 0 4px 12px rgba(244, 67, 54, 0.3);
        }

        .test-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
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

        .security-event.severity-high,
        .security-event.severity-critical {
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
          color: #f44336;
        }

        .event-time {
          font-size: 0.85rem;
          opacity: 0.7;
        }

        .event-details {
          font-size: 0.9rem;
          margin-top: 8px;
        }

        .event-path {
          font-family: monospace;
          background: rgba(0, 0, 0, 0.05);
          padding: 4px 8px;
          border-radius: 4px;
          margin-top: 5px;
          font-size: 0.85rem;
        }

        .event-query {
          font-family: monospace;
          font-size: 0.8rem;
          opacity: 0.7;
          margin-top: 5px;
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
      `}</style>
    </div>
  );
};

export default WAFDemo;