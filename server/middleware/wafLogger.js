const SecurityEvent = require('../models/SecurityEvent');

// Map ModSecurity rule IDs to attack types
const getRuleInfo = (ruleId) => {
  const ruleMap = {
    '942': { type: 'SQL Injection', severity: 'high' },
    '941': { type: 'XSS (Cross-Site Scripting)', severity: 'high' },
    '930': { type: 'Path Traversal', severity: 'high' },
    '932': { type: 'Command Injection', severity: 'critical' },
    '933': { type: 'Local File Inclusion', severity: 'medium' },
    '934': { type: 'Server-Side Request Forgery', severity: 'medium' },
    '920': { type: 'HTTP Header Injection', severity: 'medium' },
    '921': { type: 'Protocol Attack', severity: 'medium' }
  };
  
  const prefix = ruleId.substring(0, 3);
  return ruleMap[prefix] || { type: 'BLOCKED_REQUEST', severity: 'medium' };
};

// Middleware to log WAF blocks
const wafLogger = (req, res, next) => {
  // Store original send function
  const originalSend = res.send;
  const originalJson = res.json;
  
  // Flag to prevent double logging
  let logged = false;
  
  const logEvent = async () => {
    if (logged) return;
    logged = true;
    
    // Only log 403 responses (blocked by WAF)
    if (res.statusCode !== 403) return;
    
    try {
      // Try to detect attack type from request
      const url = req.originalUrl || req.url;
      const queryString = JSON.stringify(req.query);
      const bodyString = JSON.stringify(req.body);
      
      let type = 'BLOCKED_REQUEST';
      let severity = 'medium';
      let details = '';
      
      // SQL Injection patterns
      if (queryString.match(/('|--|union|select|drop|insert|delete|update|or\s+\d+=\d+)/i) ||
          bodyString.match(/('|--|union|select|drop|insert|delete|update|or\s+\d+=\d+)/i)) {
        type = 'SQL Injection';
        severity = 'high';
        details = 'SQL injection pattern detected in request';
      }
      // XSS patterns
      else if (queryString.match(/(<script|javascript:|onerror=|onload=|<img|alert\()/i) ||
               bodyString.match(/(<script|javascript:|onerror=|onload=|<img|alert\()/i)) {
        type = 'XSS (Cross-Site Scripting)';
        severity = 'high';
        details = 'XSS attack pattern detected in request';
      }
      // Path Traversal patterns
      else if (url.match(/\.\.[\/\\]|\.\.%2f|\.\.%5c/i)) {
        type = 'Path Traversal';
        severity = 'high';
        details = 'Path traversal pattern detected in URL';
      }
      // Command Injection patterns
      else if (queryString.match(/[;&|`$()]|exec|eval|system/i) ||
               bodyString.match(/[;&|`$()]|exec|eval|system/i)) {
        type = 'Command Injection';
        severity = 'critical';
        details = 'Command injection pattern detected';
      }
      
      const eventData = {
        type,
        severity,
        ip: req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown',
        userAgent: req.get('user-agent') || 'unknown',
        method: req.method,
        path: req.path || url,
        query: queryString.substring(0, 500), // Limit size
        message: `${type} attempt blocked by WAF`,
        details: details || `Blocked request to ${req.method} ${url}`,
        blocked: true
      };
      
      await SecurityEvent.create(eventData);
      console.log(`[WAF] Logged security event: ${type} from ${eventData.ip}`);
    } catch (error) {
      console.error('[WAF] Failed to log security event:', error);
    }
  };
  
  // Override res.send
  res.send = function(data) {
    logEvent();
    return originalSend.call(this, data);
  };
  
  // Override res.json
  res.json = function(data) {
    logEvent();
    return originalJson.call(this, data);
  };
  
  next();
};

module.exports = wafLogger;