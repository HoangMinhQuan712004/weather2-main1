const express = require('express');
const router = express.Router();
const SecurityEvent = require('../models/SecurityEvent');

// Admin key from environment
const ADMIN_KEY = process.env.ADMIN_KEY || 'dev-admin-key-change-in-production';

// Middleware to check admin key
const requireAdmin = (req, res, next) => {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey !== ADMIN_KEY) {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  next();
};

// GET /api/security/status - Get WAF protection status
router.get('/status', async (req, res) => {
  try {
    const recentEvents = await SecurityEvent.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });
    
    res.json({
      securityEnabled: true,
      helmet: true,
      rateLimit: true,
      mongoSanitize: false,
      xssClean: false,
      modsecurity: true,
      eventsLast24h: recentEvents,
      message: 'WAF is active and protecting your application'
    });
  } catch (error) {
    console.error('Status error:', error);
    res.status(500).json({ message: 'Failed to get status' });
  }
});

// GET /api/security/events - Get security events (requires admin key)
router.get('/events', requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const skip = parseInt(req.query.skip) || 0;
    
    const events = await SecurityEvent.find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip)
      .lean();
    
    const total = await SecurityEvent.countDocuments();
    
    res.json({
      events,
      total,
      page: Math.floor(skip / limit) + 1,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ message: 'Failed to fetch security events' });
  }
});

// DELETE /api/security/events - Clear all events (requires admin key)
router.delete('/events', requireAdmin, async (req, res) => {
  try {
    await SecurityEvent.deleteMany({});
    res.json({ 
      message: 'All security events cleared',
      deleted: true 
    });
  } catch (error) {
    console.error('Clear events error:', error);
    res.status(500).json({ message: 'Failed to clear events' });
  }
});

// POST /api/security/log - Log a security event (internal use)
router.post('/log', async (req, res) => {
  try {
    const eventData = {
      type: req.body.type || 'BLOCKED_REQUEST',
      severity: req.body.severity || 'medium',
      ip: req.ip || req.headers['x-forwarded-for'] || 'unknown',
      userAgent: req.get('user-agent') || 'unknown',
      method: req.body.method || 'GET',
      path: req.body.path || '/',
      query: req.body.query || '',
      message: req.body.message || 'Security event detected',
      details: req.body.details || '',
      ruleId: req.body.ruleId || '',
      blocked: req.body.blocked !== false
    };
    
    const event = await SecurityEvent.create(eventData);
    res.status(201).json({ 
      message: 'Event logged successfully',
      event 
    });
  } catch (error) {
    console.error('Log event error:', error);
    res.status(500).json({ message: 'Failed to log event' });
  }
});

module.exports = router;
