const express = require('express');
const SecurityEvent = require('../models/SecurityEvent');

const router = express.Router();

const SECURITY_ENABLED = process.env.ENABLE_SECURITY !== 'false';

router.get('/status', (req, res) => {
  res.json({
    helmet: true,
    rateLimit: true,
    mongoSanitize: SECURITY_ENABLED,
    xssClean: SECURITY_ENABLED,
    hpp: SECURITY_ENABLED,
    contentSecurityPolicy: SECURITY_ENABLED,
    securityEnabled: SECURITY_ENABLED
  });
});

function requireAdminKey(req, res, next) {
  const adminKey = process.env.ADMIN_API_KEY;
  if (!adminKey) {
    return res.status(500).json({
      message: 'ADMIN_API_KEY chưa được cấu hình trong server'
    });
  }

  const providedKey = req.header('x-admin-key');
  if (!providedKey || providedKey !== adminKey) {
    return res.status(403).json({ message: 'Admin key không hợp lệ' });
  }
  next();
}

router.get('/events', requireAdminKey, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const type = req.query.type;

    const filter = {};
    if (type) {
      filter.type = type;
    }

    const events = await SecurityEvent.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    res.json({ events });
  } catch (error) {
    console.error('Lỗi lấy security events:', error);
    res.status(500).json({ message: 'Không thể tải danh sách sự kiện' });
  }
});

router.delete('/events/:id', requireAdminKey, async (req, res) => {
  try {
    await SecurityEvent.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    console.error('Lỗi xoá security event:', error);
    res.status(500).json({ message: 'Không thể xoá sự kiện' });
  }
});

router.delete('/events', requireAdminKey, async (req, res) => {
  try {
    await SecurityEvent.deleteMany({});
    res.json({ success: true });
  } catch (error) {
    console.error('Lỗi xoá danh sách security event:', error);
    res.status(500).json({ message: 'Không thể xoá sự kiện' });
  }
});

module.exports = router;

