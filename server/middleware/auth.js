const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    const secret = process.env.JWT_SECRET || 'fallback_secret_key_for_development_only';
    const decoded = jwt.verify(token, secret);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ message: 'Token is not valid' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    // Helpful debug info: indicate whether an Authorization header was present
    try {
      const rawAuth = req.header('Authorization');
      if (rawAuth) {
        // don't log full token; show masked prefix for debugging
        const token = rawAuth.replace('Bearer ', '');
        console.warn('Authorization header present. token prefix:', token.slice(0, 12) + '...');
      } else {
        console.warn('No Authorization header present on request');
      }
    } catch (e) {
      // ignore logging errors
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    res.status(401).json({ message: 'Token is not valid' });
  }
};

module.exports = auth;
