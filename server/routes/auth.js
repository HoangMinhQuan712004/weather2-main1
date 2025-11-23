const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const auth = require('../middleware/auth');

const router = express.Router();

// Generate JWT token
const generateToken = (userId) => {
  const secret = process.env.JWT_SECRET || 'fallback_secret_key_for_development_only';
  if (!process.env.JWT_SECRET) {
    console.warn('WARNING: JWT_SECRET not set, using fallback key. This is not secure for production!');
  }
  return jwt.sign({ userId }, secret, { expiresIn: '7d' });
};

// ============================
// Register normal user
// ============================
router.post('/register', [
  // username is required for normal flow but optional when registering via CCCD
  body('username')
    .if((value, { req }) => !req.body.cccd)
    .isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters'),
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });

    // Basic required fields
    let { username, email, password } = req.body;

    // Optional CCCD-related fields (only used if provided)
    const { cccd, name, fullName, dateOfBirth, gender, address } = req.body;

    // If username not provided but CCCD present, generate a stable username
    if (!username && req.body.cccd) {
      username = `cccd_${Date.now()}`;
    }

    // Check if user exists (by email or username if present)
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(400).json({ message: 'User with this email or username already exists' });

    const userData = { username, email, password };
    if (cccd) userData.cccd = cccd;
    const providedName = fullName || name;
    if (providedName) userData.fullName = providedName;
    if (dateOfBirth) userData.dateOfBirth = new Date(dateOfBirth);
    if (gender) userData.gender = gender;
    if (address) userData.address = address;

    const user = new User(userData);
    await user.save();

    const token = generateToken(user._id);
    res.status(201).json({ message: 'User registered successfully', token, user: user.getPublicProfile() });
  } catch (error) {
    console.error('Registration error:', error.message);
    console.error('Stack trace:', error.stack);
    // Return detailed error message to help with debugging
    res.status(500).json({ 
      message: 'Server error during registration',
      error: error.message || 'Unknown error'
    });
  }
});

// ============================
// Login normal (username/email + password)
// ============================
router.post('/login', [
  body('email').isEmail().withMessage('Please provide a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = generateToken(user._id);
    res.json({ message: 'Login successful', token, user: user.getPublicProfile() });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// ============================
// Login with CCCD
// ============================
router.post('/login/cccd', [
  body('so_cccd').notEmpty().withMessage('Please provide your CCCD')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array() });

    const { so_cccd } = req.body;
    const user = await User.findOne({ cccd: so_cccd });
    if (!user) return res.status(404).json({ message: 'CCCD chưa được đăng ký' });


    const token = generateToken(user._id);
    res.json({ message: 'Login successful', token, user: user.getPublicProfile() });
  } catch (error) {
    console.error('CCCD login error:', error);
    res.status(500).json({ message: 'Server error during CCCD login' });
  }
});

// ============================
// Get current user
// ============================
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user: user.getPublicProfile() });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
