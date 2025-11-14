const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const auth = require('../middleware/auth');

const router = express.Router();

// @route   POST /api/discord/connect
// @desc    Connect Discord account to user
// @access  Private
router.post('/connect', auth, [
  body('discordUserId').notEmpty().withMessage('Discord User ID is required'),
  body('channelId').notEmpty().withMessage('Channel ID is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { discordUserId, channelId } = req.body;

    // Update user with Discord info
    req.user.discord = {
      userId: discordUserId,
      channelId: channelId,
      subscribed: false
    };

    await req.user.save();

    res.json({
      message: 'Discord account connected successfully',
      discord: req.user.discord
    });
  } catch (error) {
    console.error('Discord connect error:', error);
    res.status(500).json({ message: 'Failed to connect Discord account' });
  }
});

// @route   POST /api/discord/subscribe
// @desc    Subscribe to Discord weather notifications
// @access  Private
router.post('/subscribe', auth, [
  body('city').notEmpty().withMessage('City name is required'),
  body('lat').isNumeric().withMessage('Latitude must be a number'),
  body('lon').isNumeric().withMessage('Longitude must be a number')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { city, lat, lon } = req.body;

    if (!req.user.discord?.userId) {
      return res.status(400).json({ 
        message: 'Discord account not connected. Please connect your Discord account first.' 
      });
    }

    // Update user's Discord notification preferences
    req.user.discord.subscribed = true;
    req.user.discord.notificationCity = city;
    req.user.discord.lastNotification = null;

    await req.user.save();

    res.json({
      message: 'Successfully subscribed to Discord weather notifications',
      discord: req.user.discord
    });
  } catch (error) {
    console.error('Discord subscribe error:', error);
    res.status(500).json({ message: 'Failed to subscribe to notifications' });
  }
});

// @route   POST /api/discord/unsubscribe
// @desc    Unsubscribe from Discord weather notifications
// @access  Private
router.post('/unsubscribe', auth, async (req, res) => {
  try {
    if (!req.user.discord?.userId) {
      return res.status(400).json({ 
        message: 'Discord account not connected' 
      });
    }

    // Update user's Discord notification preferences
    req.user.discord.subscribed = false;
    req.user.discord.notificationCity = null;

    await req.user.save();

    res.json({
      message: 'Successfully unsubscribed from Discord weather notifications',
      discord: req.user.discord
    });
  } catch (error) {
    console.error('Discord unsubscribe error:', error);
    res.status(500).json({ message: 'Failed to unsubscribe from notifications' });
  }
});

// @route   GET /api/discord/status
// @desc    Get Discord connection status
// @access  Private
router.get('/status', auth, async (req, res) => {
  try {
    const discordStatus = {
      connected: !!req.user.discord?.userId,
      subscribed: req.user.discord?.subscribed || false,
      notificationCity: req.user.discord?.notificationCity || null,
      lastNotification: req.user.discord?.lastNotification || null
    };

    res.json({
      discord: discordStatus
    });
  } catch (error) {
    console.error('Discord status error:', error);
    res.status(500).json({ message: 'Failed to get Discord status' });
  }
});

// @route   PUT /api/discord/update-city
// @desc    Update notification city
// @access  Private
router.put('/update-city', auth, [
  body('city').notEmpty().withMessage('City name is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { city } = req.body;

    if (!req.user.discord?.userId) {
      return res.status(400).json({ 
        message: 'Discord account not connected' 
      });
    }

    if (!req.user.discord.subscribed) {
      return res.status(400).json({ 
        message: 'Not subscribed to notifications' 
      });
    }

    // Update notification city
    req.user.discord.notificationCity = city;
    await req.user.save();

    res.json({
      message: 'Notification city updated successfully',
      discord: req.user.discord
    });
  } catch (error) {
    console.error('Discord update city error:', error);
    res.status(500).json({ message: 'Failed to update notification city' });
  }
});

module.exports = router;
