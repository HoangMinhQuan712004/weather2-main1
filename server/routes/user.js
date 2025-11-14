const express = require('express');
const { body, validationResult } = require('express-validator');
const auth = require('../middleware/auth');
const userService = require('../services/userService');

const router = express.Router();

// @route   POST /api/user/favorites
// @desc    Add city to favorites
// @access  Private
router.post('/favorites', auth, [
  body('name').notEmpty().withMessage('City name is required'),
  body('country').notEmpty().withMessage('Country is required'),
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

    const favorites = await userService.addFavorite(req.user, req.body);
    res.json({
      message: 'City added to favorites',
      favorites,
    });
  } catch (error) {
    console.error('Add favorite error:', error);
    res.status(500).json({ message: error.message || 'Failed to add city to favorites' });
  }
});

// @route   DELETE /api/user/favorites/:cityId
// @desc    Remove city from favorites
// @access  Private
router.delete('/favorites/:cityId', auth, async (req, res) => {
  try {
    const { cityId } = req.params;
    const favorites = await userService.removeFavorite(req.user, cityId);
    res.json({
      message: 'City removed from favorites',
      favorites,
    });
  } catch (error) {
    console.error('Remove favorite error:', error);
    res.status(500).json({ message: 'Failed to remove city from favorites' });
  }
});

// @route   GET /api/user/favorites
// @desc    Get user's favorite cities
// @access  Private
router.get('/favorites', auth, async (req, res) => {
  try {
    const favorites = userService.getFavorites(req.user);
    res.json({
      favorites,
    });
  } catch (error) {
    console.error('Get favorites error:', error);
    res.status(500).json({ message: 'Failed to get favorite cities' });
  }
});

// @route   POST /api/user/search-history
// @desc    Add search to history
// @access  Private
router.post('/search-history', auth, [
  body('city').notEmpty().withMessage('City name is required'),
  body('country').notEmpty().withMessage('Country is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const searchHistory = await userService.addSearchToHistory(req.user, req.body);
    res.json({
      message: 'Search added to history',
      searchHistory,
    });
  } catch (error) {
    console.error('Add search history error:', error);
    res.status(500).json({ message: 'Failed to add search to history' });
  }
});

// @route   GET /api/user/search-history
// @desc    Get user's search history
// @access  Private
router.get('/search-history', auth, async (req, res) => {
  try {
    const searchHistory = userService.getSearchHistory(req.user);
    res.json({
      searchHistory,
    });
  } catch (error) {
    console.error('Get search history error:', error);
    res.status(500).json({ message: 'Failed to get search history' });
  }
});

// @route   DELETE /api/user/search-history
// @desc    Clear search history
// @access  Private
router.delete('/search-history', auth, async (req, res) => {
  try {
    await userService.clearSearchHistory(req.user);
    res.json({
      message: 'Search history cleared'
    });
  } catch (error) {
    console.error('Clear search history error:', error);
    res.status(500).json({ message: 'Failed to clear search history' });
  }
});

// @route   PUT /api/user/preferences
// @desc    Update user preferences
// @access  Private
router.put('/preferences', auth, [
  body('temperatureUnit')
    .optional()
    .isIn(['celsius', 'fahrenheit'])
    .withMessage('Temperature unit must be celsius or fahrenheit'),
  body('language')
    .optional()
    .isLength({ min: 2, max: 5 })
    .withMessage('Language must be 2-5 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const preferences = await userService.updatePreferences(req.user, req.body);
    res.json({
      message: 'Preferences updated',
      preferences,
    });
  } catch (error) {
    console.error('Update preferences error:', error);
    res.status(500).json({ message: 'Failed to update preferences' });
  }
});

// @route   PUT /api/user/last-location
// @desc    Update user's last location
// @access  Private
router.put('/last-location', auth, [
  body('lat').isNumeric().withMessage('Latitude must be a number'),
  body('lon').isNumeric().withMessage('Longitude must be a number'),
  body('city').notEmpty().withMessage('City name is required'),
  body('country').notEmpty().withMessage('Country is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const lastLocation = await userService.updateLastLocation(req.user, req.body);
    res.json({
      message: 'Last location updated',
      lastLocation,
    });
  } catch (error) {
    console.error('Update last location error:', error);
    res.status(500).json({ message: 'Failed to update last location' });
  }
});

module.exports = router;