const express = require('express');
const auth = require('../middleware/auth');
const { getWeatherData, getForecastData, getHistoricalData, searchCities } = require('../services/weatherService');

const router = express.Router();

// Request deduplication to prevent multiple identical requests
const pendingRequests = new Map();
const requestTimestamps = new Map();

const deduplicateRequest = async (key, requestFn) => {
  // Check if request is already in progress
  if (pendingRequests.has(key)) {
    console.log(`Request ${key} already in progress, waiting for result...`);
    return pendingRequests.get(key);
  }
  
  // Check if we made the same request recently (within 500ms to prevent duplicate searches)
  const lastRequestTime = requestTimestamps.get(key);
  if (lastRequestTime && Date.now() - lastRequestTime < 500) {
    console.log(`Request ${key} made too recently, skipping...`);
    return null;
  }
  
  // Record timestamp
  requestTimestamps.set(key, Date.now());
  
  const promise = requestFn().finally(() => {
    pendingRequests.delete(key);
    // Clean up old timestamps
    setTimeout(() => {
      requestTimestamps.delete(key);
    }, 5000);
  });
  
  pendingRequests.set(key, promise);
  return promise;
};

// @route   GET /api/weather/current
// @desc    Get current weather by coordinates
// @access  Private
router.get('/current', auth, async (req, res) => {
  try {
    const { lat, lon, units = 'metric' } = req.query;

    if (!lat || !lon) {
      return res.status(400).json({ message: 'Latitude and longitude are required' });
    }

    // Validate coordinates
    const latitude = parseFloat(lat);
    const longitude = parseFloat(lon);
    
    if (isNaN(latitude) || isNaN(longitude) || 
        latitude < -90 || latitude > 90 || 
        longitude < -180 || longitude > 180) {
      return res.status(400).json({ message: 'Invalid coordinates provided' });
    }

    const requestKey = `current_${latitude}_${longitude}_${units}`;
    const weatherData = await deduplicateRequest(requestKey, () => 
      getWeatherData(latitude, longitude, units)
    );
    
    // Format the response
    const formattedData = {
      location: {
        name: weatherData.name,
        country: weatherData.sys.country,
        lat: weatherData.coord.lat,
        lon: weatherData.coord.lon
      },
      current: {
        temperature: Math.round(weatherData.main.temp),
        feelsLike: Math.round(weatherData.main.feels_like),
        humidity: weatherData.main.humidity,
        pressure: weatherData.main.pressure,
        visibility: weatherData.visibility / 1000, // Convert to km
        uvIndex: weatherData.uvi || 0,
        wind: {
          speed: weatherData.wind.speed,
          direction: weatherData.wind.deg
        },
        weather: {
          main: weatherData.weather[0].main,
          description: weatherData.weather[0].description,
          icon: weatherData.weather[0].icon
        },
        sunrise: new Date(weatherData.sys.sunrise * 1000),
        sunset: new Date(weatherData.sys.sunset * 1000)
      },
      timestamp: new Date()
    };

    res.json(formattedData);
  } catch (error) {
    console.error('Current weather error:', error);
    res.status(500).json({ message: error.message || 'Failed to fetch current weather' });
  }
});

// @route   GET /api/weather/forecast
// @desc    Get weather forecast by coordinates
// @access  Private
router.get('/forecast', auth, async (req, res) => {
  try {
    const { lat, lon, units = 'metric' } = req.query;

    if (!lat || !lon) {
      return res.status(400).json({ message: 'Latitude and longitude are required' });
    }

    // Validate coordinates
    const latitude = parseFloat(lat);
    const longitude = parseFloat(lon);
    
    if (isNaN(latitude) || isNaN(longitude) || 
        latitude < -90 || latitude > 90 || 
        longitude < -180 || longitude > 180) {
      return res.status(400).json({ message: 'Invalid coordinates provided' });
    }

    const requestKey = `forecast_${latitude}_${longitude}_${units}`;
    const forecastData = await deduplicateRequest(requestKey, () => 
      getForecastData(latitude, longitude, units)
    );
    
    // Group forecast by day
    const dailyForecast = {};
    const hourlyForecast = [];

    forecastData.list.forEach(item => {
      const date = new Date(item.dt * 1000);
      const dateKey = date.toDateString();
      
      if (!dailyForecast[dateKey]) {
        dailyForecast[dateKey] = {
          date: date,
          temps: [],
          weather: item.weather[0],
          humidity: [],
          wind: []
        };
      }
      
      dailyForecast[dateKey].temps.push(item.main.temp);
      dailyForecast[dateKey].humidity.push(item.main.humidity);
      dailyForecast[dateKey].wind.push(item.wind.speed);
      
      // Add to hourly forecast (next 24 hours)
      if (hourlyForecast.length < 8) {
        hourlyForecast.push({
          time: date,
          temperature: Math.round(item.main.temp),
          weather: item.weather[0],
          humidity: item.main.humidity,
          windSpeed: item.wind.speed
        });
      }
    });

    // Calculate daily min/max temperatures
    const formattedDailyForecast = Object.values(dailyForecast).map(day => ({
      date: day.date,
      temperature: {
        min: Math.round(Math.min(...day.temps)),
        max: Math.round(Math.max(...day.temps))
      },
      weather: day.weather,
      humidity: Math.round(day.humidity.reduce((a, b) => a + b) / day.humidity.length),
      windSpeed: Math.round(day.wind.reduce((a, b) => a + b) / day.wind.length)
    }));

    res.json({
      location: {
        name: forecastData.city.name,
        country: forecastData.city.country,
        lat: forecastData.city.coord.lat,
        lon: forecastData.city.coord.lon
      },
      daily: formattedDailyForecast,
      hourly: hourlyForecast,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Forecast error:', error);
    res.status(500).json({ message: error.message || 'Failed to fetch forecast' });
  }
});

// @route   GET /api/weather/historical
// @desc    Get historical weather data by coordinates and timestamp
// @access  Private
router.get('/historical', auth, async (req, res) => {
  try {
    const { lat, lon, dt } = req.query;

    if (!lat || !lon || !dt) {
      return res.status(400).json({ message: 'Latitude, longitude, and timestamp (dt) are required' });
    }

    const latitude = parseFloat(lat);
    const longitude = parseFloat(lon);
    const timestamp = parseInt(dt, 10);

    if (isNaN(latitude) || isNaN(longitude) || isNaN(timestamp)) {
      return res.status(400).json({ message: 'Invalid coordinates or timestamp provided' });
    }

    // Historical data support has been disabled on the server because the
    // upstream provider (One Call timemachine) required a different product
    // and produced repeated 401 errors. Return a clear 501 response so
    // clients know this endpoint is intentionally unavailable.
    return res.status(501).json({
      message: 'Historical weather endpoint is disabled on this server. Enable a provider or contact the administrator.'
    });
  } catch (error) {
    console.error('Historical weather error:', error);
    res.status(500).json({ message: error.message || 'Failed to fetch historical weather' });
  }
});

// @route   GET /api/weather/search
// @desc    Search for cities
// @access  Public (no auth required)
router.get('/search', async (req, res) => {
  try {
    const { q } = req.query;

    if (!q || q.length < 2) {
      return res.status(400).json({ message: 'Search query must be at least 2 characters' });
    }

    // Sanitize search query
    const sanitizedQuery = q.trim().substring(0, 100); // Limit length and trim whitespace
    
    const requestKey = `search_${sanitizedQuery}`;
    const searchResults = await deduplicateRequest(requestKey, () => 
      searchCities(sanitizedQuery)
    );
    
    // If request was skipped due to recent duplicate, return empty results
    if (searchResults === null) {
      return res.json({
        results: [],
        count: 0,
        message: 'Request skipped due to recent duplicate'
      });
    }

    // geocoding returns an array of places
    const formattedResults = Array.isArray(searchResults)
      ? searchResults.map(item => ({
          name: item.name,
          country: item.country || item.sys?.country || null,
          lat: item.lat || item.coord?.lat,
          lon: item.lon || item.coord?.lon,
          state: item.state || null
        }))
      : [];

    console.log(`Search for "${sanitizedQuery}" returned ${formattedResults.length} results`);

    res.json({
      results: formattedResults,
      count: formattedResults.length
    });
  } catch (error) {
    console.error('Search error:', error);
    
    // Check if it's an API key issue
    if (error.message && error.message.includes('Invalid API key')) {
      return res.status(500).json({ 
        message: 'Weather API key is not configured. Please check server configuration.',
        error: 'API_KEY_MISSING'
      });
    }
    
    res.status(500).json({ 
      message: error.message || 'Failed to search cities',
      error: 'SEARCH_FAILED'
    });
  }
});

// @route   GET /api/weather/geolocation
// @desc    Get weather by geolocation
// @access  Public (no auth required)
router.get('/geolocation', async (req, res) => {
  try {
    const { lat, lon, units = 'metric' } = req.query;

    if (!lat || !lon) {
      return res.status(400).json({ message: 'Latitude and longitude are required' });
    }

    // Get both current weather and forecast
    const [currentWeather, forecast] = await Promise.all([
      getWeatherData(lat, lon, units),
      getForecastData(lat, lon, units)
    ]);

    // Format current weather
    const current = {
      temperature: Math.round(currentWeather.main.temp),
      feelsLike: Math.round(currentWeather.main.feels_like),
      humidity: currentWeather.main.humidity,
      pressure: currentWeather.main.pressure,
      visibility: currentWeather.visibility / 1000,
      uvIndex: currentWeather.uvi || 0,
      wind: {
        speed: currentWeather.wind.speed,
        direction: currentWeather.wind.deg
      },
      weather: {
        main: currentWeather.weather[0].main,
        description: currentWeather.weather[0].description,
        icon: currentWeather.weather[0].icon
      },
      sunrise: new Date(currentWeather.sys.sunrise * 1000),
      sunset: new Date(currentWeather.sys.sunset * 1000)
    };

    // Format hourly forecast (next 24 hours)
    const hourly = forecast.list.slice(0, 8).map(item => ({
      time: new Date(item.dt * 1000),
      temperature: Math.round(item.main.temp),
      weather: item.weather[0],
      humidity: item.main.humidity,
      windSpeed: item.wind.speed
    }));

    // Group forecast by day for daily forecast
    const dailyForecast = {};
    forecast.list.forEach(item => {
      const date = new Date(item.dt * 1000);
      const dateKey = date.toDateString();
      
      if (!dailyForecast[dateKey]) {
        dailyForecast[dateKey] = {
          date: date,
          temps: [],
          weather: item.weather[0],
          humidity: [],
          wind: []
        };
      }
      
      dailyForecast[dateKey].temps.push(item.main.temp);
      dailyForecast[dateKey].humidity.push(item.main.humidity);
      dailyForecast[dateKey].wind.push(item.wind.speed);
    });

    // Calculate daily min/max temperatures
    const daily = Object.values(dailyForecast).map(day => ({
      date: day.date,
      temperature: {
        min: Math.round(Math.min(...day.temps)),
        max: Math.round(Math.max(...day.temps))
      },
      weather: day.weather,
      humidity: Math.round(day.humidity.reduce((a, b) => a + b) / day.humidity.length),
      windSpeed: Math.round(day.wind.reduce((a, b) => a + b) / day.wind.length)
    }));

    res.json({
      location: {
        name: currentWeather.name,
        country: currentWeather.sys.country,
        lat: currentWeather.coord.lat,
        lon: currentWeather.coord.lon
      },
      current,
      hourly,
      daily,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Geolocation weather error:', error);
    res.status(500).json({ message: error.message || 'Failed to fetch weather data' });
  }
});

module.exports = router;