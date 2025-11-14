const axios = require('axios');

const WEATHER_API_KEY = process.env.WEATHER_API_KEY;
const WEATHER_BASE_URL = 'https://api.openweathermap.org/data/2.5';

if (!WEATHER_API_KEY) {
  console.warn('WARNING: WEATHER_API_KEY is not set. Weather requests will fail.');
}

const client = axios.create({
  baseURL: WEATHER_BASE_URL,
  timeout: 15000, // Increased timeout to 15 seconds
  headers: {
    'User-Agent': 'WeatherApp/1.0'
  }
});

// Simple in-memory cache for weather data
const cache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
const SEARCH_CACHE_DURATION = 10 * 60 * 1000; // 10 minutes for search results

const getCacheKey = (path, params) => {
  return `${path}_${JSON.stringify(params)}`;
};

const isCacheValid = (timestamp, isSearch = false) => {
  const duration = isSearch ? SEARCH_CACHE_DURATION : CACHE_DURATION;
  return Date.now() - timestamp < duration;
};

const get = async (path, params = {}) => {
  try {
    const cacheKey = getCacheKey(path, params);
    const cached = cache.get(cacheKey);
    const isSearch = path.includes('geo') || path.includes('direct');
    
    // Return cached data if valid
    if (cached && isCacheValid(cached.timestamp, isSearch)) {
      console.log('Returning cached weather data for:', cacheKey);
      return cached.data;
    }

    // If an absolute URL is provided, axios will use it instead of baseURL
    const response = await client.get(path, { params: { ...params, appid: WEATHER_API_KEY } });
    
    // Cache the response
    cache.set(cacheKey, {
      data: response.data,
      timestamp: Date.now()
    });
    
    // Clean up old cache entries periodically
    if (cache.size > 100) {
      const now = Date.now();
      for (const [key, value] of cache.entries()) {
        const keyIsSearch = key.includes('geo') || key.includes('direct');
        if (!isCacheValid(value.timestamp, keyIsSearch)) {
          cache.delete(key);
        }
      }
    }
    
    return response.data;
  } catch (err) {
    const respData = err.response?.data;
    const msg = respData?.message || respData || err.message;
    // Log structured error for debugging
    console.error('Weather API request failed:', respData || err.message);
    // Ensure we throw a string message (avoid Error([object Object]))
    const safeMessage = typeof msg === 'string' ? msg : JSON.stringify(msg);
    throw new Error(safeMessage);
  }
};

module.exports = { get };
