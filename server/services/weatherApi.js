require('dotenv').config({ path: `${__dirname}/../../.env` });
const axios = require('axios');

const WEATHER_API_KEY = process.env.WEATHER_API_KEY;
const WEATHER_BASE_URL = 'https://api.openweathermap.org/data/2.5';

if (!WEATHER_API_KEY) {
  console.warn('WARNING: WEATHER_API_KEY is not set. Weather requests will fail.');
}

// Cached flag: if OpenWeather responds with 401 Invalid API key,
// we flip this to true and fail fast on subsequent requests to avoid
// spamming logs and repeated network attempts.
let invalidApiKey = false;

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
    if (invalidApiKey) {
      throw new Error('WEATHER_API_KEY appears to be invalid (cached). Set a valid key in server/.env');
    }
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
    // If the API returned 401 / invalid key, mark and provide a clear notice
    const status = err.response?.status;
    if (status === 401 || (respData && (respData.cod === 401 || /invalid api key/i.test(respData.message || '')))) {
      invalidApiKey = true;
      console.error('OpenWeather responded with 401 Invalid API key. Please verify the value of WEATHER_API_KEY in server/.env and ensure the key is valid and has access to the requested endpoints.');
    }
    // Ensure we throw a string message (avoid Error([object Object]))
    const safeMessage = typeof msg === 'string' ? msg : JSON.stringify(msg);
    throw new Error(safeMessage);
  }
};

module.exports = { get };
