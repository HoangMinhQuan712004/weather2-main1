const weatherApi = require('./weatherApi');

const getWeatherData = async (lat, lon, units = 'metric') => {
  return await weatherApi.get('/weather', { lat, lon, units });
};

const getForecastData = async (lat, lon, units = 'metric') => {
  return await weatherApi.get('/forecast', { lat, lon, units });
};

const getHistoricalData = async (lat, lon, dt) => {
  // Historical endpoint is disabled:
  // The previous implementation called OpenWeather 'onecall/timemachine' which
  // requires a paid/appropriate key and produced repeated 401 errors in our logs.
  // To avoid noisy failures, this function now throws a clear error. If you
  // want historical data again, replace this implementation with a supported
  // provider or enable the appropriate OpenWeather product and update the
  // configuration accordingly.
  console.warn('getHistoricalData was called but historical support is disabled.');
  throw new Error('Historical weather support is disabled on this server. Enable a provider or remove calls to this endpoint.');
};

const searchCities = async (query) => {
  if (!query || typeof query !== 'string' || query.trim().length === 0) {
    throw new Error('Invalid search query');
  }

  const trimmedQuery = query.trim();
  
  // Early return for very short queries
  if (trimmedQuery.length < 2) {
    return [];
  }

  // Use OpenWeather Geocoding API for reliable city search
  // https://openweathermap.org/api/geocoding-api
  try {
    const results = await weatherApi.get('http://api.openweathermap.org/geo/1.0/direct', { 
      q: trimmedQuery, 
      limit: 10 
    });

    // The geocoding endpoint returns an array of locations
    console.log(`Search for "${trimmedQuery}" returned ${Array.isArray(results) ? results.length : 0} results`);
    return results || [];
  } catch (error) {
    console.error('Search cities error:', error);
    // If the upstream returned a 401 / invalid API key, surface a clear error
    const status = error.response?.status;
    const respData = error.response?.data;
    if (status === 401 || (respData && (respData.cod === 401 || /invalid api key/i.test(respData.message || '')))) {
      const err = new Error('Invalid API key. Please see https://openweathermap.org/faq#error401 for more info.');
      err.code = 'API_KEY_INVALID';
      throw err;
    }
    // For other errors, rethrow so route can decide how to handle it
    throw error;
  }
};

module.exports = {
  getWeatherData,
  getForecastData,
  getHistoricalData,
  searchCities,
};
