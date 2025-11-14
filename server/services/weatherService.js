const weatherApi = require('./weatherApi');

const getWeatherData = async (lat, lon, units = 'metric') => {
  return await weatherApi.get('/weather', { lat, lon, units });
};

const getForecastData = async (lat, lon, units = 'metric') => {
  return await weatherApi.get('/forecast', { lat, lon, units });
};

const getHistoricalData = async (lat, lon, dt) => {
  // dt should be a Unix timestamp (in seconds)
  // This is a placeholder. A real implementation would use a specific historical API endpoint.
  // For example, OpenWeatherMap One Call API 3.0 historical data or similar.
  console.log(`Fetching historical data for lat: ${lat}, lon: ${lon}, dt: ${dt}`);
  try {
    const response = await weatherApi.get('https://api.openweathermap.org/data/2.5/onecall/timemachine', { 
      lat, 
      lon, 
      dt, 
      units: 'metric' // Assuming metric units for historical data
    });
    return response;
  } catch (error) {
    console.error('Error fetching historical data:', error);
    throw error;
  }
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

  try {
    // Use OpenWeather Geocoding API for reliable city search
    // https://openweathermap.org/api/geocoding-api
    const results = await weatherApi.get('http://api.openweathermap.org/geo/1.0/direct', { 
      q: trimmedQuery, 
      limit: 10 
    });
    
    // The geocoding endpoint returns an array of locations
    console.log(`Search for "${trimmedQuery}" returned ${Array.isArray(results) ? results.length : 0} results`);
    return results || [];
  } catch (error) {
    console.error('Search cities error:', error);
    // Return empty array instead of throwing to prevent app crashes
    return [];
  }
};

module.exports = {
  getWeatherData,
  getForecastData,
  getHistoricalData,
  searchCities,
};
