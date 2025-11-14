const User = require('../models/User');

const addFavorite = async (user, { name, country, lat, lon }) => {
  const existingFavorite = user.favoriteCities.find(
    city => city.name === name && city.country === country
  );

  if (existingFavorite) {
    throw new Error('City already in favorites');
  }

  user.favoriteCities.push({
    name,
    country,
    lat: parseFloat(lat),
    lon: parseFloat(lon)
  });

  await user.save();
  return user.favoriteCities;
};

const removeFavorite = async (user, cityId) => {
  user.favoriteCities = user.favoriteCities.filter(
    city => city._id.toString() !== cityId
  );
  await user.save();
  return user.favoriteCities;
};

const getFavorites = (user) => {
  return user.favoriteCities;
};

const addSearchToHistory = async (user, { city, country }) => {
  user.searchHistory = user.searchHistory.filter(
    search => !(search.city === city && search.country === country)
  );

  user.searchHistory.unshift({
    city,
    country
  });

  if (user.searchHistory.length > 20) {
    user.searchHistory = user.searchHistory.slice(0, 20);
  }

  await user.save();
  return user.searchHistory;
};

const getSearchHistory = (user) => {
  return user.searchHistory;
};

const clearSearchHistory = async (user) => {
  user.searchHistory = [];
  await user.save();
};

const updatePreferences = async (user, { temperatureUnit, language }) => {
  if (temperatureUnit) {
    user.preferences.temperatureUnit = temperatureUnit;
  }

  if (language) {
    user.preferences.language = language;
  }

  await user.save();
  return user.preferences;
};

const updateLastLocation = async (user, { lat, lon, city, country }) => {
  user.lastLocation = {
    lat: parseFloat(lat),
    lon: parseFloat(lon),
    city,
    country,
    updatedAt: new Date()
  };

  await user.save();
  return user.lastLocation;
};

module.exports = {
  addFavorite,
  removeFavorite,
  getFavorites,
  addSearchToHistory,
  getSearchHistory,
  clearSearchHistory,
  updatePreferences,
  updateLastLocation,
};
