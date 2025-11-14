import React, { createContext, useContext, useReducer, useEffect, useMemo, useCallback, useRef } from 'react';
import api from '../services/api';
import toast from 'react-hot-toast';

const WeatherContext = createContext();

const initialState = {
  currentWeather: null,
  forecast: null,
  searchResults: [],
  favoriteCities: [],
  searchHistory: [],
  loading: false,
  error: null,
  units: 'metric',
  isRequestInProgress: false,
  searchLoading: false // Separate loading state for search
};

const weatherReducer = (state, action) => {
  switch (action.type) {
    case 'SET_LOADING':
      return { ...state, loading: action.payload };
    case 'SET_SEARCH_LOADING':
      return { ...state, searchLoading: action.payload };
    case 'SET_REQUEST_IN_PROGRESS':
      return { ...state, isRequestInProgress: action.payload };
    case 'SET_ERROR':
      return { ...state, error: action.payload, loading: false, isRequestInProgress: false, searchLoading: false };
    case 'SET_CURRENT_WEATHER':
      return { ...state, currentWeather: action.payload, loading: false, error: null, isRequestInProgress: false };
    case 'SET_FORECAST':
      return { ...state, forecast: action.payload, loading: false, error: null, isRequestInProgress: false };
    case 'SET_SEARCH_RESULTS':
      return { ...state, searchResults: action.payload, searchLoading: false };
    case 'SET_FAVORITE_CITIES':
      return { ...state, favoriteCities: action.payload };
    case 'SET_SEARCH_HISTORY':
      return { ...state, searchHistory: action.payload };
    case 'SET_UNITS':
      return { ...state, units: action.payload };
    case 'CLEAR_SEARCH_RESULTS':
      return { ...state, searchResults: [], searchLoading: false };
    default:
      return state;
  }
};

export const WeatherProvider = ({ children }) => {
  const [state, dispatch] = useReducer(weatherReducer, initialState);
  
  // Cache for API requests to prevent duplicate calls
  const requestCache = useRef(new Map());
  const searchCache = useRef(new Map());
  const lastSearchQuery = useRef('');
  const searchTimeoutRef = useRef(null);
  const activeRequests = useRef(new Map()); // Track active requests to prevent duplicates

  const apiRequest = useCallback(async (apiCall, successAction, errorMessage, successMessage, requestKey) => {
    // Create a unique key for this request type
    const key = requestKey || 'default';
    
    // Check if this exact request is already in progress
    if (activeRequests.current.has(key)) {
      console.log(`Request ${key} already in progress, waiting for result...`);
      return activeRequests.current.get(key);
    }

    // Prevent multiple simultaneous requests of the same type
    if (state.isRequestInProgress && !requestKey) {
      console.log('Request already in progress, skipping...');
      return;
    }

    const requestPromise = (async () => {
      try {
        dispatch({ type: 'SET_REQUEST_IN_PROGRESS', payload: true });
        dispatch({ type: 'SET_LOADING', payload: true });
        const response = await apiCall();
        if (successAction) {
          dispatch(successAction(response.data));
        }
        if (successMessage) {
          toast.success(successMessage);
        }
        return response.data;
      } catch (error) {
        const message = error.response?.data?.message || errorMessage || 'API request failed';
        dispatch({ type: 'SET_ERROR', payload: message });
        toast.error(message);
        throw error;
      } finally {
        // Remove from active requests
        activeRequests.current.delete(key);
      }
    })();

    // Store the promise for deduplication
    activeRequests.current.set(key, requestPromise);
    return requestPromise;
  }, [state.isRequestInProgress]);

  const getCurrentWeather = useCallback(async (lat, lon) => {
    // Check cache first
    const cacheKey = `current_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`;
    if (requestCache.current.has(cacheKey)) {
      const cachedEntry = requestCache.current.get(cacheKey);
      if (cachedEntry.expiresAt > Date.now()) {
        dispatch({ type: 'SET_CURRENT_WEATHER', payload: cachedEntry.data });
        return cachedEntry.data;
      } else {
        // Remove expired cache entry
        requestCache.current.delete(cacheKey);
      }
    }

    const requestKey = `current_weather_${cacheKey}`;
    return apiRequest(
      () => api.get('/weather/current', { params: { lat, lon, units: state.units } }),
      (data) => {
        // Cache the result for 10 minutes with expiration timestamp
        requestCache.current.set(cacheKey, {
          data,
          expiresAt: Date.now() + (10 * 60 * 1000)
        });
        return { type: 'SET_CURRENT_WEATHER', payload: data };
      },
      'Failed to fetch weather data',
      null,
      requestKey
    );
  }, [apiRequest, state.units]);

  const getForecast = useCallback(async (lat, lon) => {
    // Check cache first
    const cacheKey = `forecast_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`;
    if (requestCache.current.has(cacheKey)) {
      const cachedEntry = requestCache.current.get(cacheKey);
      if (cachedEntry.expiresAt > Date.now()) {
        dispatch({ type: 'SET_FORECAST', payload: cachedEntry.data });
        return cachedEntry.data;
      } else {
        // Remove expired cache entry
        requestCache.current.delete(cacheKey);
      }
    }

    const requestKey = `forecast_${cacheKey}`;
    return apiRequest(
      () => api.get('/weather/forecast', { params: { lat, lon, units: state.units } }),
      (data) => {
        // Cache the result for 10 minutes with expiration timestamp
        requestCache.current.set(cacheKey, {
          data,
          expiresAt: Date.now() + (10 * 60 * 1000)
        });
        return { type: 'SET_FORECAST', payload: data };
      },
      'Failed to fetch forecast data',
      null,
      requestKey
    );
  }, [apiRequest, state.units]);

  const searchCities = useCallback(async (query) => {
    if (!query || query.length < 2) {
      dispatch({ type: 'CLEAR_SEARCH_RESULTS' });
      return [];
    }
    
    // Prevent duplicate searches for the same query
    if (lastSearchQuery.current === query) {
      console.log('Duplicate search query detected, returning cached results');
      return state.searchResults;
    }
    
    // Check if we're already searching for this query
    const searchKey = `search_${query}`;
    if (activeRequests.current.has(searchKey)) {
      console.log('Search already in progress for:', query);
      return activeRequests.current.get(searchKey);
    }
    
    // Check cache first
    const cacheKey = `search_${query.toLowerCase()}`;
    if (searchCache.current.has(cacheKey)) {
      const cachedEntry = searchCache.current.get(cacheKey);
      if (cachedEntry.expiresAt > Date.now()) {
        dispatch({ type: 'SET_SEARCH_RESULTS', payload: cachedEntry.data });
        lastSearchQuery.current = query;
        return cachedEntry.data;
      } else {
        // Remove expired cache entry
        searchCache.current.delete(cacheKey);
      }
    }
    
    // Clear previous timeout
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }
    
    // Set loading state
    dispatch({ type: 'SET_SEARCH_LOADING', payload: true });
    lastSearchQuery.current = query;
    
    // Set a timeout to prevent infinite loading
    const timeoutId = setTimeout(() => {
      console.warn('Search request timed out after 15 seconds');
      dispatch({ type: 'SET_SEARCH_LOADING', payload: false });
      dispatch({ type: 'SET_SEARCH_RESULTS', payload: [] });
      toast.error('Search request timed out. Please try again.');
      // Remove from active requests
      activeRequests.current.delete(searchKey);
    }, 15000);
    
    const searchPromise = (async () => {
      try {
      console.log('Making API request to /weather/search with query:', query);
      const response = await api.get('/weather/search', { params: { q: query } });
      console.log('API response received:', response);
      
      // Clear timeout since request completed
      clearTimeout(timeoutId);
      
      const payload = response?.data;
      console.log('Response payload:', payload);

      // Support multiple response shapes: { results: [] } or []
      let results = [];
      if (Array.isArray(payload)) {
        results = payload;
      } else if (payload && Array.isArray(payload.results)) {
        results = payload.results;
      } else {
        results = [];
      }

      console.log('Processed results:', results);

      // Cache the results for 5 minutes with expiration timestamp
      searchCache.current.set(cacheKey, {
        data: results,
        expiresAt: Date.now() + (5 * 60 * 1000)
      });

        dispatch({ type: 'SET_SEARCH_RESULTS', payload: results });
        return results;
      } catch (error) {
        // Clear timeout since request failed
        clearTimeout(timeoutId);
        
        console.error('searchCities failed:', error);
        console.error('Error details:', {
          message: error.message,
          response: error.response,
          status: error.response?.status,
          data: error.response?.data,
          code: error.code,
          config: error.config
        });
        
        // Always show error toast for search failures (not page load)
        if (query && query.length >= 2) {
          // Handle specific error types
          if (error.response?.data?.error === 'API_KEY_MISSING') {
            toast.error('Weather API key is not configured. Please contact administrator.');
          } else if (error.response?.data?.message) {
            toast.error(`Search failed: ${error.response.data.message}`);
          } else if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
            toast.error('Request timed out. Please try again.');
          } else if (error.code === 'NETWORK_ERROR' || !error.response) {
            toast.error('Network error. Please check your connection.');
          } else {
            toast.error('Failed to search cities. Please try again.');
          }
        }
        
        // Clear loading state and results
        dispatch({ type: 'SET_SEARCH_RESULTS', payload: [] });
        return [];
      } finally {
        // Ensure loading state is cleared
        dispatch({ type: 'SET_SEARCH_LOADING', payload: false });
        // Remove from active requests
        activeRequests.current.delete(searchKey);
      }
    })();
    
    // Store the promise for deduplication
    activeRequests.current.set(searchKey, searchPromise);
    return searchPromise;
  }, [state.searchResults]);

  const getGeolocationWeather = useCallback(async () => {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('Geolocation is not supported by this browser'));
        return;
      }

      navigator.geolocation.getCurrentPosition(
        async (position) => {
          try {
            const { latitude, longitude } = position.coords;
            if (latitude && longitude) {
              // Check cache first
              const cacheKey = `geolocation_${latitude.toFixed(2)}_${longitude.toFixed(2)}_${state.units}`;
              if (requestCache.current.has(cacheKey)) {
                const cachedEntry = requestCache.current.get(cacheKey);
                if (cachedEntry.expiresAt > Date.now()) {
                  const cachedData = cachedEntry.data;
                  dispatch({ 
                    type: 'SET_CURRENT_WEATHER', 
                    payload: {
                      location: cachedData.location,
                      current: cachedData.current
                    }
                  });
                  dispatch({ 
                    type: 'SET_FORECAST', 
                    payload: {
                      location: cachedData.location,
                      hourly: cachedData.hourly,
                      daily: cachedData.daily
                    }
                  });
                  resolve(cachedData);
                  return;
                } else {
                  // Remove expired cache entry
                  requestCache.current.delete(cacheKey);
                }
              }

              // Use the geolocation endpoint that returns both current weather and forecast
              const response = await api.get('/weather/geolocation', {
                params: { lat: latitude, lon: longitude, units: state.units }
              });
              
              const data = response.data;
              
              // Cache the result for 10 minutes with expiration timestamp
              requestCache.current.set(cacheKey, {
                data,
                expiresAt: Date.now() + (10 * 60 * 1000)
              });
              
              // Set current weather
              dispatch({ 
                type: 'SET_CURRENT_WEATHER', 
                payload: {
                  location: data.location,
                  current: data.current
                }
              });
              
              // Set forecast
              dispatch({ 
                type: 'SET_FORECAST', 
                payload: {
                  location: data.location,
                  hourly: data.hourly,
                  daily: data.daily
                }
              });
              
              resolve(data);
            } else {
              reject(new Error('Could not get coordinates from geolocation.'));
            }
          } catch (error) {
            reject(error);
          }
        },
        (error) => {
          let message = 'Unable to retrieve your location';
          switch (error.code) {
            case error.PERMISSION_DENIED:
              message = 'Location access denied by user';
              break;
            case error.POSITION_UNAVAILABLE:
              message = 'Location information is unavailable';
              break;
            case error.TIMEOUT:
              message = 'Location request timed out';
              break;
          }
          reject(new Error(message));
        },
        {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 300000 // 5 minutes
        }
      );
    });
  }, [state.units]);

  const addToFavorites = async (cityData) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      const response = await api.post('/user/favorites', cityData);
      dispatch({ type: 'SET_FAVORITE_CITIES', payload: response.data.favorites });
      dispatch({ type: 'SET_LOADING', payload: false });
      toast.success('City added to favorites');
      return response.data;
    } catch (error) {
      dispatch({ type: 'SET_LOADING', payload: false });
      const message = error.response?.data?.message || 'Failed to add to favorites';
      toast.error(message);
      throw error;
    }
  };

  const removeFromFavorites = async (cityId) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      const response = await api.delete(`/user/favorites/${cityId}`);
      dispatch({ type: 'SET_FAVORITE_CITIES', payload: response.data.favorites });
      dispatch({ type: 'SET_LOADING', payload: false });
      toast.success('City removed from favorites');
      return response.data;
    } catch (error) {
      dispatch({ type: 'SET_LOADING', payload: false });
      const message = error.response?.data?.message || 'Failed to remove from favorites';
      toast.error(message);
      throw error;
    }
  };

  const addToSearchHistory = async (city, country) => {
    try {
      await api.post('/user/search-history', { city, country });
      // Refresh search history
      const response = await api.get('/user/search-history');
      dispatch({ type: 'SET_SEARCH_HISTORY', payload: response.data.searchHistory });
    } catch (error) {
      console.error('Failed to add to search history:', error);
    }
  };

  const getSearchHistory = async () => {
    try {
      const response = await api.get('/user/search-history');
      const history = response?.data?.searchHistory || [];
      dispatch({ type: 'SET_SEARCH_HISTORY', payload: history });
      return history;
    } catch (error) {
      console.error('getSearchHistory failed:', error);
      dispatch({ type: 'SET_SEARCH_HISTORY', payload: [] });
      return [];
    }
  };

  const clearSearchHistory = async () => {
    return apiRequest(
      () => api.delete('/user/search-history'),
      () => ({ type: 'SET_SEARCH_HISTORY', payload: [] }),
      'Failed to clear search history',
      'Search history cleared'
    );
  };

  const toggleUnits = () => {
    const newUnits = state.units === 'metric' ? 'imperial' : 'metric';
    dispatch({ type: 'SET_UNITS', payload: newUnits });
    
    // Update user preferences
    api.put('/user/preferences', {
      temperatureUnit: newUnits === 'metric' ? 'celsius' : 'fahrenheit'
    }).catch(error => {
      console.error('Failed to update preferences:', error);
    });
  };

  const clearSearchResults = () => {
    dispatch({ type: 'CLEAR_SEARCH_RESULTS' });
  };

  // Cleanup function to clear timeouts and cache
  useEffect(() => {
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
      // Clear all caches on unmount
      requestCache.current.clear();
      searchCache.current.clear();
      activeRequests.current.clear();
    };
  }, []);

  // Cache cleanup effect - remove expired entries every 5 minutes
  useEffect(() => {
    const cleanupInterval = setInterval(() => {
      const now = Date.now();
      
      // Clean up request cache
      for (const [key, value] of requestCache.current.entries()) {
        if (value.expiresAt && now > value.expiresAt) {
          requestCache.current.delete(key);
        }
      }
      
      // Clean up search cache
      for (const [key, value] of searchCache.current.entries()) {
        if (value.expiresAt && now > value.expiresAt) {
          searchCache.current.delete(key);
        }
      }
    }, 5 * 60 * 1000); // Every 5 minutes

    return () => clearInterval(cleanupInterval);
  }, []);

  const value = useMemo(() => ({
    ...state,
    getCurrentWeather,
    getForecast,
    searchCities,
    getGeolocationWeather,
    addToFavorites,
    removeFromFavorites,
    addToSearchHistory,
    getSearchHistory,
    clearSearchHistory,
    toggleUnits,
    clearSearchResults
  }), [
    state,
    getCurrentWeather,
    getForecast,
    searchCities,
    getGeolocationWeather,
    addToFavorites,
    removeFromFavorites,
    addToSearchHistory,
    getSearchHistory,
    clearSearchHistory,
    toggleUnits,
    clearSearchResults
  ]);

  return (
    <WeatherContext.Provider value={value}>
      {children}
    </WeatherContext.Provider>
  );
};

export const useWeather = () => {
  const context = useContext(WeatherContext);
  if (!context) {
    throw new Error('useWeather must be used within a WeatherProvider');
  }
  return context;
};