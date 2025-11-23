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
  searchLoading: false
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
  
  const requestCache = useRef(new Map());
  const searchCache = useRef(new Map());
  const sessionCacheKey = 'weather_request_cache_v1';
  
  try {
    const stored = sessionStorage.getItem(sessionCacheKey);
    if (stored) {
      const parsed = JSON.parse(stored);
      requestCache.current = new Map(Object.entries(parsed));
    }
  } catch (e) {
    // ignore
  }
  
  const lastSearchQuery = useRef('');
  const searchTimeoutRef = useRef(null);
  const searchAbortController = useRef(null);
  const activeRequests = useRef(new Map());
  const geolocationLastFetch = useRef({ timestamp: 0, data: null });

  const apiRequest = useCallback(async (apiCall, successAction, errorMessage, successMessage, requestKey) => {
    const key = requestKey || 'default';
    
    if (activeRequests.current.has(key)) {
      console.log(`Request ${key} already in progress, waiting for result...`);
      return activeRequests.current.get(key);
    }

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
        activeRequests.current.delete(key);
        try {
          const obj = Object.fromEntries(requestCache.current);
          sessionStorage.setItem(sessionCacheKey, JSON.stringify(obj));
        } catch (e) {
          // ignore storage errors
        }
      }
    })();

    activeRequests.current.set(key, requestPromise);
    return requestPromise;
  }, [state.isRequestInProgress]);

  const getCurrentWeather = useCallback(async (lat, lon) => {
    const cacheKey = `current_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`;
    
    if (requestCache.current.has(cacheKey)) {
      const cachedEntry = requestCache.current.get(cacheKey);
      if (cachedEntry.expiresAt > Date.now()) {
        dispatch({ type: 'SET_CURRENT_WEATHER', payload: cachedEntry.data });

        if (cachedEntry.expiresAt - Date.now() < 2 * 60 * 1000) {
          const bgKey = `current_bg_refresh_${cacheKey}`;
          if (!activeRequests.current.has(bgKey)) {
            apiRequest(
              () => api.get('/weather/current', { params: { lat, lon, units: state.units } }),
              (data) => {
                requestCache.current.set(cacheKey, { data, expiresAt: Date.now() + (10 * 60 * 1000) });
                return { type: 'SET_CURRENT_WEATHER', payload: data };
              },
              null,
              null,
              bgKey
            ).catch(() => {});
          }
        }

        return cachedEntry.data;
      } else {
        requestCache.current.delete(cacheKey);
      }
    }

    const requestKey = `current_weather_${cacheKey}`;
    return apiRequest(
      () => api.get('/weather/current', { params: { lat, lon, units: state.units } }),
      (data) => {
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
    const cacheKey = `forecast_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`;
    
    if (requestCache.current.has(cacheKey)) {
      const cachedEntry = requestCache.current.get(cacheKey);
      if (cachedEntry.expiresAt > Date.now()) {
        dispatch({ type: 'SET_FORECAST', payload: cachedEntry.data });

        if (cachedEntry.expiresAt - Date.now() < 2 * 60 * 1000) {
          const bgKey = `forecast_bg_refresh_${cacheKey}`;
          if (!activeRequests.current.has(bgKey)) {
            apiRequest(
              () => api.get('/weather/forecast', { params: { lat, lon, units: state.units } }),
              (data) => {
                requestCache.current.set(cacheKey, { data, expiresAt: Date.now() + (10 * 60 * 1000) });
                return { type: 'SET_FORECAST', payload: data };
              },
              null,
              null,
              bgKey
            ).catch(() => {});
          }
        }

        return cachedEntry.data;
      } else {
        requestCache.current.delete(cacheKey);
      }
    }

    const requestKey = `forecast_${cacheKey}`;
    return apiRequest(
      () => api.get('/weather/forecast', { params: { lat, lon, units: state.units } }),
      (data) => {
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

  const getWeatherBundle = useCallback(async (lat, lon) => {
    const bundleKey = `bundle_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`;

    if (requestCache.current.has(bundleKey)) {
      const cached = requestCache.current.get(bundleKey);
      if (cached.expiresAt > Date.now()) {
        dispatch({ type: 'SET_CURRENT_WEATHER', payload: cached.data.current });
        dispatch({ type: 'SET_FORECAST', payload: cached.data.forecast });

        if (cached.expiresAt - Date.now() < 2 * 60 * 1000) {
          const bgKey = `bundle_bg_${bundleKey}`;
          if (!activeRequests.current.has(bgKey)) {
            apiRequest(
              () => Promise.all([
                api.get('/weather/current', { params: { lat, lon, units: state.units } }),
                api.get('/weather/forecast', { params: { lat, lon, units: state.units } })
              ]),
              (responses) => {
                const currentData = responses[0].data;
                const forecastData = responses[1].data;
                const data = { current: currentData, forecast: forecastData };
                requestCache.current.set(bundleKey, { data, expiresAt: Date.now() + (10 * 60 * 1000) });
                requestCache.current.set(`current_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`, { data: currentData, expiresAt: Date.now() + (10 * 60 * 1000) });
                requestCache.current.set(`forecast_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`, { data: forecastData, expiresAt: Date.now() + (10 * 60 * 1000) });
                return ({ type: 'SET_CURRENT_WEATHER', payload: currentData });
              },
              null,
              null,
              bgKey
            ).catch(() => {});
          }
        }

        return cached.data;
      } else {
        requestCache.current.delete(bundleKey);
      }
    }

    const reqKey = `bundle_req_${bundleKey}`;
    if (activeRequests.current.has(reqKey)) {
      return activeRequests.current.get(reqKey);
    }

    const promise = (async () => {
      try {
        dispatch({ type: 'SET_LOADING', payload: true });
        const [currentRes, forecastRes] = await Promise.all([
          api.get('/weather/current', { params: { lat, lon, units: state.units } }),
          api.get('/weather/forecast', { params: { lat, lon, units: state.units } })
        ]);

        const data = { current: currentRes.data, forecast: forecastRes.data };

        requestCache.current.set(bundleKey, { data, expiresAt: Date.now() + (10 * 60 * 1000) });
        requestCache.current.set(`current_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`, { data: currentRes.data, expiresAt: Date.now() + (10 * 60 * 1000) });
        requestCache.current.set(`forecast_${lat.toFixed(2)}_${lon.toFixed(2)}_${state.units}`, { data: forecastRes.data, expiresAt: Date.now() + (10 * 60 * 1000) });

        dispatch({ type: 'SET_CURRENT_WEATHER', payload: currentRes.data });
        dispatch({ type: 'SET_FORECAST', payload: forecastRes.data });

        return data;
      } catch (error) {
        const message = error.response?.data?.message || 'Failed to fetch weather bundle';
        dispatch({ type: 'SET_ERROR', payload: message });
        throw error;
      } finally {
        activeRequests.current.delete(reqKey);
      }
    })();

    activeRequests.current.set(reqKey, promise);
    return promise;
  }, [state.units, apiRequest]);

  const searchCities = useCallback(async (query) => {
    if (!query || query.length < 2) {
      dispatch({ type: 'CLEAR_SEARCH_RESULTS' });
      return [];
    }
    
    if (lastSearchQuery.current === query) {
      console.log('Duplicate search query detected, returning cached results');
      return state.searchResults;
    }
    
    const cacheKey = `search_${query.toLowerCase()}`;
    if (searchCache.current.has(cacheKey)) {
      const cachedEntry = searchCache.current.get(cacheKey);
      if (cachedEntry.expiresAt > Date.now()) {
        dispatch({ type: 'SET_SEARCH_RESULTS', payload: cachedEntry.data });
        lastSearchQuery.current = query;
        console.log('Returning cached search results for:', query);
        return cachedEntry.data;
      } else {
        searchCache.current.delete(cacheKey);
      }
    }
    
    if (searchAbortController.current) {
      console.log('Canceling previous search request');
      searchAbortController.current.abort();
    }
    
    searchAbortController.current = new AbortController();
    const signal = searchAbortController.current.signal;
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }
    
    dispatch({ type: 'SET_SEARCH_LOADING', payload: true });
    lastSearchQuery.current = query;
    
    const timeoutId = setTimeout(() => {
      console.warn('Search request timed out after 15 seconds');
      dispatch({ type: 'SET_SEARCH_LOADING', payload: false });
      dispatch({ type: 'SET_SEARCH_RESULTS', payload: [] });
      toast.error('Search request timed out. Please try again.');
    }, 15000);
    
    try {
      console.log('Making API request to /weather/search with query:', query);
      const response = await api.get('/weather/search', { 
        params: { q: query },
        signal: signal
      });
      console.log('API response received:', response);
      
      clearTimeout(timeoutId);
      
      const payload = response?.data;
      console.log('Response payload:', payload);

      let results = [];
      if (Array.isArray(payload)) {
        results = payload;
      } else if (payload && Array.isArray(payload.results)) {
        results = payload.results;
      } else {
        results = [];
      }

      console.log('Processed results:', results);

      searchCache.current.set(cacheKey, {
        data: results,
        expiresAt: Date.now() + (5 * 60 * 1000)
      });

      dispatch({ type: 'SET_SEARCH_RESULTS', payload: results });
      return results;
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error.name === 'AbortError') {
        console.log('Search request was canceled by user typing new query');
        return [];
      }
      
      console.error('searchCities failed:', error);
      
      if (query && query.length >= 2) {
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
      
      dispatch({ type: 'SET_SEARCH_RESULTS', payload: [] });
      return [];
    } finally {
      dispatch({ type: 'SET_SEARCH_LOADING', payload: false });
    }
  }, [state.searchResults]);

  // THÊM THAM SỐ forceRefresh
  const getGeolocationWeather = useCallback(async (forceRefresh = false) => {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        reject(new Error('Geolocation is not supported by this browser'));
        return;
      }

      // CHỈ dùng cache nếu KHÔNG phải force refresh
      if (!forceRefresh && geolocationLastFetch.current.timestamp && (Date.now() - geolocationLastFetch.current.timestamp) < 2 * 60 * 1000) {
        console.log('Reusing cached geolocation data');
        resolve(geolocationLastFetch.current.data);
        return;
      }

      // Nếu là force refresh, XÓA cache cũ
      if (forceRefresh) {
        console.log('Force refresh - clearing geolocation cache');
        geolocationLastFetch.current = { timestamp: 0, data: null };
      }

      dispatch({ type: 'SET_LOADING', payload: true });
      
      let timeoutHandle = null;
      
      const timeoutPromise = new Promise((_, timeoutReject) => {
        timeoutHandle = setTimeout(() => {
          timeoutReject(new Error('Location request timed out. Please try again or enable location services.'));
        }, 15000);
      });

      navigator.geolocation.getCurrentPosition(
        async (position) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          
          try {
            const { latitude, longitude } = position.coords;
            console.log('Got geolocation:', { latitude, longitude });
            
            if (latitude && longitude) {
              const cacheKey = `geolocation_${latitude.toFixed(2)}_${longitude.toFixed(2)}_${state.units}`;
              
              // Nếu force refresh, XÓA cache API
              if (forceRefresh) {
                requestCache.current.delete(cacheKey);
              }
              
              if (!forceRefresh && requestCache.current.has(cacheKey)) {
                const cachedEntry = requestCache.current.get(cacheKey);
                if (cachedEntry.expiresAt > Date.now()) {
                  console.log('Using cached geolocation weather');
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
                  dispatch({ type: 'SET_LOADING', payload: false });
                  geolocationLastFetch.current = { timestamp: Date.now(), data: cachedData };
                  resolve(cachedData);
                  return;
                } else {
                  requestCache.current.delete(cacheKey);
                }
              }

              console.log('Fetching geolocation weather from API');
              const response = await api.get('/weather/geolocation', {
                params: { lat: latitude, lon: longitude, units: state.units }
              });
              
              const data = response.data;
              
              requestCache.current.set(cacheKey, {
                data,
                expiresAt: Date.now() + (10 * 60 * 1000)
              });
              
              dispatch({ 
                type: 'SET_CURRENT_WEATHER', 
                payload: {
                  location: data.location,
                  current: data.current
                }
              });
              
              dispatch({ 
                type: 'SET_FORECAST', 
                payload: {
                  location: data.location,
                  hourly: data.hourly,
                  daily: data.daily
                }
              });
              
              dispatch({ type: 'SET_LOADING', payload: false });
              
              geolocationLastFetch.current = { timestamp: Date.now(), data };
              
              resolve(data);
            } else {
              dispatch({ type: 'SET_LOADING', payload: false });
              reject(new Error('Could not get coordinates from geolocation.'));
            }
          } catch (error) {
            dispatch({ type: 'SET_LOADING', payload: false });
            console.error('Error in geolocation success callback:', error);
            reject(error);
          }
        },
        (error) => {
          if (timeoutHandle) clearTimeout(timeoutHandle);
          
          dispatch({ type: 'SET_LOADING', payload: false });
          
          let message = 'Unable to retrieve your location';
          console.error('Geolocation error:', error);
          
          switch (error.code) {
            case error.PERMISSION_DENIED:
              message = 'Location access denied. Please enable location permissions in your browser settings.';
              break;
            case error.POSITION_UNAVAILABLE:
              message = 'Location information is unavailable. Please check if location services are enabled.';
              break;
            case error.TIMEOUT:
              message = 'Location request timed out. Please try again.';
              break;
            default:
              message = error.message || 'Unable to retrieve your location';
          }
          reject(new Error(message));
        },
        {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 0 // KHÔNG dùng cache của browser
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
    
    api.put('/user/preferences', {
      temperatureUnit: newUnits === 'metric' ? 'celsius' : 'fahrenheit'
    }).catch(error => {
      console.error('Failed to update preferences:', error);
    });
  };

  const clearSearchResults = () => {
    dispatch({ type: 'CLEAR_SEARCH_RESULTS' });
  };

  useEffect(() => {
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
      requestCache.current.clear();
      searchCache.current.clear();
      activeRequests.current.clear();
    };
  }, []);

  useEffect(() => {
    const cleanupInterval = setInterval(() => {
      const now = Date.now();
      
      for (const [key, value] of requestCache.current.entries()) {
        if (value.expiresAt && now > value.expiresAt) {
          requestCache.current.delete(key);
        }
      }
      
      for (const [key, value] of searchCache.current.entries()) {
        if (value.expiresAt && now > value.expiresAt) {
          searchCache.current.delete(key);
        }
      }
    }, 5 * 60 * 1000);

    return () => clearInterval(cleanupInterval);
  }, []);

  const value = useMemo(() => ({
    ...state,
    getCurrentWeather,
    getForecast,
    getWeatherBundle,
    searchCities,
    getGeolocationWeather,
    addToFavorites,
    removeFromFavorites,
    addToSearchHistory,
    getSearchHistory,
    clearSearchHistory,
    toggleUnits,
    clearSearchResults
  }), [state]);

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