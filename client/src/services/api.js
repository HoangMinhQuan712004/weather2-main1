import axios from 'axios';
import { trackApiCall, trackError } from '../utils/performance';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || '/api',
  timeout: 15000, // 15 second timeout
  retry: 3, // Add retry configuration
  retryDelay: 1000 // Add retry delay
});

// Request interceptor to track API calls and add retry logic
api.interceptors.request.use(
  (config) => {
    config.metadata = { 
      startTime: Date.now(),
      retryCount: 0,
      maxRetries: config.retry || 3
    };
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to track performance and handle errors with retry
api.interceptors.response.use(
  (response) => {
    const duration = Date.now() - response.config.metadata.startTime;
    trackApiCall(response.config.url, duration, true);
    return response;
  },
  async (error) => {
    const config = error.config;
    const duration = config?.metadata ? 
      Date.now() - config.metadata.startTime : 0;
    
    trackApiCall(config?.url || 'unknown', duration, false);
    trackError(error, 'api_call');
    
    // Retry logic for network errors
    if (config && config.metadata && config.metadata.retryCount < config.metadata.maxRetries) {
      const isNetworkError = !error.response || 
        error.code === 'NETWORK_ERROR' || 
        error.code === 'ECONNREFUSED' ||
        error.code === 'ETIMEDOUT' ||
        error.response.status >= 500;
      
      if (isNetworkError) {
        config.metadata.retryCount += 1;
        const delay = config.retryDelay || 1000 * config.metadata.retryCount;
        
        console.log(`Retrying request (${config.metadata.retryCount}/${config.metadata.maxRetries}) after ${delay}ms`);
        
        await new Promise(resolve => setTimeout(resolve, delay));
        return api(config);
      }
    }
    
    const normalized = error.response ? error.response : { 
      data: null, 
      status: 500, 
      message: error.message 
    };
    return Promise.reject(normalized);
  }
);

export const getHistoricalWeather = async (lat, lon, dt) => {
  try {
    const response = await api.get('/weather/historical', { params: { lat, lon, dt } });
    return response.data;
  } catch (error) {
    console.error('Error fetching historical weather:', error);
    throw error;
  }
};

export default api;
