/**
 * Performance monitoring utilities
 */

// Performance metrics storage
const metrics = {
  apiCalls: [],
  renderTimes: [],
  errors: []
};

/**
 * Track API call performance
 * @param {string} endpoint - API endpoint
 * @param {number} duration - Call duration in ms
 * @param {boolean} success - Whether the call was successful
 */
export const trackApiCall = (endpoint, duration, success = true) => {
  const metric = {
    endpoint,
    duration,
    success,
    timestamp: Date.now()
  };
  
  metrics.apiCalls.push(metric);
  
  // Keep only last 100 API calls
  if (metrics.apiCalls.length > 100) {
    metrics.apiCalls = metrics.apiCalls.slice(-100);
  }
  
  // Log slow API calls in development
  if (process.env.NODE_ENV === 'development' && duration > 2000) {
    console.warn(`Slow API call detected: ${endpoint} took ${duration}ms`);
  }
};

/**
 * Track component render time
 * @param {string} componentName - Name of the component
 * @param {number} duration - Render duration in ms
 */
export const trackRenderTime = (componentName, duration) => {
  const metric = {
    component: componentName,
    duration,
    timestamp: Date.now()
  };
  
  metrics.renderTimes.push(metric);
  
  // Keep only last 50 render times
  if (metrics.renderTimes.length > 50) {
    metrics.renderTimes = metrics.renderTimes.slice(-50);
  }
  
  // Log slow renders in development
  if (process.env.NODE_ENV === 'development' && duration > 100) {
    console.warn(`Slow render detected: ${componentName} took ${duration}ms`);
  }
};

/**
 * Track application errors
 * @param {Error} error - The error object
 * @param {string} context - Context where error occurred
 */
export const trackError = (error, context = 'unknown') => {
  const metric = {
    message: error.message,
    stack: error.stack,
    context,
    timestamp: Date.now()
  };
  
  metrics.errors.push(metric);
  
  // Keep only last 20 errors
  if (metrics.errors.length > 20) {
    metrics.errors = metrics.errors.slice(-20);
  }
};

/**
 * Get performance metrics
 * @returns {Object} Performance metrics
 */
export const getMetrics = () => {
  const avgApiCallTime = metrics.apiCalls.length > 0 
    ? metrics.apiCalls.reduce((sum, call) => sum + call.duration, 0) / metrics.apiCalls.length 
    : 0;
    
  const avgRenderTime = metrics.renderTimes.length > 0 
    ? metrics.renderTimes.reduce((sum, render) => sum + render.duration, 0) / metrics.renderTimes.length 
    : 0;
    
  const errorRate = metrics.apiCalls.length > 0 
    ? (metrics.apiCalls.filter(call => !call.success).length / metrics.apiCalls.length) * 100 
    : 0;
  
  return {
    apiCalls: {
      total: metrics.apiCalls.length,
      averageTime: Math.round(avgApiCallTime),
      errorRate: Math.round(errorRate * 100) / 100
    },
    renders: {
      total: metrics.renderTimes.length,
      averageTime: Math.round(avgRenderTime)
    },
    errors: {
      total: metrics.errors.length,
      recent: metrics.errors.slice(-5)
    }
  };
};

/**
 * Clear all metrics
 */
export const clearMetrics = () => {
  metrics.apiCalls = [];
  metrics.renderTimes = [];
  metrics.errors = [];
};

// Performance observer for long tasks
if ('PerformanceObserver' in window) {
  const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      if (entry.duration > 50) { // Tasks longer than 50ms
        console.warn(`Long task detected: ${entry.duration}ms`);
      }
    }
  });
  
  try {
    observer.observe({ entryTypes: ['longtask'] });
  } catch (e) {
    // Long task API not supported
  }
}

export default {
  trackApiCall,
  trackRenderTime,
  trackError,
  getMetrics,
  clearMetrics
};
