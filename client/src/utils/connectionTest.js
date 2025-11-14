// Utility to test server connection with retry logic
export const testServerConnection = async (retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
      
      const response = await fetch('/api/health', {
        signal: controller.signal,
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        }
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        console.log('Server connection successful:', data);
        return { success: true, data };
      } else {
        console.error(`Server health check failed (attempt ${i + 1}/${retries}):`, response.status);
        if (i === retries - 1) {
          return { success: false, error: `HTTP ${response.status}` };
        }
      }
    } catch (error) {
      console.error(`Server connection failed (attempt ${i + 1}/${retries}):`, error);
      if (i === retries - 1) {
        return { 
          success: false, 
          error: error.name === 'AbortError' ? 'Connection timeout' : error.message 
        };
      }
      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
    }
  }
  return { success: false, error: 'All retry attempts failed' };
};

// Test connection on app start with better error handling
export const initializeConnectionTest = () => {
  // Test connection after a short delay to ensure app is loaded
  setTimeout(async () => {
    const result = await testServerConnection();
    if (!result.success) {
      console.warn('Server connection test failed:', result.error);
      // You could dispatch a global error state here if needed
    }
  }, 1000);
};

// Check if server is reachable before making API calls
export const isServerReachable = async () => {
  try {
    const result = await testServerConnection(1); // Single attempt for quick check
    return result.success;
  } catch (error) {
    return false;
  }
};
