import React, { createContext, useContext, useReducer, useEffect, useMemo, useCallback } from 'react';
import api from '../services/api';
import toast from 'react-hot-toast';
import { isServerReachable } from '../utils/connectionTest';

const AuthContext = createContext();

const initialState = {
  user: null,
  token: localStorage.getItem('token'),
  isAuthenticated: false,
  loading: true
};

const authReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN_SUCCESS':
      localStorage.setItem('token', action.payload.token);
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.token,
        isAuthenticated: true,
        loading: false
      };
    case 'LOGOUT':
      localStorage.removeItem('token');
      return {
        ...state,
        user: null,
        token: null,
        isAuthenticated: false,
        loading: false
      };
    case 'SET_LOADING':
      return {
        ...state,
        loading: action.payload
      };
    case 'UPDATE_USER':
      return {
        ...state,
        user: { ...state.user, ...action.payload }
      };
    default:
      return state;
  }
};

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Set up axios defaults
  useEffect(() => {
    if (state.token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${state.token}`;
    } else {
      delete api.defaults.headers.common['Authorization'];
    }
  }, [state.token]);

  // Check if user is logged in on app start
  useEffect(() => {
    const checkAuth = async () => {
      if (state.token) {
        try {
          const response = await api.get('/auth/me');
          dispatch({
            type: 'LOGIN_SUCCESS',
            payload: {
              token: state.token,
              user: response.data.user
            }
          });
        } catch (error) {
          console.error('Auth check failed:', error);
          // Clear invalid token
          delete api.defaults.headers.common['Authorization'];
          dispatch({ type: 'LOGOUT' });
        }
      } else {
        dispatch({ type: 'SET_LOADING', payload: false });
      }
    };

    checkAuth();
  }, []);

  const handleAuthRequest = useCallback(async (endpoint, data, successMessage) => {
    try {
      dispatch({ type: 'SET_LOADING', payload: true });
      
      const response = await api.post(endpoint, data);
      
      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          token: response.data.token,
          user: response.data.user
        }
      });

      toast.success(successMessage);
      return { success: true };
    } catch (error) {
      console.error('Auth request error:', error);
      
      // Handle different error types
      let message = 'Authentication failed';
      
      if (error?.response?.data?.message) {
        message = error.response.data.message;
      } else if (error?.response?.status === 401) {
        message = 'Invalid email or password';
      } else if (error?.response?.status === 500) {
        message = 'Server error. Please try again later.';
      } else if (error?.code === 'NETWORK_ERROR' || error?.code === 'ECONNREFUSED' || !error?.response) {
        message = 'Network error. Please check your connection and make sure the server is running.';
      } else if (error?.message) {
        message = error.message;
      }
      
      toast.error(message);
      dispatch({ type: 'SET_LOADING', payload: false });
      return { success: false, message };
    }
  }, []);

  const login = useCallback(async (email, password) => {
    return handleAuthRequest('/auth/login', { email, password }, 'Login successful!');
  }, [handleAuthRequest]);

  const register = useCallback(async (username, email, password) => {
    return handleAuthRequest('/auth/register', { username, email, password }, 'Registration successful!');
  }, [handleAuthRequest]);

  const logout = useCallback(() => {
    // Clear token from axios headers immediately
    delete api.defaults.headers.common['Authorization'];
    dispatch({ type: 'LOGOUT' });
    toast.success('Logged out successfully');
  }, []);

  const updateUser = useCallback((userData) => {
    dispatch({
      type: 'UPDATE_USER',
      payload: userData
    });
  }, []);

  const value = useMemo(() => ({
    ...state,
    login,
    register,
    logout,
    updateUser
  }), [state, login, register, logout, updateUser]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};