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
      const token = localStorage.getItem('token');
      if (token) {
        // ensure axios has the header set before calling /auth/me
        api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        try {
          const response = await api.get('/auth/me');
          dispatch({
            type: 'LOGIN_SUCCESS',
            payload: {
              token,
              user: response.data.user
            }
          });
        } catch (error) {
          // Don't surface a toast here — this is an automatic check on reload.
          console.warn('Auth check failed (silent):', error?.response || error.message || error);
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
      console.error('Auth error details - endpoint:', endpoint);
      console.error('Auth error details - request data:', data);
      if (error.response) {
        console.error('Auth error response status:', error.response.status);
        console.error('Auth error response data:', error.response.data);
      }

      // Normalize the caught error: our api wrapper sometimes rejects with
      // a response-like object (containing status, data) instead of an Error
      const respLike = error && (error.response || error.status || error.data);

      let message = 'Authentication failed';

      if (respLike) {
        // If it's an axios Error, prefer error.response.data.message
        const serverData = error.response ? error.response.data : error.data || {};
        const status = error.response ? error.response.status : error.status;
        if (serverData && serverData.message) {
          message = serverData.message;
          // If there's additional error detail, append it safely
          if (serverData.error && serverData.error !== serverData.message) {
            if (typeof serverData.error === 'string') {
              message = `${serverData.message}: ${serverData.error}`;
            } else {
              // Avoid showing raw objects directly in UI; stringify limited
              try {
                const small = JSON.stringify(serverData.error);
                message = `${serverData.message}: ${small}`;
              } catch (e) {
                // fallback to message only
                message = serverData.message;
              }
            }
          }
        } else if (status === 400) {
          // Try common shapes
          const candidate = serverData?.error || serverData?.message;
          message = typeof candidate === 'string' ? candidate : 'Bad request. Please check your input.';
        } else if (status === 401) {
          message = 'Invalid email or password';
        } else if (status >= 500) {
          message = 'Server error. Please try again later.';
        }
      } else if (error?.code === 'NETWORK_ERROR' || error?.code === 'ECONNREFUSED' || error?.code === 'ETIMEDOUT' || !error) {
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

  const register = useCallback(async (username, email, password, cccdData = null) => {
    const payload = { username, email, password };
    if (cccdData && typeof cccdData === 'object') {
      // merge cccd-related fields into payload
      payload.cccd = cccdData.cccd || cccdData.so_cccd || cccdData.cccdNumber || undefined;
      payload.fullName = cccdData.fullName || cccdData.ho_va_ten || cccdData.ho_ten || undefined;
      payload.dateOfBirth = cccdData.dateOfBirth || cccdData.ngay_sinh || undefined;
      payload.gender = cccdData.gender || cccdData.gioi_tinh || undefined;
      payload.address = cccdData.address || cccdData.noi_thuong_tru || cccdData.que_quan || undefined;
    }

    return handleAuthRequest('/auth/register', payload, 'Registration successful!');
  }, [handleAuthRequest]);

  const logout = useCallback(() => {
  // Xóa token khỏi axios headers
  delete api.defaults.headers.common['Authorization'];
  
  // Hủy các request đang chờ
  if (api.cancelToken) {
    api.cancelToken.cancel('Đã hủy bởi người dùng');
  }
  
  // Xóa token khỏi localStorage
  localStorage.removeItem('token');
  
  // Đặt lại trạng thái
  dispatch({ type: 'LOGOUT' });
  
  // Chuyển hướng về trang đăng nhập
  if (window.location.pathname !== '/login') {
    window.location.href = '/login';
  }
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