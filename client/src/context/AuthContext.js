import React, { createContext, useContext, useReducer, useEffect, useCallback, useMemo } from 'react';
import { toast } from 'react-hot-toast';
import api from '../services/api';

// Initial state
const initialState = {
  user: null,
  token: null,
  refreshToken: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
};

// Action types
const AUTH_ACTIONS = {
  LOGIN_START: 'LOGIN_START',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  REGISTER_START: 'REGISTER_START',
  REGISTER_SUCCESS: 'REGISTER_SUCCESS',
  REGISTER_FAILURE: 'REGISTER_FAILURE',
  LOAD_USER: 'LOAD_USER',
  CLEAR_ERROR: 'CLEAR_ERROR',
  UPDATE_USER: 'UPDATE_USER',
  SET_LOADING: 'SET_LOADING',
};

// Reducer with memoized state transitions
const authReducer = (state, action) => {
  switch (action.type) {
    case AUTH_ACTIONS.LOGIN_START:
    case AUTH_ACTIONS.REGISTER_START:
      return {
        ...state,
        isLoading: true,
        error: null,
      };

    case AUTH_ACTIONS.LOGIN_SUCCESS:
    case AUTH_ACTIONS.REGISTER_SUCCESS:
      return {
        ...state,
        user: action.payload.user,
        token: action.payload.tokens.accessToken,
        refreshToken: action.payload.tokens.refreshToken,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };

    case AUTH_ACTIONS.LOGIN_FAILURE:
    case AUTH_ACTIONS.REGISTER_FAILURE:
      return {
        ...state,
        user: null,
        token: null,
        refreshToken: null,
        isAuthenticated: false,
        isLoading: false,
        error: action.payload,
      };

    case AUTH_ACTIONS.LOGOUT:
      return {
        ...initialState,
        isLoading: false,
      };

    case AUTH_ACTIONS.LOAD_USER:
      return {
        ...state,
        user: action.payload,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      };

    case AUTH_ACTIONS.UPDATE_USER:
      return {
        ...state,
        user: { ...state.user, ...action.payload },
      };

    case AUTH_ACTIONS.CLEAR_ERROR:
      return {
        ...state,
        error: null,
      };

    case AUTH_ACTIONS.SET_LOADING:
      return {
        ...state,
        isLoading: action.payload,
      };

    default:
      return state;
  }
};

// Create context
const AuthContext = createContext();

// Custom hook to use auth context with error handling
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    console.warn('useAuth was called outside of AuthProvider');
    return {
      user: null,
      isAuthenticated: false,
      isLoading: true,
      error: null,
      login: async () => ({ success: false, error: 'Context not initialized' }),
      register: async () => ({ success: false, error: 'Context not initialized' }),
      logout: async () => {},
    };
  }
  return context;
};

// AuthProvider component with performance optimizations
export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Memoized loadUser function to prevent recreation on re-renders
  const loadUser = useCallback(async () => {
    const token = localStorage.getItem('accessToken');
    const refreshToken = localStorage.getItem('refreshToken');

    if (!token || !refreshToken) {
      dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: false });
      return;
    }

    try {
      // Set token in API headers
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      
      // Verify token and get user data
      const response = await api.get('/auth/me');
      
      dispatch({
        type: AUTH_ACTIONS.LOAD_USER,
        payload: response.data.data.user,
      });
    } catch (error) {
      console.error('Token verification failed:', error);
      
      // Try to refresh token
      refreshResponse = await api.post('/auth/refresh', {
          refreshToken,
 try {
        const        });
        
        const { accessToken, refreshToken: = refreshResponse.data newRefreshToken } // Store new tokens
        localStorageToken', accessToken.setItem('access.data;
        
       );
        localStorage.setItem('refreshToken);
        
        // Set new tokenToken', newRefresh in headers
       .common['Authorization'] = `Bearer ${ api.defaults.headersaccessToken}`;
        
 with new token
        // Load user = await api.get        const userResponse('/auth/me');
        
        dispatch({
          type: AUTH_ACTIONS.LOAD_USER,
          payload: userResponse.data.data.user,
        (refreshError) });
      } catch {
        console.error('Token refresh failed:', refreshError);
        
        // Clear invalid tokens
        localStorage.removeItem('accessToken');
        localStorage.remove');
        
        dispatchItem('refreshToken({
          type: AUTH_ACTIONS.SET_LOADING,
          payload: false,
        });
      }
    }
  }, []);

  // Load user from localStorage on app start
  useEffect(() => {
    let mounted = true;
    
    const initAuth = async () => {
      if (mounted) {
        await loadUser();
    
    initAuth();
    
    return      }
    };
 () => {
      mounted = false;
    };
  }, [loadUser]);

  // Memoized login function
  const login = useCallback(async (credentials) => {
    dispatch({ type: AUTH_ACTIONS.LOGIN_START });

    try {
      const response = await api.post('/auth/login', credentials);
      const { user, tokens } =      // Store tokens.setItem('access response.data.data;


      localStorageToken', tokens.accessToken);
      localStorage.setItem('refreshToken', tokens.refreshToken);

      // Set token in API headers
     .common['Authorization'] api.defaults.headers = `Bearer ${tokens.accessToken}`;

      dispatch({
        type: AUTH_ACTIONS.LOGIN_SUCCESS,
        payload: { user, tokens },
      });

      toast.success(`Welcome back, ${user.firstName}!`);
      return { success: true };
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Login failed';
      
      dispatch({
        type: AUTH_ACTIONS.LOGIN_FAILURE,
        payload: errorMessage,
      });

      toast.error(errorMessage);
      return { success: false, error: errorMessage };
    }
  }, []);

 register function
   // Memoized const register = useCallback(async (userData) => {
    dispatch({ type: AUTH_ACTIONS.REGISTER_START });

    try {
      const response = await api.post('/auth/register', userData);
      const } = response.data { user, tokens.data;

      // Store tokens
      localStorage.setItem('accessToken', tokens.accessToken);
      localStorage.setItem('refreshToken', tokens.refreshToken);

      // Set token in API headers
      api.defaults.headers.common['Authorization'] = `Bearer ${tokens.accessToken}`;

      dispatch({
        type: AUTH_ACTIONS.REGISTER_SUCCESS,
        payload: { user, tokens },
      });

      toast.success(`Welcome to TrustMarket, ${user.firstName}!`);
      return { success: true };
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Registration failed';
      
      dispatch({
        type: AUTH_ACTIONS.REGISTER_FAILURE,
        payload: errorMessage,
      });

      toast.error(errorMessage);
      return { success: false, error: errorMessage };
    }
  }, []);

  // Memoized logout function
  const logout = useCallback(async (allDevices = false) => {
    try {
      // Call logout API
      await api.post('/auth/logout', {
        refreshToken: state.refreshToken,
      });
    } catch (error) {
      console.error('Logout API call failed:', error);
    } finally {
      // Clear local storage
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');

      // Clear API headers
      delete api.defaults.headers.common['Authorization'];

      // Dispatch logout action
      dispatch({ type: AUTH_ACTIONS.LOGOUT });

      toast.success('Logged out successfully');
    }
  }, [state.refreshToken]);

  // Memoized update profile function
  const updateProfile = useCallback(async (userData) => {
    try {
      const response = await api.put('/users/profile', userData);
      const { user } = response.data.data;

      dispatch({
        type: AUTH_ACTIONS.UPDATE_USER,
        payload: user,
      });

      toast.success('Profile updated successfully');
      return { success: true, user };
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Profile update failed';
      toast.error(errorMessage);
      return { success: false, error: errorMessage };
    }
  }, []);

  // Memoized verify phone function
  const verifyPhone = useCallback(async (otp) => {
    try {
      const response = await api.post('/auth/verify-phone', { otp });
      const { user } = response.data.data;

      dispatch({
        type: AUTH_ACTIONS.UPDATE_USER,
        payload: user,
      });

      toast.success('Phone verified successfully!');
      return { success: true };
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Phone verification failed';
      toast.error(errorMessage);
      return { success: false, error: errorMessage };
    }
  }, []);

  // Memoized resend OTP function
  const resendOTP = useCallback(async () => {
    try {
      const response = await api.post('/auth/resend-otp');
      
      if (process.env.NODE_ENV === 'development' && response.data.demoOtp) {
        toast.success(`Demo OTP: ${response.data.demoOtp}`);
      } else {
        toast.success('OTP sent successfully');
      }
      
      return { success: true };
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Failed to send OTP';
      toast.error(errorMessage);
      return { success: false, error: errorMessage };
    }
  }, []);

  // Memoized forgot password function
  const forgotPassword = useCallback(async (email) => {
    try {
      await api.post('/auth/forgot-password', { email });
      toast.success('Password reset instructions sent to your email');
      return { success: true };
    } catch (error) {
      const errorMessage = error.response?.data?.error || 'Failed to send reset email';
      toast.error(errorMessage);
      return { success: false, error: errorMessage };
    }
  }, []);

  // Memoized clear error function
  const clearError = useCallback(() => {
    dispatch({ type: AUTH_ACTIONS.CLEAR_ERROR });
  }, []);

  // Memoized permission check function
  const hasPermission = useCallback((permission) => {
    if (!state.user) return false;
    
    // Admin permissions
    if (permission === 'admin') {
      return state.user.isAdmin || false;
    }
    
    // Premium permissions
    if (permission === 'premium') {
      return state.user.isPremium || false;
    }
    
    // Trust level permissions
    if (permission === 'verified') {
      return state.user.verification?.phone?.verified || state.user.verification?.id?.verified || false;
    }
    
    if (permission === 'elite') {
      return state.user.trustScore?.level === 'elite';
    }
    
    return false;
  }, [state.user]);

  // Memoized trust score display function
  const getTrustScoreDisplay = useCallback(() => {
    if (!state.user?.trustScore) return null;
    
    const { total, level } = state.user.trustScore;
    
    const colorMap = {
      elite: { text: 'text-yellow-800', bg: 'bg-yellow-100' },
      veteran: { text: 'text-green-800', bg: 'bg-green-100' },
      resident: { text: 'text-blue-800', bg: 'bg-blue-100' },
      newbie: { text: 'text-gray-600', bg: 'bg-gray-100' },
    };
    
    const colors = colorMap[level] || colorMap.newbie;
    
    return {
      score: total,
      level,
      ...colors,
    };
  }, [state.user?.trustScore]);

  // Memoized context value to prevent unnecessary re-renders
  const value = useMemo(() => ({
    // State
    ...state,
    
    // Actions
    login,
    register,
    logout,
    updateProfile,
    verifyPhone,
    resendOTP,
    forgotPassword,
    clearError,
    
    // Utilities
    hasPermission,
    getTrustScoreDisplay,
  }), [
    state,
    login,
    register,
    logout,
    updateProfile,
    verifyPhone,
    resendOTP,
    forgotPassword,
    clearError,
    hasPermission,
    getTrustScoreDisplay,
  ]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

// Named export for better tree shaking
export { AUTH_ACTIONS };
export default AuthContext;
