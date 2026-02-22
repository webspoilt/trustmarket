import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { apiService } from '../services/api';

// Create context
const AuthContext = createContext();

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    console.warn('useAuth was called outside of AuthProvider');
    return {
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      login: async () => ({ success: false, error: 'Context not initialized' }),
      register: async () => ({ success: false, error: 'Context not initialized' }),
      logout: async () => { },
      refreshUser: async () => { },
    };
  }
  return context;
};

// AuthProvider component
export const AuthProvider = ({ children }) => {
  const [state, setState] = useState({
    user: null,
    isAuthenticated: false,
    isLoading: true, // Start true to check for existing session
    error: null,
  });

  // Check for existing session on mount (cookie-based — call /auth/me)
  useEffect(() => {
    const checkSession = async () => {
      try {
        const response = await apiService.auth.me();
        if (response.data.success && response.data.data.user) {
          setState({
            user: response.data.data.user,
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } else {
          setState(prev => ({ ...prev, isLoading: false }));
        }
      } catch {
        // No valid session — that's fine, just mark as not authenticated
        setState(prev => ({ ...prev, isLoading: false }));
      }
    };

    checkSession();
  }, []);

  // Listen for session expired events (dispatched by api.js interceptor)
  useEffect(() => {
    const handleSessionExpired = () => {
      setState({
        user: null,
        isAuthenticated: false,
        isLoading: false,
        error: 'Session expired. Please log in again.',
      });
    };

    window.addEventListener('auth:sessionExpired', handleSessionExpired);
    return () => window.removeEventListener('auth:sessionExpired', handleSessionExpired);
  }, []);

  // Login
  const login = useCallback(async (credentials) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await apiService.auth.login(credentials);

      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true };
      } else {
        setState(prev => ({
          ...prev,
          isLoading: false,
          error: response.data.error || 'Login failed',
        }));
        return { success: false, error: response.data.error };
      }
    } catch (error) {
      const message = error.response?.data?.error || 'Login failed. Please try again.';
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      return { success: false, error: message };
    }
  }, []);

  // Register
  const register = useCallback(async (userData) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const response = await apiService.auth.register(userData);

      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true };
      } else {
        setState(prev => ({
          ...prev,
          isLoading: false,
          error: response.data.error || 'Registration failed',
        }));
        return { success: false, error: response.data.error };
      }
    } catch (error) {
      const message = error.response?.data?.error || 'Registration failed. Please try again.';
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: message,
      }));
      return { success: false, error: message };
    }
  }, []);

  // Logout
  const logout = useCallback(async () => {
    try {
      await apiService.auth.logout();
    } catch {
      // Even if the API call fails, clear local state
    }

    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  }, []);

  // Refresh user data (e.g., after profile update)
  const refreshUser = useCallback(async () => {
    try {
      const response = await apiService.auth.me();
      if (response.data.success && response.data.data.user) {
        setState(prev => ({
          ...prev,
          user: response.data.data.user,
        }));
      }
    } catch {
      // Silently fail — user data just won't be refreshed
    }
  }, []);

  // Google Login
  const googleLogin = useCallback(async (credential) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    try {
      const response = await apiService.auth.google(credential);
      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true, isNewUser: response.data.data.isNewUser };
      }
      setState(prev => ({ ...prev, isLoading: false, error: 'Google login failed' }));
      return { success: false, error: 'Google login failed' };
    } catch (error) {
      const message = error.response?.data?.error || 'Google login failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      return { success: false, error: message };
    }
  }, []);

  // OTP Login (verify step)
  const otpLogin = useCallback(async (phone, otp) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));
    try {
      const response = await apiService.auth.otpVerify(phone, otp);
      if (response.data.success) {
        setState({
          user: response.data.data.user,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
        return { success: true };
      }
      setState(prev => ({ ...prev, isLoading: false, error: 'OTP verification failed' }));
      return { success: false, error: 'OTP verification failed' };
    } catch (error) {
      const message = error.response?.data?.error || 'OTP verification failed';
      setState(prev => ({ ...prev, isLoading: false, error: message }));
      return { success: false, error: message };
    }
  }, []);

  const value = {
    ...state,
    login,
    register,
    logout,
    refreshUser,
    googleLogin,
    otpLogin,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;