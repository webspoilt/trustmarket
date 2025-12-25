import React, { createContext, useContext, useState } from 'react';

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
      logout: async () => {},
    };
  }
  return context;
};

// AuthProvider component
export const AuthProvider = ({ children }) => {
  const [state, setState] = useState({
    user: null,
    token: null,
    isAuthenticated: false,
    isLoading: false,
    error: null,
  });

  // Simple login function
  const login = async (credentials) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      // For demo purposes, we'll simulate a successful login
      const mockUser = {
        id: '1',
        email: credentials.email,
        name: 'Demo User',
        trustScore: 95,
        isPremium: false,
      };

      const mockToken = 'demo-jwt-token';

      setState({
        user: mockUser,
        token: mockToken,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      // Store in localStorage
      localStorage.setItem('accessToken', mockToken);
      localStorage.setItem('user', JSON.stringify(mockUser));

      return { success: true };
    } catch (error) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Login failed',
      }));
      return { success: false, error: 'Login failed' };
    }
  };

  // Simple register function
  const register = async (userData) => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      // For demo purposes, we'll simulate a successful registration
      const mockUser = {
        id: '1',
        email: userData.email,
        name: userData.name,
        trustScore: 95,
        isPremium: false,
      };

      const mockToken = 'demo-jwt-token';

      setState({
        user: mockUser,
        token: mockToken,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      // Store in localStorage
      localStorage.setItem('accessToken', mockToken);
      localStorage.setItem('user', JSON.stringify(mockUser));

      return { success: true };
    } catch (error) {
      setState(prev => ({
        ...prev,
        isLoading: false,
        error: 'Registration failed',
      }));
      return { success: false, error: 'Registration failed' };
    }
  };

  // Simple logout function
  const logout = async () => {
    setState({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });

    // Clear localStorage
    localStorage.removeItem('accessToken');
    localStorage.removeItem('user');
  };

  // Check for existing session on mount
  React.useEffect(() => {
    const token = localStorage.getItem('accessToken');
    const user = localStorage.getItem('user');

    if (token && user) {
      try {
        const parsedUser = JSON.parse(user);
        setState({
          user: parsedUser,
          token,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
      } catch (error) {
        console.error('Failed to parse user data:', error);
        localStorage.removeItem('accessToken');
        localStorage.removeItem('user');
      }
    } else {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  }, []);

  const value = {
    ...state,
    login,
    register,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;