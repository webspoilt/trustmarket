import axios from 'axios';
import { toast } from 'react-hot-toast';

// Create axios instance
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:5000/api',
  timeout: 30000, // 30 seconds
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh and errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 errors (unauthorized)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem('refreshToken');
      
      if (refreshToken) {
        try {
          // Attempt to refresh token
          const refreshResponse = await axios.post(
            `${process.env.REACT_APP_API_URL || 'http://localhost:5000/api'}/auth/refresh`,
            { refreshToken }
          );

          const { accessToken, refreshToken: newRefreshToken } = refreshResponse.data.data;

          // Store new tokens
          localStorage.setItem('accessToken', accessToken);
          localStorage.setItem('refreshToken', newRefreshToken);

          // Update header and retry original request
          api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
          originalRequest.headers['Authorization'] = `Bearer ${accessToken}`;

          return api(originalRequest);
        } catch (refreshError) {
          console.error('Token refresh failed:', refreshError);
          
          // Clear tokens and dispatch navigation event
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          delete api.defaults.headers.common['Authorization'];
          
          // Dispatch custom event for navigation instead of full page reload
          if (!window.location.pathname.includes('/login') && 
              !window.location.pathname.includes('/register')) {
            window.dispatchEvent(new CustomEvent('auth:sessionExpired', { 
              detail: { reason: 'token_refresh_failed' } 
            }));
          }
          
          return Promise.reject(refreshError);
        }
      } else {
        // No refresh token, dispatch navigation event
        localStorage.removeItem('accessToken');
        delete api.defaults.headers.common['Authorization'];
        
        if (!window.location.pathname.includes('/login') && 
            !window.location.pathname.includes('/register')) {
          window.dispatchEvent(new CustomEvent('auth:sessionExpired', { 
            detail: { reason: 'no_refresh_token' } 
          }));
        }
      }
    }

    // Handle network errors
    if (!error.response) {
      if (error.code === 'ECONNABORTED') {
        toast.error('Request timeout. Please try again.');
      } else if (error.message === 'Network Error') {
        toast.error('Network error. Please check your connection.');
      } else {
        toast.error('Something went wrong. Please try again.');
      }
      return Promise.reject(error);
    }

    // Handle specific error status codes
    const { status, data } = error.response;

    switch (status) {
      case 400:
        if (data.error) {
          if (typeof data.error === 'string') {
            toast.error(data.error);
          } else if (Array.isArray(data.error)) {
            data.error.forEach(err => toast.error(err));
          }
        }
        break;

      case 403:
        toast.error('Access denied. You do not have permission to perform this action.');
        break;

      case 404:
        toast.error(data.error || 'Resource not found.');
        break;

      case 429:
        toast.error('Too many requests. Please try again later.');
        break;

      case 500:
        toast.error('Server error. Please try again later.');
        break;

      default:
        if (data.error) {
          toast.error(data.error);
        }
    }

    return Promise.reject(error);
  }
);

// API service object with all endpoints
const apiService = {
  // Auth endpoints
  auth: {
    login: (credentials) => api.post('/auth/login', credentials),
    register: (userData) => api.post('/auth/register', userData),
    logout: (refreshToken) => api.post('/auth/logout', { refreshToken }),
    logoutAll: () => api.post('/auth/logout-all'),
    refresh: (refreshToken) => api.post('/auth/refresh', { refreshToken }),
    me: () => api.get('/auth/me'),
    verifyPhone: (otp) => api.post('/auth/verify-phone', { otp }),
    resendOTP: () => api.post('/auth/resend-otp'),
    forgotPassword: (email) => api.post('/auth/forgot-password', { email }),
  },

  // User endpoints
  users: {
    getProfile: () => api.get('/users/profile'),
    updateProfile: (data) => api.put('/users/profile', data),
    uploadPhoto: (formData) => 
      api.post('/users/upload-photo', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    getUser: (id) => api.get(`/users/${id}`),
    getUserListings: (id, params) => api.get(`/users/${id}/listings`, { params }),
    getUserStats: (id) => api.get(`/users/${id}/stats`),
    submitIDVerification: (data) => api.post('/users/verify-id', data),
    getTrustScoreHistory: () => api.get('/users/trust-score/history'),
    blockUser: (userId) => api.post(`/users/block/${userId}`),
    unblockUser: (userId) => api.delete(`/users/block/${userId}`),
  },

  // Listing endpoints
  listings: {
    getListings: (params) => api.get('/listings', { params }),
    getListing: (id) => api.get(`/listings/${id}`),
    createListing: (formData) =>
      api.post('/listings', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    updateListing: (id, formData) =>
      api.put(`/listings/${id}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    deleteListing: (id) => api.delete(`/listings/${id}`),
    inquireAboutListing: (id) => api.post(`/listings/${id}/inquire`),
    saveListing: (id) => api.post(`/listings/${id}/save`),
    reportListing: (id, data) => api.post(`/listings/${id}/report`, data),
    getCategories: () => api.get('/listings/categories'),
    getSearchSuggestions: (q) => api.get('/listings/search/suggestions', { params: { q } }),
  },

  // Message endpoints
  messages: {
    getConversations: (params) => api.get('/messages/conversations', { params }),
    getConversationMessages: (conversationId, params) =>
      api.get(`/messages/conversations/${conversationId}`, { params }),
    sendMessage: (data) => api.post('/messages', data),
    addReaction: (messageId, emoji) => api.post(`/messages/${messageId}/reaction`, { emoji }),
    reportMessage: (messageId, data) => api.post(`/messages/${messageId}/report`, data),
    getUnreadMessages: () => api.get('/messages/unread'),
    getSafetyAlerts: () => api.get('/messages/safety-alerts'),
    uploadMedia: (formData) =>
      api.post('/messages/upload-media', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    deleteMessage: (id) => api.delete(`/messages/${id}`),
  },

  // Admin endpoints
  admin: {
    getDashboard: () => api.get('/admin/dashboard'),
    getUsers: (params) => api.get('/admin/users', { params }),
    getUser: (id) => api.get(`/admin/users/${id}`),
    banUser: (id, data) => api.put(`/admin/users/${id}/ban`, data),
    adjustTrustScore: (id, data) => api.put(`/admin/users/${id}/trust-score`, data),
    verifyID: (id, data) => api.put(`/admin/users/${id}/verify`, data),
    getListings: (params) => api.get('/admin/listings', { params }),
    updateListingStatus: (id, data) => api.put(`/admin/listings/${id}/status`, data),
    getReports: (params) => api.get('/admin/reports', { params }),
    resolveReport: (type, id, data) => api.put(`/admin/reports/${type}/${id}/resolve`, data),
    getAnalytics: (params) => api.get('/admin/analytics', { params }),
  },

  // Search endpoints
  search: {
    search: (query, filters) => api.get('/search', { params: { q: query, ...filters } }),
    searchListings: (query, filters) => api.get('/search/listings', { params: { q: query, ...filters } }),
    searchUsers: (query, filters) => api.get('/search/users', { params: { q: query, ...filters } }),
  },

  // Upload endpoints
  upload: {
    uploadImage: (formData) =>
      api.post('/upload/image', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    uploadVideo: (formData) =>
      api.post('/upload/video', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
    uploadMultiple: (formData) =>
      api.post('/upload/multiple', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }),
  },

  // Utility endpoints
  utils: {
    healthCheck: () => api.get('/health'),
    getVersion: () => api.get('/version'),
    getConfig: () => api.get('/config'),
  },
};

// Helper functions for common API patterns
const createFormData = (data) => {
  const formData = new FormData();
  
  Object.keys(data).forEach(key => {
    if (data[key] !== undefined && data[key] !== null) {
      if (Array.isArray(data[key])) {
        data[key].forEach((item, index) => {
          if (item instanceof File) {
            formData.append(`${key}[${index}]`, item);
          } else {
            formData.append(`${key}[${index}]`, item);
          }
        });
      } else if (data[key] instanceof File) {
        formData.append(key, data[key]);
      } else {
        formData.append(key, data[key]);
      }
    }
  });
  
  return formData;
};

const handleApiError = (error) => {
  if (error.response) {
    // Server responded with error status
    const { status, data } = error.response;
    
    return {
      status,
      message: data.error || 'An error occurred',
      details: data.details,
      isNetworkError: false,
    };
  } else if (error.request) {
    // Request was made but no response received
    return {
      status: 0,
      message: 'Network error - please check your connection',
      isNetworkError: true,
    };
  } else {
    // Something else happened
    return {
      status: 0,
      message: error.message || 'An unexpected error occurred',
      isNetworkError: false,
    };
  }
};

const retryRequest = async (requestFn, maxRetries = 3, delay = 1000) => {
  let lastError;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await requestFn();
    } catch (error) {
      lastError = error;
      
      // Don't retry on client errors (4xx)
      if (error.response && error.response.status >= 400 && error.response.status < 500) {
        throw error;
      }
      
      // Wait before retrying (exponential backoff)
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, i)));
      }
    }
  }
  
  throw lastError;
};

// Export API service and utilities
export { api, apiService, createFormData, handleApiError, retryRequest };
export default api;