import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { toast } from 'react-hot-toast';

const NotificationContext = createContext();

export const useNotification = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
};

// Action types
const NOTIFICATION_ACTIONS = {
  ADD_NOTIFICATION: 'ADD_NOTIFICATION',
  REMOVE_NOTIFICATION: 'REMOVE_NOTIFICATION',
  MARK_AS_READ: 'MARK_AS_READ',
  CLEAR_ALL: 'CLEAR_ALL',
  SET_PERMISSION: 'SET_PERMISSION',
};

// Initial state
const initialState = {
  notifications: [],
  unreadCount: 0,
  permission: 'default', // 'default', 'granted', 'denied'
  isLoading: false,
};

// Reducer
const notificationReducer = (state, action) => {
  switch (action.type) {
    case NOTIFICATION_ACTIONS.ADD_NOTIFICATION:
      const newNotification = {
        id: action.payload.id || Date.now().toString(),
        ...action.payload,
        timestamp: new Date(),
        read: false,
      };
      
      return {
        ...state,
        notifications: [newNotification, ...state.notifications],
        unreadCount: state.unreadCount + 1,
      };

    case NOTIFICATION_ACTIONS.REMOVE_NOTIFICATION:
      const notificationToRemove = state.notifications.find(n => n.id === action.payload);
      
      return {
        ...state,
        notifications: state.notifications.filter(n => n.id !== action.payload),
        unreadCount: notificationToRemove && !notificationToRemove.read 
          ? state.unreadCount - 1 
          : state.unreadCount,
      };

    case NOTIFICATION_ACTIONS.MARK_AS_READ:
      return {
        ...state,
        notifications: state.notifications.map(notification =>
          notification.id === action.payload
            ? { ...notification, read: true }
            : notification
        ),
        unreadCount: Math.max(0, state.unreadCount - 1),
      };

    case NOTIFICATION_ACTIONS.CLEAR_ALL:
      return {
        ...state,
        notifications: [],
        unreadCount: 0,
      };

    case NOTIFICATION_ACTIONS.SET_PERMISSION:
      return {
        ...state,
        permission: action.payload,
      };

    default:
      return state;
  }
};

export const NotificationProvider = ({ children }) => {
  const [state, dispatch] = useReducer(notificationReducer, initialState);

  // Check notification permission on mount
  useEffect(() => {
    if ('Notification' in window) {
      dispatch({
        type: NOTIFICATION_ACTIONS.SET_PERMISSION,
        payload: Notification.permission,
      });
    }
  }, []);

  // Request notification permission
  const requestPermission = async () => {
    if (!('Notification' in window)) {
      toast.error('Notifications are not supported in this browser');
      return false;
    }

    try {
      const permission = await Notification.requestPermission();
      
      dispatch({
        type: NOTIFICATION_ACTIONS.SET_PERMISSION,
        payload: permission,
      });

      if (permission === 'granted') {
        toast.success('Notifications enabled successfully!');
        return true;
      } else {
        toast.error('Notification permission denied');
        return false;
      }
    } catch (error) {
      console.error('Failed to request notification permission:', error);
      toast.error('Failed to enable notifications');
      return false;
    }
  };

  // Show browser notification
  const showBrowserNotification = (title, options = {}) => {
    if (!('Notification' in window) || state.permission !== 'granted') {
      return false;
    }

    try {
      const notification = new Notification(title, {
        icon: options.icon || '/icons/icon-192.png',
        badge: '/icons/badge-72.png',
        image: options.image,
        tag: options.tag || 'trustmarket-notification',
        requireInteraction: options.requireInteraction || false,
        silent: options.silent || false,
        ...options,
      });

      // Auto-close after 5 seconds unless requireInteraction is true
      if (!options.requireInteraction) {
        setTimeout(() => {
          notification.close();
        }, 5000);
      }

      // Handle notification click
      notification.onclick = () => {
        window.focus();
        notification.close();
        
        // Navigate to specific page if URL provided
        if (options.url) {
          window.location.href = options.url;
        }
      };

      return true;
    } catch (error) {
      console.error('Failed to show browser notification:', error);
      return false;
    }
  };

  // Add notification
  const addNotification = (notification) => {
    const id = notification.id || Date.now().toString();
    
    dispatch({
      type: NOTIFICATION_ACTIONS.ADD_NOTIFICATION,
      payload: { ...notification, id },
    });

    // Show toast notification
    showToast(notification);

    // Show browser notification if enabled and not in foreground
    if (document.hidden && notification.browserNotification !== false) {
      showBrowserNotification(notification.title, {
        body: notification.message,
        icon: notification.icon,
        image: notification.image,
        tag: notification.tag || `notification-${id}`,
        url: notification.url,
        requireInteraction: notification.requireInteraction,
      });
    }

    return id;
  };

  // Show toast notification
  const showToast = (notification) => {
    const { type = 'info', message, title, duration, ...toastOptions } = notification;

    switch (type) {
      case 'success':
        toast.success(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 3000,
            icon: notification.icon || '✅',
            ...toastOptions,
          }
        );
        break;

      case 'error':
        toast.error(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 5000,
            icon: notification.icon || '❌',
            ...toastOptions,
          }
        );
        break;

      case 'warning':
        toast(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 4000,
            icon: notification.icon || '⚠️',
            ...toastOptions,
          }
        );
        break;

      case 'loading':
        toast.loading(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            ...toastOptions,
          }
        );
        break;

      default:
        toast(
          <div>
            {title && <div className="font-semibold">{title}</div>}
            <div className={title ? 'text-sm' : ''}>{message}</div>
          </div>,
          {
            duration: duration || 4000,
            icon: notification.icon || '🔔',
            ...toastOptions,
          }
        );
    }
  };

  // Remove notification
  const removeNotification = (id) => {
    dispatch({
      type: NOTIFICATION_ACTIONS.REMOVE_NOTIFICATION,
      payload: id,
    });
  };

  // Mark notification as read
  const markAsRead = (id) => {
    dispatch({
      type: NOTIFICATION_ACTIONS.MARK_AS_READ,
      payload: id,
    });
  };

  // Mark all as read
  const markAllAsRead = () => {
    state.notifications.forEach(notification => {
      if (!notification.read) {
        markAsRead(notification.id);
      }
    });
  };

  // Clear all notifications
  const clearAll = () => {
    dispatch({
      type: NOTIFICATION_ACTIONS.CLEAR_ALL,
    });
  };

  // Utility functions for common notification types
  const showSuccess = (message, title, options = {}) => {
    return addNotification({
      type: 'success',
      message,
      title,
      ...options,
    });
  };

  const showError = (message, title, options = {}) => {
    return addNotification({
      type: 'error',
      message,
      title,
      ...options,
    });
  };

  const showWarning = (message, title, options = {}) => {
    return addNotification({
      type: 'warning',
      message,
      title,
      ...options,
    });
  };

  const showInfo = (message, title, options = {}) => {
    return addNotification({
      type: 'info',
      message,
      title,
      ...options,
    });
  };

  const showLoading = (message, title, options = {}) => {
    return addNotification({
      type: 'loading',
      message,
      title,
      ...options,
    });
  };

  // Specialized notification types
  const showTrustScoreUpdate = (oldScore, newScore, level) => {
    const improved = newScore > oldScore;
    
    return addNotification({
      type: improved ? 'success' : 'info',
      message: `Your trust score ${improved ? 'increased' : 'updated'} to ${newScore}`,
      title: improved ? 'Trust Score Improved!' : 'Trust Score Updated',
      icon: improved ? '📈' : '📊',
      duration: 5000,
      tag: 'trust-score-update',
    });
  };

  const showSafetyAlert = (message, severity = 'medium', options = {}) => {
    const alertOptions = {
      type: 'error',
      message,
      title: 'Safety Alert',
      icon: severity === 'high' ? '🚨' : '⚠️',
      duration: severity === 'high' ? 10000 : 6000,
      requireInteraction: severity === 'high',
      ...options,
    };

    return addNotification(alertOptions);
  };

  const showNewMessage = (senderName, preview, options = {}) => {
    return addNotification({
      type: 'info',
      message: preview,
      title: `New message from ${senderName}`,
      icon: '💬',
      duration: 4000,
      tag: 'new-message',
      ...options,
    });
  };

  const showListingUpdate = (action, title, options = {}) => {
    const messages = {
      created: 'Your listing has been created successfully',
      updated: 'Your listing has been updated',
      sold: 'Congratulations! Your listing has been sold',
      expired: 'Your listing has expired',
    };

    return addNotification({
      type: action === 'sold' ? 'success' : 'info',
      message: messages[action] || `Your listing "${title}" has been ${action}`,
      title: action === 'sold' ? 'Listing Sold!' : 'Listing Update',
      icon: action === 'sold' ? '🎉' : '📝',
      duration: 5000,
      tag: 'listing-update',
      ...options,
    });
  };

  const showVerificationUpdate = (type, status, options = {}) => {
    const messages = {
      phone: {
        verified: 'Phone number verified successfully!',
        pending: 'Phone verification is being processed',
      },
      id: {
        verified: 'ID verification approved!',
        pending: 'ID verification is being reviewed',
        rejected: 'ID verification was rejected',
      },
    };

    return addNotification({
      type: status === 'verified' ? 'success' : status === 'rejected' ? 'error' : 'info',
      message: messages[type]?.[status] || `${type} verification ${status}`,
      title: status === 'verified' ? 'Verification Complete!' : 'Verification Update',
      icon: status === 'verified' ? '✅' : status === 'rejected' ? '❌' : '🔄',
      duration: 6000,
      tag: 'verification-update',
      ...options,
    });
  };

  // Context value
  const value = {
    // State
    ...state,
    
    // Permission
    requestPermission,
    
    // Actions
    addNotification,
    removeNotification,
    markAsRead,
    markAllAsRead,
    clearAll,
    
    // Browser notifications
    showBrowserNotification,
    
    // Toast notifications
    showToast,
    
    // Utility methods
    showSuccess,
    showError,
    showWarning,
    showInfo,
    showLoading,
    
    // Specialized notifications
    showTrustScoreUpdate,
    showSafetyAlert,
    showNewMessage,
    showListingUpdate,
    showVerificationUpdate,
  };

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
};

export default NotificationContext;