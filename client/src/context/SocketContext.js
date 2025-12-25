import React, { createContext, useContext, useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { io } from 'socket.io-client';
import { toast } from 'react-hot-toast';
import { useAuth } from './AuthContext';

// Memoized SVG Icon components for consistent iconography and performance
const WarningIcon = React.memo(() => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" />
    <line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
));

WarningIcon.displayName = 'WarningIcon';

const AlertIcon = React.memo(() => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="8" x2="12" y2="12" />
    <line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
));

AlertIcon.displayName = 'AlertIcon';

const BellIcon = React.memo(({ className }) => (
  <svg xmlns="http://www.w3.org/2000/svg" className={className} width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
    <path d="M13.73 21a2 2 0 0 1-3.46 0" />
  </svg>
));

BellIcon.displayName = 'BellIcon';

// Context creation
const SocketContext = createContext();

// Custom hook with error handling
export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    console.warn('useSocket was called outside of SocketProvider');
    return {
      isConnected: false,
      unreadCount: 0,
      onlineUsers: [],
      typingUsers: {},
      safetyAlerts: [],
      sendMessage: async () => {},
      joinConversation: () => {},
      leaveConversation: () => {},
    };
  }
  return context;
};

// Memoized SocketProvider component
export const SocketProvider = React.memo(({ children }) => {
  const { isAuthenticated, token, user } = useAuth();
  const [socket, setSocket] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [typingUsers, setTypingUsers] = useState({});
  const [unreadCount, setUnreadCount] = useState(0);
  const [safetyAlerts, setSafetyAlerts] = useState([]);
  
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;
  const reconnectDelay = useRef(1000);
  const socketRef = useRef(null);

  // Memoized connection function
  const connectSocket = useCallback(() => {
    if (!isAuthenticated || !token || !user) return;

    try {
      const newSocket = io(process.env.REACT_APP_SERVER_URL || 'http://localhost:5000', {
        auth: { token },
        transports: ['websocket', 'polling'],
        timeout: 20000,
        forceNew: true,
        reconnection: false, // We handle reconnection manually
      });

      socketRef.current = newSocket;

      // Connection event handlers
      newSocket.on('connect', () => {
        console.log('Socket connected:', newSocket.id);
        setIsConnected(true);
        reconnectAttempts.current = 0;
        reconnectDelay.current = 1000;
        
        // Join user-specific room
        newSocket.emit('join_user_room', user._id);
      });

      newSocket.on('disconnect', (reason) => {
        console.log('Socket disconnected:', reason);
        setIsConnected(false);
        
        if (reason !== 'io client disconnect' && reason !== 'io server disconnect') {
          handleReconnect();
        }
      });

      newSocket.on('connect_error', (error) => {
        console.error('Socket connection error:', error);
        setIsConnected(false);
        handleReconnect();
      });

      // Message events - memoized handlers
      newSocket.on('new_message', handleNewMessage);
      newSocket.on('message_sent', handleMessageSent);
      newSocket.on('message_delivered', handleMessageDelivered);
      newSocket.on('message_read', handleMessageRead);
      newSocket.on('user_typing', handleUserTyping);

      // User presence events
      newSocket.on('user_online', handleUserOnline);
      newSocket.on('user_offline', handleUserOffline);

      // Safety events
      newSocket.on('safety_warning', handleSafetyWarning);
      newSocket.on('safety_alert', handleSafetyAlert);

      // Trust score events
      newSocket.on('trust_score_updated', handleTrustScoreUpdate);

      // Notification events
      newSocket.on('notification', handleNotification);

      // Error events
      newSocket.on('error', (error) => {
        console.error('Socket error:', error);
        toast.error(error.message || 'Connection error');
      });

      setSocket(newSocket);
    } catch (error) {
      console.error('Failed to create socket connection:', error);
    }
  }, [isAuthenticated, token, user]);

  // Memoized disconnect function
  const disconnectSocket = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
    }
    setSocket(null);
    setIsConnected(false);
    setOnlineUsers([]);
    setTypingUsers({});
  }, []);

  // Reconnection handler with exponential backoff
  const handleReconnect = useCallback(() => {
    if (reconnectAttempts.current < maxReconnectAttempts) {
      reconnectAttempts.current += 1;
      
      setTimeout(() => {
        console.log(`Attempting to reconnect... (${reconnectAttempts.current}/${maxReconnectAttempts})`);
        connectSocket();
      }, reconnectDelay.current);
      
      // Exponential backoff
      reconnectDelay.current = Math.min(reconnectDelay.current * 2, 30000);
    } else {
      console.error('Max reconnection attempts reached');
      toast.error('Connection lost. Please refresh the page.', { duration: 5000 });
    }
  }, [connectSocket]);

  // Memoized message handlers
  const handleNewMessage = useCallback((data) => {
    setUnreadCount(prev => prev + 1);
    
    // Show notification if app is not focused
    if (document.hidden) {
      showNotification('New Message', {
        body: data.message.content?.substring(0, 100) || 'New message received',
        icon: '/icons/icon-192.png',
        tag: `message-${data.conversationId}`,
        data: {
          type: 'message',
          conversationId: data.conversationId,
          messageId: data.message?._id,
        },
      });
    }
    
    // Dispatch custom event for components to listen
    window.dispatchEvent(new CustomEvent('new_message', { detail: data }));
  }, []);

  const handleMessageSent = useCallback((data) => {
    window.dispatchEvent(new CustomEvent('message_sent', { detail: data }));
  }, []);

  const handleMessageDelivered = useCallback((data) => {
    window.dispatchEvent(new CustomEvent('message_delivered', { detail: data }));
  }, []);

  const handleMessageRead = useCallback((data) => {
    window.dispatchEvent(new CustomEvent('message_read', { detail: data }));
  }, []);

  const handleUserTyping = useCallback((data) => {
    setTypingUsers(prev => {
      const updated = { ...prev };
      if (data.isTyping) {
        updated[data.userId] = data;
      } else {
        delete updated[data.userId];
      }
      return updated;
    });
    
    // Clear typing indicator after 3 seconds
    if (data.isTyping) {
      setTimeout(() => {
        setTypingUsers(prev => {
          const updated = { ...prev };
          delete updated[data.userId];
          return updated;
        });
      }, 3000);
    }
  }, []);

  const handleUserOnline = useCallback((data) => {
    setOnlineUsers(prev => [...prev, data.userId]);
  }, []);

  const handleUserOffline = useCallback((data) => {
    setOnlineUsers(prev => prev.filter(id => id !== data.userId));
  }, []);

  // Safety handlers
  const handleSafetyWarning = useCallback((data) => {
    setSafetyAlerts(prev => [data, ...prev.slice(0, 9)]);
    
    if (data.warnings?.length > 0) {
      toast.error(
        <div>
          <div className="font-semibold">Safety Warning</div>
          <div className="text-sm">{data.warnings[0]}</div>
        </div>,
        {
          duration: 6000,
          icon: <WarningIcon />,
        }
      );
    }
    
    if (data.safetyScore < 30) {
      showNotification('Safety Alert', {
        body: 'High-risk message detected. Please review carefully.',
        icon: '/icons/icon-192.png',
        tag: 'safety-alert',
        requireInteraction: true,
      });
    }
  }, []);

  const handleSafetyAlert = useCallback((data) => {
    toast.error(
      <div>
        <div className="font-semibold">Safety Alert</div>
        <div className="text-sm">{data.description}</div>
      </div>,
      {
        duration: 8000,
        icon: <AlertIcon />,
      }
    );
  }, []);

  const handleTrustScoreUpdate = useCallback((data) => {
    window.dispatchEvent(new CustomEvent('trust_score_updated', { detail: data }));
  }, []);

  const handleNotification = useCallback((data) => {
    toast.success(data.message, {
      icon: data.icon ? data.icon : <BellIcon className="w-5 h-5" />,
      duration: 4000,
    });
    
    if (Notification.permission === 'granted') {
      showNotification(data.title || 'TrustMarket', {
        body: data.message,
        icon: '/icons/icon-192.png',
        tag: 'trustmarket-notification',
      });
    }
  }, []);

  // Initialize socket connection
  useEffect(() => {
    if (isAuthenticated && token && user) {
      connectSocket();
    } else {
      disconnectSocket();
    }

    return () => {
      disconnectSocket();
    };
  }, [isAuthenticated, token, user, connectSocket, disconnectSocket]);

  // Cleanup socket on unmount
  useEffect(() => {
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  // Memoized utility functions
  const joinConversation = useCallback((conversationId) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('join_conversation', conversationId);
    }
  }, [isConnected]);

  const leaveConversation = useCallback((conversationId) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('leave_conversation', conversationId);
    }
  }, [isConnected]);

  const sendMessage = useCallback((messageData) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('send_message', messageData);
    } else {
      toast.error('Not connected. Please check your internet connection.', {
        icon: '📡',
      });
    }
  }, [isConnected]);

  const startTyping = useCallback((conversationId) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('typing_start', { conversationId });
    }
  }, [isConnected]);

  const stopTyping = useCallback((conversationId) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('typing_stop', { conversationId });
    }
  }, [isConnected]);

  const markMessageRead = useCallback((messageId) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('mark_message_read', messageId);
      setUnreadCount(prev => Math.max(0, prev - 1));
    }
  }, [isConnected]);

  const reportSuspiciousActivity = useCallback((data) => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('report_suspicious_activity', data);
      toast.success('Activity reported. Our team will review it.');
    }
  }, [isConnected]);

  const requestTrustScoreUpdate = useCallback(() => {
    if (socketRef.current && isConnected) {
      socketRef.current.emit('trust_score_update');
    }
  }, [isConnected]);

  const showNotification = useCallback((title, options = {}) => {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(title, {
        icon: options.icon || '/icons/icon-192.png',
        badge: '/icons/badge-72.png',
        ...options,
      });
    }
  }, []);

  const requestNotificationPermission = useCallback(async () => {
    if ('Notification' in window) {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }
    return false;
  }, []);

  const clearUnreadCount = useCallback(() => {
    setUnreadCount(0);
  }, []);

  const dismissSafetyAlert = useCallback((index) => {
    setSafetyAlerts(prev => prev.filter((_, i) => i !== index));
  }, []);

  const isUserOnline = useCallback((userId) => {
    return onlineUsers.includes(userId);
  }, [onlineUsers]);

  const getTypingUsers = useCallback((conversationId) => {
    return Object.values(typingUsers).filter(user => user.conversationId === conversationId);
  }, [typingUsers]);

  // Memoized context value
  const contextValue = useMemo(() => ({
    // State
    socket,
    isConnected,
    onlineUsers,
    typingUsers,
    unreadCount,
    safetyAlerts,
    
    // Actions
    joinConversation,
    leaveConversation,
    sendMessage,
    startTyping,
    stopTyping,
    markMessageRead,
    reportSuspiciousActivity,
    requestTrustScoreUpdate,
    requestNotificationPermission,
    clearUnreadCount,
    dismissSafetyAlert,
    
    // Utilities
    showNotification,
    isUserOnline,
    getTypingUsers,
  }), [
    socket,
    isConnected,
    onlineUsers,
    typingUsers,
    unreadCount,
    safetyAlerts,
    joinConversation,
    leaveConversation,
    sendMessage,
    startTyping,
    stopTyping,
    markMessageRead,
    reportSuspiciousActivity,
    requestTrustScoreUpdate,
    requestNotificationPermission,
    clearUnreadCount,
    dismissSafetyAlert,
    showNotification,
    isUserOnline,
    getTypingUsers,
  ]);

  return (
    <SocketContext.Provider value={contextValue}>
      {children}
    </SocketContext.Provider>
  );
});

SocketProvider.displayName = 'SocketProvider';

export default SocketContext;
