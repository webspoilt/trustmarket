import React, { createContext, useContext, useState, useEffect } from 'react';

// Create context
const SocketContext = createContext();

// Custom hook to use socket context
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

// SocketProvider component
export const SocketProvider = ({ children }) => {
  const [state, setState] = useState({
    isConnected: false,
    unreadCount: 0,
    onlineUsers: [],
    typingUsers: {},
    safetyAlerts: [],
  });

  // Mock connection for demo
  const connectSocket = () => {
    console.log('Connecting to socket...');
    setState(prev => ({ ...prev, isConnected: true }));
  };

  const disconnectSocket = () => {
    console.log('Disconnecting from socket...');
    setState(prev => ({ ...prev, isConnected: false }));
  };

  const joinConversation = (conversationId) => {
    console.log('Joining conversation:', conversationId);
  };

  const leaveConversation = (conversationId) => {
    console.log('Leaving conversation:', conversationId);
  };

  const sendMessage = async (messageData) => {
    console.log('Sending message:', messageData);
    // Simulate successful send
    return { success: true };
  };

  const startTyping = (conversationId) => {
    console.log('Start typing in conversation:', conversationId);
  };

  const stopTyping = (conversationId) => {
    console.log('Stop typing in conversation:', conversationId);
  };

  const markMessageRead = (messageId) => {
    console.log('Mark message as read:', messageId);
    setState(prev => ({ ...prev, unreadCount: Math.max(0, prev.unreadCount - 1) }));
  };

  const reportSuspiciousActivity = (data) => {
    console.log('Reporting suspicious activity:', data);
  };

  const requestTrustScoreUpdate = () => {
    console.log('Requesting trust score update');
  };

  const requestNotificationPermission = async () => {
    if ('Notification' in window) {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }
    return false;
  };

  const clearUnreadCount = () => {
    setState(prev => ({ ...prev, unreadCount: 0 }));
  };

  const dismissSafetyAlert = (index) => {
    setState(prev => ({
      ...prev,
      safetyAlerts: prev.safetyAlerts.filter((_, i) => i !== index)
    }));
  };

  const isUserOnline = (userId) => {
    return state.onlineUsers.includes(userId);
  };

  const getTypingUsers = (conversationId) => {
    return Object.values(state.typingUsers).filter(user => user.conversationId === conversationId);
  };

  // Mock connection on mount
  useEffect(() => {
    const timer = setTimeout(() => {
      connectSocket();
    }, 1000);

    return () => {
      clearTimeout(timer);
      disconnectSocket();
    };
  }, []);

  const value = {
    ...state,
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
    isUserOnline,
    getTypingUsers,
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
};

export default SocketContext;