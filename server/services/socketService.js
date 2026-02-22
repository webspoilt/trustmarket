const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Message = require('../models/Message');
const { verifyToken } = require('../middleware/auth');

const connectedUsers = new Map(); // userId -> socketId
const userSockets = new Map(); // socketId -> userId
const conversationRooms = new Map(); // conversationId -> Set of socketIds

const setupSocket = (io) => {
  // Authentication middleware for Socket.io
  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth.token;
      
      if (!token) {
        return next(new Error('Authentication error: Token required'));
      }

      const decoded = verifyToken(
        token,
        process.env.JWT_SECRET || 'trustmarket-secret-key'
      );

      if (decoded.type !== 'access') {
        return next(new Error('Authentication error: Invalid token type'));
      }

      const user = await User.findById(decoded.userId);
      if (!user || !user.isActive || user.isBanned) {
        return next(new Error('Authentication error: User inactive'));
      }

      socket.userId = user._id.toString();
      socket.user = user;
      next();
    } catch (error) {
      console.error('Socket authentication error:', error);
      next(new Error('Authentication error: Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    console.log(`User ${socket.user.firstName} connected: ${socket.id}`);
    
    // Store user connection
    connectedUsers.set(socket.userId, socket.id);
    userSockets.set(socket.id, socket.userId);
    
    // Join user to their personal room
    socket.join(`user_${socket.userId}`);
    
    // Update user's online status
    updateUserOnlineStatus(socket.userId, true);

    // Handle joining conversation rooms
    socket.on('join_conversation', (conversationId) => {
      try {
        socket.join(conversationId);
        
        // Track conversation participants
        if (!conversationRooms.has(conversationId)) {
          conversationRooms.set(conversationId, new Set());
        }
        conversationRooms.get(conversationId).add(socket.id);
        
        console.log(`User ${socket.userId} joined conversation ${conversationId}`);
      } catch (error) {
        console.error('Join conversation error:', error);
        socket.emit('error', { message: 'Failed to join conversation' });
      }
    });

    // Handle leaving conversation rooms
    socket.on('leave_conversation', (conversationId) => {
      try {
        socket.leave(conversationId);
        
        if (conversationRooms.has(conversationId)) {
          conversationRooms.get(conversationId).delete(socket.id);
          
          // Clean up empty conversation rooms
          if (conversationRooms.get(conversationId).size === 0) {
            conversationRooms.delete(conversationId);
          }
        }
        
        console.log(`User ${socket.userId} left conversation ${conversationId}`);
      } catch (error) {
        console.error('Leave conversation error:', error);
      }
    });

    // Handle new messages
    socket.on('send_message', async (data) => {
      try {
        const { conversationId, receiverId, listingId, content, media } = data;
        
        // Validate required fields
        if (!conversationId || !receiverId || !listingId || !content) {
          return socket.emit('error', { message: 'Missing required message fields' });
        }

        // Create new message
        const message = new Message({
          conversationId,
          sender: socket.userId,
          receiver: receiverId,
          listing: listingId,
          content: content.trim(),
          media: media || [],
          status: 'sent'
        });

        await message.calculateSafetyScore();
        await message.save();
        
        // Populate sender info
        await message.populate('sender', 'firstName lastName profilePhoto trustScore.verification');
        await message.populate('listing', 'title price images');

        // Send to receiver if online
        const receiverSocketId = connectedUsers.get(receiverId);
        if (receiverSocketId) {
          io.to(receiverSocketId).emit('new_message', {
            message: message.toJSON(),
            conversationId
          });
          
          // Update message status to delivered
          message.status = 'delivered';
          await message.save();
          
          // Notify sender of delivery
          socket.emit('message_delivered', {
            messageId: message._id,
            conversationId
          });
        }

        // Send confirmation to sender
        socket.emit('message_sent', {
          message: message.toJSON(),
          conversationId
        });

        // Check for safety warnings
        if (message.isFlagged) {
          socket.emit('safety_warning', {
            messageId: message._id,
            warnings: message.safetyScore.warnings,
            flags: message.safetyScore.flags,
            safetyScore: message.safetyScore.overall
          });
          
          if (receiverSocketId) {
            io.to(receiverSocketId).emit('safety_warning', {
              messageId: message._id,
              warnings: message.safetyScore.warnings,
              flags: message.safetyScore.flags,
              safetyScore: message.safetyScore.overall
            });
          }
        }

        console.log(`Message sent in conversation ${conversationId}`);
      } catch (error) {
        console.error('Send message error:', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    // Handle message read status
    socket.on('mark_message_read', async (messageId) => {
      try {
        const message = await Message.findById(messageId);
        
        if (message && message.receiver.toString() === socket.userId) {
          await message.markAsRead();
          
          // Notify sender that message was read
          const senderSocketId = connectedUsers.get(message.sender.toString());
          if (senderSocketId) {
            io.to(senderSocketId).emit('message_read', {
              messageId,
              readAt: message.readAt
            });
          }
        }
      } catch (error) {
        console.error('Mark message read error:', error);
      }
    });

    // Handle typing indicators
    socket.on('typing_start', (data) => {
      const { conversationId } = data;
      socket.to(conversationId).emit('user_typing', {
        userId: socket.userId,
        isTyping: true
      });
    });

    socket.on('typing_stop', (data) => {
      const { conversationId } = data;
      socket.to(conversationId).emit('user_typing', {
        userId: socket.userId,
        isTyping: false
      });
    });

    // Handle trust score updates
    socket.on('trust_score_update', async () => {
      try {
        const updatedUser = await User.findById(socket.userId);
        if (updatedUser) {
          socket.emit('trust_score_updated', {
            trustScore: updatedUser.trustScore
          });
        }
      } catch (error) {
        console.error('Trust score update error:', error);
      }
    });

    // Handle safety alerts
    socket.on('report_suspicious_activity', async (data) => {
      try {
        const { type, targetId, reason, description } = data;
        
        // Create system message for safety alert
        const systemMessage = new Message({
          conversationId: `safety_${targetId}`,
          sender: socket.userId,
          receiver: targetId,
          listing: data.listingId || null,
          content: `Safety Alert: ${reason}`,
          isSystemMessage: true,
          systemMessageType: 'safety_warning',
          safetyScore: {
            overall: 0,
            flags: ['safety_alert'],
            warnings: [description || 'Suspicious activity reported']
          }
        });

        await systemMessage.save();
        
        // Notify both parties
        const targetSocketId = connectedUsers.get(targetId);
        if (targetSocketId) {
          io.to(targetSocketId).emit('safety_alert', {
            type,
            reason,
            description,
            reportedBy: socket.userId,
            timestamp: new Date()
          });
        }
      } catch (error) {
        console.error('Safety alert error:', error);
      }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      console.log(`User ${socket.userId} disconnected: ${socket.id}`);
      
      // Remove from connected users
      connectedUsers.delete(socket.userId);
      userSockets.delete(socket.id);
      
      // Clean up conversation rooms
      conversationRooms.forEach((socketIds, conversationId) => {
        socketIds.delete(socket.id);
        if (socketIds.size === 0) {
          conversationRooms.delete(conversationId);
        }
      });
      
      // Update user's online status
      updateUserOnlineStatus(socket.userId, false);
    });

    // Handle errors
    socket.on('error', (error) => {
      console.error(`Socket error for user ${socket.userId}:`, error);
    });
  });

  // Utility functions
  const updateUserOnlineStatus = async (userId, isOnline) => {
    try {
      await User.findByIdAndUpdate(userId, {
        'settings.privacy.showOnlineStatus': isOnline,
        lastLogin: isOnline ? new Date() : undefined
      });
    } catch (error) {
      console.error('Update online status error:', error);
    }
  };

  const getOnlineUsers = () => {
    return Array.from(connectedUsers.keys());
  };

  const isUserOnline = (userId) => {
    return connectedUsers.has(userId);
  };

  const getConversationParticipants = (conversationId) => {
    const socketIds = conversationRooms.get(conversationId);
    if (!socketIds) return [];
    
    return Array.from(socketIds).map(socketId => userSockets.get(socketId)).filter(Boolean);
  };

  // Make utilities available globally
  io.getOnlineUsers = getOnlineUsers;
  io.isUserOnline = isUserOnline;
  io.getConversationParticipants = getConversationParticipants;

  console.log('Socket.io setup completed');
};

module.exports = { setupSocket };