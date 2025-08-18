const mongoose = require('mongoose');
const Notification = require('../models/Notification');
const Handshake = require('../models/Handshake');
const User = require('../models/User');
const { sanitizeMongoInput, sanitizeObjectId, logSecurityEvent } = require('../middleware/querySanitization');

class NotificationService {
  constructor(config = {}) {
    this.config = {
      maxNotificationsPerUser: config.maxNotificationsPerUser || 1000,
      cleanupIntervalHours: config.cleanupIntervalHours || 24,
      defaultExpirationDays: config.defaultExpirationDays || 7,
      realTimeEnabled: config.realTimeEnabled || true,
      batchSize: config.batchSize || 50
    };
    
    // Store SSE connections for real-time updates
    this.sseConnections = new Map();
    
    // Start cleanup interval
    this.startCleanupInterval();
  }

  /**
   * Create a notification for a user
   * @param {Object} notificationData - Notification data
   * @returns {Promise<Object>} Created notification
   */
  async createNotification(notificationData) {
    try {
      // Sanitize input data
      const sanitizedData = sanitizeMongoInput(notificationData);
      
      // Validate recipient exists
      const recipientId = sanitizeObjectId(sanitizedData.recipientId);
      if (!recipientId) {
        throw new Error('Invalid recipient ID');
      }

      const recipient = await User.findById(recipientId);
      if (!recipient) {
        throw new Error('Recipient user not found');
      }

      // Check notification limits
      await this.checkNotificationLimits(recipientId);

      // Create notification
      const notification = await Notification.create({
        ...sanitizedData,
        recipientId,
        metadata: {
          ...sanitizedData.metadata,
          source: sanitizedData.metadata?.source || 'system'
        }
      });

      // Populate related data for real-time updates
      const populatedNotification = await Notification.findById(notification._id)
        .populate('relatedUserId', 'username email')
        .populate('relatedHandshakeId');

      // Send real-time update
      if (this.config.realTimeEnabled) {
        this.sendRealTimeUpdate(recipientId, 'notification_created', populatedNotification);
      }

      return populatedNotification;

    } catch (error) {
      logSecurityEvent('NOTIFICATION_CREATION_ERROR', {
        error: error.message,
        recipientId: notificationData.recipientId
      });
      throw new Error(`Failed to create notification: ${error.message}`);
    }
  }

  /**
   * Create handshake-related notification
   * @param {String} type - Notification type
   * @param {ObjectId} recipientId - Recipient user ID
   * @param {Object} handshake - Handshake object
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Created notification
   */
  async createHandshakeNotification(type, recipientId, handshake, options = {}) {
    try {
      const sanitizedRecipientId = sanitizeObjectId(recipientId);
      const sanitizedOptions = sanitizeMongoInput(options);
      
      if (!sanitizedRecipientId) {
        throw new Error('Invalid recipient ID');
      }

      // Check if notification already exists for this handshake/type combination
      const existingNotification = await Notification.findOne({
        recipientId: sanitizedRecipientId,
        type,
        relatedHandshakeId: handshake._id,
        status: { $ne: 'archived' }
      });

      if (existingNotification) {
        // Update existing notification instead of creating duplicate
        existingNotification.createdAt = new Date();
        existingNotification.status = 'unread';
        existingNotification.delivery.isDelivered = false;
        existingNotification.delivery.readAt = null;
        
        await existingNotification.save();
        return existingNotification;
      }

      return await Notification.createHandshakeNotification(
        type, 
        sanitizedRecipientId, 
        handshake, 
        sanitizedOptions
      );

    } catch (error) {
      throw new Error(`Failed to create handshake notification: ${error.message}`);
    }
  }

  /**
   * Get user notifications with filtering and pagination
   * @param {ObjectId} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Notifications with pagination
   */
  async getUserNotifications(userId, options = {}) {
    try {
      const sanitizedUserId = sanitizeObjectId(userId);
      const sanitizedOptions = sanitizeMongoInput(options);
      
      if (!sanitizedUserId) {
        throw new Error('Invalid user ID');
      }

      return await Notification.getUserNotifications(sanitizedUserId, sanitizedOptions);

    } catch (error) {
      throw new Error(`Failed to get user notifications: ${error.message}`);
    }
  }

  /**
   * Get unread notification counts for user
   * @param {ObjectId} userId - User ID
   * @returns {Promise<Object>} Unread counts by type
   */
  async getUnreadCounts(userId) {
    try {
      const sanitizedUserId = sanitizeObjectId(userId);
      
      if (!sanitizedUserId) {
        throw new Error('Invalid user ID');
      }

      return await Notification.getUnreadCounts(sanitizedUserId);

    } catch (error) {
      throw new Error(`Failed to get unread counts: ${error.message}`);
    }
  }

  /**
   * Mark notification as read
   * @param {ObjectId} notificationId - Notification ID
   * @param {ObjectId} userId - User ID (for authorization)
   * @returns {Promise<Object>} Updated notification
   */
  async markAsRead(notificationId, userId) {
    try {
      const sanitizedNotificationId = sanitizeObjectId(notificationId);
      const sanitizedUserId = sanitizeObjectId(userId);
      
      if (!sanitizedNotificationId || !sanitizedUserId) {
        throw new Error('Invalid notification or user ID');
      }

      const notification = await Notification.findOne({
        _id: sanitizedNotificationId,
        recipientId: sanitizedUserId
      });

      if (!notification) {
        throw new Error('Notification not found or access denied');
      }

      await notification.markAsRead();

      // Send real-time update
      if (this.config.realTimeEnabled) {
        this.sendRealTimeUpdate(sanitizedUserId, 'notification_read', {
          notificationId: sanitizedNotificationId,
          status: 'read'
        });
      }

      return notification;

    } catch (error) {
      throw new Error(`Failed to mark notification as read: ${error.message}`);
    }
  }

  /**
   * Mark all notifications as read for user
   * @param {ObjectId} userId - User ID
   * @param {String} type - Optional notification type filter
   * @returns {Promise<Object>} Update result
   */
  async markAllAsRead(userId, type = null) {
    try {
      const sanitizedUserId = sanitizeObjectId(userId);
      
      if (!sanitizedUserId) {
        throw new Error('Invalid user ID');
      }

      const result = await Notification.markAllAsRead(sanitizedUserId, type);

      // Send real-time update
      if (this.config.realTimeEnabled) {
        this.sendRealTimeUpdate(sanitizedUserId, 'notifications_read_all', {
          type,
          count: result.modifiedCount
        });
      }

      return result;

    } catch (error) {
      throw new Error(`Failed to mark all notifications as read: ${error.message}`);
    }
  }

  /**
   * Handle handshake actions with notification updates
   * @param {String} action - Action type (accept, decline)
   * @param {ObjectId} handshakeId - Handshake ID
   * @param {ObjectId} userId - User ID performing action
   * @param {String} responseMessage - Optional response message
   * @returns {Promise<Object>} Result with updated handshake and notifications
   */
  async handleHandshakeAction(action, handshakeId, userId, responseMessage = '') {
    try {
      const sanitizedHandshakeId = sanitizeObjectId(handshakeId);
      const sanitizedUserId = sanitizeObjectId(userId);
      
      if (!sanitizedHandshakeId || !sanitizedUserId) {
        throw new Error('Invalid handshake or user ID');
      }

      // Get handshake with populated user data
      const handshake = await Handshake.findById(sanitizedHandshakeId)
        .populate('requesterId', 'username email')
        .populate('targetId', 'username email');

      if (!handshake) {
        throw new Error('Handshake not found');
      }

      // Verify user can perform this action
      if (!handshake.targetId._id.equals(new mongoose.Types.ObjectId(sanitizedUserId))) {
        throw new Error('Only the recipient can perform this action');
      }

      if (handshake.status !== 'pending') {
        throw new Error(`Handshake already ${handshake.status}`);
      }

      if (handshake.isExpired()) {
        throw new Error('This handshake has expired');
      }

      let notificationType;
      let updatedHandshake;

      // Perform the action
      if (action === 'accept') {
        updatedHandshake = await handshake.accept(responseMessage);
        notificationType = 'handshake_accepted';
      } else if (action === 'decline') {
        updatedHandshake = await handshake.decline(responseMessage);
        notificationType = 'handshake_declined';
      } else {
        throw new Error('Invalid action type');
      }

      // Create notification for the requester
      await this.createHandshakeNotification(
        notificationType,
        handshake.requesterId._id,
        updatedHandshake,
        { priority: 'normal' }
      );

      // Mark original notification as read
      await Notification.updateMany(
        {
          recipientId: sanitizedUserId,
          relatedHandshakeId: sanitizedHandshakeId,
          type: 'handshake_request',
          status: 'unread'
        },
        { 
          status: 'read',
          'delivery.readAt': new Date() 
        }
      );

      // Send real-time updates to both users
      if (this.config.realTimeEnabled) {
        this.sendRealTimeUpdate(sanitizedUserId, 'handshake_action_completed', {
          handshakeId: sanitizedHandshakeId,
          action,
          status: updatedHandshake.status
        });

        this.sendRealTimeUpdate(handshake.requesterId._id, 'handshake_response_received', {
          handshakeId: sanitizedHandshakeId,
          action,
          status: updatedHandshake.status,
          from: handshake.targetId.username
        });
      }

      return {
        handshake: updatedHandshake,
        success: true,
        message: `Handshake ${action}ed successfully`
      };

    } catch (error) {
      throw new Error(`Failed to handle handshake action: ${error.message}`);
    }
  }

  /**
   * Register SSE connection for real-time updates
   * @param {ObjectId} userId - User ID
   * @param {Object} response - Express response object
   */
  registerSSEConnection(userId, response) {
    const sanitizedUserId = sanitizeObjectId(userId);
    
    if (!sanitizedUserId) {
      return;
    }

    const connectionId = `${sanitizedUserId}_${Date.now()}`;
    
    this.sseConnections.set(connectionId, {
      userId: sanitizedUserId,
      response,
      lastHeartbeat: Date.now()
    });

    // Send initial connection confirmation
    this.sendSSEMessage(response, {
      type: 'connection_established',
      data: { connectionId, timestamp: new Date().toISOString() }
    });

    // Handle connection cleanup
    response.on('close', () => {
      this.sseConnections.delete(connectionId);
    });

    return connectionId;
  }

  /**
   * Send real-time update to user
   * @param {ObjectId} userId - User ID
   * @param {String} eventType - Event type
   * @param {Object} data - Event data
   */
  sendRealTimeUpdate(userId, eventType, data) {
    const sanitizedUserId = sanitizeObjectId(userId);
    
    if (!sanitizedUserId || !this.config.realTimeEnabled) {
      return;
    }

    // Find all connections for this user
    for (const [connectionId, connection] of this.sseConnections.entries()) {
      if (connection.userId.toString() === sanitizedUserId.toString()) {
        this.sendSSEMessage(connection.response, {
          type: eventType,
          data: data,
          timestamp: new Date().toISOString()
        });
      }
    }
  }

  /**
   * Send SSE message to client
   * @param {Object} response - Express response object
   * @param {Object} message - Message to send
   */
  sendSSEMessage(response, message) {
    try {
      const data = JSON.stringify(message);
      response.write(`data: ${data}\n\n`);
    } catch (error) {
      console.warn('Failed to send SSE message:', error.message);
    }
  }

  /**
   * Send heartbeat to all connections
   */
  sendHeartbeat() {
    const heartbeatMessage = {
      type: 'heartbeat',
      data: { timestamp: new Date().toISOString() }
    };

    for (const [connectionId, connection] of this.sseConnections.entries()) {
      try {
        this.sendSSEMessage(connection.response, heartbeatMessage);
        connection.lastHeartbeat = Date.now();
      } catch (error) {
        // Remove dead connections
        this.sseConnections.delete(connectionId);
      }
    }
  }

  /**
   * Check notification limits for user
   * @param {ObjectId} userId - User ID
   */
  async checkNotificationLimits(userId) {
    const count = await Notification.countDocuments({
      recipientId: userId,
      status: { $ne: 'archived' }
    });

    if (count >= this.config.maxNotificationsPerUser) {
      // Archive oldest read notifications to make room
      await Notification.updateMany(
        {
          recipientId: userId,
          status: 'read'
        },
        { status: 'archived' },
        { 
          sort: { 'delivery.readAt': 1 },
          limit: Math.floor(this.config.maxNotificationsPerUser * 0.1) // Archive 10%
        }
      );
    }
  }

  /**
   * Start automatic cleanup interval
   */
  startCleanupInterval() {
    // Skip interval setup in test environment
    if (process.env.NODE_ENV === 'test') {
      return;
    }
    
    const intervalMs = this.config.cleanupIntervalHours * 60 * 60 * 1000;
    
    setInterval(async () => {
      try {
        await this.performCleanup();
      } catch (error) {
        console.error('Notification cleanup error:', error.message);
      }
    }, intervalMs);
  }

  /**
   * Perform notification cleanup
   * @returns {Promise<Object>} Cleanup results
   */
  async performCleanup() {
    const result = await Notification.cleanupOldNotifications(30);
    
    // Clean up expired handshake notifications
    const expiredCount = await Notification.updateMany(
      {
        type: 'handshake_request',
        'actionData.expiresAt': { $lt: new Date() },
        status: { $ne: 'archived' }
      },
      { status: 'archived' }
    );

    result.expiredHandshakes = expiredCount.modifiedCount;

    return result;
  }

  /**
   * Get notification statistics for monitoring
   * @returns {Promise<Object>} Statistics
   */
  async getStatistics() {
    const stats = await Notification.aggregate([
      {
        $group: {
          _id: null,
          totalNotifications: { $sum: 1 },
          unreadCount: { $sum: { $cond: [{ $eq: ['$status', 'unread'] }, 1, 0] } },
          readCount: { $sum: { $cond: [{ $eq: ['$status', 'read'] }, 1, 0] } },
          archivedCount: { $sum: { $cond: [{ $eq: ['$status', 'archived'] }, 1, 0] } },
          highPriorityCount: { $sum: { $cond: [{ $in: ['$priority', ['high', 'urgent']] }, 1, 0] } }
        }
      }
    ]);

    const result = stats[0] || {
      totalNotifications: 0,
      unreadCount: 0,
      readCount: 0,
      archivedCount: 0,
      highPriorityCount: 0
    };

    result.activeConnections = this.sseConnections.size;
    result.readRate = result.totalNotifications > 0 ? 
      Math.round((result.readCount / result.totalNotifications) * 100) : 0;

    return result;
  }
}

module.exports = NotificationService;