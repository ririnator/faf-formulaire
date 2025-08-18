// routes/notificationRoutes.js
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const { body, param, query, validationResult } = require('express-validator');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtectionStrict } = require('../middleware/csrf');
const { authLimiters } = require('../middleware/authRateLimit');
const { 
  apiLimiter,
  notificationLimiter,
  realtimeLimiter
} = require('../middleware/rateLimiting');
const { requireUserAuth } = require('../middleware/hybridAuth');
const { trackSimpleStats } = require('../middleware/statisticsMonitoring');
const { smartEscape } = require('../middleware/validation');
const ServiceFactory = require('../services/serviceFactory');
const NotificationService = require('../services/notificationService');
const { 
  preventParameterPollution,
  securityLogger,
  antiAutomation,
  validateContentType
} = require('../middleware/enhancedSecurity');

// Apply body parser middleware for all routes
router.use(createAdminBodyParser());

// Apply security middleware for all routes
router.use(securityLogger);
router.use(preventParameterPollution(['type', 'status']));
router.use(antiAutomation());

// Apply authentication middleware for all routes
router.use(requireUserAuth);

// Initialize notification service
const notificationService = new NotificationService({
  realTimeEnabled: true,
  maxNotificationsPerUser: 1000,
  cleanupIntervalHours: 6
});

// Secure validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.warn('Notification validation errors:', {
      ip: req.ip,
      path: req.path,
      errors: errors.array(),
      timestamp: new Date().toISOString()
    });
    
    return res.status(400).json({ 
      success: false,
      error: 'Données invalides. Vérifiez votre saisie.', 
      code: 'VALIDATION_ERROR'
    });
  }
  next();
};

// Helper function to validate MongoDB ObjectId
const isValidObjectId = (id) => {
  return mongoose.Types.ObjectId.isValid(id);
};

// Helper function to get user ID from session
const getUserId = (req) => {
  const userId = req.currentUser?.id || req.session?.userId;
  return userId ? userId.toString() : null;
};

/**
 * GET /api/notifications - Get user notifications with filtering and pagination
 */
router.get('/', 
  notificationLimiter,
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
    query('status').optional().isIn(['unread', 'read', 'archived', '']),
    query('type').optional().isIn(['handshake_request', 'handshake_accepted', 'handshake_declined', 'handshake_expired', 'contact_suggestion', 'system_announcement', '']),
    query('includeRead').optional().isBoolean(),
    query('priority').optional().isIn(['low', 'normal', 'high', 'urgent', '']),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const { 
      page = 1, 
      limit = 20, 
      status = '', 
      type = '',
      includeRead = true,
      priority = ''
    } = req.query;

    const options = {
      page: parseInt(page),
      limit: Math.min(50, parseInt(limit)),
      status: status.trim() || null,
      type: type.trim() || null,
      includeRead: includeRead === true || includeRead === 'true',
      includePriority: priority.trim() || null
    };

    const result = await notificationService.getUserNotifications(userId, options);
    
    // Convert notifications to client-safe format
    const notifications = result.notifications.map(notification => {
      if (notification.toClientJSON) {
        return notification.toClientJSON();
      }
      // Handle lean objects
      return {
        id: notification._id,
        type: notification.type,
        title: notification.title,
        message: notification.message,
        status: notification.status,
        priority: notification.priority,
        createdAt: notification.createdAt,
        readAt: notification.delivery?.readAt,
        actionData: notification.actionData,
        metadata: notification.metadata,
        relatedHandshakeId: notification.relatedHandshakeId,
        relatedContactId: notification.relatedContactId,
        relatedUserId: notification.relatedUserId,
        isActionable: notification.metadata?.isActionable || false
      };
    });
    
    res.json({
      success: true,
      notifications,
      pagination: result.pagination,
      options
    });

  } catch (error) {
    console.error('❌ Error getting notifications:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer les notifications.', 
      code: 'GET_NOTIFICATIONS_ERROR'
    });
  }
});

/**
 * GET /api/notifications/counts - Get unread notification counts
 */
router.get('/counts', 
  apiLimiter,
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const counts = await notificationService.getUnreadCounts(userId);
    
    res.json({
      success: true,
      counts
    });

  } catch (error) {
    console.error('❌ Error getting notification counts:', {
      error: error.message,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer les compteurs de notifications.', 
      code: 'GET_COUNTS_ERROR'
    });
  }
});

/**
 * POST /api/notifications/:id/read - Mark notification as read
 */
router.post('/:id/read', 
  notificationLimiter,
  csrfProtectionStrict(),
  [
    param('id').custom((value) => {
      if (!isValidObjectId(value)) {
        throw new Error('Invalid notification ID format');
      }
      return true;
    }),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const notificationId = req.params.id;

    if (!isValidObjectId(notificationId)) {
      return res.status(400).json({ 
        error: 'Invalid notification ID format', 
        code: 'INVALID_NOTIFICATION_ID' 
      });
    }

    const notification = await notificationService.markAsRead(notificationId, userId);
    
    res.json({
      success: true,
      notification: notification.toClientJSON ? notification.toClientJSON() : notification,
      message: 'Notification marquée comme lue'
    });

  } catch (error) {
    console.error('❌ Error marking notification as read:', error);
    
    if (error.message.includes('not found')) {
      return res.status(404).json({ 
        error: 'Notification not found', 
        code: 'NOTIFICATION_NOT_FOUND' 
      });
    }
    
    if (error.message.includes('access denied')) {
      return res.status(403).json({ 
        error: 'Access denied', 
        code: 'ACCESS_DENIED' 
      });
    }
    
    res.status(500).json({ 
      error: 'Failed to mark notification as read', 
      code: 'MARK_READ_ERROR' 
    });
  }
});

/**
 * POST /api/notifications/mark-all-read - Mark all notifications as read
 */
router.post('/mark-all-read', 
  notificationLimiter,
  csrfProtectionStrict(),
  [
    body('type').optional().isIn(['handshake_request', 'handshake_accepted', 'handshake_declined', 'handshake_expired', 'contact_suggestion', 'system_announcement']),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const { type } = req.body;

    const result = await notificationService.markAllAsRead(userId, type || null);
    
    res.json({
      success: true,
      modifiedCount: result.modifiedCount,
      type: type || 'all',
      message: `${result.modifiedCount} notifications marquées comme lues`
    });

  } catch (error) {
    console.error('❌ Error marking all notifications as read:', error);
    res.status(500).json({ 
      error: 'Failed to mark all notifications as read', 
      code: 'MARK_ALL_READ_ERROR' 
    });
  }
});

/**
 * POST /api/notifications/handshake/:id/accept - Accept handshake request via notification
 */
router.post('/handshake/:id/accept', 
  notificationLimiter,
  csrfProtectionStrict(),
  [
    param('id').custom((value) => {
      if (!isValidObjectId(value)) {
        throw new Error('Invalid handshake ID format');
      }
      return true;
    }),
    body('responseMessage').optional().trim().isLength({ max: 500 }),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const handshakeId = req.params.id;
    const { responseMessage } = req.body;

    if (!isValidObjectId(handshakeId)) {
      return res.status(400).json({ 
        error: 'Invalid handshake ID format', 
        code: 'INVALID_HANDSHAKE_ID' 
      });
    }

    const sanitizedMessage = responseMessage ? smartEscape(responseMessage.trim()) : '';
    
    const result = await notificationService.handleHandshakeAction(
      'accept', 
      handshakeId, 
      userId, 
      sanitizedMessage
    );
    
    res.json({
      success: result.success,
      handshake: result.handshake,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error accepting handshake via notification:', error);
    
    if (error.message.includes('not found')) {
      return res.status(404).json({ 
        error: 'Handshake not found', 
        code: 'HANDSHAKE_NOT_FOUND' 
      });
    }
    
    if (error.message.includes('recipient')) {
      return res.status(403).json({ 
        error: 'Only the recipient can accept this handshake', 
        code: 'PERMISSION_DENIED' 
      });
    }
    
    if (error.message.includes('already')) {
      return res.status(409).json({ 
        error: 'Handshake already processed', 
        code: 'HANDSHAKE_ALREADY_PROCESSED' 
      });
    }
    
    if (error.message.includes('expired')) {
      return res.status(410).json({ 
        error: 'This handshake has expired', 
        code: 'HANDSHAKE_EXPIRED' 
      });
    }
    
    res.status(400).json({ 
      error: 'Failed to accept handshake', 
      code: 'ACCEPT_HANDSHAKE_ERROR' 
    });
  }
});

/**
 * POST /api/notifications/handshake/:id/decline - Decline handshake request via notification
 */
router.post('/handshake/:id/decline', 
  notificationLimiter,
  csrfProtectionStrict(),
  [
    param('id').custom((value) => {
      if (!isValidObjectId(value)) {
        throw new Error('Invalid handshake ID format');
      }
      return true;
    }),
    body('responseMessage').optional().trim().isLength({ max: 500 }),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const handshakeId = req.params.id;
    const { responseMessage } = req.body;

    if (!isValidObjectId(handshakeId)) {
      return res.status(400).json({ 
        error: 'Invalid handshake ID format', 
        code: 'INVALID_HANDSHAKE_ID' 
      });
    }

    const sanitizedMessage = responseMessage ? smartEscape(responseMessage.trim()) : '';
    
    const result = await notificationService.handleHandshakeAction(
      'decline', 
      handshakeId, 
      userId, 
      sanitizedMessage
    );
    
    res.json({
      success: result.success,
      handshake: result.handshake,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error declining handshake via notification:', error);
    
    if (error.message.includes('not found')) {
      return res.status(404).json({ 
        error: 'Handshake not found', 
        code: 'HANDSHAKE_NOT_FOUND' 
      });
    }
    
    if (error.message.includes('recipient')) {
      return res.status(403).json({ 
        error: 'Only the recipient can decline this handshake', 
        code: 'PERMISSION_DENIED' 
      });
    }
    
    if (error.message.includes('already')) {
      return res.status(409).json({ 
        error: 'Handshake already processed', 
        code: 'HANDSHAKE_ALREADY_PROCESSED' 
      });
    }
    
    res.status(400).json({ 
      error: 'Failed to decline handshake', 
      code: 'DECLINE_HANDSHAKE_ERROR' 
    });
  }
});

/**
 * GET /api/notifications/stream - Server-Sent Events endpoint for real-time updates
 */
router.get('/stream', 
  realtimeLimiter,
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    // Set SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });

    // Register SSE connection
    const connectionId = notificationService.registerSSEConnection(userId, res);

    // Send periodic heartbeats
    const heartbeatInterval = setInterval(() => {
      notificationService.sendHeartbeat();
    }, 30000); // Every 30 seconds

    // Handle client disconnect
    req.on('close', () => {
      clearInterval(heartbeatInterval);
    });

    req.on('aborted', () => {
      clearInterval(heartbeatInterval);
    });

  } catch (error) {
    console.error('❌ Error setting up SSE stream:', {
      error: error.message,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    if (!res.headersSent) {
      res.status(500).json({ 
        error: 'Failed to establish real-time connection', 
        code: 'SSE_SETUP_ERROR' 
      });
    }
  }
});

/**
 * GET /api/notifications/stats - Get notification statistics (for monitoring)
 */
router.get('/stats', 
  require('../middleware/rateLimiting').statsSimpleLimiter,
  trackSimpleStats,
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const stats = await notificationService.getStatistics();
    
    res.json({
      success: true,
      stats
    });

  } catch (error) {
    console.error('❌ Error getting notification stats:', error);
    res.status(500).json({ 
      error: 'Failed to get notification statistics', 
      code: 'GET_NOTIFICATION_STATS_ERROR'
    });
  }
});

/**
 * POST /api/notifications/test - Create test notification (development only)
 */
if (process.env.NODE_ENV !== 'production') {
  router.post('/test', 
    notificationLimiter,
    csrfProtectionStrict(),
    [
      body('type').isIn(['handshake_request', 'handshake_accepted', 'handshake_declined', 'handshake_expired', 'contact_suggestion', 'system_announcement']),
      body('title').trim().isLength({ min: 1, max: 200 }),
      body('message').trim().isLength({ min: 1, max: 1000 }),
      body('priority').optional().isIn(['low', 'normal', 'high', 'urgent']),
      handleValidationErrors
    ],
    async (req, res) => {
    try {
      const userId = getUserId(req);
      if (!userId) {
        return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
      }

      const { type, title, message, priority } = req.body;

      const notification = await notificationService.createNotification({
        recipientId: userId,
        type,
        title: smartEscape(title.trim()),
        message: smartEscape(message.trim()),
        priority: priority || 'normal',
        metadata: {
          source: 'admin',
          category: 'test',
          isActionable: false
        }
      });
      
      res.json({
        success: true,
        notification: notification.toClientJSON ? notification.toClientJSON() : notification,
        message: 'Test notification created'
      });

    } catch (error) {
      console.error('❌ Error creating test notification:', error);
      res.status(500).json({ 
        error: 'Failed to create test notification', 
        code: 'CREATE_TEST_NOTIFICATION_ERROR' 
      });
    }
  });
}

module.exports = router;