// routes/handshakeRoutes.js
const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const { body, param, query, validationResult } = require('express-validator');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtectionStrict } = require('../middleware/csrf');
const { authLimiters } = require('../middleware/authRateLimit');
const { 
  handshakeLimiter, 
  apiLimiter,
  searchBasicLimiter,
  searchSuggestionsLimiter,
  searchAnalyticsLimiter 
} = require('../middleware/rateLimiting');
const { searchComplexityMiddleware } = require('../middleware/searchComplexityAnalyzer');
const searchMonitoringService = require('../services/searchMonitoringService');
const { requireUserAuth } = require('../middleware/hybridAuth');
const { trackSimpleStats } = require('../middleware/statisticsMonitoring');
const { smartEscape } = require('../middleware/validation');
const ServiceFactory = require('../services/serviceFactory');
const User = require('../models/User');
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
router.use(preventParameterPollution(['tags', 'skills']));
router.use(antiAutomation());

// Apply authentication middleware for all routes
router.use(requireUserAuth);

// Secure validation error handler - prevents information disclosure
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Log detailed errors server-side for debugging
    console.warn('Handshake validation errors:', {
      ip: req.ip,
      path: req.path,
      errors: errors.array(),
      timestamp: new Date().toISOString()
    });
    
    // Return generic error to client to prevent information disclosure
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
  // Convert ObjectId to string if necessary
  return userId ? userId.toString() : null;
};

// Search monitoring middleware for handshakes
const trackHandshakeSearchEvent = (req, res, next) => {
  const originalSend = res.send;
  const startTime = Date.now();
  
  res.send = function(data) {
    const responseTime = Date.now() - startTime;
    
    // Parse response to get result count if possible
    let resultCount = 0;
    let success = res.statusCode < 400;
    
    try {
      const responseData = typeof data === 'string' ? JSON.parse(data) : data;
      if (responseData.handshakes) {
        resultCount = Array.isArray(responseData.handshakes) ? responseData.handshakes.length : 0;
      } else if (responseData.suggestions) {
        resultCount = Array.isArray(responseData.suggestions) ? responseData.suggestions.length : 0;
      } else if (responseData.total !== undefined) {
        resultCount = responseData.total;
      }
    } catch (e) {
      // Ignore parsing errors
    }

    // Record search event
    searchMonitoringService.recordSearchEvent({
      userId: getUserId(req),
      ip: req.ip,
      query: `${req.query.status || ''}${req.query.dateFrom ? ' date-filtered' : ''}`,
      path: req.path,
      complexity: req.searchComplexity,
      responseTime,
      resultCount,
      success,
      userAgent: req.get('user-agent')
    });

    return originalSend.call(this, data);
  };
  
  next();
};

/**
 * GET /api/handshakes/received - Get handshake requests received by the user
 */
router.get('/received', 
  searchComplexityMiddleware, // Apply smart search rate limiting
  trackHandshakeSearchEvent, // Monitor search patterns
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
    query('status').optional().isIn(['pending', 'accepted', 'declined', 'blocked', 'expired', '']),
    query('includeExpired').optional().isBoolean(),
    query('dateFrom').optional().isISO8601(),
    query('dateTo').optional().isISO8601(),
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
      includeExpired = false,
      dateFrom,
      dateTo 
    } = req.query;

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const filters = {
      direction: 'received',
      status: status.trim(),
      includeExpired: includeExpired === true || includeExpired === 'true',
      dateFrom: dateFrom ? new Date(dateFrom) : null,
      dateTo: dateTo ? new Date(dateTo) : null
    };

    const pagination = {
      page: parseInt(page),
      limit: Math.min(50, parseInt(limit)),
      sortBy: 'requestedAt',
      sortOrder: 'desc'
    };

    const result = await handshakeService.getUserHandshakes(userId, filters, pagination);
    
    res.json({
      success: true,
      handshakes: result.handshakes,
      pagination: result.pagination,
      stats: result.stats,
      filters
    });

  } catch (error) {
    console.error('❌ Error getting received handshakes:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer les handshakes reçus.', 
      code: 'GET_RECEIVED_HANDSHAKES_ERROR'
    });
  }
});

/**
 * GET /api/handshakes/sent - Get handshake requests sent by the user
 */
router.get('/sent', 
  searchComplexityMiddleware, // Apply smart search rate limiting
  trackHandshakeSearchEvent, // Monitor search patterns
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
    query('status').optional().isIn(['pending', 'accepted', 'declined', 'blocked', 'expired', '']),
    query('includeExpired').optional().isBoolean(),
    query('dateFrom').optional().isISO8601(),
    query('dateTo').optional().isISO8601(),
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
      includeExpired = false,
      dateFrom,
      dateTo 
    } = req.query;

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const filters = {
      direction: 'sent',
      status: status.trim(),
      includeExpired: includeExpired === true || includeExpired === 'true',
      dateFrom: dateFrom ? new Date(dateFrom) : null,
      dateTo: dateTo ? new Date(dateTo) : null
    };

    const pagination = {
      page: parseInt(page),
      limit: Math.min(50, parseInt(limit)),
      sortBy: 'requestedAt',
      sortOrder: 'desc'
    };

    const result = await handshakeService.getUserHandshakes(userId, filters, pagination);
    
    res.json({
      success: true,
      handshakes: result.handshakes,
      pagination: result.pagination,
      stats: result.stats,
      filters
    });

  } catch (error) {
    console.error('❌ Error getting sent handshakes:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer les handshakes envoyés.', 
      code: 'GET_SENT_HANDSHAKES_ERROR'
    });
  }
});

/**
 * POST /api/handshakes/request - Send a handshake request to another user
 */
router.post('/request', 
  handshakeLimiter,
  csrfProtectionStrict(),
  [
    // Either email or userId must be provided
    body('email').optional().trim().isEmail().normalizeEmail(),
    body('userId').optional().custom((value) => {
      if (value && !isValidObjectId(value)) {
        throw new Error('Invalid userId format');
      }
      return true;
    }),
    body('message').optional().trim().isLength({ max: 500 }),
    body('source').optional().isIn(['manual', 'contact_add', 'invitation_response']),
    // Custom validation to ensure either email or userId is provided
    body().custom((req) => {
      if (!req.email && !req.userId) {
        throw new Error('Either email or userId must be provided');
      }
      if (req.email && req.userId) {
        throw new Error('Provide either email or userId, not both');
      }
      return true;
    }),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const currentUserId = getUserId(req);
    if (!currentUserId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const { email, userId, message, source } = req.body;
    let targetUserId;

    // Find target user by email or use provided userId
    if (email) {
      const targetUser = await User.findOne({ email: email }).select('_id username email');
      if (!targetUser) {
        return res.status(404).json({ 
          error: 'User not found with this email address', 
          code: 'USER_NOT_FOUND' 
        });
      }
      targetUserId = targetUser._id;
    } else {
      // Validate userId exists
      const targetUser = await User.findById(userId).select('_id username email');
      if (!targetUser) {
        return res.status(404).json({ 
          error: 'User not found', 
          code: 'USER_NOT_FOUND' 
        });
      }
      targetUserId = userId;
    }

    // Check if trying to send handshake to self
    if (new mongoose.Types.ObjectId(currentUserId).equals(new mongoose.Types.ObjectId(targetUserId))) {
      return res.status(400).json({ 
        error: 'Cannot send handshake request to yourself', 
        code: 'SELF_HANDSHAKE_ERROR' 
      });
    }

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const options = {
      initiator: currentUserId,
      message: message ? smartEscape(message.trim()) : '',
      source: source || 'manual',
      metadata: {
        requestMethod: email ? 'email' : 'userId',
        requestedAt: new Date()
      }
    };

    const result = await handshakeService.createMutual(currentUserId, targetUserId, options);
    
    res.status(201).json({
      success: true,
      handshake: result.handshake,
      created: result.created,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error creating handshake request:', error);
    
    console.error('❌ Error creating handshake request:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      targetEmail: req.body.email,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    if (error.message.includes('Limite de handshakes atteinte')) {
      return res.status(429).json({ 
        success: false,
        error: 'Limite de demandes atteinte. Réessayez plus tard.', 
        code: 'RATE_LIMIT_EXCEEDED' 
      });
    }
    
    if (error.message.includes('bloqué')) {
      return res.status(403).json({ 
        success: false,
        error: 'Action non autorisée.', 
        code: 'USER_BLOCKED' 
      });
    }
    
    if (error.message.includes('déjà existant')) {
      return res.status(409).json({ 
        success: false,
        error: 'Cette demande existe déjà.', 
        code: 'HANDSHAKE_EXISTS' 
      });
    }
    
    res.status(400).json({ 
      success: false,
      error: 'Impossible de créer la demande de handshake.', 
      code: 'CREATE_HANDSHAKE_ERROR' 
    });
  }
});

/**
 * POST /api/handshakes/:id/accept - Accept a received handshake request
 */
router.post('/:id/accept', 
  handshakeLimiter,
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

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const sanitizedMessage = responseMessage ? smartEscape(responseMessage.trim()) : '';
    
    const result = await handshakeService.accept(handshakeId, userId, sanitizedMessage);
    
    res.json({
      success: result.success,
      handshake: result.handshake,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error accepting handshake:', error);
    
    if (error.message.includes('non trouvé')) {
      return res.status(404).json({ 
        error: 'Handshake not found', 
        code: 'HANDSHAKE_NOT_FOUND' 
      });
    }
    
    if (error.message.includes('destinataire')) {
      return res.status(403).json({ 
        error: 'Only the recipient can accept this handshake', 
        code: 'PERMISSION_DENIED' 
      });
    }
    
    if (error.message.includes('déjà')) {
      return res.status(409).json({ 
        error: 'Handshake already processed', 
        code: 'HANDSHAKE_ALREADY_PROCESSED' 
      });
    }
    
    if (error.message.includes('expiré')) {
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
 * POST /api/handshakes/:id/decline - Decline a received handshake request
 */
router.post('/:id/decline', 
  handshakeLimiter,
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

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const sanitizedMessage = responseMessage ? smartEscape(responseMessage.trim()) : '';
    
    const result = await handshakeService.decline(handshakeId, userId, sanitizedMessage);
    
    res.json({
      success: result.success,
      handshake: result.handshake,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error declining handshake:', error);
    
    if (error.message.includes('non trouvé')) {
      return res.status(404).json({ 
        error: 'Handshake not found', 
        code: 'HANDSHAKE_NOT_FOUND' 
      });
    }
    
    if (error.message.includes('destinataire')) {
      return res.status(403).json({ 
        error: 'Only the recipient can decline this handshake', 
        code: 'PERMISSION_DENIED' 
      });
    }
    
    if (error.message.includes('déjà')) {
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
 * GET /api/handshakes/:id - Get specific handshake details
 */
router.get('/:id', 
  apiLimiter,
  [
    param('id').custom((value) => {
      if (!isValidObjectId(value)) {
        throw new Error('Invalid handshake ID format');
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

    const handshakeId = req.params.id;

    if (!isValidObjectId(handshakeId)) {
      return res.status(400).json({ 
        error: 'Invalid handshake ID format', 
        code: 'INVALID_HANDSHAKE_ID' 
      });
    }

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    // SECURITY FIX: Direct ownership validation instead of filtering all handshakes
    // Get handshake directly and verify user is either requester or target
    const handshake = await handshakeService.getHandshakeById(handshakeId);
    
    if (!handshake) {
      return res.status(404).json({ 
        error: 'Handshake not found', 
        code: 'HANDSHAKE_NOT_FOUND' 
      });
    }

    // CRITICAL AUTHORIZATION CHECK: Ensure user is involved in this handshake
    const userObjectId = new mongoose.Types.ObjectId(userId);
    const isRequester = handshake.requesterId.equals(userObjectId);
    const isTarget = handshake.targetId.equals(userObjectId);
    
    if (!isRequester && !isTarget) {
      return res.status(403).json({ 
        error: 'Access denied. You are not authorized to view this handshake.', 
        code: 'ACCESS_DENIED' 
      });
    }
    
    res.json({
      success: true,
      handshake
    });

  } catch (error) {
    console.error('❌ Error getting handshake:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      handshakeId: req.params.id,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer le handshake.', 
      code: 'GET_HANDSHAKE_ERROR'
    });
  }
});

/**
 * POST /api/handshakes/:id/cancel - Cancel a sent handshake request (by requester only)
 */
router.post('/:id/cancel', 
  handshakeLimiter,
  csrfProtectionStrict(),
  [
    param('id').custom((value) => {
      if (!isValidObjectId(value)) {
        throw new Error('Invalid handshake ID format');
      }
      return true;
    }),
    body('reason').optional().trim().isLength({ max: 200 }),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const handshakeId = req.params.id;
    const { reason } = req.body;

    if (!isValidObjectId(handshakeId)) {
      return res.status(400).json({ 
        error: 'Invalid handshake ID format', 
        code: 'INVALID_HANDSHAKE_ID' 
      });
    }

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const sanitizedReason = reason ? smartEscape(reason.trim()) : 'user_cancelled';
    
    const result = await handshakeService.cancel(handshakeId, userId, sanitizedReason);
    
    res.json({
      success: result.success,
      handshake: result.handshake,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error cancelling handshake:', error);
    
    if (error.message.includes('non trouvé')) {
      return res.status(404).json({ 
        error: 'Handshake not found', 
        code: 'HANDSHAKE_NOT_FOUND' 
      });
    }
    
    if (error.message.includes('demandeur')) {
      return res.status(403).json({ 
        error: 'Only the requester can cancel this handshake', 
        code: 'PERMISSION_DENIED' 
      });
    }
    
    if (error.message.includes('Impossible d\'annuler')) {
      return res.status(409).json({ 
        error: 'Cannot cancel handshake in current state', 
        code: 'HANDSHAKE_CANNOT_CANCEL' 
      });
    }
    
    res.status(400).json({ 
      error: 'Failed to cancel handshake', 
      code: 'CANCEL_HANDSHAKE_ERROR' 
    });
  }
});

/**
 * POST /api/handshakes/:id/block - Block a user (prevents future handshakes)
 */
router.post('/:id/block', 
  handshakeLimiter,
  csrfProtectionStrict(),
  [
    param('id').custom((value) => {
      if (!isValidObjectId(value)) {
        throw new Error('Invalid handshake ID format');
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

    const handshakeId = req.params.id;

    if (!isValidObjectId(handshakeId)) {
      return res.status(400).json({ 
        error: 'Invalid handshake ID format', 
        code: 'INVALID_HANDSHAKE_ID' 
      });
    }

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const result = await handshakeService.block(handshakeId, userId);
    
    res.json({
      success: result.success,
      handshake: result.handshake,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error blocking user:', error);
    
    if (error.message.includes('non trouvé')) {
      return res.status(404).json({ 
        error: 'Handshake not found', 
        code: 'HANDSHAKE_NOT_FOUND' 
      });
    }
    
    if (error.message.includes('destinataire')) {
      return res.status(403).json({ 
        error: 'Only the recipient can block this user', 
        code: 'PERMISSION_DENIED' 
      });
    }
    
    res.status(400).json({ 
      error: 'Failed to block user', 
      code: 'BLOCK_USER_ERROR' 
    });
  }
});

/**
 * GET /api/handshakes/suggestions - Get handshake suggestions for the user
 */
router.get('/suggestions', 
  searchSuggestionsLimiter, // Use suggestions-specific rate limiting
  trackHandshakeSearchEvent, // Monitor search patterns
  [
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt(),
    query('excludeExisting').optional().isBoolean(),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const { limit = 10, excludeExisting = true } = req.query;

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const options = {
      limit: Math.min(50, parseInt(limit)),
      excludeExisting: excludeExisting === true || excludeExisting === 'true'
    };

    const suggestions = await handshakeService.getSuggestions(userId, options);
    
    res.json({
      success: true,
      suggestions,
      total: suggestions.length,
      options
    });

  } catch (error) {
    console.error('❌ Error getting handshake suggestions:', error);
    res.status(500).json({ 
      error: 'Failed to get handshake suggestions', 
      code: 'GET_SUGGESTIONS_ERROR'
    });
  }
});

/**
 * GET /api/handshakes/stats - Get handshake statistics for the user
 * SECURITY: Uses statsSimpleLimiter for user-specific handshake stats (40 requests per 10 minutes)
 */
router.get('/stats', 
  require('../middleware/rateLimiting').statsSimpleLimiter, // Use simple stats rate limiting
  trackSimpleStats, // Monitor statistics access patterns
  trackHandshakeSearchEvent, // Monitor search patterns
  async (req, res) => {
  try {
    const userId = getUserId(req);
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const handshakeService = ServiceFactory.create().getHandshakeService();
    
    const stats = await handshakeService.getUserHandshakeStats(userId);
    
    res.json({
      success: true,
      stats
    });

  } catch (error) {
    console.error('❌ Error getting handshake stats:', error);
    res.status(500).json({ 
      error: 'Failed to get handshake statistics', 
      code: 'GET_HANDSHAKE_STATS_ERROR'
    });
  }
});

module.exports = router;