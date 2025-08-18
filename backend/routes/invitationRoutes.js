const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
const router = express.Router();

const Invitation = require('../models/Invitation');
const Submission = require('../models/Submission');
const User = require('../models/User');
const Contact = require('../models/Contact');
const ServiceFactory = require('../services/serviceFactory');
const { trackSimpleStats } = require('../middleware/statisticsMonitoring');
const { validateResponseStrict, handleValidationErrors, sanitizeResponse, smartEscape, validatePhotoUrl } = require('../middleware/validation');
const { createFormBodyParser, createStandardBodyParser, createAdminBodyParser } = require('../middleware/bodyParser');
const { detectAuthMethod, requireUserAuth, enrichUserData } = require('../middleware/hybridAuth');
const { csrfProtection, csrfProtectionStrict, csrfProtectionPublic } = require('../middleware/csrf');
const { authLimiters } = require('../middleware/authRateLimit');
const { HTTP_STATUS } = require('../constants');
const { 
  preventParameterPollution,
  securityLogger,
  enhanceTokenValidation,
  antiAutomation,
  validateContentType
} = require('../middleware/enhancedSecurity');

// ===== RATE LIMITERS =====

// Middleware to bypass rate limiting in test environment
const bypassInTests = (middleware) => {
  return (req, res, next) => {
    if (process.env.NODE_ENV === 'test' || process.env.DISABLE_RATE_LIMITING === 'true') {
      return next();
    }
    return middleware(req, res, next);
  };
};

// Rate limiter for authenticated API endpoints
const apiLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60, // Reduced from 100 to 60 requests per window per IP
  message: { 
    success: false,
    error: 'Trop de requêtes. Réessayez dans quelques minutes.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Enhanced security logging
  handler: (req, res) => {
    console.warn('API rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      path: req.path,
      method: req.method,
      userId: req.user?.id || req.session?.userId || 'anonymous',
      timestamp: new Date().toISOString()
    });
    res.status(429).json({
      success: false,
      error: 'Trop de requêtes. Réessayez dans quelques minutes.',
      retryAfter: 900 // 15 minutes
    });
  }
});

// Stricter rate limiter for public token endpoints
const publicTokenLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Reduced from 20 to 15 requests per window per IP
  message: { 
    success: false,
    error: 'Trop de tentatives d\'accès. Réessayez dans 15 minutes.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Enhanced security for public token access
  keyGenerator: (req) => {
    // Use IP + first part of token for better rate limiting granularity
    const tokenPrefix = req.params.token ? req.params.token.substring(0, 8) : 'no-token';
    return `${req.ip}:${tokenPrefix}:${req.get('user-agent') || 'unknown'}`;
  },
  handler: (req, res) => {
    console.warn('Public token rate limit exceeded', {
      ip: req.ip,
      tokenPrefix: req.params.token ? req.params.token.substring(0, 8) : 'no-token',
      userAgent: req.get('user-agent'),
      path: req.path,
      timestamp: new Date().toISOString()
    });
    res.status(429).json({
      success: false,
      error: 'Trop de tentatives d\'accès. Réessayez dans 15 minutes.',
      retryAfter: 900 // 15 minutes
    });
  }
});

// Very strict limiter for token validation to prevent brute force
const tokenValidationLimiterRaw = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // Reduced to 5 attempts per window per IP for enhanced security
  message: { 
    success: false,
    error: 'Trop de tentatives de validation. Réessayez dans quelques minutes.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Enhanced security: skip successful requests to only count failures
  skipSuccessfulRequests: true,
  // Use IP + User-Agent for better fingerprinting
  keyGenerator: (req) => `${req.ip}:${req.get('user-agent') || 'unknown'}`,
  // Custom handler for security logging
  handler: (req, res) => {
    console.warn('Token validation rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      path: req.path,
      timestamp: new Date().toISOString()
    });
    res.status(429).json({
      success: false,
      error: 'Trop de tentatives de validation. Réessayez dans quelques minutes.',
      retryAfter: 300 // 5 minutes
    });
  }
});

// Apply test bypass to all limiters
const apiLimiter = bypassInTests(apiLimiterRaw);
const publicTokenLimiter = bypassInTests(publicTokenLimiterRaw);
const tokenValidationLimiter = bypassInTests(tokenValidationLimiterRaw);

// ===== UTILITY FUNCTIONS =====

function getSecurityContext(req) {
  return {
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('User-Agent') || '',
    referrer: req.get('Referer') || ''
  };
}

// Secure user ID extraction helper
function getUserId(req) {
  // Priority: currentUser.id (from enrichUserData middleware) > user.id > session.userId
  const userId = req.currentUser?.id || req.user?.id || req.session?.userId;
  // Convert ObjectId to string if necessary
  return userId ? userId.toString() : null;
}

function validateSubmissionData(responses) {
  if (!Array.isArray(responses) || responses.length === 0) {
    throw new Error('Réponses manquantes ou invalides');
  }

  if (responses.length > 20) {
    throw new Error('Maximum 20 réponses autorisées');
  }

  for (const response of responses) {
    if (!response.questionId || typeof response.questionId !== 'string') {
      throw new Error('questionId manquant ou invalide');
    }
    
    if (!response.type || !['text', 'photo', 'radio'].includes(response.type)) {
      throw new Error('Type de réponse invalide');
    }

    if (response.answer && response.answer.length > 10000) {
      throw new Error('Réponse trop longue (maximum 10000 caractères)');
    }

    if (response.photoCaption && response.photoCaption.length > 500) {
      throw new Error('Légende photo trop longue (maximum 500 caractères)');
    }
  }

  return true;
}

// Apply body parser middleware for authenticated routes only
// Public routes will use specific body parsers

// ===== VALIDATION MIDDLEWARE =====

const validateInvitationSend = [
  body('contactIds')
    .optional()
    .isArray({ max: 50 })
    .withMessage('Maximum 50 contacts par envoi'),
  body('contactIds.*')
    .isMongoId()
    .withMessage('ID de contact invalide'),
  body('emails')
    .optional()
    .isArray({ max: 50 })
    .withMessage('Maximum 50 emails par envoi'),
  body('emails.*')
    .isEmail()
    .normalizeEmail()
    .withMessage('Format email invalide'),
  body('month')
    .matches(/^\d{4}-\d{2}$/)
    .withMessage('Format mois invalide (YYYY-MM)'),
  body('customMessage')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Message personnalisé maximum 500 caractères')
    .customSanitizer(value => value ? smartEscape(value.trim()) : ''),
  body('expirationDays')
    .optional()
    .isInt({ min: 1, max: 90 })
    .withMessage('Expiration entre 1 et 90 jours'),
  body('antiTransfer')
    .optional()
    .isBoolean()
    .withMessage('antiTransfer doit être un booléen')
];

const validateTokenParam = [
  param('token')
    .isLength({ min: 64, max: 64 })
    .matches(/^[a-f0-9]{64}$/)
    .withMessage('Token invalide')
];

const validateShortCode = [
  body('shortCode')
    .isLength({ min: 6, max: 8 })
    .matches(/^[A-Z0-9]+$/)
    .withMessage('Code invalide')
];

const validateAntiTransferCode = [
  body('verificationCode')
    .isLength({ min: 4, max: 16 })
    .matches(/^[A-Z0-9]+$/)
    .withMessage('Code de vérification invalide')
];

// Legacy validation rules (keeping for backward compatibility)
const createInvitationValidation = [
  body('toEmail')
    .isEmail()
    .normalizeEmail()
    .withMessage('Email valide requis'),
  
  body('month')
    .matches(/^\d{4}-\d{2}$/)
    .withMessage('Format de mois invalide (YYYY-MM)'),
  
  body('type')
    .optional()
    .isIn(['external', 'internal', 'anonymous'])
    .withMessage('Type d\'invitation invalide'),
  
  body('customExpiration')
    .optional()
    .isISO8601()
    .withMessage('Date d\'expiration invalide')
];

const validateTokenValidation = [
  body('token')
    .notEmpty()
    .isLength({ min: 16 })
    .withMessage('Token invalide')
];

// ===== AUTHENTICATED API ROUTES =====

/**
 * POST /api/invitations - Créer une nouvelle invitation (Legacy)
 */
router.post('/', 
  apiLimiter, 
  createAdminBodyParser(),
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  authLimiters.createInvitation, 
  csrfProtectionStrict(), // Use strict CSRF for authenticated users
  createInvitationValidation, 
  async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: 'Données invalides',
        details: errors.array()
      });
    }

    const userId = getUserId(req);
    
    if (!userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Authentification requise', 
        code: 'AUTH_REQUIRED' 
      });
    }

    const { toEmail, month, type, metadata, customExpiration } = req.body;
    
    const invitationService = ServiceFactory.create().getInvitationService();
    
    const securityContext = {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      referrer: req.get('Referer')
    };

    const invitationData = {
      fromUserId: userId,
      toEmail,
      month,
      type,
      metadata: metadata || {},
      customExpiration
    };

    const result = await invitationService.createInvitation(invitationData, securityContext);
    
    res.status(201).json({
      success: true,
      invitation: result.invitation,
      tokens: result.tokens,
      message: 'Invitation créée avec succès'
    });

  } catch (error) {
    console.error('❌ Error creating invitation:', error);
    
    if (error.message.includes('déjà une invitation')) {
      return res.status(HTTP_STATUS.CONFLICT).json({ 
        error: 'Invitation already exists for this user', 
        code: 'DUPLICATE_INVITATION' 
      });
    }
    
    res.status(HTTP_STATUS.BAD_REQUEST).json({ 
      error: 'Erreur lors de la création de l\'invitation', 
      code: 'CREATE_INVITATION_ERROR' 
    });
  }
});

/**
 * GET /api/invitations - Liste des invitations de l'utilisateur (Legacy)
 */
router.get('/', 
  apiLimiter,
  detectAuthMethod,
  enrichUserData,
  async (req, res) => {
  try {
    const userId = getUserId(req);
    
    if (!userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Authentification requise', 
        code: 'AUTH_REQUIRED' 
      });
    }

    const { 
      page = 1, 
      limit = 20, 
      status = '', 
      type = '', 
      month = '' 
    } = req.query;

    const invitationService = ServiceFactory.create().getInvitationService();
    
    const options = {
      page: parseInt(page),
      limit: Math.min(100, parseInt(limit)),
      status: status.trim(),
      type: type.trim(),
      month: month.trim()
    };

    const result = await invitationService.getInvitations(userId, options);
    
    res.json({
      success: true,
      invitations: result.invitations,
      pagination: result.pagination,
      summary: result.summary
    });

  } catch (error) {
    console.error('❌ Error getting invitations:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      error: 'Erreur lors de la récupération des invitations', 
      code: 'GET_INVITATIONS_ERROR' 
    });
  }
});

/**
 * GET /api/invitations/validate/:token - Valider un token d'invitation (Legacy)
 */
router.get('/validate/:token', 
  tokenValidationLimiter,
  async (req, res) => {
  try {
    const { token } = req.params;
    
    if (!token) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: 'Token requis', 
        code: 'VALIDATION_ERROR' 
      });
    }

    const invitationService = ServiceFactory.create().getInvitationService();
    
    const securityContext = {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    };

    const result = await invitationService.validateInvitationToken(token, securityContext);
    
    if (!result.valid) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({
        valid: false,
        error: result.error,
        code: 'INVALID_TOKEN'
      });
    }

    res.json({
      valid: true,
      invitation: result.invitation,
      metadata: result.metadata
    });

  } catch (error) {
    console.error('❌ Error validating invitation token:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      error: 'Erreur lors de la validation du token', 
      code: 'VALIDATE_TOKEN_ERROR' 
    });
  }
});

/**
 * POST /api/invitations/:id/cancel - Annuler une invitation (Legacy)
 */
router.post('/:id/cancel', 
  apiLimiter,
  createAdminBodyParser(),
  detectAuthMethod,
  enrichUserData,
  csrfProtectionStrict(), // Use strict CSRF for authenticated users
  async (req, res) => {
  try {
    const userId = getUserId(req);
    const invitationId = req.params.id;
    
    if (!userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Authentification requise', 
        code: 'AUTH_REQUIRED' 
      });
    }

    const { reason } = req.body;

    const invitationService = ServiceFactory.create().getInvitationService();
    
    const result = await invitationService.cancelInvitation(invitationId, userId, reason);
    
    if (!result.success) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ 
        error: 'Invitation non trouvée ou non autorisée', 
        code: 'NOT_FOUND' 
      });
    }

    res.json({
      success: true,
      invitation: result.invitation,
      message: 'Invitation annulée avec succès'
    });

  } catch (error) {
    console.error('❌ Error canceling invitation:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      error: 'Erreur lors de l\'annulation de l\'invitation', 
      code: 'CANCEL_INVITATION_ERROR' 
    });
  }
});

/**
 * POST /api/invitations/:id/extend - Prolonger une invitation (Legacy)
 */
router.post('/:id/extend', 
  apiLimiter,
  createAdminBodyParser(),
  detectAuthMethod,
  enrichUserData,
  csrfProtectionStrict(), // Use strict CSRF for authenticated users
  async (req, res) => {
  try {
    const userId = getUserId(req);
    const invitationId = req.params.id;
    
    if (!userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Authentification requise', 
        code: 'AUTH_REQUIRED' 
      });
    }

    const { additionalHours = 24 } = req.body;

    const invitationService = ServiceFactory.create().getInvitationService();
    
    const result = await invitationService.extendInvitation(invitationId, userId, additionalHours);
    
    if (!result.success) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ 
        error: 'Invitation non trouvée ou non autorisée', 
        code: 'NOT_FOUND' 
      });
    }

    res.json({
      success: true,
      invitation: result.invitation,
      newExpiration: result.newExpiration,
      message: `Invitation prolongée de ${additionalHours} heures`
    });

  } catch (error) {
    console.error('❌ Error extending invitation:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      error: 'Erreur lors de la prolongation de l\'invitation', 
      code: 'EXTEND_INVITATION_ERROR' 
    });
  }
});

/**
 * GET /api/invitations/stats - Statistiques des invitations (Legacy)
 * SECURITY: Uses statsSimpleLimiter for basic invitation statistics (40 requests per 10 minutes)
 */
router.get('/stats', 
  require('../middleware/rateLimiting').statsSimpleLimiter, // Use simple stats rate limiting
  trackSimpleStats, // Monitor statistics access patterns
  detectAuthMethod,
  enrichUserData,
  async (req, res) => {
  try {
    const userId = getUserId(req);
    
    if (!userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Authentification requise', 
        code: 'AUTH_REQUIRED' 
      });
    }

    const { period = '30d' } = req.query;

    const invitationService = ServiceFactory.create().getInvitationService();
    
    const stats = await invitationService.getInvitationStats(userId, period);
    
    res.json({
      success: true,
      stats,
      period
    });

  } catch (error) {
    console.error('❌ Error getting invitation stats:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      error: 'Erreur lors de la récupération des statistiques', 
      code: 'GET_STATS_ERROR' 
    });
  }
});

/**
 * POST /api/invitations/bulk-send - Envoi en masse d'invitations (Legacy)
 */
router.post('/bulk-send', 
  apiLimiter,
  createAdminBodyParser(),
  detectAuthMethod,
  enrichUserData,
  authLimiters.bulkInvitations, 
  csrfProtectionStrict(), // Use strict CSRF for authenticated users
  [
  body('emails')
    .isArray({ min: 1, max: 50 })
    .withMessage('Liste d\'emails requise (1-50 emails)'),
  
  body('emails.*')
    .isEmail()
    .normalizeEmail()
    .withMessage('Emails valides requis'),
  
  body('month')
    .matches(/^\d{4}-\d{2}$/)
    .withMessage('Format de mois invalide (YYYY-MM)')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: 'Données invalides',
        details: errors.array()
      });
    }

    const userId = getUserId(req);
    
    if (!userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Authentification requise', 
        code: 'AUTH_REQUIRED' 
      });
    }

    const { emails, month, type = 'external', metadata = {} } = req.body;

    const invitationService = ServiceFactory.create().getInvitationService();
    
    const securityContext = {
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      referrer: req.get('Referer')
    };

    const result = await invitationService.bulkCreateInvitations({
      fromUserId: userId,
      emails,
      month,
      type,
      metadata
    }, securityContext);

    res.json({
      success: true,
      created: result.created,
      errors: result.errors,
      duplicates: result.duplicates,
      total: emails.length,
      message: `${result.created.length} invitations créées sur ${emails.length}`
    });

  } catch (error) {
    console.error('❌ Error bulk creating invitations:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      error: 'Erreur lors de la création en masse des invitations', 
      code: 'BULK_CREATE_ERROR' 
    });
  }
});

/**
 * GET /api/invitations/:id - Obtenir une invitation spécifique (Legacy)
 */
router.get('/:id', 
  apiLimiter,
  detectAuthMethod,
  enrichUserData,
  async (req, res) => {
  try {
    const userId = getUserId(req);
    const invitationId = req.params.id;
    
    if (!userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Authentification requise', 
        code: 'AUTH_REQUIRED' 
      });
    }

    const invitationService = ServiceFactory.create().getInvitationService();
    
    const invitation = await invitationService.getInvitationById(invitationId, userId);
    
    if (!invitation) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ 
        error: 'Invitation non trouvée', 
        code: 'NOT_FOUND' 
      });
    }

    res.json({
      success: true,
      invitation
    });

  } catch (error) {
    console.error('❌ Error getting invitation:', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      error: 'Erreur lors de la récupération de l\'invitation', 
      code: 'GET_INVITATION_ERROR' 
    });
  }
});

// ===== ENHANCED AUTHENTICATED ROUTES =====

/**
 * GET /api/invitations/list - Enhanced list with filtering and pagination
 * Requires user authentication
 */
router.get('/list',
  apiLimiter,
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Page doit être un entier positif'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limite entre 1 et 100'),
    query('status').optional().isIn(['queued', 'sent', 'opened', 'started', 'submitted', 'expired', 'cancelled']),
    query('month').optional().matches(/^\d{4}-\d{2}$/),
    query('type').optional().isIn(['user', 'external']),
    query('search').optional().trim().isLength({ max: 100 })
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const invitationService = ServiceFactory.create().getInvitationService();
      const userId = req.currentUser.id;
      
      const filters = {
        status: req.query.status,
        month: req.query.month,
        type: req.query.type,
        search: req.query.search,
        includeExpired: req.query.includeExpired === 'true'
      };

      const pagination = {
        page: parseInt(req.query.page) || 1,
        limit: parseInt(req.query.limit) || 20,
        sortBy: req.query.sortBy || 'createdAt',
        sortOrder: req.query.sortOrder || 'desc'
      };

      const result = await invitationService.getInvitations(userId, filters, pagination);

      res.json({
        success: true,
        data: result
      });

    } catch (error) {
      console.error('Error fetching enhanced invitations:', error);
      res.status(500).json({
        success: false,
        error: 'Erreur lors de la récupération des invitations'
      });
    }
  }
);

/**
 * POST /api/invitations/send - Enhanced send with contact integration
 * Requires user authentication
 */
router.post('/send',
  apiLimiter,
  createStandardBodyParser(),
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  validateInvitationSend,
  handleValidationErrors,
  async (req, res) => {
    try {
      const invitationService = ServiceFactory.create().getInvitationService();
      const userId = req.currentUser.id;
      const securityContext = getSecurityContext(req);
      
      const {
        contactIds = [],
        emails = [],
        month,
        customMessage = '',
        expirationDays = 60,
        antiTransfer = false
      } = req.body;

      if (contactIds.length === 0 && emails.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'Au moins un contact ou email requis'
        });
      }

      const results = {
        sent: [],
        errors: [],
        duplicates: []
      };

      // Process contact IDs
      if (contactIds.length > 0) {
        const contacts = await Contact.find({
          _id: { $in: contactIds },
          ownerId: userId
        });

        for (const contact of contacts) {
          try {
            const customExpiration = expirationDays !== 60 ? 
              new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000) : null;

            const invitation = await invitationService.createInvitation({
              fromUserId: userId,
              toEmail: contact.email,
              month,
              metadata: {
                customMessage: customMessage || '',
                contactId: contact._id,
                antiTransferEnabled: antiTransfer
              },
              customExpiration
            }, securityContext);

            results.sent.push({
              email: contact.email,
              invitationId: invitation._id,
              token: invitation.token
            });

          } catch (error) {
            if (error.message.includes('déjà envoyée')) {
              results.duplicates.push({
                email: contact.email,
                reason: 'Invitation déjà envoyée'
              });
            } else {
              results.errors.push({
                email: contact.email,
                error: 'Failed to create invitation'
              });
            }
          }
        }
      }

      // Process direct emails
      for (const email of emails) {
        try {
          const customExpiration = expirationDays !== 60 ? 
            new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000) : null;

          const invitation = await invitationService.createInvitation({
            fromUserId: userId,
            toEmail: email,
            month,
            metadata: {
              customMessage: customMessage || '',
              antiTransferEnabled: antiTransfer
            },
            customExpiration
          }, securityContext);

          results.sent.push({
            email: email,
            invitationId: invitation._id,
            token: invitation.token
          });

        } catch (error) {
          if (error.message.includes('déjà envoyée')) {
            results.duplicates.push({
              email: email,
              reason: 'Invitation déjà envoyée'
            });
          } else {
            results.errors.push({
              email: email,
              error: 'Failed to create invitation'
            });
          }
        }
      }

      res.status(201).json({
        success: true,
        message: `${results.sent.length} invitation(s) envoyée(s)`,
        data: results
      });

    } catch (error) {
      console.error('Error sending enhanced invitations:', error);
      res.status(500).json({
        success: false,
        error: 'Erreur lors de l\'envoi des invitations'
      });
    }
  }
);

/**
 * POST /api/invitations/reminder - Send reminder for pending invitation
 * Requires user authentication and ownership
 */
router.post('/reminder',
  apiLimiter,
  createStandardBodyParser(),
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  [
    body('invitationId').isMongoId().withMessage('ID d\'invitation invalide'),
    body('type').isIn(['first', 'second', 'final']).withMessage('Type de relance invalide')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const { invitationId, type } = req.body;
      const userId = req.currentUser.id;

      const invitation = await Invitation.findById(invitationId);
      
      if (!invitation) {
        return res.status(404).json({
          success: false,
          error: 'Invitation non trouvée'
        });
      }

      // Check authorization
      if (invitation.fromUserId.toString() !== userId) {
        return res.status(403).json({
          success: false,
          error: 'Non autorisé pour cette invitation'
        });
      }

      // Check if reminder can be sent
      if (!invitation.canSendReminder(type)) {
        return res.status(400).json({
          success: false,
          error: 'Relance déjà envoyée ou invitation expirée'
        });
      }

      // Add reminder to invitation
      invitation.reminders.push({
        type: type,
        sentAt: new Date()
      });

      await invitation.save();

      res.json({
        success: true,
        message: 'Relance envoyée avec succès',
        data: {
          invitationId: invitation._id,
          reminderType: type,
          totalReminders: invitation.reminders.length
        }
      });

    } catch (error) {
      console.error('Error sending reminder:', error);
      res.status(500).json({
        success: false,
        error: 'Erreur lors de l\'envoi de la relance'
      });
    }
  }
);

/**
 * DELETE /api/invitations/cancel/:id - Cancel/revoke an invitation
 * Requires user authentication and ownership
 */
router.delete('/cancel/:id',
  apiLimiter,
  createStandardBodyParser(),
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  [
    param('id').isMongoId().withMessage('ID d\'invitation invalide'),
    body('reason').optional().trim().isLength({ max: 200 }).withMessage('Raison maximum 200 caractères')
  ],
  handleValidationErrors,
  async (req, res) => {
    try {
      const invitationService = ServiceFactory.create().getInvitationService();
      const invitationId = req.params.id;
      const userId = req.currentUser.id;
      const reason = req.body.reason || 'user_cancelled';

      const cancelledInvitation = await invitationService.cancelInvitation(
        invitationId, 
        userId, 
        reason
      );

      res.json({
        success: true,
        message: 'Invitation annulée avec succès',
        data: cancelledInvitation
      });

    } catch (error) {
      console.error('Error cancelling invitation:', error);
      
      if (error.message.includes('Non autorisé')) {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }
      
      if (error.message.includes('non trouvée')) {
        return res.status(404).json({
          success: false,
          error: 'Invitation not found'
        });
      }

      res.status(500).json({
        success: false,
        error: 'Erreur lors de l\'annulation'
      });
    }
  }
);

// ===== PUBLIC TOKEN ROUTES =====

/**
 * GET /api/invitations/public/:token - Get invitation details without authentication
 * Uses token-based access with security checks
 */
router.get('/public/:token',
  publicTokenLimiter,
  securityLogger,
  enhanceTokenValidation,
  antiAutomation(),
  preventParameterPollution(),
  validateTokenParam,
  handleValidationErrors,
  async (req, res) => {
    try {
      const invitationService = ServiceFactory.create().getInvitationService();
      const token = req.params.token;
      const securityContext = getSecurityContext(req);

      const validation = await invitationService.validateInvitationToken(token, securityContext);

      if (!validation.valid) {
        return res.status(400).json({
          success: false,
          error: validation.message,
          reason: validation.reason,
          securityRisk: validation.securityRisk
        });
      }

      const invitation = validation.invitation;
      
      // Return safe invitation data for public access
      res.json({
        success: true,
        data: {
          id: invitation._id,
          month: invitation.month,
          fromUser: invitation.fromUserId ? {
            username: invitation.fromUserId.username
          } : null,
          type: invitation.type,
          status: invitation.status,
          expiresAt: invitation.expiresAt,
          customMessage: invitation.metadata?.customMessage,
          remaining: validation.remaining,
          securityLevel: validation.securityLevel,
          antiTransferEnabled: !!invitation.metadata?.antiTransferEnabled
        }
      });

    } catch (error) {
      console.error('Error validating public token:', error);
      res.status(500).json({
        success: false,
        error: 'Erreur de validation du token'
      });
    }
  }
);

/**
 * GET /api/invitations/public/:token/form - Get form with sender's submission pre-filled
 * Provides 1-vs-1 comparison functionality
 */
router.get('/public/:token/form',
  publicTokenLimiter,
  validateTokenParam,
  handleValidationErrors,
  async (req, res) => {
    try {
      const invitationService = ServiceFactory.create().getInvitationService();
      const token = req.params.token;
      const securityContext = getSecurityContext(req);

      const validation = await invitationService.validateInvitationToken(token, securityContext);

      if (!validation.valid) {
        return res.status(400).json({
          success: false,
          error: validation.message,
          reason: validation.reason
        });
      }

      const invitation = validation.invitation;

      // Mark invitation as started if not already
      if (['sent', 'opened'].includes(invitation.status)) {
        await invitationService.markInvitationStarted(token, securityContext);
      }

      // Get sender's submission for pre-filling (if exists)
      let senderSubmission = null;
      if (invitation.fromUserId) {
        senderSubmission = await Submission.findOne({
          userId: invitation.fromUserId._id,
          month: invitation.month
        }).select('responses freeText');
      }

      res.json({
        success: true,
        data: {
          invitation: {
            id: invitation._id,
            month: invitation.month,
            fromUser: invitation.fromUserId ? {
              username: invitation.fromUserId.username
            } : null,
            customMessage: invitation.metadata?.customMessage
          },
          senderSubmission: senderSubmission ? senderSubmission.getPublicData() : null,
          formQuestions: [], // This would be populated by form service
          antiTransferRequired: !!invitation.metadata?.antiTransferEnabled
        }
      });

    } catch (error) {
      console.error('Error getting form data:', error);
      res.status(500).json({
        success: false,
        error: 'Erreur lors du chargement du formulaire'
      });
    }
  }
);

/**
 * POST /api/invitations/public/:token/submit - Submit response via token
 * Handles external user submissions without authentication
 */
router.post('/public/:token/submit',
  publicTokenLimiter,
  securityLogger,
  enhanceTokenValidation,
  antiAutomation(),
  validateContentType(['application/json']),
  preventParameterPollution(),
  createFormBodyParser(), // 2MB limit for form data
  csrfProtectionPublic(), // Public route CSRF protection
  validateTokenParam,
  [
    body('responses').isArray({ min: 1, max: 20 }).withMessage('1 à 20 réponses requises'),
    body('responses.*.questionId').notEmpty().withMessage('questionId requis'),
    body('responses.*.type').isIn(['text', 'photo', 'radio']).withMessage('Type invalide'),
    body('responses.*.answer').optional().isLength({ max: 10000 }).withMessage('Réponse trop longue'),
    body('responses.*.photoCaption').optional().isLength({ max: 500 }).withMessage('Légende trop longue'),
    body('freeText').optional().isLength({ max: 5000 }).withMessage('Texte libre trop long'),
    body('verificationCode').optional().isLength({ min: 4, max: 16 }).withMessage('Code de vérification invalide'),
    // Honeypot field
    body('website').optional().isEmpty().withMessage('Tentative de spam détectée')
  ],
  handleValidationErrors,
  sanitizeResponse,
  async (req, res) => {
    try {
      const invitationService = ServiceFactory.create().getInvitationService();
      const token = req.params.token;
      const securityContext = getSecurityContext(req);
      
      const { responses, freeText = '', verificationCode } = req.body;

      // Validate invitation token
      const validation = await invitationService.validateInvitationToken(token, securityContext);

      if (!validation.valid) {
        return res.status(400).json({
          success: false,
          error: validation.message,
          reason: validation.reason
        });
      }

      const invitation = validation.invitation;

      // Check if anti-transfer verification is required
      if (invitation.metadata?.antiTransferEnabled && !verificationCode) {
        return res.status(400).json({
          success: false,
          error: 'Code de vérification requis',
          requiresVerification: true
        });
      }

      // Validate anti-transfer code if provided
      if (verificationCode && invitation.metadata?.antiTransferCode) {
        const expectedCode = invitation.metadata.antiTransferCode;
        
        // Add constant-time delay BEFORE comparison to prevent timing attacks
        const baseDelay = 100;
        const randomDelay = Math.random() * 50;
        
        // Perform the comparison
        let isValid = false;
        try {
          // Ensure both buffers are same length for constant-time comparison
          const providedBuffer = Buffer.from(verificationCode.toUpperCase().padEnd(6, '0'));
          const expectedBuffer = Buffer.from(expectedCode.toUpperCase().padEnd(6, '0'));
          isValid = crypto.timingSafeEqual(providedBuffer, expectedBuffer);
        } catch (err) {
          // Buffer length mismatch or other error
          isValid = false;
        }
        
        // Always wait the same amount of time regardless of result
        await new Promise(resolve => setTimeout(resolve, baseDelay + randomDelay));
        
        if (!isValid) {
          return res.status(400).json({
            success: false,
            error: 'Code de vérification incorrect'
          });
        }
      }

      // Validate submission data
      validateSubmissionData(responses);

      // Create user account if external invitation and email provided
      let submissionUserId = invitation.toUserId?._id;
      
      if (!submissionUserId && invitation.type === 'external') {
        // Create temporary user account for external submission
        const tempUser = new User({
          username: `temp_${Date.now()}`,
          email: invitation.toEmail,
          password: crypto.randomBytes(32).toString('hex'), // Random password
          role: 'user',
          metadata: {
            isActive: false, // Temporary account
            emailVerified: false,
            isTemporary: true,
            createdViaInvitation: invitation._id
          }
        });
        
        await tempUser.save();
        submissionUserId = tempUser._id;
        
        // Update invitation with created user
        invitation.toUserId = submissionUserId;
        invitation.type = 'user';
        await invitation.save();
      }

      // Create submission
      const submission = new Submission({
        userId: submissionUserId,
        month: invitation.month,
        responses: responses.map(r => {
          const response = {
            questionId: r.questionId,
            type: r.type,
            answer: smartEscape(r.answer || ''),
            photoCaption: smartEscape(r.photoCaption || '')
          };
          
          // Apply enhanced photo URL validation
          if (r.photoUrl) {
            const photoValidation = validatePhotoUrl(r.photoUrl);
            if (photoValidation.isValid) {
              response.photoUrl = photoValidation.sanitized;
            } else {
              // Log security event and remove invalid photo URL
              console.warn('🔒 Invalid photo URL removed from invitation submission:', {
                reason: photoValidation.reason,
                originalUrl: r.photoUrl.substring(0, 100),
                invitationToken: token
              });
              // Don't include photoUrl in response
            }
          }
          
          return response;
        }),
        freeText: smartEscape(freeText),
        formVersion: 'v2_invitation'
      });

      await submission.save();

      // Mark invitation as submitted
      await invitationService.markInvitationSubmitted(
        token, 
        submission._id, 
        securityContext
      );

      res.status(201).json({
        success: true,
        message: 'Réponse enregistrée avec succès !',
        data: {
          submissionId: submission._id,
          completionRate: submission.completionRate,
          month: submission.month
        }
      });

    } catch (error) {
      console.error('Error submitting via token:', error);
      
      if (error.code === 11000) {
        return res.status(409).json({
          success: false,
          error: 'Une réponse existe déjà pour cette période'
        });
      }

      res.status(500).json({
        success: false,
        error: 'Erreur lors de l\'enregistrement'
      });
    }
  }
);

/**
 * POST /api/invitations/public/:token/verify - Verify anti-transfer code
 * Validates security codes without submitting the form
 */
router.post('/public/:token/verify',
  tokenValidationLimiter,
  securityLogger,
  enhanceTokenValidation,
  antiAutomation(),
  validateContentType(['application/json']),
  preventParameterPollution(),
  createStandardBodyParser(),
  csrfProtectionPublic(), // Public route CSRF protection
  validateTokenParam,
  validateAntiTransferCode,
  handleValidationErrors,
  async (req, res) => {
    try {
      const invitationService = ServiceFactory.create().getInvitationService();
      const token = req.params.token;
      const { verificationCode } = req.body;
      const securityContext = getSecurityContext(req);

      const validation = await invitationService.validateInvitationToken(token, securityContext);

      if (!validation.valid) {
        return res.status(400).json({
          success: false,
          error: validation.message
        });
      }

      const invitation = validation.invitation;

      // Check if anti-transfer is enabled
      if (!invitation.metadata?.antiTransferEnabled) {
        return res.status(400).json({
          success: false,
          error: 'Vérification non requise pour cette invitation'
        });
      }

      // Validate the code
      const expectedCode = invitation.metadata.antiTransferCode;
      const isValid = crypto.timingSafeEqual(
        Buffer.from(verificationCode.toUpperCase()),
        Buffer.from(expectedCode.toUpperCase())
      );

      if (!isValid) {
        // Add constant-time delay to prevent timing attacks
        await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 50));
        return res.status(400).json({
          success: false,
          error: 'Code de vérification incorrect'
        });
      }

      res.json({
        success: true,
        message: 'Code de vérification valide',
        data: {
          verified: true,
          validUntil: new Date(Date.now() + 30 * 60 * 1000) // Valid for 30 minutes
        }
      });

    } catch (error) {
      console.error('Error verifying code:', error);
      res.status(500).json({
        success: false,
        error: 'Erreur de vérification'
      });
    }
  }
);

module.exports = router;