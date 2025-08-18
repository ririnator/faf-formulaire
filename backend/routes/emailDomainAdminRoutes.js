const express = require('express');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtectionStrict } = require('../middleware/csrf');
const { apiLimiter } = require('../middleware/rateLimiting');
const { requireAdminAccess } = require('../middleware/hybridAuth');
const { smartEscape } = require('../middleware/validation');
const {
  emailConfig,
  getDomainBlockingStats,
  DISPOSABLE_DOMAINS,
  SUSPICIOUS_PATTERNS
} = require('../middleware/emailDomainValidation');
const SecureLogger = require('../utils/secureLogger');

// Apply body parser and security middleware
router.use(createAdminBodyParser());
router.use(requireAdminAccess);

// Validation error handler
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Données invalides',
      details: errors.array()
    });
  }
  next();
};

/**
 * GET /api/admin/email-domains/stats - Get email domain blocking statistics
 */
router.get('/stats', apiLimiter, async (req, res) => {
  try {
    const stats = getDomainBlockingStats();
    
    // Add recent activity if available
    const recentActivity = {
      blockedToday: 0, // Could be populated from logs
      blockedThisWeek: 0,
      blockedThisMonth: 0,
      topBlockedDomains: [], // Could be populated from logs
      lastUpdated: new Date().toISOString()
    };

    res.json({
      success: true,
      stats: {
        ...stats,
        recentActivity
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to get email domain stats', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des statistiques'
    });
  }
});

/**
 * GET /api/admin/email-domains/whitelist - Get whitelisted domains
 */
router.get('/whitelist', apiLimiter, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;
    
    const domains = Array.from(emailConfig.allowedDomains);
    const total = domains.length;
    const paginatedDomains = domains
      .sort()
      .slice(offset, offset + parseInt(limit));

    res.json({
      success: true,
      domains: paginatedDomains,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to get whitelisted domains', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération de la liste blanche'
    });
  }
});

/**
 * GET /api/admin/email-domains/blacklist - Get blacklisted domains
 */
router.get('/blacklist', apiLimiter, async (req, res) => {
  try {
    const { page = 1, limit = 50, type = 'all' } = req.query;
    const offset = (page - 1) * limit;
    
    let domains = Array.from(emailConfig.blockedDomains);
    
    // Filter by type if specified
    if (type === 'custom') {
      // Show only custom blocked domains (not disposable domains)
      domains = domains.filter(domain => !DISPOSABLE_DOMAINS.has(domain));
    } else if (type === 'disposable') {
      // Show only disposable domains
      domains = domains.filter(domain => DISPOSABLE_DOMAINS.has(domain));
    }
    
    const total = domains.length;
    const paginatedDomains = domains
      .sort()
      .slice(offset, offset + parseInt(limit));

    res.json({
      success: true,
      domains: paginatedDomains.map(domain => ({
        domain,
        type: DISPOSABLE_DOMAINS.has(domain) ? 'disposable' : 'custom',
        isRemovable: !DISPOSABLE_DOMAINS.has(domain) // Can't remove built-in disposable domains
      })),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to get blacklisted domains', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération de la liste noire'
    });
  }
});

/**
 * POST /api/admin/email-domains/whitelist - Add domain to whitelist
 */
router.post('/whitelist', 
  apiLimiter,
  csrfProtectionStrict(),
  [
    body('domain')
      .trim()
      .isLength({ min: 3, max: 253 })
      .matches(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/)
      .withMessage('Format de domaine invalide'),
    body('reason')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('La raison ne peut dépasser 500 caractères'),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const { domain, reason } = req.body;
    const sanitizedDomain = domain.toLowerCase().trim();
    const adminId = req.session?.userId || req.user?.id;

    // Check if domain is already whitelisted
    if (emailConfig.isDomainAllowed(sanitizedDomain)) {
      return res.status(409).json({
        success: false,
        error: 'Ce domaine est déjà dans la liste blanche'
      });
    }

    // Add to whitelist
    emailConfig.allowDomain(sanitizedDomain);
    
    // Remove from blacklist if present
    if (emailConfig.isDomainBlocked(sanitizedDomain)) {
      emailConfig.unblockDomain(sanitizedDomain);
    }

    // Log the action
    SecureLogger.logAudit('email_domain_whitelisted', adminId, {
      domain: sanitizedDomain,
      reason: reason ? smartEscape(reason) : null,
      action: 'add_to_whitelist'
    });

    res.json({
      success: true,
      message: `Domaine ${sanitizedDomain} ajouté à la liste blanche`,
      domain: sanitizedDomain
    });

  } catch (error) {
    SecureLogger.logError('Failed to add domain to whitelist', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de l\'ajout à la liste blanche'
    });
  }
});

/**
 * POST /api/admin/email-domains/blacklist - Add domain to blacklist
 */
router.post('/blacklist',
  apiLimiter,
  csrfProtectionStrict(),
  [
    body('domain')
      .trim()
      .isLength({ min: 3, max: 253 })
      .matches(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/)
      .withMessage('Format de domaine invalide'),
    body('reason')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('La raison ne peut dépasser 500 caractères'),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const { domain, reason } = req.body;
    const sanitizedDomain = domain.toLowerCase().trim();
    const adminId = req.session?.userId || req.user?.id;

    // Check if domain is already blacklisted
    if (emailConfig.isDomainBlocked(sanitizedDomain)) {
      return res.status(409).json({
        success: false,
        error: 'Ce domaine est déjà dans la liste noire'
      });
    }

    // Add to blacklist
    emailConfig.blockDomain(sanitizedDomain);
    
    // Remove from whitelist if present
    if (emailConfig.isDomainAllowed(sanitizedDomain)) {
      emailConfig.disallowDomain(sanitizedDomain);
    }

    // Log the action
    SecureLogger.logAudit('email_domain_blacklisted', adminId, {
      domain: sanitizedDomain,
      reason: reason ? smartEscape(reason) : null,
      action: 'add_to_blacklist'
    });

    res.json({
      success: true,
      message: `Domaine ${sanitizedDomain} ajouté à la liste noire`,
      domain: sanitizedDomain
    });

  } catch (error) {
    SecureLogger.logError('Failed to add domain to blacklist', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de l\'ajout à la liste noire'
    });
  }
});

/**
 * DELETE /api/admin/email-domains/whitelist/:domain - Remove domain from whitelist
 */
router.delete('/whitelist/:domain',
  apiLimiter,
  csrfProtectionStrict(),
  [
    param('domain')
      .trim()
      .isLength({ min: 3, max: 253 })
      .matches(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/)
      .withMessage('Format de domaine invalide'),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const domain = req.params.domain.toLowerCase().trim();
    const adminId = req.session?.userId || req.user?.id;

    // Check if domain is in whitelist
    if (!emailConfig.isDomainAllowed(domain)) {
      return res.status(404).json({
        success: false,
        error: 'Ce domaine n\'est pas dans la liste blanche'
      });
    }

    // Remove from whitelist
    emailConfig.disallowDomain(domain);

    // Log the action
    SecureLogger.logAudit('email_domain_whitelist_removed', adminId, {
      domain: domain,
      action: 'remove_from_whitelist'
    });

    res.json({
      success: true,
      message: `Domaine ${domain} retiré de la liste blanche`,
      domain: domain
    });

  } catch (error) {
    SecureLogger.logError('Failed to remove domain from whitelist', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la suppression de la liste blanche'
    });
  }
});

/**
 * DELETE /api/admin/email-domains/blacklist/:domain - Remove domain from blacklist
 */
router.delete('/blacklist/:domain',
  apiLimiter,
  csrfProtectionStrict(),
  [
    param('domain')
      .trim()
      .isLength({ min: 3, max: 253 })
      .matches(/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/)
      .withMessage('Format de domaine invalide'),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const domain = req.params.domain.toLowerCase().trim();
    const adminId = req.session?.userId || req.user?.id;

    // Check if domain is in blacklist
    if (!emailConfig.isDomainBlocked(domain)) {
      return res.status(404).json({
        success: false,
        error: 'Ce domaine n\'est pas dans la liste noire'
      });
    }

    // Prevent removal of built-in disposable domains
    if (DISPOSABLE_DOMAINS.has(domain)) {
      return res.status(403).json({
        success: false,
        error: 'Impossible de retirer un domaine de la liste des domaines jetables intégrés'
      });
    }

    // Remove from blacklist
    emailConfig.unblockDomain(domain);

    // Log the action
    SecureLogger.logAudit('email_domain_blacklist_removed', adminId, {
      domain: domain,
      action: 'remove_from_blacklist'
    });

    res.json({
      success: true,
      message: `Domaine ${domain} retiré de la liste noire`,
      domain: domain
    });

  } catch (error) {
    SecureLogger.logError('Failed to remove domain from blacklist', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la suppression de la liste noire'
    });
  }
});

/**
 * GET /api/admin/email-domains/config - Get current configuration
 */
router.get('/config', apiLimiter, async (req, res) => {
  try {
    res.json({
      success: true,
      config: {
        enableMXValidation: emailConfig.enableMXValidation,
        enableDisposableCheck: emailConfig.enableDisposableCheck,
        enableSuspiciousPatternCheck: emailConfig.enableSuspiciousPatternCheck,
        logBlockedAttempts: emailConfig.logBlockedAttempts,
        whitelistCount: emailConfig.allowedDomains.size,
        blacklistCount: emailConfig.blockedDomains.size,
        disposableDomainsCount: DISPOSABLE_DOMAINS.size,
        suspiciousPatternsCount: SUSPICIOUS_PATTERNS.length
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to get email domain config', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération de la configuration'
    });
  }
});

/**
 * PUT /api/admin/email-domains/config - Update configuration
 */
router.put('/config',
  apiLimiter,
  csrfProtectionStrict(),
  [
    body('enableMXValidation').optional().isBoolean(),
    body('enableDisposableCheck').optional().isBoolean(),
    body('enableSuspiciousPatternCheck').optional().isBoolean(),
    body('logBlockedAttempts').optional().isBoolean(),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const adminId = req.session?.userId || req.user?.id;
    const updates = {};

    // Update configuration settings
    if (req.body.enableMXValidation !== undefined) {
      emailConfig.enableMXValidation = req.body.enableMXValidation;
      updates.enableMXValidation = req.body.enableMXValidation;
    }
    
    if (req.body.enableDisposableCheck !== undefined) {
      emailConfig.enableDisposableCheck = req.body.enableDisposableCheck;
      updates.enableDisposableCheck = req.body.enableDisposableCheck;
    }
    
    if (req.body.enableSuspiciousPatternCheck !== undefined) {
      emailConfig.enableSuspiciousPatternCheck = req.body.enableSuspiciousPatternCheck;
      updates.enableSuspiciousPatternCheck = req.body.enableSuspiciousPatternCheck;
    }
    
    if (req.body.logBlockedAttempts !== undefined) {
      emailConfig.logBlockedAttempts = req.body.logBlockedAttempts;
      updates.logBlockedAttempts = req.body.logBlockedAttempts;
    }

    // Log the configuration change
    SecureLogger.logAudit('email_domain_config_updated', adminId, {
      updates: updates,
      action: 'update_config'
    });

    res.json({
      success: true,
      message: 'Configuration mise à jour avec succès',
      config: {
        enableMXValidation: emailConfig.enableMXValidation,
        enableDisposableCheck: emailConfig.enableDisposableCheck,
        enableSuspiciousPatternCheck: emailConfig.enableSuspiciousPatternCheck,
        logBlockedAttempts: emailConfig.logBlockedAttempts
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to update email domain config', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la mise à jour de la configuration'
    });
  }
});

/**
 * POST /api/admin/email-domains/test - Test email domain validation
 */
router.post('/test',
  apiLimiter,
  csrfProtectionStrict(),
  [
    body('email')
      .trim()
      .isEmail()
      .withMessage('Format d\'email invalide'),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const { email } = req.body;
    const { validateEmailDomain } = require('../middleware/emailDomainValidation');
    
    // Test with different validation options
    const fullValidation = await validateEmailDomain(email);
    const withoutMX = await validateEmailDomain(email, { skipMXValidation: true });
    const withoutDNS = await validateEmailDomain(email, { 
      skipMXValidation: true, 
      skipDomainExistenceCheck: true 
    });

    res.json({
      success: true,
      email: email,
      results: {
        fullValidation: {
          isValid: fullValidation.isValid,
          reason: fullValidation.reason,
          message: fullValidation.message
        },
        withoutMXValidation: {
          isValid: withoutMX.isValid,
          reason: withoutMX.reason,
          message: withoutMX.message
        },
        basicValidation: {
          isValid: withoutDNS.isValid,
          reason: withoutDNS.reason,
          message: withoutDNS.message
        }
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to test email domain validation', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors du test de validation'
    });
  }
});

module.exports = router;