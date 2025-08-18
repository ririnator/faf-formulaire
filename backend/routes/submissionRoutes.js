// backend/routes/submissionRoutes.js

const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();

const Submission = require('../models/Submission');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Handshake = require('../models/Handshake');
const ServiceFactory = require('../services/serviceFactory');
const { trackComparison } = require('../middleware/statisticsMonitoring');
const { detectAuthMethod, requireUserAuth, enrichUserData } = require('../middleware/hybridAuth');
const { smartEscape, handleValidationErrors, isCloudinaryUrl, validatePhotoUrl } = require('../middleware/validation');
const { body, param, validationResult } = require('express-validator');
const { 
  formLimiter, 
  adminLimiter, 
  apiLimiter,
  searchAnalyticsLimiter 
} = require('../middleware/rateLimiting');
const searchMonitoringService = require('../services/searchMonitoringService');
const { createFormBodyParser } = require('../middleware/bodyParser');
const { csrfProtectionStrict } = require('../middleware/csrf');
const { 
  preventParameterPollution,
  securityLogger,
  antiAutomation,
  validateContentType
} = require('../middleware/enhancedSecurity');

// Validation helpers
const validateMonthFormat = [
  param('month')
    .matches(/^\d{4}-\d{2}$/)
    .withMessage('Format de mois invalide. Utilisez YYYY-MM')
];

const validateContactId = [
  param('contactId')
    .isMongoId()
    .withMessage('ID de contact invalide')
];

const validateSubmissionData = [
  body('responses')
    .isArray({ min: 1, max: 20 })
    .withMessage('Il faut entre 1 et 20 réponses'),
  
  body('responses.*.questionId')
    .trim()
    .notEmpty()
    .withMessage('ID de question requis'),
  
  body('responses.*.type')
    .isIn(['text', 'photo', 'radio'])
    .withMessage('Type de réponse invalide'),
  
  body('responses.*.answer')
    .optional()
    .trim()
    .isLength({ max: 10000 })
    .withMessage('Réponse trop longue (max 10000 caractères)'),
  
  body('responses.*.photoUrl')
    .optional()
    .trim()
    .custom((value) => {
      if (value) {
        const validation = validatePhotoUrl(value);
        if (!validation.isValid) {
          throw new Error(`URL photo invalide: ${validation.reason}`);
        }
      }
      return true;
    }),
  
  body('responses.*.photoCaption')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Légende photo trop longue (max 500 caractères)'),
  
  body('freeText')
    .optional()
    .trim()
    .isLength({ max: 5000 })
    .withMessage('Texte libre trop long (max 5000 caractères)'),
  
  body('website')
    .optional()
    .isEmpty()
    .withMessage('Champ honeypot détecté - tentative de spam')
];

// Middleware pour sanitiser les données de soumission
function sanitizeSubmissionData(req, res, next) {
  if (req.body.responses && Array.isArray(req.body.responses)) {
    req.body.responses = req.body.responses.map(response => {
      const sanitized = {
        questionId: response.questionId.trim(),
        type: response.type
      };

      if (response.answer) {
        sanitized.answer = smartEscape(response.answer.trim());
      }
      
      if (response.photoUrl) {
        const photoValidation = validatePhotoUrl(response.photoUrl);
        if (photoValidation.isValid) {
          sanitized.photoUrl = photoValidation.sanitized;
        } else {
          // Log security event and remove invalid photo URL
          console.warn('🔒 Invalid photo URL removed during sanitization:', {
            reason: photoValidation.reason,
            originalUrl: response.photoUrl.substring(0, 100)
          });
          // Don't include photoUrl in sanitized response
        }
      }
      
      if (response.photoCaption) {
        sanitized.photoCaption = smartEscape(response.photoCaption.trim());
      }

      return sanitized;
    });
  }

  if (req.body.freeText) {
    req.body.freeText = smartEscape(req.body.freeText.trim());
  }

  next();
}

// Secure user ID extraction helper
const getUserId = (req) => {
  // Priority: currentUser.id (from enrichUserData middleware) > user.id > session.userId
  const userId = req.currentUser?.id || req.user?.id || req.session?.userId;
  // Convert ObjectId to string if necessary
  return userId ? userId.toString() : null;
};

// Search monitoring middleware for submissions analytics
const trackSubmissionSearchEvent = (req, res, next) => {
  const originalSend = res.send;
  const startTime = Date.now();
  
  res.send = function(data) {
    const responseTime = Date.now() - startTime;
    
    // Parse response to get result count if possible
    let resultCount = 0;
    let success = res.statusCode < 400;
    
    try {
      const responseData = typeof data === 'string' ? JSON.parse(data) : data;
      if (responseData.timeline) {
        resultCount = Array.isArray(responseData.timeline) ? responseData.timeline.length : 0;
      } else if (responseData.submission) {
        resultCount = 1;
      }
    } catch (e) {
      // Ignore parsing errors
    }

    // Record search event for analytics endpoints
    if (req.path.includes('timeline') || req.path.includes('comparison')) {
      searchMonitoringService.recordSearchEvent({
        userId: getUserId(req),
        ip: req.ip,
        query: `${req.params.contactId || ''} ${req.params.month || ''}`,
        path: req.path,
        complexity: { level: 'medium', score: 4, type: 'analytics' }, // Timeline/comparison are inherently complex
        responseTime,
        resultCount,
        success,
        userAgent: req.get('user-agent')
      });
    }

    return originalSend.call(this, data);
  };
  
  next();
};

// Middleware pour vérifier les permissions de contact avec logging sécurisé
async function checkContactPermission(req, res, next) {
  try {
    const { contactId } = req.params;
    const currentUserId = getUserId(req);

    if (!currentUserId) {
      console.warn('📋 Permission check failed: No authenticated user', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        path: req.path,
        timestamp: new Date().toISOString()
      });
      
      return res.status(401).json({
        success: false,
        error: 'Authentification requise',
        code: 'AUTH_REQUIRED'
      });
    }

    // Vérifier que le contactId est bien formaté (sécurité)
    if (!mongoose.Types.ObjectId.isValid(contactId)) {
      console.warn('📋 Permission check failed: Invalid contact ID format', {
        ip: req.ip,
        userId: currentUserId,
        contactId,
        path: req.path,
        timestamp: new Date().toISOString()
      });
      
      return res.status(400).json({
        success: false,
        error: 'ID de contact invalide',
        code: 'INVALID_CONTACT_ID'
      });
    }

    // Vérifier que le contact existe et qu'il y a un handshake accepté
    const hasPermission = await Handshake.checkPermission(currentUserId, contactId);
    
    if (!hasPermission) {
      console.warn('📋 Permission check failed: No valid handshake', {
        ip: req.ip,
        userId: currentUserId,
        contactId,
        path: req.path,
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({
        success: false,
        error: 'Accès non autorisé. Vous devez avoir un handshake accepté avec ce contact.',
        code: 'HANDSHAKE_REQUIRED'
      });
    }

    // Logging réussi pour audit
    console.log('✅ Permission check passed', {
      userId: currentUserId,
      contactId,
      path: req.path,
      timestamp: new Date().toISOString()
    });

    next();
  } catch (error) {
    console.error('❌ Erreur vérification permission contact:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      contactId: req.params.contactId,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    return res.status(500).json({
      success: false,
      error: 'Erreur lors de la vérification des permissions',
      code: 'PERMISSION_CHECK_ERROR'
    });
  }
}

// GET /api/submissions/current - Récupère la soumission du mois courant pour l'utilisateur connecté
router.get(
  '/current',
  apiLimiter,
  securityLogger,
  preventParameterPollution(),
  antiAutomation(),
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  async (req, res) => {
    try {
      const factory = ServiceFactory.create();
      const submissionService = factory.getSubmissionService();
      
      const currentMonth = submissionService.getCurrentMonth();
      const submission = await submissionService.getSubmissionByUser(getUserId(req), currentMonth);
      
      if (!submission) {
        return res.json({
          success: true,
          submission: null,
          message: 'Aucune soumission pour ce mois'
        });
      }

      return res.json({
        success: true,
        submission: {
          id: submission._id,
          month: submission.month,
          responses: submission.responses,
          freeText: submission.freeText,
          completionRate: submission.completionRate,
          isComplete: submission.isComplete,
          submittedAt: submission.submittedAt,
          canEdit: (Date.now() - submission.submittedAt) < (24 * 60 * 60 * 1000) // 24h
        }
      });

    } catch (error) {
      console.error('Erreur récupération soumission courante:', error);
      return res.status(500).json({
        success: false,
        error: 'Erreur lors de la récupération de votre soumission'
      });
    }
  }
);

// POST /api/submissions - Crée ou met à jour une soumission pour le mois courant
router.post(
  '/',
  createFormBodyParser(),
  formLimiter,
  securityLogger,
  validateContentType(['application/json']),
  preventParameterPollution(),
  antiAutomation(),
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  csrfProtectionStrict(), // Add CSRF protection for authenticated users
  validateSubmissionData,
  handleValidationErrors,
  sanitizeSubmissionData,
  async (req, res) => {
    try {
      const factory = ServiceFactory.create();
      const submissionService = factory.getSubmissionService();
      
      const currentMonth = submissionService.getCurrentMonth();
      const { responses, freeText, invitationToken } = req.body;
      
      // Vérifier si une soumission existe déjà
      const existingSubmission = await submissionService.getSubmissionByUser(req.currentUser.id, currentMonth);
      
      let result;
      
      if (existingSubmission) {
        // Mise à jour si dans les 24h
        const daysSinceSubmission = (Date.now() - existingSubmission.submittedAt) / (1000 * 60 * 60 * 24);
        
        if (daysSinceSubmission > 1) {
          return res.status(403).json({
            success: false,
            error: 'Modification non autorisée après 24h'
          });
        }
        
        result = await submissionService.updateSubmission(getUserId(req), currentMonth, {
          responses,
          freeText
        });
      } else {
        // Nouvelle soumission
        const metadata = {
          ipAddress: req.ip,
          userAgent: req.get('User-Agent')
        };
        
        result = await submissionService.createSubmission(getUserId(req), {
          responses,
          freeText,
          month: currentMonth,
          invitationToken
        }, metadata);
      }

      return res.status(existingSubmission ? 200 : 201).json({
        success: true,
        submission: {
          id: result._id,
          month: result.month,
          responses: result.responses,
          freeText: result.freeText,
          completionRate: result.completionRate,
          isComplete: result.isComplete,
          submittedAt: result.submittedAt
        },
        message: existingSubmission ? 'Soumission mise à jour avec succès' : 'Soumission créée avec succès'
      });

    } catch (error) {
      console.error('Erreur création/mise à jour soumission:', error);
      
      if (error.message.includes('déjà soumis une réponse')) {
        return res.status(409).json({
          success: false,
          error: error.message
        });
      }
      
      if (error.message.includes('Token d\'invitation')) {
        return res.status(400).json({
          success: false,
          error: error.message
        });
      }
      
      return res.status(500).json({
        success: false,
        error: 'Erreur lors de la création/mise à jour de votre soumission'
      });
    }
  }
);

// GET /api/submissions/timeline/:contactId - Récupère la timeline des soumissions pour un contact avec statistiques d'engagement
router.get(
  '/timeline/:contactId',
  searchAnalyticsLimiter, // Use analytics rate limiting for timeline requests
  trackSubmissionSearchEvent, // Monitor timeline search patterns
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  validateContactId,
  handleValidationErrors,
  checkContactPermission,
  async (req, res) => {
    try {
      const { contactId } = req.params;
      const { limit = 24, page = 1, includeStats = 'true' } = req.query;
      
      const factory = ServiceFactory.create();
      const submissionService = factory.getSubmissionService();
      
      // Récupérer les soumissions du contact avec pagination
      const submissions = await submissionService.getSubmissions(
        { userId: contactId },
        { 
          page: parseInt(page), 
          limit: parseInt(limit),
          sortBy: 'submittedAt',
          sortOrder: 'desc'
        }
      );

      // Calculer les statistiques d'engagement si demandées
      let engagementStats = null;
      if (includeStats === 'true' && submissions.submissions.length > 0) {
        engagementStats = await calculateEngagementStatistics(contactId, submissions.submissions);
      }
      
      // Formater pour timeline avec indicateurs visuels
      const timeline = submissions.submissions.map((submission, index) => {
        const timelineEntry = {
          id: submission._id,
          month: submission.month,
          monthLabel: formatMonthLabel(submission.month),
          completionRate: submission.completionRate,
          isComplete: submission.isComplete,
          submittedAt: submission.submittedAt,
          responseCount: submission.responses.length,
          hasFreeText: !!submission.freeText,
          
          // Visual indicators for timeline
          status: submission.isComplete ? 'complete' : 'partial',
          engagementLevel: getEngagementLevel(submission.completionRate),
          timeFromPrevious: index > 0 ? calculateTimeDifference(
            submissions.submissions[index - 1].submittedAt, 
            submission.submittedAt
          ) : null,
          
          // Response details for preview
          responsePreview: submission.responses.slice(0, 3).map(r => ({
            question: r.questionId,
            hasAnswer: !!r.answer,
            hasPhoto: !!r.photoUrl,
            type: r.type
          }))
        };
        
        return timelineEntry;
      });
      
      // Récupérer les informations du contact
      const Contact = require('../models/Contact');
      const contact = await Contact.findById(contactId).select('firstName lastName email tracking').lean();
      
      return res.json({
        success: true,
        timeline,
        pagination: submissions.pagination,
        contact: {
          id: contactId,
          username: submissions.submissions[0]?.userId?.username || 'Contact inconnu',
          firstName: contact?.firstName,
          lastName: contact?.lastName,
          email: contact?.email,
          tracking: contact?.tracking
        },
        engagementStats: engagementStats
      });

    } catch (error) {
      console.error('Erreur récupération timeline:', error);
      return res.status(500).json({
        success: false,
        error: 'Erreur lors de la récupération de la timeline'
      });
    }
  }
);

// GET /api/submissions/comparison/:contactId/:month - Compare les soumissions utilisateur/contact
// SECURITY: Uses statsComparisonLimiter for cross-data comparison analysis (15 requests per 20 minutes)
router.get(
  '/comparison/:contactId/:month',
  require('../middleware/rateLimiting').statsComparisonLimiter, // Use comparison analytics rate limiting
  trackComparison, // Monitor statistics access patterns
  trackSubmissionSearchEvent, // Monitor comparison search patterns
  detectAuthMethod,
  enrichUserData,
  requireUserAuth,
  validateContactId,
  validateMonthFormat,
  handleValidationErrors,
  checkContactPermission,
  async (req, res) => {
    try {
      const { contactId, month } = req.params;
      const currentUserId = getUserId(req);
      
      const factory = ServiceFactory.create();
      const submissionService = factory.getSubmissionService();
      
      // Options de comparaison
      const comparisonOptions = {
        includePrivateData: false,
        anonymize: false
      };
      
      const comparison = await submissionService.compareSubmissions(
        currentUserId,
        contactId,
        month,
        comparisonOptions
      );
      
      return res.json({
        success: true,
        comparison: {
          month: comparison.month,
          monthLabel: formatMonthLabel(comparison.month),
          metadata: comparison.metadata,
          yourSubmission: {
            responses: comparison.user1.responses,
            freeText: comparison.user1.freeText,
            completionRate: comparison.user1.completionRate,
            submittedAt: comparison.user1.submittedAt
          },
          contactSubmission: {
            username: comparison.user2.username,
            responses: comparison.user2.responses,
            freeText: comparison.user2.freeText,
            completionRate: comparison.user2.completionRate,
            submittedAt: comparison.user2.submittedAt
          },
          analysis: comparison.analysis,
          compatibility: {
            overallScore: comparison.compatibility.overallScore,
            details: comparison.compatibility.details,
            matches: comparison.compatibility.matches.slice(0, 5), // Limiter à 5 matches
            differences: comparison.compatibility.differences.slice(0, 3), // Limiter à 3 différences
            recommendations: comparison.compatibility.recommendations
          }
        }
      });

    } catch (error) {
      console.error('Erreur comparaison soumissions:', error);
      
      if (error.message.includes('soumission non trouvée')) {
        return res.status(404).json({
          success: false,
          error: 'L\'une des soumissions n\'existe pas pour ce mois'
        });
      }
      
      return res.status(500).json({
        success: false,
        error: 'Erreur lors de la comparaison des soumissions'
      });
    }
  }
);

// Fonctions utilitaires

/**
 * Formate un mois YYYY-MM en français
 * @param {String} month - Mois au format YYYY-MM
 * @returns {String} Mois formaté en français
 */
function formatMonthLabel(month) {
  if (!month || !month.match(/^\d{4}-\d{2}$/)) {
    return 'Mois inconnu';
  }
  
  const [year, monthNum] = month.split('-');
  const monthNames = [
    'janvier', 'février', 'mars', 'avril', 'mai', 'juin',
    'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'
  ];
  
  const monthIndex = parseInt(monthNum) - 1;
  return `${monthNames[monthIndex]} ${year}`;
}

/**
 * Calcule les statistiques d'engagement pour un contact
 * @param {String} contactId - ID du contact
 * @param {Array} submissions - Liste des soumissions
 * @returns {Object} Statistiques d'engagement
 */
async function calculateEngagementStatistics(contactId, submissions) {
  try {
    const now = new Date();
    const totalSubmissions = submissions.length;
    
    // Calcul du taux de réponse moyen
    const averageCompletionRate = totalSubmissions > 0 
      ? Math.round(submissions.reduce((sum, s) => sum + s.completionRate, 0) / totalSubmissions)
      : 0;
    
    // Calcul de la consistance (soumissions complètes vs partielles)
    const completeSubmissions = submissions.filter(s => s.isComplete).length;
    const consistencyRate = totalSubmissions > 0 
      ? Math.round((completeSubmissions / totalSubmissions) * 100)
      : 0;
    
    // Calcul du temps de réponse moyen (en jours depuis le début du mois)
    const responseTimes = submissions.map(s => {
      const submissionDate = new Date(s.submittedAt);
      const monthStart = new Date(submissionDate.getFullYear(), submissionDate.getMonth(), 1);
      return Math.ceil((submissionDate - monthStart) / (1000 * 60 * 60 * 24));
    }).filter(days => days >= 0);
    
    const averageResponseTime = responseTimes.length > 0
      ? Math.round(responseTimes.reduce((sum, days) => sum + days, 0) / responseTimes.length)
      : null;
    
    // Calcul des streaks (mois consécutifs)
    const streaks = calculateSubmissionStreaks(submissions);
    
    // Calcul de l'activité récente (3 derniers mois)
    const threeMonthsAgo = new Date();
    threeMonthsAgo.setMonth(threeMonthsAgo.getMonth() - 3);
    const recentSubmissions = submissions.filter(s => new Date(s.submittedAt) >= threeMonthsAgo);
    const recentActivityRate = recentSubmissions.length;
    
    // Tendance d'engagement (comparaison 3 derniers mois vs 3 précédents)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
    const olderSubmissions = submissions.filter(s => {
      const date = new Date(s.submittedAt);
      return date >= sixMonthsAgo && date < threeMonthsAgo;
    });
    
    const recentAvgCompletion = recentSubmissions.length > 0
      ? recentSubmissions.reduce((sum, s) => sum + s.completionRate, 0) / recentSubmissions.length
      : 0;
    const olderAvgCompletion = olderSubmissions.length > 0
      ? olderSubmissions.reduce((sum, s) => sum + s.completionRate, 0) / olderSubmissions.length
      : 0;
    
    const engagementTrend = recentAvgCompletion > olderAvgCompletion ? 'improving' : 
                           recentAvgCompletion < olderAvgCompletion ? 'declining' : 'stable';
    
    // Types de réponses favoris
    const responseTypeStats = calculateResponseTypePreferences(submissions);
    
    return {
      totalSubmissions,
      averageCompletionRate,
      consistencyRate,
      averageResponseTime,
      streaks,
      recentActivityRate,
      engagementTrend,
      responseTypeStats,
      
      // Scores calculés pour visualisation
      engagementScore: Math.round((averageCompletionRate + consistencyRate) / 2),
      activityLevel: getActivityLevel(recentActivityRate),
      
      // Périodes d'activité
      firstSubmission: submissions.length > 0 ? submissions[submissions.length - 1].submittedAt : null,
      lastSubmission: submissions.length > 0 ? submissions[0].submittedAt : null,
      
      // Métadonnées pour graphiques
      monthlyActivity: generateMonthlyActivityData(submissions),
      completionTrends: generateCompletionTrendData(submissions)
    };
    
  } catch (error) {
    console.error('Erreur calcul statistiques engagement:', error);
    return null;
  }
}

/**
 * Détermine le niveau d'engagement basé sur le taux de completion
 * @param {Number} completionRate - Taux de completion (0-100)
 * @returns {String} Niveau d'engagement
 */
function getEngagementLevel(completionRate) {
  if (completionRate >= 90) return 'excellent';
  if (completionRate >= 75) return 'high';
  if (completionRate >= 50) return 'medium';
  if (completionRate >= 25) return 'low';
  return 'minimal';
}

/**
 * Détermine le niveau d'activité basé sur le nombre de soumissions récentes
 * @param {Number} recentCount - Nombre de soumissions dans les 3 derniers mois
 * @returns {String} Niveau d'activité
 */
function getActivityLevel(recentCount) {
  if (recentCount >= 3) return 'very-active';
  if (recentCount >= 2) return 'active';
  if (recentCount >= 1) return 'moderate';
  return 'inactive';
}

/**
 * Calcule la différence de temps entre deux dates
 * @param {Date} date1 - Date plus récente
 * @param {Date} date2 - Date plus ancienne
 * @returns {Object} Différence en jours et description
 */
function calculateTimeDifference(date1, date2) {
  const diff = Math.abs(new Date(date1) - new Date(date2));
  const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
  
  if (days < 7) return { days, description: `${days} jour${days > 1 ? 's' : ''}` };
  if (days < 30) return { days, description: `${Math.ceil(days / 7)} semaine${Math.ceil(days / 7) > 1 ? 's' : ''}` };
  if (days < 365) return { days, description: `${Math.ceil(days / 30)} mois` };
  return { days, description: `${Math.ceil(days / 365)} an${Math.ceil(days / 365) > 1 ? 's' : ''}` };
}

/**
 * Calcule les streaks de soumissions consécutives
 * @param {Array} submissions - Liste des soumissions triées par date décroissante
 * @returns {Object} Informations sur les streaks
 */
function calculateSubmissionStreaks(submissions) {
  if (submissions.length === 0) return { current: 0, longest: 0, periods: [] };
  
  // Grouper par mois pour identifier les streaks
  const monthsWithSubmissions = submissions.map(s => s.month).sort();
  const streaks = [];
  let currentStreak = 1;
  let longestStreak = 1;
  
  for (let i = 1; i < monthsWithSubmissions.length; i++) {
    const current = new Date(monthsWithSubmissions[i] + '-01');
    const previous = new Date(monthsWithSubmissions[i - 1] + '-01');
    
    // Vérifier si les mois sont consécutifs
    const monthDiff = (current.getFullYear() - previous.getFullYear()) * 12 + (current.getMonth() - previous.getMonth());
    
    if (monthDiff === 1) {
      currentStreak++;
    } else {
      if (currentStreak > 1) {
        streaks.push({
          length: currentStreak,
          start: monthsWithSubmissions[i - currentStreak],
          end: monthsWithSubmissions[i - 1]
        });
      }
      longestStreak = Math.max(longestStreak, currentStreak);
      currentStreak = 1;
    }
  }
  
  if (currentStreak > 1) {
    streaks.push({
      length: currentStreak,
      start: monthsWithSubmissions[monthsWithSubmissions.length - currentStreak],
      end: monthsWithSubmissions[monthsWithSubmissions.length - 1]
    });
  }
  longestStreak = Math.max(longestStreak, currentStreak);
  
  return {
    current: currentStreak,
    longest: longestStreak,
    periods: streaks.sort((a, b) => b.length - a.length).slice(0, 5) // Top 5 streaks
  };
}

/**
 * Calcule les préférences de types de réponses
 * @param {Array} submissions - Liste des soumissions
 * @returns {Object} Statistiques par type de réponse
 */
function calculateResponseTypePreferences(submissions) {
  const stats = {
    text: { count: 0, total: 0 },
    photo: { count: 0, total: 0 },
    radio: { count: 0, total: 0 },
    freeText: { count: 0, total: submissions.length }
  };
  
  submissions.forEach(submission => {
    submission.responses.forEach(response => {
      stats[response.type].total++;
      if (response.answer || response.photoUrl) {
        stats[response.type].count++;
      }
    });
    
    if (submission.freeText && submission.freeText.trim()) {
      stats.freeText.count++;
    }
  });
  
  // Calculer les pourcentages
  Object.keys(stats).forEach(type => {
    stats[type].percentage = stats[type].total > 0 
      ? Math.round((stats[type].count / stats[type].total) * 100)
      : 0;
  });
  
  return stats;
}

/**
 * Génère les données d'activité mensuelle pour les graphiques
 * @param {Array} submissions - Liste des soumissions
 * @returns {Array} Données formatées pour Chart.js
 */
function generateMonthlyActivityData(submissions) {
  const monthlyData = {};
  
  submissions.forEach(submission => {
    const month = submission.month;
    if (!monthlyData[month]) {
      monthlyData[month] = {
        month,
        label: formatMonthLabel(month),
        submissions: 0,
        totalCompletionRate: 0,
        averageCompletionRate: 0
      };
    }
    
    monthlyData[month].submissions++;
    monthlyData[month].totalCompletionRate += submission.completionRate;
    monthlyData[month].averageCompletionRate = Math.round(
      monthlyData[month].totalCompletionRate / monthlyData[month].submissions
    );
  });
  
  return Object.values(monthlyData).sort((a, b) => a.month.localeCompare(b.month));
}

/**
 * Génère les données de tendance de completion pour les graphiques
 * @param {Array} submissions - Liste des soumissions triées par date décroissante
 * @returns {Array} Données de tendance
 */
function generateCompletionTrendData(submissions) {
  return submissions.slice(0, 12).reverse().map((submission, index) => ({
    month: submission.month,
    label: formatMonthLabel(submission.month),
    completionRate: submission.completionRate,
    isComplete: submission.isComplete,
    trend: index > 0 ? (
      submission.completionRate > submissions[submissions.length - index].completionRate ? 'up' : 
      submission.completionRate < submissions[submissions.length - index].completionRate ? 'down' : 'stable'
    ) : 'neutral'
  }));
}

module.exports = router;