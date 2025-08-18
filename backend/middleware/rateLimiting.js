const rateLimit = require('express-rate-limit');

// Middleware to bypass rate limiting in test environment
const bypassInTests = (middleware) => {
  return (req, res, next) => {
    if (process.env.NODE_ENV === 'test' || process.env.DISABLE_RATE_LIMITING === 'true') {
      return next();
    }
    return middleware(req, res, next);
  };
};

// Enhanced security logging for rate limit violations
const createSecureHandler = (limitType, retryAfterSeconds = 900) => {
  return (req, res) => {
    const logData = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      path: req.path,
      method: req.method,
      userId: req.user?.id || req.session?.userId || 'anonymous',
      limitType,
      timestamp: new Date().toISOString()
    };
    
    // Log to console for monitoring
    console.warn(`Rate limit exceeded: ${limitType}`, logData);
    
    // Generic error response to prevent information disclosure
    res.status(429).json({
      success: false,
      error: 'Trop de requêtes. Réessayez plus tard.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: retryAfterSeconds
    });
  };
};

// ===== EXISTING LIMITERS =====

const formLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 3,
  message: { success: false, error: "Trop de soumissions. Réessaie dans 15 minutes.", code: 'RATE_LIMIT_EXCEEDED' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: createSecureHandler('form_submission', 900)
});

const adminLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,
  message: { success: false, error: "Trop de requêtes admin. Réessaie plus tard.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('admin_operations', 900)
});

const loginLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,
  message: { success: false, error: "Trop de tentatives de connexion. Réessaie dans 15 minutes.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('login_attempts', 900)
});

// ===== NEW API ENDPOINT LIMITERS =====

// Contact operations rate limiter
const contactLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 30, // 30 contact operations per 15 minutes
  message: { success: false, error: "Trop d'opérations sur les contacts. Réessayez plus tard.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('contact_operations', 900)
});

// Handshake operations rate limiter
const handshakeLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 20, // 20 handshake operations per 15 minutes
  message: { success: false, error: "Trop d'opérations de handshake. Réessayez plus tard.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('handshake_operations', 900)
});

// Invitation operations rate limiter
const invitationLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 25, // 25 invitation operations per 15 minutes
  message: { success: false, error: "Trop d'opérations d'invitation. Réessayez plus tard.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('invitation_operations', 900)
});

// Submission operations rate limiter
const submissionLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10, // 10 submission operations per 15 minutes
  message: { success: false, error: "Trop d'opérations de soumission. Réessayez plus tard.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('submission_operations', 900)
});

// CSV/Bulk import rate limiter (stricter)
const bulkImportLimiterRaw = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 3, // 3 bulk imports per hour
  message: { success: false, error: "Limite d'importation atteinte. Réessayez dans 1 heure.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('bulk_import', 3600)
});

// API search/stats rate limiter
const apiLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 60, // 60 API calls per 15 minutes
  message: { success: false, error: "Trop de requêtes API. Réessayez plus tard.", code: 'RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('api_operations', 900)
});

// ===== SEARCH-SPECIFIC RATE LIMITERS =====

// Basic search operations (simple queries, pagination)
const searchBasicLimiterRaw = rateLimit({
  windowMs: 10 * 60 * 1000,  // 10 minutes
  max: 50, // 50 basic search requests per 10 minutes
  message: { success: false, error: "Trop de recherches simples. Réessayez plus tard.", code: 'SEARCH_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('basic_search', 600)
});

// Advanced search operations (complex filters, stats, analytics)
const searchAdvancedLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 25, // 25 advanced search requests per 15 minutes
  message: { success: false, error: "Trop de recherches avancées. Réessayez plus tard.", code: 'ADVANCED_SEARCH_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('advanced_search', 900)
});

// Complex analytics and statistics queries
const searchAnalyticsLimiterRaw = rateLimit({
  windowMs: 30 * 60 * 1000,  // 30 minutes
  max: 15, // 15 analytics requests per 30 minutes
  message: { success: false, error: "Limite d'analyses atteinte. Réessayez plus tard.", code: 'ANALYTICS_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('search_analytics', 1800)
});

// Suggestion and recommendation systems
const searchSuggestionsLimiterRaw = rateLimit({
  windowMs: 5 * 60 * 1000,   // 5 minutes
  max: 20, // 20 suggestion requests per 5 minutes
  message: { success: false, error: "Trop de demandes de suggestions. Réessayez plus tard.", code: 'SUGGESTIONS_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('search_suggestions', 300)
});

// Bulk/export operations with search functionality
const searchExportLimiterRaw = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 5, // 5 export operations per hour
  message: { success: false, error: "Limite d'export atteinte. Réessayez dans 1 heure.", code: 'EXPORT_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('search_export', 3600)
});

// Anonymous user search limiter (stricter)
const searchAnonymousLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10, // 10 searches per 15 minutes for anonymous users
  message: { success: false, error: "Limite de recherche pour utilisateurs non connectés atteinte.", code: 'ANONYMOUS_SEARCH_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('anonymous_search', 900)
});

// ===== STATISTICS-SPECIFIC RATE LIMITERS =====

// Simple statistics (basic counts, status summaries)
const statsSimpleLimiterRaw = rateLimit({
  windowMs: 10 * 60 * 1000,  // 10 minutes
  max: 40, // 40 simple stats requests per 10 minutes
  message: { success: false, error: "Trop de demandes de statistiques simples. Réessayez plus tard.", code: 'SIMPLE_STATS_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('simple_statistics', 600)
});

// Complex admin summary statistics (aggregation pipelines, complex queries)
const statsAdminSummaryLimiterRaw = rateLimit({
  windowMs: 30 * 60 * 1000,  // 30 minutes
  max: 20, // 20 admin summary requests per 30 minutes
  message: { success: false, error: "Limite de résumés admin atteinte. Réessayez plus tard.", code: 'ADMIN_SUMMARY_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('admin_summary_statistics', 1800)
});

// Heavy computational analytics (performance monitoring, deep analysis)
const statsHeavyAnalyticsLimiterRaw = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 10, // 10 heavy analytics requests per hour
  message: { success: false, error: "Limite d'analyses lourdes atteinte. Réessayez dans 1 heure.", code: 'HEAVY_ANALYTICS_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('heavy_analytics', 3600)
});

// Real-time monitoring and metrics (frequent updates)
const statsRealTimeMonitoringLimiterRaw = rateLimit({
  windowMs: 5 * 60 * 1000,   // 5 minutes
  max: 30, // 30 real-time monitoring requests per 5 minutes
  message: { success: false, error: "Limite de monitoring temps réel atteinte. Réessayez plus tard.", code: 'REALTIME_MONITORING_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('realtime_monitoring', 300)
});

// Comparison and correlation analytics (cross-data analysis)
const statsComparisonLimiterRaw = rateLimit({
  windowMs: 20 * 60 * 1000,  // 20 minutes
  max: 15, // 15 comparison requests per 20 minutes
  message: { success: false, error: "Limite d'analyses comparatives atteinte. Réessayez plus tard.", code: 'COMPARISON_STATS_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('comparison_analytics', 1200)
});

// Global statistics across all entities (database-wide queries)
const statsGlobalLimiterRaw = rateLimit({
  windowMs: 45 * 60 * 1000,  // 45 minutes
  max: 12, // 12 global stats requests per 45 minutes
  message: { success: false, error: "Limite de statistiques globales atteinte. Réessayez plus tard.", code: 'GLOBAL_STATS_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('global_statistics', 2700)
});

// Performance and system statistics (resource intensive)
const statsPerformanceLimiterRaw = rateLimit({
  windowMs: 30 * 60 * 1000,  // 30 minutes
  max: 8, // 8 performance stats requests per 30 minutes
  message: { success: false, error: "Limite de statistiques de performance atteinte. Réessayez plus tard.", code: 'PERFORMANCE_STATS_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('performance_statistics', 1800)
});

// Notification-specific rate limiters
const notificationLimiterRaw = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 notification requests per window
  message: { success: false, error: "Trop de requêtes de notifications. Réessayez plus tard.", code: 'NOTIFICATION_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('notification_operations', 900)
});

const realtimeLimiterRaw = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // 10 SSE connection attempts per window
  message: { success: false, error: "Trop de tentatives de connexion temps réel. Réessayez plus tard.", code: 'REALTIME_CONNECTION_RATE_LIMIT_EXCEEDED' },
  handler: createSecureHandler('realtime_connection', 300)
});

// Apply test bypass to all limiters
const formLimiter = bypassInTests(formLimiterRaw);
const adminLimiter = bypassInTests(adminLimiterRaw);
const loginLimiter = bypassInTests(loginLimiterRaw);
const contactLimiter = bypassInTests(contactLimiterRaw);
const handshakeLimiter = bypassInTests(handshakeLimiterRaw);
const invitationLimiter = bypassInTests(invitationLimiterRaw);
const submissionLimiter = bypassInTests(submissionLimiterRaw);
const bulkImportLimiter = bypassInTests(bulkImportLimiterRaw);
const apiLimiter = bypassInTests(apiLimiterRaw);

// Apply test bypass to search limiters
const searchBasicLimiter = bypassInTests(searchBasicLimiterRaw);
const searchAdvancedLimiter = bypassInTests(searchAdvancedLimiterRaw);
const searchAnalyticsLimiter = bypassInTests(searchAnalyticsLimiterRaw);
const searchSuggestionsLimiter = bypassInTests(searchSuggestionsLimiterRaw);
const searchExportLimiter = bypassInTests(searchExportLimiterRaw);
const searchAnonymousLimiter = bypassInTests(searchAnonymousLimiterRaw);

// Apply test bypass to statistics limiters
const statsSimpleLimiter = bypassInTests(statsSimpleLimiterRaw);
const statsAdminSummaryLimiter = bypassInTests(statsAdminSummaryLimiterRaw);
const statsHeavyAnalyticsLimiter = bypassInTests(statsHeavyAnalyticsLimiterRaw);
const statsRealTimeMonitoringLimiter = bypassInTests(statsRealTimeMonitoringLimiterRaw);
const statsComparisonLimiter = bypassInTests(statsComparisonLimiterRaw);
const statsGlobalLimiter = bypassInTests(statsGlobalLimiterRaw);
const statsPerformanceLimiter = bypassInTests(statsPerformanceLimiterRaw);

// Apply test bypass to notification limiters
const notificationLimiter = bypassInTests(notificationLimiterRaw);
const realtimeLimiter = bypassInTests(realtimeLimiterRaw);

module.exports = {
  // Legacy limiters
  formLimiter,
  adminLimiter,
  loginLimiter,
  
  // API endpoint limiters
  contactLimiter,
  handshakeLimiter,
  invitationLimiter,
  submissionLimiter,
  bulkImportLimiter,
  apiLimiter,
  
  // Search-specific rate limiters
  searchBasicLimiter,
  searchAdvancedLimiter,
  searchAnalyticsLimiter,
  searchSuggestionsLimiter,
  searchExportLimiter,
  searchAnonymousLimiter,
  
  // Statistics-specific rate limiters
  statsSimpleLimiter,
  statsAdminSummaryLimiter,
  statsHeavyAnalyticsLimiter,
  statsRealTimeMonitoringLimiter,
  statsComparisonLimiter,
  statsGlobalLimiter,
  statsPerformanceLimiter,
  
  // Notification-specific rate limiters
  notificationLimiter,
  realtimeLimiter,
  
  // Helper function for custom rate limiting
  createSecureHandler
};