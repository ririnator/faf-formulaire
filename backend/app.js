// app.js
require('dotenv').config();
const express       = require('express');
const rateLimit     = require('express-rate-limit');
const mongoose      = require('mongoose');
const path          = require('path');
const session       = require('express-session');
const cors          = require('cors');
const helmet        = require('helmet');

const formRoutes     = require('./routes/formRoutes');
const responseRoutes = require('./routes/responseRoutes');
const adminRoutes    = require('./routes/adminRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const authRoutes     = require('./routes/authRoutes');
const uploadRoutes   = require('./routes/upload');
const contactRoutes  = require('./routes/contactRoutes');
const invitationRoutes = require('./routes/invitationRoutes');
const submissionRoutes = require('./routes/submissionRoutes');
const handshakeRoutes = require('./routes/handshakeRoutes');
const notificationRoutes = require('./routes/notificationRoutes');
const emailDomainAdminRoutes = require('./routes/emailDomainAdminRoutes');
const securityRoutes = require('./routes/securityRoutes');
const webhookRoutes = require('./routes/webhookRoutes');
const emailHealthRoutes = require('./routes/emailHealthRoutes');
const { router: schedulerMonitoringRoutes, initializeRoutes: initializeSchedulerMonitoringRoutes } = require('./routes/schedulerMonitoringRoutes');
const Response       = require('./models/Response');
const { HTTP_STATUS, APP_CONSTANTS } = require('./constants');
const TemplateRenderer = require('./utils/templateRenderer');
const { ensureAdmin, authenticateAdmin, destroySession } = require('./middleware/auth');
const { requireAdminAccess, requireUserAuth, requireDashboardAccess, detectAuthMethod, enrichUserData, protectAgainstSessionFixation } = require('./middleware/hybridAuth');
const { createSecurityMiddleware, createSessionOptions } = require('./middleware/security');
const SessionConfig = require('./config/session');
const { createStandardBodyParser, createPayloadErrorHandler } = require('./middleware/bodyParser');
const { csrfTokenMiddleware, csrfProtection } = require('./middleware/csrf');
const { 
  preventParameterPollution,
  securityLogger,
  enhanceTokenValidation,
  antiAutomation,
  validateContentType
} = require('./middleware/enhancedSecurity');
const { createQuerySanitizationMiddleware } = require('./middleware/querySanitization');
const { initializeSecurity, getSecurityMiddleware } = require('./config/enterpriseSecurity');
const sessionMonitoringMiddleware = require('./middleware/sessionMonitoring');
const DBPerformanceMonitor = require('./services/dbPerformanceMonitor');
const HybridIndexMonitor = require('./services/hybridIndexMonitor');
const RealTimeMetrics = require('./services/realTimeMetrics');
const PerformanceAlerting = require('./services/performanceAlerting');
const SchedulerMonitoringFactory = require('./services/schedulerMonitoringFactory');

const app  = express();

// Simple cache middleware for testing
const cacheMiddleware = (req, res, next) => {
  // Basic cache headers for API responses
  if (req.method === 'GET') {
    res.set('Cache-Control', 'public, max-age=300'); // 5 minutes
  } else {
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  }
  next();
};
const port = process.env.PORT || APP_CONSTANTS.DEFAULT_PORT;

// Health check endpoint pour Docker
app.get('/health', (req, res) => {
  res.status(HTTP_STATUS.OK).json({ 
    status: 'healthy', 
    timestamp: Date.now(),
    uptime: process.uptime()
  });
});

// Endpoints de debug - seulement en développement
if (process.env.NODE_ENV !== 'production') {
  // SIMPLE TEST - aucun middleware, juste du JSON brut
  app.get('/test-simple', (req, res) => {
    res.json({ message: 'Simple test works', timestamp: Date.now() });
  });

  app.get('/test-debug', (req, res) => {
    const info = {
      nodeVersion: process.version,
      platform: process.platform,
      env: process.env.NODE_ENV,
      port: port,
      mongoConnected: mongoose.connection.readyState === 1,
      timestamp: new Date().toISOString()
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(info, null, 2));
  });
}

// 1) Enhanced Security headers with nonce-based CSP
app.use(createSecurityMiddleware());

// 1.1) Enhanced Security Middleware Stack
app.use(securityLogger);
app.use(preventParameterPollution());
app.use(enhanceTokenValidation);
app.use(antiAutomation());
app.use(validateContentType(['application/json', 'multipart/form-data', 'application/x-www-form-urlencoded']));

// 1.5) UTF-8 encoding middleware for all responses
app.use((req, res, next) => {
  // Définir l'encodage UTF-8 par défaut pour toutes les réponses
  const originalSend = res.send;
  const originalJson = res.json;
  
  res.send = function(data) {
    if (!res.get('Content-Type')) {
      if (typeof data === 'string' && data.trim().startsWith('<')) {
        res.set('Content-Type', 'text/html; charset=utf-8');
      } else {
        res.set('Content-Type', 'text/plain; charset=utf-8');
      }
    }
    return originalSend.call(this, data);
  };
  
  res.json = function(data) {
    res.set('Content-Type', 'application/json; charset=utf-8');
    return originalJson.call(this, data);
  };
  
  next();
});

// 2) CORS – n'autorise que votre front
app.use(cors({
  origin: [
    process.env.APP_BASE_URL, 
    process.env.FRONTEND_URL
  ].filter(Boolean), // Removes any undefined values
  credentials: true
}));
app.set('trust proxy', 1);

// 3) Initialize MongoDB connection BEFORE session store
const initializeDatabase = async () => {
  if (mongoose.connection.readyState === 0 && process.env.NODE_ENV !== 'test') {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("Connecté à la base de données");
    
    // Performance indexes for dashboard queries
    
    // Index for chronological sorting (existing)
    await mongoose.connection.collection('responses')
      .createIndex({ createdAt: -1 });
    console.log("Index créé sur responses.createdAt");
    
    // Unique constraint to prevent admin duplicates per month (existing)
    await mongoose.connection.collection('responses')
      .createIndex(
        { month: 1, isAdmin: 1 }, 
        { unique: true, partialFilterExpression: { isAdmin: true } }
      );
    console.log("Index unique créé sur responses.{month, isAdmin} avec filtre admin");
    
    // Performance index for date extraction in month aggregations
    await mongoose.connection.collection('responses')
      .createIndex({ createdAt: 1, userId: 1 });
    console.log("Index composé créé sur responses.{createdAt, userId}");
    
    // Performance indexes for submissions (FAF v2)
    try {
      await mongoose.connection.collection('submissions')
        .createIndex({ userId: 1, month: -1 });
      console.log("Index créé sur submissions.{userId, month}");
      
      await mongoose.connection.collection('submissions')
        .createIndex({ month: -1, completionRate: -1 });
      console.log("Index créé sur submissions.{month, completionRate}");
      
      await mongoose.connection.collection('submissions')
        .createIndex({ submittedAt: -1 });
      console.log("Index créé sur submissions.submittedAt");
    } catch (error) {
      console.log("Submissions collection not yet available - indexes will be created when needed");
    }
    
    // Performance indexes for contacts
    try {
      await mongoose.connection.collection('contacts')
        .createIndex({ ownerId: 1, isActive: 1 });
      console.log("Index créé sur contacts.{ownerId, isActive}");
      
      await mongoose.connection.collection('contacts')
        .createIndex({ ownerId: 1, 'tracking.responseRate': -1 });
      console.log("Index créé sur contacts.{ownerId, tracking.responseRate}");
    } catch (error) {
      console.log("Contacts collection not yet available - indexes will be created when needed");
    }
  } else if (process.env.NODE_ENV === 'test') {
    console.log("Test environment detected - using existing MongoDB connection");
  } else {
    console.log("MongoDB already connected (readyState:", mongoose.connection.readyState, ")");
  }
};

// Initialize database synchronously to ensure readiness for session store
if (process.env.NODE_ENV !== 'test') {
  initializeDatabase().catch(err => console.error("Erreur de connexion à la DB :", err));
}

// 4) Enhanced Sessions with better dev/prod handling (AFTER MongoDB is ready)
app.use(session(SessionConfig.getConfig()));

// 4.1) Enhanced session security middleware (disabled in test environment)
if (process.env.NODE_ENV !== 'test') {
  app.use(SessionConfig.sessionRenewal());
  app.use(SessionConfig.idleTimeoutCheck());
  app.use(SessionConfig.validateSessionIntegrity());
}

// 4.2) Session monitoring for security (disabled in test environment)
if (process.env.NODE_ENV !== 'test') {
  app.use(sessionMonitoringMiddleware.trackSessionCreation());
  app.use(sessionMonitoringMiddleware.trackSessionDestruction());
  app.use(sessionMonitoringMiddleware.trackFailedLogins());
  app.use(sessionMonitoringMiddleware.validateAPISession());
}

// 4.5) CSRF Token generation for admin routes
app.use(csrfTokenMiddleware());

// 5) Optimized Body Parsers (512KB standard limit)
app.use(createStandardBodyParser());
app.use(createPayloadErrorHandler());

// 6) Pages avec CSP nonce (AVANT les fichiers statiques)
// Page d'accueil moderne avec CSP nonce
app.get('/', (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/public/index.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Page not found');
  }
});

// Route pour le formulaire principal avec CSP nonce
app.get('/form', (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/public/form.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Page not found');
  }
});

// 7) Front public (autres fichiers statiques)
app.use((req, res, next) => {
  // Set proper MIME types for public assets
  if (req.path.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    const cacheMaxAge = process.env.NODE_ENV === 'production' ? 86400 : 3600;
    res.setHeader('Cache-Control', `public, max-age=${cacheMaxAge}`);
  } else if (req.path.endsWith('.css')) {
    res.setHeader('Content-Type', 'text/css; charset=utf-8');
    const cacheMaxAge = process.env.NODE_ENV === 'production' ? 86400 : 3600;
    res.setHeader('Cache-Control', `public, max-age=${cacheMaxAge}`);
  }
  next();
}, express.static(path.join(__dirname, '../frontend/public')));

// 8) Pages d'authentification avec CSP nonce
app.get('/auth-choice', (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/public/auth-choice.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Page not found');
  }
});

app.get('/register', (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/public/register.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Page not found');
  }
});

app.get('/login', (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/public/login.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Page not found');
  }
});

app.get('/admin-login', (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/public/admin-login.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Page not found');
  }
});

// Routes legacy admin with session security
app.post('/login', sessionMonitoringMiddleware.blockSuspiciousSessions(), protectAgainstSessionFixation, authenticateAdmin);
app.post('/admin-login', sessionMonitoringMiddleware.blockSuspiciousSessions(), protectAgainstSessionFixation, authenticateAdmin);
app.get('/logout', destroySession);

// 8) Universal Dashboard (accessible to all authenticated users)
// Main dashboard route - universal access for users and admins
app.get('/dashboard', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/dashboard/dashboard.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Dashboard not available');
  }
});

// Dashboard sub-pages - all require authentication
app.get('/dashboard/contacts', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/dashboard/dashboard-contacts.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Contacts page not available');
  }
});

app.get('/dashboard/responses', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/dashboard/dashboard-responses.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Responses page not available');
  }
});

app.get('/dashboard/contact/:id', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/dashboard/dashboard-contact-view.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Contact view not available');
  }
});

// Legacy admin route redirect to universal dashboard
app.get('/admin', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res) => {
  res.redirect('/dashboard');
});

// Admin management page - admin access only
app.get('/admin/gestion', detectAuthMethod, requireAdminAccess, (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/admin/admin_gestion.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Admin management not available');
  }
});

// Compare page - accessible to all authenticated users (requires handshake validation on API level)
app.get('/admin/compare', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res) => {
  try {
    const html = TemplateRenderer.renderWithNonce(path.join(__dirname, '../frontend/admin/compare.html'), res);
    res.send(html);
  } catch (error) {
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).send('Comparison page not available');
  }
});

// Dashboard assets (dashboard.js module, CSS, images, etc.) - accessible to all authenticated users
app.use('/dashboard', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res, next) => {
  // Set proper MIME types for assets
  if (req.path.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    // Cache pour 1 heure en développement, 24h en production
    const cacheMaxAge = process.env.NODE_ENV === 'production' ? 86400 : 3600;
    res.setHeader('Cache-Control', `public, max-age=${cacheMaxAge}`);
  } else if (req.path.endsWith('.css')) {
    res.setHeader('Content-Type', 'text/css; charset=utf-8');
    // Cache pour 1 heure en développement, 24h en production
    const cacheMaxAge = process.env.NODE_ENV === 'production' ? 86400 : 3600;
    res.setHeader('Cache-Control', `public, max-age=${cacheMaxAge}`);
  }
  next();
}, express.static(path.join(__dirname, '../frontend/dashboard')));

// Admin assets (faf-admin.js module, CSS, images, etc.) - accessible to all authenticated users
app.use('/admin', detectAuthMethod, enrichUserData, requireDashboardAccess, (req, res, next) => {
  // Set proper MIME types for assets
  if (req.path.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    // Cache pour 1 heure en développement, 24h en production
    const cacheMaxAge = process.env.NODE_ENV === 'production' ? 86400 : 3600;
    res.setHeader('Cache-Control', `public, max-age=${cacheMaxAge}`);
  } else if (req.path.endsWith('.css')) {
    res.setHeader('Content-Type', 'text/css; charset=utf-8');
    // Cache pour 1 heure en développement, 24h en production
    const cacheMaxAge = process.env.NODE_ENV === 'production' ? 86400 : 3600;
    res.setHeader('Cache-Control', `public, max-age=${cacheMaxAge}`);
  }
  next();
}, express.static(path.join(__dirname, '../frontend/admin')));

// DEBUG ENDPOINTS - désactivés en production pour la sécurité
if (process.env.NODE_ENV !== 'production') {
  app.get('/api/debug/health', (req, res) => {
    console.log('=== DEBUG HEALTH CHECK ===');
    try {
      res.setHeader('Content-Type', 'application/json');
      const response = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        environment: process.env.NODE_ENV || 'development',
        version: 'debug-1.0'
      };
      if (process.env.NODE_ENV === 'development' && process.env.DEBUG_VERBOSE) {
        console.log('Debug endpoint accessed - response prepared');
      }
      res.status(HTTP_STATUS.OK).json(response);
    } catch (error) {
      console.error('ERROR in debug endpoint:', error);
      res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: error.message });
    }
  });

  // Debug endpoint - disabled in production for security
  if (process.env.NODE_ENV === 'development') {
    app.post('/api/debug/echo', (req, res) => {
      // Log sanitized info only - no sensitive data
      console.log(`[DEBUG] ${req.method} ${req.path}`);
      try {
        res.setHeader('Content-Type', 'application/json');
        res.status(HTTP_STATUS.OK).json({
          method: req.method,
          path: req.path,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        console.error('[DEBUG] Error:', error.message);
        res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Debug error' });
      }
    });
  }
}

// 9) Universal Dashboard API with role-based access control
app.use('/api/dashboard', detectAuthMethod, enrichUserData, requireDashboardAccess, csrfProtection(), dashboardRoutes);

// 10) API Admin with CSRF protection - admin only
app.use('/api/admin', ensureAdmin, csrfProtection(), adminRoutes);

// Email domain admin routes with enhanced security
app.use('/api/admin/email-domains', emailDomainAdminRoutes);

// Search monitoring admin routes
const searchMonitoringRoutes = require('./routes/searchMonitoringRoutes');
app.use('/api/admin/search-monitoring', searchMonitoringRoutes);

// Security monitoring admin routes
app.use('/api/security', ensureAdmin, securityRoutes);

// 9.1) Session monitoring admin endpoints
app.get('/api/admin/session-stats', ensureAdmin, sessionMonitoringMiddleware.getMonitoringStats());
app.post('/api/admin/reset-suspicious-ip', ensureAdmin, sessionMonitoringMiddleware.resetSuspiciousIP());

// 9.2) Hybrid index monitoring admin endpoints
app.get('/api/admin/hybrid-index-stats', ensureAdmin, (req, res) => {
  try {
    const hybridIndexMonitor = req.app.locals.services?.hybridIndexMonitor;
    if (!hybridIndexMonitor) {
      return res.status(503).json({ 
        error: 'Hybrid index monitoring not available',
        message: 'Service not initialized or not running'
      });
    }

    const metrics = hybridIndexMonitor.getMetrics();
    const report = hybridIndexMonitor.generatePerformanceReport();

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      monitoring: {
        isActive: hybridIndexMonitor.isMonitoring,
        uptime: Date.now() - metrics.lastUpdated.getTime()
      },
      metrics,
      performanceReport: report
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to retrieve hybrid index monitoring stats',
      message: error.message
    });
  }
});

app.post('/api/admin/hybrid-index-reset', ensureAdmin, (req, res) => {
  try {
    const hybridIndexMonitor = req.app.locals.services?.hybridIndexMonitor;
    if (!hybridIndexMonitor) {
      return res.status(503).json({ 
        error: 'Hybrid index monitoring not available' 
      });
    }

    hybridIndexMonitor.resetMetrics();
    res.json({ 
      success: true, 
      message: 'Hybrid index monitoring metrics reset successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to reset hybrid index monitoring metrics',
      message: error.message
    });
  }
});

// 10) Consultation privée (JSON)
app.get('/api/view/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const userResp  = await Response.findOne({ token, isAdmin: false }).lean();
    if (!userResp) {
      return res.status(HTTP_STATUS.NOT_FOUND).json({ error: 'Lien invalide ou expiré' });
    }
    const adminResp = await Response.findOne({ month: userResp.month, isAdmin: true }).lean();
    return res.json({ user: userResp, admin: adminResp });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// 11) Limiteur pour les soumissions de formulaire
const formLimiter = rateLimit({
  windowMs: APP_CONSTANTS.RATE_LIMIT_WINDOW_MS,
  max: 3,
  message: { message: "Trop de soumissions. Réessaie dans 15 minutes." },
  // Bypass rate limiting in test environment
  skip: (req) => {
    return process.env.NODE_ENV === 'test' || process.env.DISABLE_RATE_LIMITING === 'true';
  }
});
app.use('/api/response', formLimiter);

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  if (!req.session) {
    return res.status(500).json({ 
      error: 'Session non initialisée', 
      code: 'SESSION_ERROR' 
    });
  }
  
  // Generate token if it doesn't exist
  if (!req.session.csrfToken) {
    const { generateCSRFToken } = require('./middleware/csrf');
    generateCSRFToken(req);
  }
  
  res.json({ 
    csrfToken: req.session.csrfToken,
    token: req.session.csrfToken,
    headerName: 'x-csrf-token'
  });
});

// 12) API publiques with selective CSRF protection
app.use('/api/auth', authRoutes);
// Alias route for security tests compatibility
app.get('/api/users/me', (req, res, next) => {
  req.url = '/api/auth/me';
  next();
}, authRoutes);
app.use('/api/form', formRoutes);
app.use('/api/response', responseRoutes);
app.use('/api/upload', uploadRoutes);

// Webhook routes (no CSRF protection needed for webhooks)
app.use('/webhooks', webhookRoutes);

// Email health dashboard routes (admin only)
app.use('/api/admin/email-health', ensureAdmin, emailHealthRoutes);

// Scheduler monitoring dashboard routes (admin only)
app.use('/api/scheduler-monitoring', schedulerMonitoringRoutes);

// ===== FAF V2 ENHANCED API ROUTES =====
// All new routes use comprehensive security middleware stack with proper error handling

// Apply enhanced security middleware to all v2 routes
const v2SecurityStack = process.env.NODE_ENV === 'test' ? [
  // Minimal stack for tests but with proper authentication and CSRF
  createQuerySanitizationMiddleware(),
  detectAuthMethod,
  requireUserAuth,
  enrichUserData,
  csrfProtection()
] : [
  // Enhanced rate limiting with device fingerprinting
  require('./middleware/authRateLimit').rateLimitMonitoring,
  require('./middleware/authRateLimit').addFingerprintInfo,
  
  // Security event logging and correlation
  securityLogger,
  preventParameterPollution(['tags', 'emails', 'skills', 'contactIds']),
  enhanceTokenValidation,
  antiAutomation(),
  validateContentType(['application/json', 'multipart/form-data']),
  
  // MongoDB injection protection
  createQuerySanitizationMiddleware(),
  
  // Authentication detection and enrichment
  detectAuthMethod,
  enrichUserData,
  
  // CSRF protection for all authenticated operations
  csrfProtection()
];

// Contact Management Routes - Enhanced with bulk operations and CSV import
app.use('/api/contacts', 
  v2SecurityStack,
  contactRoutes
);

// Handshake Management Routes - Social connection system  
app.use('/api/handshakes', 
  v2SecurityStack,
  handshakeRoutes
);

// Notification Routes - Real-time notification center
app.use('/api/notifications',
  v2SecurityStack,
  notificationRoutes
);

// Enhanced Invitation Routes - V2 system with token-based access
app.use('/api/invitations', 
  v2SecurityStack,
  invitationRoutes
);

// Submission Management Routes - Form response handling with comparison features
app.use('/api/submissions', 
  v2SecurityStack,
  submissionRoutes
);

// Add health check endpoint specifically for V2 routes
app.get('/api/v2/health', 
  require('./middleware/authRateLimit').authLimiters.api,
  (req, res) => {
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '2.0',
      services: {
        contacts: 'operational',
        handshakes: 'operational', 
        invitations: 'operational',
        submissions: 'operational'
      },
      mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      environment: process.env.NODE_ENV || 'development'
    };
    
    // Add performance metrics if available
    if (req.app.locals.services?.realTimeMetrics) {
      try {
        const metrics = req.app.locals.services.realTimeMetrics.getMetrics();
        healthStatus.performance = {
          avgResponseTime: metrics.avgExecutionTime,
          queriesPerMinute: metrics.queriesPerMinute,
          indexEfficiency: metrics.indexEfficiency
        };
      } catch (error) {
        healthStatus.performance = 'unavailable';
      }
    }
    
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.json(healthStatus);
  }
);

// 13) Servir la page view.html pour /view/:token
app.get('/view/:token', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/view.html'));
});

// ===== CENTRALIZED ERROR HANDLING =====
// Enhanced error handling for FAF v2 routes with comprehensive logging

// V2 API Error Handler - Handles all v2 route errors with security logging
app.use('/api/contacts', (error, req, res, next) => {
  console.error('❌ Contact API Error:', {
    error: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('user-agent'),
    userId: req.currentUser?.id || req.session?.userId || 'anonymous',
    timestamp: new Date().toISOString()
  });
  
  // Don't expose internal errors in production
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (error.name === 'ValidationError') {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: 'Données invalides',
      code: 'VALIDATION_ERROR',
      details: isProduction ? undefined : error.errors
    });
  }
  
  if (error.name === 'MongoError' && error.code === 11000) {
    return res.status(HTTP_STATUS.CONFLICT).json({
      success: false,
      error: 'Ressource déjà existante',
      code: 'DUPLICATE_RESOURCE'
    });
  }
  
  if (error.name === 'CastError') {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: 'ID de ressource invalide',
      code: 'INVALID_RESOURCE_ID'
    });
  }
  
  if (error.message?.includes('Rate limit')) {
    return res.status(HTTP_STATUS.TOO_MANY_REQUESTS).json({
      success: false,
      error: 'Trop de requêtes. Veuillez patienter.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 900
    });
  }
  
  // Generic server error
  res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: isProduction ? 'Erreur interne du serveur' : error.message,
    code: 'INTERNAL_SERVER_ERROR',
    requestId: req.id || Date.now()
  });
});

// Handshake API Error Handler
app.use('/api/handshakes', (error, req, res, next) => {
  console.error('❌ Handshake API Error:', {
    error: error.message,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userId: req.currentUser?.id || 'anonymous',
    timestamp: new Date().toISOString()
  });
  
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (error.message?.includes('Handshake déjà existant')) {
    return res.status(HTTP_STATUS.CONFLICT).json({
      success: false,
      error: 'Handshake already exists',
      code: 'DUPLICATE_HANDSHAKE'
    });
  }
  
  if (error.message?.includes('User not found')) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({
      success: false,
      error: 'Utilisateur non trouvé',
      code: 'USER_NOT_FOUND'
    });
  }
  
  if (error.message?.includes('Permission denied')) {
    return res.status(HTTP_STATUS.FORBIDDEN).json({
      success: false,
      error: 'Accès non autorisé',
      code: 'PERMISSION_DENIED'
    });
  }
  
  res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: isProduction ? 'Erreur interne du serveur' : error.message,
    code: 'INTERNAL_SERVER_ERROR'
  });
});

// Invitation API Error Handler
app.use('/api/invitations', (error, req, res, next) => {
  console.error('❌ Invitation API Error:', {
    error: error.message,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userId: req.currentUser?.id || 'anonymous',
    timestamp: new Date().toISOString()
  });
  
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (error.message?.includes('Token invalide')) {
    return res.status(HTTP_STATUS.BAD_REQUEST).json({
      success: false,
      error: 'Token d\'invitation invalide ou expiré',
      code: 'INVALID_TOKEN'
    });
  }
  
  if (error.message?.includes('Invitation expirée')) {
    return res.status(HTTP_STATUS.GONE).json({
      success: false,
      error: 'Cette invitation a expiré',
      code: 'EXPIRED_INVITATION'
    });
  }
  
  if (error.message?.includes('déjà soumis')) {
    return res.status(HTTP_STATUS.CONFLICT).json({
      success: false,
      error: 'Réponse déjà soumise pour cette période',
      code: 'DUPLICATE_SUBMISSION'
    });
  }
  
  res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: isProduction ? 'Erreur interne du serveur' : error.message,
    code: 'INTERNAL_SERVER_ERROR'
  });
});

// Submission API Error Handler
app.use('/api/submissions', (error, req, res, next) => {
  console.error('❌ Submission API Error:', {
    error: error.message,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userId: req.currentUser?.id || 'anonymous',
    timestamp: new Date().toISOString()
  });
  
  const isProduction = process.env.NODE_ENV === 'production';
  
  if (error.message?.includes('soumission non trouvée')) {
    return res.status(HTTP_STATUS.NOT_FOUND).json({
      success: false,
      error: 'Soumission non trouvée',
      code: 'SUBMISSION_NOT_FOUND'
    });
  }
  
  if (error.message?.includes('Permission de contact')) {
    return res.status(HTTP_STATUS.FORBIDDEN).json({
      success: false,
      error: 'Accès non autorisé. Handshake requis.',
      code: 'HANDSHAKE_REQUIRED'
    });
  }
  
  if (error.message?.includes('Modification non autorisée')) {
    return res.status(HTTP_STATUS.FORBIDDEN).json({
      success: false,
      error: 'Modification impossible après 24h',
      code: 'EDIT_WINDOW_EXPIRED'
    });
  }
  
  res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: isProduction ? 'Erreur interne du serveur' : error.message,
    code: 'INTERNAL_SERVER_ERROR'
  });
});

// 14) 404 générique
app.use((req, res) => {
  res.status(HTTP_STATUS.NOT_FOUND).sendFile(path.join(__dirname, '../frontend/404.html'));
});

// 14) Lancement du serveur - Test environment aware
if (require.main === module) {
  const server = app.listen(port, async () => {
    console.log(`Serveur lancé sur le port ${port}`);
    
    // Skip service initialization in test environment to prevent setInterval issues
    if (process.env.NODE_ENV === 'test') {
      console.log('Test environment detected - skipping service initialization');
      app.locals.services = {}; // Initialize empty services for tests
      return;
    }
    
    // Initialize enterprise security first
    try {
      await initializeSecurity();
      console.log('Enterprise security initialized');
    } catch (error) {
      console.error('Failed to initialize enterprise security:', error.message);
    }
    
    // Skip all monitoring services in test environment
    if (process.env.NODE_ENV !== 'test') {
      // Initialize session cleanup service
      try {
        SessionConfig.initializeCleanupService();
        console.log('Session cleanup service initialized');
      } catch (error) {
        console.error('Failed to initialize session cleanup service:', error.message);
      }

      // Initialize session monitoring service
      try {
        sessionMonitoringMiddleware.initialize();
        console.log('Session monitoring service initialized');
      } catch (error) {
        console.error('Failed to initialize session monitoring service:', error.message);
      }

      // Initialize performance monitoring
      try {
        const performanceMonitor = new DBPerformanceMonitor({
          slowQueryThreshold: 100,
          sampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 1.0,
          enableProfiling: process.env.NODE_ENV === 'production',
          enableExplainAnalysis: true
        });

        const realTimeMetrics = new RealTimeMetrics(performanceMonitor, {
          windowSize: 5 * 60 * 1000, // 5 minutes
          updateInterval: 10 * 1000, // 10 seconds
          alertThresholds: {
            slowQueryRate: 0.15, // 15%
            avgExecutionTime: 150, // ms
            queryVolume: 500, // queries per minute
            indexEfficiency: 0.75 // 75%
          }
        });

        // Initialize performance alerting
        const performanceAlerting = new PerformanceAlerting(realTimeMetrics, {
          autoRemediation: process.env.NODE_ENV === 'production',
          enableEmailAlerts: false, // Disabled for now
          enableWebhooks: false,    // Disabled for now
          escalationTimeouts: {
            low: 30 * 60 * 1000,    // 30 minutes
            medium: 15 * 60 * 1000,  // 15 minutes
            high: 5 * 60 * 1000      // 5 minutes
          }
        });

        // Start monitoring
        performanceMonitor.startMonitoring();
        realTimeMetrics.startCollection();
        performanceAlerting.startAlerting();

        // Initialize hybrid index monitoring for dual auth system
        const hybridIndexMonitor = new HybridIndexMonitor({
          monitoringInterval: 30000, // 30 seconds
          slowQueryThreshold: 100,
          indexEfficiencyThreshold: 0.8,
          enableDetailedLogging: process.env.NODE_ENV !== 'production'
        });

        hybridIndexMonitor.startMonitoring();

        // Initialize admin routes with performance monitoring
        const adminRoutes = require('./routes/adminRoutes');
        adminRoutes.initializePerformanceMonitoring(performanceMonitor, realTimeMetrics);

        // Initialize V2 service monitoring for enhanced routes with full automation
        try {
          const ServiceFactory = require('./services/serviceFactory');
          const serviceFactory = ServiceFactory.create();
          
          // Initialize all services with dependency injection
          await serviceFactory.initializeServices();
          
          const { 
            contactService, 
            handshakeService, 
            invitationService, 
            submissionService,
            emailService,
            emailMonitoringService,
            schedulerService,
            realTimeMetrics: factoryRealTimeMetrics
          } = await serviceFactory.getAllServices();
          
          // Initialize performance monitoring for all v2 services
          [contactService, handshakeService, invitationService, submissionService].forEach(service => {
            if (service && typeof service.initializeMonitoring === 'function') {
              service.initializeMonitoring(performanceMonitor, realTimeMetrics);
            }
          });
          
          // Store serviceFactory globally for graceful shutdown
          app.locals.serviceFactory = serviceFactory;
          
          // Start email monitoring service in production
          if (process.env.NODE_ENV === 'production' || process.env.ENABLE_EMAIL_MONITORING === 'true') {
            emailMonitoringService.start().then(() => {
              console.log('📧 Email monitoring service started');
            }).catch(error => {
              console.warn('⚠️  Email monitoring service failed to start:', error.message);
            });
          }
          
          // Store service instances for health checks and monitoring
          app.locals.services.v2Services = {
            contactService,
            handshakeService,
            invitationService,
            submissionService
          };
        
          console.log('✅ V2 Service monitoring initialized successfully');
          console.log('✅ Contact, Handshake, Invitation, and Submission services monitoring enabled');
          console.log('✅ V2 service instances stored for health monitoring');
          
          // Initialize scheduler monitoring ecosystem
          try {
            const schedulerMonitoringFactory = SchedulerMonitoringFactory.createForEnvironment(
              process.env.NODE_ENV || 'development'
            );
            
            const schedulerMonitoringResult = await schedulerMonitoringFactory.createMonitoringEcosystem({
              schedulerService: schedulerService,
              emailService: emailService,
              dbPerformanceMonitor: performanceMonitor
            });
            
            if (schedulerMonitoringResult.success) {
              await schedulerMonitoringFactory.startMonitoringEcosystem();
              
              // Initialize scheduler monitoring routes
              initializeSchedulerMonitoringRoutes(schedulerMonitoringFactory.getServices());
              
              // Store scheduler monitoring services
              app.locals.services.schedulerMonitoring = schedulerMonitoringFactory.getServices();
              server.schedulerMonitoringFactory = schedulerMonitoringFactory;
              
              console.log('✅ Scheduler monitoring ecosystem initialized successfully');
              console.log(`✅ ${Object.keys(schedulerMonitoringFactory.getServices()).filter(s => schedulerMonitoringFactory.getServices()[s] !== null).length} monitoring services started`);
            } else {
              console.warn('⚠️  Scheduler monitoring ecosystem initialization had errors:', schedulerMonitoringResult.errors);
            }
          } catch (error) {
            console.error('❌ Failed to initialize scheduler monitoring ecosystem:', error.message);
          }
          
        } catch (error) {
          console.error('❌ Failed to initialize V2 service monitoring:', error.message);
        }

        console.log('Database performance monitoring initialized');
        console.log('Hybrid index monitoring initialized for dual auth system');
        console.log('Performance alerting system initialized');
        console.log('✅ FAF V2 API routes fully integrated with comprehensive security middleware');
        
        // Store references for graceful shutdown and admin access
        server.performanceMonitor = performanceMonitor;
        server.hybridIndexMonitor = hybridIndexMonitor;
        server.realTimeMetrics = realTimeMetrics;
        server.performanceAlerting = performanceAlerting;
        
        // Make services accessible to routes
        app.locals.services = {
          performanceMonitor,
          hybridIndexMonitor,
          realTimeMetrics,
          performanceAlerting
        };
        
      } catch (error) {
        console.error('Failed to initialize performance monitoring:', error.message);
      }
    } else {
      // In test environment, initialize minimal services
      console.log('🧪 Test mode: Skipping monitoring services to improve test performance');
      
      // Initialize minimal services required for testing
      app.locals.services = {};
    }
  });

  // Graceful shutdown - Test environment aware
  const gracefulShutdown = (signal) => {
    console.log(`${signal} received: starting graceful shutdown`);
    
    server.close(async () => {
      console.log('HTTP server closed');
      
      // Skip service shutdown in test environment
      if (process.env.NODE_ENV !== 'test') {
        try {
          // Shutdown integrated services first (highest priority)
          if (app.locals.serviceFactory) {
            console.log('Shutting down integrated automation services...');
            await app.locals.serviceFactory.shutdownServices();
            console.log('Integrated automation services shutdown completed');
          }
          
          // Shutdown cleanup service
          SessionConfig.shutdownCleanupService();
          
          // Shutdown session monitoring service
          sessionMonitoringMiddleware.shutdown();
          console.log('Session monitoring service stopped');
          
          // Shutdown performance monitoring
          if (server.performanceMonitor) {
            server.performanceMonitor.stopMonitoring();
            console.log('Performance monitoring stopped');
          }
          
          if (server.realTimeMetrics) {
            server.realTimeMetrics.stopCollection();
            console.log('Real-time metrics collection stopped');
          }

          if (server.performanceAlerting) {
            server.performanceAlerting.stopAlerting();
            console.log('Performance alerting system stopped');
          }
          
          // Shutdown scheduler monitoring ecosystem
          if (server.schedulerMonitoringFactory) {
            try {
              await server.schedulerMonitoringFactory.stopMonitoringEcosystem();
              console.log('Scheduler monitoring ecosystem stopped');
            } catch (error) {
              console.error('Error stopping scheduler monitoring ecosystem:', error.message);
            }
          }

          // Shutdown hybrid index monitoring
          if (server.hybridIndexMonitor) {
            server.hybridIndexMonitor.stopMonitoring();
            console.log('Hybrid index monitoring stopped');
          }
        } catch (shutdownError) {
          console.error('Error during service shutdown:', shutdownError);
        }
      } else {
        console.log('Test environment detected - skipping service shutdown');
      }
      
      // Close database connection only if not managed by tests
      if (process.env.NODE_ENV !== 'test') {
        try {
          await mongoose.connection.close();
          console.log('MongoDB connection closed');
          process.exit(0);
        } catch (error) {
          console.error('Error closing MongoDB connection:', error);
          process.exit(1);
        }
      } else {
        console.log('Test environment - leaving MongoDB connection for test management');
        process.exit(0);
      }
    });
    
    // Force shutdown after 10 seconds
    setTimeout(() => {
      console.error('Forcing shutdown after timeout');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

module.exports = app;
