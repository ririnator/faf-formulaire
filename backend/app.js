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
const authRoutes     = require('./routes/authRoutes');
const uploadRoutes   = require('./routes/upload');
const Response       = require('./models/Response');
const { HTTP_STATUS, APP_CONSTANTS } = require('./constants');
const TemplateRenderer = require('./utils/templateRenderer');
const { ensureAdmin, authenticateAdmin, destroySession } = require('./middleware/auth');
const { createSecurityMiddleware, createSessionOptions } = require('./middleware/security');
const { createStandardBodyParser, createPayloadErrorHandler } = require('./middleware/bodyParser');
const { csrfTokenMiddleware } = require('./middleware/csrf');
const SessionConfig = require('./config/session');
const sessionMonitoringMiddleware = require('./middleware/sessionMonitoring');
const DBPerformanceMonitor = require('./services/dbPerformanceMonitor');
const HybridIndexMonitor = require('./services/hybridIndexMonitor');
const RealTimeMetrics = require('./services/realTimeMetrics');
const PerformanceAlerting = require('./services/performanceAlerting');

const app  = express();
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

// 3) Enhanced Sessions with better dev/prod handling
app.use(session(createSessionOptions()));

// 3.2) Session monitoring for security
app.use(sessionMonitoringMiddleware.trackSessionCreation());
app.use(sessionMonitoringMiddleware.trackSessionDestruction());
app.use(sessionMonitoringMiddleware.trackFailedLogins());

// 3.5) CSRF Token generation for admin routes
app.use(csrfTokenMiddleware());

// 4) Optimized Body Parsers (512KB standard limit)
app.use(createStandardBodyParser());
app.use(createPayloadErrorHandler());

// 5) Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("Connecté à la base de données");
    
    // Index for performance (chronological sorting)
    await mongoose.connection.collection('responses')
      .createIndex({ createdAt: -1 });
    console.log("Index créé sur responses.createdAt");
    
    // Unique constraint to prevent admin duplicates per month
    await mongoose.connection.collection('responses')
      .createIndex(
        { month: 1, isAdmin: 1 }, 
        { unique: true, partialFilterExpression: { isAdmin: true } }
      );
    console.log("Index unique créé sur responses.{month, isAdmin} avec filtre admin");
  })
  .catch(err => console.error("Erreur de connexion à la DB :", err));

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
app.use(express.static(path.join(__dirname, '../frontend/public')));

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
  res.sendFile(path.join(__dirname, '../frontend/public/admin-login.html'));
});

// Routes legacy admin with session security
app.post('/login', sessionMonitoringMiddleware.blockSuspiciousSessions(), authenticateAdmin);
app.get('/logout', destroySession);

// 8) Back-office Admin (HTML + assets)
// Dashboard route that redirects to the admin interface
app.get('/dashboard', ensureAdmin, (req, res) => {
  res.redirect('/admin');
});

app.get('/admin', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/admin.html'));
});
app.get('/admin/gestion', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/admin_gestion.html'));
});

// Assets admin (faf-admin.js module, CSS, images, etc.) - accessible si session admin active
app.use('/admin', ensureAdmin, (req, res, next) => {
  // Set proper MIME type for JavaScript modules
  if (req.path.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
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
      console.log('Sending response:', JSON.stringify(response, null, 2));
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

// 9) API Admin
app.use('/api/admin', ensureAdmin, adminRoutes);

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
  message: { message: "Trop de soumissions. Réessaie dans 15 minutes." }
});
app.use('/api/response', formLimiter);

// 12) API publiques
app.use('/api/auth', authRoutes);
app.use('/api/form', formRoutes);
app.use('/api/response', responseRoutes);
app.use('/api/upload', uploadRoutes);

// 13) Servir la page view.html pour /view/:token
app.get('/view/:token', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/view.html'));
});

// 14) 404 générique
app.use((req, res) => {
  res.status(HTTP_STATUS.NOT_FOUND).sendFile(path.join(__dirname, '../frontend/404.html'));
});

// 14) Lancement du serveur
if (require.main === module) {
  const server = app.listen(port, () => {
    console.log(`Serveur lancé sur le port ${port}`);
    
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

      console.log('Database performance monitoring initialized');
      console.log('Hybrid index monitoring initialized for dual auth system');
      console.log('Performance alerting system initialized');
      
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
  });

  // Graceful shutdown
  const gracefulShutdown = (signal) => {
    console.log(`${signal} received: starting graceful shutdown`);
    
    server.close(async () => {
      console.log('HTTP server closed');
      
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

      // Shutdown hybrid index monitoring
      if (server.hybridIndexMonitor) {
        server.hybridIndexMonitor.stopMonitoring();
        console.log('Hybrid index monitoring stopped');
      }
      
      // Close database connection
      try {
        await mongoose.connection.close();
        console.log('MongoDB connection closed');
        process.exit(0);
      } catch (error) {
        console.error('Error closing MongoDB connection:', error);
        process.exit(1);
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
