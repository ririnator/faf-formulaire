const User = require('../models/User');
const SecureLogger = require('../utils/secureLogger');
const SessionConfig = require('../config/session');

// Middleware pour détecter la méthode d'authentification
function detectAuthMethod(req, res, next) {
  // 1. Vérifier session utilisateur d'abord (nouveau système)
  if (req.session?.userId) {
    req.authMethod = 'user';
    req.currentUser = req.session.user;
    return next();
  }
  
  // 2. Fallback sur système token (compatibilité legacy)
  if (req.params.token || req.query.token) {
    req.authMethod = 'token';
    req.viewToken = req.params.token || req.query.token;
    return next();
  }
  
  // 3. Pas d'auth détectée
  req.authMethod = 'none';
  next();
}

// Middleware pour exiger une authentification (n'importe laquelle)
function requireAuth(req, res, next) {
  if (req.authMethod === 'none') {
    // Rediriger vers la page de choix d'authentification
    if (req.accepts('html')) {
      return res.redirect('/auth-choice');
    } else {
      return res.status(401).json({
        error: 'Authentification requise',
        authOptions: {
          login: '/api/auth/login',
          register: '/api/auth/register',
          guestMode: 'legacy'
        }
      });
    }
  }
  next();
}

// Middleware pour les utilisateurs connectés uniquement (nouveau système)
function requireUserAuth(req, res, next) {
  if (req.authMethod !== 'user' || !req.currentUser) {
    // For API endpoints (start with /api/), always return JSON
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required - user account needed',
        message: 'Cette fonctionnalité nécessite un compte utilisateur'
      });
    }
    
    // For non-API requests, check Accept header
    if (req.accepts('html')) {
      return res.redirect('/login');
    } else {
      return res.status(401).json({
        success: false,
        error: 'Authentication required - user account needed',
        message: 'Cette fonctionnalité nécessite un compte utilisateur'
      });
    }
  }
  next();
}

// Middleware intelligent pour l'accès admin
function requireAdminAccess(req, res, next) {
  // Admin moderne (avec compte User.role = 'admin')
  if (req.authMethod === 'user' && req.currentUser?.role === 'admin') {
    return next();
  }
  
  // Admin legacy (session isAdmin pour compatibilité)
  if (req.session?.isAdmin) {
    req.authMethod = 'legacy-admin';
    return next();
  }
  
  if (req.accepts('html')) {
    return res.redirect('/admin-login');
  } else {
    return res.status(403).json({
      error: 'Accès administrateur requis'
    });
  }
}

// Middleware pour valider et enrichir les données utilisateur
async function enrichUserData(req, res, next) {
  if (req.authMethod === 'user' && req.session?.userId) {
    try {
      // Recharger les données utilisateur depuis la DB si nécessaire
      const user = await User.findById(req.session.userId)
        .select('-password');
      
      if (!user || !user.metadata.isActive) {
        // User supprimé ou désactivé
        req.session.destroy();
        req.authMethod = 'none';
        req.currentUser = null;
      } else {
        // Mettre à jour les données en session si nécessaire
        req.currentUser = user.toPublicJSON();
        req.session.user = req.currentUser;
        
        // Update last activity for session renewal
        req.session.lastActivity = Date.now();
      }
    } catch (error) {
      SecureLogger.logError('Error enriching user data', error);
      // Continuer sans enrichissement en cas d'erreur DB
    }
  }
  next();
}

// Middleware pour obtenir les données de réponse selon le mode d'auth
function getResponseAccess(req, res, next) {
  if (req.authMethod === 'user') {
    // Accès par userId
    req.responseQuery = { userId: req.currentUser.id };
  } else if (req.authMethod === 'token') {
    // Accès par token legacy
    req.responseQuery = { token: req.viewToken };
  } else {
    return res.status(401).json({
      error: 'Méthode d\'authentification requise pour accéder aux réponses'
    });
  }
  next();
}

// Middleware pour log et analytics (sécurisé)
function logAuthMethod(req, res, next) {
  // Only log aggregated metrics, not individual user paths
  if (process.env.NODE_ENV === 'development' && process.env.VERBOSE_AUTH_LOGS === 'true') {
    // Only log auth method statistics, not paths that could identify users
    SecureLogger.logAuth(req.method, 'REDACTED', req.authMethod);
  }
  
  // In production, only increment counters without logging
  if (process.env.NODE_ENV === 'production') {
    // Could increment metrics here without logging sensitive data
    // e.g., authMethodCounters[req.authMethod]++;
  }
  
  next();
}

// Session fixation protection middleware
function protectAgainstSessionFixation(req, res, next) {
  // Regenerate session ID on privilege escalation
  if (req.session && (req.session.isAdmin || req.session.userId)) {
    const wasAuthenticated = req.session.authenticated;
    
    if (!wasAuthenticated && req.session.userId) {
      // User just authenticated, regenerate session ID
      return SessionConfig.regenerateSession()(req, res, () => {
        req.session.authenticated = true;
        SecureLogger.logInfo('Session regenerated after authentication', {
          userId: req.session.userId.toString().substring(0, 8) + '...',
          newSessionId: req.sessionID.substring(0, 8) + '...'
        });
        next();
      });
    }
  }
  next();
}

// Enhanced session validation for sensitive operations
function requireSecureSession(req, res, next) {
  if (!req.session || !req.sessionID) {
    return res.status(401).json({
      error: 'Session required for this operation',
      code: 'NO_SESSION'
    });
  }
  
  // Check session age for sensitive operations
  const sessionAge = Date.now() - (req.session.createdAt || 0);
  const maxSessionAge = 2 * 60 * 60 * 1000; // 2 hours for sensitive operations
  
  if (sessionAge > maxSessionAge) {
    SecureLogger.logWarning('Session too old for sensitive operation', {
      sessionId: req.sessionID.substring(0, 8) + '...',
      ageHours: Math.floor(sessionAge / (60 * 60 * 1000))
    });
    
    req.session.destroy();
    return res.status(401).json({
      error: 'Session expired. Please log in again.',
      code: 'SESSION_TOO_OLD'
    });
  }
  
  next();
}

// Middleware for universal dashboard access (both users and admins)
function requireDashboardAccess(req, res, next) {
  // Check for authenticated user (new system)
  if (req.authMethod === 'user' && req.currentUser) {
    return next();
  }
  
  // Check for legacy admin session
  if (req.session?.isAdmin) {
    req.authMethod = 'legacy-admin';
    return next();
  }
  
  // No valid authentication found
  // Improved API detection for consistent JSON responses
  const isApiRequest = req.path.startsWith('/api/') || 
                      req.xhr || 
                      req.headers.accept?.includes('application/json') ||
                      req.headers['content-type']?.includes('application/json');
  
  if (isApiRequest) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required for dashboard access',
      message: 'Veuillez vous connecter pour accéder au tableau de bord'
    });
  } else {
    return res.redirect('/login');
  }
}

// Enhanced privilege validation
function validatePrivilegeEscalation(req, res, next) {
  // Check for suspicious privilege changes
  if (req.session) {
    const currentPrivileges = {
      isAdmin: req.session.isAdmin || false,
      userId: req.session.userId || null,
      role: req.currentUser?.role || 'guest'
    };
    
    const previousPrivileges = req.session.previousPrivileges || {};
    
    // Detect privilege escalation
    if (!previousPrivileges.isAdmin && currentPrivileges.isAdmin) {
      SecureLogger.logWarning('Admin privilege escalation detected', {
        sessionId: req.sessionID.substring(0, 8) + '...',
        userId: currentPrivileges.userId ? currentPrivileges.userId.toString().substring(0, 8) + '...' : 'anonymous',
        ip: req.ip
      });
      
      // Force session regeneration on privilege escalation
      return SessionConfig.regenerateSession()(req, res, () => {
        req.session.previousPrivileges = currentPrivileges;
        next();
      });
    }
    
    // Store current privileges for next request
    req.session.previousPrivileges = currentPrivileges;
  }
  
  next();
}

module.exports = {
  detectAuthMethod,
  requireAuth,
  requireUserAuth,
  requireAdminAccess,
  requireDashboardAccess,
  enrichUserData,
  getResponseAccess,
  logAuthMethod,
  protectAgainstSessionFixation,
  requireSecureSession,
  validatePrivilegeEscalation
};