const User = require('../models/User');
const SecureLogger = require('../utils/secureLogger');

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
    if (req.accepts('html')) {
      return res.redirect('/login');
    } else {
      return res.status(401).json({
        error: 'Compte utilisateur requis',
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

module.exports = {
  detectAuthMethod,
  requireAuth,
  requireUserAuth,
  requireAdminAccess,
  enrichUserData,
  getResponseAccess,
  logAuthMethod
};