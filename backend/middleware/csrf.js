// middleware/csrf.js
const crypto = require('crypto');
const TokenGenerator = require('../utils/tokenGenerator');

/**
 * Middleware CSRF simple pour les opérations sensibles
 * Génère et valide les tokens CSRF
 */

/**
 * Génère un token CSRF et l'ajoute à la session
 */
function generateCSRFToken(req) {
  if (!req.session) {
    throw new Error('Session middleware required for CSRF protection');
  }
  
  const token = TokenGenerator.generateCSRFToken();
  req.session.csrfToken = token;
  req.session.csrfTokenTimestamp = Date.now();
  return token;
}

/**
 * Middleware pour générer et exposer le token CSRF
 */
function csrfTokenMiddleware() {
  return (req, res, next) => {
    // Générer un nouveau token si pas présent
    if (!req.session.csrfToken) {
      generateCSRFToken(req);
    }
    
    // Exposer le token dans res.locals pour les templates
    res.locals.csrfToken = req.session.csrfToken;
    
    next();
  };
}

/**
 * Middleware pour valider le token CSRF sur les requêtes sensibles
 * Enhanced with comprehensive security checks and attack prevention
 */
function csrfProtection(options = {}) {
  const { 
    methods = ['POST', 'PUT', 'DELETE', 'PATCH'],
    headerName = 'x-csrf-token',
    bodyName = '_csrf',
    skipForPublic = false, // Option to explicitly skip for public routes
    requireHttps = process.env.NODE_ENV === 'production', // Require HTTPS in production
    checkOrigin = true, // Validate request origin
    maxTokenAge = 3600000 // 1 hour token validity
  } = options;
  
  return (req, res, next) => {
    // Skip pour les méthodes non-sensibles
    if (!methods.includes(req.method)) {
      return next();
    }
    
    // Enhanced security checks for production
    if (requireHttps && req.protocol !== 'https' && process.env.NODE_ENV === 'production') {
      console.warn('CSRF Protection: HTTPS required', {
        method: req.method,
        path: req.path,
        protocol: req.protocol,
        ip: req.ip,
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({ 
        error: 'HTTPS required for secure operations', 
        code: 'HTTPS_REQUIRED' 
      });
    }
    
    // Origin validation for CSRF prevention
    if (checkOrigin) {
      const origin = req.get('Origin') || req.get('Referer');
      const host = req.get('Host');
      
      if (origin && host) {
        try {
          const originHost = new URL(origin).host;
          if (originHost !== host) {
            console.warn('CSRF Protection: Origin mismatch', {
              method: req.method,
              path: req.path,
              origin,
              host,
              ip: req.ip,
              timestamp: new Date().toISOString()
            });
            
            return res.status(403).json({ 
              error: 'Origin validation failed', 
              code: 'ORIGIN_MISMATCH' 
            });
          }
        } catch (error) {
          console.warn('CSRF Protection: Invalid origin header', {
            method: req.method,
            path: req.path,
            origin,
            error: error.message,
            ip: req.ip,
            timestamp: new Date().toISOString()
          });
          
          return res.status(403).json({ 
            error: 'Invalid origin header', 
            code: 'INVALID_ORIGIN' 
          });
        }
      }
    }
    
    // Skip seulement si explicitement demandé pour routes publiques
    if (skipForPublic === true) {
      return next();
    }
    
    // SECURITY FIX: Require CSRF protection for ALL authenticated users
    // Skip seulement si aucune session n'existe (routes vraiment publiques)
    if (!req.session) {
      console.warn('CSRF Protection: No session found', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        timestamp: new Date().toISOString()
      });
      return next();
    }
    
    // Valider la présence d'une session authentifiée (admin OU utilisateur)
    const isAuthenticated = req.session.isAdmin || 
                           req.session.userId || 
                           req.currentUser ||
                           req.user;
    
    if (!isAuthenticated) {
      return next();
    }
    
    const sessionToken = req.session.csrfToken;
    const tokenTimestamp = req.session.csrfTokenTimestamp;
    
    if (!sessionToken) {
      // Enhanced security logging
      console.warn('CSRF Protection: Missing session token', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.session.userId || 'unknown',
        isAdmin: !!req.session.isAdmin,
        sessionId: req.sessionID?.substring(0, 8) + '...',
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({ 
        error: 'Token CSRF manquant dans la session', 
        code: 'CSRF_SESSION_MISSING' 
      });
    }
    
    // Check token age
    if (tokenTimestamp && (Date.now() - tokenTimestamp > maxTokenAge)) {
      console.warn('CSRF Protection: Token expired', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        tokenAge: Date.now() - tokenTimestamp,
        maxAge: maxTokenAge,
        timestamp: new Date().toISOString()
      });
      
      // Regenerate token for next use
      req.session.csrfToken = TokenGenerator.generateCSRFToken();
      req.session.csrfTokenTimestamp = Date.now();
      
      return res.status(403).json({ 
        error: 'Token CSRF expiré', 
        code: 'CSRF_TOKEN_EXPIRED',
        newToken: req.session.csrfToken
      });
    }
    
    // Récupérer le token depuis header ou body
    const clientToken = req.get(headerName) || req.body[bodyName];
    
    if (!clientToken) {
      // Enhanced security logging
      console.warn('CSRF Protection: Missing client token', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.session.userId || 'unknown',
        isAdmin: !!req.session.isAdmin,
        hasHeader: !!req.get(headerName),
        hasBody: !!req.body[bodyName],
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({ 
        error: 'Token CSRF requis pour cette opération', 
        code: 'CSRF_TOKEN_MISSING' 
      });
    }
    
    // Validate token format
    if (!TokenGenerator.validateToken(clientToken, 'csrf')) {
      console.warn('CSRF Protection: Invalid token format', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        tokenLength: clientToken.length,
        tokenPrefix: clientToken.substring(0, 8),
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({ 
        error: 'Format de token CSRF invalide', 
        code: 'CSRF_TOKEN_MALFORMED' 
      });
    }
    
    // Validation du token (comparaison sécurisée)
    try {
      if (!crypto.timingSafeEqual(
        Buffer.from(sessionToken, 'hex'), 
        Buffer.from(clientToken, 'hex')
      )) {
        throw new Error('Token mismatch');
      }
    } catch (error) {
      // Enhanced security logging for invalid tokens
      console.warn('CSRF Protection: Invalid token', {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.session.userId || 'unknown',
        isAdmin: !!req.session.isAdmin,
        error: error.message,
        sessionTokenPrefix: sessionToken?.substring(0, 8),
        clientTokenPrefix: clientToken?.substring(0, 8),
        timestamp: new Date().toISOString()
      });
      
      return res.status(403).json({ 
        error: 'Token CSRF invalide', 
        code: 'CSRF_TOKEN_INVALID' 
      });
    }
    
    // Add security headers for successful validation
    res.setHeader('X-CSRF-Protected', 'true');
    
    next();
  };
}

/**
 * Créer une protection CSRF pour les routes publiques
 * Ces routes n'ont pas d'authentification requise mais peuvent toujours bénéficier de CSRF protection
 */
function csrfProtectionPublic(options = {}) {
  return csrfProtection({ 
    ...options, 
    skipForPublic: true 
  });
}

/**
 * Créer une protection CSRF stricte pour toutes les routes authentifiées
 * Applique la validation CSRF à tous les utilisateurs connectés (admin ET utilisateurs)
 */
function csrfProtectionStrict(options = {}) {
  return csrfProtection({ 
    ...options, 
    skipForPublic: false 
  });
}

/**
 * Endpoint pour récupérer le token CSRF actuel
 */
function csrfTokenEndpoint() {
  return (req, res) => {
    if (!req.session) {
      return res.status(500).json({ 
        error: 'Session non initialisée', 
        code: 'SESSION_ERROR' 
      });
    }
    
    // Générer un nouveau token si nécessaire
    const token = req.session.csrfToken || generateCSRFToken(req);
    
    res.json({ 
      token,
      headerName: 'x-csrf-token'
    });
  };
}

module.exports = {
  generateCSRFToken,
  csrfTokenMiddleware,
  csrfProtection,
  csrfProtectionPublic,
  csrfProtectionStrict,
  csrfTokenEndpoint
};