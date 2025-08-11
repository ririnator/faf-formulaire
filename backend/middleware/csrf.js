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
 */
function csrfProtection(options = {}) {
  const { 
    methods = ['POST', 'PUT', 'DELETE', 'PATCH'],
    headerName = 'x-csrf-token',
    bodyName = '_csrf'
  } = options;
  
  return (req, res, next) => {
    // Skip pour les méthodes non-sensibles
    if (!methods.includes(req.method)) {
      return next();
    }
    
    // Skip pour les routes API publiques (sans session admin)
    if (!req.session || !req.session.isAdmin) {
      return next();
    }
    
    const sessionToken = req.session.csrfToken;
    if (!sessionToken) {
      return res.status(403).json({ 
        error: 'Token CSRF manquant dans la session', 
        code: 'CSRF_SESSION_MISSING' 
      });
    }
    
    // Récupérer le token depuis header ou body
    const clientToken = req.get(headerName) || req.body[bodyName];
    
    if (!clientToken) {
      return res.status(403).json({ 
        error: 'Token CSRF requis pour cette opération', 
        code: 'CSRF_TOKEN_MISSING' 
      });
    }
    
    // Validation du token (comparaison sécurisée)
    if (!crypto.timingSafeEqual(
      Buffer.from(sessionToken, 'hex'), 
      Buffer.from(clientToken, 'hex')
    )) {
      return res.status(403).json({ 
        error: 'Token CSRF invalide', 
        code: 'CSRF_TOKEN_INVALID' 
      });
    }
    
    next();
  };
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
  csrfTokenEndpoint
};