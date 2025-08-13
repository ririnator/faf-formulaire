const bcrypt = require('bcrypt');

const LOGIN_ADMIN_USER = process.env.LOGIN_ADMIN_USER;
const LOGIN_ADMIN_PASS = process.env.LOGIN_ADMIN_PASS;
const ADMIN_IP_WHITELIST = process.env.ADMIN_IP_WHITELIST;

// Protection contre force brute - stockage en mémoire (pour démo)
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes
const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes

function ensureAdmin(req, res, next) {
  // Support both legacy admin sessions and new user-based admin sessions
  const isLegacyAdmin = req.session?.isAdmin;
  const isNewAdmin = req.session?.user?.role === 'admin';
  
  if (isLegacyAdmin || isNewAdmin) {
    // Vérifier timeout de session (pour legacy admin seulement)
    if (isLegacyAdmin) {
      const sessionAge = Date.now() - (req.session.adminLoginTime || 0);
      if (sessionAge > SESSION_TIMEOUT) {
        logSecurityEvent('ADMIN_SESSION_TIMEOUT', { 
          ip: req.session.adminIP, 
          sessionAge: Math.ceil(sessionAge / 1000) 
        });
        req.session.destroy();
        return res.redirect('/login?timeout=1');
      }
    }
    
    // Vérifier IP consistency (pour legacy admin seulement)  
    if (isLegacyAdmin) {
      const currentIP = req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress;
      if (req.session.adminIP && req.session.adminIP !== currentIP) {
        logSecurityEvent('ADMIN_SESSION_IP_CHANGE', { 
          originalIP: req.session.adminIP, 
          newIP: currentIP 
        });
        req.session.destroy();
        return res.redirect('/login?security=1');
      }
    }
    
    return next();
  }
  return res.redirect('/login');
}

async function authenticateAdmin(req, res, next) {
  try {
    const { username, password } = req.body;
    const clientIP = req.ip || req.socket?.remoteAddress || req.connection?.remoteAddress;
    const userAgent = req.get('User-Agent') || 'unknown';
    
    // Validation des entrées
    if (!username || !password) {
      logSecurityEvent('ADMIN_LOGIN_INVALID_INPUT', { ip: clientIP, userAgent });
      return res.redirect('/login?error=1');
    }
    
    // Vérification IP whitelist (optionnel)
    if (ADMIN_IP_WHITELIST && !isIPWhitelisted(clientIP)) {
      logSecurityEvent('ADMIN_LOGIN_IP_BLOCKED', { ip: clientIP, userAgent, username });
      return res.status(403).json({ error: 'Access denied from this IP' });
    }
    
    // Protection contre force brute
    const attemptKey = `${clientIP}_${username}`;
    const attempts = loginAttempts.get(attemptKey);
    
    if (attempts && attempts.count >= MAX_LOGIN_ATTEMPTS) {
      const timeLeft = LOCKOUT_TIME - (Date.now() - attempts.lastAttempt);
      if (timeLeft > 0) {
        logSecurityEvent('ADMIN_LOGIN_RATE_LIMITED', { 
          ip: clientIP, 
          username, 
          attempts: attempts.count,
          timeLeft: Math.ceil(timeLeft / 1000)
        });
        return res.status(429).json({ 
          error: 'Too many login attempts', 
          retryAfter: Math.ceil(timeLeft / 1000) 
        });
      } else {
        // Reset après expiration du lockout
        loginAttempts.delete(attemptKey);
      }
    }
    
    // Vérification des credentials
    const isValidAuth = username === LOGIN_ADMIN_USER && await bcrypt.compare(password, LOGIN_ADMIN_PASS);
    
    if (isValidAuth) {
      // Authentification réussie
      loginAttempts.delete(attemptKey); // Reset tentatives
      
      req.session.isAdmin = true;
      req.session.adminLoginTime = Date.now();
      req.session.adminIP = clientIP;
      req.session.adminUserAgent = userAgent;
      
      logSecurityEvent('ADMIN_LOGIN_SUCCESS', { ip: clientIP, userAgent });
      return res.redirect('/admin');
    } else {
      // Authentification échouée
      const currentAttempts = attempts ? attempts.count + 1 : 1;
      loginAttempts.set(attemptKey, {
        count: currentAttempts,
        lastAttempt: Date.now()
      });
      
      logSecurityEvent('ADMIN_LOGIN_FAILED', { 
        ip: clientIP, 
        username, 
        attempts: currentAttempts,
        userAgent 
      });
      
      return res.redirect('/login?error=1');
    }
  } catch (error) {
    console.error('Authentication error:', error);
    logSecurityEvent('ADMIN_LOGIN_ERROR', { 
      ip: req.ip, 
      error: error.message 
    });
    return res.redirect('/login?error=1');
  }
}

function destroySession(req, res) {
  const adminIP = req.session?.adminIP;
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
    } else {
      logSecurityEvent('ADMIN_LOGOUT', { ip: adminIP });
    }
    res.clearCookie('faf-session');
    res.redirect('/login');
  });
}

// Fonctions utilitaires de sécurité
function logSecurityEvent(eventType, data) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    event: eventType,
    ...data
  };
  
  // Log sécurisé - ne pas exposer de données sensibles
  if (process.env.NODE_ENV === 'production') {
    console.warn('🔐 SECURITY_EVENT:', JSON.stringify(logEntry));
  } else {
    console.log('🔐 SECURITY_EVENT:', logEntry);
  }
  
  // TODO: En production, envoyer vers un système de logging sécurisé
  // comme Elasticsearch, Splunk, ou service cloud
}

function isIPWhitelisted(ip) {
  if (!ADMIN_IP_WHITELIST) return true;
  
  const allowedIPs = ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
  return allowedIPs.includes(ip) || allowedIPs.includes('127.0.0.1'); // localhost toujours autorisé
}

// Cleanup périodique des tentatives expirées
setInterval(() => {
  const now = Date.now();
  for (const [key, attempt] of loginAttempts.entries()) {
    if (now - attempt.lastAttempt > LOCKOUT_TIME) {
      loginAttempts.delete(key);
    }
  }
}, 5 * 60 * 1000); // Cleanup toutes les 5 minutes

module.exports = {
  ensureAdmin,
  authenticateAdmin,
  destroySession
};