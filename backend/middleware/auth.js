const bcrypt = require('bcrypt');
const crypto = require('crypto');
const SecureLogger = require('../utils/secureLogger');

const LOGIN_ADMIN_USER = process.env.LOGIN_ADMIN_USER;
const LOGIN_ADMIN_PASS = process.env.LOGIN_ADMIN_PASS;
const ADMIN_IP_WHITELIST = process.env.ADMIN_IP_WHITELIST;

// Advanced authentication security configuration
const AUTH_CONFIG = {
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_TIME: 15 * 60 * 1000, // 15 minutes
  SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
  PROGRESSIVE_DELAY: true,
  MAX_SESSIONS_PER_IP: 3,
  REQUIRE_SECURE_HEADERS: true,
  ENABLE_SESSION_FINGERPRINTING: true,
  SESSION_ROTATION_INTERVAL: 10 * 60 * 1000, // 10 minutes
  SUSPICIOUS_ACTIVITY_THRESHOLD: 10
};

// Enhanced security tracking
const loginAttempts = new Map();
const sessionFingerprints = new Map();
const suspiciousActivities = new Map();
const activeAdminSessions = new Map();

/**
 * Enhanced admin access verification with comprehensive security checks
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
async function ensureAdmin(req, res, next) {
  // Support both legacy admin sessions and new user-based admin sessions
  const isLegacyAdmin = req.session?.isAdmin;
  const isNewAdmin = req.session?.user?.role === 'admin';
  
  if (isLegacyAdmin || isNewAdmin) {
    const currentIP = getClientIP(req);
    const currentUserAgent = req.get('User-Agent') || 'unknown';
    const currentFingerprint = generateRequestFingerprint(req);
    
    // Enhanced session validation for legacy admin
    if (isLegacyAdmin) {
      // Session timeout validation
      const sessionAge = Date.now() - (req.session.adminLoginTime || 0);
      if (sessionAge > AUTH_CONFIG.SESSION_TIMEOUT) {
        await logSecurityEvent('ADMIN_SESSION_TIMEOUT', { 
          ip: maskIP(req.session.adminIP), 
          sessionAge: Math.ceil(sessionAge / 1000),
          sessionId: req.session.sessionId?.substring(0, 16)
        });
        await destroySessionSecurely(req);
        return res.redirect('/admin-login?timeout=1');
      }
      
      // Enhanced IP consistency check
      if (req.session.adminIP && req.session.adminIP !== currentIP) {
        await logSecurityEvent('ADMIN_SESSION_IP_CHANGE', { 
          originalIP: maskIP(req.session.adminIP), 
          newIP: maskIP(currentIP),
          sessionId: req.session.sessionId?.substring(0, 16)
        });
        await destroySessionSecurely(req);
        return res.redirect('/admin-login?security=1');
      }
      
      // User agent consistency check
      if (req.session.adminUserAgent && req.session.adminUserAgent !== currentUserAgent) {
        await logSecurityEvent('ADMIN_SESSION_UA_CHANGE', {
          originalUA: req.session.adminUserAgent.substring(0, 100),
          newUA: currentUserAgent.substring(0, 100),
          sessionId: req.session.sessionId?.substring(0, 16)
        });
        // Less strict than IP change, but log for monitoring
      }
      
      // Advanced fingerprint validation
      if (AUTH_CONFIG.ENABLE_SESSION_FINGERPRINTING && req.session.fingerprint) {
        const fingerprintSimilarity = calculateFingerprintSimilarity(req.session.fingerprint, currentFingerprint);
        if (fingerprintSimilarity < 0.7) { // 70% similarity threshold
          await logSecurityEvent('ADMIN_SESSION_FINGERPRINT_MISMATCH', {
            similarity: fingerprintSimilarity,
            sessionId: req.session.sessionId?.substring(0, 16),
            ip: maskIP(currentIP)
          });
          await destroySessionSecurely(req);
          return res.redirect('/admin-login?security=1');
        }
      }
      
      // Session rotation check
      const timeSinceLogin = Date.now() - (req.session.adminLoginTime || 0);
      const lastActivity = req.session.lastActivity || req.session.adminLoginTime;
      const timeSinceActivity = Date.now() - lastActivity;
      
      if (timeSinceLogin > AUTH_CONFIG.SESSION_ROTATION_INTERVAL && 
          timeSinceActivity < AUTH_CONFIG.SESSION_ROTATION_INTERVAL / 2) {
        // Rotate session for long-running active sessions
        await rotateSession(req);
      }
      
      // Update last activity
      req.session.lastActivity = Date.now();
      
      // Update active session tracking
      if (req.session.sessionId && activeAdminSessions.has(req.session.sessionId)) {
        const sessionData = activeAdminSessions.get(req.session.sessionId);
        sessionData.lastActivity = Date.now();
        activeAdminSessions.set(req.session.sessionId, sessionData);
      }
    }
    
    return next();
  }
  return res.redirect('/admin-login');
}

async function authenticateAdmin(req, res, next) {
  try {
    const { username, password } = req.body;
    const clientIP = getClientIP(req);
    const userAgent = req.get('User-Agent') || 'unknown';
    const requestFingerprint = generateRequestFingerprint(req);
    
    // Advanced input validation
    const validationResult = validateAuthenticationInput(username, password, req);
    if (!validationResult.valid) {
      await logSecurityEvent('ADMIN_LOGIN_INVALID_INPUT', { 
        ip: maskIP(clientIP), 
        userAgent: userAgent.substring(0, 100),
        reason: validationResult.reason,
        fingerprint: requestFingerprint.substring(0, 16)
      });
      await applyProgressiveDelay(clientIP, 'invalid_input');
      return res.redirect('/login?error=1');
    }
    
    // Enhanced suspicious activity detection
    if (await isSuspiciousActivity(clientIP, userAgent, req)) {
      await logSecurityEvent('ADMIN_LOGIN_SUSPICIOUS_ACTIVITY', { 
        ip: maskIP(clientIP),
        userAgent: userAgent.substring(0, 100),
        indicators: getSuspiciousIndicators(req)
      });
      return res.status(403).json({ error: 'Access denied - suspicious activity detected' });
    }
    
    // Advanced IP whitelist validation
    if (ADMIN_IP_WHITELIST && !isIPWhitelisted(clientIP)) {
      await logSecurityEvent('ADMIN_LOGIN_IP_BLOCKED', { 
        ip: maskIP(clientIP), 
        userAgent: userAgent.substring(0, 100), 
        username: username.substring(0, 20)
      });
      return res.status(403).json({ error: 'Access denied from this IP' });
    }
    
    // Enhanced brute force protection with progressive delays
    const attemptKey = `${clientIP}_${username}`;
    const attempts = loginAttempts.get(attemptKey);
    
    if (attempts && attempts.count >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
      const timeLeft = AUTH_CONFIG.LOCKOUT_TIME - (Date.now() - attempts.lastAttempt);
      if (timeLeft > 0) {
        await logSecurityEvent('ADMIN_LOGIN_RATE_LIMITED', { 
          ip: maskIP(clientIP), 
          username: username.substring(0, 20), 
          attempts: attempts.count,
          timeLeft: Math.ceil(timeLeft / 1000),
          progressiveDelay: attempts.progressiveDelay || 0
        });
        await applyProgressiveDelay(clientIP, 'rate_limited', attempts.count);
        return res.status(429).json({ 
          error: 'Too many login attempts', 
          retryAfter: Math.ceil(timeLeft / 1000) 
        });
      } else {
        // Reset after lockout expiration
        loginAttempts.delete(attemptKey);
      }
    }
    
    // Advanced session limit enforcement
    const activeSessionCount = getActiveSessionCount(clientIP);
    if (activeSessionCount >= AUTH_CONFIG.MAX_SESSIONS_PER_IP) {
      await logSecurityEvent('ADMIN_LOGIN_TOO_MANY_SESSIONS', {
        ip: maskIP(clientIP),
        activeSessions: activeSessionCount,
        maxAllowed: AUTH_CONFIG.MAX_SESSIONS_PER_IP
      });
      return res.status(429).json({ error: 'Too many active sessions from this IP' });
    }
    
    // Enhanced credential verification with timing attack protection
    const authStartTime = Date.now();
    const isValidAuth = await verifyCredentialsSecurely(username, password);
    const authDuration = Date.now() - authStartTime;
    
    // Ensure minimum processing time to prevent timing attacks
    const minProcessingTime = 100; // 100ms minimum
    if (authDuration < minProcessingTime) {
      await new Promise(resolve => setTimeout(resolve, minProcessingTime - authDuration));
    }
    
    if (isValidAuth) {
      // Successful authentication with enhanced session security
      loginAttempts.delete(attemptKey); // Reset attempts
      
      const sessionId = crypto.randomBytes(32).toString('hex');
      const sessionToken = crypto.randomBytes(64).toString('hex');
      
      req.session.isAdmin = true;
      req.session.adminLoginTime = Date.now();
      req.session.adminIP = clientIP;
      req.session.adminUserAgent = userAgent;
      req.session.sessionId = sessionId;
      req.session.sessionToken = sessionToken;
      req.session.fingerprint = requestFingerprint;
      req.session.lastActivity = Date.now();
      
      // Track active session
      activeAdminSessions.set(sessionId, {
        ip: clientIP,
        userAgent,
        loginTime: Date.now(),
        lastActivity: Date.now(),
        fingerprint: requestFingerprint
      });
      
      await logSecurityEvent('ADMIN_LOGIN_SUCCESS', { 
        ip: maskIP(clientIP), 
        userAgent: userAgent.substring(0, 100),
        sessionId: sessionId.substring(0, 16),
        authDuration
      });
      
      return res.redirect('/dashboard');
    } else {
      // Failed authentication with enhanced tracking
      const currentAttempts = attempts ? attempts.count + 1 : 1;
      const progressiveDelay = calculateProgressiveDelay(currentAttempts);
      
      loginAttempts.set(attemptKey, {
        count: currentAttempts,
        lastAttempt: Date.now(),
        progressiveDelay,
        userAgent,
        fingerprint: requestFingerprint
      });
      
      await logSecurityEvent('ADMIN_LOGIN_FAILED', { 
        ip: maskIP(clientIP), 
        username: username.substring(0, 20), 
        attempts: currentAttempts,
        userAgent: userAgent.substring(0, 100),
        authDuration
      });
      
      await applyProgressiveDelay(clientIP, 'failed_auth', currentAttempts);
      return res.redirect('/login?error=1');
    }
  } catch (error) {
    await logSecurityEvent('ADMIN_LOGIN_ERROR', { 
      ip: maskIP(getClientIP(req)), 
      error: error.message,
      stack: error.stack?.substring(0, 500)
    });
    return res.redirect('/login?error=1');
  }
}

async function destroySession(req, res) {
  const adminIP = req.session?.adminIP;
  req.session.destroy(async (err) => {
    if (err) {
      console.error('Session destruction error:', err);
    } else {
      await logSecurityEvent('ADMIN_LOGOUT', { ip: adminIP });
    }
    res.clearCookie('faf-session');
    res.redirect('/login');
  });
}

// Advanced authentication security functions
function getClientIP(req) {
  return req.ip || 
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.connection?.remoteAddress ||
         req.socket?.remoteAddress ||
         '0.0.0.0';
}

function maskIP(ip) {
  if (!ip || ip === '0.0.0.0') return 'unknown';
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.xxx.xxx`;
  }
  return ip.substring(0, 8) + '...';
}

function generateRequestFingerprint(req) {
  const components = [
    req.get('User-Agent') || '',
    req.get('Accept-Language') || '',
    req.get('Accept-Encoding') || '',
    req.get('Connection') || '',
    getClientIP(req),
    req.headers['sec-ch-ua'] || '',
    req.headers['sec-ch-ua-mobile'] || '',
    req.headers['sec-ch-ua-platform'] || ''
  ].join('|');
  
  return crypto.createHash('sha256').update(components).digest('hex');
}

function calculateFingerprintSimilarity(fp1, fp2) {
  if (!fp1 || !fp2 || fp1 === fp2) return fp1 === fp2 ? 1 : 0;
  
  // Simple Hamming distance for hex strings
  let matches = 0;
  const minLength = Math.min(fp1.length, fp2.length);
  
  for (let i = 0; i < minLength; i++) {
    if (fp1[i] === fp2[i]) matches++;
  }
  
  return matches / Math.max(fp1.length, fp2.length);
}

function validateAuthenticationInput(username, password, req) {
  if (!username || !password) {
    return { valid: false, reason: 'missing_credentials' };
  }
  
  if (typeof username !== 'string' || typeof password !== 'string') {
    return { valid: false, reason: 'invalid_type' };
  }
  
  if (username.length > 100 || password.length > 200) {
    return { valid: false, reason: 'input_too_long' };
  }
  
  // Check for malicious patterns
  const maliciousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /(union|select|insert|update|delete|drop)/i,
    /\.\.[\/\\]/,
    /[\x00-\x1F\x7F-\x9F]/
  ];
  
  const combinedInput = username + password;
  if (maliciousPatterns.some(pattern => pattern.test(combinedInput))) {
    return { valid: false, reason: 'malicious_content' };
  }
  
  return { valid: true };
}

async function isSuspiciousActivity(clientIP, userAgent, req) {
  // Skip suspicious activity detection in test environment
  if (process.env.NODE_ENV === 'test' || process.env.DISABLE_SUSPICIOUS_DETECTION === 'true') {
    return false;
  }
  
  const suspiciousIndicators = [];
  
  // Check user agent
  if (!userAgent || userAgent.length < 10) {
    suspiciousIndicators.push('short_user_agent');
  }
  
  const suspiciousUAPatterns = [
    /^curl/i,
    /^wget/i,
    /^python/i,
    /^java/i,
    /bot|crawler|spider/i,
    /postman|insomnia/i
  ];
  
  if (suspiciousUAPatterns.some(pattern => pattern.test(userAgent))) {
    suspiciousIndicators.push('automated_tool');
  }
  
  // Check for missing common headers
  if (!req.get('Accept') || !req.get('Accept-Language')) {
    suspiciousIndicators.push('missing_headers');
  }
  
  // Check request frequency
  const activityKey = `activity_${clientIP}`;
  const now = Date.now();
  let activity = suspiciousActivities.get(activityKey) || { requests: [], firstSeen: now };
  
  activity.requests = activity.requests.filter(timestamp => now - timestamp < 60000); // Last minute
  activity.requests.push(now);
  
  if (activity.requests.length > AUTH_CONFIG.SUSPICIOUS_ACTIVITY_THRESHOLD) {
    suspiciousIndicators.push('high_frequency');
  }
  
  suspiciousActivities.set(activityKey, activity);
  
  return suspiciousIndicators.length >= 2; // Require multiple indicators
}

function getSuspiciousIndicators(req) {
  const indicators = [];
  const userAgent = req.get('User-Agent') || '';
  
  if (!userAgent || userAgent.length < 10) indicators.push('short_ua');
  if (/bot|crawler|spider|curl|wget/i.test(userAgent)) indicators.push('automated_tool');
  if (!req.get('Accept')) indicators.push('missing_accept');
  if (!req.get('Accept-Language')) indicators.push('missing_lang');
  
  return indicators;
}

async function verifyCredentialsSecurely(username, password) {
  try {
    // Use constant-time comparison for username
    const expectedUsername = LOGIN_ADMIN_USER || '';
    const usernameMatch = crypto.timingSafeEqual(
      Buffer.from(username.padEnd(expectedUsername.length)),
      Buffer.from(expectedUsername.padEnd(username.length))
    );
    
    if (!usernameMatch) return false;
    
    // Bcrypt comparison already provides timing attack protection
    return await bcrypt.compare(password, LOGIN_ADMIN_PASS);
  } catch (error) {
    await logSecurityEvent('CREDENTIAL_VERIFICATION_ERROR', {
      error: error.message
    });
    return false;
  }
}

function calculateProgressiveDelay(attemptCount) {
  if (!AUTH_CONFIG.PROGRESSIVE_DELAY) return 0;
  
  // Exponential backoff: 2^(attempt-1) * 1000ms, max 30 seconds
  return Math.min(Math.pow(2, attemptCount - 1) * 1000, 30000);
}

async function applyProgressiveDelay(clientIP, reason, attemptCount = 1) {
  if (!AUTH_CONFIG.PROGRESSIVE_DELAY) return;
  
  const delay = calculateProgressiveDelay(attemptCount);
  if (delay > 0) {
    await logSecurityEvent('PROGRESSIVE_DELAY_APPLIED', {
      ip: maskIP(clientIP),
      reason,
      delay,
      attemptCount
    });
    await new Promise(resolve => setTimeout(resolve, delay));
  }
}

function getActiveSessionCount(clientIP) {
  let count = 0;
  const now = Date.now();
  
  for (const [sessionId, sessionData] of activeAdminSessions.entries()) {
    if (sessionData.ip === clientIP && 
        (now - sessionData.lastActivity) < AUTH_CONFIG.SESSION_TIMEOUT) {
      count++;
    }
  }
  
  return count;
}

async function rotateSession(req) {
  if (!req.session) return;
  
  const oldSessionId = req.session.sessionId;
  const newSessionId = crypto.randomBytes(32).toString('hex');
  const newSessionToken = crypto.randomBytes(64).toString('hex');
  
  req.session.sessionId = newSessionId;
  req.session.sessionToken = newSessionToken;
  req.session.lastActivity = Date.now();
  
  // Update session tracking
  if (oldSessionId && activeAdminSessions.has(oldSessionId)) {
    const sessionData = activeAdminSessions.get(oldSessionId);
    activeAdminSessions.delete(oldSessionId);
    activeAdminSessions.set(newSessionId, {
      ...sessionData,
      lastActivity: Date.now()
    });
  }
  
  await logSecurityEvent('ADMIN_SESSION_ROTATED', {
    oldSessionId: oldSessionId?.substring(0, 16),
    newSessionId: newSessionId.substring(0, 16),
    ip: maskIP(getClientIP(req))
  });
}

async function destroySessionSecurely(req) {
  const sessionId = req.session?.sessionId;
  const clientIP = getClientIP(req);
  
  if (sessionId && activeAdminSessions.has(sessionId)) {
    activeAdminSessions.delete(sessionId);
  }
  
  return new Promise((resolve) => {
    req.session.destroy(async (err) => {
      if (err) {
        await logSecurityEvent('SESSION_DESTRUCTION_ERROR', {
          error: err.message,
          sessionId: sessionId?.substring(0, 16),
          ip: maskIP(clientIP)
        });
      }
      resolve();
    });
  });
}

// Enhanced security logging
async function logSecurityEvent(eventType, data) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    event: eventType,
    severity: getEventSeverity(eventType),
    ...data
  };
  
  // Secure logging - no sensitive data exposure
  if (process.env.NODE_ENV === 'production') {
    console.warn('🔐 SECURITY_EVENT:', JSON.stringify(logEntry));
  } else {
    console.log('🔐 SECURITY_EVENT:', logEntry);
  }
  
  // Forward to SecureLogger if available
  if (SecureLogger && SecureLogger.logSecurityEvent) {
    SecureLogger.logSecurityEvent(eventType, data);
  }
}

function getEventSeverity(eventType) {
  const severityMap = {
    'ADMIN_LOGIN_SUCCESS': 5,
    'ADMIN_LOGIN_FAILED': 6,
    'ADMIN_LOGIN_RATE_LIMITED': 8,
    'ADMIN_LOGIN_SUSPICIOUS_ACTIVITY': 9,
    'ADMIN_SESSION_TIMEOUT': 5,
    'ADMIN_SESSION_IP_CHANGE': 9,
    'ADMIN_SESSION_UA_CHANGE': 6,
    'ADMIN_SESSION_FINGERPRINT_MISMATCH': 8,
    'ADMIN_LOGIN_IP_BLOCKED': 7,
    'ADMIN_LOGIN_TOO_MANY_SESSIONS': 7,
    'PROGRESSIVE_DELAY_APPLIED': 6,
    'ADMIN_SESSION_ROTATED': 4,
    'SESSION_DESTRUCTION_ERROR': 7
  };
  
  return severityMap[eventType] || 5;
}

function isIPWhitelisted(ip) {
  if (!ADMIN_IP_WHITELIST) return true;
  
  const allowedIPs = ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
  return allowedIPs.includes(ip) || allowedIPs.includes('127.0.0.1'); // localhost toujours autorisé
}

// Enhanced cleanup with session tracking - Test environment aware
let cleanupInterval;
if (process.env.NODE_ENV !== 'test') {
  cleanupInterval = setInterval(() => {
    const now = Date.now();
    
    // Clean up login attempts
    for (const [key, attempt] of loginAttempts.entries()) {
      if (now - attempt.lastAttempt > AUTH_CONFIG.LOCKOUT_TIME) {
        loginAttempts.delete(key);
      }
    }
    
    // Clean up expired sessions
    for (const [sessionId, sessionData] of activeAdminSessions.entries()) {
      if (now - sessionData.lastActivity > AUTH_CONFIG.SESSION_TIMEOUT) {
        activeAdminSessions.delete(sessionId);
      }
    }
    
    // Clean up suspicious activities
    for (const [key, activity] of suspiciousActivities.entries()) {
      if (now - activity.firstSeen > 60 * 60 * 1000) { // 1 hour
        suspiciousActivities.delete(key);
      }
    }
  }, 5 * 60 * 1000); // Cleanup every 5 minutes
}

// Cleanup function for tests
const cleanup = () => {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
  loginAttempts.clear();
  activeAdminSessions.clear();
  suspiciousActivities.clear();
};

/**
 * Validate session continuity for admin operations
 */
function validateSessionContinuity(req, res, next) {
  if (req.session?.isAdmin) {
    const sessionId = req.session.sessionId;
    const storedSession = activeAdminSessions.get(sessionId);
    
    if (!storedSession) {
      // Session not found in tracking - potential hijacking
      logSecurityEvent('ADMIN_SESSION_TRACKING_MISMATCH', {
        sessionId: sessionId?.substring(0, 16),
        ip: maskIP(getClientIP(req))
      });
      
      destroySessionSecurely(req);
      return res.status(401).json({
        error: 'Session validation failed',
        code: 'SESSION_INVALID'
      });
    }
    
    // Update last activity
    storedSession.lastActivity = Date.now();
    req.session.lastActivity = Date.now();
  }
  
  next();
}

module.exports = {
  ensureAdmin,
  authenticateAdmin,
  destroySession,
  destroySessionSecurely,
  validateSessionContinuity,
  getClientIP,
  maskIP,
  cleanup,
  // Expose for testing or advanced usage
  loginAttempts,
  activeAdminSessions,
  calculateFingerprintSimilarity,
  generateRequestFingerprint,
  applyProgressiveDelay,
  logSecurityEvent
};