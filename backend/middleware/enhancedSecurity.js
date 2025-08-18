// Enhanced Security Middleware - Additional protection layers for API routes
const rateLimit = require('express-rate-limit');

/**
 * Parameter pollution protection
 * Prevents duplicate query parameters that could be used for attacks
 */
const preventParameterPollution = (allowedDuplicates = []) => {
  return (req, res, next) => {
    // Check for parameter pollution in query parameters
    for (const [key, value] of Object.entries(req.query)) {
      if (Array.isArray(value) && !allowedDuplicates.includes(key)) {
        console.warn('Parameter pollution detected', {
          parameter: key,
          values: value,
          ip: req.ip,
          userAgent: req.get('user-agent'),
          path: req.path
        });
        
        return res.status(400).json({
          success: false,
          error: 'Invalid request parameters',
          code: 'PARAMETER_POLLUTION'
        });
      }
    }
    next();
  };
};

/**
 * Enhanced request logging for security monitoring
 */
const securityLogger = (req, res, next) => {
  // Log potentially suspicious requests
  const suspiciousPatterns = [
    /\.\./,  // Directory traversal
    /<script/i,  // XSS attempts
    /union.*select/i,  // SQL injection
    /javascript:/i,  // JavaScript protocol
    /data:/i,  // Data protocol
    /%00/,  // Null byte
    /\.\.\//,  // Path traversal
    /etc\/passwd/,  // System file access
    /\/proc\//,  // Process information
    /cmd\.exe/i,  // Windows command execution
    /powershell/i,  // PowerShell execution
    /wget|curl/i  // Remote file download
  ];
  
  const requestContent = JSON.stringify({
    url: req.url,
    body: req.body,
    query: req.query,
    headers: req.headers
  });
  
  const suspicious = suspiciousPatterns.some(pattern => pattern.test(requestContent));
  
  if (suspicious) {
    console.warn('Suspicious request detected', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      url: req.url,
      method: req.method,
      suspiciousContent: requestContent.substring(0, 500),
      timestamp: new Date().toISOString()
    });
  }
  
  next();
};

/**
 * Validates token entropy to detect weak or predictable tokens
 * @param {string} token - Token to validate (should be 64 character hex)
 * @returns {Object} Validation result with score and reason
 */
const validateTokenEntropy = (token) => {
  if (!token || token.length !== 64) {
    return { isValid: false, score: 0, reason: 'invalid_length' };
  }

  // Calculate character frequency distribution
  const charFreq = {};
  for (let i = 0; i < token.length; i++) {
    const char = token[i].toLowerCase();
    charFreq[char] = (charFreq[char] || 0) + 1;
  }

  // Check for excessive repetition of characters
  const maxFreq = Math.max(...Object.values(charFreq));
  const expectedMaxFreq = Math.ceil(64 / 16); // ~4 for perfectly random hex
  
  if (maxFreq > expectedMaxFreq * 2) { // Allow some variance but flag extreme cases
    return { 
      isValid: false, 
      score: maxFreq / 64, 
      reason: 'excessive_repetition',
      details: { maxFreq, expectedMaxFreq }
    };
  }

  // Check for patterns (sequential characters, repeated segments)
  if (hasSequentialPattern(token)) {
    return { 
      isValid: false, 
      score: 0.1, 
      reason: 'sequential_pattern' 
    };
  }

  if (hasRepeatedSegments(token)) {
    return { 
      isValid: false, 
      score: 0.2, 
      reason: 'repeated_segments' 
    };
  }

  // Calculate approximate entropy score
  const uniqueChars = Object.keys(charFreq).length;
  const entropyScore = uniqueChars / 16; // 16 possible hex characters

  // Require reasonable character distribution
  if (uniqueChars < 8) { // Less than half the possible hex characters
    return { 
      isValid: false, 
      score: entropyScore, 
      reason: 'insufficient_character_variety',
      details: { uniqueChars }
    };
  }

  return { 
    isValid: true, 
    score: entropyScore, 
    reason: 'valid' 
  };
};

/**
 * Detects sequential patterns in tokens (e.g., 123456, abcdef)
 * @param {string} token - Token to check
 * @returns {boolean} True if sequential pattern detected
 */
const hasSequentialPattern = (token) => {
  // Check for ascending sequences of 4+ characters
  for (let i = 0; i < token.length - 3; i++) {
    const segment = token.substring(i, i + 4);
    let isSequential = true;
    
    for (let j = 1; j < segment.length; j++) {
      const current = parseInt(segment[j], 16);
      const previous = parseInt(segment[j-1], 16);
      
      if (isNaN(current) || isNaN(previous) || current !== (previous + 1) % 16) {
        isSequential = false;
        break;
      }
    }
    
    if (isSequential) return true;
  }
  
  return false;
};

/**
 * Detects repeated segments in tokens
 * @param {string} token - Token to check
 * @returns {boolean} True if repeated segments detected
 */
const hasRepeatedSegments = (token) => {
  // Check for repeated 4-character segments
  for (let segmentLength = 4; segmentLength <= 8; segmentLength++) {
    for (let i = 0; i <= token.length - segmentLength * 2; i++) {
      const segment = token.substring(i, i + segmentLength);
      const nextSegment = token.substring(i + segmentLength, i + segmentLength * 2);
      
      if (segment === nextSegment) {
        return true;
      }
    }
  }
  
  return false;
};

/**
 * Token validation security enhancement
 * Adds additional checks for token format and prevents common attacks
 */
const enhanceTokenValidation = (req, res, next) => {
  const token = req.params?.token || req.body?.token || req.query?.token;
  
  if (token) {
    // Check for valid hex format
    if (!/^[a-f0-9]{64}$/i.test(token)) {
      console.warn('Invalid token format detected', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        tokenLength: token.length,
        tokenPrefix: token.substring(0, 8),
        path: req.path
      });
      
      return res.status(400).json({
        success: false,
        error: 'Invalid token format',
        code: 'INVALID_TOKEN_FORMAT'
      });
    }
    
    // Enhanced entropy validation to detect weak tokens
    const entropyCheck = validateTokenEntropy(token);
    if (!entropyCheck.isValid) {
      console.warn('Weak token entropy detected', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        tokenPrefix: token.substring(0, 8),
        entropyScore: entropyCheck.score,
        reason: entropyCheck.reason,
        path: req.path
      });
      
      return res.status(400).json({
        success: false,
        error: 'Invalid token',
        code: 'WEAK_TOKEN_ENTROPY'
      });
    }
    
    // Prevent token enumeration attempts
    if (token === '0'.repeat(64) || token === 'f'.repeat(64)) {
      console.warn('Token enumeration attempt detected', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        token: token.substring(0, 8) + '...',
        path: req.path
      });
      
      return res.status(400).json({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
  }
  
  next();
};

/**
 * Anti-automation detection
 * Detects and blocks automated requests based on timing and patterns
 */
const antiAutomation = () => {
  // Bypass in test environment
  if (process.env.NODE_ENV === 'test' || process.env.DISABLE_RATE_LIMITING === 'true') {
    return (req, res, next) => next();
  }
  
  const requestTimes = new Map();
  const MAX_TRACKING_ENTRIES = 10000; // Maximum number of unique clients to track
  const MAX_REQUESTS_PER_CLIENT = 20; // Maximum requests to track per client
  
  return (req, res, next) => {
    const clientKey = `${req.ip}:${req.get('user-agent') || 'unknown'}`;
    const now = Date.now();
    
    // Implement memory limit protection
    if (requestTimes.size >= MAX_TRACKING_ENTRIES) {
      // Remove oldest entries (LRU eviction)
      const entriesToRemove = Math.floor(MAX_TRACKING_ENTRIES * 0.2); // Remove 20% of entries
      const sortedEntries = Array.from(requestTimes.entries())
        .sort((a, b) => {
          const aLastTime = a[1][a[1].length - 1] || 0;
          const bLastTime = b[1][b[1].length - 1] || 0;
          return aLastTime - bLastTime;
        });
      
      for (let i = 0; i < entriesToRemove && i < sortedEntries.length; i++) {
        requestTimes.delete(sortedEntries[i][0]);
      }
      
      console.info('Anti-automation memory limit reached, cleaned old entries', {
        entriesRemoved: entriesToRemove,
        currentSize: requestTimes.size
      });
    }
    
    if (requestTimes.has(clientKey)) {
      const times = requestTimes.get(clientKey);
      times.push(now);
      
      // Keep only last MAX_REQUESTS_PER_CLIENT requests
      if (times.length > MAX_REQUESTS_PER_CLIENT) {
        times.splice(0, times.length - MAX_REQUESTS_PER_CLIENT);
      }
      
      // Check for rapid successive requests (less than 100ms between requests)
      if (times.length >= 3) {
        const intervals = [];
        for (let i = 1; i < times.length; i++) {
          intervals.push(times[i] - times[i-1]);
        }
        
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const minInterval = Math.min(...intervals);
        
        // Flag as automation if average interval < 200ms or any interval < 50ms
        if (avgInterval < 200 || minInterval < 50) {
          console.warn('Potential automation detected', {
            ip: req.ip,
            userAgent: req.get('user-agent'),
            avgInterval,
            minInterval,
            requestCount: times.length,
            path: req.path
          });
          
          return res.status(429).json({
            success: false,
            error: 'Requests too frequent. Please slow down.',
            code: 'AUTOMATION_DETECTED',
            retryAfter: 60
          });
        }
      }
    } else {
      requestTimes.set(clientKey, [now]);
    }
    
    // Cleanup old entries (older than 5 minutes)
    const fiveMinutesAgo = now - 5 * 60 * 1000;
    let cleanupCount = 0;
    for (const [key, times] of requestTimes.entries()) {
      if (times[times.length - 1] < fiveMinutesAgo) {
        requestTimes.delete(key);
        cleanupCount++;
      }
    }
    
    if (cleanupCount > 0) {
      console.debug('Cleaned up old anti-automation entries', { count: cleanupCount });
    }
    
    next();
  };
};

/**
 * Enhanced CSRF protection with additional security checks
 */
const enhancedCSRFProtection = (req, res, next) => {
  // Check for double-submit cookie pattern
  const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
  const csrfCookie = req.cookies['csrf-token'];
  
  if (!csrfToken || !csrfCookie) {
    console.warn('Missing CSRF tokens', {
      ip: req.ip,
      hasToken: !!csrfToken,
      hasCookie: !!csrfCookie,
      path: req.path
    });
  }
  
  // Check referrer header for additional protection
  const referrer = req.get('referer');
  const origin = req.get('origin');
  const host = req.get('host');
  
  if (referrer && origin) {
    try {
      const referrerHost = new URL(referrer).host;
      const originHost = new URL(origin).host;
      
      if (referrerHost !== host || originHost !== host) {
        console.warn('Cross-origin request detected', {
          ip: req.ip,
          referrer,
          origin,
          host,
          path: req.path
        });
      }
    } catch (e) {
      console.warn('Invalid referrer or origin header', {
        ip: req.ip,
        referrer,
        origin,
        error: e.message
      });
    }
  }
  
  next();
};

/**
 * Content type validation
 * Ensures requests have appropriate content types
 */
const validateContentType = (allowedTypes = ['application/json', 'multipart/form-data']) => {
  return (req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const contentType = req.get('content-type');
      
      if (!contentType) {
        return res.status(400).json({
          success: false,
          error: 'Content-Type header required',
          code: 'MISSING_CONTENT_TYPE'
        });
      }
      
      const isAllowed = allowedTypes.some(type => contentType.includes(type));
      
      if (!isAllowed) {
        console.warn('Invalid content type', {
          ip: req.ip,
          contentType,
          path: req.path,
          allowedTypes
        });
        
        return res.status(400).json({
          success: false,
          error: 'Invalid content type',
          code: 'INVALID_CONTENT_TYPE'
        });
      }
    }
    
    next();
  };
};

module.exports = {
  preventParameterPollution,
  securityLogger,
  enhanceTokenValidation,
  antiAutomation,
  enhancedCSRFProtection,
  validateContentType
};