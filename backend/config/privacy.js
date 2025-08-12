// Privacy and Data Protection Configuration
// Ensures sensitive user data is never logged or exposed

const PRIVACY_CONFIG = {
  // Logging configuration
  logging: {
    // Never log these fields
    blacklistedFields: [
      'password',
      'token',
      'sessionId',
      'email',
      'userId',
      'responses',
      'migrateToken',
      'csrfToken'
    ],
    
    // Redact patterns in paths
    pathRedactionPatterns: [
      /\/api\/view\/[^\/]+/,          // Token in view path
      /\/api\/auth\/verify\/[^\/]+/,  // Verification tokens
      /\/api\/users\/[^\/]+/,         // User IDs
      /\/api\/responses\/[^\/]+/      // Response IDs
    ],
    
    // Only log these auth events in aggregate
    authEventsToAggregate: [
      'login_attempt',
      'login_success',
      'login_failure',
      'registration',
      'logout',
      'session_validation'
    ]
  },
  
  // Data retention
  retention: {
    // Anonymize logs after this period
    logAnonymizationDays: 30,
    // Delete old session data
    sessionRetentionDays: 14,
    // Archive old responses
    responseArchiveDays: 365
  },
  
  // Privacy compliance
  compliance: {
    // GDPR compliance mode
    gdprMode: process.env.GDPR_COMPLIANCE === 'true',
    // Log user consent
    requireConsent: process.env.REQUIRE_CONSENT === 'true',
    // Right to be forgotten
    allowDeletion: true
  }
};

// Privacy-preserving utilities
class PrivacyUtils {
  // Sanitize object for logging
  static sanitizeForLogging(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (PRIVACY_CONFIG.logging.blacklistedFields.includes(key)) {
        sanitized[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeForLogging(value);
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }
  
  // Redact sensitive path patterns
  static redactPath(path) {
    let redactedPath = path;
    for (const pattern of PRIVACY_CONFIG.logging.pathRedactionPatterns) {
      redactedPath = redactedPath.replace(pattern, (match) => {
        const parts = match.split('/');
        parts[parts.length - 1] = '[REDACTED]';
        return parts.join('/');
      });
    }
    return redactedPath;
  }
  
  // Generate anonymous ID for analytics
  static generateAnonymousId(identifier) {
    const crypto = require('crypto');
    const salt = process.env.ANALYTICS_SALT || 'default-salt';
    return crypto
      .createHash('sha256')
      .update(identifier + salt)
      .digest('hex')
      .substring(0, 16);
  }
  
  // Check if logging is allowed for this data
  static canLog(dataType) {
    // Never log in production unless explicitly allowed
    if (process.env.NODE_ENV === 'production') {
      return process.env.PRODUCTION_LOGGING === 'true' && 
             process.env.PRIVACY_OVERRIDE === 'true';
    }
    
    // In development, require explicit opt-in for sensitive data
    if (dataType === 'auth' || dataType === 'user') {
      return process.env.VERBOSE_AUTH_LOGS === 'true';
    }
    
    return true;
  }
}

module.exports = {
  PRIVACY_CONFIG,
  PrivacyUtils
};