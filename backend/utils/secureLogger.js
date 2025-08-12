// Secure logging utility to prevent sensitive data exposure
const { APP_CONSTANTS } = require('../constants');
const { PrivacyUtils, PRIVACY_CONFIG } = require('../config/privacy');

class SecureLogger {
  // Use centralized privacy utilities for consistent sanitization
  static sanitizeForLogging(obj) {
    return PrivacyUtils.sanitizeForLogging(obj);
  }

  static logInfo(message, data = null) {
    // Check privacy config before logging
    if (!PrivacyUtils.canLog('info')) return;
    
    const timestamp = new Date().toISOString();
    if (data) {
      const sanitizedData = this.sanitizeForLogging(data);
      console.log(`[${timestamp}] INFO: ${message}`, sanitizedData);
    } else {
      console.log(`[${timestamp}] INFO: ${message}`);
    }
  }

  static logError(message, error = null) {
    const timestamp = new Date().toISOString();
    if (error) {
      // Only log error message, not full error object which might contain sensitive data
      const errorMessage = error.message || 'Unknown error';
      // Never log stack traces in production as they may expose file paths
      if (process.env.NODE_ENV === 'production') {
        console.error(`[${timestamp}] ERROR: ${message} - ${errorMessage}`);
      } else {
        console.error(`[${timestamp}] ERROR: ${message} - ${errorMessage}`);
        // Stack trace only in development with explicit opt-in
        if (process.env.DEBUG_STACK_TRACES === 'true') {
          console.error('Stack:', error.stack);
        }
      }
    } else {
      console.error(`[${timestamp}] ERROR: ${message}`);
    }
  }

  static logDebug(message, data = null) {
    // Debug logging only in development or when explicitly enabled
    if (process.env.NODE_ENV === 'production' && !process.env.ENABLE_DEBUG_LOGS) return;
    
    const timestamp = new Date().toISOString();
    if (data) {
      const sanitizedData = this.sanitizeForLogging(data);
      console.log(`[${timestamp}] DEBUG: ${message}`, sanitizedData);
    } else {
      console.log(`[${timestamp}] DEBUG: ${message}`);
    }
  }

  static logWarning(message, data = null) {
    if (!PrivacyUtils.canLog('warning')) return;
    
    const timestamp = new Date().toISOString();
    if (data) {
      const sanitizedData = this.sanitizeForLogging(data);
      console.warn(`[${timestamp}] WARN: ${message}`, sanitizedData);
    } else {
      console.warn(`[${timestamp}] WARN: ${message}`);
    }
  }

  static logAuth(method, path, authMethod) {
    // Check privacy config before any auth logging
    if (!PrivacyUtils.canLog('auth')) return;
    
    const timestamp = new Date().toISOString();
    // Never log actual paths or methods that could reveal user behavior
    // Only log anonymous aggregate statistics
    console.log(`[${timestamp}] AUTH_STATS: AuthMethod=${authMethod} (aggregated)`);
  }

  static logMigration(action, success = true, count = 0) {
    // Migration logs should not contain user-identifiable information
    if (!PrivacyUtils.canLog('migration')) return;
    
    const timestamp = new Date().toISOString();
    const status = success ? 'SUCCESS' : 'ERROR';
    // Only log aggregate counts, not specific user data
    console.log(`[${timestamp}] MIGRATION: ${action} - ${status} - Count: ${count}`);
  }

  // Production-safe performance logging
  static logPerformance(operation, duration, metadata = {}) {
    // Performance logs should be anonymous
    const sanitizedMetadata = this.sanitizeForLogging(metadata);
    const timestamp = new Date().toISOString();
    
    // In production, only log if explicitly enabled
    if (process.env.NODE_ENV === 'production' && process.env.PERFORMANCE_LOGGING !== 'true') {
      return;
    }
    
    // Redact any paths in operation name
    const sanitizedOperation = PrivacyUtils.redactPath(operation);
    console.log(`[${timestamp}] PERF: ${sanitizedOperation} - ${duration}ms`, sanitizedMetadata);
  }

  // New method for GDPR-compliant audit logging
  static logAudit(action, userId = null, metadata = {}) {
    // Audit logs require special handling for compliance
    if (PRIVACY_CONFIG.compliance.gdprMode) {
      const timestamp = new Date().toISOString();
      const anonymousId = userId ? PrivacyUtils.generateAnonymousId(userId) : 'ANONYMOUS';
      const sanitizedMetadata = this.sanitizeForLogging(metadata);
      
      // Store in audit log with anonymous ID
      console.log(`[${timestamp}] AUDIT: Action=${action} User=${anonymousId}`, sanitizedMetadata);
    }
  }
}

module.exports = SecureLogger;