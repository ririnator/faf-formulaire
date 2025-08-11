// Secure logging utility to prevent sensitive data exposure
const { APP_CONSTANTS } = require('../constants');

class SecureLogger {
  static sanitizeForLogging(obj) {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }

    const sensitiveFields = [
      'password', 'token', 'secret', 'key', 'apiKey',
      'authorization', 'cookie', 'session', '_id', 'id'
    ];

    const sanitized = { ...obj };
    
    for (const field of sensitiveFields) {
      if (field in sanitized) {
        if (field === 'token' && typeof sanitized[field] === 'string') {
          // Show only first 8 characters for tokens
          sanitized[field] = sanitized[field].substring(0, 8) + '...';
        } else if (field === '_id' || field === 'id') {
          // Replace IDs with generic placeholder
          sanitized[field] = '[ID]';
        } else {
          sanitized[field] = '[REDACTED]';
        }
      }
    }

    return sanitized;
  }

  static logInfo(message, data = null) {
    if (process.env.NODE_ENV === 'development') {
      const timestamp = new Date().toISOString();
      if (data) {
        const sanitizedData = this.sanitizeForLogging(data);
        console.log(`[${timestamp}] INFO: ${message}`, sanitizedData);
      } else {
        console.log(`[${timestamp}] INFO: ${message}`);
      }
    }
  }

  static logError(message, error = null) {
    const timestamp = new Date().toISOString();
    if (error) {
      // Only log error message, not full error object which might contain sensitive data
      const errorMessage = error.message || 'Unknown error';
      console.error(`[${timestamp}] ERROR: ${message} - ${errorMessage}`);
    } else {
      console.error(`[${timestamp}] ERROR: ${message}`);
    }
  }

  static logAuth(method, path, authMethod) {
    if (process.env.NODE_ENV === 'development') {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] AUTH: ${method} ${path} - Method: ${authMethod}`);
    }
  }

  static logMigration(action, success = true, count = 0) {
    if (process.env.NODE_ENV === 'development') {
      const timestamp = new Date().toISOString();
      const status = success ? 'SUCCESS' : 'ERROR';
      console.log(`[${timestamp}] MIGRATION: ${action} - ${status} - Count: ${count}`);
    }
  }

  // Production-safe performance logging
  static logPerformance(operation, duration, metadata = {}) {
    const sanitizedMetadata = this.sanitizeForLogging(metadata);
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] PERF: ${operation} - ${duration}ms`, sanitizedMetadata);
  }
}

module.exports = SecureLogger;