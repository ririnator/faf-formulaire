/**
 * Centralized Error Sanitization System
 * Prevents information disclosure through error messages
 */

class ErrorSanitizer {
  constructor() {
    // Patterns that might reveal sensitive information
    this.sensitivePatterns = [
      // File paths
      /\/[a-zA-Z0-9_\-\/]+\.(js|ts|json|env|config)/gi,
      /[C-Z]:\\\\[^\\s]+/gi, // Windows paths
      /\/home\/[^\/\s]+/gi,
      /\/Users\/[^\/\s]+/gi,
      /\/var\/[^\/\s]+/gi,
      
      // Database information
      /mongodb:\/\/[^\/\s]+/gi,
      /postgres:\/\/[^\/\s]+/gi,
      /mysql:\/\/[^\/\s]+/gi,
      /Connection string:.*$/gi,
      
      // Stack traces
      /at\s+[^\s]+\s+\([^\)]+\)/gi,
      /at\s+[^\s]+:[0-9]+:[0-9]+/gi,
      
      // Environment variables
      /process\.env\.[A-Z_]+/gi,
      /NODE_ENV\s*=\s*[^\s]+/gi,
      
      // IP addresses and ports
      /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b:[0-9]+/gi,
      /localhost:[0-9]+/gi,
      
      // API keys and secrets (common patterns)
      /[a-zA-Z0-9]{32,}/g, // Long strings that might be keys
      /Bearer\s+[^\s]+/gi,
      /api[_-]?key[_-]?[=:]\s*[^\s]+/gi,
      /secret[_-]?[=:]\s*[^\s]+/gi,
      
      // Module/package names that reveal tech stack
      /node_modules\/[^\/\s]+/gi,
      /require\(['""][^\)]+['"]\)/gi,
      
      // Database field names - be more selective to avoid over-sanitization
      /\b(password|passwd|pwd|secret|api_key|apikey|credential)\b[=:]\s*[^\s]+/gi
    ];
    
    // Predefined safe error messages for common scenarios
    this.safeMessages = {
      // Authentication errors
      AUTH_FAILED: 'Authentication failed',
      INVALID_CREDENTIALS: 'Invalid credentials',
      SESSION_EXPIRED: 'Session expired',
      UNAUTHORIZED: 'Unauthorized access',
      FORBIDDEN: 'Access forbidden',
      
      // Validation errors
      VALIDATION_ERROR: 'Validation error',
      INVALID_INPUT: 'Invalid input',
      MISSING_REQUIRED: 'Missing required field',
      INVALID_FORMAT: 'Invalid format',
      
      // Database errors
      DB_ERROR: 'Database operation failed',
      NOT_FOUND: 'Resource not found',
      DUPLICATE: 'Duplicate entry',
      CONSTRAINT_ERROR: 'Constraint violation',
      
      // Rate limiting
      RATE_LIMITED: 'Too many requests',
      
      // File operations
      FILE_ERROR: 'File operation failed',
      UPLOAD_FAILED: 'Upload failed',
      
      // Network errors
      NETWORK_ERROR: 'Network error',
      TIMEOUT: 'Request timeout',
      
      // Generic errors
      INTERNAL_ERROR: 'Internal server error',
      OPERATION_FAILED: 'Operation failed',
      INVALID_REQUEST: 'Invalid request',
      SERVICE_UNAVAILABLE: 'Service temporarily unavailable'
    };
    
    // Map specific error types to safe messages
    this.errorTypeMap = {
      'MongoError': this.safeMessages.DB_ERROR,
      'ValidationError': this.safeMessages.VALIDATION_ERROR,
      'CastError': this.safeMessages.INVALID_INPUT,
      'JsonWebTokenError': this.safeMessages.AUTH_FAILED,
      'TokenExpiredError': this.safeMessages.SESSION_EXPIRED,
      'MulterError': this.safeMessages.UPLOAD_FAILED,
      'TypeError': this.safeMessages.INTERNAL_ERROR,
      'ReferenceError': this.safeMessages.INTERNAL_ERROR,
      'SyntaxError': this.safeMessages.INVALID_INPUT,
      'RangeError': this.safeMessages.INVALID_INPUT,
      'URIError': this.safeMessages.INVALID_REQUEST,
      'NetworkError': this.safeMessages.NETWORK_ERROR
    };
  }
  
  /**
   * Sanitize an error message to prevent information disclosure
   * @param {Error|string} error - The error to sanitize
   * @param {Object} options - Sanitization options
   * @returns {Object} Sanitized error response
   */
  sanitize(error, options = {}) {
    const {
      includeCode = true,
      includeTimestamp = false,
      context = null,
      userFriendly = true
    } = options;
    
    // Handle different error types
    let errorMessage = '';
    let errorCode = 'ERROR';
    let statusCode = 500;
    
    if (typeof error === 'string') {
      errorMessage = error;
    } else if (error instanceof Error) {
      errorMessage = error.message || '';
      errorCode = error.code || error.name || 'ERROR';
      statusCode = error.statusCode || error.status || 500;
    } else if (error && typeof error === 'object') {
      errorMessage = error.message || error.error || '';
      errorCode = error.code || 'ERROR';
      statusCode = error.statusCode || error.status || 500;
    }
    
    // Check if this is a known error type
    const knownErrorType = error?.constructor?.name;
    if (knownErrorType && this.errorTypeMap[knownErrorType]) {
      errorMessage = this.errorTypeMap[knownErrorType];
    } else {
      // Remove sensitive information from the message
      errorMessage = this.removeSensitiveInfo(errorMessage);
      
      // If the message is still too revealing, use a generic message
      if (this.containsSensitiveInfo(errorMessage) || !userFriendly) {
        errorMessage = this.getGenericMessage(statusCode, context);
      }
    }
    
    // Build sanitized response
    const sanitized = {
      success: false,
      error: errorMessage
    };
    
    if (includeCode) {
      sanitized.code = this.sanitizeCode(errorCode);
    }
    
    if (includeTimestamp) {
      sanitized.timestamp = new Date().toISOString();
    }
    
    // Log the original error securely (for debugging)
    if (process.env.NODE_ENV !== 'production') {
      console.error('Original error (dev only):', {
        message: error?.message,
        stack: error?.stack,
        code: error?.code
      });
    } else {
      // In production, log sanitized version with request ID for correlation
      console.error('Error occurred:', {
        sanitizedMessage: errorMessage,
        code: sanitized.code,
        timestamp: new Date().toISOString(),
        requestId: options.requestId
      });
    }
    
    return sanitized;
  }
  
  /**
   * Remove sensitive information from a string
   * @param {string} text - Text to sanitize
   * @returns {string} Sanitized text
   */
  removeSensitiveInfo(text) {
    if (!text || typeof text !== 'string') {
      return '';
    }
    
    let sanitized = text;
    
    // Apply all sensitive patterns
    for (const pattern of this.sensitivePatterns) {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    }
    
    // Remove line numbers and file references
    sanitized = sanitized.replace(/:[0-9]+:[0-9]+/g, '');
    sanitized = sanitized.replace(/line [0-9]+/gi, '');
    sanitized = sanitized.replace(/column [0-9]+/gi, '');
    
    // Trim excessive whitespace
    sanitized = sanitized.replace(/\s+/g, ' ').trim();
    
    // Limit length to prevent verbose errors
    if (sanitized.length > 200) {
      sanitized = sanitized.substring(0, 200) + '...';
    }
    
    return sanitized;
  }
  
  /**
   * Check if text contains sensitive information
   * @param {string} text - Text to check
   * @returns {boolean} True if sensitive info detected
   */
  containsSensitiveInfo(text) {
    if (!text || typeof text !== 'string') {
      return false;
    }
    
    // Check against all patterns
    for (const pattern of this.sensitivePatterns) {
      if (pattern.test(text)) {
        return true;
      }
    }
    
    // Check for common sensitive keywords
    const sensitiveKeywords = [
      'stack', 'trace', 'path', 'directory',
      'mongodb', 'database', 'connection',
      'env', 'config', 'secret', 'key',
      'node_modules', 'require', 'import'
    ];
    
    const lowerText = text.toLowerCase();
    return sensitiveKeywords.some(keyword => lowerText.includes(keyword));
  }
  
  /**
   * Get a generic error message based on status code
   * @param {number} statusCode - HTTP status code
   * @param {string} context - Optional context
   * @returns {string} Generic error message
   */
  getGenericMessage(statusCode, context) {
    // Map status codes to safe messages
    const statusMessages = {
      400: this.safeMessages.INVALID_REQUEST,
      401: this.safeMessages.UNAUTHORIZED,
      403: this.safeMessages.FORBIDDEN,
      404: this.safeMessages.NOT_FOUND,
      405: 'Method not allowed',
      409: this.safeMessages.DUPLICATE,
      422: this.safeMessages.VALIDATION_ERROR,
      429: this.safeMessages.RATE_LIMITED,
      500: this.safeMessages.INTERNAL_ERROR,
      502: 'Bad gateway',
      503: this.safeMessages.SERVICE_UNAVAILABLE,
      504: this.safeMessages.TIMEOUT
    };
    
    // Add context-specific messages if provided
    if (context) {
      switch (context) {
        case 'auth':
          return statusCode === 401 ? this.safeMessages.AUTH_FAILED : this.safeMessages.UNAUTHORIZED;
        case 'validation':
          return this.safeMessages.VALIDATION_ERROR;
        case 'database':
          return this.safeMessages.DB_ERROR;
        case 'file':
          return this.safeMessages.FILE_ERROR;
        case 'network':
          return this.safeMessages.NETWORK_ERROR;
      }
    }
    
    return statusMessages[statusCode] || this.safeMessages.OPERATION_FAILED;
  }
  
  /**
   * Sanitize error codes to prevent information disclosure
   * @param {string} code - Error code to sanitize
   * @returns {string} Sanitized error code
   */
  sanitizeCode(code) {
    if (!code || typeof code !== 'string') {
      return 'ERROR';
    }
    
    // Remove any file paths or sensitive info from codes
    let sanitized = code.toUpperCase();
    sanitized = sanitized.replace(/[^A-Z0-9_]/g, '_');
    
    // Limit length
    if (sanitized.length > 50) {
      sanitized = sanitized.substring(0, 50);
    }
    
    // Map known problematic codes
    const codeMap = {
      'ENOENT': 'NOT_FOUND',
      'EACCES': 'FORBIDDEN',
      'ECONNREFUSED': 'CONNECTION_ERROR',
      'ETIMEDOUT': 'TIMEOUT',
      'ENOTFOUND': 'NOT_FOUND'
    };
    
    return codeMap[sanitized] || sanitized;
  }
  
  /**
   * Express middleware for automatic error sanitization
   * @returns {Function} Express middleware
   */
  middleware() {
    return (err, req, res, next) => {
      const sanitized = this.sanitize(err, {
        includeCode: true,
        includeTimestamp: true,
        requestId: req.id || req.requestId,
        context: req.path?.includes('/auth') ? 'auth' : null
      });
      
      const statusCode = err.statusCode || err.status || 500;
      
      res.status(statusCode).json(sanitized);
    };
  }
}

// Export singleton instance
module.exports = new ErrorSanitizer();