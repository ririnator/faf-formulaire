// Centralized secure token generation utility
const crypto = require('crypto');
const { APP_CONSTANTS } = require('../constants');

class TokenGenerator {
  /**
   * Generate a cryptographically secure token with additional entropy
   * @param {Object} options - Token generation options
   * @param {number} options.length - Byte length of random component (default: 32)
   * @param {boolean} options.includeTimestamp - Include timestamp entropy (default: true)  
   * @param {boolean} options.includeProcess - Include process ID entropy (default: true)
   * @param {string} options.encoding - Output encoding: 'hex' | 'base64' | 'base64url' (default: 'hex')
   * @param {boolean} options.hash - Whether to hash the final result (default: true)
   * @returns {string} Secure token
   */
  static generateSecureToken(options = {}) {
    const {
      length = APP_CONSTANTS.TOKEN_BYTES_LENGTH || 32,
      includeTimestamp = true,
      includeProcess = true,
      encoding = 'hex',
      hash = true
    } = options;

    const entropyComponents = [];

    // Primary cryptographically secure random bytes
    entropyComponents.push(crypto.randomBytes(length));

    // Add timestamp entropy for uniqueness
    if (includeTimestamp) {
      const timestamp = Buffer.from(Date.now().toString(36));
      entropyComponents.push(timestamp);
      
      // Add high-resolution time for additional entropy
      const hrTime = Buffer.from(process.hrtime.bigint().toString(36));
      entropyComponents.push(hrTime);
    }

    // Add process-specific entropy
    if (includeProcess) {
      const processComponent = Buffer.from(process.pid.toString());
      entropyComponents.push(processComponent);
    }

    // Add additional system entropy
    const memoryUsage = Buffer.from(process.memoryUsage().heapUsed.toString(36));
    entropyComponents.push(memoryUsage);

    // Combine all entropy sources
    const combined = Buffer.concat(entropyComponents);

    if (hash) {
      // Hash with SHA-256 for uniform distribution and length
      const hashed = crypto.createHash('sha256').update(combined).digest();
      return this.encodeBuffer(hashed, encoding);
    } else {
      return this.encodeBuffer(combined, encoding);
    }
  }

  /**
   * Generate a token specifically for response viewing
   * Uses enhanced entropy suitable for long-term tokens
   */
  static generateResponseToken() {
    return this.generateSecureToken({
      length: 32,
      includeTimestamp: true,
      includeProcess: true,
      encoding: 'hex',
      hash: true
    });
  }

  /**
   * Generate a CSRF token for form protection
   * Uses lighter entropy as these are short-lived
   */
  static generateCSRFToken() {
    return this.generateSecureToken({
      length: 16,
      includeTimestamp: true,
      includeProcess: false,
      encoding: 'hex',
      hash: false
    });
  }

  /**
   * Generate a session token for user sessions
   * Uses maximum entropy for session security
   */
  static generateSessionToken() {
    return this.generateSecureToken({
      length: 48,
      includeTimestamp: true,
      includeProcess: true,
      encoding: 'base64url',
      hash: true
    });
  }

  /**
   * Generate a nonce for CSP headers
   * Lightweight but secure for inline script protection
   */
  static generateNonce() {
    return this.generateSecureToken({
      length: 16,
      includeTimestamp: false,
      includeProcess: false,
      encoding: 'base64',
      hash: false
    });
  }

  /**
   * Generate a migration token for account linking
   * Uses enhanced entropy and longer length for security
   */
  static generateMigrationToken() {
    return this.generateSecureToken({
      length: 40,
      includeTimestamp: true,
      includeProcess: true,
      encoding: 'hex',
      hash: true
    });
  }

  /**
   * Encode buffer with specified encoding
   * @private
   */
  static encodeBuffer(buffer, encoding) {
    switch (encoding) {
      case 'base64':
        return buffer.toString('base64');
      case 'base64url':
        return buffer.toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '');
      case 'hex':
      default:
        return buffer.toString('hex');
    }
  }

  /**
   * Validate token format and minimum entropy
   * @param {string} token - Token to validate
   * @param {string} type - Expected token type: 'response' | 'csrf' | 'session' | 'migration'
   * @returns {boolean} Whether token meets security requirements
   */
  static validateToken(token, type = 'response') {
    if (!token || typeof token !== 'string') {
      return false;
    }

    const requirements = {
      response: { minLength: 64, pattern: /^[a-f0-9]+$/ },
      csrf: { minLength: 32, pattern: /^[a-f0-9]+$/ },
      session: { minLength: 64, pattern: /^[A-Za-z0-9_-]+$/ },
      migration: { minLength: 80, pattern: /^[a-f0-9]+$/ }
    };

    const req = requirements[type];
    if (!req) {
      return false;
    }

    return token.length >= req.minLength && req.pattern.test(token);
  }

  /**
   * Generate a secure random string for testing purposes
   * @param {number} length - Desired length in bytes
   * @returns {string} Random hex string
   */
  static generateTestToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
}

module.exports = TokenGenerator;