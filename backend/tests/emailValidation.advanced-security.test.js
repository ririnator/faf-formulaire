const request = require('supertest');
const {
  validateEmailDomain,
  createEmailDomainMiddleware,
  sanitizeInput,
  validateEmailFormat,
  extractDomain
} = require('../middleware/emailDomainValidation');

const SecureLogger = require('../utils/secureLogger');

// Mock SecureLogger
jest.mock('../utils/secureLogger');

describe('Advanced Email Security Validation Tests', () => {
  let mockApp;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create mock Express app for middleware testing
    mockApp = {
      locals: {},
      use: jest.fn(),
      post: jest.fn()
    };
  });

  describe('Input Sanitization', () => {
    test('should sanitize SQL injection patterns', () => {
      const maliciousInputs = [
        "user@domain.com'; DROP TABLE users; --",
        "user@domain.com' OR 1=1 --",
        "user@domain.com' UNION SELECT * FROM users --",
        "user@domain.com'; INSERT INTO admin VALUES('hacker') --"
      ];

      maliciousInputs.forEach(input => {
        const sanitized = sanitizeInput(input);
        
        // Should remove SQL injection patterns
        expect(sanitized).not.toContain("';");
        expect(sanitized).not.toContain("--");
        expect(sanitized).not.toContain("DROP");
        expect(sanitized).not.toContain("UNION");
        expect(sanitized).not.toContain("INSERT");
      });
    });

    test('should sanitize NoSQL injection patterns', () => {
      const noSqlInjections = [
        'user@domain.com", "$where": "1==1',
        'user@domain.com", "$regex": ".*',
        'user@domain.com", "$ne": null',
        'user@domain.com", "$in": ["admin"]',
        'user@domain.com", "$exists": true'
      ];

      noSqlInjections.forEach(input => {
        const sanitized = sanitizeInput(input);
        
        expect(sanitized).not.toContain('$where');
        expect(sanitized).not.toContain('$regex');
        expect(sanitized).not.toContain('$ne');
        expect(sanitized).not.toContain('$in');
        expect(sanitized).not.toContain('$exists');
      });
    });

    test('should remove control characters and null bytes', () => {
      const maliciousInputs = [
        'user@domain.com\x00',
        'user@domain.com\x01\x02\x03',
        'user@domain.com\n\r\t',
        'user@domain.com\x7F'
      ];

      maliciousInputs.forEach(input => {
        const sanitized = sanitizeInput(input);
        
        // Should not contain any control characters
        expect(sanitized).toMatch(/^[a-zA-Z0-9._%+-@]*$/);
      });
    });
  });

  describe('Email Format Validation', () => {
    test('should enforce RFC length limits', () => {
      const longLocalPart = 'a'.repeat(65) + '@domain.com'; // > 64 chars
      const longDomainPart = 'user@' + 'a'.repeat(250) + '.com'; // > 253 chars
      const longEmail = 'a'.repeat(350); // > 320 chars total

      expect(validateEmailFormat(longLocalPart)).toBe(false);
      expect(validateEmailFormat(longDomainPart)).toBe(false);
      expect(validateEmailFormat(longEmail)).toBe(false);
    });

    test('should reject emails with injection patterns', () => {
      const injectionEmails = [
        "user@domain.com'; DROP TABLE users; --",
        'user@domain.com", "$where": "1==1',
        'user@<script>alert(1)</script>.com',
        'user@domain.com && rm -rf /',
        'user@domain.com`whoami`'
      ];

      injectionEmails.forEach(email => {
        expect(validateEmailFormat(email)).toBe(false);
      });
    });

    test('should reject emails with consecutive dots in domain', () => {
      const invalidEmails = [
        'user@domain..com',
        'user@..domain.com',
        'user@domain.com..',
        'user@sub..domain.com'
      ];

      invalidEmails.forEach(email => {
        expect(validateEmailFormat(email)).toBe(false);
      });
    });

    test('should accept valid email formats', () => {
      const validEmails = [
        'user@domain.com',
        'test.email@example.org',
        'user+tag@sub.domain.co.uk',
        'user123@domain123.net'
      ];

      validEmails.forEach(email => {
        expect(validateEmailFormat(email)).toBe(true);
      });
    });
  });

  describe('Domain Extraction Security', () => {
    test('should return null for emails with injection attempts', () => {
      const maliciousEmails = [
        "user@domain.com'; DROP TABLE users; --",
        'user@domain.com", "$ne": null',
        'user@<script>alert(1)</script>.com',
        'user@domain.com && whoami'
      ];

      maliciousEmails.forEach(email => {
        expect(extractDomain(email)).toBeNull();
      });
    });

    test('should extract domain from valid emails only', () => {
      expect(extractDomain('user@example.com')).toBe('example.com');
      expect(extractDomain('test@sub.domain.org')).toBe('sub.domain.org');
      expect(extractDomain('invalid-email')).toBeNull();
      expect(extractDomain('user@')).toBeNull();
      expect(extractDomain('@domain.com')).toBeNull();
    });
  });

  describe('Rate Limiting Protection', () => {
    test('should implement rate limiting for email validation', async () => {
      const middleware = createEmailDomainMiddleware({
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });

      const mockReq = {
        body: { email: 'test@example.com' },
        ip: '192.168.1.1',
        path: '/test',
        get: jest.fn().mockReturnValue('TestAgent'),
        app: {
          locals: {
            emailValidationAttempts: new Map()
          }
        }
      };

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      const mockNext = jest.fn();

      // Simulate 11 rapid requests (should trigger rate limit)
      for (let i = 0; i < 11; i++) {
        await middleware(mockReq, mockRes, mockNext);
      }

      // Should have triggered rate limiting
      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Trop de tentatives',
          code: 'RATE_LIMITED'
        })
      );
    });
  });

  describe('Security Event Logging', () => {
    test('should log security violations', async () => {
      const result = await validateEmailDomain("user@domain.com'; DROP TABLE users; --", {
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });

      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('SECURITY_VIOLATION');
      expect(SecureLogger.logSecurityEvent).toHaveBeenCalledWith(
        'email_injection_attempt',
        expect.objectContaining({
          originalEmail: expect.any(String),
          sanitizedEmail: expect.any(String),
          timestamp: expect.any(String)
        })
      );
    });

    test('should handle type tampering attempts', () => {
      const middleware = createEmailDomainMiddleware();

      const mockReq = {
        body: { email: { $ne: null } }, // Object instead of string
        ip: '192.168.1.1',
        path: '/test',
        get: jest.fn().mockReturnValue('TestAgent'),
        app: { locals: {} }
      };

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      const mockNext = jest.fn();

      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'INVALID_DATA_TYPE'
        })
      );

      expect(SecureLogger.logSecurityEvent).toHaveBeenCalledWith(
        'email_type_tampering',
        expect.any(Object)
      );
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle undefined and null inputs gracefully', () => {
      expect(sanitizeInput(null)).toBeNull();
      expect(sanitizeInput(undefined)).toBeNull();
      expect(sanitizeInput('')).toBeNull(); // Empty string should return null for consistency
      
      expect(validateEmailFormat(null)).toBe(false);
      expect(validateEmailFormat(undefined)).toBe(false);
      expect(validateEmailFormat('')).toBe(false);
      
      expect(extractDomain(null)).toBeNull();
      expect(extractDomain(undefined)).toBeNull();
      expect(extractDomain('')).toBeNull();
    });

    test('should handle non-string inputs', () => {
      const nonStringInputs = [123, [], {}, true, false];
      
      nonStringInputs.forEach(input => {
        expect(sanitizeInput(input)).toBeNull();
        expect(validateEmailFormat(input)).toBe(false);
        expect(extractDomain(input)).toBeNull();
      });
    });

    test('should handle extremely long inputs without crashing', () => {
      const veryLongString = 'a'.repeat(10000);
      
      expect(() => sanitizeInput(veryLongString)).not.toThrow();
      expect(() => validateEmailFormat(veryLongString)).not.toThrow();
      expect(() => extractDomain(veryLongString)).not.toThrow();
      
      expect(validateEmailFormat(veryLongString)).toBe(false);
      expect(extractDomain(veryLongString)).toBeNull();
    });
  });

  describe('Bypass Attempt Prevention', () => {
    test('should prevent encoding bypass attempts', async () => {
      const encodedInjections = [
        'user@domain.com%27%20OR%201%3D1%20--', // URL encoded
        'user@domain.com&#x27; OR 1=1 --',      // HTML encoded
        'user@domain.com\\x27 OR 1=1 --',       // Hex encoded
        'user@domain.com%2527%2520OR%25201%253D1%2520--' // Double encoded
      ];

      for (const email of encodedInjections) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });

        expect(result.isValid).toBe(false);
        expect(['SECURITY_VIOLATION', 'INVALID_EMAIL_FORMAT'].includes(result.reason)).toBe(true);
      }
    });

    test('should prevent unicode and internationalization bypasses', async () => {
      const maliciousUnicodeAttempts = [
        'user@domain.com\u0000', // Null character (definitely malicious)
        'user@domain.com\u200B', // Zero-width space (can be used for bypass)
        'user@domain.com\u0001\u0002' // Control characters
      ];

      // Test truly malicious Unicode patterns
      for (const email of maliciousUnicodeAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });

        expect(result.isValid).toBe(false);
      }

      // Verify that normal emails still work
      const normalEmail = 'test@example.com';
      const normalResult = await validateEmailDomain(normalEmail, {
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });
      
      expect(['VALID', 'NO_MX_RECORD', 'DOMAIN_NOT_EXISTS'].includes(normalResult.reason)).toBe(true);
    });
  });
});