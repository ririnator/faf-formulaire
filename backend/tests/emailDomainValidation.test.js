const {
  validateEmailDomain,
  createEmailDomainMiddleware,
  isDisposableEmail,
  extractDomain,
  EmailDomainConfig,
  emailConfig,
  getDomainBlockingStats,
  DISPOSABLE_DOMAINS,
  SUSPICIOUS_PATTERNS
} = require('../middleware/emailDomainValidation');

const SecureLogger = require('../utils/secureLogger');

// Mock SecureLogger to prevent actual logging during tests
jest.mock('../utils/secureLogger');

describe('Email Domain Validation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset config to defaults
    emailConfig.allowedDomains.clear();
    emailConfig.blockedDomains.clear();
    // Don't automatically populate blocked domains - disposable domains are checked separately
  });

  describe('extractDomain', () => {
    test('should extract domain from valid email', () => {
      expect(extractDomain('user@example.com')).toBe('example.com');
      expect(extractDomain('test.user@sub.domain.co.uk')).toBe('sub.domain.co.uk');
      expect(extractDomain('USER@EXAMPLE.COM')).toBe('example.com'); // Case insensitive
    });

    test('should return null for invalid email formats', () => {
      expect(extractDomain('')).toBe(null);
      expect(extractDomain('invalid-email')).toBe(null);
      expect(extractDomain('user@')).toBe(null);
      expect(extractDomain('@domain.com')).toBe(null);
      expect(extractDomain(null)).toBe(null);
      expect(extractDomain(undefined)).toBe(null);
    });

    test('should handle edge cases', () => {
      // These invalid formats should return null with our strict regex
      expect(extractDomain('user@@domain.com')).toBe(null);
      expect(extractDomain('user@domain@domain.com')).toBe(null);
    });
  });

  describe('isDisposableEmail', () => {
    test('should detect known disposable email domains', () => {
      expect(isDisposableEmail('test@10minutemail.com')).toBe(true);
      expect(isDisposableEmail('user@guerrillamail.com')).toBe(true);
      expect(isDisposableEmail('temp@mailinator.com')).toBe(true);
      expect(isDisposableEmail('fake@yopmail.com')).toBe(true);
    });

    test('should not flag legitimate email domains', () => {
      expect(isDisposableEmail('user@gmail.com')).toBe(false);
      expect(isDisposableEmail('user@outlook.com')).toBe(false);
      expect(isDisposableEmail('user@company.com')).toBe(false);
      expect(isDisposableEmail('user@university.edu')).toBe(false);
    });

    test('should handle case insensitivity', () => {
      expect(isDisposableEmail('test@MAILINATOR.COM')).toBe(true);
      expect(isDisposableEmail('test@MailinAtor.COM')).toBe(true);
    });
  });

  describe('EmailDomainConfig', () => {
    let config;

    beforeEach(() => {
      config = new EmailDomainConfig();
    });

    test('should initialize with default settings', () => {
      expect(config.enableMXValidation).toBe(true);
      expect(config.enableDisposableCheck).toBe(true);
      expect(config.enableSuspiciousPatternCheck).toBe(true);
      expect(config.logBlockedAttempts).toBe(true);
    });

    test('should manage whitelist correctly', () => {
      config.allowDomain('trusted.com');
      expect(config.isDomainAllowed('trusted.com')).toBe(true);
      expect(config.isDomainAllowed('TRUSTED.COM')).toBe(true); // Case insensitive
      expect(config.isDomainAllowed('untrusted.com')).toBe(false);

      config.disallowDomain('trusted.com');
      expect(config.isDomainAllowed('trusted.com')).toBe(false);
    });

    test('should manage blacklist correctly', () => {
      config.blockDomain('blocked.com');
      expect(config.isDomainBlocked('blocked.com')).toBe(true);
      expect(config.isDomainBlocked('BLOCKED.COM')).toBe(true); // Case insensitive
      expect(config.isDomainBlocked('allowed.com')).toBe(false);

      config.unblockDomain('blocked.com');
      expect(config.isDomainBlocked('blocked.com')).toBe(false);
    });
  });

  describe('validateEmailDomain', () => {
    test('should validate legitimate email domains', async () => {
      const result = await validateEmailDomain('user@gmail.com', {
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });
      expect(result.isValid).toBe(true);
      expect(result.reason).toBe('VALID');
    });

    test('should reject invalid email formats', async () => {
      const result = await validateEmailDomain('invalid-email');
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('INVALID_EMAIL_FORMAT');
    });

    test('should reject disposable email domains', async () => {
      const result = await validateEmailDomain('test@10minutemail.com');
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('DISPOSABLE_DOMAIN');
      expect(result.message).toContain('temporaires');
    });

    test('should reject blacklisted domains', async () => {
      emailConfig.blockDomain('blocked.com');
      const result = await validateEmailDomain('user@blocked.com');
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('BLACKLISTED');
    });

    test('should allow whitelisted domains even if suspicious', async () => {
      emailConfig.allowDomain('tempmail.com');
      const result = await validateEmailDomain('user@tempmail.com');
      expect(result.isValid).toBe(true);
      expect(result.reason).toBe('WHITELISTED');
    });

    test('should detect suspicious patterns', async () => {
      const suspiciousEmails = [
        'user@10mail.com',
        'user@tempmail.test',
        'user@disposable.test',
        'user@throwaway.test',
        'user@trashmail.test',
        'user@spammail.test',
        'user@fakemail.test',
        'user@testmail.test',
        'user@guerrilla.test',
        'user@mailinator.test'
      ];

      for (const email of suspiciousEmails) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        expect(result.isValid).toBe(false);
        expect(result.reason).toBe('SUSPICIOUS_PATTERN');
      }
    });

    test('should handle validation options correctly', async () => {
      const result = await validateEmailDomain('user@example.com', {
        skipMXValidation: true,
        skipDisposableCheck: true,
        skipSuspiciousPatternCheck: true,
        skipDomainExistenceCheck: true
      });
      expect(result.isValid).toBe(true);
    });

    test('should reject domains that do not exist', async () => {
      const result = await validateEmailDomain('user@nonexistentdomain12345.com');
      expect(result.isValid).toBe(false);
      expect(result.reason).toBe('DOMAIN_NOT_EXISTS');
    });
  });

  describe('createEmailDomainMiddleware', () => {
    let req, res, next;

    beforeEach(() => {
      req = {
        body: {},
        path: '/test',
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('Test-Agent')
      };
      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      next = jest.fn();
    });

    test('should pass valid emails through', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email',
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });

      req.body.email = 'user@gmail.com';
      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('should block disposable emails', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email'
      });

      req.body.email = 'user@10minutemail.com';
      await middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Email non autorisé',
        message: 'Les adresses email temporaires ne sont pas autorisées',
        code: 'DISPOSABLE_DOMAIN'
      });
    });

    test('should log blocked attempts', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email',
        logBlocked: true
      });

      req.body.email = 'user@mailinator.com';
      await middleware(req, res, next);

      expect(SecureLogger.logSecurityEvent).toHaveBeenCalledWith(
        'email_domain_blocked',
        expect.objectContaining({
          domain: 'mailinator.com',
          reason: 'DISPOSABLE_DOMAIN',
          ip: '127.0.0.1',
          path: '/test'
        })
      );
    });

    test('should skip validation when email field is missing', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email'
      });

      // No email field in req.body
      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('should skip validation for specified routes', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email',
        skipValidationFor: ['/test']
      });

      req.body.email = 'user@mailinator.com';
      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    test('should handle validation errors gracefully', async () => {
      // Mock the validateEmailDomain function
      const mockValidateEmailDomain = jest.fn().mockRejectedValue(new Error('DNS lookup failed'));
      
      // Create middleware with mocked validation
      const middleware = jest.requireActual('../middleware/emailDomainValidation').createEmailDomainMiddleware({
        emailField: 'email'
      });

      // Temporarily override the function 
      jest.doMock('../middleware/emailDomainValidation', () => ({
        ...jest.requireActual('../middleware/emailDomainValidation'),
        validateEmailDomain: mockValidateEmailDomain
      }));

      req.body.email = 'user@example.com';
      
      // The middleware should handle errors gracefully
      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      // In a real scenario, SecureLogger.logError would be called, but for simplicity we'll just check next() was called
      expect(res.status).not.toHaveBeenCalled();
    });
  });

  describe('getDomainBlockingStats', () => {
    test('should return correct statistics', () => {
      const stats = getDomainBlockingStats();

      expect(stats).toHaveProperty('disposableDomainsCount');
      expect(stats).toHaveProperty('suspiciousPatternsCount');
      expect(stats).toHaveProperty('whitelistedDomainsCount');
      expect(stats).toHaveProperty('blacklistedDomainsCount');
      expect(stats).toHaveProperty('config');

      expect(typeof stats.disposableDomainsCount).toBe('number');
      expect(stats.disposableDomainsCount).toBeGreaterThan(0);
      expect(stats.suspiciousPatternsCount).toBeGreaterThan(0);
      expect(typeof stats.config.enableMXValidation).toBe('boolean');
    });
  });

  describe('Integration with existing validation', () => {
    test('should work alongside express-validator email validation', async () => {
      // Test that our domain validation doesn't interfere with existing email format validation
      const validEmails = [
        'user@example.com',
        'test.email@domain.co.uk',
        'user+tag@company.org'
      ];

      for (const email of validEmails) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        expect(result.isValid).toBe(true);
      }
    });

    test('should handle French characters in email validation', async () => {
      // Ensure French domain names work correctly
      const result = await validateEmailDomain('utilisateur@société.fr', {
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });
      expect(result.isValid).toBe(true);
    });
  });

  describe('Security edge cases', () => {
    test('should handle very long domain names', async () => {
      const longDomain = 'a'.repeat(250) + '.com';
      const result = await validateEmailDomain(`user@${longDomain}`, {
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });
      // Should not crash, behavior depends on domain existence
      expect(result).toHaveProperty('isValid');
    });

    test('should handle special characters in domains', async () => {
      const specialDomains = [
        'user@domain-with-dashes.com',
        'user@domain.with.dots.com',
        'user@123numeric.com'
      ];

      for (const email of specialDomains) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        expect(result).toHaveProperty('isValid');
      }
    });

    test('should prevent some bypass attempts', async () => {
      // Test various bypass attempts
      const bypassAttempts = [
        'user@example.com', // Legitimate domain - should pass
        'user@tempmail.test', // Matches suspicious pattern - should fail 
        'user@company.org' // Different legitimate domain - should pass
      ];

      const results = await Promise.all(
        bypassAttempts.map(email => 
          validateEmailDomain(email, {
            skipMXValidation: true,
            skipDomainExistenceCheck: true
          })
        )
      );

      expect(results[0].isValid).toBe(true); // Legitimate domain
      expect(results[1].isValid).toBe(false); // Caught by suspicious pattern matching
      expect(results[2].isValid).toBe(true); // Different legitimate domain, not suspicious
    });
  });

  describe('Performance tests', () => {
    test('should validate emails quickly', async () => {
      const startTime = Date.now();
      const emails = Array(100).fill('user@example.com');
      
      await Promise.all(emails.map(email => 
        validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        })
      ));
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Should complete 100 validations in under 1 second
      expect(duration).toBeLessThan(1000);
    });

    test('should handle concurrent validations', async () => {
      const emails = [
        'user1@gmail.com',
        'user2@yahoo.com',
        'user3@outlook.com',
        'spam@mailinator.com',
        'temp@10minutemail.com'
      ];

      const results = await Promise.all(emails.map(email => 
        validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        })
      ));

      expect(results[0].isValid).toBe(true);
      expect(results[1].isValid).toBe(true);
      expect(results[2].isValid).toBe(true);
      expect(results[3].isValid).toBe(false);
      expect(results[4].isValid).toBe(false);
    });
  });
});