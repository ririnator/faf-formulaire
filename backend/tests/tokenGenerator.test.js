// Token Generator Security Tests
const TokenGenerator = require('../utils/tokenGenerator');

describe('TokenGenerator Security Tests', () => {
  describe('generateSecureToken', () => {
    test('should generate unique tokens', () => {
      const token1 = TokenGenerator.generateSecureToken();
      const token2 = TokenGenerator.generateSecureToken();
      
      expect(token1).not.toBe(token2);
      expect(token1.length).toBeGreaterThan(0);
      expect(token2.length).toBeGreaterThan(0);
    });

    test('should generate tokens with proper entropy', () => {
      const tokens = new Set();
      
      // Generate 100 tokens - should all be unique
      for (let i = 0; i < 100; i++) {
        const token = TokenGenerator.generateSecureToken();
        expect(tokens.has(token)).toBe(false);
        tokens.add(token);
      }
      
      expect(tokens.size).toBe(100);
    });

    test('should support different encodings', () => {
      const hexToken = TokenGenerator.generateSecureToken({ encoding: 'hex' });
      const base64Token = TokenGenerator.generateSecureToken({ encoding: 'base64' });
      const base64urlToken = TokenGenerator.generateSecureToken({ encoding: 'base64url' });

      expect(hexToken).toMatch(/^[a-f0-9]+$/);
      expect(base64Token).toMatch(/^[A-Za-z0-9+/=]+$/);
      expect(base64urlToken).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    test('should respect length parameter', () => {
      const shortToken = TokenGenerator.generateSecureToken({ 
        length: 16, 
        hash: false,
        includeTimestamp: false,
        includeProcess: false
      });
      const longToken = TokenGenerator.generateSecureToken({ 
        length: 64, 
        hash: false,
        includeTimestamp: false,
        includeProcess: false
      });

      // When not hashed, length should be proportional to input
      expect(shortToken.length).toBeLessThan(longToken.length);
    });

    test('should produce consistent length with hashing', () => {
      const token1 = TokenGenerator.generateSecureToken({ hash: true });
      const token2 = TokenGenerator.generateSecureToken({ hash: true });

      // SHA-256 hash should always produce 64-character hex strings
      expect(token1.length).toBe(64);
      expect(token2.length).toBe(64);
    });
  });

  describe('Specific Token Types', () => {
    test('generateResponseToken should be secure', () => {
      const token = TokenGenerator.generateResponseToken();
      
      expect(token).toMatch(/^[a-f0-9]+$/);
      expect(token.length).toBe(64); // SHA-256 hex output
      expect(TokenGenerator.validateToken(token, 'response')).toBe(true);
    });

    test('generateCSRFToken should be appropriate for CSRF', () => {
      const token = TokenGenerator.generateCSRFToken();
      
      expect(token).toMatch(/^[a-f0-9]+$/);
      expect(token.length).toBeGreaterThanOrEqual(32);
      expect(TokenGenerator.validateToken(token, 'csrf')).toBe(true);
    });

    test('generateSessionToken should be maximum security', () => {
      const token = TokenGenerator.generateSessionToken();
      
      expect(token).toMatch(/^[A-Za-z0-9_-]+$/); // base64url
      expect(token.length).toBeGreaterThanOrEqual(64);
      expect(TokenGenerator.validateToken(token, 'session')).toBe(true);
    });

    test('generateNonce should be suitable for CSP', () => {
      const nonce = TokenGenerator.generateNonce();
      
      expect(nonce).toMatch(/^[A-Za-z0-9+/=]+$/); // base64
      expect(nonce.length).toBeGreaterThanOrEqual(16);
    });

    test('generateMigrationToken should be extra secure', () => {
      const token = TokenGenerator.generateMigrationToken();
      
      expect(token).toMatch(/^[a-f0-9]+$/);
      expect(token.length).toBe(64); // SHA-256 hex
      expect(TokenGenerator.validateToken(token, 'migration')).toBe(true);
    });
  });

  describe('Token Validation', () => {
    test('should validate response tokens correctly', () => {
      const validToken = TokenGenerator.generateResponseToken();
      const invalidToken = 'too-short';
      const wrongFormatToken = 'invalid!@#$%^&*()characters';

      expect(TokenGenerator.validateToken(validToken, 'response')).toBe(true);
      expect(TokenGenerator.validateToken(invalidToken, 'response')).toBe(false);
      expect(TokenGenerator.validateToken(wrongFormatToken, 'response')).toBe(false);
      expect(TokenGenerator.validateToken(null, 'response')).toBe(false);
      expect(TokenGenerator.validateToken('', 'response')).toBe(false);
    });

    test('should validate CSRF tokens correctly', () => {
      const validToken = TokenGenerator.generateCSRFToken();
      
      expect(TokenGenerator.validateToken(validToken, 'csrf')).toBe(true);
      expect(TokenGenerator.validateToken('short', 'csrf')).toBe(false);
    });

    test('should validate session tokens correctly', () => {
      const validToken = TokenGenerator.generateSessionToken();
      
      expect(TokenGenerator.validateToken(validToken, 'session')).toBe(true);
      expect(TokenGenerator.validateToken('invalid+chars', 'session')).toBe(false);
    });
  });

  describe('Security Properties', () => {
    test('should not repeat tokens even with same timestamp', () => {
      const tokens = [];
      
      // Generate tokens rapidly to potentially get same timestamp
      for (let i = 0; i < 10; i++) {
        tokens.push(TokenGenerator.generateSecureToken());
      }
      
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(tokens.length);
    });

    test('should include process entropy when requested', () => {
      const withProcess = TokenGenerator.generateSecureToken({ 
        includeProcess: true,
        hash: false,
        includeTimestamp: false,
        length: 16
      });
      const withoutProcess = TokenGenerator.generateSecureToken({ 
        includeProcess: false,
        hash: false,
        includeTimestamp: false,
        length: 16
      });

      // Tokens with process entropy should generally be longer
      // (though this test might be flaky due to random nature)
      expect(withProcess.length).toBeGreaterThan(16 * 2); // hex encoding doubles length
    });

    test('should produce cryptographically random output', () => {
      const tokens = Array(50).fill(null).map(() => 
        TokenGenerator.generateSecureToken({ length: 32 })
      );

      // Statistical test: check character distribution
      const hexChars = '0123456789abcdef';
      const charCounts = {};
      
      tokens.forEach(token => {
        for (const char of token) {
          charCounts[char] = (charCounts[char] || 0) + 1;
        }
      });

      // Each hex character should appear roughly equally
      // With 50 * 64 = 3200 characters, each of 16 hex chars should appear ~200 times
      // Allow significant variance due to randomness
      for (const char of hexChars) {
        const count = charCounts[char] || 0;
        expect(count).toBeGreaterThan(100); // At least some representation
        expect(count).toBeLessThan(400);    // Not overly concentrated
      }
    });
  });

  describe('Test Token Generation', () => {
    test('generateTestToken should be simple but secure', () => {
      const token = TokenGenerator.generateTestToken(32);
      
      expect(token).toMatch(/^[a-f0-9]+$/);
      expect(token.length).toBe(64); // 32 bytes = 64 hex chars
    });

    test('generateTestToken should accept different lengths', () => {
      const short = TokenGenerator.generateTestToken(16);
      const long = TokenGenerator.generateTestToken(48);
      
      expect(short.length).toBe(32); // 16 bytes = 32 hex chars
      expect(long.length).toBe(96);  // 48 bytes = 96 hex chars
    });
  });

  describe('Edge Cases', () => {
    test('should handle zero length gracefully', () => {
      const token = TokenGenerator.generateSecureToken({ 
        length: 0,
        includeTimestamp: true,
        includeProcess: true
      });
      
      // Should still generate a token due to timestamp/process entropy
      expect(token.length).toBeGreaterThan(0);
    });

    test('should handle missing options', () => {
      expect(() => {
        TokenGenerator.generateSecureToken(null);
      }).not.toThrow();
      
      expect(() => {
        TokenGenerator.generateSecureToken(undefined);
      }).not.toThrow();
    });

    test('should validate unknown token types', () => {
      const token = TokenGenerator.generateSecureToken();
      expect(TokenGenerator.validateToken(token, 'unknown')).toBe(false);
    });
  });
});