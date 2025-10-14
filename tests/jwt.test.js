const { generateToken, verifyToken, decodeToken } = require('../utils/jwt');

// Setup JWT_SECRET pour les tests
process.env.JWT_SECRET = 'test-secret-key-for-jwt-testing-only';

describe('JWT Utils', () => {

  describe('generateToken', () => {
    test('Should generate a valid token', () => {
      const payload = { sub: 'user-123', username: 'testuser' };
      const token = generateToken(payload);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.').length).toBe(3); // JWT format: header.payload.signature
    });

    test('Should throw error if JWT_SECRET is not defined', () => {
      const originalSecret = process.env.JWT_SECRET;
      delete process.env.JWT_SECRET;

      expect(() => {
        generateToken({ sub: 'test' });
      }).toThrow('JWT_SECRET is not defined');

      process.env.JWT_SECRET = originalSecret;
    });

    test('Should generate different tokens for same payload', async () => {
      const payload = { sub: 'user-123' };
      const token1 = generateToken(payload);

      // Wait 1s to ensure different iat (JWT uses second precision)
      await new Promise(resolve => setTimeout(resolve, 1100));

      const token2 = generateToken(payload);
      expect(token1).not.toBe(token2); // Different because of iat
    });
  });

  describe('verifyToken', () => {
    test('Should verify a valid token', () => {
      const payload = { sub: 'user-123', username: 'testuser' };
      const token = generateToken(payload);

      const decoded = verifyToken(token);

      expect(decoded).toBeDefined();
      expect(decoded.sub).toBe('user-123');
      expect(decoded.username).toBe('testuser');
      expect(decoded.iss).toBe('faf-multitenant');
      expect(decoded.aud).toBe('faf-users');
    });

    test('Should reject an invalid token', () => {
      const decoded = verifyToken('invalid-token');

      expect(decoded).toBeNull();
    });

    test('Should reject a token with wrong signature', () => {
      const payload = { sub: 'user-123' };
      const token = generateToken(payload);

      // Modifier le token
      const parts = token.split('.');
      parts[2] = 'wrong-signature';
      const invalidToken = parts.join('.');

      const decoded = verifyToken(invalidToken);
      expect(decoded).toBeNull();
    });

    test('Should expire after specified duration', async () => {
      const payload = { sub: 'user-123' };
      const token = generateToken(payload, '1ms'); // Expire immédiatement

      // Attendre 100ms
      await new Promise(resolve => setTimeout(resolve, 100));

      const decoded = verifyToken(token);
      expect(decoded).toBeNull(); // Token expiré
    });

    test('Should throw error if JWT_SECRET is not defined', () => {
      const originalSecret = process.env.JWT_SECRET;
      delete process.env.JWT_SECRET;

      expect(() => {
        verifyToken('some-token');
      }).toThrow('JWT_SECRET is not defined');

      process.env.JWT_SECRET = originalSecret;
    });
  });

  describe('decodeToken', () => {
    test('Should decode token without verification', () => {
      const payload = { sub: 'user-123', username: 'testuser' };
      const token = generateToken(payload);

      const decoded = decodeToken(token);

      expect(decoded).toBeDefined();
      expect(decoded.sub).toBe('user-123');
      expect(decoded.username).toBe('testuser');
    });

    test('Should decode expired token without error', () => {
      const payload = { sub: 'user-123' };
      const token = generateToken(payload, '0s');

      const decoded = decodeToken(token);
      expect(decoded).toBeDefined();
      expect(decoded.sub).toBe('user-123');
    });

    test('Should return null for invalid token', () => {
      const decoded = decodeToken('not-a-valid-token');
      expect(decoded).toBeNull();
    });
  });

  describe('Token expiration', () => {
    test('Should generate token with default 7 days expiration', () => {
      const payload = { sub: 'user-123' };
      const token = generateToken(payload);
      const decoded = decodeToken(token);

      const now = Math.floor(Date.now() / 1000);
      const sevenDays = 7 * 24 * 60 * 60;

      expect(decoded.exp).toBeGreaterThan(now);
      expect(decoded.exp).toBeLessThanOrEqual(now + sevenDays + 10); // +10s margin
    });

    test('Should generate token with custom expiration', () => {
      const payload = { sub: 'user-123' };
      const token = generateToken(payload, '1h');
      const decoded = decodeToken(token);

      const now = Math.floor(Date.now() / 1000);
      const oneHour = 60 * 60;

      expect(decoded.exp).toBeGreaterThan(now);
      expect(decoded.exp).toBeLessThanOrEqual(now + oneHour + 10); // +10s margin
    });
  });

});
