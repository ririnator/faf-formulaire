// Unit tests for authentication components
const bcrypt = require('bcrypt');
const User = require('../models/User');
const { authLimiters, createAuthRateLimit } = require('../middleware/authRateLimit');
const { APP_CONSTANTS } = require('../constants');

const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

beforeAll(async () => {
  app = getTestApp();
}, 30000);

describe('User Model Unit Tests', () => {
  beforeAll(async () => {
    
    });

  afterAll(async () => {
    await mongoose.disconnect();
    });

  beforeEach(async () => {
    await User.deleteMany({});
  });

  describe('Password Hashing', () => {
    test('should hash password on save', async () => {
      const plainPassword = 'TestPassword123!';
      const user = new User({
        username: 'testuser',
        email: 'test@example.com',
        password: plainPassword,
      });

      await user.save();

      expect(user.password).not.toBe(plainPassword);
      expect(user.password).toMatch(/^\$2b\$/); // bcrypt hash format
    });

    test('should not rehash password if not modified', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'TestPassword123!',
      });

      const originalHash = user.password;
      
      user.username = 'UpdatedName';
      await user.save();

      expect(user.password).toBe(originalHash);
    });

    test('should use correct salt rounds', async () => {
      const spy = jest.spyOn(bcrypt, 'genSalt');
      
      await User.create({
        username: 'salttest',
        email: 'salt@test.com',
        password: 'Password123!'
      });

      expect(spy).toHaveBeenCalledWith(APP_CONSTANTS.BCRYPT_SALT_ROUNDS);
      spy.mockRestore();
    });
  });

  describe('Password Comparison', () => {
    let user;
    const correctPassword = 'CorrectPassword123!';

    beforeEach(async () => {
      user = await User.create({
        username: 'comparetest',
        email: 'compare@test.com',
        password: correctPassword,
      });
    });

    test('should validate correct password', async () => {
      const isValid = await user.comparePassword(correctPassword);
      expect(isValid).toBe(true);
    });

    test('should reject incorrect password', async () => {
      const isValid = await user.comparePassword('WrongPassword');
      expect(isValid).toBe(false);
    });

    test('should handle null password comparison', async () => {
      const isValid = await user.comparePassword(null);
      expect(isValid).toBe(false);
    });
  });

  describe('User Methods', () => {
    let user;

    beforeEach(async () => {
      user = await User.create({
        username: 'methodtest',
        email: 'method@test.com',
        password: 'Password123!'
      });
    });

    test('should update last active', async () => {
      const originalLastActive = user.metadata.lastActive;
      
      // Wait a bit to ensure time difference
      await new Promise(resolve => setTimeout(resolve, 10));
      
      await user.updateLastActive();
      
      const updatedUser = await User.findById(user._id);
      expect(updatedUser.metadata.lastActive.getTime()).toBeGreaterThan(
        originalLastActive.getTime()
      );
    });

    test('should increment response count', async () => {
      expect(user.metadata.responseCount).toBe(0);
      
      await user.incrementResponseCount();
      expect(user.metadata.responseCount).toBe(1);
      
      await user.incrementResponseCount();
      expect(user.metadata.responseCount).toBe(2);
    });

    test('should return public JSON without password', () => {
      const publicData = user.toPublicJSON();
      
      expect(publicData).toHaveProperty('id');
      expect(publicData).toHaveProperty('username', user.username);
      expect(publicData).toHaveProperty('email', user.email);
      expect(publicData).toHaveProperty('displayName', user.username);
      expect(publicData).not.toHaveProperty('password');
      expect(publicData).not.toHaveProperty('_id');
    });
  });

  describe('User Validation', () => {
    test('should require all mandatory fields', async () => {
      const user = new User({});
      
      const validationError = user.validateSync();
      expect(validationError.errors).toHaveProperty('username');
      expect(validationError.errors).toHaveProperty('email');
      expect(validationError.errors).toHaveProperty('password');
    });

    test('should validate email format', async () => {
      const user = new User({
        username: 'emailtest',
        email: 'invalid-email',
        password: 'Password123!'
      });

      const validationError = user.validateSync();
      expect(validationError.errors).toHaveProperty('email');
    });

    test('should enforce unique constraints', async () => {
      await User.create({
        username: 'unique',
        email: 'unique@test.com',
        password: 'Password123!'
      });

      // Try to create duplicate
      const duplicate = new User({
        username: 'unique', // Duplicate username
        email: 'different@test.com',
        password: 'Password123!'
      });

      await expect(duplicate.save()).rejects.toThrow();
    });

    test('should enforce field length constraints', () => {
      const user = new User({
        username: 'ab', // Too short
        email: 'test@test.com',
        password: '12345' // Too short
      });

      const validationError = user.validateSync();
      expect(validationError.errors).toHaveProperty('username');
      expect(validationError.errors).toHaveProperty('password');
    });
  });

  describe('Migration Data', () => {
    test('should set default migration source', async () => {
      const user = await User.create({
        username: 'migrationtest',
        email: 'migration@test.com',
        password: 'Password123!'
      });

      expect(user.migrationData.source).toBe('registration');
    });

    test('should store migration metadata', async () => {
      const user = await User.create({
        username: 'migrationtest2',
        email: 'migration2@test.com',
        password: 'Password123!',
        migrationData: {
          legacyName: 'Old Name',
          migratedAt: new Date(),
          source: 'migration'
        }
      });

      expect(user.migrationData.legacyName).toBe('Old Name');
      expect(user.migrationData.source).toBe('migration');
      expect(user.migrationData.migratedAt).toBeInstanceOf(Date);
    });
  });
});

describe('Rate Limiting Unit Tests', () => {
  describe('Auth Rate Limiter Creation', () => {
    test('should create rate limiter with default options', () => {
      const limiter = createAuthRateLimit();
      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    test('should merge custom options', () => {
      const limiter = createAuthRateLimit({
        max: 10,
        windowMs: 5000
      });
      expect(limiter).toBeDefined();
    });

    test('should have predefined limiters', () => {
      expect(authLimiters.login).toBeDefined();
      expect(authLimiters.register).toBeDefined();
      expect(authLimiters.passwordReset).toBeDefined();
      expect(authLimiters.profileUpdate).toBeDefined();
    });
  });

  describe('Key Generation', () => {
    test('should generate unique keys for different IPs', () => {
      const req1 = { ip: '192.168.1.1', get: () => 'Mozilla/5.0' };
      const req2 = { ip: '192.168.1.2', get: () => 'Mozilla/5.0' };
      
      const limiter = createAuthRateLimit();
      
      // Access private keyGenerator through options
      const keyGen = limiter.options.keyGenerator;
      
      expect(keyGen(req1)).not.toBe(keyGen(req2));
    });

    test('should include user agent in key', () => {
      const req = { 
        ip: '192.168.1.1', 
        get: (header) => header === 'user-agent' ? 'TestAgent' : null 
      };
      
      const limiter = createAuthRateLimit();
      const key = limiter.options.keyGenerator(req);
      
      expect(key).toContain('192.168.1.1');
      expect(key).toContain('TestAgent');
    });
  });
});

describe('Security Middleware Unit Tests', () => {
  const { generateNonce } = require('../middleware/security');

  describe('Nonce Generation', () => {
    test('should generate unique nonces', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      
      expect(nonce1).not.toBe(nonce2);
      expect(nonce1).toMatch(/^[A-Za-z0-9+/=]+$/); // Base64 format
    });

    test('should generate nonces of correct length', () => {
      const nonce = generateNonce();
      // 16 bytes in base64 = 24 characters (with padding)
      expect(nonce.length).toBeGreaterThanOrEqual(22);
      expect(nonce.length).toBeLessThanOrEqual(24);
    });
  });
});

describe('Template Renderer Unit Tests', () => {
  const TemplateRenderer = require('../utils/templateRenderer');
  const fs = require('fs');
  const path = require('path');

  describe('HTML Rendering', () => {
    const testHtmlPath = path.join(__dirname, 'test-template.html');
    const testHtml = '<script nonce="{{nonce}}">console.log("test");</script>';

    beforeAll(() => {
      fs.writeFileSync(testHtmlPath, testHtml);
    });

    afterAll(() => {
      if (fs.existsSync(testHtmlPath)) {
        fs.unlinkSync(testHtmlPath);
      }
    });

    test('should replace template variables', () => {
      const rendered = TemplateRenderer.renderHTML(testHtmlPath, {
        nonce: 'test-nonce-123'
      });

      expect(rendered).toContain('nonce="test-nonce-123"');
      expect(rendered).not.toContain('{{nonce}}');
    });

    test('should handle missing template file', () => {
      expect(() => {
        TemplateRenderer.renderHTML('/nonexistent/file.html', {});
      }).toThrow('Template not found');
    });

    test('should render with nonce from response locals', () => {
      const res = { locals: { nonce: 'response-nonce' } };
      
      const rendered = TemplateRenderer.renderWithNonce(testHtmlPath, res);
      expect(rendered).toContain('nonce="response-nonce"');
    });

    test('should handle empty nonce gracefully', () => {
      const res = { locals: {} };
      
      const rendered = TemplateRenderer.renderWithNonce(testHtmlPath, res);
      expect(rendered).toContain('nonce=""');
    });
  });
});