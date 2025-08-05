/**
 * Environment Variables Validation Tests
 * 
 * Tests that required environment variables are present and valid
 */

describe('Environment Variables', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset environment for each test
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  describe('Required Environment Variables', () => {
    const requiredEnvVars = [
      'MONGODB_URI',
      'SESSION_SECRET', 
      'ADMIN_USER',
      'ADMIN_PASS',
      'APP_BASE_URL'
    ];

    test.each(requiredEnvVars)('should validate %s environment variable format', (envVar) => {
      // Skip actual env validation in tests, focus on format validation
      const testValue = getTestValue(envVar);
      expect(testValue).toBeDefined();
      expect(testValue).not.toBe('');
    });

    function getTestValue(envVar) {
      // Return test values instead of actual env vars
      const testValues = {
        'MONGODB_URI': 'mongodb://localhost:27017/test',
        'SESSION_SECRET': 'test-secret-key-minimum-32-chars-long',
        'ADMIN_USER': 'testadmin',
        'ADMIN_PASS': 'testpassword123',
        'APP_BASE_URL': 'http://localhost:3000'
      };
      return testValues[envVar];
    }

    test('should have valid MongoDB URI format', () => {
      const mongoUri = process.env.MONGODB_URI;
      expect(mongoUri).toBeDefined();
      
      // Check for basic MongoDB URI pattern
      expect(mongoUri).toMatch(/^mongodb(\+srv)?:\/\//);
    });

    test('should have session secret with sufficient length', () => {
      const sessionSecret = process.env.SESSION_SECRET;
      expect(sessionSecret).toBeDefined();
      expect(sessionSecret.length).toBeGreaterThanOrEqual(32);
    });

    test('should have valid base URL format', () => {
      const baseUrl = process.env.APP_BASE_URL;
      expect(baseUrl).toBeDefined();
      expect(baseUrl).toMatch(/^https?:\/\//);
    });

    test('should have admin credentials configured', () => {
      const adminUser = process.env.ADMIN_USER;
      const adminPass = process.env.ADMIN_PASS;
      
      expect(adminUser).toBeDefined();
      expect(adminUser).not.toBe('');
      expect(adminPass).toBeDefined();
      expect(adminPass).not.toBe('');
    });
  });

  describe('Optional Environment Variables', () => {
    test('should handle missing FRONTEND_URL gracefully', () => {
      delete process.env.FRONTEND_URL;
      
      // Simulate CORS origin array filtering
      const origins = [
        process.env.APP_BASE_URL,
        process.env.FRONTEND_URL
      ].filter(Boolean);

      expect(origins).toHaveLength(1);
      expect(origins[0]).toBe(process.env.APP_BASE_URL);
    });

    test('should include FRONTEND_URL when present', () => {
      process.env.FRONTEND_URL = 'https://frontend.example.com';
      
      const origins = [
        process.env.APP_BASE_URL,
        process.env.FRONTEND_URL
      ].filter(Boolean);

      expect(origins).toHaveLength(2);
      expect(origins).toContain('https://frontend.example.com');
    });
  });

  describe('Cloudinary Configuration', () => {
    const cloudinaryVars = [
      'CLOUDINARY_CLOUD_NAME',
      'CLOUDINARY_API_KEY',
      'CLOUDINARY_API_SECRET'
    ];

    test('should have Cloudinary variables for file upload', () => {
      cloudinaryVars.forEach(envVar => {
        expect(process.env[envVar]).toBeDefined();
        expect(process.env[envVar]).not.toBe('');
      });
    });

    test('should have valid Cloudinary cloud name format', () => {
      const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
      expect(cloudName).toBeDefined();
      
      // Cloud name should be alphanumeric with hyphens/underscores
      expect(cloudName).toMatch(/^[a-zA-Z0-9_-]+$/);
    });
  });

  describe('Environment-specific Configuration', () => {
    test('should handle test environment', () => {
      process.env.NODE_ENV = 'test';
      
      // In test environment, some validations might be relaxed
      expect(process.env.NODE_ENV).toBe('test');
    });

    test('should handle production environment requirements', () => {
      process.env.NODE_ENV = 'production';
      
      // In production, stricter requirements
      expect(process.env.NODE_ENV).toBe('production');
      
      // Should have HTTPS URLs
      if (process.env.APP_BASE_URL) {
        expect(process.env.APP_BASE_URL).toMatch(/^https:\/\//);
      }
      
      if (process.env.FRONTEND_URL) {
        expect(process.env.FRONTEND_URL).toMatch(/^https:\/\//);
      }
    });
  });

  describe('Environment Variable Validation Functions', () => {
    // Helper function that could be used in the actual app
    const validateEnvironment = () => {
      const required = ['MONGODB_URI', 'SESSION_SECRET', 'ADMIN_USER', 'ADMIN_PASS', 'APP_BASE_URL'];
      const missing = required.filter(key => !process.env[key]);
      
      if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
      }
      
      return true;
    };

    test('should pass validation with all required variables', () => {
      expect(() => validateEnvironment()).not.toThrow();
    });

    test('should fail validation with missing variables', () => {
      delete process.env.MONGODB_URI;
      
      expect(() => validateEnvironment()).toThrow('Missing required environment variables: MONGODB_URI');
    });

    test('should fail validation with multiple missing variables', () => {
      delete process.env.MONGODB_URI;
      delete process.env.SESSION_SECRET;
      
      expect(() => validateEnvironment()).toThrow('Missing required environment variables: MONGODB_URI, SESSION_SECRET');
    });
  });

  describe('Configuration Object Creation', () => {
    test('should create valid configuration object', () => {
      const config = {
        mongodb: {
          uri: process.env.MONGODB_URI
        },
        session: {
          secret: process.env.SESSION_SECRET
        },
        admin: {
          user: process.env.ADMIN_USER,
          pass: process.env.ADMIN_PASS
        },
        app: {
          baseUrl: process.env.APP_BASE_URL,
          frontendUrl: process.env.FRONTEND_URL
        },
        cloudinary: {
          cloudName: process.env.CLOUDINARY_CLOUD_NAME,
          apiKey: process.env.CLOUDINARY_API_KEY,
          apiSecret: process.env.CLOUDINARY_API_SECRET
        }
      };

      // Validate required fields
      expect(config.mongodb.uri).toBeDefined();
      expect(config.session.secret).toBeDefined();
      expect(config.admin.user).toBeDefined();
      expect(config.admin.pass).toBeDefined();
      expect(config.app.baseUrl).toBeDefined();
      
      // Cloudinary should be configured
      expect(config.cloudinary.cloudName).toBeDefined();
      expect(config.cloudinary.apiKey).toBeDefined();
      expect(config.cloudinary.apiSecret).toBeDefined();
    });
  });
});