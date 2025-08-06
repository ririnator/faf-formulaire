const request = require('supertest');
const { createSecurityMiddleware, createSessionOptions, getEnvironmentInfo } = require('../middleware/security');

// Mock Express app for testing security middleware
const express = require('express');

describe('Enhanced Security Middleware', () => {
  let app;
  let originalNodeEnv;

  beforeEach(() => {
    originalNodeEnv = process.env.NODE_ENV;
    app = express();
  });

  afterEach(() => {
    process.env.NODE_ENV = originalNodeEnv;
  });

  describe('Nonce-based CSP', () => {
    test('should generate unique nonce for each request', async () => {
      app.use(createSecurityMiddleware());
      app.get('/test', (req, res) => {
        res.json({ nonce: res.locals.nonce });
      });

      const response1 = await request(app).get('/test');
      const response2 = await request(app).get('/test');

      expect(response1.body.nonce).toBeDefined();
      expect(response2.body.nonce).toBeDefined();
      expect(response1.body.nonce).not.toBe(response2.body.nonce);
    });

    test('should set CSP headers with nonce', async () => {
      app.use(createSecurityMiddleware());
      app.get('/test', (req, res) => res.send('OK'));

      const response = await request(app).get('/test');
      
      const cspHeader = response.headers['content-security-policy'];
      expect(cspHeader).toBeDefined();
      expect(cspHeader).toContain('nonce-');
      expect(cspHeader).not.toContain('unsafe-inline');
    });

    test('should include allowed external domains in CSP', async () => {
      app.use(createSecurityMiddleware());
      app.get('/test', (req, res) => res.send('OK'));

      const response = await request(app).get('/test');
      const cspHeader = response.headers['content-security-policy'];
      
      expect(cspHeader).toContain('cdn.tailwindcss.com');
      expect(cspHeader).toContain('cdn.jsdelivr.net');
      expect(cspHeader).toContain('res.cloudinary.com');
    });

    test('should deny frame embedding', async () => {
      app.use(createSecurityMiddleware());
      app.get('/test', (req, res) => res.send('OK'));

      const response = await request(app).get('/test');
      const cspHeader = response.headers['content-security-policy'];
      
      expect(cspHeader).toContain("frame-src 'none'");
    });
  });

  describe('Enhanced Session Configuration', () => {
    test('should create secure session config for production', () => {
      process.env.NODE_ENV = 'production';
      const sessionConfig = createSessionOptions();

      expect(sessionConfig.cookie.sameSite).toBe('none');
      expect(sessionConfig.cookie.secure).toBe(true);
      expect(sessionConfig.cookie.httpOnly).toBe(true);
      expect(sessionConfig.name).toBe('faf-session');
    });

    test('should create dev-friendly session config for development', () => {
      process.env.NODE_ENV = 'development';
      const sessionConfig = createSessionOptions();

      expect(sessionConfig.cookie.sameSite).toBe('lax');
      expect(sessionConfig.cookie.secure).toBe(false);
      expect(sessionConfig.cookie.httpOnly).toBe(true);
    });

    test('should handle HTTPS override in development', () => {
      process.env.NODE_ENV = 'development';
      process.env.HTTPS = 'true';
      
      const sessionConfig = createSessionOptions();

      expect(sessionConfig.cookie.sameSite).toBe('lax');
      expect(sessionConfig.cookie.secure).toBe(true); // HTTPS override
    });

    test('should set custom domain in production when provided', () => {
      process.env.NODE_ENV = 'production';
      process.env.COOKIE_DOMAIN = '.example.com';
      
      const sessionConfig = createSessionOptions();

      expect(sessionConfig.cookie.domain).toBe('.example.com');
      expect(sessionConfig.cookie.path).toBe('/');
      
      delete process.env.COOKIE_DOMAIN;
    });

    test('should have proper session duration', () => {
      const sessionConfig = createSessionOptions();
      
      expect(sessionConfig.cookie.maxAge).toBe(1000 * 60 * 60); // 1 hour
      expect(sessionConfig.store).toBeDefined();
    });
  });

  describe('Environment Detection', () => {
    test('should correctly detect production environment', () => {
      process.env.NODE_ENV = 'production';
      const envInfo = getEnvironmentInfo();

      expect(envInfo.isProduction).toBe(true);
      expect(envInfo.isDevelopment).toBe(false);
      expect(envInfo.isHttps).toBe(true);
    });

    test('should correctly detect development environment', () => {
      process.env.NODE_ENV = 'development';
      delete process.env.HTTPS; // Ensure HTTPS is not set
      const envInfo = getEnvironmentInfo();

      expect(envInfo.isProduction).toBe(false);
      expect(envInfo.isDevelopment).toBe(true);
      expect(envInfo.isHttps).toBe(false);
    });

    test('should default to development when NODE_ENV is not set', () => {
      delete process.env.NODE_ENV;
      delete process.env.HTTPS; // Ensure HTTPS is not set
      const envInfo = getEnvironmentInfo();

      expect(envInfo.isProduction).toBe(false);
      expect(envInfo.isDevelopment).toBe(true);
      expect(envInfo.isHttps).toBe(false);
    });

    test('should detect custom domain configuration', () => {
      process.env.COOKIE_DOMAIN = '.example.com';
      const envInfo = getEnvironmentInfo();

      expect(envInfo.hasCustomDomain).toBe(true);
      
      delete process.env.COOKIE_DOMAIN;
    });
  });

  describe('Security Headers Validation', () => {
    test('should set all required security headers', async () => {
      app.use(createSecurityMiddleware());
      app.get('/test', (req, res) => res.send('OK'));

      const response = await request(app).get('/test');
      
      expect(response.headers['content-security-policy']).toBeDefined();
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('SAMEORIGIN');
      expect(response.headers['x-xss-protection']).toBeDefined();
    });

    test('should not include deprecated unsafe-inline in CSP', async () => {
      app.use(createSecurityMiddleware());
      app.get('/test', (req, res) => res.send('OK'));

      const response = await request(app).get('/test');
      const cspHeader = response.headers['content-security-policy'];
      
      expect(cspHeader).not.toContain("'unsafe-inline'");
    });
  });

  describe('Regression Tests', () => {
    test('should maintain backward compatibility with existing functionality', () => {
      const sessionConfig = createSessionOptions();
      
      // Verify core session properties are maintained
      expect(sessionConfig.secret).toBe(process.env.SESSION_SECRET);
      expect(sessionConfig.resave).toBe(false);
      expect(sessionConfig.saveUninitialized).toBe(false);
      expect(sessionConfig.store).toBeDefined();
    });

    test('should not break existing middleware chain', async () => {
      app.use(createSecurityMiddleware());
      app.use((req, res, next) => {
        res.locals.testValue = 'middleware-works';
        next();
      });
      app.get('/test', (req, res) => {
        res.json({ 
          nonce: res.locals.nonce, 
          test: res.locals.testValue 
        });
      });

      const response = await request(app).get('/test');
      
      expect(response.body.nonce).toBeDefined();
      expect(response.body.test).toBe('middleware-works');
    });
  });

  describe('Performance Impact', () => {
    test('should generate nonce efficiently', () => {
      const { generateNonce } = require('../middleware/security');
      
      const start = Date.now();
      for (let i = 0; i < 1000; i++) {
        generateNonce();
      }
      const end = Date.now();
      
      // Should generate 1000 nonces in less than 100ms
      expect(end - start).toBeLessThan(100);
    });

    test('should reuse session config object', () => {
      const config1 = createSessionOptions();
      const config2 = createSessionOptions();
      
      // Configs should have same structure but different store instances
      expect(config1.secret).toBe(config2.secret);
      expect(config1.cookie.maxAge).toBe(config2.cookie.maxAge);
    });
  });
});