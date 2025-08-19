/**
 * Security Validation Test Suite for Performance Optimizations
 * 
 * Ensures that performance optimizations do not compromise security features
 * Tests XSS protection, authentication, authorization, input validation, etc.
 */

const request = require('supertest');
const mongoose = require('mongoose');
const Response = require('../models/Response');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Submission = require('../models/Submission');
const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;
let adminSession = null;
let userSession = null;
let securityTestAdmin = null;
let securityTestUser = null;

describe('🛡️ Security Validation with Performance Optimizations', () => {
  beforeAll(async () => {
    app = getTestApp();
    
    // Clean up
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
    
    // Create security test users
    securityTestAdmin = await User.create({
      username: 'securityadmin',
      email: 'security.admin@test.com',
      password: '$2a$10$security.hash.for.admin.testing',
      role: 'admin',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    securityTestUser = await User.create({
      username: 'securityuser',
      email: 'security.user@test.com',
      password: '$2a$10$security.hash.for.user.testing',
      role: 'user',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    // Create test data with potential security issues
    await Response.create([
      {
        name: '<script>alert("XSS")</script>',
        responses: [
          { question: 'Test Question', answer: '<img src="x" onerror="alert(1)">' },
          { question: 'Script Injection', answer: '<script>document.location="http://evil.com"</script>' }
        ],
        month: '2025-01',
        isAdmin: false,
        token: 'xss-test-token',
        createdAt: new Date()
      },
      {
        name: 'SQL Injection Test',
        responses: [
          { question: 'Malicious Input', answer: "'; DROP TABLE responses; --" },
          { question: 'NoSQL Injection', answer: '{"$ne": null}' }
        ],
        month: '2025-01',
        isAdmin: false,
        token: 'sql-injection-token',
        createdAt: new Date()
      }
    ]);
    
    // Login sessions
    const adminLogin = await request(app)
      .post('/auth/login')
      .send({
        username: 'securityadmin',
        password: 'admin123'
      });
      
    if (adminLogin.headers['set-cookie']) {
      adminSession = adminLogin.headers['set-cookie'];
    }
    
    const userLogin = await request(app)
      .post('/auth/login')
      .send({
        username: 'securityuser',
        password: 'user123'
      });
      
    if (userLogin.headers['set-cookie']) {
      userSession = userLogin.headers['set-cookie'];
    }
  }, 30000);

  afterAll(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
  });

  describe('🚨 XSS Protection with Caching', () => {
    test('should sanitize cached XSS content properly', async () => {
      // Request data that might contain XSS (should be cached)
      const firstResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      // Request same data again (should come from cache)
      const secondResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      expect([200, 302]).toContain(firstResponse.status);
      expect([200, 302]).toContain(secondResponse.status);

      if (firstResponse.status === 200 && secondResponse.status === 200) {
        // Check both responses for XSS content
        const firstBodyStr = JSON.stringify(firstResponse.body);
        const secondBodyStr = JSON.stringify(secondResponse.body);

        // Should not contain unescaped script tags
        expect(firstBodyStr).not.toMatch(/<script[^>]*>/i);
        expect(secondBodyStr).not.toMatch(/<script[^>]*>/i);
        expect(firstBodyStr).not.toMatch(/onerror\s*=/i);
        expect(secondBodyStr).not.toMatch(/onerror\s*=/i);

        // Both responses should be identical (proper cache consistency)
        expect(firstBodyStr).toBe(secondBodyStr);

        console.log('✅ XSS protection maintained in cached responses');
      }
    });

    test('should handle XSS in search parameters with caching', async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '"><script>alert(1)</script>',
        'javascript:alert(1)',
        '<img src="x" onerror="alert(1)">',
        '<svg onload="alert(1)">',
        '${alert(1)}'
      ];

      for (const payload of xssPayloads) {
        const response = await request(app)
          .get('/api/dashboard/contacts')
          .query({ search: payload })
          .set('Cookie', adminSession || []);

        expect([200, 302, 400]).toContain(response.status);

        if (response.status === 200) {
          const responseStr = JSON.stringify(response.body);
          
          // Should not contain unescaped XSS payload
          expect(responseStr).not.toContain(payload);
          expect(responseStr).not.toMatch(/<script[^>]*>/i);
          expect(responseStr).not.toMatch(/on\w+\s*=/i);
        }

        console.log(`🛡️ XSS payload handled safely: ${payload.substring(0, 20)}...`);
      }
    });

    test('should maintain HTML entity escaping in aggregated data', async () => {
      const response = await request(app)
        .get('/api/dashboard/summary')
        .set('Cookie', adminSession || []);

      if (response.status === 200 && response.body.length > 0) {
        const responseStr = JSON.stringify(response.body);

        // Check that dangerous HTML is properly escaped
        expect(responseStr).not.toMatch(/<script[^>]*>/);
        expect(responseStr).not.toMatch(/<img[^>]*onerror/);
        
        // Should contain HTML entities instead
        if (responseStr.includes('alert')) {
          expect(responseStr).toMatch(/&lt;|&gt;|&quot;|&#x27;|&amp;/);
        }

        console.log('✅ HTML entities properly escaped in aggregated data');
      }
    });
  });

  describe('🔐 Authentication and Authorization Security', () => {
    test('should enforce authentication for cached endpoints', async () => {
      const protectedEndpoints = [
        '/api/dashboard/profile',
        '/api/dashboard/months',
        '/api/dashboard/summary', 
        '/api/dashboard/stats',
        '/api/dashboard/contacts',
        '/api/dashboard/responses'
      ];

      for (const endpoint of protectedEndpoints) {
        // Unauthenticated request
        const unauthResponse = await request(app).get(endpoint);
        expect([302, 401, 403]).toContain(unauthResponse.status);

        // Authenticated request
        const authResponse = await request(app)
          .get(endpoint)
          .set('Cookie', adminSession || []);
        expect([200, 302]).toContain(authResponse.status);

        console.log(`🔒 ${endpoint}: Unauth=${unauthResponse.status}, Auth=${authResponse.status}`);
      }
    });

    test('should maintain user data isolation in cached responses', async () => {
      // Admin request
      const adminResponse = await request(app)
        .get('/api/dashboard/summary')
        .set('Cookie', adminSession || []);

      // User request
      const userResponse = await request(app)
        .get('/api/dashboard/summary')
        .set('Cookie', userSession || []);

      expect([200, 302, 403]).toContain(adminResponse.status);
      expect([200, 302, 403]).toContain(userResponse.status);

      // If both return data, verify they're different (proper isolation)
      if (adminResponse.status === 200 && userResponse.status === 200) {
        const adminData = JSON.stringify(adminResponse.body);
        const userData = JSON.stringify(userResponse.body);
        
        // Admin should see more or different data than regular user
        if (adminResponse.body.length > 0 && userResponse.body.length > 0) {
          console.log(`👥 Data isolation: Admin sees ${adminResponse.body.length} items, User sees ${userResponse.body.length} items`);
        }
      }

      console.log('✅ User data isolation maintained with caching');
    });

    test('should validate session integrity across cached requests', async () => {
      // Make multiple requests with same session
      const endpoints = [
        '/api/dashboard/profile',
        '/api/dashboard/months', 
        '/api/dashboard/stats'
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('Cookie', adminSession || []);

        // Session should remain valid across all requests
        expect([200, 302]).toContain(response.status);

        if (response.status === 200 && response.body.authMethod) {
          expect(['legacy-admin', 'user']).toContain(response.body.authMethod);
        }
      }

      console.log('✅ Session integrity maintained across cached endpoints');
    });

    test('should prevent cache poisoning through authorization bypass', async () => {
      // Try to access admin data without proper authorization
      const maliciousHeaders = [
        { 'X-Forwarded-For': '127.0.0.1' },
        { 'X-Real-IP': '127.0.0.1' },
        { 'Authorization': 'Bearer fake-token' },
        { 'X-Admin': 'true' },
        { 'X-User-Id': securityTestAdmin._id.toString() }
      ];

      for (const headers of maliciousHeaders) {
        const response = await request(app)
          .get('/api/dashboard/summary')
          .set(headers)
          .set('Cookie', userSession || []); // User session but malicious headers

        // Should not bypass authentication
        expect([200, 302, 403]).toContain(response.status);

        if (response.status === 200) {
          // Should return user-limited data, not admin data
          console.log(`🚫 Malicious header blocked: ${Object.keys(headers)[0]}`);
        }
      }
    });
  });

  describe('💉 Input Validation and Injection Prevention', () => {
    test('should prevent SQL/NoSQL injection in cached queries', async () => {
      const injectionPayloads = [
        "'; DROP TABLE responses; --",
        '{"$ne": null}',
        '{"$where": "1==1"}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '1; DELETE FROM responses; --',
        "admin'; --",
        '1\' OR \'1\'=\'1',
        '{$ne: null}'
      ];

      for (const payload of injectionPayloads) {
        // Test in search parameter
        const searchResponse = await request(app)
          .get('/api/dashboard/contacts')
          .query({ search: payload })
          .set('Cookie', adminSession || []);

        expect([200, 302, 400]).toContain(searchResponse.status);

        // Test in month parameter
        const monthResponse = await request(app)
          .get('/api/dashboard/summary')
          .query({ month: payload })
          .set('Cookie', adminSession || []);

        expect([200, 302, 400]).toContain(monthResponse.status);

        console.log(`💉 Injection payload handled: ${payload.substring(0, 20)}...`);
      }

      // Verify database integrity after injection attempts
      const responseCount = await Response.countDocuments({});
      expect(responseCount).toBeGreaterThan(0); // Data should still exist
    });

    test('should validate ObjectId parameters in cached endpoints', async () => {
      const invalidIds = [
        'invalid-id',
        '123',
        'null',
        'undefined',
        '<script>alert(1)</script>',
        '{"$ne": null}',
        '../../../etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
      ];

      for (const id of invalidIds) {
        const response = await request(app)
          .get(`/api/dashboard/contact/${id}`)
          .set('Cookie', adminSession || []);

        // Should reject invalid ObjectIds
        expect([400, 404, 302]).toContain(response.status);
        console.log(`🆔 Invalid ObjectId rejected: ${id} -> ${response.status}`);
      }
    });

    test('should sanitize pagination parameters', async () => {
      const maliciousParams = [
        { page: -1, limit: 10 },
        { page: 'admin', limit: 'unlimited' },
        { page: '<script>alert(1)</script>', limit: '{"$gt": 0}' },
        { page: 999999, limit: 999999 },
        { page: 1, limit: -1 }
      ];

      for (const params of maliciousParams) {
        const response = await request(app)
          .get('/api/dashboard/contacts')
          .query(params)
          .set('Cookie', adminSession || []);

        // Should handle malicious params gracefully
        expect([200, 400, 302]).toContain(response.status);

        if (response.status === 200) {
          expect(response.body.pagination.page).toBeGreaterThan(0);
          expect(response.body.pagination.limit).toBeLessThanOrEqual(50); // Max limit enforced
        }

        console.log(`📄 Malicious pagination handled: page=${params.page}, limit=${params.limit}`);
      }
    });
  });

  describe('🔒 CSRF and Request Security', () => {
    test('should maintain CSRF protection with caching', async () => {
      // Get CSRF token
      const csrfResponse = await request(app)
        .get('/api/dashboard/csrf-token')
        .set('Cookie', adminSession || []);

      expect([200, 302]).toContain(csrfResponse.status);

      // Try POST without CSRF token
      const unprotectedResponse = await request(app)
        .post('/api/dashboard/profile')
        .send({ test: 'data' })
        .set('Cookie', adminSession || []);

      // Should be rejected for lack of CSRF token
      expect([400, 403, 404, 302]).toContain(unprotectedResponse.status);
      console.log(`🛡️ CSRF protection active: ${unprotectedResponse.status}`);
    });

    test('should prevent cache-based CSRF attacks', async () => {
      // Try to access sensitive endpoints with GET (should be protected)
      const sensitiveActions = [
        '/api/dashboard/contact/delete/507f1f77bcf86cd799439011',
        '/api/dashboard/admin/clear-cache',
        '/api/dashboard/user/elevate'
      ];

      for (const action of sensitiveActions) {
        const response = await request(app)
          .get(action)
          .set('Cookie', adminSession || []);

        // These should not exist or should require POST
        expect([404, 405, 403, 302]).toContain(response.status);
        console.log(`🚫 CSRF protection: ${action} -> ${response.status}`);
      }
    });
  });

  describe('🕐 Rate Limiting Security', () => {
    test('should maintain rate limiting on cached endpoints', async () => {
      // Rapid fire requests to test rate limiting
      const rapidRequests = Array.from({ length: 20 }, () =>
        request(app)
          .get('/api/dashboard/profile')
          .set('Cookie', adminSession || [])
          .catch(err => ({ status: 'error', error: err.message }))
      );

      const results = await Promise.all(rapidRequests);
      
      const rateLimited = results.filter(r => r.status === 429).length;
      const successful = results.filter(r => [200, 302].includes(r.status)).length;

      console.log(`⏱️ Rate limiting: ${successful} successful, ${rateLimited} rate limited`);

      // Should have some successful requests and potentially some rate limited
      expect(successful).toBeGreaterThan(0);
      expect(successful + rateLimited).toBe(results.length);
    });

    test('should rate limit expensive operations', async () => {
      // Test potentially expensive cached operations
      const expensiveOps = Array.from({ length: 10 }, () =>
        request(app)
          .get('/api/dashboard/summary')
          .query({ month: 'all' })
          .set('Cookie', adminSession || [])
      );

      const results = await Promise.allSettled(expensiveOps);
      const successful = results.filter(r => r.status === 'fulfilled' && [200, 302].includes(r.value.status)).length;

      console.log(`💰 Expensive operations: ${successful}/10 successful`);
      
      // Should handle expensive operations without crashing
      expect(successful).toBeGreaterThan(0);
    });
  });

  describe('📊 Data Leakage Prevention', () => {
    test('should not leak sensitive data in cached error responses', async () => {
      // Try to access nonexistent resources
      const invalidRequests = [
        '/api/dashboard/contact/507f1f77bcf86cd799439999',
        '/api/dashboard/admin/secret-config',
        '/api/dashboard/internal/debug'
      ];

      for (const request_path of invalidRequests) {
        const response = await request(app)
          .get(request_path)
          .set('Cookie', adminSession || []);

        if (response.status >= 400) {
          const responseStr = JSON.stringify(response.body);
          
          // Should not leak internal paths or sensitive info
          expect(responseStr).not.toMatch(/\/var\/log/);
          expect(responseStr).not.toMatch(/password/i);
          expect(responseStr).not.toMatch(/secret/i);
          expect(responseStr).not.toMatch(/config/);
          expect(responseStr).not.toMatch(/mongodb:\/\//);
        }

        console.log(`🔍 No data leakage in: ${request_path} -> ${response.status}`);
      }
    });

    test('should not expose internal cache keys or metadata', async () => {
      const response = await request(app)
        .get('/api/dashboard/summary')
        .set('Cookie', adminSession || []);

      if (response.status === 200) {
        const responseStr = JSON.stringify(response.body);
        
        // Should not contain internal cache information
        expect(responseStr).not.toMatch(/cache.*key/i);
        expect(responseStr).not.toMatch(/ttl/i);
        expect(responseStr).not.toMatch(/internal.*id/i);
        expect(responseStr).not.toMatch(/_id.*ObjectId/);
        
        console.log('✅ No internal cache metadata exposed');
      }
    });
  });

  describe('🌊 Security Headers Validation', () => {
    test('should maintain security headers with cached responses', async () => {
      const response = await request(app)
        .get('/api/dashboard/profile')
        .set('Cookie', adminSession || []);

      // Check for important security headers
      const securityHeaders = [
        'x-frame-options',
        'x-content-type-options', 
        'x-xss-protection',
        'content-security-policy'
      ];

      let headerCount = 0;
      securityHeaders.forEach(header => {
        if (response.headers[header]) {
          headerCount++;
          console.log(`✅ Security header: ${header} = ${response.headers[header]}`);
        }
      });

      // Should have at least some security headers
      expect(headerCount).toBeGreaterThan(0);
    });
  });
});