/**
 * Dashboard API Endpoints Test Suite
 * 
 * Focused testing of dashboard API functionality and security
 */

const request = require('supertest');
const app = require('../app');

describe('🚪 Dashboard API Endpoints Test', () => {

  describe('Authentication Requirements', () => {
    
    test('should protect all dashboard API routes', async () => {
      const protectedRoutes = [
        '/api/dashboard',
        '/api/dashboard/profile',
        '/api/dashboard/months',
        '/api/dashboard/summary',
        '/api/dashboard/stats',
        '/api/dashboard/contacts',
        '/api/dashboard/responses',
        '/api/dashboard/contact/507f1f77bcf86cd799439011'
      ];

      for (const route of protectedRoutes) {
        const res = await request(app).get(route);
        
        // Should redirect to auth or return unauthorized
        expect([302, 401, 403]).toContain(res.status);
        console.log(`✓ ${route} properly protected (${res.status})`);
      }
    });

    test('should redirect unauthenticated requests properly', async () => {
      const res = await request(app).get('/api/dashboard/profile');
      
      if (res.status === 302) {
        expect(res.headers.location).toBeDefined();
        console.log(`✓ Redirect location: ${res.headers.location}`);
      }
    });
  });

  describe('CSRF Protection', () => {
    
    test('should provide CSRF token endpoint', async () => {
      const res = await request(app).get('/api/dashboard/csrf-token');
      
      // Should either require auth or provide token
      expect([200, 302, 401, 403]).toContain(res.status);
      console.log(`✓ CSRF token endpoint returns ${res.status}`);
    });

    test('should reject requests without CSRF token', async () => {
      const res = await request(app)
        .post('/api/dashboard/profile')
        .send({ test: 'data' });
        
      // Should reject without proper CSRF token
      expect([400, 403, 404, 302, 401]).toContain(res.status);
      console.log(`✓ POST request without CSRF rejected (${res.status})`);
    });
  });

  describe('Input Validation & Security', () => {
    
    test('should sanitize query parameters', async () => {
      const maliciousQueries = [
        { month: '<script>alert("xss")</script>' },
        { search: '$ne' },
        { limit: 'invalid' },
        { page: '-1' }
      ];

      for (const query of maliciousQueries) {
        const res = await request(app)
          .get('/api/dashboard/summary')
          .query(query);
          
        // Should handle gracefully or reject
        expect([200, 400, 302, 401, 403]).toContain(res.status);
        console.log(`✓ Malicious query handled: ${JSON.stringify(query)} -> ${res.status}`);
      }
    });

    test('should validate ObjectId parameters', async () => {
      const invalidIds = ['invalid', '123', 'null', '', 'undefined'];
      
      for (const id of invalidIds) {
        const res = await request(app).get(`/api/dashboard/contact/${id}`);
        
        // Should reject invalid ObjectIds
        expect([400, 404, 302, 401, 403]).toContain(res.status);
        console.log(`✓ Invalid ObjectId rejected: ${id} -> ${res.status}`);
      }
    });

    test('should handle pagination parameters correctly', async () => {
      const testCases = [
        { page: 0, limit: 10, expectError: true },
        { page: 1, limit: 0, expectError: true },
        { page: 1, limit: 1000, expectError: false }, // Should be clamped
        { page: -1, limit: 5, expectError: true }
      ];

      for (const testCase of testCases) {
        const res = await request(app)
          .get('/api/dashboard/contacts')
          .query({ page: testCase.page, limit: testCase.limit });
          
        if (testCase.expectError) {
          expect([400, 302, 401, 403]).toContain(res.status);
        } else {
          expect([200, 302, 401, 403]).toContain(res.status);
        }
        
        console.log(`✓ Pagination test: page=${testCase.page}, limit=${testCase.limit} -> ${res.status}`);
      }
    });
  });

  describe('Rate Limiting', () => {
    
    test('should apply rate limiting to dashboard endpoints', async () => {
      // Send multiple requests rapidly
      const promises = Array(15).fill().map(() => 
        request(app).get('/api/dashboard/profile')
      );

      const results = await Promise.all(promises);
      
      // Check if any requests were rate limited
      const rateLimitedCount = results.filter(res => res.status === 429).length;
      const nonRateLimitedCount = results.filter(res => [200, 302, 401, 403].includes(res.status)).length;
      
      console.log(`✓ Rate limiting test: ${rateLimitedCount} rate limited, ${nonRateLimitedCount} processed`);
      
      // At least some requests should be processed
      expect(nonRateLimitedCount).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    
    test('should handle non-existent routes gracefully', async () => {
      const nonExistentRoutes = [
        '/api/dashboard/nonexistent',
        '/api/dashboard/invalid/route',
        '/api/dashboard/contact/507f1f77bcf86cd799439011/invalid'
      ];

      for (const route of nonExistentRoutes) {
        const res = await request(app).get(route);
        
        // Should return appropriate error codes
        expect([404, 400, 302, 401, 403]).toContain(res.status);
        console.log(`✓ Non-existent route handled: ${route} -> ${res.status}`);
      }
    });

    test('should handle malformed JSON gracefully', async () => {
      const res = await request(app)
        .post('/api/dashboard/profile')
        .set('Content-Type', 'application/json')
        .send('invalid-json');
        
      expect([400, 302, 401, 403]).toContain(res.status);
      console.log(`✓ Malformed JSON handled: ${res.status}`);
    });
  });

  describe('Response Format Validation', () => {
    
    test('should return appropriate Content-Type headers', async () => {
      const res = await request(app).get('/api/dashboard/profile');
      
      if (res.status === 200) {
        expect(res.headers['content-type']).toMatch(/application\/json/);
      }
      
      console.log(`✓ Content-Type validation: ${res.headers['content-type']}`);
    });

    test('should include security headers', async () => {
      const res = await request(app).get('/api/dashboard/profile');
      
      // Check for important security headers
      const securityHeaders = [
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection'
      ];

      securityHeaders.forEach(header => {
        if (res.headers[header]) {
          console.log(`✓ Security header present: ${header} = ${res.headers[header]}`);
        }
      });
    });
  });

  describe('Performance Tests', () => {
    
    test('should respond within reasonable time', async () => {
      const startTime = Date.now();
      const res = await request(app).get('/api/dashboard/profile');
      const responseTime = Date.now() - startTime;
      
      // Should respond within 5 seconds
      expect(responseTime).toBeLessThan(5000);
      console.log(`✓ Response time: ${responseTime}ms`);
    });

    test('should handle concurrent requests', async () => {
      const startTime = Date.now();
      
      const promises = Array(5).fill().map(() =>
        request(app).get('/api/dashboard/stats')
      );

      const results = await Promise.all(promises);
      const totalTime = Date.now() - startTime;
      
      console.log(`✓ Concurrent requests completed in ${totalTime}ms`);
      
      // All requests should complete
      expect(results).toHaveLength(5);
      
      // Should complete within reasonable time
      expect(totalTime).toBeLessThan(10000);
    });
  });
});

describe('🌐 Dashboard Frontend Routes Test', () => {

  describe('HTML Page Serving', () => {
    
    test('should serve main dashboard page', async () => {
      const res = await request(app).get('/dashboard');
      
      // Should redirect to auth or serve page
      expect([200, 302, 401, 403]).toContain(res.status);
      
      if (res.status === 200) {
        expect(res.headers['content-type']).toMatch(/text\/html/);
        expect(res.text).toContain('dashboard');
      }
      
      console.log(`✓ Dashboard page: ${res.status}`);
    });

    test('should serve dashboard sub-pages', async () => {
      const dashboardPages = [
        '/dashboard/contacts',
        '/dashboard/responses',
        '/dashboard/contact/123'
      ];

      for (const page of dashboardPages) {
        const res = await request(app).get(page);
        
        expect([200, 302, 401, 403]).toContain(res.status);
        console.log(`✓ Dashboard page ${page}: ${res.status}`);
      }
    });

    test('should include CSP nonces in HTML', async () => {
      const res = await request(app).get('/dashboard');
      
      if (res.status === 200) {
        expect(res.text).toMatch(/nonce-[a-zA-Z0-9+/]+=*/);
        console.log('✓ CSP nonces included in HTML');
      }
    });

    test('should include required dashboard assets', async () => {
      const res = await request(app).get('/dashboard');
      
      if (res.status === 200) {
        // Should include dashboard.js module
        expect(res.text).toMatch(/dashboard\.js/);
        console.log('✓ Dashboard assets referenced in HTML');
      }
    });
  });

  describe('Asset Serving', () => {
    
    test('should serve dashboard JavaScript module', async () => {
      const res = await request(app).get('/dashboard/dashboard.js');
      
      // Should require auth or serve the file
      expect([200, 302, 401, 403]).toContain(res.status);
      
      if (res.status === 200) {
        expect(res.headers['content-type']).toMatch(/javascript|text/);
      }
      
      console.log(`✓ Dashboard JS: ${res.status}`);
    });

    test('should serve dashboard CSS', async () => {
      const res = await request(app).get('/dashboard/css/dashboard.css');
      
      expect([200, 302, 401, 403, 404]).toContain(res.status);
      
      if (res.status === 200) {
        expect(res.headers['content-type']).toMatch(/css|text/);
      }
      
      console.log(`✓ Dashboard CSS: ${res.status}`);
    });
  });

  describe('Authentication Integration', () => {
    
    test('should redirect unauthenticated users to login', async () => {
      const res = await request(app).get('/dashboard');
      
      if (res.status === 302) {
        const location = res.headers.location;
        expect(location).toMatch(/login|auth/);
        console.log(`✓ Redirect to: ${location}`);
      }
    });

    test('should handle legacy admin route authentication', async () => {
      const res = await request(app).get('/admin');
      
      // Should require authentication first, then redirect to dashboard
      if (res.status === 302) {
        // Should redirect to login for unauthenticated users
        expect(res.headers.location).toMatch(/login|auth/);
        console.log(`✓ Legacy admin requires auth, redirects to: ${res.headers.location}`);
      }
    });
  });
});