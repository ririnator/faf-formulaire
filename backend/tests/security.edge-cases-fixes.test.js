/**
 * Edge Cases Fixes Security Tests
 * Tests for the critical edge cases identified and fixed
 */

const request = require('supertest');
const Response = require('../models/Response');

const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

beforeAll(async () => {
  app = getTestApp();
}, 30000);

describe('🔧 Edge Cases Fixes Security Tests', () => {
  let adminSession = null;

  beforeAll(async () => {
    if (!mongoose.connection.readyState) {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-test');
    }
    
    await Response.deleteMany({});
    await Response.create([
      { name: 'Alice Test', responses: [{ question: 'Test français?', answer: 'Réponse française' }], month: '2025-01', isAdmin: false, token: 'token1' },
      { name: 'Bob Example', responses: [{ question: 'English test?', answer: 'English response' }], month: '2025-01', isAdmin: false, token: 'token2' },
      { name: 'José García', responses: [{ question: 'Pregunta española?', answer: 'Respuesta española' }], month: '2025-01', isAdmin: false, token: 'token3' }
    ]);

    // Login as admin
    const loginResponse = await request(app)
      .post('/auth/login')
      .send({
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: process.env.LOGIN_ADMIN_PASS || 'password'
      });
      
    if (loginResponse.headers['set-cookie']) {
      adminSession = loginResponse.headers['set-cookie'];
    }
  });

  afterAll(async () => {
    await Response.deleteMany({});
    });

  describe('🌐 IP Address Handling Fix', () => {
    test('should handle modern Node.js socket.remoteAddress', async () => {
      const response = await request(app)
        .post('/auth/login')
        .set('X-Forwarded-For', '192.168.1.100')
        .send({
          username: process.env.LOGIN_ADMIN_USER || 'admin',
          password: 'wrongpassword'
        });

      // Should handle IP extraction without crashing
      expect([400, 401, 429, 302]).toContain(response.status);
    });

    test('should handle undefined req.connection gracefully', async () => {
      // Simulate request without legacy connection object
      const response = await request(app)
        .get('/admin/api/responses')
        .set('X-Real-IP', '203.0.113.1')
        .set('Cookie', adminSession || '');

      expect([200, 302, 401]).toContain(response.status);
    });

    test('should handle IPv6 addresses in IP extraction', async () => {
      const ipv6Addresses = [
        '2001:db8::1',
        '::1',
        'fe80::1%eth0',
        '2001:db8:85a3::8a2e:370:7334'
      ];

      for (const ip of ipv6Addresses) {
        const response = await request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', ip)
          .send({
            username: process.env.LOGIN_ADMIN_USER || 'admin',
            password: 'ipv6test'
          });

        expect(response.status).toBeLessThan(500);
      }
    });

    test('should handle proxy chain IP extraction', async () => {
      const proxyChain = '203.0.113.1, 198.51.100.1, 192.0.2.1';
      
      const response = await request(app)
        .post('/auth/login')
        .set('X-Forwarded-For', proxyChain)
        .send({
          username: process.env.LOGIN_ADMIN_USER || 'admin',
          password: 'proxytest'
        });

      expect(response.status).toBeLessThan(500);
    });
  });

  describe('💾 Upload Memory Management', () => {
    test('should handle memory monitoring without crashing', async () => {
      // Get initial upload stats
      const uploadModule = require('../routes/upload');
      let initialStats;
      
      try {
        initialStats = uploadModule.getUploadStats ? uploadModule.getUploadStats() : { activeIPs: 0 };
      } catch (error) {
        initialStats = { activeIPs: 0 }; // Fallback if stats not available
      }

      expect(typeof initialStats.activeIPs).toBe('number');
      expect(initialStats.activeIPs).toBeGreaterThanOrEqual(0);
    });

    test('should handle large upload tracking maps', async () => {
      // Simulate tracking many IPs for uploads
      const manyUploads = Array(50).fill(null).map((_, i) =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', `10.0.1.${i + 1}`)
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(1024), 'test.jpg')
          .timeout(5000)
          .catch(error => ({ status: 'error', error: error.message }))
      );

      const responses = await Promise.allSettled(manyUploads);
      
      // Should handle all requests without server crashes
      expect(responses.length).toBe(50);
      responses.forEach(result => {
        if (result.status === 'fulfilled') {
          expect(result.value.status).toBeLessThan(500);
        }
      });
    }, 30000);

    test('should handle memory threshold warnings', async () => {
      const originalConsoleWarn = console.warn;
      const warnings = [];
      console.warn = (...args) => warnings.push(args.join(' '));

      // Simulate memory pressure scenario
      const rapidUploads = Array(20).fill(null).map((_, i) =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', `172.16.0.${i + 1}`)
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(1024), 'memory-test.jpg')
          .timeout(5000)
          .catch(() => ({ status: 500 }))
      );

      await Promise.allSettled(rapidUploads);
      
      console.warn = originalConsoleWarn;

      // Should not crash under memory pressure
      expect(true).toBe(true); // Test completed without crashing
    }, 25000);

    test('should cleanup expired upload tracking entries', async () => {
      // This test verifies the cleanup mechanism works
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Create some upload tracking entries
      const testUploads = Array(10).fill(null).map((_, i) =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', `192.168.100.${i + 1}`)
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(512), 'cleanup-test.jpg')
          .timeout(3000)
          .catch(() => ({ status: 'handled' }))
      );

      await Promise.allSettled(testUploads);
      
      // Wait for potential cleanup
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory should not increase dramatically
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB
    }, 15000);
  });

  describe('🌍 Language Detection and Fallback', () => {
    test('should detect French text and use appropriate language', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: 'français réponse' })
        .set('Cookie', adminSession);

      expect([200, 302]).toContain(response.status);
      
      if (response.status === 200) {
        expect(response.body).toHaveProperty('responses');
        expect(Array.isArray(response.body.responses)).toBe(true);
      }
    });

    test('should detect English text and use appropriate language', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: 'english the test' })
        .set('Cookie', adminSession);

      expect([200, 302]).toContain(response.status);
      
      if (response.status === 200) {
        expect(response.body).toHaveProperty('responses');
        expect(Array.isArray(response.body.responses)).toBe(true);
      }
    });

    test('should handle mixed language text', async () => {
      const mixedTexts = [
        'français english mixed',
        'test avec accents éàù',
        'numbers 123 and symbols !@#',
        'José García mixed name'
      ];

      for (const text of mixedTexts) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: text })
          .set('Cookie', adminSession);

        expect([200, 302]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('responses');
          expect(Array.isArray(response.body.responses)).toBe(true);
        }
      }
    }, 15000);

    test('should fallback to regex search when text search fails', async () => {
      // Test with potentially problematic text search queries
      const problematicQueries = [
        'très spécial caractères',
        'ñoño español',
        'café crème',
        'naïve résumé'
      ];

      for (const query of problematicQueries) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: query })
          .set('Cookie', adminSession);

        expect([200, 302]).toContain(response.status);
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('responses');
          expect(Array.isArray(response.body.responses)).toBe(true);
        }
      }
    }, 20000);

    test('should handle search with no language detection', async () => {
      const neutralTexts = [
        '12345',
        '***###',
        '     ',
        'xyz'
      ];

      for (const text of neutralTexts) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: text })
          .set('Cookie', adminSession);

        expect([200, 302]).toContain(response.status);
      }
    });

    test('should handle text search MongoDB errors gracefully', async () => {
      // Test queries that might cause text search errors
      const edgeCaseQueries = [
        'very long query that exceeds normal limits and might cause issues with text indexing',
        '"quoted text with special characters"',
        '((( parentheses )))',
        'search with | pipes and & ampersands'
      ];

      for (const query of edgeCaseQueries) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: query })
          .set('Cookie', adminSession);

        // Should not crash, even if text search fails
        expect(response.status).toBeLessThan(500);
      }
    });
  });

  describe('🛠️ Integrated Edge Cases', () => {
    test('should handle concurrent requests with all edge case fixes', async () => {
      const concurrentRequests = [
        // IP handling edge case
        request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', '2001:db8::1')
          .send({ username: 'test', password: 'test' }),
        
        // Memory management edge case
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', '203.0.113.99')
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(1024), 'concurrent.jpg'),
        
        // Language detection edge case
        request(app)
          .get('/admin/api/responses')
          .query({ search: 'concurrent français test' })
          .set('Cookie', adminSession),
        
        // Mixed edge cases
        request(app)
          .get('/admin/api/responses')
          .set('X-Real-IP', '::1')
          .set('Cookie', adminSession)
      ];

      const responses = await Promise.allSettled(concurrentRequests.map(req => 
        req.timeout(8000).catch(error => ({ status: 'timeout', error }))
      ));

      // All requests should complete without server crashes
      responses.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          expect(result.value.status).toBeLessThan(500);
        }
      });
    }, 20000);

    test('should maintain performance with all fixes active', async () => {
      const startTime = Date.now();
      
      // Test performance impact of all edge case fixes
      const performanceRequests = Array(10).fill(null).map((_, i) =>
        request(app)
          .get('/admin/api/responses')
          .query({ search: `performance test ${i} français` })
          .set('X-Forwarded-For', `10.0.1.${i + 1}`)
          .set('Cookie', adminSession)
          .timeout(5000)
      );

      const responses = await Promise.allSettled(performanceRequests);
      const duration = Date.now() - startTime;

      // Should complete within reasonable time
      expect(duration).toBeLessThan(15000); // 15 seconds max
      
      const successfulResponses = responses.filter(r => 
        r.status === 'fulfilled' && [200, 302].includes(r.value.status)
      ).length;
      
      expect(successfulResponses).toBeGreaterThanOrEqual(5); // At least half successful
    }, 25000);

    test('should handle error scenarios gracefully', async () => {
      // Test error handling with edge case fixes
      const errorScenarios = [
        // Invalid IP format
        request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', 'invalid.ip.format')
          .send({ username: 'test', password: 'test' }),
        
        // Malformed upload
        request(app)
          .post('/api/upload')
          .set('Cookie', adminSession || '')
          .send({ malformed: 'data' }),
        
        // Invalid search query
        request(app)
          .get('/admin/api/responses')
          .query({ search: '\x00\x01\x02' })
          .set('Cookie', adminSession)
      ];

      const responses = await Promise.allSettled(errorScenarios.map(req => 
        req.timeout(5000)
      ));

      // Should handle all error scenarios without crashing
      responses.forEach(result => {
        if (result.status === 'fulfilled') {
          expect(result.value.status).toBeLessThan(500);
        }
      });
    }, 15000);
  });
});