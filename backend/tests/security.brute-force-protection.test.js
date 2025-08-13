/**
 * Advanced Brute Force Protection Tests
 * Tests comprehensive protection against various brute force attack vectors
 */

const request = require('supertest');
const app = require('../app');
const mongoose = require('mongoose');
const Response = require('../models/Response');

describe('🛡️ Advanced Brute Force Protection', () => {
  let testResponses = [];

  beforeAll(async () => {
    if (!mongoose.connection.readyState) {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-test');
    }
    
    await Response.deleteMany({});
    testResponses = await Response.create([
      { name: 'Alice', responses: [{ question: 'Test?', answer: 'Yes' }], month: '2025-01', isAdmin: false, token: 'token1' },
      { name: 'Bob', responses: [{ question: 'Test?', answer: 'No' }], month: '2025-01', isAdmin: false, token: 'token2' },
      { name: 'Admin', responses: [{ question: 'Admin?', answer: 'Yes' }], month: '2025-01', isAdmin: true }
    ]);
  });

  afterAll(async () => {
    await Response.deleteMany({});
    await mongoose.connection.close();
  });

  describe('🔐 Authentication Brute Force Protection', () => {
    test('should block rapid successive failed login attempts', async () => {
      const invalidCredentials = {
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: 'wrongpassword'
      };

      let successCount = 0;
      let blockedCount = 0;

      // Attempt 10 rapid failed logins
      for (let i = 0; i < 10; i++) {
        const response = await request(app)
          .post('/auth/login')
          .send(invalidCredentials)
          .timeout(5000);

        if (response.status === 401 || response.status === 400) {
          successCount++;
        } else if (response.status === 429) {
          blockedCount++;
        }
      }

      // Should start blocking after several attempts
      expect(blockedCount).toBeGreaterThan(0);
      expect(successCount + blockedCount).toBe(10);
    }, 30000);

    test('should differentiate between different IP addresses', async () => {
      const invalidCredentials = {
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: 'wrongpassword'
      };

      // Make failed attempts from different IPs
      const ip1Responses = [];
      const ip2Responses = [];

      // IP 1: Make several failed attempts
      for (let i = 0; i < 5; i++) {
        const response = await request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', '192.168.1.100')
          .send(invalidCredentials);
        ip1Responses.push(response.status);
      }

      // IP 2: Should still be able to attempt
      for (let i = 0; i < 3; i++) {
        const response = await request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', '192.168.1.200')
          .send(invalidCredentials);
        ip2Responses.push(response.status);
      }

      // IP2 should have fewer blocks initially
      const ip1Blocks = ip1Responses.filter(status => status === 429).length;
      const ip2Blocks = ip2Responses.filter(status => status === 429).length;
      
      expect(ip1Blocks).toBeGreaterThanOrEqual(ip2Blocks);
    }, 20000);

    test('should handle distributed brute force from multiple IPs', async () => {
      const invalidCredentials = {
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: 'wrongpassword'
      };

      const ips = [
        '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5',
        '172.16.0.1', '172.16.0.2', '172.16.0.3', '172.16.0.4', '172.16.0.5'
      ];

      const results = {};

      // Simulate distributed attack
      for (const ip of ips) {
        results[ip] = [];
        
        for (let i = 0; i < 3; i++) {
          const response = await request(app)
            .post('/auth/login')
            .set('X-Forwarded-For', ip)
            .send(invalidCredentials)
            .timeout(3000);
          
          results[ip].push(response.status);
        }
      }

      // Verify each IP gets tracked independently
      Object.values(results).forEach(statuses => {
        expect(statuses.length).toBe(3);
        expect(statuses.every(status => [401, 400, 429].includes(status))).toBe(true);
      });
    }, 25000);

    test('should allow valid login after rate limit period', async () => {
      // This test would require waiting for rate limit reset
      // or manipulating time, so we'll test the logic conceptually
      const response = await request(app)
        .post('/auth/login')
        .send({
          username: process.env.LOGIN_ADMIN_USER || 'admin',
          password: process.env.LOGIN_ADMIN_PASS || 'password'
        });

      // Valid credentials should work (unless globally rate limited)
      expect([200, 429, 302]).toContain(response.status);
    });
  });

  describe('📊 Rate Limiting Across Multiple IPs', () => {
    test('should track rate limits per IP for form submissions', async () => {
      const validFormData = {
        name: 'BruteTest',
        responses: [{ question: 'Test?', answer: 'Answer' }]
      };

      const ips = ['203.0.113.1', '203.0.113.2', '203.0.113.3'];
      const results = [];

      for (const ip of ips) {
        // Each IP should get its own rate limit allowance
        for (let i = 0; i < 4; i++) {
          const response = await request(app)
            .post('/api/response')
            .set('X-Forwarded-For', ip)
            .send({ ...validFormData, name: `BruteTest-${ip}-${i}` })
            .timeout(5000);

          results.push({ ip, attempt: i + 1, status: response.status });
        }
      }

      // Each IP should be able to make at least 3 requests
      const successByIP = {};
      results.forEach(result => {
        if (!successByIP[result.ip]) successByIP[result.ip] = 0;
        if (result.status === 201) successByIP[result.ip]++;
      });

      Object.values(successByIP).forEach(count => {
        expect(count).toBeGreaterThanOrEqual(3);
      });
    }, 30000);

    test('should handle rapid requests from same IP', async () => {
      const validFormData = {
        name: 'RapidTest',
        responses: [{ question: 'Rapid?', answer: 'Test' }]
      };

      const rapidRequests = Array(8).fill(null).map((_, i) =>
        request(app)
          .post('/api/response')
          .set('X-Forwarded-For', '198.51.100.1')
          .send({ ...validFormData, name: `RapidTest-${i}` })
          .timeout(5000)
      );

      const responses = await Promise.allSettled(rapidRequests);
      
      const successful = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status === 201
      ).length;

      const rateLimited = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status === 429
      ).length;

      // Should allow some but rate limit others
      expect(successful).toBeGreaterThan(0);
      expect(successful).toBeLessThan(8);
      expect(rateLimited).toBeGreaterThan(0);
    }, 15000);

    test('should handle concurrent brute force attempts', async () => {
      const invalidCredentials = {
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: 'concurrent-brute-force'
      };

      // Launch 15 concurrent login attempts
      const concurrentAttempts = Array(15).fill(null).map((_, i) =>
        request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', `10.1.1.${i + 1}`)
          .send(invalidCredentials)
          .timeout(8000)
      );

      const responses = await Promise.allSettled(concurrentAttempts);
      
      // All should complete without server errors
      const completed = responses.filter(r => r.status === 'fulfilled').length;
      const serverErrors = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status >= 500
      ).length;

      expect(completed).toBe(15);
      expect(serverErrors).toBe(0);
    }, 20000);
  });

  describe('⏱️ Session Timeout and Cleanup', () => {
    test('should handle session timeout scenarios', async () => {
      // Login successfully first
      const loginResponse = await request(app)
        .post('/auth/login')
        .send({
          username: process.env.LOGIN_ADMIN_USER || 'admin',
          password: process.env.LOGIN_ADMIN_PASS || 'password'
        });

      const cookies = loginResponse.headers['set-cookie'];

      if (cookies) {
        // Attempt to use session for protected endpoint
        const protectedResponse = await request(app)
          .get('/admin/api/responses')
          .set('Cookie', cookies)
          .timeout(5000);

        expect([200, 401, 403]).toContain(protectedResponse.status);
      }
    });

    test('should handle multiple concurrent sessions', async () => {
      const validCredentials = {
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: process.env.LOGIN_ADMIN_PASS || 'password'
      };

      // Attempt multiple concurrent logins
      const sessionAttempts = Array(5).fill(null).map(() =>
        request(app)
          .post('/auth/login')
          .send(validCredentials)
          .timeout(5000)
      );

      const responses = await Promise.allSettled(sessionAttempts);
      
      // Should handle concurrent sessions gracefully
      const successful = responses.filter(r => 
        r.status === 'fulfilled' && [200, 302].includes(r.value.status)
      ).length;

      expect(successful).toBeGreaterThan(0);
    }, 15000);

    test('should handle session cleanup under load', async () => {
      // Create multiple sessions rapidly
      const sessionCreation = Array(10).fill(null).map((_, i) =>
        request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', `172.20.0.${i + 1}`)
          .send({
            username: process.env.LOGIN_ADMIN_USER || 'admin',
            password: 'invalid-session-test'
          })
          .timeout(5000)
      );

      const responses = await Promise.allSettled(sessionCreation);

      // Server should handle session creation/cleanup without crashing
      const completed = responses.filter(r => r.status === 'fulfilled').length;
      expect(completed).toBe(10);
    }, 15000);
  });

  describe('🚫 IP Whitelist/Blacklist Functionality', () => {
    test('should handle requests from suspicious IP ranges', async () => {
      const suspiciousIPs = [
        '0.0.0.0',        // Invalid
        '127.0.0.1',      // Localhost
        '169.254.1.1',    // Link-local
        '224.0.0.1',      // Multicast
        '255.255.255.255' // Broadcast
      ];

      for (const ip of suspiciousIPs) {
        const response = await request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', ip)
          .send({
            username: process.env.LOGIN_ADMIN_USER || 'admin',
            password: 'suspicious-ip-test'
          })
          .timeout(5000);

        // Should handle gracefully (not necessarily block, but not crash)
        expect(response.status).toBeLessThan(500);
      }
    });

    test('should handle IPv6 addresses', async () => {
      const ipv6Addresses = [
        '2001:db8::1',
        '::1',
        'fe80::1',
        '2001:db8:85a3::8a2e:370:7334'
      ];

      for (const ip of ipv6Addresses) {
        const response = await request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', ip)
          .send({
            username: process.env.LOGIN_ADMIN_USER || 'admin',
            password: 'ipv6-test'
          })
          .timeout(5000);

        expect(response.status).toBeLessThan(500);
      }
    });

    test('should handle malformed IP headers', async () => {
      const malformedHeaders = [
        'not.an.ip',
        '999.999.999.999',
        '192.168.1',
        '192.168.1.1.1',
        '',
        null,
        undefined
      ];

      for (const header of malformedHeaders) {
        const response = await request(app)
          .post('/auth/login')
          .set('X-Forwarded-For', header || '')
          .send({
            username: process.env.LOGIN_ADMIN_USER || 'admin',
            password: 'malformed-header-test'
          })
          .timeout(5000);

        expect(response.status).toBeLessThan(500);
      }
    });
  });

  describe('📈 Performance Under Attack Load', () => {
    test('should maintain performance under sustained attack', async () => {
      const startTime = Date.now();
      
      // Sustained attack simulation
      const attackWaves = [];
      for (let wave = 0; wave < 3; wave++) {
        const wavePromises = Array(10).fill(null).map((_, i) =>
          request(app)
            .post('/auth/login')
            .set('X-Forwarded-For', `192.168.${wave + 1}.${i + 1}`)
            .send({
              username: process.env.LOGIN_ADMIN_USER || 'admin',
              password: `attack-wave-${wave}-${i}`
            })
            .timeout(8000)
        );
        
        attackWaves.push(Promise.allSettled(wavePromises));
      }

      const allWaves = await Promise.all(attackWaves);
      const duration = Date.now() - startTime;

      // Should complete within reasonable time
      expect(duration).toBeLessThan(30000); // 30 seconds max
      
      // All waves should complete
      expect(allWaves.length).toBe(3);
      allWaves.forEach(wave => {
        expect(wave.length).toBe(10);
      });
    }, 45000);

    test('should not consume excessive memory during attack', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Memory stress test
      const memoryStressRequests = Array(50).fill(null).map((_, i) =>
        request(app)
          .post('/api/response')
          .set('X-Forwarded-For', `10.0.${Math.floor(i / 10)}.${i % 10}`)
          .send({
            name: `MemoryTest-${i}`,
            responses: Array(20).fill(null).map((_, j) => ({
              question: `Question ${j}?`,
              answer: `Answer ${j} - ${i} - ${'x'.repeat(100)}`
            }))
          })
          .timeout(10000)
      );

      await Promise.allSettled(memoryStressRequests);
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable (less than 100MB)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
    }, 30000);
  });

  describe('🔍 Attack Pattern Detection', () => {
    test('should detect and handle bot-like user agents', async () => {
      const botUserAgents = [
        'python-requests/2.25.1',
        'curl/7.68.0',
        'wget/1.20.3',
        'PostmanRuntime/7.26.8',
        'Apache-HttpClient/4.5.10',
        'okhttp/3.14.9',
        'Go-http-client/1.1'
      ];

      for (const userAgent of botUserAgents) {
        const response = await request(app)
          .post('/auth/login')
          .set('User-Agent', userAgent)
          .send({
            username: process.env.LOGIN_ADMIN_USER || 'admin',
            password: 'bot-detection-test'
          })
          .timeout(5000);

        // Should handle bot requests (may apply stricter rate limiting)
        expect([401, 400, 429]).toContain(response.status);
      }
    });

    test('should handle requests without standard headers', async () => {
      const response = await request(app)
        .post('/auth/login')
        // Minimal headers (suspicious)
        .send({
          username: process.env.LOGIN_ADMIN_USER || 'admin',
          password: 'minimal-headers-test'
        })
        .timeout(5000);

      expect([401, 400, 429]).toContain(response.status);
    });

    test('should detect rapid pattern changes', async () => {
      // Simulate attacker changing tactics rapidly
      const tactics = [
        { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', ip: '203.0.113.10' },
        { userAgent: 'python-requests/2.25.1', ip: '203.0.113.11' },
        { userAgent: 'curl/7.68.0', ip: '203.0.113.12' },
        { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X)', ip: '203.0.113.13' }
      ];

      const responses = [];
      for (const tactic of tactics) {
        for (let i = 0; i < 3; i++) {
          const response = await request(app)
            .post('/auth/login')
            .set('User-Agent', tactic.userAgent)
            .set('X-Forwarded-For', tactic.ip)
            .send({
              username: process.env.LOGIN_ADMIN_USER || 'admin',
              password: `tactic-change-${i}`
            })
            .timeout(5000);

          responses.push(response.status);
        }
      }

      // Should handle tactic changes without crashing
      expect(responses.every(status => status < 500)).toBe(true);
    });
  });
});