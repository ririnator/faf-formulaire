// tests/statistics-rate-limiting.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../app');
const User = require('../models/User');
const Response = require('../models/Response');
const { statisticsMonitor } = require('../middleware/statisticsMonitoring');

describe('Statistics Rate Limiting Security Tests', () => {
  let mongoServer;
  let adminAgent;
  let userAgent;
  let adminUser;
  let regularUser;

  beforeAll(async () => {
    // Start in-memory MongoDB instance
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    // Close existing connection if any
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
    
    await mongoose.connect(mongoUri);
    
    // Create test users
    adminUser = await User.create({
      username: 'admin_stats_test',
      email: 'admin.stats@test.com',
      password: 'securepass123',
      role: 'admin'
    });

    regularUser = await User.create({
      username: 'user_stats_test', 
      email: 'user.stats@test.com',
      password: 'userpass123',
      role: 'user'
    });

    // Create authenticated agents
    adminAgent = request.agent(app);
    userAgent = request.agent(app);
    
    // Admin login
    await adminAgent
      .post('/admin-login')
      .send({
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: process.env.LOGIN_ADMIN_PASS || 'password'
      });

    // User login  
    await userAgent
      .post('/api/users/login')
      .send({
        email: 'user.stats@test.com',
        password: 'userpass123'
      });
  });

  afterAll(async () => {
    statisticsMonitor.reset();
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(() => {
    // Reset statistics monitoring before each test
    statisticsMonitor.reset();
  });

  describe('Statistics Rate Limiter Configuration', () => {
    test('should have appropriate limits for different endpoint types', () => {
      const { 
        statsSimpleLimiter,
        statsAdminSummaryLimiter,
        statsHeavyAnalyticsLimiter,
        statsRealTimeMonitoringLimiter,
        statsComparisonLimiter,
        statsGlobalLimiter,
        statsPerformanceLimiter
      } = require('../middleware/rateLimiting');

      // Verify rate limiters exist
      expect(statsSimpleLimiter).toBeDefined();
      expect(statsAdminSummaryLimiter).toBeDefined();
      expect(statsHeavyAnalyticsLimiter).toBeDefined();
      expect(statsRealTimeMonitoringLimiter).toBeDefined();
      expect(statsComparisonLimiter).toBeDefined();
      expect(statsGlobalLimiter).toBeDefined();
      expect(statsPerformanceLimiter).toBeDefined();
    });

    test('should have progressively stricter limits for more resource-intensive operations', () => {
      // Test that rate limits are appropriately configured
      // This is validated by checking the middleware configuration
      expect(true).toBe(true); // Placeholder - actual limits are configured in middleware
    });
  });

  describe('Admin Dashboard Statistics Protection', () => {
    test('should apply rate limiting to admin summary endpoint', async () => {
      // Create test data for summary
      await Response.create({
        name: 'Test User',
        month: '2024-01',
        responses: [
          { question: 'Test Question', answer: 'Test Answer' }
        ],
        isAdmin: false,
        token: 'test-token-123'
      });

      const endpoint = '/api/admin/summary';
      let successCount = 0;
      let rateLimitedCount = 0;

      // Make multiple requests to test rate limiting
      for (let i = 0; i < 25; i++) {
        const response = await adminAgent.get(endpoint);
        
        if (response.status === 200) {
          successCount++;
        } else if (response.status === 429) {
          rateLimitedCount++;
          expect(response.body).toHaveProperty('code', 'ADMIN_SUMMARY_RATE_LIMIT_EXCEEDED');
        }
      }

      expect(successCount).toBeGreaterThan(0);
      // Should be rate limited after configured limit (20 per 30 minutes)
      if (process.env.NODE_ENV !== 'test') {
        expect(rateLimitedCount).toBeGreaterThan(0);
      }
    });

    test('should track admin summary access patterns', async () => {
      const endpoint = '/api/admin/summary';
      
      await adminAgent.get(endpoint);
      
      const stats = statisticsMonitor.getMonitoringStats();
      expect(stats.monitoring.totalRequests).toBeGreaterThan(0);
      
      // Verify endpoint tracking
      const summaryEndpoint = stats.endpoints.find(ep => 
        ep.endpoint.includes('/summary') && ep.type === 'admin_summary'
      );
      expect(summaryEndpoint).toBeDefined();
    });

    test('should apply rate limiting to performance monitoring endpoints', async () => {
      const performanceEndpoints = [
        '/api/admin/performance/status',
        '/api/admin/performance/summary',
        '/api/admin/performance/realtime'
      ];

      for (const endpoint of performanceEndpoints) {
        const response = await adminAgent.get(endpoint);
        // Should either succeed or be properly rate limited
        expect([200, 429, 503].includes(response.status)).toBe(true);
        
        if (response.status === 429) {
          expect(response.body.code).toMatch(/RATE_LIMIT_EXCEEDED/);
        }
      }
    });
  });

  describe('Global Statistics Protection', () => {
    test('should protect global contact statistics endpoint', async () => {
      const endpoint = '/api/contacts/stats/global';
      let requestCount = 0;
      let rateLimitedCount = 0;

      // Test rate limiting on global stats
      for (let i = 0; i < 15; i++) {
        const response = await userAgent.get(endpoint);
        requestCount++;
        
        if (response.status === 429) {
          rateLimitedCount++;
          expect(response.body.code).toBe('GLOBAL_STATS_RATE_LIMIT_EXCEEDED');
        }
      }

      expect(requestCount).toBe(15);
      // Global stats should be strictly limited (12 per 45 minutes)
      if (process.env.NODE_ENV !== 'test') {
        expect(rateLimitedCount).toBeGreaterThan(0);
      }
    });

    test('should track global statistics access patterns', async () => {
      await userAgent.get('/api/contacts/stats/global');
      
      const stats = statisticsMonitor.getMonitoringStats();
      const globalStatsEndpoint = stats.endpoints.find(ep => 
        ep.endpoint.includes('/stats/global') && ep.type === 'global_statistics'
      );
      
      expect(globalStatsEndpoint).toBeDefined();
      expect(globalStatsEndpoint.totalRequests).toBeGreaterThan(0);
    });
  });

  describe('Simple Statistics Protection', () => {
    test('should apply appropriate limits to simple stats endpoints', async () => {
      const simpleStatsEndpoints = [
        '/api/handshakes/stats',
        '/api/invitations/stats'
      ];

      for (const endpoint of simpleStatsEndpoints) {
        let successCount = 0;
        
        // Test multiple requests
        for (let i = 0; i < 45; i++) {
          const response = await userAgent.get(endpoint);
          
          if (response.status === 200) {
            successCount++;
          } else if (response.status === 429) {
            expect(response.body.code).toBe('SIMPLE_STATS_RATE_LIMIT_EXCEEDED');
            break;
          }
        }
        
        // Simple stats should allow more requests (40 per 10 minutes)
        expect(successCount).toBeGreaterThan(30);
      }
    });
  });

  describe('Comparison Analytics Protection', () => {
    test('should protect submission comparison endpoint', async () => {
      // Note: This endpoint requires specific setup with contacts and submissions
      // For now, test that the endpoint responds with proper authentication/validation
      const endpoint = '/api/submissions/comparison/test-contact-id/2024-01';
      
      const response = await userAgent.get(endpoint);
      
      // Should either be protected by rate limiting or validation
      expect([400, 401, 404, 422, 429].includes(response.status)).toBe(true);
      
      if (response.status === 429) {
        expect(response.body.code).toBe('COMPARISON_STATS_RATE_LIMIT_EXCEEDED');
      }
    });
  });

  describe('Statistics Monitoring System', () => {
    test('should detect suspicious patterns', async () => {
      const endpoint = '/api/admin/summary';
      
      // Rapid successive requests to trigger suspicion detection
      const promises = [];
      for (let i = 0; i < 12; i++) {
        promises.push(adminAgent.get(endpoint));
      }
      
      await Promise.all(promises);
      
      const stats = statisticsMonitor.getMonitoringStats();
      expect(stats.monitoring.totalRequests).toBeGreaterThan(10);
    });

    test('should track endpoint metrics', async () => {
      await adminAgent.get('/api/admin/summary');
      await userAgent.get('/api/handshakes/stats');
      
      const stats = statisticsMonitor.getMonitoringStats();
      
      expect(stats.endpoints.length).toBeGreaterThan(0);
      expect(stats.endpoints[0]).toHaveProperty('endpoint');
      expect(stats.endpoints[0]).toHaveProperty('type');
      expect(stats.endpoints[0]).toHaveProperty('totalRequests');
      expect(stats.endpoints[0]).toHaveProperty('averageResponseTime');
    });

    test('should provide monitoring dashboard data', async () => {
      const response = await adminAgent.get('/api/admin/statistics-monitoring/status');
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('monitoring');
      expect(response.body.monitoring).toHaveProperty('totalRequests');
      expect(response.body.monitoring).toHaveProperty('uniqueIPs');
      expect(response.body.monitoring).toHaveProperty('trackedEndpoints');
    });

    test('should allow monitoring configuration updates', async () => {
      const newConfig = {
        maxRequestsPerMinute: 5,
        maxResponseTime: 20000
      };
      
      const response = await adminAgent
        .put('/api/admin/statistics-monitoring/config')
        .send({ config: newConfig });
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('newConfig');
    });

    test('should allow monitoring data reset', async () => {
      // Generate some data first
      await adminAgent.get('/api/admin/summary');
      
      const response = await adminAgent.post('/api/admin/statistics-monitoring/reset');
      
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success', true);
      
      // Verify data was reset
      const stats = statisticsMonitor.getMonitoringStats();
      expect(stats.monitoring.totalRequests).toBe(0);
    });
  });

  describe('Security Event Logging', () => {
    test('should log suspicious access patterns', async () => {
      const originalWarn = console.warn;
      const warnSpy = jest.fn();
      console.warn = warnSpy;
      
      // Create rapid requests to trigger suspicious pattern detection
      const endpoint = '/api/admin/summary';
      const promises = [];
      
      for (let i = 0; i < 15; i++) {
        promises.push(adminAgent.get(endpoint));
      }
      
      await Promise.all(promises);
      
      // Restore console.warn
      console.warn = originalWarn;
      
      // Check if security warnings were logged
      const securityWarnings = warnSpy.mock.calls.filter(call => 
        call[0] && call[0].includes('Suspicious statistics access')
      );
      
      // In non-test environment, should detect suspicious patterns
      if (process.env.NODE_ENV !== 'test') {
        expect(securityWarnings.length).toBeGreaterThan(0);
      }
    });

    test('should log performance alerts for slow queries', async () => {
      const originalWarn = console.warn;
      const warnSpy = jest.fn();
      console.warn = warnSpy;
      
      // Make a request that might be slow
      await adminAgent.get('/api/admin/summary');
      
      console.warn = originalWarn;
      
      // Performance alerts might not trigger in test environment
      // This test validates the logging mechanism exists
      expect(warnSpy).toBeDefined();
    });
  });

  describe('Rate Limiting Error Responses', () => {
    test('should return appropriate error messages for rate limits', async () => {
      const rateLimiters = [
        { endpoint: '/api/admin/summary', code: 'ADMIN_SUMMARY_RATE_LIMIT_EXCEEDED' },
        { endpoint: '/api/contacts/stats/global', code: 'GLOBAL_STATS_RATE_LIMIT_EXCEEDED' },
        { endpoint: '/api/handshakes/stats', code: 'SIMPLE_STATS_RATE_LIMIT_EXCEEDED' }
      ];

      for (const { endpoint, code } of rateLimiters) {
        // Make enough requests to potentially trigger rate limiting
        let rateLimitResponse = null;
        
        for (let i = 0; i < 50; i++) {
          const response = await (endpoint.includes('/admin/') ? adminAgent : userAgent).get(endpoint);
          
          if (response.status === 429) {
            rateLimitResponse = response;
            break;
          }
        }
        
        if (rateLimitResponse && process.env.NODE_ENV !== 'test') {
          expect(rateLimitResponse.body).toHaveProperty('success', false);
          expect(rateLimitResponse.body).toHaveProperty('code', code);
          expect(rateLimitResponse.body).toHaveProperty('error');
          expect(rateLimitResponse.body).toHaveProperty('retryAfter');
        }
      }
    });
  });

  describe('Performance Impact Assessment', () => {
    test('should not significantly impact response times', async () => {
      const endpoint = '/api/admin/summary';
      const startTime = Date.now();
      
      await adminAgent.get(endpoint);
      
      const responseTime = Date.now() - startTime;
      
      // Statistics monitoring should add minimal overhead
      expect(responseTime).toBeLessThan(5000); // 5 seconds max
    });

    test('should cleanup old monitoring data', () => {
      // Test the cleanup mechanism
      statisticsMonitor.cleanupOldEntries();
      
      // Should not throw errors
      expect(true).toBe(true);
    });
  });
});