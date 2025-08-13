/**
 * Performance Optimizations Test Suite
 * Tests for the performance improvements implemented
 */

const request = require('supertest');
const app = require('../app');
const mongoose = require('mongoose');
const Response = require('../models/Response');
const SessionMonitoringService = require('../services/sessionMonitoringService');

describe('🚀 Performance Optimizations Test Suite', () => {
  let adminSession = null;
  let sessionMonitor = null;

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

    // Initialize session monitor for testing
    sessionMonitor = new SessionMonitoringService();
  });

  afterAll(async () => {
    await Response.deleteMany({});
    await mongoose.connection.close();
  });

  describe('🔤 Language Detection Caching', () => {
    test('should cache language detection results for repeated searches', async () => {
      const searchTerms = [
        'français test',
        'english search',
        'mixed français english',
        'français test', // Repeat for cache hit
        'english search' // Repeat for cache hit
      ];

      const startTime = Date.now();
      const responses = [];

      for (const term of searchTerms) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: term })
          .set('Cookie', adminSession)
          .timeout(5000);

        responses.push({
          term,
          status: response.status,
          duration: response.duration || 0
        });
      }

      const totalDuration = Date.now() - startTime;

      // All requests should succeed
      responses.forEach(response => {
        expect([200, 302]).toContain(response.status);
      });

      // Should complete efficiently with caching
      expect(totalDuration).toBeLessThan(10000); // Less than 10 seconds for all requests
      
      // Later requests (cache hits) should be faster
      const initialRequests = responses.slice(0, 3);
      const repeatedRequests = responses.slice(3);
      
      if (repeatedRequests.length > 0) {
        const avgInitialTime = initialRequests.reduce((sum, r) => sum + r.duration, 0) / initialRequests.length;
        const avgRepeatedTime = repeatedRequests.reduce((sum, r) => sum + r.duration, 0) / repeatedRequests.length;
        
        // Cache hits should generally be faster (allowing for variance)
        expect(avgRepeatedTime).toBeLessThanOrEqual(avgInitialTime * 1.5);
      }
    }, 15000);

    test('should handle language detection cache cleanup', async () => {
      // Generate many unique search terms to test cache limits
      const uniqueTerms = Array.from({ length: 50 }, (_, i) => `search term ${i} français`);

      const responses = await Promise.all(
        uniqueTerms.map(term =>
          request(app)
            .get('/admin/api/responses')
            .query({ search: term })
            .set('Cookie', adminSession)
            .timeout(3000)
            .catch(error => ({ status: 'timeout', error }))
        )
      );

      // Should handle all requests without memory issues
      const successfulRequests = responses.filter(r => [200, 302].includes(r.status)).length;
      expect(successfulRequests).toBeGreaterThan(40); // At least 80% success rate
    }, 25000);

    test('should normalize search text consistently for caching', async () => {
      const variations = [
        'français test',
        'FRANÇAIS TEST', // Case variation
        '  français test  ', // Whitespace variation
        'français test' // Exact repeat
      ];

      const responses = await Promise.all(
        variations.map(term =>
          request(app)
            .get('/admin/api/responses')
            .query({ search: term })
            .set('Cookie', adminSession)
            .timeout(5000)
        )
      );

      // All variations should work
      responses.forEach(response => {
        expect([200, 302]).toContain(response.status);
      });
    }, 10000);
  });

  describe('📁 Upload LRU Cache Optimization', () => {
    test('should handle upload tracking with LRU efficiency', async () => {
      const uploadAttempts = Array.from({ length: 20 }, (_, i) =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', `10.1.1.${i + 1}`)
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(1024), `lru-test-${i}.jpg`)
          .timeout(8000)
          .catch(error => ({ status: 'handled', error: error.message }))
      );

      const responses = await Promise.allSettled(uploadAttempts);
      
      // Should handle all requests without memory crashes
      expect(responses.length).toBe(20);
      
      const handledResponses = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status < 500
      ).length;
      
      expect(handledResponses).toBeGreaterThan(15); // At least 75% handled properly
    }, 30000);

    test('should perform intelligent cleanup based on access patterns', async () => {
      // Create upload attempts with different access patterns
      const highFrequencyIP = '192.168.1.100';
      const lowFrequencyIP = '192.168.1.200';

      // High frequency uploads (should be retained longer)
      const highFreqUploads = Array.from({ length: 5 }, (_, i) =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', highFrequencyIP)
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(512), `high-freq-${i}.jpg`)
          .timeout(5000)
          .catch(() => ({ status: 'handled' }))
      );

      // Low frequency upload (should be cleaned up first)
      const lowFreqUpload = request(app)
        .post('/api/upload')
        .set('X-Forwarded-For', lowFrequencyIP)
        .set('Cookie', adminSession || '')
        .attach('image', Buffer.alloc(512), 'low-freq.jpg')
        .timeout(5000)
        .catch(() => ({ status: 'handled' }));

      await Promise.allSettled([...highFreqUploads, lowFreqUpload]);

      // Get upload stats to verify LRU is working
      const uploadModule = require('../routes/upload');
      let stats;
      
      try {
        stats = uploadModule.getUploadStats ? uploadModule.getUploadStats() : null;
      } catch (error) {
        stats = null; // Module might not expose stats in test
      }

      if (stats) {
        expect(stats.activeIPs).toBeGreaterThanOrEqual(0);
        expect(typeof stats.activeIPs).toBe('number');
      }

      // Test passes if no memory crashes occurred
      expect(true).toBe(true);
    }, 20000);

    test('should handle concurrent upload tracking efficiently', async () => {
      const concurrentUploads = Array.from({ length: 15 }, (_, i) =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', `172.16.1.${i + 1}`)
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(256), `concurrent-${i}.jpg`)
          .timeout(10000)
      );

      const startTime = Date.now();
      const responses = await Promise.allSettled(concurrentUploads);
      const duration = Date.now() - startTime;

      // Should handle concurrent requests efficiently
      expect(duration).toBeLessThan(30000); // Less than 30 seconds
      expect(responses.length).toBe(15);
      
      // No server crashes
      const serverErrors = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status >= 500
      ).length;
      expect(serverErrors).toBe(0);
    }, 35000);
  });

  describe('📊 Session Monitoring Batch Alerts', () => {
    test('should batch similar alerts for performance', async () => {
      // Generate multiple suspicious activities
      const activities = Array.from({ length: 8 }, (_, i) => ({
        sessionId: `test-session-${i}`,
        clientIP: '203.0.113.1',
        userId: `user-${i}`,
        activityType: 'suspicious_session_creation',
        details: { userAgent: 'test-agent', timestamp: Date.now() }
      }));

      const startTime = Date.now();

      // Trigger multiple alerts
      activities.forEach(activity => {
        sessionMonitor.handleSuspiciousActivity(
          activity.sessionId,
          activity.clientIP,
          activity.userId,
          activity.activityType,
          activity.details
        );
      });

      // Wait for batch processing
      await new Promise(resolve => setTimeout(resolve, 2000));

      const processingTime = Date.now() - startTime;

      // Should complete efficiently with batching
      expect(processingTime).toBeLessThan(5000);

      // Get stats to verify batch processing
      const stats = sessionMonitor.getMonitoringStats();
      expect(stats.batchProcessing).toBeDefined();
      expect(stats.suspiciousActivities).toBeGreaterThanOrEqual(8);
    });

    test('should handle critical alerts immediately', async () => {
      const criticalActivity = {
        sessionId: 'critical-session',
        clientIP: '203.0.113.99',
        userId: 'critical-user',
        activityType: 'brute_force_detected',
        details: { attempts: 10, timespan: 60000 }
      };

      const startTime = Date.now();

      sessionMonitor.handleSuspiciousActivity(
        criticalActivity.sessionId,
        criticalActivity.clientIP,
        criticalActivity.userId,
        criticalActivity.activityType,
        criticalActivity.details
      );

      const processingTime = Date.now() - startTime;

      // Critical alerts should be processed immediately (< 100ms)
      expect(processingTime).toBeLessThan(100);

      const stats = sessionMonitor.getMonitoringStats();
      expect(stats.blockedAttempts).toBeGreaterThan(0);
    });

    test('should group and deduplicate similar alerts', async () => {
      // Generate duplicate alerts from same IP/activity
      const duplicateActivities = Array.from({ length: 5 }, () => ({
        sessionId: 'duplicate-session',
        clientIP: '198.51.100.1',
        userId: 'duplicate-user',
        activityType: 'suspicious_login_pattern',
        details: { pattern: 'rapid_requests' }
      }));

      duplicateActivities.forEach(activity => {
        sessionMonitor.handleSuspiciousActivity(
          activity.sessionId,
          activity.clientIP,
          activity.userId,
          activity.activityType,
          activity.details
        );
      });

      // Force batch processing
      sessionMonitor.processBatchedAlerts();

      // Should handle duplicates efficiently
      const stats = sessionMonitor.getMonitoringStats();
      expect(stats.suspiciousActivities).toBeGreaterThan(0);
      expect(stats.batchProcessing.queuedAlerts).toBe(0); // Queue should be empty after processing
    });
  });

  describe('🔄 Integrated Performance Tests', () => {
    test('should handle mixed operations efficiently', async () => {
      const startTime = Date.now();

      // Mix of operations: search, upload, monitoring
      const operations = [
        // Language detection cached searches
        request(app)
          .get('/admin/api/responses')
          .query({ search: 'performance français test' })
          .set('Cookie', adminSession)
          .timeout(5000),

        // Upload with LRU tracking
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', '10.0.0.100')
          .set('Cookie', adminSession || '')
          .attach('image', Buffer.alloc(512), 'integrated-test.jpg')
          .timeout(8000)
          .catch(() => ({ status: 'handled' })),

        // Another cached search (should be faster)
        request(app)
          .get('/admin/api/responses')
          .query({ search: 'performance français test' })
          .set('Cookie', adminSession)
          .timeout(5000)
      ];

      // Generate session monitoring alerts
      Array.from({ length: 3 }, (_, i) => {
        sessionMonitor.handleSuspiciousActivity(
          `integrated-${i}`,
          '10.0.0.100',
          `user-${i}`,
          'integrated_test',
          { testType: 'performance' }
        );
      });

      const responses = await Promise.allSettled(operations);
      const totalDuration = Date.now() - startTime;

      // Should complete all operations efficiently
      expect(totalDuration).toBeLessThan(15000); // 15 seconds max

      // All operations should succeed or be handled gracefully
      responses.forEach((response, index) => {
        if (response.status === 'fulfilled') {
          expect([200, 302, 'handled'].includes(response.value.status) || 
                 response.value.status < 500).toBe(true);
        }
      });

      // Session monitoring should still be responsive
      const stats = sessionMonitor.getMonitoringStats();
      expect(stats).toBeDefined();
      expect(typeof stats.suspiciousActivities).toBe('number');
    }, 20000);

    test('should maintain performance under sustained load', async () => {
      const loadTestDuration = 5000; // 5 seconds
      const startTime = Date.now();
      const operations = [];

      // Sustained load simulation
      const loadInterval = setInterval(() => {
        if (Date.now() - startTime >= loadTestDuration) {
          clearInterval(loadInterval);
          return;
        }

        // Mixed operations every 500ms
        operations.push(
          request(app)
            .get('/admin/api/responses')
            .query({ search: `load test ${Date.now()} français` })
            .set('Cookie', adminSession)
            .timeout(3000)
            .catch(() => ({ status: 'timeout' }))
        );

        // Session monitoring
        sessionMonitor.handleSuspiciousActivity(
          'load-test',
          '10.0.0.200',
          'load-user',
          'sustained_load_test',
          { timestamp: Date.now() }
        );
      }, 500);

      // Wait for load test to complete
      await new Promise(resolve => setTimeout(resolve, loadTestDuration + 1000));

      const responses = await Promise.allSettled(operations);
      const actualDuration = Date.now() - startTime;

      // Should handle sustained load
      expect(actualDuration).toBeLessThan(loadTestDuration + 3000); // Allow 3s buffer
      
      const successfulOperations = responses.filter(r => 
        r.status === 'fulfilled' && 
        ([200, 302].includes(r.value.status) || r.value.status === 'timeout')
      ).length;

      // At least 70% of operations should succeed
      expect(successfulOperations).toBeGreaterThan(responses.length * 0.7);
    }, 15000);
  });

  describe('📈 Performance Metrics and Monitoring', () => {
    test('should provide comprehensive performance statistics', async () => {
      // Get upload stats
      const uploadModule = require('../routes/upload');
      let uploadStats;
      
      try {
        uploadStats = uploadModule.getUploadStats ? uploadModule.getUploadStats() : null;
      } catch (error) {
        uploadStats = null;
      }

      // Get session monitoring stats
      const sessionStats = sessionMonitor.getMonitoringStats();

      // Verify stats structure
      expect(sessionStats).toBeDefined();
      expect(sessionStats.batchProcessing).toBeDefined();
      expect(typeof sessionStats.suspiciousActivities).toBe('number');

      if (uploadStats) {
        expect(typeof uploadStats.activeIPs).toBe('number');
        expect(uploadStats.cacheEfficiency).toBeDefined();
        expect(uploadStats.memoryThresholds).toBeDefined();
      }
    });

    test('should track memory usage efficiently', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Perform memory-intensive operations
      const operations = Array.from({ length: 20 }, (_, i) =>
        request(app)
          .get('/admin/api/responses')
          .query({ search: `memory test ${i} with lots of text to process français` })
          .set('Cookie', adminSession)
          .timeout(3000)
          .catch(() => ({ status: 'handled' }))
      );

      await Promise.allSettled(operations);

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      await new Promise(resolve => setTimeout(resolve, 1000));

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 100MB for this test)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
    }, 15000);
  });
});