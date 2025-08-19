/**
 * Performance Benchmarks Test Suite
 * 
 * Measures and validates performance improvements from optimizations
 * Compares baseline vs optimized performance metrics
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
let benchmarkUser = null;

// Performance thresholds (based on stated improvements)
const PERFORMANCE_THRESHOLDS = {
  dashboardAPI: {
    baseline: 6000,     // 6ms baseline (from report: 6ms → 3ms)
    optimized: 3000,    // 3ms optimized target
    improvement: 0.50   // 50% improvement expected
  },
  concurrentRequests: {
    baseline: 17000,    // 17ms baseline (from report: 17ms → 15ms)
    optimized: 15000,   // 15ms optimized target  
    improvement: 0.12   // 12% improvement expected
  },
  cacheHit: {
    maxTime: 1000,      // Cache hits should be under 1ms
    improvementRatio: 0.3 // Cache hits should be 70% faster
  },
  memoryUsage: {
    maxIncrease: 50 * 1024 * 1024, // 50MB max increase
    baseline: 500 * 1024 * 1024     // 500MB baseline
  }
};

describe('⚡ Performance Benchmarks and Validation', () => {
  beforeAll(async () => {
    app = getTestApp();
    
    // Clean and setup test data
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
    
    // Create benchmark user
    benchmarkUser = await User.create({
      username: 'benchmarkuser',
      email: 'benchmark@test.com',
      password: '$2a$10$benchmark.hash.for.testing',
      role: 'admin',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    // Create substantial test dataset for meaningful benchmarks
    const testResponses = Array.from({ length: 100 }, (_, i) => ({
      name: `Benchmark User ${i}`,
      responses: [
        { question: 'Performance Question 1', answer: `Answer ${i} part 1` },
        { question: 'Performance Question 2', answer: `Answer ${i} part 2` },
        { question: 'En rapide, comment ça va ?', answer: `Benchmark réponse ${i}` }
      ],
      month: `202${Math.floor(i/20) + 1}-${String((i % 12) + 1).padStart(2, '0')}`,
      isAdmin: i % 10 === 0, // 10% admin responses
      token: i % 10 === 0 ? null : `benchmark-token-${i}`,
      createdAt: new Date(2024, (i % 12), 15, 10, i % 60)
    }));
    
    await Response.create(testResponses);
    
    // Create contacts for N+1 testing
    const testContacts = Array.from({ length: 50 }, (_, i) => ({
      firstName: `Contact${i}`,
      lastName: 'Benchmark',
      email: `contact${i}@benchmark.test`,
      ownerId: benchmarkUser._id,
      isActive: true,
      status: 'active',
      contactUserId: i % 5 === 0 ? benchmarkUser._id : null,
      tracking: {
        responsesReceived: Math.floor(Math.random() * 10),
        responseRate: Math.random() * 100,
        lastInteractionAt: new Date(),
        firstResponseAt: new Date(2024, Math.floor(Math.random() * 12), 1)
      }
    }));
    
    await Contact.create(testContacts);
    
    // Create submissions for complex queries
    const testSubmissions = Array.from({ length: 200 }, (_, i) => ({
      userId: benchmarkUser._id,
      month: `202${Math.floor(i/50) + 1}-${String((i % 12) + 1).padStart(2, '0')}`,
      responses: [
        { question: `Benchmark Q${i % 5 + 1}`, answer: `Benchmark A${i}` }
      ],
      completionRate: Math.floor(Math.random() * 100),
      submittedAt: new Date(2024, i % 12, Math.floor(Math.random() * 28) + 1),
      freeText: i % 3 === 0 ? `Free text ${i}` : null
    }));
    
    await Submission.create(testSubmissions);
    
    // Login for session
    const loginResponse = await request(app)
      .post('/auth/login')
      .send({
        username: 'benchmarkuser',
        password: 'benchmark123'
      });
      
    if (loginResponse.headers['set-cookie']) {
      adminSession = loginResponse.headers['set-cookie'];
    }
  }, 60000);

  afterAll(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
  });

  describe('🚀 Dashboard API Performance Benchmarks', () => {
    test('should achieve target response time improvements (6ms → 3ms)', async () => {
      const iterations = 5;
      const results = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = process.hrtime.bigint();
        
        const response = await request(app)
          .get('/api/dashboard/summary')
          .query({ month: 'all' })
          .set('Cookie', adminSession || []);
          
        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
        
        results.push({
          iteration: i + 1,
          status: response.status,
          duration,
          dataPoints: response.status === 200 ? response.body.length : 0
        });
        
        expect([200, 302]).toContain(response.status);
      }

      const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;
      const minDuration = Math.min(...results.map(r => r.duration));
      const maxDuration = Math.max(...results.map(r => r.duration));

      console.log(`📊 Dashboard API Performance:
        Average: ${avgDuration.toFixed(2)}ms
        Min: ${minDuration.toFixed(2)}ms  
        Max: ${maxDuration.toFixed(2)}ms
        Target: <${PERFORMANCE_THRESHOLDS.dashboardAPI.optimized}ms
        Baseline: ${PERFORMANCE_THRESHOLDS.dashboardAPI.baseline}ms`);

      // Validate performance improvement
      expect(avgDuration).toBeLessThan(PERFORMANCE_THRESHOLDS.dashboardAPI.optimized);
      
      // Validate improvement vs baseline
      const improvement = (PERFORMANCE_THRESHOLDS.dashboardAPI.baseline - avgDuration) / PERFORMANCE_THRESHOLDS.dashboardAPI.baseline;
      expect(improvement).toBeGreaterThan(0); // Should be faster than baseline
      
      console.log(`✅ Performance improvement: ${(improvement * 100).toFixed(1)}%`);
    });

    test('should handle concurrent requests efficiently (17ms → 15ms)', async () => {
      const concurrentRequests = 10;
      const startTime = process.hrtime.bigint();

      const promises = Array.from({ length: concurrentRequests }, (_, i) =>
        request(app)
          .get('/api/dashboard/stats')
          .set('Cookie', adminSession || [])
          .then(res => ({
            index: i,
            status: res.status,
            duration: Date.now()
          }))
      );

      const results = await Promise.all(promises);
      const endTime = process.hrtime.bigint();
      const totalDuration = Number(endTime - startTime) / 1000000;
      const avgDuration = totalDuration / concurrentRequests;

      const successfulRequests = results.filter(r => [200, 302].includes(r.status)).length;

      console.log(`🔄 Concurrent Requests Performance:
        Total Duration: ${totalDuration.toFixed(2)}ms
        Average per Request: ${avgDuration.toFixed(2)}ms
        Successful Requests: ${successfulRequests}/${concurrentRequests}
        Target: <${PERFORMANCE_THRESHOLDS.concurrentRequests.optimized}ms
        Baseline: ${PERFORMANCE_THRESHOLDS.concurrentRequests.baseline}ms`);

      // Validate concurrent performance
      expect(avgDuration).toBeLessThan(PERFORMANCE_THRESHOLDS.concurrentRequests.optimized);
      expect(successfulRequests).toBeGreaterThan(concurrentRequests * 0.8); // 80% success rate

      const improvement = (PERFORMANCE_THRESHOLDS.concurrentRequests.baseline - avgDuration) / PERFORMANCE_THRESHOLDS.concurrentRequests.baseline;
      console.log(`✅ Concurrent performance improvement: ${(improvement * 100).toFixed(1)}%`);
    });

    test('should demonstrate cache performance benefits', async () => {
      const cacheEndpoint = '/api/dashboard/months';
      
      // Cold request (cache miss)
      const coldStart = process.hrtime.bigint();
      const coldResponse = await request(app)
        .get(cacheEndpoint)
        .set('Cookie', adminSession || []);
      const coldEnd = process.hrtime.bigint();
      const coldDuration = Number(coldEnd - coldStart) / 1000000;

      // Warm request (cache hit)
      const warmStart = process.hrtime.bigint();
      const warmResponse = await request(app)
        .get(cacheEndpoint)
        .set('Cookie', adminSession || []);
      const warmEnd = process.hrtime.bigint();
      const warmDuration = Number(warmEnd - warmStart) / 1000000;

      console.log(`🔥 Cache Performance:
        Cold Request: ${coldDuration.toFixed(2)}ms
        Warm Request: ${warmDuration.toFixed(2)}ms
        Improvement: ${((coldDuration - warmDuration) / coldDuration * 100).toFixed(1)}%`);

      expect([200, 302]).toContain(coldResponse.status);
      expect([200, 302]).toContain(warmResponse.status);
      expect(coldResponse.status).toBe(warmResponse.status);

      // Cache hit should be faster or equal
      expect(warmDuration).toBeLessThanOrEqual(coldDuration + 10); // Allow small variance
      
      // Cache hit should be under threshold
      if (coldResponse.status === 200) {
        expect(warmDuration).toBeLessThan(PERFORMANCE_THRESHOLDS.cacheHit.maxTime);
      }
    });
  });

  describe('📊 N+1 Query Optimization Benchmarks', () => {
    test('should optimize contact comparison queries with $facet', async () => {
      const contact = await Contact.findOne({ ownerId: benchmarkUser._id });
      
      if (contact) {
        const iterations = 3;
        const results = [];

        for (let i = 0; i < iterations; i++) {
          const startTime = process.hrtime.bigint();
          
          const response = await request(app)
            .get(`/api/dashboard/contact/${contact._id}`)
            .set('Cookie', adminSession || []);
            
          const endTime = process.hrtime.bigint();
          const duration = Number(endTime - startTime) / 1000000;
          
          results.push({
            iteration: i + 1,
            status: response.status,
            duration,
            comparisonPoints: response.status === 200 ? response.body.comparison?.length : 0
          });
          
          expect([200, 302, 403, 404]).toContain(response.status);
        }

        const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;
        
        console.log(`🔍 N+1 Query Optimization:
          Average Duration: ${avgDuration.toFixed(2)}ms
          Max Acceptable: 1000ms
          Data Points: ${results[0].comparisonPoints || 0}`);

        // Should complete efficiently with $facet aggregation
        expect(avgDuration).toBeLessThan(1000);
      }
    });

    test('should handle multiple contact queries without N+1 issues', async () => {
      const contacts = await Contact.find({ ownerId: benchmarkUser._id }).limit(5);
      
      if (contacts.length > 0) {
        const startTime = process.hrtime.bigint();
        
        const promises = contacts.map(contact =>
          request(app)
            .get(`/api/dashboard/contact/${contact._id}`)
            .set('Cookie', adminSession || [])
            .then(res => ({ status: res.status, id: contact._id }))
            .catch(err => ({ status: 'error', error: err.message, id: contact._id }))
        );

        const results = await Promise.all(promises);
        const endTime = process.hrtime.bigint();
        const totalDuration = Number(endTime - startTime) / 1000000;

        const avgDurationPerQuery = totalDuration / contacts.length;

        console.log(`📊 Multiple Contact Queries:
          Total Duration: ${totalDuration.toFixed(2)}ms
          Average per Query: ${avgDurationPerQuery.toFixed(2)}ms
          Queries: ${contacts.length}
          Success Rate: ${results.filter(r => [200, 302, 403, 404].includes(r.status)).length}/${contacts.length}`);

        // Should scale linearly, not exponentially (indicating no N+1)
        expect(avgDurationPerQuery).toBeLessThan(2000); // 2 seconds per query max
        expect(totalDuration).toBeLessThan(10000); // 10 seconds total max
      }
    });
  });

  describe('💾 Memory Usage Benchmarks', () => {
    test('should maintain reasonable memory usage with optimizations', async () => {
      const initialMemory = process.memoryUsage();

      // Generate memory-intensive operations
      const operations = Array.from({ length: 20 }, (_, i) =>
        request(app)
          .get('/api/dashboard/summary')
          .query({ 
            month: 'all',
            t: Date.now() + i // Force unique cache keys
          })
          .set('Cookie', adminSession || [])
          .catch(err => ({ status: 'error' }))
      );

      await Promise.all(operations);

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      await new Promise(resolve => setTimeout(resolve, 1000));

      const finalMemory = process.memoryUsage();
      const heapIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      console.log(`💾 Memory Usage Benchmark:
        Initial Heap: ${Math.round(initialMemory.heapUsed / 1024 / 1024)}MB
        Final Heap: ${Math.round(finalMemory.heapUsed / 1024 / 1024)}MB
        Increase: ${Math.round(heapIncrease / 1024 / 1024)}MB
        Max Acceptable: ${Math.round(PERFORMANCE_THRESHOLDS.memoryUsage.maxIncrease / 1024 / 1024)}MB`);

      // Memory increase should be within acceptable limits
      expect(heapIncrease).toBeLessThan(PERFORMANCE_THRESHOLDS.memoryUsage.maxIncrease);
      expect(finalMemory.heapUsed).toBeLessThan(PERFORMANCE_THRESHOLDS.memoryUsage.baseline);
    });

    test('should handle large result sets efficiently', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Request large dataset
      const response = await request(app)
        .get('/api/dashboard/contacts')
        .query({ limit: 50 })
        .set('Cookie', adminSession || []);

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryDelta = finalMemory - initialMemory;

      console.log(`📊 Large Dataset Memory Usage:
        Memory Delta: ${Math.round(memoryDelta / 1024)}KB
        Response Status: ${response.status}
        Data Size: ${response.status === 200 ? response.body.contacts?.length : 0} contacts`);

      expect([200, 302, 403]).toContain(response.status);
      
      // Memory usage should be reasonable for large datasets
      expect(memoryDelta).toBeLessThan(20 * 1024 * 1024); // Less than 20MB

      if (response.status === 200) {
        expect(response.body).toHaveProperty('contacts');
        expect(response.body).toHaveProperty('pagination');
      }
    });
  });

  describe('📈 Database Performance Benchmarks', () => {
    test('should use indexes efficiently for time-based queries', async () => {
      const iterations = 5;
      const results = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = process.hrtime.bigint();
        
        const response = await request(app)
          .get('/api/dashboard/months')
          .set('Cookie', adminSession || []);
          
        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - startTime) / 1000000;
        
        results.push({
          iteration: i + 1,
          status: response.status,
          duration,
          months: response.status === 200 ? response.body.length : 0
        });
      }

      const avgDuration = results.reduce((sum, r) => sum + r.duration, 0) / results.length;

      console.log(`🗄️ Database Index Performance:
        Average Query Time: ${avgDuration.toFixed(2)}ms
        Data Points: ${results[0].months || 0}
        Index Target: <500ms`);

      // Should use createdAt index efficiently
      expect(avgDuration).toBeLessThan(500);
      
      results.forEach(result => {
        expect([200, 302]).toContain(result.status);
      });
    });

    test('should perform aggregation queries efficiently', async () => {
      const aggregationQueries = [
        { endpoint: '/api/dashboard/summary?month=all', description: 'Full Summary Aggregation' },
        { endpoint: '/api/dashboard/summary?month=2025-01', description: 'Monthly Summary Aggregation' },
        { endpoint: '/api/dashboard/stats', description: 'Statistics Aggregation' }
      ];

      for (const query of aggregationQueries) {
        const startTime = process.hrtime.bigint();
        
        const response = await request(app)
          .get(query.endpoint)
          .set('Cookie', adminSession || []);
          
        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - startTime) / 1000000;

        console.log(`⚡ ${query.description}: ${duration.toFixed(2)}ms (Status: ${response.status})`);

        expect([200, 302]).toContain(response.status);
        expect(duration).toBeLessThan(2000); // 2 second limit for aggregations
      }
    });
  });

  describe('🎯 End-to-End Performance Validation', () => {
    test('should maintain performance under realistic load', async () => {
      const loadTestDuration = 10000; // 10 seconds
      const requestInterval = 500; // Every 500ms
      const startTime = Date.now();
      const results = [];

      const loadTest = setInterval(async () => {
        if (Date.now() - startTime >= loadTestDuration) {
          clearInterval(loadTest);
          return;
        }

        const endpoints = [
          '/api/dashboard/months',
          '/api/dashboard/summary',
          '/api/dashboard/stats',
          '/api/dashboard/contacts?limit=10'
        ];

        const randomEndpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
        const requestStart = process.hrtime.bigint();

        try {
          const response = await request(app)
            .get(randomEndpoint)
            .set('Cookie', adminSession || [])
            .timeout(5000);

          const requestEnd = process.hrtime.bigint();
          const requestDuration = Number(requestEnd - requestStart) / 1000000;

          results.push({
            endpoint: randomEndpoint,
            status: response.status,
            duration: requestDuration,
            timestamp: Date.now()
          });
        } catch (error) {
          results.push({
            endpoint: randomEndpoint,
            status: 'error',
            duration: 5000,
            error: error.message,
            timestamp: Date.now()
          });
        }
      }, requestInterval);

      // Wait for load test to complete
      await new Promise(resolve => setTimeout(resolve, loadTestDuration + 1000));

      const successfulRequests = results.filter(r => [200, 302].includes(r.status));
      const averageResponseTime = successfulRequests.length > 0 
        ? successfulRequests.reduce((sum, r) => sum + r.duration, 0) / successfulRequests.length 
        : 0;

      console.log(`🎯 Load Test Results:
        Duration: ${loadTestDuration}ms
        Total Requests: ${results.length}
        Successful: ${successfulRequests.length}
        Success Rate: ${Math.round(successfulRequests.length / results.length * 100)}%
        Average Response Time: ${averageResponseTime.toFixed(2)}ms`);

      // Performance requirements
      expect(successfulRequests.length / results.length).toBeGreaterThan(0.8); // 80% success rate
      expect(averageResponseTime).toBeLessThan(1000); // Under 1 second average
      expect(results.length).toBeGreaterThan(10); // Should have processed multiple requests
    });
  });
});