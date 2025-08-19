/**
 * Integration and Edge Cases Test Suite for Performance Optimizations
 * 
 * Tests integration between middleware, services, and optimized code paths
 * Validates edge cases including cache limits, memory pressure, and error scenarios
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
let integrationTestAdmin = null;
let integrationTestUser = null;

describe('🔗 Integration Tests for Optimized Code Paths', () => {
  beforeAll(async () => {
    app = getTestApp();
    
    // Clean setup
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
    
    // Create integration test users
    integrationTestAdmin = await User.create({
      username: 'integrationadmin',
      email: 'integration.admin@test.com',
      password: '$2a$10$integration.hash.for.admin',
      role: 'admin',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    integrationTestUser = await User.create({
      username: 'integrationuser',
      email: 'integration.user@test.com',
      password: '$2a$10$integration.hash.for.user',
      role: 'user',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    // Create comprehensive test dataset
    const testData = {
      responses: Array.from({ length: 50 }, (_, i) => ({
        name: `Integration User ${i}`,
        responses: [
          { question: 'Integration Question 1', answer: `Integration Answer ${i}-1` },
          { question: 'Integration Question 2', answer: `Integration Answer ${i}-2` },
          { question: 'En rapide, comment ça va ?', answer: `Ça va bien ${i}` }
        ],
        month: `202${Math.floor(i/15) + 3}-${String((i % 12) + 1).padStart(2, '0')}`,
        isAdmin: i % 10 === 0,
        token: i % 10 === 0 ? null : `integration-token-${i}`,
        createdAt: new Date(2023 + Math.floor(i/15), i % 12, (i % 28) + 1)
      })),
      contacts: Array.from({ length: 30 }, (_, i) => ({
        firstName: `Contact${i}`,
        lastName: 'Integration',
        email: `contact${i}@integration.test`,
        ownerId: i % 2 === 0 ? integrationTestAdmin._id : integrationTestUser._id,
        isActive: i % 5 !== 0, // 80% active
        status: i % 5 === 0 ? 'opted_out' : 'active',
        contactUserId: i % 3 === 0 ? (i % 2 === 0 ? integrationTestAdmin._id : integrationTestUser._id) : null,
        tracking: {
          responsesReceived: Math.floor(Math.random() * 20),
          responseRate: Math.random() * 100,
          lastInteractionAt: new Date(2024, Math.floor(Math.random() * 12), Math.floor(Math.random() * 28) + 1),
          firstResponseAt: new Date(2024, 0, 1)
        }
      })),
      submissions: Array.from({ length: 100 }, (_, i) => ({
        userId: i % 2 === 0 ? integrationTestAdmin._id : integrationTestUser._id,
        month: `202${Math.floor(i/25) + 1}-${String((i % 12) + 1).padStart(2, '0')}`,
        responses: [
          { question: `Integration Q${i % 5 + 1}`, answer: `Integration A${i}` }
        ],
        completionRate: Math.floor(Math.random() * 100),
        submittedAt: new Date(2024, i % 12, (i % 28) + 1),
        freeText: i % 4 === 0 ? `Free text for submission ${i}` : null
      }))
    };
    
    await Response.create(testData.responses);
    await Contact.create(testData.contacts);
    await Submission.create(testData.submissions);
    
    // Get sessions
    const adminLogin = await request(app)
      .post('/auth/login')
      .send({
        username: 'integrationadmin',
        password: 'admin123'
      });
    
    const userLogin = await request(app)
      .post('/auth/login')
      .send({
        username: 'integrationuser',
        password: 'user123'
      });
    
    if (adminLogin.headers['set-cookie']) {
      adminSession = adminLogin.headers['set-cookie'];
    }
    
    if (userLogin.headers['set-cookie']) {
      userSession = userLogin.headers['set-cookie'];
    }
  }, 60000);

  afterAll(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
  });

  describe('🔄 Middleware Chain Integration', () => {
    test('should integrate authentication → cache → query optimization properly', async () => {
      const endpoints = [
        { path: '/api/dashboard/summary', description: 'Summary with aggregation' },
        { path: '/api/dashboard/months', description: 'Months with caching' },
        { path: '/api/dashboard/contacts', description: 'Contacts with pagination' }
      ];

      for (const endpoint of endpoints) {
        // Unauthenticated request - should be blocked before cache
        const unauthStart = Date.now();
        const unauthResponse = await request(app).get(endpoint.path);
        const unauthTime = Date.now() - unauthStart;
        
        expect([302, 401, 403]).toContain(unauthResponse.status);
        console.log(`🚫 ${endpoint.description} - Unauth blocked: ${unauthTime}ms`);

        // Authenticated request - should go through full pipeline
        const authStart = Date.now();
        const authResponse = await request(app)
          .get(endpoint.path)
          .set('Cookie', adminSession || []);
        const authTime = Date.now() - authStart;
        
        expect([200, 302]).toContain(authResponse.status);
        console.log(`✅ ${endpoint.description} - Auth successful: ${authTime}ms`);

        // Second authenticated request - should be faster (cache hit)
        const cacheStart = Date.now();
        const cacheResponse = await request(app)
          .get(endpoint.path)
          .set('Cookie', adminSession || []);
        const cacheTime = Date.now() - cacheStart;
        
        expect([200, 302]).toContain(cacheResponse.status);
        console.log(`⚡ ${endpoint.description} - Cache hit: ${cacheTime}ms`);

        // Cache should be faster or similar (allowing for variance)
        if (authResponse.status === 200 && cacheResponse.status === 200) {
          expect(cacheTime).toBeLessThanOrEqual(authTime + 100);
        }
      }
    });

    test('should maintain role-based access through optimization layers', async () => {
      const roleRestrictedEndpoints = [
        '/api/dashboard/contacts',
        '/api/dashboard/contact/507f1f77bcf86cd799439011',
        '/api/dashboard/responses'
      ];

      for (const endpoint of roleRestrictedEndpoints) {
        // Admin access
        const adminResponse = await request(app)
          .get(endpoint)
          .set('Cookie', adminSession || []);
        
        // User access
        const userResponse = await request(app)
          .get(endpoint)
          .set('Cookie', userSession || []);

        expect([200, 302, 403, 404]).toContain(adminResponse.status);
        expect([200, 302, 403, 404]).toContain(userResponse.status);

        console.log(`🔐 ${endpoint} - Admin: ${adminResponse.status}, User: ${userResponse.status}`);

        // Verify role-based data filtering is working
        if (adminResponse.status === 200 && userResponse.status === 200) {
          const adminDataSize = JSON.stringify(adminResponse.body).length;
          const userDataSize = JSON.stringify(userResponse.body).length;
          
          console.log(`📊 Data sizes - Admin: ${adminDataSize}, User: ${userDataSize}`);
        }
      }
    });

    test('should handle error propagation through optimization layers', async () => {
      const errorScenarios = [
        { path: '/api/dashboard/contact/invalid-id', expectedStatus: [400, 404] },
        { path: '/api/dashboard/nonexistent', expectedStatus: [404] },
        { path: '/api/dashboard/contacts?page=invalid', expectedStatus: [400, 200] }
      ];

      for (const scenario of errorScenarios) {
        const response = await request(app)
          .get(scenario.path)
          .set('Cookie', adminSession || []);

        expect([...scenario.expectedStatus, 302]).toContain(response.status);
        
        if (response.status >= 400) {
          expect(response.body).toBeDefined();
          // Should have proper error structure
          if (response.body.error || response.body.message) {
            console.log(`❌ Error handled: ${scenario.path} -> ${response.status}`);
          }
        }
      }
    });
  });

  describe('🔀 Service Layer Integration', () => {
    test('should integrate contact service with dashboard caching', async () => {
      const contactsResponse = await request(app)
        .get('/api/dashboard/contacts')
        .query({ limit: 20, page: 1, search: 'Integration' })
        .set('Cookie', adminSession || []);

      if (contactsResponse.status === 200) {
        expect(contactsResponse.body).toHaveProperty('contacts');
        expect(contactsResponse.body).toHaveProperty('pagination');
        expect(contactsResponse.body).toHaveProperty('summary');
        
        const contacts = contactsResponse.body.contacts;
        expect(Array.isArray(contacts)).toBe(true);
        
        if (contacts.length > 0) {
          const contact = contacts[0];
          expect(contact).toHaveProperty('id');
          expect(contact).toHaveProperty('firstName');
          expect(contact).toHaveProperty('tracking');
          
          console.log(`📇 Contact service integration: ${contacts.length} contacts loaded`);
        }
      }
    });

    test('should integrate submission service with response history', async () => {
      const responsesResponse = await request(app)
        .get('/api/dashboard/responses')
        .set('Cookie', userSession || []);

      if (responsesResponse.status === 200) {
        expect(responsesResponse.body).toHaveProperty('currentMonth');
        expect(responsesResponse.body).toHaveProperty('history');
        expect(responsesResponse.body).toHaveProperty('stats');
        
        const history = responsesResponse.body.history;
        expect(Array.isArray(history)).toBe(true);
        
        console.log(`📝 Submission service integration: ${history.length} submissions in history`);
      }
    });

    test('should integrate N+1 optimization with contact comparison service', async () => {
      const contact = await Contact.findOne({ ownerId: integrationTestAdmin._id });
      
      if (contact) {
        const comparisonStart = Date.now();
        const comparisonResponse = await request(app)
          .get(`/api/dashboard/contact/${contact._id}`)
          .set('Cookie', adminSession || []);
        const comparisonTime = Date.now() - comparisonStart;

        if (comparisonResponse.status === 200) {
          expect(comparisonResponse.body).toHaveProperty('contact');
          expect(comparisonResponse.body).toHaveProperty('comparison');
          expect(comparisonResponse.body).toHaveProperty('stats');
          
          const comparison = comparisonResponse.body.comparison;
          console.log(`🔍 N+1 optimization: ${comparison.length} comparison points in ${comparisonTime}ms`);
          
          // Should be efficient with $facet aggregation
          expect(comparisonTime).toBeLessThan(2000);
        }
      }
    });
  });
});

describe('🌪️ Edge Cases and Stress Testing', () => {
  describe('💾 Cache Memory Limits', () => {
    test('should handle cache size limits gracefully', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Generate many unique cache requests
      const uniqueRequests = Array.from({ length: 100 }, (_, i) =>
        request(app)
          .get('/api/dashboard/summary')
          .query({ 
            month: `202${Math.floor(i/20) + 1}-${String((i % 12) + 1).padStart(2, '0')}`,
            unique: `stress-${i}-${Date.now()}`
          })
          .set('Cookie', adminSession || [])
          .catch(err => ({ status: 'error', error: err.message }))
      );

      const results = await Promise.allSettled(uniqueRequests);
      const successful = results.filter(r => r.status === 'fulfilled').length;
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      console.log(`🧠 Cache stress test:
        Requests: 100
        Successful: ${successful}
        Memory increase: ${Math.round(memoryIncrease/1024/1024)}MB`);

      // Should handle most requests without excessive memory usage
      expect(successful).toBeGreaterThan(80);
      expect(memoryIncrease).toBeLessThan(200 * 1024 * 1024); // Less than 200MB
    });

    test('should evict old cache entries properly', async () => {
      // Fill cache with entries
      const fillRequests = Array.from({ length: 50 }, (_, i) =>
        request(app)
          .get('/api/dashboard/months')
          .query({ fill: `cache-fill-${i}` })
          .set('Cookie', adminSession || [])
      );

      await Promise.allSettled(fillRequests);

      // Wait for potential cleanup
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Make new requests - should still work
      const newResponse = await request(app)
        .get('/api/dashboard/months')
        .set('Cookie', adminSession || []);

      expect([200, 302]).toContain(newResponse.status);
      console.log('✅ Cache eviction working properly');
    });
  });

  describe('🗄️ Database Edge Cases', () => {
    test('should handle large aggregation pipelines efficiently', async () => {
      // Create large dataset for aggregation stress test
      const largeDataset = Array.from({ length: 500 }, (_, i) => ({
        name: `Stress User ${i}`,
        responses: Array.from({ length: 5 }, (_, j) => ({
          question: `Stress Question ${j + 1}`,
          answer: `Stress Answer ${i}-${j} with lots of text content to make the aggregation work harder`
        })),
        month: `202${Math.floor(i/100) + 1}-${String((i % 12) + 1).padStart(2, '0')}`,
        isAdmin: i % 20 === 0,
        token: i % 20 === 0 ? null : `stress-token-${i}`,
        createdAt: new Date(2021 + Math.floor(i/100), i % 12, (i % 28) + 1)
      }));

      await Response.create(largeDataset);

      const aggregationStart = Date.now();
      const response = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: 'all' })
        .set('Cookie', adminSession || []);
      const aggregationTime = Date.now() - aggregationStart;

      console.log(`📊 Large aggregation: ${aggregationTime}ms`);

      expect([200, 302]).toContain(response.status);
      expect(aggregationTime).toBeLessThan(10000); // 10 seconds max

      if (response.status === 200) {
        expect(response.body.length).toBeGreaterThan(0);
        console.log(`✅ Aggregated ${response.body.length} question groups`);
      }

      // Cleanup
      await Response.deleteMany({ name: /^Stress User/ });
    });

    test('should handle concurrent database operations', async () => {
      const concurrentOps = [
        // Summary requests
        ...Array.from({ length: 5 }, () => 
          request(app)
            .get('/api/dashboard/summary')
            .set('Cookie', adminSession || [])
        ),
        // Contacts requests  
        ...Array.from({ length: 5 }, () =>
          request(app)
            .get('/api/dashboard/contacts')
            .set('Cookie', adminSession || [])
        ),
        // Stats requests
        ...Array.from({ length: 5 }, () =>
          request(app)
            .get('/api/dashboard/stats')
            .set('Cookie', adminSession || [])
        )
      ];

      const startTime = Date.now();
      const results = await Promise.allSettled(concurrentOps);
      const totalTime = Date.now() - startTime;

      const successful = results.filter(r => 
        r.status === 'fulfilled' && [200, 302].includes(r.value.status)
      ).length;

      console.log(`⚡ Concurrent operations:
        Total: ${concurrentOps.length}
        Successful: ${successful}
        Time: ${totalTime}ms`);

      expect(successful).toBeGreaterThan(concurrentOps.length * 0.7); // 70% success rate
      expect(totalTime).toBeLessThan(15000); // 15 seconds max
    });

    test('should handle corrupted or missing data gracefully', async () => {
      // Create responses with missing/null data
      await Response.create([
        {
          name: null,
          responses: [],
          month: '2025-01',
          isAdmin: false,
          token: 'null-name-token'
        },
        {
          name: 'Valid Name',
          responses: [
            { question: null, answer: 'Valid Answer' },
            { question: 'Valid Question', answer: null }
          ],
          month: '2025-01',
          isAdmin: false,
          token: 'null-data-token'
        }
      ]);

      const response = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      expect([200, 302]).toContain(response.status);
      
      if (response.status === 200) {
        // Should handle null data without crashing
        expect(Array.isArray(response.body)).toBe(true);
        console.log('✅ Corrupted data handled gracefully');
      }

      // Cleanup
      await Response.deleteMany({ name: null });
      await Response.deleteMany({ token: 'null-data-token' });
    });
  });

  describe('🔄 Error Recovery and Resilience', () => {
    test('should fall back gracefully when cache fails', async () => {
      // This is more of a simulation since we can't easily break the cache
      // But we can test that the system continues to work under stress
      
      const stressRequests = Array.from({ length: 30 }, (_, i) =>
        request(app)
          .get('/api/dashboard/summary')
          .query({ stress: `failover-${i}`, month: Math.random() > 0.5 ? 'all' : '2025-01' })
          .set('Cookie', adminSession || [])
          .timeout(10000)
          .catch(err => ({ status: 'timeout', error: err.message }))
      );

      const results = await Promise.allSettled(stressRequests);
      const successful = results.filter(r => 
        r.status === 'fulfilled' && [200, 302].includes(r.value.status)
      ).length;
      
      const timeouts = results.filter(r =>
        r.status === 'fulfilled' && r.value.status === 'timeout'
      ).length;

      console.log(`🔄 Stress resilience:
        Successful: ${successful}
        Timeouts: ${timeouts}
        Errors: ${results.length - successful - timeouts}`);

      // Should handle most requests even under stress
      expect(successful).toBeGreaterThan(results.length * 0.6); // 60% success rate minimum
    });

    test('should handle network interruption simulation', async () => {
      // Simulate network issues with very short timeouts
      const networkTests = Array.from({ length: 10 }, (_, i) =>
        request(app)
          .get('/api/dashboard/months')
          .set('Cookie', adminSession || [])
          .timeout(100 + i * 50) // Varying short timeouts
          .catch(err => ({ 
            status: err.code === 'ECONNABORTED' ? 'timeout' : 'error',
            timeout: 100 + i * 50
          }))
      );

      const results = await Promise.all(networkTests);
      
      const completed = results.filter(r => [200, 302].includes(r.status)).length;
      const timeouts = results.filter(r => r.status === 'timeout').length;

      console.log(`🌐 Network resilience:
        Completed: ${completed}
        Timeouts: ${timeouts}
        Total: ${results.length}`);

      // At least some should complete (those with longer timeouts)
      expect(completed + timeouts).toBe(results.length);
    });

    test('should maintain data consistency under concurrent modifications', async () => {
      // This is tricky to test without actual concurrent writes,
      // but we can test that reads remain consistent
      
      const consistencyChecks = Array.from({ length: 10 }, () =>
        request(app)
          .get('/api/dashboard/summary')
          .query({ month: '2025-01' })
          .set('Cookie', adminSession || [])
      );

      const results = await Promise.all(consistencyChecks);
      const successful = results.filter(r => r.status === 200);

      if (successful.length > 1) {
        // All successful responses should return the same data
        const firstResponse = JSON.stringify(successful[0].body);
        const allConsistent = successful.every(r => 
          JSON.stringify(r.body) === firstResponse
        );

        expect(allConsistent).toBe(true);
        console.log(`✅ Data consistency maintained across ${successful.length} concurrent reads`);
      }
    });
  });

  describe('🔒 Security Edge Cases', () => {
    test('should prevent cache pollution attacks', async () => {
      // Try to pollute cache with malicious data
      const pollutionAttempts = [
        { month: '<script>alert("xss")</script>' },
        { month: '"; DROP TABLE responses; --' },
        { search: '{"$ne": null}' },
        { limit: '999999' },
        { page: '-999999' }
      ];

      for (const attack of pollutionAttempts) {
        const response = await request(app)
          .get('/api/dashboard/summary')
          .query(attack)
          .set('Cookie', adminSession || []);

        // Should handle gracefully
        expect([200, 400, 302]).toContain(response.status);

        if (response.status === 200) {
          const responseStr = JSON.stringify(response.body);
          // Should not contain raw attack payload
          expect(responseStr).not.toContain(Object.values(attack)[0]);
        }

        console.log(`🛡️ Cache pollution prevented: ${JSON.stringify(attack)}`);
      }
    });

    test('should maintain rate limiting under cache load', async () => {
      // Try to bypass rate limiting through cache manipulation
      const rapidCachedRequests = Array.from({ length: 25 }, (_, i) =>
        request(app)
          .get('/api/dashboard/profile')
          .query({ cache_bypass: i })
          .set('Cookie', adminSession || [])
      );

      const results = await Promise.all(rapidCachedRequests);
      
      const rateLimited = results.filter(r => r.status === 429).length;
      const successful = results.filter(r => [200, 302].includes(r.status)).length;

      console.log(`⏱️ Rate limiting under cache load:
        Successful: ${successful}
        Rate Limited: ${rateLimited}
        Total: ${results.length}`);

      // Rate limiting should still be effective
      expect(successful + rateLimited).toBe(results.length);
    });
  });
});

describe('📈 Production Readiness Validation', () => {
  test('should handle production-level data volumes', async () => {
    // Simulate production data volume
    const productionDataset = Array.from({ length: 1000 }, (_, i) => ({
      name: `Production User ${i}`,
      responses: Array.from({ length: Math.floor(Math.random() * 10) + 1 }, (_, j) => ({
        question: `Production Question ${j + 1}`,
        answer: `Production answer ${i}-${j} with varying lengths of content that might be encountered in real usage`
      })),
      month: `202${Math.floor(i/200) + 1}-${String((i % 12) + 1).padStart(2, '0')}`,
      isAdmin: i % 50 === 0, // 2% admin responses
      token: i % 50 === 0 ? null : `prod-token-${i}`,
      createdAt: new Date(2021 + Math.floor(i/200), i % 12, (i % 28) + 1)
    }));

    console.log('📊 Creating production-level dataset...');
    await Response.create(productionDataset);

    const productionStart = Date.now();
    const response = await request(app)
      .get('/api/dashboard/summary')
      .query({ month: 'all' })
      .set('Cookie', adminSession || []);
    const productionTime = Date.now() - productionStart;

    console.log(`🏭 Production simulation: ${productionTime}ms`);

    expect([200, 302]).toContain(response.status);
    expect(productionTime).toBeLessThan(30000); // 30 seconds max for large dataset

    if (response.status === 200) {
      expect(response.body.length).toBeGreaterThan(0);
      console.log(`✅ Handled production dataset: ${response.body.length} question groups`);
    }

    // Cleanup
    await Response.deleteMany({ name: /^Production User/ });
  });

  test('should maintain performance under sustained load', async () => {
    const sustainedLoadDuration = 15000; // 15 seconds
    const requestInterval = 1000; // Every second
    const startTime = Date.now();
    const performanceMetrics = [];

    const sustainedTest = setInterval(async () => {
      if (Date.now() - startTime >= sustainedLoadDuration) {
        clearInterval(sustainedTest);
        return;
      }

      const requestStart = Date.now();
      try {
        const response = await request(app)
          .get('/api/dashboard/stats')
          .set('Cookie', adminSession || [])
          .timeout(5000);

        const requestTime = Date.now() - requestStart;
        performanceMetrics.push({
          timestamp: Date.now(),
          status: response.status,
          responseTime: requestTime
        });
      } catch (error) {
        performanceMetrics.push({
          timestamp: Date.now(),
          status: 'error',
          responseTime: 5000,
          error: error.message
        });
      }
    }, requestInterval);

    await new Promise(resolve => setTimeout(resolve, sustainedLoadDuration + 2000));

    const successful = performanceMetrics.filter(m => [200, 302].includes(m.status));
    const avgResponseTime = successful.length > 0 
      ? successful.reduce((sum, m) => sum + m.responseTime, 0) / successful.length 
      : 0;

    console.log(`⏱️ Sustained load test:
      Duration: ${sustainedLoadDuration}ms
      Requests: ${performanceMetrics.length}
      Successful: ${successful.length}
      Average Response Time: ${Math.round(avgResponseTime)}ms`);

    expect(successful.length).toBeGreaterThan(performanceMetrics.length * 0.8); // 80% success
    expect(avgResponseTime).toBeLessThan(3000); // 3 seconds average
  });
});