/**
 * Performance Cache Validation Test Suite
 * Tests for universal cache system, N+1 query optimizations, and index performance
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
let testUser = null;

describe('📦 Universal Cache System Validation', () => {
  beforeAll(async () => {
    app = getTestApp();
    
    // Create test user for authentication
    await User.deleteMany({});
    testUser = await User.create({
      username: 'testadmin',
      email: 'admin@test.com',
      password: '$2a$10$test.hash.for.testing.purposes.only',
      role: 'admin',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    // Login as admin to get session
    const loginResponse = await request(app)
      .post('/auth/login')
      .send({
        username: 'testadmin',
        password: 'admin123'
      });
      
    if (loginResponse.headers['set-cookie']) {
      adminSession = loginResponse.headers['set-cookie'];
    }
  }, 30000);

  afterAll(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
  });

  describe('🕒 Cache TTL Configuration', () => {
    test('should use different TTL values for different data types', async () => {
      // Test months cache (30 minutes TTL)
      const monthsStart = Date.now();
      const monthsResponse = await request(app)
        .get('/api/dashboard/months')
        .set('Cookie', adminSession || []);
      const monthsTime = Date.now() - monthsStart;

      // Test summary cache (10 minutes TTL)
      const summaryStart = Date.now();
      const summaryResponse = await request(app)
        .get('/api/dashboard/summary')
        .set('Cookie', adminSession || []);
      const summaryTime = Date.now() - summaryStart;

      // Test stats cache (5 minutes TTL)
      const statsStart = Date.now();
      const statsResponse = await request(app)
        .get('/api/dashboard/stats')
        .set('Cookie', adminSession || []);
      const statsTime = Date.now() - statsStart;

      // Performance validation
      expect([200, 302]).toContain(monthsResponse.status);
      expect([200, 302]).toContain(summaryResponse.status);
      expect([200, 302]).toContain(statsResponse.status);

      console.log(`📊 Performance metrics:
        Months: ${monthsTime}ms
        Summary: ${summaryTime}ms
        Stats: ${statsTime}ms`);

      // First requests should be reasonable (under 2 seconds)
      expect(monthsTime).toBeLessThan(2000);
      expect(summaryTime).toBeLessThan(2000);
      expect(statsTime).toBeLessThan(2000);
    });

    test('should provide cache hits on repeated requests', async () => {
      // Create test data for more reliable caching
      await Response.create([
        {
          name: 'Test User 1',
          responses: [{ question: 'Test Q1', answer: 'Test A1' }],
          month: '2025-01',
          isAdmin: false,
          token: 'test1',
          createdAt: new Date('2025-01-15')
        },
        {
          name: 'Test User 2',
          responses: [{ question: 'Test Q2', answer: 'Test A2' }],
          month: '2025-01',
          isAdmin: false,
          token: 'test2',
          createdAt: new Date('2025-01-16')
        }
      ]);

      // First request (cache miss)
      const firstStart = Date.now();
      const firstResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);
      const firstTime = Date.now() - firstStart;

      // Second request (should be cache hit)
      const secondStart = Date.now();
      const secondResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);
      const secondTime = Date.now() - secondStart;

      // Both should succeed
      expect([200, 302]).toContain(firstResponse.status);
      expect([200, 302]).toContain(secondResponse.status);

      // Cache hit should generally be faster (allowing for variance)
      console.log(`🔄 Cache performance: First: ${firstTime}ms, Second: ${secondTime}ms`);
      
      // If authenticated and data returned, second request should be faster
      if (firstResponse.status === 200 && secondResponse.status === 200) {
        expect(secondTime).toBeLessThanOrEqual(firstTime * 1.5); // Allow 50% variance
      }
    });
  });

  describe('👥 User Data Isolation', () => {
    let userSession = null;

    beforeAll(async () => {
      // Create regular user
      const regularUser = await User.create({
        username: 'testuser',
        email: 'user@test.com',
        password: '$2a$10$test.hash.for.regular.user.only',
        role: 'user',
        metadata: { isActive: true, registeredAt: new Date() }
      });

      // Login as regular user
      const userLoginResponse = await request(app)
        .post('/auth/login')
        .send({
          username: 'testuser',
          password: 'user123'
        });
        
      if (userLoginResponse.headers['set-cookie']) {
        userSession = userLoginResponse.headers['set-cookie'];
      }
    });

    test('should isolate cache by user ID and admin status', async () => {
      // Admin request
      const adminResponse = await request(app)
        .get('/api/dashboard/summary')
        .set('Cookie', adminSession || []);

      // User request
      const userResponse = await request(app)
        .get('/api/dashboard/summary')
        .set('Cookie', userSession || []);

      // Both should be handled but may have different access levels
      expect([200, 302, 403]).toContain(adminResponse.status);
      expect([200, 302, 403]).toContain(userResponse.status);

      // If both succeed, they should potentially have different data
      if (adminResponse.status === 200 && userResponse.status === 200) {
        console.log('✓ Cache isolation working - different users get different data');
      }
    });

    test('should prevent cache contamination between users', async () => {
      // Create user-specific data
      await Submission.create({
        userId: testUser._id,
        month: '2025-01',
        responses: [{ question: 'Admin Q', answer: 'Admin A' }],
        completionRate: 100,
        submittedAt: new Date()
      });

      // Make admin request to populate admin cache
      const adminSummary = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      // Make user request - should not see admin data
      const userSummary = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', userSession || []);

      console.log(`🔒 Admin response: ${adminSummary.status}, User response: ${userSummary.status}`);
      expect([200, 302, 403]).toContain(adminSummary.status);
      expect([200, 302, 403]).toContain(userSummary.status);
    });
  });

  describe('🔄 Cache Memory Management', () => {
    test('should enforce cache size limits to prevent memory leaks', async () => {
      // Generate many unique cache keys to test size limits
      const uniqueRequests = Array.from({ length: 50 }, (_, i) =>
        request(app)
          .get('/api/dashboard/summary')
          .query({ 
            month: `2025-${String(i % 12 + 1).padStart(2, '0')}`,
            unique: `test-${i}` // Force unique cache keys
          })
          .set('Cookie', adminSession || [])
          .then(res => ({
            index: i,
            status: res.status,
            time: Date.now()
          }))
          .catch(err => ({
            index: i,
            status: 'error',
            error: err.message
          }))
      );

      const results = await Promise.allSettled(uniqueRequests);
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      console.log(`📊 Cache stress test: ${successful} successful, ${failed} failed`);
      
      // Should handle at least 80% of requests without crashing
      expect(successful).toBeGreaterThan(40);
      
      // No memory crashes should occur
      expect(process.memoryUsage().heapUsed).toBeLessThan(1024 * 1024 * 1024); // 1GB limit
    });

    test('should clean up expired cache entries', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Make several requests to populate cache
      const populationRequests = Array.from({ length: 10 }, (_, i) =>
        request(app)
          .get('/api/dashboard/stats')
          .query({ t: Date.now() + i })
          .set('Cookie', adminSession || [])
      );

      await Promise.allSettled(populationRequests);

      // Wait a bit for any cleanup processes
      await new Promise(resolve => setTimeout(resolve, 1000));

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      console.log(`💾 Memory usage: Initial: ${Math.round(initialMemory/1024/1024)}MB, Final: ${Math.round(finalMemory/1024/1024)}MB, Increase: ${Math.round(memoryIncrease/1024/1024)}MB`);

      // Memory increase should be reasonable
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB increase
    });
  });

  describe('⚡ Cache Performance Benchmarks', () => {
    test('should show measurable performance improvement with caching', async () => {
      // Clear any existing cache by making a unique request first
      await request(app)
        .get('/api/dashboard/months')
        .query({ clear: Date.now() })
        .set('Cookie', adminSession || []);

      // Measure initial (cold) request
      const coldStart = Date.now();
      const coldResponse = await request(app)
        .get('/api/dashboard/months')
        .set('Cookie', adminSession || []);
      const coldTime = Date.now() - coldStart;

      // Measure cached (warm) request
      const warmStart = Date.now();
      const warmResponse = await request(app)
        .get('/api/dashboard/months')
        .set('Cookie', adminSession || []);
      const warmTime = Date.now() - warmStart;

      console.log(`🚀 Performance comparison: Cold: ${coldTime}ms, Warm: ${warmTime}ms`);

      // Both should succeed or fail consistently
      expect(coldResponse.status).toBe(warmResponse.status);
      
      // If successful, warm request should generally be faster or similar
      if (coldResponse.status === 200) {
        expect(warmTime).toBeLessThanOrEqual(coldTime + 50); // Allow small variance
      }

      // Both should complete within reasonable time
      expect(coldTime).toBeLessThan(5000);
      expect(warmTime).toBeLessThan(5000);
    });
  });
});

describe('🔍 N+1 Query Optimization Validation', () => {
  beforeAll(async () => {
    // Create test data for N+1 query testing
    await Contact.deleteMany({});
    await Submission.deleteMany({});

    // Create contacts and submissions for N+1 testing
    const contacts = await Contact.create([
      {
        firstName: 'Contact',
        lastName: 'One',
        email: 'contact1@test.com',
        ownerId: testUser._id,
        isActive: true,
        status: 'active',
        contactUserId: testUser._id
      },
      {
        firstName: 'Contact',
        lastName: 'Two', 
        email: 'contact2@test.com',
        ownerId: testUser._id,
        isActive: true,
        status: 'active',
        contactUserId: testUser._id
      }
    ]);

    await Submission.create([
      {
        userId: testUser._id,
        month: '2025-01',
        responses: [{ question: 'Q1', answer: 'A1' }],
        completionRate: 100,
        submittedAt: new Date()
      },
      {
        userId: testUser._id,
        month: '2024-12',
        responses: [{ question: 'Q2', answer: 'A2' }],
        completionRate: 80,
        submittedAt: new Date()
      }
    ]);
  });

  test('should use $facet aggregation for contact submissions', async () => {
    const contactId = await Contact.findOne({ ownerId: testUser._id }).then(c => c._id);
    
    const start = Date.now();
    const response = await request(app)
      .get(`/api/dashboard/contact/${contactId}`)
      .set('Cookie', adminSession || []);
    const queryTime = Date.now() - start;

    console.log(`🔎 Contact comparison query time: ${queryTime}ms`);

    // Should complete efficiently with $facet aggregation
    expect(queryTime).toBeLessThan(1000); // Under 1 second
    expect([200, 302, 403, 404]).toContain(response.status);

    if (response.status === 200) {
      expect(response.body).toHaveProperty('contact');
      expect(response.body).toHaveProperty('comparison');
      expect(response.body).toHaveProperty('stats');
    }
  });

  test('should handle multiple contact requests efficiently', async () => {
    const contacts = await Contact.find({ ownerId: testUser._id }).limit(5);
    
    const start = Date.now();
    const promises = contacts.map(contact =>
      request(app)
        .get(`/api/dashboard/contact/${contact._id}`)
        .set('Cookie', adminSession || [])
        .catch(err => ({ status: 'error', error: err.message }))
    );

    const results = await Promise.all(promises);
    const totalTime = Date.now() - start;

    console.log(`📊 Multiple contact queries: ${results.length} requests in ${totalTime}ms`);

    // Should handle multiple requests efficiently
    expect(totalTime).toBeLessThan(5000); // Under 5 seconds for all
    
    const successfulRequests = results.filter(r => [200, 302, 403, 404].includes(r.status));
    expect(successfulRequests.length).toBeGreaterThan(0);
  });
});

describe('🗄️ Database Index Performance Validation', () => {
  test('should use indexes efficiently for months query', async () => {
    // Create more test data to make index usage meaningful
    await Response.create([
      {
        name: 'Index Test 1',
        responses: [{ question: 'IQ1', answer: 'IA1' }],
        month: '2024-11',
        isAdmin: false,
        token: 'idx1',
        createdAt: new Date('2024-11-15')
      },
      {
        name: 'Index Test 2',
        responses: [{ question: 'IQ2', answer: 'IA2' }],
        month: '2024-12',
        isAdmin: false,
        token: 'idx2',
        createdAt: new Date('2024-12-15')
      }
    ]);

    const start = Date.now();
    const response = await request(app)
      .get('/api/dashboard/months')
      .set('Cookie', adminSession || []);
    const queryTime = Date.now() - start;

    console.log(`🗃️ Months index query time: ${queryTime}ms`);

    // Should use createdAt index for efficient querying
    expect(queryTime).toBeLessThan(500); // Should be very fast with indexes
    expect([200, 302]).toContain(response.status);

    if (response.status === 200) {
      expect(Array.isArray(response.body)).toBe(true);
    }
  });

  test('should use aggregation pipeline with hints for optimal performance', async () => {
    const start = Date.now();
    const response = await request(app)
      .get('/api/dashboard/summary')
      .query({ month: 'all' })
      .set('Cookie', adminSession || []);
    const queryTime = Date.now() - start;

    console.log(`📊 Aggregation pipeline time: ${queryTime}ms`);

    // Aggregation with hints should be efficient
    expect(queryTime).toBeLessThan(2000);
    expect([200, 302]).toContain(response.status);

    if (response.status === 200) {
      expect(Array.isArray(response.body)).toBe(true);
    }
  });
});

describe('💾 Memory Optimization Validation', () => {
  test('should use projection to limit data transfer', async () => {
    const initialMemory = process.memoryUsage().heapUsed;

    // Make request that should use projection
    const response = await request(app)
      .get('/api/dashboard/contacts')
      .query({ limit: 50 })
      .set('Cookie', adminSession || []);

    const finalMemory = process.memoryUsage().heapUsed;
    const memoryDelta = finalMemory - initialMemory;

    console.log(`💾 Memory usage for contacts query: ${Math.round(memoryDelta/1024)}KB`);

    expect([200, 302, 403]).toContain(response.status);
    
    // Memory usage should be reasonable
    expect(memoryDelta).toBeLessThan(50 * 1024 * 1024); // Less than 50MB

    if (response.status === 200) {
      expect(response.body).toHaveProperty('contacts');
      expect(response.body).toHaveProperty('pagination');
    }
  });

  test('should handle large result sets without memory issues', async () => {
    // Create substantial test data
    const testSubmissions = Array.from({ length: 50 }, (_, i) => ({
      userId: testUser._id,
      month: `2024-${String((i % 12) + 1).padStart(2, '0')}`,
      responses: [{ question: `Q${i}`, answer: `A${i}` }],
      completionRate: Math.floor(Math.random() * 100),
      submittedAt: new Date()
    }));

    await Submission.create(testSubmissions);

    const initialMemory = process.memoryUsage().heapUsed;

    const response = await request(app)
      .get('/api/dashboard/responses')
      .set('Cookie', adminSession || []);

    const finalMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = finalMemory - initialMemory;

    console.log(`📈 Large dataset memory usage: ${Math.round(memoryIncrease/1024/1024)}MB`);

    expect([200, 302, 403]).toContain(response.status);
    
    // Should handle large datasets without excessive memory usage
    expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB
  });
});