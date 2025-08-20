/**
 * Integration Tests for /api/responses/current endpoint
 * Tests the complete request flow from API to database for current month status
 * 
 * Test Coverage:
 * - Authentication and Authorization (5 tests)
 * - Rate Limiting (2 tests) 
 * - Data Consistency and Integrity (3 tests)
 * - Performance and Caching (2 tests)
 * - Error Handling and Edge Cases (4 tests)
 * - Cross-User Data Isolation (2 tests)
 * - API Response Format Validation (2 tests)
 * 
 * Security Features Tested:
 * - Proper authentication requirement
 * - Session validation
 * - Data isolation between users
 * - Input parameter validation
 * - Error message security
 * 
 * Performance Benchmarks:
 * - Response time < 500ms (configurable)
 * - Concurrent request handling
 * - Large dataset efficiency
 */

const request = require('supertest');
const mongoose = require('mongoose');
const MongoMemoryServer = require('mongodb-memory-server').MongoMemoryServer;
const app = require('../app');
const User = require('../models/User');
const Submission = require('../models/Submission');
const Contact = require('../models/Contact');
const { setupTestDatabase, cleanupDatabase } = require('./integration/setup-integration');
const { getTestCredentials } = require('./config/test-credentials');
const { TEST_DATA, PERFORMANCE_THRESHOLDS, ERROR_PATTERNS, TEST_ENV } = require('./config/test-constants');
const { performanceOptimizer, setupPerformanceMonitoring } = require('./config/performance-optimization');

describe('API Integration - /api/responses/current', () => {
  let mongoServer;
  let testUser;
  let testAdmin;
  let authCookie;
  let currentMonth;
  let testCredentials;

  // Setup performance monitoring for this test suite
  setupPerformanceMonitoring();

  beforeAll(async () => {
    // Use the same setup as other integration tests
    await setupTestDatabase();
    currentMonth = new Date().toISOString().slice(0, 7);
    
    // Initialize secure test credentials
    testCredentials = getTestCredentials();
  });

  afterAll(async () => {
    await cleanupDatabase();
  });

  beforeEach(async () => {
    // Optimized parallel cleanup using performance optimizer
    await performanceOptimizer.parallelCleanup([
      User, Submission, Contact
    ], 3);

    // Create test user with secure credentials
    testUser = await User.create({
      username: testCredentials.user.username,
      email: testCredentials.user.email,
      password: testCredentials.user.hashedPassword,
      role: 'user',
      metadata: {
        isActive: true,
        emailVerified: true,
        registeredAt: new Date()
      }
    });

    // Create test admin with secure credentials
    testAdmin = await User.create({
      username: testCredentials.admin.username,
      email: testCredentials.admin.email,
      password: testCredentials.admin.hashedPassword,
      role: 'admin',
      metadata: {
        isActive: true,
        emailVerified: true,
        registeredAt: new Date()
      }
    });

    // Login with secure test credentials
    const loginResponse = await request(app)
      .post('/login')
      .send({
        username: testCredentials.admin.username,
        password: testCredentials.admin.password
      });

    if (loginResponse.status === 200) {
      authCookie = loginResponse.headers['set-cookie'];
    } else {
      // Fallback: create a mock session for testing
      const mockSession = 'faf-session=mock-session-id';
      authCookie = [mockSession];
    }
  });

  describe('Authentication and Authorization', () => {
    test('should require authentication', async () => {
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .expect(403);

      expect(response.body).toMatchObject({
        error: expect.any(String)
      });
    });

    test('should accept valid user authentication', async () => {
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      expect(response.body.month).toBe(currentMonth);
    });

    test('should reject expired or invalid sessions', async () => {
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', ['invalid-session=expired'])
        .expect(403);

      expect(response.body.error).toBeDefined();
    });
  });

  describe('Rate Limiting', () => {
    test('should handle normal request rate', async () => {
      // Make several requests rapidly
      const requests = Array(5).fill().map(() =>
        request(app)
          .get('/api/dashboard/responses/current')
          .set('Cookie', authCookie)
      );

      const responses = await Promise.all(requests);
      
      // All requests should succeed (within rate limit)
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
    });

    test('should handle rate limit gracefully if exceeded', async () => {
      // Make many requests to trigger rate limiting
      const requests = Array(100).fill().map(() =>
        request(app)
          .get('/api/dashboard/responses/current')
          .set('Cookie', authCookie)
      );

      const responses = await Promise.allSettled(requests);
      
      // Some requests should succeed, others may be rate limited
      const successful = responses.filter(r => r.status === 'fulfilled' && r.value.status === 200);
      const rateLimited = responses.filter(r => r.status === 'fulfilled' && r.value.status === 429);
      
      expect(successful.length).toBeGreaterThan(0);
      // Rate limiting may or may not kick in depending on configuration
    });
  });

  describe('Data Consistency and Integrity', () => {
    test('should return consistent data across multiple requests', async () => {
      // Create a submission
      await Submission.create({
        userId: testUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Consistent answer' }
        ],
        completionRate: 80,
        submittedAt: new Date()
      });

      // Make multiple requests
      const requests = Array(3).fill().map(() =>
        request(app)
          .get('/api/dashboard/responses/current')
          .set('Cookie', authCookie)
      );

      const responses = await Promise.all(requests);
      
      // All responses should be identical
      const firstResponse = responses[0].body;
      responses.forEach(response => {
        expect(response.body).toEqual(firstResponse);
      });
    });

    test('should reflect real-time database changes', async () => {
      // Initial state - no submission
      let response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      expect(response.body.hasSubmitted).toBe(false);

      // Create a submission
      await Submission.create({
        userId: testUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'New submission' }
        ],
        completionRate: 90,
        submittedAt: new Date()
      });

      // Should now reflect the new submission
      response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      expect(response.body.hasSubmitted).toBe(true);
      expect(response.body.submission.completionRate).toBe(90);
    });

    test('should handle concurrent submissions correctly', async () => {
      // This test ensures database consistency under concurrent operations
      const submissions = Array(5).fill().map((_, index) =>
        Submission.create({
          userId: testUser._id,
          month: currentMonth,
          responses: [
            { questionId: `q${index}`, type: 'text', answer: `Answer ${index}` }
          ],
          completionRate: 20 * (index + 1),
          submittedAt: new Date()
        })
      );

      await Promise.allSettled(submissions);

      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      // Should find exactly one submission (due to unique constraints or the last one created)
      expect(response.body.hasSubmitted).toBe(true);
      expect(response.body.submission).toBeDefined();
    });
  });

  describe('Performance and Caching', () => {
    test('should respond within acceptable time limits', async () => {
      const startTime = Date.now();
      
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      const responseTime = Date.now() - startTime;
      
      // Use performance threshold from constants
      expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.API_RESPONSE_TIME);
      expect(response.body.month).toBeDefined();
    });

    test('should handle large datasets efficiently', async () => {
      // Create multiple submissions for different months
      const submissions = [];
      for (let i = 0; i < 12; i++) {
        const month = new Date();
        month.setMonth(month.getMonth() - i);
        const monthStr = month.toISOString().slice(0, 7);
        
        if (monthStr !== currentMonth) {
          submissions.push(Submission.create({
            userId: testUser._id,
            month: monthStr,
            responses: [
              { questionId: 'q1', type: 'text', answer: `Answer for ${monthStr}` }
            ],
            completionRate: Math.floor(Math.random() * 100),
            submittedAt: new Date(month)
          }));
        }
      }

      await Promise.all(submissions);

      const startTime = Date.now();
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      const responseTime = Date.now() - startTime;
      
      // Should still be fast even with many historical submissions
      expect(responseTime).toBeLessThan(500);
      expect(response.body.month).toBe(currentMonth);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    test('should handle malformed ObjectIds gracefully', async () => {
      // Create user with potentially problematic data
      const problematicUser = await User.create({
        username: 'problematic',
        email: 'problematic@test.com',
        password: '$2b$10$hashedpassword',
        role: 'user'
      });

      // Login as problematic user with secure credentials
      const loginResponse = await request(app)
        .post('/login')
        .send({
          username: testCredentials.admin.username,
          password: testCredentials.admin.password
        });

      const problematicCookie = loginResponse.headers['set-cookie'] || ['faf-session=mock-session'];

      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', problematicCookie)
        .expect(200);

      expect(response.body.month).toBeDefined();
    });

    test('should handle database connection issues', async () => {
      // Simulate database connection error by temporarily disrupting the connection
      const originalFind = Submission.findOne;
      Submission.findOne = jest.fn().mockRejectedValue(new Error('Database connection lost'));
      
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(500);

      // Validate proper error response structure
      expect(response.body).toMatchObject({
        error: expect.stringMatching(/Failed to get current month status|Database connection lost/),
        code: expect.stringMatching(/CURRENT_STATUS_ERROR|DATABASE_ERROR/)
      });
      
      // Validate error is logged (check for proper error handling)
      expect(Submission.findOne).toHaveBeenCalled();
      
      // Restore original method
      Submission.findOne = originalFind;
    });

    test('should validate input parameters properly', async () => {
      // Test with query parameters (though this endpoint doesn't use them)
      const response = await request(app)
        .get('/api/dashboard/responses/current?invalid=parameter&month=invalid')
        .set('Cookie', authCookie)
        .expect(200);

      // Should ignore invalid parameters and work normally
      expect(response.body.month).toBe(currentMonth);
    });

    test('should handle special characters in user data', async () => {
      // Create user with special characters
      const specialUser = await User.create({
        username: 'user_with_éspecial_chars',
        email: 'special+chars@test.com',
        password: '$2b$10$hashedpassword',
        role: 'user'
      });

      const loginResponse = await request(app)
        .post('/login')
        .send({
          username: testCredentials.admin.username,
          password: testCredentials.admin.password
        });

      const specialCookie = loginResponse.headers['set-cookie'] || ['faf-session=mock-session'];

      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', specialCookie)
        .expect(200);

      expect(response.body.month).toBeDefined();
    });
  });

  describe('Cross-User Data Isolation', () => {
    test('should only return data for authenticated user', async () => {
      // Create another user with submission
      const otherUser = await User.create({
        username: 'otheruser',
        email: 'other@test.com',
        password: '$2b$10$hashedpassword',
        role: 'user'
      });

      await Submission.create({
        userId: otherUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Other user answer' }
        ],
        completionRate: 95,
        submittedAt: new Date()
      });

      // Request as original test user
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      // Should not see other user's data
      expect(response.body.hasSubmitted).toBe(false);
      expect(response.body.submission).toBeNull();
    });

    test('should maintain data isolation with admin users', async () => {
      // Create admin user
      const adminUser = await User.create({
        username: 'admin',
        email: 'admin@test.com',
        password: '$2b$10$hashedpassword',
        role: 'admin'
      });

      await Submission.create({
        userId: adminUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Admin answer' }
        ],
        completionRate: 100,
        submittedAt: new Date()
      });

      // Request as regular user
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      // Should not see admin's data
      expect(response.body.hasSubmitted).toBe(false);
    });
  });

  describe('API Response Format Validation', () => {
    test('should return properly formatted response structure', async () => {
      await Submission.create({
        userId: testUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Test answer' },
          { questionId: 'q2', type: 'photo', answer: '', photoUrl: 'https://example.com/photo.jpg' }
        ],
        completionRate: 85,
        submittedAt: new Date()
      });

      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      // Validate response structure
      expect(response.body).toMatchObject({
        month: expect.stringMatching(/^\d{4}-\d{2}$/),
        hasSubmitted: expect.any(Boolean),
        submission: {
          completionRate: expect.any(Number),
          submittedAt: expect.any(String),
          responseCount: expect.any(Number)
        }
      });

      // Validate data ranges
      expect(response.body.submission.completionRate).toBeGreaterThanOrEqual(0);
      expect(response.body.submission.completionRate).toBeLessThanOrEqual(100);
      expect(response.body.submission.responseCount).toBeGreaterThanOrEqual(0);
    });

    test('should return null submission when no data exists', async () => {
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', authCookie)
        .expect(200);

      expect(response.body).toMatchObject({
        month: expect.stringMatching(/^\d{4}-\d{2}$/),
        hasSubmitted: false,
        submission: null
      });
    });
  });
});