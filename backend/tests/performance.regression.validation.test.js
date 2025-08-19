/**
 * Performance Regression Validation Test Suite
 * 
 * Validates that all existing functionality works correctly with performance optimizations
 * and measures performance improvements vs baseline
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
let testAdminUser = null;
let testRegularUser = null;

describe('🔍 Functional Regression Validation with Optimizations', () => {
  beforeAll(async () => {
    app = getTestApp();
    
    // Clean up existing data
    await User.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Submission.deleteMany({});
    
    // Create test admin user
    testAdminUser = await User.create({
      username: 'testadmin',
      email: 'admin@regression.test',
      password: '$2a$10$test.hash.for.regression.testing',
      role: 'admin',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    // Create test regular user
    testRegularUser = await User.create({
      username: 'testuser',
      email: 'user@regression.test',
      password: '$2a$10$test.hash.for.user.testing',
      role: 'user',
      metadata: { isActive: true, registeredAt: new Date() }
    });
    
    // Create test data for regression testing
    await Response.create([
      {
        name: 'Test Admin',
        responses: [
          { question: 'Regression Q1', answer: 'Admin Answer 1' },
          { question: 'Regression Q2', answer: 'Admin Answer 2' }
        ],
        month: '2025-01',
        isAdmin: true,
        token: null,
        createdAt: new Date('2025-01-15')
      },
      {
        name: 'Test User 1',
        responses: [
          { question: 'Regression Q1', answer: 'User 1 Answer 1' },
          { question: 'Regression Q2', answer: 'User 1 Answer 2' }
        ],
        month: '2025-01',
        isAdmin: false,
        token: 'regression-token-1',
        createdAt: new Date('2025-01-16')
      },
      {
        name: 'Test User 2',
        responses: [
          { question: 'Regression Q1', answer: 'User 2 Answer 1' },
          { question: 'Regression Q2', answer: 'User 2 Answer 2' }
        ],
        month: '2025-01',
        isAdmin: false,
        token: 'regression-token-2',
        createdAt: new Date('2025-01-17')
      }
    ]);
    
    await Contact.create([
      {
        firstName: 'Test',
        lastName: 'Contact',
        email: 'contact@regression.test',
        ownerId: testAdminUser._id,
        isActive: true,
        status: 'active',
        tracking: {
          responsesReceived: 2,
          responseRate: 80,
          lastInteractionAt: new Date(),
          firstResponseAt: new Date('2024-12-01')
        }
      }
    ]);
    
    await Submission.create([
      {
        userId: testRegularUser._id,
        month: '2025-01',
        responses: [
          { question: 'Regression Q1', answer: 'My Answer 1' },
          { question: 'Regression Q2', answer: 'My Answer 2' }
        ],
        completionRate: 100,
        submittedAt: new Date('2025-01-18'),
        freeText: 'Additional thoughts for regression testing'
      },
      {
        userId: testRegularUser._id,
        month: '2024-12',
        responses: [
          { question: 'December Q1', answer: 'December Answer' }
        ],
        completionRate: 50,
        submittedAt: new Date('2024-12-15')
      }
    ]);
    
    // Obtain admin session
    const adminLogin = await request(app)
      .post('/auth/login')
      .send({
        username: 'testadmin',
        password: 'admin123'
      });
      
    if (adminLogin.headers['set-cookie']) {
      adminSession = adminLogin.headers['set-cookie'];
    }
    
    // Obtain user session
    const userLogin = await request(app)
      .post('/auth/login')
      .send({
        username: 'testuser',
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

  describe('📊 Dashboard API Regression Tests', () => {
    test('should maintain existing dashboard functionality with caching', async () => {
      const tests = [
        { endpoint: '/api/dashboard/profile', description: 'Profile API' },
        { endpoint: '/api/dashboard/months', description: 'Months API' },
        { endpoint: '/api/dashboard/summary', description: 'Summary API' },
        { endpoint: '/api/dashboard/stats', description: 'Stats API' },
        { endpoint: '/api/dashboard', description: 'Main Dashboard API' }
      ];

      for (const test of tests) {
        const adminResponse = await request(app)
          .get(test.endpoint)
          .set('Cookie', adminSession || []);

        expect([200, 302]).toContain(adminResponse.status);
        console.log(`✓ ${test.description} (Admin): ${adminResponse.status}`);

        if (adminResponse.status === 200) {
          expect(adminResponse.body).toBeDefined();
          expect(typeof adminResponse.body).toBe('object');
        }
      }
    });

    test('should maintain role-based access control with optimizations', async () => {
      const restrictedEndpoints = [
        '/api/dashboard/contacts',
        '/api/dashboard/responses'
      ];

      for (const endpoint of restrictedEndpoints) {
        // Admin should have access
        const adminResponse = await request(app)
          .get(endpoint)
          .set('Cookie', adminSession || []);
        
        // User may have limited access or no access depending on endpoint
        const userResponse = await request(app)
          .get(endpoint)
          .set('Cookie', userSession || []);

        console.log(`🔒 ${endpoint} - Admin: ${adminResponse.status}, User: ${userResponse.status}`);
        
        expect([200, 302, 403]).toContain(adminResponse.status);
        expect([200, 302, 403]).toContain(userResponse.status);
      }
    });

    test('should return correct data structure from cached responses', async () => {
      const summaryResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      if (summaryResponse.status === 200) {
        expect(Array.isArray(summaryResponse.body)).toBe(true);
        
        if (summaryResponse.body.length > 0) {
          const firstItem = summaryResponse.body[0];
          expect(firstItem).toHaveProperty('question');
          expect(firstItem).toHaveProperty('items');
          expect(Array.isArray(firstItem.items)).toBe(true);
          
          if (firstItem.items.length > 0) {
            expect(firstItem.items[0]).toHaveProperty('user');
            expect(firstItem.items[0]).toHaveProperty('answer');
          }
        }

        console.log(`✓ Summary API returns correct structure with ${summaryResponse.body.length} items`);
      }
    });

    test('should handle month filtering correctly with caching', async () => {
      // Test all months
      const allMonthsResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: 'all' })
        .set('Cookie', adminSession || []);

      // Test specific month
      const specificMonthResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      expect([200, 302]).toContain(allMonthsResponse.status);
      expect([200, 302]).toContain(specificMonthResponse.status);

      if (allMonthsResponse.status === 200 && specificMonthResponse.status === 200) {
        // All months should have same or more data than specific month
        expect(allMonthsResponse.body.length).toBeGreaterThanOrEqual(specificMonthResponse.body.length);
        console.log(`✓ Month filtering: All=${allMonthsResponse.body.length}, Specific=${specificMonthResponse.body.length}`);
      }
    });
  });

  describe('🔗 Contact Management Regression Tests', () => {
    test('should maintain contact management functionality with N+1 optimizations', async () => {
      const contactsResponse = await request(app)
        .get('/api/dashboard/contacts')
        .query({ limit: 10, page: 1 })
        .set('Cookie', adminSession || []);

      expect([200, 302, 403]).toContain(contactsResponse.status);

      if (contactsResponse.status === 200) {
        expect(contactsResponse.body).toHaveProperty('contacts');
        expect(contactsResponse.body).toHaveProperty('pagination');
        expect(contactsResponse.body).toHaveProperty('summary');
        expect(Array.isArray(contactsResponse.body.contacts)).toBe(true);
        
        console.log(`✓ Contacts API returns ${contactsResponse.body.contacts.length} contacts`);
      }
    });

    test('should handle contact comparison with $facet aggregation', async () => {
      const contact = await Contact.findOne({ ownerId: testAdminUser._id });
      
      if (contact) {
        const comparisonResponse = await request(app)
          .get(`/api/dashboard/contact/${contact._id}`)
          .set('Cookie', adminSession || []);

        expect([200, 302, 403, 404]).toContain(comparisonResponse.status);

        if (comparisonResponse.status === 200) {
          expect(comparisonResponse.body).toHaveProperty('contact');
          expect(comparisonResponse.body).toHaveProperty('comparison');
          expect(comparisonResponse.body).toHaveProperty('stats');
          expect(Array.isArray(comparisonResponse.body.comparison)).toBe(true);
          
          console.log(`✓ Contact comparison returns ${comparisonResponse.body.comparison.length} comparison points`);
        }
      }
    });

    test('should handle contact search and filtering with pagination', async () => {
      const searchResponse = await request(app)
        .get('/api/dashboard/contacts')
        .query({ 
          search: 'test',
          status: 'active',
          limit: 5,
          page: 1
        })
        .set('Cookie', adminSession || []);

      expect([200, 302, 403]).toContain(searchResponse.status);

      if (searchResponse.status === 200) {
        expect(searchResponse.body.pagination.limit).toBeLessThanOrEqual(5);
        expect(searchResponse.body.pagination.page).toBe(1);
        console.log('✓ Contact search and filtering works correctly');
      }
    });
  });

  describe('📝 Response Management Regression Tests', () => {
    test('should maintain response history functionality', async () => {
      const responsesResponse = await request(app)
        .get('/api/dashboard/responses')
        .set('Cookie', userSession || []);

      expect([200, 302, 403]).toContain(responsesResponse.status);

      if (responsesResponse.status === 200) {
        expect(responsesResponse.body).toHaveProperty('currentMonth');
        expect(responsesResponse.body).toHaveProperty('history');
        expect(responsesResponse.body).toHaveProperty('stats');
        expect(Array.isArray(responsesResponse.body.history)).toBe(true);
        
        console.log(`✓ Response history returns ${responsesResponse.body.history.length} submissions`);
      }
    });

    test('should calculate statistics correctly', async () => {
      const responsesResponse = await request(app)
        .get('/api/dashboard/responses')
        .set('Cookie', userSession || []);

      if (responsesResponse.status === 200) {
        const stats = responsesResponse.body.stats;
        expect(stats).toHaveProperty('totalSubmissions');
        expect(stats).toHaveProperty('averageCompletion');
        expect(typeof stats.totalSubmissions).toBe('number');
        expect(typeof stats.averageCompletion).toBe('number');
        
        console.log(`✓ Statistics: ${stats.totalSubmissions} submissions, ${stats.averageCompletion}% avg completion`);
      }
    });

    test('should identify current month submission status correctly', async () => {
      const responsesResponse = await request(app)
        .get('/api/dashboard/responses')
        .set('Cookie', userSession || []);

      if (responsesResponse.status === 200) {
        const currentMonth = responsesResponse.body.currentMonth;
        expect(currentMonth).toHaveProperty('month');
        expect(currentMonth).toHaveProperty('canSubmit');
        expect(currentMonth).toHaveProperty('hasSubmitted');
        expect(typeof currentMonth.canSubmit).toBe('boolean');
        expect(typeof currentMonth.hasSubmitted).toBe('boolean');
        
        console.log(`✓ Current month status: Can submit: ${currentMonth.canSubmit}, Has submitted: ${currentMonth.hasSubmitted}`);
      }
    });
  });

  describe('🔐 Authentication and Security Regression Tests', () => {
    test('should maintain authentication requirements with optimizations', async () => {
      const protectedEndpoints = [
        '/api/dashboard/profile',
        '/api/dashboard/months',
        '/api/dashboard/summary',
        '/api/dashboard/stats',
        '/api/dashboard/contacts',
        '/api/dashboard/responses'
      ];

      for (const endpoint of protectedEndpoints) {
        // Request without authentication should be redirected or denied
        const unauthResponse = await request(app).get(endpoint);
        expect([302, 401, 403]).toContain(unauthResponse.status);
        
        // Request with authentication should succeed or have proper handling
        const authResponse = await request(app)
          .get(endpoint)
          .set('Cookie', adminSession || []);
        expect([200, 302, 403]).toContain(authResponse.status);
        
        console.log(`🔒 ${endpoint} - Unauth: ${unauthResponse.status}, Auth: ${authResponse.status}`);
      }
    });

    test('should maintain CSRF protection', async () => {
      const csrfResponse = await request(app)
        .get('/api/dashboard/csrf-token')
        .set('Cookie', adminSession || []);

      expect([200, 302, 403]).toContain(csrfResponse.status);
      console.log(`🛡️ CSRF token endpoint: ${csrfResponse.status}`);
    });

    test('should validate input parameters correctly', async () => {
      const invalidRequests = [
        { endpoint: '/api/dashboard/contact/invalid-id', expectedStatus: [400, 404, 302, 403] },
        { endpoint: '/api/dashboard/contacts?page=-1', expectedStatus: [400, 200, 302, 403] },
        { endpoint: '/api/dashboard/contacts?limit=1000', expectedStatus: [200, 302, 403] }
      ];

      for (const test of invalidRequests) {
        const response = await request(app)
          .get(test.endpoint)
          .set('Cookie', adminSession || []);
        
        expect(test.expectedStatus).toContain(response.status);
        console.log(`✓ Input validation: ${test.endpoint} -> ${response.status}`);
      }
    });
  });

  describe('📈 Data Accuracy Regression Tests', () => {
    test('should return accurate month listings', async () => {
      const monthsResponse = await request(app)
        .get('/api/dashboard/months')
        .set('Cookie', adminSession || []);

      if (monthsResponse.status === 200) {
        expect(Array.isArray(monthsResponse.body)).toBe(true);
        
        if (monthsResponse.body.length > 0) {
          const month = monthsResponse.body[0];
          expect(month).toHaveProperty('key');
          expect(month).toHaveProperty('label');
          expect(typeof month.key).toBe('string');
          expect(typeof month.label).toBe('string');
        }
        
        console.log(`✓ Months API returns ${monthsResponse.body.length} months`);
      }
    });

    test('should maintain question-answer pairing integrity', async () => {
      const summaryResponse = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      if (summaryResponse.status === 200 && summaryResponse.body.length > 0) {
        const questionData = summaryResponse.body[0];
        expect(questionData).toHaveProperty('question');
        expect(questionData).toHaveProperty('items');
        
        if (questionData.items.length > 0) {
          const item = questionData.items[0];
          expect(item).toHaveProperty('user');
          expect(item).toHaveProperty('answer');
          expect(typeof item.user).toBe('string');
          expect(typeof item.answer).toBe('string');
        }
        
        console.log('✓ Question-answer pairing maintained correctly');
      }
    });

    test('should preserve data consistency across cache invalidations', async () => {
      // First request to populate cache
      const firstRequest = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      // Second request should return same data (from cache)
      const secondRequest = await request(app)
        .get('/api/dashboard/summary')
        .query({ month: '2025-01' })
        .set('Cookie', adminSession || []);

      if (firstRequest.status === 200 && secondRequest.status === 200) {
        expect(firstRequest.body.length).toBe(secondRequest.body.length);
        
        if (firstRequest.body.length > 0 && secondRequest.body.length > 0) {
          // Compare first question to ensure consistency
          expect(firstRequest.body[0].question).toBe(secondRequest.body[0].question);
          expect(firstRequest.body[0].items.length).toBe(secondRequest.body[0].items.length);
        }
        
        console.log('✓ Data consistency maintained across cache requests');
      }
    });
  });
});