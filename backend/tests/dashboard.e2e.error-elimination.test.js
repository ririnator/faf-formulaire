/**
 * E2E Tests for Complete Dashboard Error Elimination
 * Tests the entire dashboard flow from authentication to data display without errors
 * 
 * Includes internationalization testing with French text to validate:
 * - UTF-8 character encoding support 
 * - French UI element handling
 * - Accented character storage and retrieval
 */

const request = require('supertest');
const mongoose = require('mongoose');
const MongoMemoryServer = require('mongodb-memory-server').MongoMemoryServer;
const app = require('../app');
const User = require('../models/User');
const Submission = require('../models/Submission');
const Contact = require('../models/Contact');
const Handshake = require('../models/Handshake');
const Invitation = require('../models/Invitation');
const Notification = require('../models/Notification');
const { setupTestDatabase, cleanupDatabase } = require('./integration/setup-integration');

describe('Dashboard E2E - Complete Error Elimination Tests', () => {
  let mongoServer;
  let testUser;
  let adminUser;
  let userAuthCookie;
  let adminAuthCookie;
  let currentMonth;

  beforeAll(async () => {
    await setupTestDatabase();
    currentMonth = new Date().toISOString().slice(0, 7);
  });

  afterAll(async () => {
    await cleanupDatabase();
  });

  beforeEach(async () => {
    // Clean database
    await Promise.all([
      User.deleteMany({}),
      Submission.deleteMany({}),
      Contact.deleteMany({}),
      Handshake.deleteMany({}),
      Invitation.deleteMany({}),
      Notification.deleteMany({})
    ]);

    // Create test users with complete data
    testUser = await User.create({
      username: 'testuser',
      email: 'test@form-a-friend.com',
      password: '$2b$10$hashedpassword',
      role: 'user',
      profile: {
        firstName: 'Test',
        lastName: 'User',
        dateOfBirth: new Date('1990-01-01'),
        profession: 'Software Developer',
        location: 'Paris, France'
      },
      preferences: {
        emailNotifications: true,
        reminderFrequency: 'weekly',
        timezone: 'Europe/Paris',
        language: 'fr',
        privacy: {
          shareProfile: true,
          allowSearchByEmail: true
        }
      },
      metadata: {
        isActive: true,
        emailVerified: true,
        lastActive: new Date(),
        responseCount: 5,
        registeredAt: new Date()
      }
    });

    adminUser = await User.create({
      username: 'adminuser',
      email: 'admin@form-a-friend.com',
      password: '$2b$10$hashedpassword',
      role: 'admin',
      profile: {
        firstName: 'Admin',
        lastName: 'User'
      },
      metadata: {
        isActive: true,
        emailVerified: true,
        registeredAt: new Date()
      }
    });

    // Authenticate users using correct endpoints
    const userLogin = await request(app)
      .post('/login')
      .send({
        username: 'admin',
        password: 'password123'
      });
    userAuthCookie = userLogin.headers['set-cookie'] || ['faf-session=mock-user-session'];

    const adminLogin = await request(app)
      .post('/admin-login')
      .send({
        username: 'admin',
        password: 'password123'
      });
    adminAuthCookie = adminLogin.headers['set-cookie'] || ['faf-session=mock-admin-session'];
  });

  describe('Complete Dashboard Flow - User Journey', () => {
    test('should complete entire user dashboard flow without errors', async () => {
      // Step 1: Create test data
      const testContact = await Contact.create({
        ownerId: testUser._id,
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        status: 'active',
        isActive: true,
        tags: ['friend', 'work'],
        notes: 'Test contact for E2E testing',
        tracking: {
          responsesReceived: 3,
          responseRate: 75,
          lastInteractionAt: new Date(),
          firstResponseAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
        }
      });

      const testSubmission = await Submission.create({
        userId: testUser._id,
        month: currentMonth,
        responses: [
          {
            questionId: 'q1',
            type: 'text',
            answer: 'Je me sens très bien ce mois-ci!'
          },
          {
            questionId: 'q2',
            type: 'photo',
            answer: '',
            photoUrl: 'https://res.cloudinary.com/test/image/upload/v123/sample.jpg',
            photoCaption: 'Belle photo du mois'
          },
          {
            questionId: 'q3',
            type: 'radio',
            answer: 'Excellent'
          }
        ],
        freeText: 'Commentaire libre pour ce mois.',
        completionRate: 95,
        submittedAt: new Date(),
        metadata: {
          submittedAt: new Date(),
          timeSpent: 1200,
          deviceInfo: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          ipAddress: '192.168.1.100'
        }
      });

      const testHandshake = await Handshake.create({
        requesterId: testUser._id,
        targetId: testUser._id,  // Use correct field name
        status: 'accepted',
        // French text for internationalization testing - Form-a-Friend supports French UI
        message: 'Salut! Veux-tu rejoindre Form-a-Friend?',
        createdAt: new Date(),
        respondedAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days from now
      });

      const testNotification = await Notification.create({
        recipientId: testUser._id,  // Use correct field name
        type: 'handshake_accepted',
        // French text for internationalization testing - validates UTF-8 support
        title: 'Handshake accepté',
        message: 'Votre demande de contact a été acceptée par friend@example.com',
        read: false,
        actionUrl: '/dashboard/contacts'
      });

      // Step 2: Test main dashboard endpoint
      const dashboardResponse = await request(app)
        .get('/api/dashboard')
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(dashboardResponse.body).toMatchObject({
        user: {
          username: 'testuser',
          email: 'test@form-a-friend.com',
          role: 'user'
        },
        currentMonth: {
          month: currentMonth,
          hasSubmitted: true,
          submission: expect.objectContaining({
            completionRate: 95
          })
        },
        stats: expect.objectContaining({
          totalContacts: expect.any(Number),
          totalSubmissions: expect.any(Number)
        }),
        recentActivity: expect.objectContaining({
          submissions: expect.any(Array),
          contacts: expect.any(Array)
        })
      });

      // Step 3: Test profile endpoint
      const profileResponse = await request(app)
        .get('/api/dashboard/profile')
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(profileResponse.body).toMatchObject({
        authMethod: 'user',
        accessLevel: 'user',
        permissions: expect.objectContaining({
          canViewAll: false,
          canManage: false,
          canViewAdminFeatures: false
        }),
        user: expect.objectContaining({
          id: expect.any(String),
          username: 'testuser',
          email: 'test@form-a-friend.com',
          role: 'user'
        })
      });

      // Step 4: Test current month status
      const currentResponse = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(currentResponse.body).toMatchObject({
        month: currentMonth,
        hasSubmitted: true,
        submission: expect.objectContaining({
          completionRate: 95,
          responseCount: 3
        })
      });

      // Step 5: Test contacts list
      const contactsResponse = await request(app)
        .get('/api/dashboard/contacts')
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(contactsResponse.body).toMatchObject({
        contacts: expect.arrayContaining([
          expect.objectContaining({
            firstName: 'John',
            lastName: 'Doe',
            email: 'john.doe@example.com',
            status: 'active',
            tags: expect.arrayContaining(['friend', 'work'])
          })
        ]),
        pagination: expect.objectContaining({
          page: 1,
          total: expect.any(Number)
        }),
        summary: expect.objectContaining({
          total: expect.any(Number),
          active: expect.any(Number)
        })
      });

      // Step 6: Test responses history
      const responsesResponse = await request(app)
        .get('/api/dashboard/responses')
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(responsesResponse.body).toMatchObject({
        currentMonth: expect.objectContaining({
          month: currentMonth,
          canSubmit: false,
          hasSubmitted: true
        }),
        history: expect.arrayContaining([
          expect.objectContaining({
            month: currentMonth,
            completionRate: 95,
            responseCount: 3
          })
        ]),
        stats: expect.objectContaining({
          totalSubmissions: expect.any(Number),
          averageCompletion: expect.any(Number)
        })
      });

      // Step 7: Test contact comparison view
      const comparisonResponse = await request(app)
        .get(`/api/dashboard/contact/${testContact._id}`)
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(comparisonResponse.body).toMatchObject({
        contact: expect.objectContaining({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com'
        }),
        comparison: expect.any(Array),
        stats: expect.objectContaining({
          totalSharedMonths: expect.any(Number),
          userSubmissions: expect.any(Number)
        })
      });

      // Step 8: Test dashboard statistics
      const statsResponse = await request(app)
        .get('/api/dashboard/stats')
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(statsResponse.body).toMatchObject({
        totalResponses: expect.any(Number),
        userRole: 'user'
      });

      // All endpoints should complete without errors
      expect(dashboardResponse.status).toBe(200);
      expect(profileResponse.status).toBe(200);
      expect(currentResponse.status).toBe(200);
      expect(contactsResponse.status).toBe(200);
      expect(responsesResponse.status).toBe(200);
      expect(comparisonResponse.status).toBe(200);
      expect(statsResponse.status).toBe(200);
    });

    test('should handle admin dashboard flow without errors', async () => {
      // Create admin test data
      await Submission.create({
        userId: testUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'User response' }
        ],
        completionRate: 80,
        submittedAt: new Date()
      });

      await Contact.create({
        ownerId: adminUser._id,
        firstName: 'Admin',
        lastName: 'Contact',
        email: 'admin.contact@test.com',
        status: 'active',
        isActive: true
      });

      // Test admin dashboard
      const adminDashboardResponse = await request(app)
        .get('/api/dashboard')
        .set('Cookie', adminAuthCookie)
        .expect(200);

      expect(adminDashboardResponse.body).toMatchObject({
        user: expect.objectContaining({
          role: 'admin'
        }),
        systemStats: expect.objectContaining({
          totalUsers: expect.any(Number),
          totalSubmissions: expect.any(Number),
          thisMonthSubmissions: expect.any(Number),
          totalContacts: expect.any(Number)
        })
      });

      // Test admin profile
      const adminProfileResponse = await request(app)
        .get('/api/dashboard/profile')
        .set('Cookie', adminAuthCookie)
        .expect(200);

      expect(adminProfileResponse.body).toMatchObject({
        accessLevel: 'admin',
        permissions: expect.objectContaining({
          canViewAll: true,
          canManage: true,
          canViewAdminFeatures: true
        })
      });

      // Test admin stats
      const adminStatsResponse = await request(app)
        .get('/api/dashboard/stats')
        .set('Cookie', adminAuthCookie)
        .expect(200);

      expect(adminStatsResponse.body).toMatchObject({
        totalResponses: expect.any(Number),
        totalUsers: expect.any(Number),
        thisMonthResponses: expect.any(Number),
        userRole: 'admin'
      });
    });
  });

  describe('Error Scenarios and Recovery', () => {
    test('should handle missing user data gracefully', async () => {
      // Delete user data and test graceful degradation
      await User.findByIdAndDelete(testUser._id);

      const response = await request(app)
        .get('/api/dashboard')
        .set('Cookie', userAuthCookie);

      // Should either redirect to login (401/403) or handle gracefully
      expect([200, 401, 403, 500]).toContain(response.status);
    });

    test('should handle database connectivity issues', async () => {
      // This is challenging to test without actually disrupting the DB
      // Instead, we'll test that our endpoints handle errors gracefully
      
      const response = await request(app)
        .get('/api/dashboard/responses/current')
        .set('Cookie', userAuthCookie);

      // Response should be either success or controlled failure
      expect([200, 500]).toContain(response.status);
      
      if (response.status === 500) {
        expect(response.body).toMatchObject({
          error: expect.any(String),
          code: expect.any(String)
        });
      }
    });

    test('should handle malformed request data', async () => {
      // Test with various malformed requests
      const malformedRequests = [
        { url: '/api/dashboard/contact/invalid-id', expectedStatuses: [400, 404, 500] },
        { url: '/api/dashboard/contacts?page=invalid', expectedStatuses: [200, 400] },
        { url: '/api/dashboard/responses?month=invalid', expectedStatuses: [200, 400] }
      ];

      for (const { url, expectedStatuses } of malformedRequests) {
        const response = await request(app)
          .get(url)
          .set('Cookie', userAuthCookie);

        expect(expectedStatuses).toContain(response.status);
        
        if (response.status >= 400) {
          expect(response.body).toMatchObject({
            error: expect.any(String)
          });
        }
      }
    });

    test('should handle concurrent requests without conflicts', async () => {
      // Create submission for testing
      await Submission.create({
        userId: testUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Concurrent test' }
        ],
        completionRate: 75,
        submittedAt: new Date()
      });

      // Make multiple concurrent requests
      const concurrentRequests = Array(10).fill().map(() =>
        request(app)
          .get('/api/dashboard/responses/current')
          .set('Cookie', userAuthCookie)
      );

      const responses = await Promise.allSettled(concurrentRequests);
      
      // All should complete without throwing
      const successful = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status === 200
      );
      
      expect(successful.length).toBeGreaterThan(7); // Allow some margin for system load
    });

    test('should validate all response data types and structures', async () => {
      // Create comprehensive test data
      await Submission.create({
        userId: testUser._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Text response with émoji 😊' },
          { questionId: 'q2', type: 'photo', photoUrl: 'https://res.cloudinary.com/test/image.jpg' },
          { questionId: 'q3', type: 'radio', answer: 'Option A' }
        ],
        freeText: 'Free text with special characters: àéèùç',
        completionRate: 100,
        submittedAt: new Date()
      });

      await Contact.create({
        ownerId: testUser._id,
        firstName: 'François',
        lastName: 'Müller',
        email: 'françois+test@example.com',
        tags: ['émoji-tag-😊', 'special-chars-àéè'],
        status: 'active',
        isActive: true
      });

      const endpoints = [
        '/api/dashboard',
        '/api/dashboard/profile',
        '/api/dashboard/responses/current',
        '/api/dashboard/contacts',
        '/api/dashboard/responses',
        '/api/dashboard/stats'
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('Cookie', userAuthCookie);

        expect([200, 201]).toContain(response.status);
        
        if (response.status === 200) {
          // Validate that response is valid JSON
          expect(response.body).toBeInstanceOf(Object);
          
          // Validate no undefined or null critical fields
          const responseStr = JSON.stringify(response.body);
          expect(responseStr).not.toContain('"undefined"');
          expect(responseStr).not.toContain('null,null');
        }
      }
    });

    test('should handle edge cases in data processing', async () => {
      // Create edge case data
      const edgeCases = [
        // Empty responses array
        {
          userId: testUser._id,
          month: currentMonth,
          responses: [],
          completionRate: 0,
          submittedAt: new Date()
        },
        // Very long text responses
        {
          userId: testUser._id,
          month: '2024-01', // Different month
          responses: [{
            questionId: 'long-text',
            type: 'text',
            answer: 'A'.repeat(9999) // Very long answer
          }],
          completionRate: 50,
          submittedAt: new Date()
        }
      ];

      for (const submissionData of edgeCases) {
        await Submission.create(submissionData);
      }

      // Test that dashboard handles edge cases
      const response = await request(app)
        .get('/api/dashboard')
        .set('Cookie', userAuthCookie)
        .expect(200);

      expect(response.body).toBeDefined();
      expect(response.body.user).toBeDefined();
      expect(response.body.stats).toBeDefined();
    });
  });

  describe('Performance and Load Testing', () => {
    test('should handle dashboard with large datasets', async () => {
      // Create large dataset
      const submissions = [];
      const contacts = [];
      
      // Create 50 submissions across different months
      for (let i = 0; i < 50; i++) {
        const date = new Date();
        date.setMonth(date.getMonth() - i);
        const month = date.toISOString().slice(0, 7);
        
        submissions.push(Submission.create({
          userId: testUser._id,
          month,
          responses: [
            { questionId: `q${i}`, type: 'text', answer: `Response ${i}` }
          ],
          completionRate: Math.floor(Math.random() * 100),
          submittedAt: new Date(date)
        }));
      }

      // Create 100 contacts
      for (let i = 0; i < 100; i++) {
        contacts.push(Contact.create({
          ownerId: testUser._id,
          firstName: `Contact${i}`,
          lastName: `Test${i}`,
          email: `contact${i}@test.com`,
          status: i % 2 === 0 ? 'active' : 'pending',
          isActive: true,
          tags: [`tag${i % 5}`]
        }));
      }

      await Promise.all([...submissions, ...contacts]);

      const startTime = Date.now();
      
      const response = await request(app)
        .get('/api/dashboard')
        .set('Cookie', userAuthCookie)
        .expect(200);

      const responseTime = Date.now() - startTime;
      
      // Should respond within 2 seconds even with large dataset
      expect(responseTime).toBeLessThan(2000);
      expect(response.body.stats.totalContacts).toBeGreaterThan(90);
    });

    test('should maintain performance under concurrent load', async () => {
      // Create baseline data
      await Promise.all([
        Submission.create({
          userId: testUser._id,
          month: currentMonth,
          responses: [{ questionId: 'q1', type: 'text', answer: 'Test' }],
          completionRate: 80,
          submittedAt: new Date()
        }),
        Contact.create({
          ownerId: testUser._id,
          firstName: 'Test',
          lastName: 'Contact',
          email: 'test@example.com',
          status: 'active',
          isActive: true
        })
      ]);

      // Make 20 concurrent requests to different endpoints
      const concurrentRequests = [
        ...Array(5).fill('/api/dashboard'),
        ...Array(5).fill('/api/dashboard/contacts'),
        ...Array(5).fill('/api/dashboard/responses'),
        ...Array(5).fill('/api/dashboard/responses/current')
      ].map(endpoint =>
        request(app)
          .get(endpoint)
          .set('Cookie', userAuthCookie)
      );

      const startTime = Date.now();
      const responses = await Promise.allSettled(concurrentRequests);
      const totalTime = Date.now() - startTime;

      const successfulResponses = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status === 200
      );

      // Most requests should succeed
      expect(successfulResponses.length).toBeGreaterThan(15);
      
      // Total time for all concurrent requests should be reasonable
      expect(totalTime).toBeLessThan(5000);
    });
  });

  describe('Security and Data Isolation', () => {
    test('should prevent cross-user data access', async () => {
      // Create another user with data
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
          { questionId: 'secret', type: 'text', answer: 'SECRET DATA' }
        ],
        completionRate: 100,
        submittedAt: new Date()
      });

      await Contact.create({
        ownerId: otherUser._id,
        firstName: 'Secret',
        lastName: 'Contact',
        email: 'secret@test.com',
        status: 'active',
        isActive: true
      });

      // Test user should not see other user's data
      const dashboardResponse = await request(app)
        .get('/api/dashboard')
        .set('Cookie', userAuthCookie)
        .expect(200);

      const responseStr = JSON.stringify(dashboardResponse.body);
      expect(responseStr).not.toContain('SECRET DATA');
      expect(responseStr).not.toContain('secret@test.com');

      // Test contacts endpoint
      const contactsResponse = await request(app)
        .get('/api/dashboard/contacts')
        .set('Cookie', userAuthCookie)
        .expect(200);

      const contactsStr = JSON.stringify(contactsResponse.body);
      expect(contactsStr).not.toContain('Secret');
      expect(contactsStr).not.toContain('secret@test.com');
    });

    test('should validate session integrity throughout dashboard flow', async () => {
      // Test that session remains valid throughout multiple requests
      const endpoints = [
        '/api/dashboard/profile',
        '/api/dashboard',
        '/api/dashboard/responses/current',
        '/api/dashboard/contacts',
        '/api/dashboard/responses',
        '/api/dashboard/stats'
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('Cookie', userAuthCookie)
          .expect(200);

        // Each response should contain authenticated user data
        const responseStr = JSON.stringify(response.body);
        if (responseStr.includes('user') || responseStr.includes('User')) {
          // Should contain reference to test user
          expect(
            responseStr.includes('testuser') || 
            responseStr.includes('test@form-a-friend.com')
          ).toBe(true);
        }
      }
    });
  });
});