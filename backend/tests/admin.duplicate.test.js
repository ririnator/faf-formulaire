const request = require('supertest');
const Response = require('../models/Response');
const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

describe('Admin Duplicate Submission Scenarios', () => {
  beforeAll(async () => {
    process.env.FORM_ADMIN_NAME = 'admin';
    app = getTestApp();
  });

  beforeEach(async () => {
    await Response.deleteMany({});
  });

  describe('Admin Duplicate Prevention', () => {
    test('should allow first admin submission for a month', async () => {
      const adminData = {
        name: 'admin', // Matches FORM_ADMIN_NAME
        responses: [
          {
            question: 'How are things going?',
            answer: 'All good on the admin side!'
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(adminData)
        .expect(201);

      expect(response.body.message).toBe('Réponse enregistrée avec succès !');
      expect(response.body.link).toBeNull(); // Admin should not get a link

      // Verify in database
      const savedResponse = await Response.findOne({ name: 'admin' });
      expect(savedResponse).toBeTruthy();
      expect(savedResponse.isAdmin).toBe(true);
      expect(savedResponse.token).toBeNull();
    });

    test('should reject duplicate admin submission for same month', async () => {
      // First admin submission
      const adminData = {
        name: 'admin',
        responses: [
          {
            question: 'First question',
            answer: 'First answer'
          }
        ]
      };

      await request(app)
        .post('/api/response')
        .send(adminData)
        .expect(201);

      // Second admin submission (should fail)
      const duplicateAdminData = {
        name: 'admin',
        responses: [
          {
            question: 'Second question',
            answer: 'Second answer'
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(duplicateAdminData)
        .expect(409);

      expect(response.body.message).toBe('Une réponse admin existe déjà pour ce mois.');

      // Verify only one admin response exists
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(1);
      expect(adminResponses[0].responses[0].question).toBe('First question');
    });

    test('should handle case-insensitive admin name detection', async () => {
      const variations = ['ADMIN', 'Admin', 'aDmIn', 'admin'];

      // First submission should succeed
      const firstResponse = await request(app)
        .post('/api/response')
        .send({
          name: variations[0],
          responses: [{ question: 'Test', answer: 'Test' }]
        })
        .expect(201);

      expect(firstResponse.body.link).toBeNull(); // Should be admin

      // All subsequent variations should fail
      for (let i = 1; i < variations.length; i++) {
        await request(app)
          .post('/api/response')
          .send({
            name: variations[i],
            responses: [{ question: `Test ${i}`, answer: `Test ${i}` }]
          })
          .expect(409);
      }

      // Verify only one admin response exists
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(1);
    });

    test('should allow regular users even when admin exists', async () => {
      // First, create admin response
      await request(app)
        .post('/api/response')
        .send({
          name: 'admin',
          responses: [{ question: 'Admin question', answer: 'Admin answer' }]
        })
        .expect(201);

      // Regular user should still be able to submit
      const userResponse = await request(app)
        .post('/api/response')
        .send({
          name: 'John Doe',
          responses: [{ question: 'User question', answer: 'User answer' }]
        })
        .expect(201);

      expect(userResponse.body.link).toBeTruthy(); // User should get a link

      // Verify both responses exist
      const allResponses = await Response.find({});
      expect(allResponses).toHaveLength(2);
      
      const adminResponse = allResponses.find(r => r.isAdmin);
      const regularResponse = allResponses.find(r => !r.isAdmin);
      
      expect(adminResponse).toBeTruthy();
      expect(regularResponse).toBeTruthy();
      expect(regularResponse.token).toBeTruthy();
    });

    test('should allow admin submission in different months', async () => {
      // Create first admin response with explicit month
      const firstAdmin = new Response({
        name: 'admin',
        responses: [{ question: 'January question', answer: 'January answer' }],
        month: '2023-01',
        isAdmin: true,
        authMethod: 'token'
        // Note: omitting token field to avoid unique constraint conflict
      });
      await firstAdmin.save();

      // Create second admin response with different month
      const secondAdmin = new Response({
        name: 'admin',
        responses: [{ question: 'February question', answer: 'February answer' }],
        month: '2023-02',
        isAdmin: true,
        authMethod: 'token'
        // Note: omitting token field to avoid unique constraint conflict
      });
      await secondAdmin.save();

      // Verify both admin responses exist with different months
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(2);
      expect(adminResponses[0].month).not.toBe(adminResponses[1].month);
      expect(adminResponses.map(r => r.month).sort()).toEqual(['2023-01', '2023-02']);
    });

    test('should handle whitespace in admin name correctly', async () => {
      // First submission with extra whitespace
      await request(app)
        .post('/api/response')
        .send({
          name: '  admin  ',
          responses: [{ question: 'First', answer: 'First' }]
        })
        .expect(201);

      // Second submission should still be detected as duplicate
      const response = await request(app)
        .post('/api/response')
        .send({
          name: 'admin',
          responses: [{ question: 'Second', answer: 'Second' }]
        })
        .expect(409);

      expect(response.body.message).toBe('Une réponse admin existe déjà pour ce mois.');
    });

    test('should handle empty admin name environment variable', async () => {
      const originalAdminName = process.env.FORM_ADMIN_NAME;
      delete process.env.FORM_ADMIN_NAME;

      // Without admin name set, no user should be detected as admin
      const response = await request(app)
        .post('/api/response')
        .send({
          name: 'admin',
          responses: [{ question: 'Test', answer: 'Test' }]
        })
        .expect(201);

      expect(response.body.link).toBeTruthy(); // Should get a link (not admin)

      // Verify user is not admin
      const savedResponse = await Response.findOne({ name: 'admin' });
      expect(savedResponse.isAdmin).toBe(false);
      expect(savedResponse.token).toBeTruthy();

      // Restore environment variable
      process.env.FORM_ADMIN_NAME = originalAdminName;
    });
  });

  describe('Admin Response Validation Edge Cases', () => {
    test('should apply strict validation to admin submissions', async () => {
      const invalidAdminData = {
        name: 'admin',
        responses: [
          {
            question: 'X'.repeat(501), // Over 500 character limit
            answer: 'Valid answer'
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(invalidAdminData)
        .expect(400);

      expect(response.body.message).toContain('500 caractères');
    });

    test('should reject XSS in admin submissions', async () => {
      const xssAdminData = {
        name: 'admin',
        responses: [
          {
            question: '<script>alert("admin-xss")</script>Question?',
            answer: 'Safe answer'
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(xssAdminData)
        .expect(400);

      expect(response.body.message).toBe('Contenu malveillant détecté dans une question');

      // Verify no admin response was created
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(0);
    });

    test('should reject admin submission with honeypot', async () => {
      const spamAdminData = {
        name: 'admin',
        responses: [{ question: 'Test?', answer: 'Test!' }],
        website: 'spam.com' // Honeypot field
      };

      const response = await request(app)
        .post('/api/response')
        .send(spamAdminData)
        .expect(400);

      expect(response.body.message).toBe('Champ honeypot détecté - tentative de spam');

      // Verify no admin response was created
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(0);
    });
  });

  describe('Database Consistency', () => {
    test('should maintain unique constraint on admin responses per month', async () => {
      const currentMonth = new Date().toISOString().slice(0, 7);

      // Create first admin response directly in database
      const firstAdmin = new Response({
        name: 'admin',
        responses: [{ question: 'Direct DB', answer: 'Direct DB' }],
        month: currentMonth,
        isAdmin: true,
        token: null
      });
      await firstAdmin.save();

      // Try to submit through API (should be blocked by application logic)
      const response = await request(app)
        .post('/api/response')
        .send({
          name: 'admin',
          responses: [{ question: 'API attempt', answer: 'API attempt' }]
        })
        .expect(409);

      expect(response.body.message).toBe('Une réponse admin existe déjà pour ce mois.');
    });

    test('should handle race condition scenarios', async () => {
      // Simulate concurrent admin submissions
      const adminData = {
        name: 'admin',
        responses: [{ question: 'Concurrent test', answer: 'Concurrent test' }]
      };

      const promises = Array.from({ length: 3 }, () => 
        request(app)
          .post('/api/response')
          .send(adminData)
      );

      const results = await Promise.allSettled(promises);

      // Only one should succeed, others should fail
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.status === 201);
      const failed = results.filter(r => 
        r.status === 'fulfilled' && (r.value.status === 409 || r.value.status === 500) ||
        r.status === 'rejected'
      );

      expect(successful).toHaveLength(1);
      expect(failed.length).toBeGreaterThan(0);

      // Verify only one admin response exists in database
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(1);
    });
  });
});