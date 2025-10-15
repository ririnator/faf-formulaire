const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../app');
const Response = require('../models/Response');

describe('Middleware Integration Tests', () => {
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    // Close existing connection if any
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
    
    await mongoose.connect(mongoUri);
    process.env.FORM_ADMIN_NAME = 'testadmin';
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await Response.deleteMany({});
  });

  describe('Complete Validation Pipeline', () => {
    test('should process valid submission through entire pipeline', async () => {
      const validData = {
        name: 'John Doe',
        responses: [
          {
            question: 'What is your favorite programming language?',
            answer: 'JavaScript is amazing!'
          },
          {
            question: 'How do you feel about testing?',
            answer: 'Testing is crucial for quality software'
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(validData)
        .expect(201);

      expect(response.body.message).toBe('Réponse enregistrée avec succès !');
      expect(response.body.link).toBeTruthy();
      expect(response.body.link).toContain('/view/');

      // Verify data is properly stored in database
      const savedResponse = await Response.findOne({ name: 'John Doe' });
      expect(savedResponse).toBeTruthy();
      expect(savedResponse.isAdmin).toBe(false);
      expect(savedResponse.token).toBeTruthy();
      expect(savedResponse.responses).toHaveLength(2);
    });

    test('should reject and sanitize malicious submission', async () => {
      const maliciousData = {
        name: '<script>alert("xss")</script>Evil User',
        responses: [
          {
            question: '<img src="x" onerror="alert(1)">What is your name?',
            answer: '<div onmouseover="steal()">Innocent answer</div>'
          }
        ]
      };

      // Should still pass validation but content should be escaped
      const response = await request(app)
        .post('/api/response')
        .send(maliciousData)
        .expect(201);

      // Verify data is escaped in database
      const savedResponse = await Response.findOne({ name: /Evil User/ });
      expect(savedResponse).toBeTruthy();
      expect(savedResponse.name).toContain('&lt;script&gt;');
      expect(savedResponse.responses[0].question).toContain('&lt;img');
      expect(savedResponse.responses[0].answer).toContain('&lt;div');
      expect(savedResponse.name).not.toContain('<script>');
    });

    test('should handle rate limiting correctly', async () => {
      const validData = {
        name: 'Rate Test User',
        responses: [{ question: 'Test?', answer: 'Test!' }]
      };

      // First 3 requests should succeed
      for (let i = 0; i < 3; i++) {
        const uniqueData = { ...validData, name: `Rate Test User ${i}` };
        await request(app)
          .post('/api/response')
          .send(uniqueData)
          .expect(201);
      }

      // 4th request should be rate limited
      const rateLimitResponse = await request(app)
        .post('/api/response')
        .send({ ...validData, name: 'Rate Test User 4' })
        .expect(429);

      expect(rateLimitResponse.body.message).toContain('Trop de soumissions');
    });

    test('should enforce character limits with proper error messages', async () => {
      const oversizedData = {
        name: 'A'.repeat(101), // Over 100 character limit
        responses: [
          {
            question: 'Q'.repeat(501), // Over 500 character limit
            answer: 'A'.repeat(10001) // Over 10000 character limit
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(oversizedData)
        .expect(400);

      // Should get the first validation error (name length)
      expect(response.body.message).toContain('100 caractères');
      expect(response.body.field).toBe('name');
    });

    test('should handle admin logic with validation', async () => {
      const adminData = {
        name: 'testadmin',
        responses: [
          {
            question: 'Admin question with <script>alert("admin")</script>',
            answer: 'Admin answer'
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(adminData)
        .expect(201);

      expect(response.body.link).toBeNull(); // Admin should not get link

      // Verify admin response is properly sanitized
      const savedResponse = await Response.findOne({ isAdmin: true });
      expect(savedResponse).toBeTruthy();
      expect(savedResponse.token).toBeNull();
      expect(savedResponse.responses[0].question).toContain('&lt;script&gt;');
    });
  });

  describe('Error Handling Integration', () => {
    test('should handle validation errors gracefully', async () => {
      const invalidData = {
        name: '', // Too short
        responses: [] // Empty array
      };

      const response = await request(app)
        .post('/api/response')
        .send(invalidData)
        .expect(400);

      expect(response.body.message).toBeTruthy();
      expect(response.body.field).toBeTruthy();
    });

    test('should handle missing required fields', async () => {
      const incompleteData = {
        name: 'John Doe'
        // Missing responses array
      };

      const response = await request(app)
        .post('/api/response')
        .send(incompleteData)
        .expect(400);

      expect(response.body.message).toContain('réponse');
    });

    test('should handle malformed JSON gracefully', async () => {
      const response = await request(app)
        .post('/api/response')
        .type('json')
        .send('{"name": "John", "responses": [{"question": "Test", "answer":}]}') // Invalid JSON
        .expect(400);

      // Express should handle JSON parsing errors
      expect(response.status).toBe(400);
    });
  });

  describe('Security Headers Integration', () => {
    test('should include security headers in response', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);

      // Check for Helmet security headers
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('0');
    });

    test('should include CSP header', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);

      expect(response.headers['content-security-policy']).toBeTruthy();
      expect(response.headers['content-security-policy']).toContain("default-src 'self'");
    });
  });

  describe('End-to-End Submission Flow', () => {
    test('should complete full submission and retrieval cycle', async () => {
      // Step 1: Submit user response
      const userData = {
        name: 'Integration User',
        responses: [
          {
            question: 'How do you like the new validation?',
            answer: 'It works great & keeps us <safe>!'
          }
        ]
      };

      const submitResponse = await request(app)
        .post('/api/response')
        .send(userData)
        .expect(201);

      const token = submitResponse.body.link.split('/').pop();

      // Step 2: Submit admin response for same month
      const adminData = {
        name: 'testadmin',
        responses: [
          {
            question: 'How do you like the new validation?',
            answer: 'Admin perspective: Very secure!'
          }
        ]
      };

      await request(app)
        .post('/api/response')
        .send(adminData)
        .expect(201);

      // Step 3: Retrieve both responses via token
      const viewResponse = await request(app)
        .get(`/api/view/${token}`)
        .expect(200);

      expect(viewResponse.body.user).toBeTruthy();
      expect(viewResponse.body.admin).toBeTruthy();
      expect(viewResponse.body.user.name).toBe('Integration User');
      expect(viewResponse.body.admin.name).toBe('testadmin');
      
      // Verify content is properly escaped
      expect(viewResponse.body.user.responses[0].answer).toContain('&amp;');
      expect(viewResponse.body.user.responses[0].answer).toContain('&lt;safe&gt;');
    });

    test('should handle concurrent submissions correctly', async () => {
      const baseData = {
        name: 'Concurrent User',
        responses: [{ question: 'Concurrent test?', answer: 'Yes!' }]
      };

      // Submit multiple concurrent requests
      const promises = Array.from({ length: 5 }, (_, i) => 
        request(app)
          .post('/api/response')
          .send({ ...baseData, name: `Concurrent User ${i}` })
      );

      const results = await Promise.all(promises);

      // All should succeed (different names)
      results.forEach(result => {
        expect(result.status).toBe(201);
      });

      // Verify all were saved
      const responses = await Response.find({ name: /Concurrent User/ });
      expect(responses).toHaveLength(5);
    });

    test('should maintain data integrity under stress', async () => {
      const stressData = {
        name: 'Stress Test User',
        responses: Array.from({ length: 20 }, (_, i) => ({
          question: `Stress question ${i + 1}?`,
          answer: `Stress answer ${i + 1} with special chars: <>&"'`
        }))
      };

      const response = await request(app)
        .post('/api/response')
        .send(stressData)
        .expect(201);

      const savedResponse = await Response.findOne({ name: 'Stress Test User' });
      expect(savedResponse.responses).toHaveLength(20);
      
      // Verify all special characters are properly escaped
      savedResponse.responses.forEach(r => {
        expect(r.answer).toContain('&lt;');
        expect(r.answer).toContain('&gt;');
        expect(r.answer).toContain('&amp;');
        expect(r.answer).toContain('&quot;');
        expect(r.answer).toContain('&#x27;');
      });
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle large valid payloads efficiently', async () => {
      const largeData = {
        name: 'Performance User',
        responses: [
          {
            question: 'Q'.repeat(500), // Max allowed
            answer: 'A'.repeat(10000) // Max allowed
          }
        ]
      };

      const startTime = Date.now();
      const response = await request(app)
        .post('/api/response')
        .send(largeData)
        .expect(201);
      const endTime = Date.now();

      // Should complete within reasonable time (< 1 second)
      expect(endTime - startTime).toBeLessThan(1000);
      expect(response.body.message).toBe('Réponse enregistrée avec succès !');
    });

    test('should efficiently reject oversized payloads', async () => {
      const oversizedData = {
        name: 'Oversized User',
        responses: [
          {
            question: 'Normal question?',
            answer: 'A'.repeat(10001) // Over limit
          }
        ]
      };

      const startTime = Date.now();
      await request(app)
        .post('/api/response')
        .send(oversizedData)
        .expect(400);
      const endTime = Date.now();

      // Should fail fast (validation before processing)
      expect(endTime - startTime).toBeLessThan(100);
    });
  });
});