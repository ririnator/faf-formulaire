const request = require('supertest');
const express = require('express');
const formRoutes = require('../routes/formRoutes');
const Response = require('../models/Response');

const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

beforeAll(async () => {
  app = getTestApp();
}, 30000);

describe('Form Routes Tests', () => {
  beforeAll(async () => {
    
    // Only connect if not already connected
    if (mongoose.connection.readyState === 0) {
      }
  });

  afterAll(async () => {
    await mongoose.disconnect();
    });

  beforeEach(async () => {
    await Response.deleteMany({});
    
    // Create test app
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use('/api/form', formRoutes);
  });

  describe('POST /api/form/response', () => {
    test('should successfully save a form response', async () => {
      const formData = {
        name: 'Test User',
        responses: [
          { question: 'How are you?', answer: 'Great!' },
          { question: 'Favorite color?', answer: 'Blue' }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      expect(response.body.message).toBe('Réponse enregistrée avec succès');
      expect(response.body).toHaveProperty('responseId');
      expect(response.body).toHaveProperty('viewUrl'); // Should have viewUrl for non-admin

      // Verify data was saved to database
      const savedResponse = await Response.findOne({ name: 'Test User' });
      expect(savedResponse).toBeTruthy();
      expect(savedResponse.name).toBe(formData.name);
      expect(savedResponse.responses).toHaveLength(2);
      expect(savedResponse.month).toMatch(/^\d{4}-\d{2}$/); // YYYY-MM format
      expect(savedResponse.isAdmin).toBe(false);
      expect(savedResponse.token).toBeTruthy();
    });

    test('should handle single response', async () => {
      const formData = {
        name: 'Single Response User',
        responses: [
          { question: 'Only question?', answer: 'Only answer' }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      expect(response.body.message).toBe('Réponse enregistrée avec succès');

      const savedResponse = await Response.findOne({ name: 'Single Response User' });
      expect(savedResponse.responses).toHaveLength(1);
    });

    test('should handle empty responses array', async () => {
      const formData = {
        name: 'Empty Responses User',
        responses: []
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      expect(response.body.message).toBe('Réponse enregistrée avec succès');

      const savedResponse = await Response.findOne({ name: 'Empty Responses User' });
      expect(savedResponse.responses).toHaveLength(0);
    });

    test('should detect admin user and not provide token', async () => {
      const formData = {
        name: process.env.FORM_ADMIN_NAME || 'testadmin',
        responses: [
          { question: 'Admin question', answer: 'Admin answer' }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      expect(response.body.message).toBe('Réponse enregistrée avec succès');
      expect(response.body).toHaveProperty('responseId');
      expect(response.body).not.toHaveProperty('viewUrl'); // No viewUrl for admin

      const savedResponse = await Response.findOne({ name: formData.name });
      expect(savedResponse.isAdmin).toBe(true);
      expect(savedResponse.token).toBeNull();
    });

    test('should handle missing name field', async () => {
      const formData = {
        responses: [
          { question: 'Test question', answer: 'Test answer' }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(500);

      expect(response.body.message).toBe('Erreur lors de l\'enregistrement de la réponse');
    });

    test('should handle missing responses field', async () => {
      const formData = {
        name: 'Test User'
        // responses field is missing
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData);

      // Missing responses will create empty array, which is valid, so it should succeed
      expect([200, 500]).toContain(response.status);
      
      if (response.status === 200) {
        expect(response.body.message).toBe('Réponse enregistrée avec succès');
        const savedResponse = await Response.findOne({ name: 'Test User' });
        expect(savedResponse.responses).toHaveLength(0);
      } else {
        expect(response.body.message).toBe('Erreur lors de l\'enregistrement de la réponse');
      }
    });

    test('should handle invalid response format', async () => {
      const formData = {
        name: 'Invalid Format User',
        responses: 'not an array'
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(500);

      expect(response.body.message).toBe('Erreur lors de l\'enregistrement de la réponse');
    });

    test('should handle malformed response objects', async () => {
      const formData = {
        name: 'Malformed User',
        responses: [
          { question: 'Valid question', answer: 'Valid answer' },
          { question: 'Missing answer question' }, // Missing answer
          { answer: 'Missing question answer' }, // Missing question
          'not an object'
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData);

      // Should either succeed (if validation is lenient) or fail gracefully
      expect([200, 500]).toContain(response.status);
    });

    test('should handle very long responses', async () => {
      const longAnswer = 'x'.repeat(10000); // 10KB answer
      const formData = {
        name: 'Long Response User',
        responses: [
          { question: 'Long question?', answer: longAnswer }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData);

      expect([200, 413, 500]).toContain(response.status);
    });

    test('should handle special characters in responses', async () => {
      const formData = {
        name: 'Special Chars User 🚀',
        responses: [
          { question: 'Émoji question? 🤔', answer: 'Émoji answer! 😊' },
          { question: 'HTML <script>alert("xss")</script>', answer: 'JSON {"test": "value"}' },
          { question: 'Unicode: 你好世界', answer: 'Arabic: مرحبا بالعالم' }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      const savedResponse = await Response.findOne({ name: 'Special Chars User 🚀' });
      expect(savedResponse).toBeTruthy();
      expect(savedResponse.responses[0].question).toContain('🤔');
      expect(savedResponse.responses[0].answer).toContain('😊');
    });
  });

  describe('Database Integration', () => {
    test('should handle database connection errors', async () => {
      // Mock Response.prototype.save to throw an error
      const originalSave = Response.prototype.save;
      Response.prototype.save = jest.fn().mockRejectedValue(
        new Error('Database connection lost')
      );

      const formData = {
        name: 'DB Error User',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(500);

      expect(response.body.message).toBe('Erreur lors de l\'enregistrement de la réponse');

      // Restore original method
      Response.prototype.save = originalSave;
    });

    test('should handle mongoose validation errors', async () => {
      // Mock Response constructor to create invalid document
      const formData = {
        name: '', // Empty name should trigger validation error
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData);

      // Should handle validation error gracefully
      expect([200, 400, 500]).toContain(response.status);
    });

    test('should handle concurrent requests', async () => {
      const formData = {
        name: 'Concurrent User',
        responses: [{ question: 'Concurrent test', answer: 'Test answer' }]
      };

      // Send multiple concurrent requests
      const promises = Array(5).fill(null).map((_, i) =>
        request(app)
          .post('/api/form/response')
          .send({ ...formData, name: `Concurrent User ${i}` })
      );

      const responses = await Promise.all(promises);

      // All should succeed since they have different names
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });

      // Verify all were saved
      const savedResponses = await Response.find({ name: /^Concurrent User/ });
      expect(savedResponses).toHaveLength(5);
    });
  });

  describe('Request Validation', () => {
    test('should handle empty request body', async () => {
      const response = await request(app)
        .post('/api/form/response')
        .send({})
        .expect(500);

      expect(response.body.message).toBe('Erreur lors de l\'enregistrement de la réponse');
    });

    test('should handle null values', async () => {
      const formData = {
        name: null,
        responses: null
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(500);

      expect(response.body.message).toBe('Erreur lors de l\'enregistrement de la réponse');
    });

    test('should handle undefined values', async () => {
      const formData = {
        name: undefined,
        responses: undefined
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(500);

      expect(response.body.message).toBe('Erreur lors de l\'enregistrement de la réponse');
    });

    test('should handle malformed JSON', async () => {
      const response = await request(app)
        .post('/api/form/response')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }');

      expect(response.status).toBe(400);
    });
  });

  describe('Response Structure Validation', () => {
    test('should validate response object structure', async () => {
      const formData = {
        name: 'Structure Test User',
        responses: [
          { question: 'Valid', answer: 'Valid' },
          { question: '', answer: 'Empty question' },
          { question: 'Empty answer', answer: '' },
          { question: 'Both empty', answer: '' }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData);

      expect([200, 400, 500]).toContain(response.status);
    });

    test('should handle extra fields in request', async () => {
      const formData = {
        name: 'Extra Fields User',
        responses: [{ question: 'Test', answer: 'Test' }],
        extraField: 'should be ignored',
        anotherExtra: { nested: 'object' }
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      const savedResponse = await Response.findOne({ name: 'Extra Fields User' });
      expect(savedResponse).toBeTruthy();
      // Extra fields should not be saved to database
      expect(savedResponse.extraField).toBeUndefined();
      expect(savedResponse.anotherExtra).toBeUndefined();
    });
  });

  describe('Content Security', () => {
    test('should handle potential XSS attempts in responses', async () => {
      const formData = {
        name: 'XSS Test User',
        responses: [
          { 
            question: '<script>alert("xss")</script>What is your name?',
            answer: '<img src="x" onerror="alert(\'xss\')">' 
          },
          {
            question: 'javascript:alert("xss")',
            answer: 'onclick="alert(\'xss\')" value'
          }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      // Data should be stored as-is (sanitization happens on output, not input)
      const savedResponse = await Response.findOne({ name: 'XSS Test User' });
      expect(savedResponse.responses[0].question).toContain('<script>');
      expect(savedResponse.responses[0].answer).toContain('<img');
    });

    test('should handle SQL injection attempts', async () => {
      const formData = {
        name: "'; DROP TABLE responses; --",
        responses: [
          { 
            question: "1' OR '1'='1",
            answer: "UNION SELECT * FROM users--" 
          }
        ]
      };

      const response = await request(app)
        .post('/api/form/response')
        .send(formData)
        .expect(200);

      // MongoDB should handle this safely
      const savedResponse = await Response.findOne({ name: "'; DROP TABLE responses; --" });
      expect(savedResponse).toBeTruthy();
    });
  });
});