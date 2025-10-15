// tests/admin.question-order.test.js - Dynamic Question Order Tests
const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const Response = require('../models/Response');

// Import app without starting it
process.env.NODE_ENV = 'test';
process.env.FORM_ADMIN_NAME = 'testadmin';
process.env.SESSION_SECRET = 'test-secret-key-for-sessions';
process.env.APP_BASE_URL = 'http://localhost:3000';
process.env.LOGIN_ADMIN_USER = 'admin';
process.env.LOGIN_ADMIN_PASS = '$2b$10$hashedpassword'; // bcrypt hash

let mongoServer;
let app;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  await mongoose.connect(mongoUri);
  app = require('../app');
}, 30000);

afterAll(async () => {
  await mongoose.connection.dropDatabase();
  await mongoose.connection.close();
  await mongoServer.stop();
}, 30000);

beforeEach(async () => {
  await Response.deleteMany({});
});

describe('📋 Dynamic Admin Question Order Tests', () => {
  const testMonth = '2025-01';

  describe('Dynamic Question Ordering Logic', () => {
    test('should use first submission question order', async () => {
      // First response defines the order
      const firstResponse = new Response({
        name: 'user1',
        responses: [
          { question: 'En rapide, comment ça va ?', answer: 'Bien' }, // PIE_Q
          { question: 'Question Alpha', answer: 'Answer A' },
          { question: 'Question Beta', answer: 'Answer B' },
          { question: 'Question Gamma', answer: 'Answer C' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token1',
        createdAt: new Date('2025-01-01T10:00:00Z')
      });
      await firstResponse.save();

      // Second response with different order (should not affect summary order)
      const secondResponse = new Response({
        name: 'user2',
        responses: [
          { question: 'En rapide, comment ça va ?', answer: 'Moyen' },
          { question: 'Question Gamma', answer: 'Answer C2' }, // Different order
          { question: 'Question Alpha', answer: 'Answer A2' },
          { question: 'Question Beta', answer: 'Answer B2' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token2',
        createdAt: new Date('2025-01-02T10:00:00Z') // Later
      });
      await secondResponse.save();

      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      // Should follow first response order: PIE_Q, Alpha, Beta, Gamma
      expect(response.body).toHaveLength(4);
      expect(response.body[0].question).toBe('En rapide, comment ça va ?'); // PIE_Q first
      expect(response.body[1].question).toBe('Question Alpha');
      expect(response.body[2].question).toBe('Question Beta');
      expect(response.body[3].question).toBe('Question Gamma');
    });

    test('should handle empty dataset gracefully', async () => {
      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      expect(response.body).toEqual([]);
    });

    test('should handle corrupted first response with fallback', async () => {
      // Corrupted first response
      const corruptedResponse = new Response({
        name: 'user1',
        responses: [
          { question: null, answer: 'Invalid' },
          { question: '', answer: 'Empty' },
          { question: '   ', answer: 'Whitespace' },
          { question: 123, answer: 'Number' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token1',
        createdAt: new Date('2025-01-01T10:00:00Z')
      });
      await corruptedResponse.save();

      // Valid second response
      const validResponse = new Response({
        name: 'user2',
        responses: [
          { question: 'Valid Question', answer: 'Valid Answer' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token2',
        createdAt: new Date('2025-01-02T10:00:00Z')
      });
      await validResponse.save();

      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      // Should use fallback ordering
      expect(response.body).toHaveLength(1);
      expect(response.body[0].question).toBe('Valid Question');
    });

    test('should prioritize PIE_Q question first always', async () => {
      const testResponse = new Response({
        name: 'user1',
        responses: [
          { question: 'Other Question First', answer: 'Other Answer' },
          { question: 'En rapide, comment ça va ?', answer: 'Bien' }, // PIE_Q in middle
          { question: 'Final Question Last', answer: 'Final Answer' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token1',
        createdAt: new Date('2025-01-01T10:00:00Z')
      });
      await testResponse.save();

      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      // PIE_Q should always be first
      expect(response.body[0].question).toBe('En rapide, comment ça va ?');
      expect(response.body[1].question).toBe('Other Question First');
      expect(response.body[2].question).toBe('Final Question Last');
    });

    test('should handle responses without PIE_Q question', async () => {
      const testResponse = new Response({
        name: 'user1',
        responses: [
          { question: 'Question One', answer: 'Answer One' },
          { question: 'Question Two', answer: 'Answer Two' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token1',
        createdAt: new Date('2025-01-01T10:00:00Z')
      });
      await testResponse.save();

      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      expect(response.body).toHaveLength(2);
      expect(response.body[0].question).toBe('Question One');
      expect(response.body[1].question).toBe('Question Two');
    });

    test('should maintain order consistency across multiple calls', async () => {
      const testResponse = new Response({
        name: 'user1',
        responses: [
          { question: 'First', answer: '1' },
          { question: 'Second', answer: '2' },
          { question: 'Third', answer: '3' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token1',
        createdAt: new Date('2025-01-01T10:00:00Z')
      });
      await testResponse.save();

      // Make multiple concurrent requests
      const responses = await Promise.all([
        request(app).get(`/api/admin/summary?month=${testMonth}`),
        request(app).get(`/api/admin/summary?month=${testMonth}`),
        request(app).get(`/api/admin/summary?month=${testMonth}`)
      ]);

      // All should have same order
      responses.forEach(response => {
        expect(response.body.map(item => item.question))
          .toEqual(['First', 'Second', 'Third']);
      });
    });
  });

  describe('Edge Cases and Validation', () => {
    test('should filter out invalid questions from first response', async () => {
      const mixedValidityResponse = new Response({
        name: 'user1',
        responses: [
          { question: 'Valid Question 1', answer: 'Valid Answer 1' },
          { question: null, answer: 'Invalid null question' },
          { question: '', answer: 'Invalid empty question' },
          { question: 'Valid Question 2', answer: 'Valid Answer 2' },
          { question: '   ', answer: 'Invalid whitespace question' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token1',
        createdAt: new Date('2025-01-01T10:00:00Z')
      });
      await mixedValidityResponse.save();

      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      // Should only include valid questions
      expect(response.body).toHaveLength(2);
      expect(response.body[0].question).toBe('Valid Question 1');
      expect(response.body[1].question).toBe('Valid Question 2');
    });

    test('should handle normalization failures gracefully', async () => {
      const testResponse = new Response({
        name: 'user1',
        responses: [
          { question: 'Normal Question', answer: 'Normal Answer' },
          { question: new Array(10000).join('x'), answer: 'Extremely long question' } // Edge case
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token1',
        createdAt: new Date('2025-01-01T10:00:00Z')
      });
      await testResponse.save();

      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      // Should handle gracefully
      expect(response.body.length).toBeGreaterThan(0);
      expect(response.body[0].question).toBe('Normal Question');
    });

    test('should use textSummary fallback when no valid first response', async () => {
      // Create multiple responses with invalid questions
      for (let i = 0; i < 3; i++) {
        await new Response({
          name: `user${i}`,
          responses: [
            { question: null, answer: 'Invalid' },
            { question: '', answer: 'Empty' }
          ],
          month: testMonth,
          isAdmin: false,
          token: `token${i}`,
          createdAt: new Date(`2025-01-0${i + 1}T10:00:00Z`)
        }).save();
      }

      // Add one response that will appear in textSummary
      await new Response({
        name: 'user_valid',
        responses: [
          { question: 'Fallback Question', answer: 'Fallback Answer' }
        ],
        month: testMonth,
        isAdmin: false,
        token: 'token_valid',
        createdAt: new Date('2025-01-04T10:00:00Z')
      }).save();

      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);

      // Should use textSummary fallback
      expect(response.body).toHaveLength(1);
      expect(response.body[0].question).toBe('Fallback Question');
    });
  });

  describe('Performance Tests', () => {
    test('should handle large datasets efficiently', async () => {
      // Create response with many questions
      const manyQuestions = Array.from({ length: 50 }, (_, i) => ({
        question: `Performance Question ${i + 1}`,
        answer: `Performance Answer ${i + 1}`
      }));

      await new Response({
        name: 'performance_user',
        responses: manyQuestions,
        month: testMonth,
        isAdmin: false,
        token: 'perf_token',
        createdAt: new Date('2025-01-01T10:00:00Z')
      }).save();

      const startTime = Date.now();
      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);
      const endTime = Date.now();

      expect(response.body).toHaveLength(50);
      expect(endTime - startTime).toBeLessThan(2000); // Should complete within 2 seconds
    });

    test('should handle multiple responses with same questions efficiently', async () => {
      // Create multiple responses with same questions to test deduplication
      for (let i = 0; i < 10; i++) {
        await new Response({
          name: `user${i}`,
          responses: [
            { question: 'Common Question 1', answer: `Answer ${i}-1` },
            { question: 'Common Question 2', answer: `Answer ${i}-2` }
          ],
          month: testMonth,
          isAdmin: false,
          token: `token${i}`,
          createdAt: new Date(`2025-01-01T${10 + i}:00:00Z`)
        }).save();
      }

      const startTime = Date.now();
      const response = await request(app)
        .get(`/api/admin/summary?month=${testMonth}`)
        .expect(200);
      const endTime = Date.now();

      // Should be deduplicated to 2 questions with 10 answers each
      expect(response.body).toHaveLength(2);
      expect(response.body[0].items).toHaveLength(10);
      expect(response.body[1].items).toHaveLength(10);
      expect(endTime - startTime).toBeLessThan(1000);
    });
  });
});