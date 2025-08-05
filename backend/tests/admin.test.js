const request = require('supertest');
const express = require('express');
const session = require('express-session');
const adminRoutes = require('../routes/adminRoutes');
const Response = require('../models/Response');

// Create test app with simple admin middleware
const createTestApp = (withAuth = false) => {
  const app = express();
  app.use(express.json());

  // Simple mock admin middleware
  const ensureAdmin = (req, res, next) => {
    if (withAuth) return next(); // Bypass auth when testing admin routes
    return res.status(401).json({ message: 'Admin access required' });
  };

  app.use('/api/admin', ensureAdmin, adminRoutes);
  return app;
};

describe('Admin Routes', () => {
  let app;

  describe('Authentication Middleware', () => {
    test('should reject unauthenticated requests', async () => {
      app = createTestApp(false); // No auth
      const response = await request(app)
        .get('/api/admin/responses')
        .expect(401);

      expect(response.body.message).toBe('Admin access required');
    });

    test('should allow authenticated admin requests', async () => {
      app = createTestApp(true); // With auth
      await request(app)
        .get('/api/admin/responses')
        .expect(200);
    });
  });

  describe('GET /api/admin/responses (Pagination)', () => {
    beforeEach(async () => {
      app = createTestApp(true); // Authenticated app
      
      // Create test data
      const testResponses = Array.from({ length: 15 }, (_, i) => ({
        name: `User${i + 1}`,
        responses: [{ question: 'Test question', answer: `Answer ${i + 1}` }],
        month: '2024-01',
        isAdmin: false,
        token: `token${i + 1}`
      }));

      await Response.insertMany(testResponses);
    });

    test('should return paginated responses', async () => {
      const response = await request(app)
        .get('/api/admin/responses?page=1&limit=10')
        .expect(200);

      expect(response.body).toHaveProperty('responses');
      expect(response.body).toHaveProperty('pagination');
      expect(response.body.responses.length).toBeLessThanOrEqual(10);
      expect(response.body.pagination.totalCount).toBe(15);
    });

    test('should handle invalid pagination parameters', async () => {
      const response = await request(app)
        .get('/api/admin/responses?page=-1&limit=100')
        .expect(200);

      // Should normalize to page=1, limit=20 (max)
      expect(response.body.pagination.page).toBe(1);
      expect(response.body.responses.length).toBeLessThanOrEqual(20);
    });
  });

  describe('GET /api/admin/responses/:id', () => {
    let testResponse;

    beforeEach(async () => {
      app = createTestApp(true);
      testResponse = await Response.create({
        name: 'TestUser',
        responses: [{ question: 'Test', answer: 'Answer' }],
        month: '2024-01',
        isAdmin: false,
        token: 'test-token'
      });
    });

    test('should return specific response', async () => {
      const response = await request(app)
        .get(`/api/admin/responses/${testResponse._id}`)
        .expect(200);

      expect(response.body.name).toBe('TestUser');
      expect(response.body._id).toBe(testResponse._id.toString());
    });

    test('should return 404 for non-existent response', async () => {
      const fakeId = '507f1f77bcf86cd799439011';
      await request(app)
        .get(`/api/admin/responses/${fakeId}`)
        .expect(404);
    });
  });

  describe('DELETE /api/admin/responses/:id', () => {
    let testResponse;

    beforeEach(async () => {
      app = createTestApp(true);
      testResponse = await Response.create({
        name: 'TestUser',
        responses: [{ question: 'Test', answer: 'Answer' }],
        month: '2024-01',
        isAdmin: false,
        token: 'test-token'
      });
    });

    test('should delete response successfully', async () => {
      const response = await request(app)
        .delete(`/api/admin/responses/${testResponse._id}`)
        .expect(200);

      expect(response.body.message).toBe('Réponse supprimée avec succès');

      // Verify deletion
      const deletedResponse = await Response.findById(testResponse._id);
      expect(deletedResponse).toBeNull();
    });
  });

  describe('GET /api/admin/summary', () => {
    beforeEach(async () => {
      app = createTestApp(true);
      await Response.create({
        name: 'User1',
        responses: [
          { question: 'En rapide, comment ça va ?', answer: 'ça va' },
          { question: 'Autre question', answer: 'Autre réponse' }
        ],
        month: '2024-01',
        isAdmin: false,
        createdAt: new Date('2024-01-15')
      });
    });

    test('should return summary data', async () => {
      const response = await request(app)
        .get('/api/admin/summary')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });

    test('should filter by month', async () => {
      const response = await request(app)
        .get('/api/admin/summary?month=2024-01')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
    });
  });

  describe('GET /api/admin/months', () => {
    beforeEach(async () => {
      app = createTestApp(true);
      await Response.create({
        name: 'User1',
        responses: [{ question: 'Test', answer: 'Answer' }],
        month: '2024-01',
        isAdmin: false,
        createdAt: new Date('2024-01-15')
      });
    });

    test('should return available months', async () => {
      const response = await request(app)
        .get('/api/admin/months')
        .expect(200);

      expect(Array.isArray(response.body)).toBe(true);
      if (response.body.length > 0) {
        expect(response.body[0]).toHaveProperty('key');
        expect(response.body[0]).toHaveProperty('label');
      }
    });
  });
});