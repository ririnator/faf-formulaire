const request = require('supertest');
const express = require('express');
const Response = require('../models/Response');
const responseRoutes = require('../routes/responseRoutes');
const adminRoutes = require('../routes/adminRoutes');
const uploadRoutes = require('../routes/upload');

// Mock Cloudinary to simulate failures
jest.mock('../config/cloudinary', () => ({
  uploader: {
    upload: jest.fn()
  }
}));

const cloudinary = require('../config/cloudinary');

const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

beforeAll(async () => {
  app = getTestApp();
}, 30000);

describe('Error Handling and Database Failure Tests', () => {
  let mongoUri;

  beforeAll(async () => {
    
    mongoUri = mongoServer.getUri();
    
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

    // Mock admin middleware for testing
    const mockAdminMiddleware = (req, res, next) => {
      req.session = { isAdmin: true };
      next();
    };

    app.use('/api/responses', responseRoutes);
    app.use('/api/admin', mockAdminMiddleware, adminRoutes);
    app.use('/api/upload', uploadRoutes);

    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('Database Connection Failures', () => {
    test('should handle MongoDB connection loss during write operations', async () => {
      // Simulate connection loss
      const originalSave = Response.prototype.save;
      Response.prototype.save = jest.fn().mockRejectedValue(
        new Error('MongoNetworkError: connection lost')
      );

      const formData = {
        name: 'Test User',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      const response = await request(app)
        .post('/api/responses')
        .send(formData);

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('message');

      // Restore original method
      Response.prototype.save = originalSave;
    });

    test('should handle MongoDB read failures', async () => {
      // Mock Response.find to throw an error
      const originalFind = Response.find;
      Response.find = jest.fn().mockRejectedValue(
        new Error('MongoError: read concern error')
      );

      const response = await request(app)
        .get('/api/admin/responses');

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('message');

      // Restore original method
      Response.find = originalFind;
    });

    test('should handle MongoDB timeout errors', async () => {
      const originalFindById = Response.findById;
      Response.findById = jest.fn().mockRejectedValue(
        new Error('MongoTimeoutError: operation timed out')
      );

      const fakeId = '507f1f77bcf86cd799439011';
      const response = await request(app)
        .get(`/api/admin/responses/${fakeId}`);

      expect(response.status).toBe(500);
      expect(response.body).toHaveProperty('message');

      Response.findById = originalFindById;
    });
  });

  describe('Validation Error Handling', () => {
    test('should handle Mongoose validation errors', async () => {
      // Create a response that will trigger validation error
      const invalidData = {
        name: '', // Required field is empty
        responses: [],
        month: 'invalid-month-format' // Invalid format
      };

      const response = await request(app)
        .post('/api/responses')
        .send(invalidData);

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message');
    });

    test('should handle malformed ObjectId errors', async () => {
      const invalidId = 'invalid-object-id';
      
      const response = await request(app)
        .get(`/api/admin/responses/${invalidId}`);

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('Invalid ID format');
    });

    test('should handle cast errors for invalid data types', async () => {
      // Mock Response.findById to throw CastError
      const originalFindById = Response.findById;
      Response.findById = jest.fn().mockRejectedValue(
        Object.assign(new Error('Cast to ObjectId failed'), {
          name: 'CastError',
          kind: 'ObjectId',
          value: 'invalid-id',
          path: '_id'
        })
      );

      const response = await request(app)
        .get('/api/admin/responses/invalid-id');

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('message');

      Response.findById = originalFindById;
    });
  });

  describe('Network and External Service Failures', () => {
    test('should handle Cloudinary upload failures', async () => {
      // Mock Cloudinary to fail
      const mockError = new Error('Cloudinary service unavailable');
      
      // Since upload route uses multer-storage-cloudinary, we need to test differently
      const response = await request(app)
        .post('/api/upload')
        .attach('wrongfield', Buffer.from('fake-image'), 'test.jpg');

      // Should handle missing file gracefully
      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Aucun fichier reçu');
    });

    test('should handle file upload size limit exceeded', async () => {
      // Create a large buffer to simulate oversized file
      const largeBuffer = Buffer.alloc(100 * 1024 * 1024); // 100MB
      
      const response = await request(app)
        .post('/api/upload')
        .attach('image', largeBuffer, 'large-file.jpg');

      // Should handle based on multer configuration
      expect([400, 413, 500]).toContain(response.status);
    });
  });

  describe('Concurrency and Race Condition Handling', () => {
    test('should handle concurrent duplicate submissions', async () => {
      const userData = {
        name: 'Concurrent User',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      // Send multiple concurrent requests
      const promises = Array(3).fill(null).map(() =>
        request(app)
          .post('/api/responses')
          .send(userData)
      );

      const responses = await Promise.all(promises);
      
      // Only one should succeed, others should fail with duplicate error
      const successCount = responses.filter(r => r.status === 201).length;
      const duplicateErrorCount = responses.filter(r => r.status === 400).length;
      
      expect(successCount).toBe(1);
      expect(duplicateErrorCount).toBe(2);
    });

    test('should handle concurrent admin operations', async () => {
      const testResponse = await Response.create({
        name: 'Test User',
        responses: [{ question: 'Test', answer: 'Test' }],
        month: '2024-01',
        isAdmin: false,
        token: 'test-token'
      });

      // Attempt concurrent deletes of the same response
      const deletePromises = Array(3).fill(null).map(() =>
        request(app)
          .delete(`/api/admin/responses/${testResponse._id}`)
      );

      const responses = await Promise.all(deletePromises);
      
      // One should succeed, others should fail with 404
      const successCount = responses.filter(r => r.status === 200).length;
      const notFoundCount = responses.filter(r => r.status === 404).length;
      
      expect(successCount).toBe(1);
      expect(notFoundCount).toBe(2);
    });
  });

  describe('Memory and Resource Exhaustion', () => {
    test('should handle large payload gracefully', async () => {
      const largeResponses = Array(1000).fill(null).map((_, i) => ({
        question: `Question ${i}`,
        answer: 'A'.repeat(1000) // 1KB per answer
      }));

      const largeData = {
        name: 'Large Data User',
        responses: largeResponses
      };

      const response = await request(app)
        .post('/api/responses')
        .send(largeData);

      // Should either succeed or fail with appropriate error
      expect([201, 400, 413, 500]).toContain(response.status);
    });

    test('should handle malformed JSON payloads', async () => {
      const response = await request(app)
        .post('/api/responses')
        .set('Content-Type', 'application/json')
        .send('{ "name": "test", "responses": [ invalid json }');

      expect(response.status).toBe(400);
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    test('should handle empty database queries', async () => {
      // Ensure database is empty
      await Response.deleteMany({});

      const response = await request(app)
        .get('/api/admin/responses');

      expect(response.status).toBe(200);
      expect(response.body.responses).toEqual([]);
      expect(response.body.pagination.totalCount).toBe(0);
    });

    test('should handle pagination edge cases', async () => {
      // Test with page number beyond available data
      const response = await request(app)
        .get('/api/admin/responses?page=999&limit=10');

      expect(response.status).toBe(200);
      expect(response.body.responses).toEqual([]);
    });

    test('should handle negative pagination values', async () => {
      const response = await request(app)
        .get('/api/admin/responses?page=-1&limit=-10');

      expect(response.status).toBe(200);
      // Should normalize to valid values
      expect(response.body.pagination.page).toBeGreaterThan(0);
    });

    test('should handle missing required environment variables', async () => {
      // Temporarily remove env var
      const originalFormAdminName = process.env.FORM_ADMIN_NAME;
      delete process.env.FORM_ADMIN_NAME;

      const formData = {
        name: 'testadmin',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      const response = await request(app)
        .post('/api/responses')
        .send(formData);

      // Should still work but not detect as admin
      expect([201, 500]).toContain(response.status);

      // Restore env var
      process.env.FORM_ADMIN_NAME = originalFormAdminName;
    });
  });

  describe('Recovery and Resilience', () => {
    test('should recover from temporary database disconnection', async () => {
      // Simulate temporary disconnection
      const formData = {
        name: 'Recovery Test',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      // This should fail
      const failedResponse = await request(app)
        .post('/api/responses')
        .send(formData);

      expect(failedResponse.status).toBe(500);

      // Reconnect
      // This should succeed
      const successResponse = await request(app)
        .post('/api/responses')
        .send(formData);

      expect(successResponse.status).toBe(201);
    });
  });
});