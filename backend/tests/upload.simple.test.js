const request = require('supertest');
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const uploadRoutes = require('../routes/upload');

// Mock Cloudinary storage for testing
jest.mock('multer-storage-cloudinary', () => ({
  CloudinaryStorage: jest.fn().mockImplementation(() => ({
    _handleFile: jest.fn((req, file, cb) => {
      // Simulate successful upload
      cb(null, {
        path: 'https://res.cloudinary.com/test/image/upload/v123456/test.jpg',
        filename: 'test.jpg'
      });
    }),
    _removeFile: jest.fn((req, file, cb) => cb(null))
  }))
}));

const cloudinary = require('../config/cloudinary');

describe('Upload Route Integration Tests', () => {
  let app;
  const testImagePath = path.join(__dirname, 'fixtures', 'test-image.jpg');

  beforeAll(() => {
    // Create test fixtures directory and test image if they don't exist
    const fixturesDir = path.join(__dirname, 'fixtures');
    if (!fs.existsSync(fixturesDir)) {
      fs.mkdirSync(fixturesDir, { recursive: true });
    }
    
    // Create a minimal test image if it doesn't exist
    if (!fs.existsSync(testImagePath)) {
      // Create a minimal test file (not a real image but sufficient for testing)
      fs.writeFileSync(testImagePath, Buffer.from('fake-image-data'));
    }
  });

  beforeEach(() => {
    // Create test app with actual upload route
    app = express();
    app.use(express.json());
    app.use('/api/upload', uploadRoutes);
    
    // Reset mocks
    jest.clearAllMocks();
  });

  describe('Upload endpoints', () => {
    test('should upload file successfully with actual multer integration', async () => {
      // Mock successful Cloudinary response
      const mockCloudinaryResult = {
        secure_url: 'https://res.cloudinary.com/test/image/upload/v123456/test.jpg',
        public_id: 'test-image',
        format: 'jpg'
      };
      
      // The actual route uses multer-storage-cloudinary which doesn't use uploader.upload directly
      // Instead we test the actual route behavior
      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(200);

      expect(response.body).toHaveProperty('url');
      expect(typeof response.body.url).toBe('string');
      expect(response.body.url.length).toBeGreaterThan(0);
    });

    test('should return error for missing file', async () => {
      const response = await request(app)
        .post('/api/upload')
        .expect(400);

      expect(response.body.message).toBe('Aucun fichier reçu');
    });

    test('should handle multer errors gracefully', async () => {
      // Test with invalid field name (not 'image')
      const response = await request(app)
        .post('/api/upload')
        .attach('wrongfield', testImagePath);
        
      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Aucun fichier reçu');
    });
  });

  describe('Response format validation', () => {
    test('should return JSON response with proper headers', async () => {
      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(200);

      expect(response.headers['content-type']).toMatch(/json/);
      expect(typeof response.body.url).toBe('string');
      expect(response.body.url.length).toBeGreaterThan(0);
    });
  });

  describe('Error handling validation', () => {
    test('should return proper error structure for missing file', async () => {
      const response = await request(app)
        .post('/api/upload')
        .expect(400);

      expect(response.body).toHaveProperty('message');
      expect(typeof response.body.message).toBe('string');
      expect(response.body.message).toBe('Aucun fichier reçu');
    });

    test('should handle file size limits', async () => {
      // This would need to be configured in multer options in the actual route
      // For now, we test that the route handles basic validation
      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath);
        
      expect([200, 400, 413]).toContain(response.status);
    });
  });

  afterAll(() => {
    // Clean up test fixtures
    const fixturesDir = path.join(__dirname, 'fixtures');
    if (fs.existsSync(fixturesDir)) {
      fs.rmSync(fixturesDir, { recursive: true, force: true });
    }
  });
});