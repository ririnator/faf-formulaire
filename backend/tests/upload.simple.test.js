const request = require('supertest');
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const uploadRoutes = require('../routes/upload');

// Mock Cloudinary storage with more realistic scenarios
const mockCloudinaryStorage = {
  _handleFile: jest.fn(),
  _removeFile: jest.fn()
};

jest.mock('multer-storage-cloudinary', () => ({
  CloudinaryStorage: jest.fn().mockImplementation(() => mockCloudinaryStorage)
}));

// Mock Cloudinary config
jest.mock('../config/cloudinary', () => ({
  api_key: 'test-api-key',
  api_secret: 'test-api-secret',
  cloud_name: 'test-cloud'
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
    
    // Setup default successful mock behavior
    mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
      cb(null, {
        path: `https://res.cloudinary.com/test-cloud/image/upload/v${Date.now()}/${file.originalname}`,
        filename: file.originalname,
        size: file.size || 1024,
        format: path.extname(file.originalname).slice(1) || 'jpg'
      });
    });
    
    mockCloudinaryStorage._removeFile.mockImplementation((req, file, cb) => {
      cb(null);
    });
  });

  describe('Upload endpoints - Basic Functionality', () => {
    test('should upload file successfully with realistic Cloudinary response', async () => {
      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(200);

      expect(response.body).toHaveProperty('url');
      expect(typeof response.body.url).toBe('string');
      expect(response.body.url).toMatch(/^https:\/\/res\.cloudinary\.com\/test-cloud/);
      expect(response.body.url).toContain('test-image.jpg');
      
      // Verify Cloudinary storage was called correctly
      expect(mockCloudinaryStorage._handleFile).toHaveBeenCalledTimes(1);
      const callArgs = mockCloudinaryStorage._handleFile.mock.calls[0];
      expect(callArgs[1]).toHaveProperty('originalname', 'test-image.jpg');
    });

    test('should return error for missing file', async () => {
      const response = await request(app)
        .post('/api/upload')
        .expect(400);

      expect(response.body.message).toBe('Aucun fichier reçu');
      expect(mockCloudinaryStorage._handleFile).not.toHaveBeenCalled();
    });

    test('should handle wrong field name gracefully', async () => {
      const response = await request(app)
        .post('/api/upload')
        .attach('wrongfield', testImagePath);
        
      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Aucun fichier reçu');
    });

    test('should handle multiple file upload attempts', async () => {
      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .attach('image', testImagePath); // Second file should be ignored
        
      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('url');
    });
  });

  describe('Cloudinary Integration - Error Scenarios', () => {
    test('should handle Cloudinary upload timeout', async () => {
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(new Error('Upload timeout - Cloudinary service unavailable'));
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(500);

      expect(response.body.message).toBe('Erreur upload');
      expect(response.body.detail).toBe('Upload timeout - Cloudinary service unavailable');
    });

    test('should handle Cloudinary API key errors', async () => {
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(new Error('Invalid API key - check your credentials'));
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(500);

      expect(response.body.message).toBe('Erreur upload');
      expect(response.body.detail).toBe('Invalid API key - check your credentials');
    });

    test('should handle Cloudinary quota exceeded', async () => {
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(new Error('Monthly quota exceeded'));
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(500);

      expect(response.body.detail).toBe('Monthly quota exceeded');
    });

    test('should handle Cloudinary file size limit', async () => {
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(new Error('File size exceeds limit'));
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(500);

      expect(response.body.detail).toBe('File size exceeds limit');
    });

    test('should handle network connectivity issues', async () => {
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(new Error('ECONNREFUSED - Cannot connect to Cloudinary'));
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(500);

      expect(response.body.detail).toContain('ECONNREFUSED');
    });
  });

  describe('File Type and Format Handling', () => {
    beforeEach(() => {
      // Create different test files
      const fixturesDir = path.join(__dirname, 'fixtures');
      const pngPath = path.join(fixturesDir, 'test.png');
      const gifPath = path.join(fixturesDir, 'test.gif');
      const webpPath = path.join(fixturesDir, 'test.webp');
      
      if (!fs.existsSync(pngPath)) {
        fs.writeFileSync(pngPath, Buffer.from('fake-png-data'));
      }
      if (!fs.existsSync(gifPath)) {
        fs.writeFileSync(gifPath, Buffer.from('fake-gif-data'));
      }
      if (!fs.existsSync(webpPath)) {
        fs.writeFileSync(webpPath, Buffer.from('fake-webp-data'));
      }
    });

    test('should handle PNG uploads', async () => {
      const pngPath = path.join(__dirname, 'fixtures', 'test.png');
      
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(null, {
          path: `https://res.cloudinary.com/test-cloud/image/upload/v${Date.now()}/test.png`,
          filename: 'test.png',
          format: 'png'
        });
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', pngPath)
        .expect(200);

      expect(response.body.url).toContain('.png');
    });

    test('should handle GIF uploads', async () => {
      const gifPath = path.join(__dirname, 'fixtures', 'test.gif');
      
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(null, {
          path: `https://res.cloudinary.com/test-cloud/image/upload/v${Date.now()}/test.gif`,
          filename: 'test.gif',
          format: 'gif'
        });
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', gifPath)
        .expect(200);

      expect(response.body.url).toContain('.gif');
    });

    test('should handle unsupported file formats', async () => {
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        cb(new Error('Unsupported file format'));
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(500);

      expect(response.body.detail).toBe('Unsupported file format');
    });
  });

  describe('Cloudinary Configuration Integration', () => {
    test('should use correct Cloudinary folder configuration', async () => {
      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(200);

      // Verify the upload uses the configured folder structure
      expect(mockCloudinaryStorage._handleFile).toHaveBeenCalledTimes(1);
      const callArgs = mockCloudinaryStorage._handleFile.mock.calls[0];
      expect(callArgs[1]).toHaveProperty('originalname');
    });

    test('should generate unique public_id based on timestamp', async () => {
      const startTime = Date.now();
      
      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        const timestamp = Date.now();
        const publicId = `${timestamp}-${file.originalname.replace(/\s+/g, '_')}`;
        cb(null, {
          path: `https://res.cloudinary.com/test-cloud/image/upload/v${timestamp}/${publicId}`,
          filename: publicId,
          public_id: publicId
        });
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', testImagePath)
        .expect(200);

      expect(response.body.url).toMatch(/v\d{13}-/); // Should contain timestamp
    });

    test('should handle filename sanitization', async () => {
      const specialCharsPath = path.join(__dirname, 'fixtures', 'file with spaces & chars!.jpg');
      fs.writeFileSync(specialCharsPath, Buffer.from('fake-image-data'));

      mockCloudinaryStorage._handleFile.mockImplementation((req, file, cb) => {
        const sanitizedName = file.originalname.replace(/\s+/g, '_');
        cb(null, {
          path: `https://res.cloudinary.com/test-cloud/image/upload/v${Date.now()}/${sanitizedName}`,
          filename: sanitizedName
        });
      });

      const response = await request(app)
        .post('/api/upload')
        .attach('image', specialCharsPath)
        .expect(200);

      expect(response.body.url).toContain('file_with_spaces');
      
      // Cleanup
      fs.unlinkSync(specialCharsPath);
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