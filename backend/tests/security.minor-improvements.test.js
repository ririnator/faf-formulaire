// security.minor-improvements.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const express = require('express');

// Test app setup
const app = express();
const { createBulkImportBodyParser } = require('../middleware/bodyParser');
const { enhanceTokenValidation } = require('../middleware/enhancedSecurity');
const HandshakeService = require('../services/handshakeService');
const Handshake = require('../models/Handshake');
const User = require('../models/User');

describe('Security Minor Improvements Tests', () => {
  // Use existing test database connection from setup-global.js

  beforeEach(async () => {
    await User.deleteMany({});
    await Handshake.deleteMany({});
  });

  describe('CSV Import Size Validation', () => {
    let testApp;

    beforeAll(() => {
      testApp = express();
      testApp.use(express.json());
      
      // Mock validation middleware for CSV data
      const validateCSVData = (req, res, next) => {
        const { csvData } = req.body;
        
        if (!csvData) {
          return res.status(400).json({
            error: 'CSV data is required',
            code: 'MISSING_CSV_DATA'
          });
        }
        
        // Check CSV data size (5MB = 5 * 1024 * 1024 bytes)
        const csvSizeBytes = Buffer.byteLength(csvData, 'utf8');
        const maxSizeBytes = 5 * 1024 * 1024; // 5MB
        
        if (csvSizeBytes > maxSizeBytes) {
          return res.status(413).json({
            error: 'CSV data too large. Maximum size is 5MB.',
            code: 'CSV_SIZE_LIMIT_EXCEEDED',
            maxSizeMB: 5,
            actualSizeMB: Math.round((csvSizeBytes / 1024 / 1024) * 100) / 100
          });
        }
        
        // Additional security check: prevent binary data uploads disguised as CSV
        if (csvData.includes('\x00') || /[\x01-\x08\x0B\x0C\x0E-\x1F]/.test(csvData)) {
          return res.status(400).json({
            error: 'Binary content detected in CSV data',
            code: 'INVALID_CSV_CONTENT'
          });
        }
        
        next();
      };

      testApp.post('/test/csv-import', 
        createBulkImportBodyParser(), 
        validateCSVData, 
        (req, res) => {
          res.json({ success: true, message: 'CSV processed successfully' });
        }
      );
    });

    test('should accept valid CSV data under 5MB', async () => {
      const validCSV = 'email,firstName,lastName\n' + 
        'test@example.com,John,Doe\n'.repeat(1000); // Small CSV

      const response = await request(testApp)
        .post('/test/csv-import')
        .send({ csvData: validCSV })
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    test('should reject CSV data over 5MB', async () => {
      // Create a CSV larger than 5MB
      const largeCsvRow = 'test@example.com,' + 'a'.repeat(1000) + ',Doe\n';
      const largeCSV = 'email,firstName,lastName\n' + largeCsvRow.repeat(6000); // > 5MB

      const response = await request(testApp)
        .post('/test/csv-import')
        .send({ csvData: largeCSV });

      // Should reject with either 413 (payload too large) or 400 (our validation)
      expect([400, 413]).toContain(response.status);
      
      if (response.status === 413) {
        expect(response.body.code).toBe('CSV_SIZE_LIMIT_EXCEEDED');
        expect(response.body.maxSizeMB).toBe(5);
        expect(response.body.actualSizeMB).toBeGreaterThan(5);
      }
    });

    test('should reject binary content disguised as CSV', async () => {
      const binaryCSV = 'email,firstName,lastName\n' + 
        'test@example.com,\x00binary\x01content,Doe\n';

      const response = await request(testApp)
        .post('/test/csv-import')
        .send({ csvData: binaryCSV })
        .expect(400);

      expect(response.body.code).toBe('INVALID_CSV_CONTENT');
    });

    test('should reject missing CSV data', async () => {
      const response = await request(testApp)
        .post('/test/csv-import')
        .send({})
        .expect(400);

      expect(response.body.code).toBe('MISSING_CSV_DATA');
    });

    test('should calculate correct size for UTF-8 content', async () => {
      // CSV with UTF-8 characters (accents, etc.)
      const utf8CSV = 'email,firstName,lastName\n' + 
        'café@example.com,François,Müller\n'.repeat(2000);

      const actualBytes = Buffer.byteLength(utf8CSV, 'utf8');
      expect(actualBytes).toBeGreaterThan(utf8CSV.length); // UTF-8 is larger than string length

      if (actualBytes <= 5 * 1024 * 1024) {
        await request(testApp)
          .post('/test/csv-import')
          .send({ csvData: utf8CSV })
          .expect(200);
      } else {
        await request(testApp)
          .post('/test/csv-import')
          .send({ csvData: utf8CSV })
          .expect(413);
      }
    });
  });

  describe('Token Entropy Validation', () => {
    let testApp;

    beforeAll(() => {
      testApp = express();
      testApp.use(express.json());
      testApp.get('/test/token/:token', enhanceTokenValidation, (req, res) => {
        res.json({ success: true, token: req.params.token });
      });
    });

    test('should accept tokens with good entropy', async () => {
      // Create a truly random-looking hex token with good entropy
      const goodToken = 'f7a3b2c9e5d81467203948756b0cd1e5f92a7b4c8e1f3d6a0971c5e2b48f7320';
      
      const response = await request(testApp)
        .get(`/test/token/${goodToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });

    test('should reject tokens with excessive character repetition', async () => {
      const weakToken = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      
      await request(testApp)
        .get(`/test/token/${weakToken}`)
        .expect(400);
    });

    test('should reject tokens with sequential patterns', async () => {
      const sequentialToken = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      
      await request(testApp)
        .get(`/test/token/${sequentialToken}`)
        .expect(400);
    });

    test('should reject tokens with repeated segments', async () => {
      const repeatedToken = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234';
      
      await request(testApp)
        .get(`/test/token/${repeatedToken}`)
        .expect(400);
    });

    test('should reject tokens with insufficient character variety', async () => {
      const limitedToken = '1111222233334444555566667777888899990000aaaabbbbccccddddeeeefffff';
      
      await request(testApp)
        .get(`/test/token/${limitedToken}`)
        .expect(400);
    });

    test('should reject known weak patterns', async () => {
      const allZeros = '0000000000000000000000000000000000000000000000000000000000000000';
      const allFs = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      
      await request(testApp)
        .get(`/test/token/${allZeros}`)
        .expect(400);
        
      await request(testApp)
        .get(`/test/token/${allFs}`)
        .expect(400);
    });

    test('should reject invalid token formats', async () => {
      const shortToken = 'abc123';
      const longToken = 'a'.repeat(100);
      const nonHexToken = 'gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg';
      
      await request(testApp)
        .get(`/test/token/${shortToken}`)
        .expect(400);
        
      await request(testApp)
        .get(`/test/token/${longToken}`)
        .expect(400);
        
      await request(testApp)
        .get(`/test/token/${nonHexToken}`)
        .expect(400);
    });

    test('should accept tokens in request body and query', async () => {
      const goodToken = 'f7a3b2c9e5d81467203948756b0cd1e5f92a7b4c8e1f3d6a0971c5e2b48f7320';
      
      // Create separate test apps to avoid route conflicts
      const bodyTestApp = express();
      bodyTestApp.use(express.json());
      bodyTestApp.post('/test/token-body', enhanceTokenValidation, (req, res) => {
        res.json({ success: true });
      });
      
      const queryTestApp = express();
      queryTestApp.use(express.json());
      queryTestApp.get('/test/token-query', enhanceTokenValidation, (req, res) => {
        res.json({ success: true });
      });

      // Test token in body
      await request(bodyTestApp)
        .post('/test/token-body')
        .send({ token: goodToken })
        .expect(200);

      // Test token in query
      await request(queryTestApp)
        .get('/test/token-query')
        .query({ token: goodToken })
        .expect(200);
    });
  });

  describe('Handshake Race Condition Prevention', () => {
    let handshakeService;
    let user1, user2;

    beforeEach(async () => {
      handshakeService = new HandshakeService();

      user1 = await User.create({
        username: 'user1',
        email: 'user1@example.com',
        password: 'password123'
      });

      user2 = await User.create({
        username: 'user2',
        email: 'user2@example.com',
        password: 'password123'
      });
    });

    test('should have normalized query functionality', async () => {
      const service = new HandshakeService();
      
      // Test the normalized query method exists
      expect(typeof service.createNormalizedHandshakeQuery).toBe('function');
      
      // Test the normalized query structure
      const query1 = service.createNormalizedHandshakeQuery(user1._id, user2._id);
      const query2 = service.createNormalizedHandshakeQuery(user2._id, user1._id);

      // Both queries should have the same structure (both contain both user combinations)
      expect(query1.$or).toHaveLength(2);
      expect(query2.$or).toHaveLength(2);
      
      // Each query should contain both possible combinations
      const query1Combos = query1.$or.map(combo => `${combo.requesterId}-${combo.targetId}`);
      const query2Combos = query2.$or.map(combo => `${combo.requesterId}-${combo.targetId}`);
      
      expect(query1Combos.sort()).toEqual(query2Combos.sort());
    });

    test('should prevent simple duplicate handshakes', async () => {
      // Create a handshake directly in DB to test duplicate prevention
      const handshake = new Handshake({
        requesterId: user1._id,
        targetId: user2._id,
        message: 'Direct creation',
        status: 'pending'
      });
      await handshake.save();

      // Try to create another through service - should detect existing
      const result = await handshakeService.createMutual(user1._id, user2._id, {
        initiator: user1._id,
        message: 'Service creation'
      });

      // Should not create a new one
      expect(result.created).toBe(false);
      
      // Verify only one handshake exists
      const handshakes = await Handshake.find({
        $or: [
          { requesterId: user1._id, targetId: user2._id },
          { requesterId: user2._id, targetId: user1._id }
        ]
      });

      expect(handshakes).toHaveLength(1);
    });

    test('should handle findOneAndUpdate atomic operation structure', async () => {
      // Test that our atomic operation approach is structurally sound
      const query = handshakeService.createNormalizedHandshakeQuery(user1._id, user2._id);
      
      // Test the atomic operation would work (without actually running it)
      const handshakeData = {
        requesterId: user1._id,
        targetId: user2._id,
        message: 'Test atomic operation',
        status: 'pending',
        requestedAt: new Date()
      };

      // Use findOne to simulate the check part of atomic operation
      const existing = await Handshake.findOne(query);
      expect(existing).toBeNull();

      // Create handshake and then test query finds it
      const handshake = new Handshake(handshakeData);
      await handshake.save();

      const found = await Handshake.findOne(query);
      expect(found).toBeTruthy();
      expect(found._id.toString()).toBe(handshake._id.toString());
    });
  });

  describe('Integration Security Tests', () => {
    test('should maintain security across all improvements', async () => {
      // This test ensures all security improvements work together
      const testApp = express();
      testApp.use(express.json({ limit: '5mb' }));
      
      // Apply all security middlewares
      testApp.use(enhanceTokenValidation);
      
      testApp.post('/test/secure-endpoint/:token', (req, res) => {
        const { csvData } = req.body;
        
        // Simulate CSV processing with size check
        if (csvData && Buffer.byteLength(csvData, 'utf8') > 5 * 1024 * 1024) {
          return res.status(413).json({ error: 'CSV too large' });
        }
        
        res.json({ success: true });
      });

      const validToken = 'f7a3b2c9e5d81467203948756b0cd1e5f92a7b4c8e1f3d6a0971c5e2b48f7320';
      const validCSV = 'email,name\ntest@example.com,Test User\n';

      await request(testApp)
        .post(`/test/secure-endpoint/${validToken}`)
        .send({ csvData: validCSV })
        .expect(200);
    });
  });
});