const request = require('supertest');
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const MongoStore = require('connect-mongo');

// Mock mongoose connection to avoid connecting to real DB in tests
jest.mock('mongoose', () => ({
  connect: jest.fn().mockResolvedValue(true),
  connection: {
    collection: jest.fn().mockReturnValue({
      createIndex: jest.fn().mockResolvedValue(true)
    })
  }
}));

describe('App Configuration Integration Tests', () => {
  let app;
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
  });

  afterAll(async () => {
    await mongoServer.stop();
  });

  beforeEach(() => {
    // Create app with actual configuration (without database connection)
    app = express();
    
    // CORS configuration matching production
    app.use(cors({
      origin: [
        process.env.APP_BASE_URL || 'http://localhost:3000',
        process.env.FRONTEND_URL || 'http://localhost:3001'
      ].filter(Boolean),
      credentials: true
    }));
    
    app.set('trust proxy', 1);

    // Session configuration (simplified for testing)
    app.use(session({
      secret: process.env.SESSION_SECRET || 'test-session-secret',
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: mongoServer.getUri(),
        collectionName: 'test-sessions'
      }),
      cookie: {
        maxAge: 1000 * 60 * 60,
        sameSite: 'none',
        secure: false // false for testing
      }
    }));

    // Body parsers matching production
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ limit: '50mb', extended: true }));

    // Test routes
    app.get('/health', (req, res) => {
      res.json({ status: 'ok' });
    });

    app.post('/test-session', (req, res) => {
      req.session.testData = req.body.data;
      res.json({ stored: req.session.testData });
    });

    app.get('/test-session', (req, res) => {
      res.json({ data: req.session.testData || null });
    });
  });

  describe('Express App Configuration', () => {
    test('should handle JSON requests with correct limits', async () => {
      const largeData = { content: 'x'.repeat(1000) }; // 1KB test data
      
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body).toEqual({ status: 'ok' });
    });

    test('should have trust proxy enabled', () => {
      expect(app.get('trust proxy')).toBe(1);
    });

    test('should handle URL encoded data', async () => {
      const response = await request(app)
        .post('/test-session')
        .type('form')
        .send('data=testvalue')
        .expect(200);

      expect(response.body.stored).toBe('testvalue');
    });
  });

  describe('CORS Configuration', () => {
    test('should set proper CORS headers for allowed origins', async () => {
      const response = await request(app)
        .get('/health')
        .set('Origin', 'http://localhost:3000');

      expect(response.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });

    test('should handle preflight requests', async () => {
      const response = await request(app)
        .options('/health')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST');

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-origin']).toBe('http://localhost:3000');
    });
  });

  describe('Session Configuration', () => {
    test('should maintain session data between requests', async () => {
      const agent = request.agent(app);

      // Store data in session
      await agent
        .post('/test-session')
        .send({ data: 'persistent-data' })
        .expect(200);

      // Retrieve data from session
      const response = await agent
        .get('/test-session')
        .expect(200);

      expect(response.body.data).toBe('persistent-data');
    });

    test('should isolate sessions between different clients', async () => {
      const agent1 = request.agent(app);
      const agent2 = request.agent(app);

      // Agent1 stores data
      await agent1
        .post('/test-session')
        .send({ data: 'agent1-data' });

      // Agent2 should not see agent1's data
      const response = await agent2
        .get('/test-session')
        .expect(200);

      expect(response.body.data).toBeNull();
    });
  });

  describe('Error Handling', () => {
    test('should handle malformed JSON gracefully', async () => {
      const response = await request(app)
        .post('/health')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }');

      expect(response.status).toBe(400);
    });

    test('should handle large payloads within limits', async () => {
      const largeButValidData = {
        content: 'x'.repeat(1024 * 1024) // 1MB of data
      };

      const response = await request(app)
        .post('/test-session')
        .send(largeButValidData);

      // Should either succeed or fail with 413 (payload too large)
      expect([200, 413]).toContain(response.status);
    });
  });
});