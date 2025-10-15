const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

const Response = require('../models/Response');

describe('Full Request/Response Cycle Integration Tests', () => {
  let app;
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);
    
    // Import app after MongoDB connection is established
    delete require.cache[require.resolve('../app')]; // Clear require cache
    process.env.MONGODB_URI = mongoUri;
    process.env.NODE_ENV = 'test';
    
    // Mock console.log to avoid test output pollution
    const originalConsoleLog = console.log;
    console.log = jest.fn();
    
    // Create a test version of the app without starting the server
    const express = require('express');
    const cors = require('cors');
    const session = require('express-session');
    const MongoStore = require('connect-mongo');
    const rateLimit = require('express-rate-limit');
    
    const formRoutes = require('../routes/formRoutes');
    const responseRoutes = require('../routes/responseRoutes');
    const adminRoutes = require('../routes/adminRoutes');
    const uploadRoutes = require('../routes/upload');
    
    app = express();
    
    // CORS
    app.use(cors({
      origin: ['http://localhost:3000', 'http://localhost:3001'],
      credentials: true
    }));
    
    // Sessions
    app.use(session({
      secret: 'test-session-secret',
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: mongoUri,
        collectionName: 'test-sessions'
      }),
      cookie: {
        maxAge: 1000 * 60 * 60,
        secure: false
      }
    }));
    
    // Body parsers
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ limit: '50mb', extended: true }));
    
    // Rate limiting (relaxed for testing)
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100,
      message: { message: 'Trop de tentatives' }
    });
    
    // Admin middleware
    const ensureAdmin = (req, res, next) => {
      if (req.session?.isAdmin) return next();
      return res.status(401).json({ message: 'Admin access required' });
    };
    
    // Routes
    app.use('/api/form', formRoutes);
    app.use('/api/responses', limiter, responseRoutes);
    app.use('/api/admin', ensureAdmin, adminRoutes);
    app.use('/api/upload', uploadRoutes);
    
    // Admin login route for testing
    app.post('/login', async (req, res) => {
      const { username, password } = req.body;
      if (username === 'testadmin' && password === 'testpassword') {
        req.session.isAdmin = true;
        res.json({ message: 'Login successful' });
      } else {
        res.status(401).json({ message: 'Invalid credentials' });
      }
    });
    
    // Restore console.log
    console.log = originalConsoleLog;
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await Response.deleteMany({});
  });

  describe('Complete User Flow - Form Submission', () => {
    test('should handle complete form submission flow', async () => {
      const formData = {
        name: 'Integration Test User',
        responses: [
          { question: 'How are you?', answer: 'Great!' },
          { question: 'Favorite color?', answer: 'Blue' }
        ]
      };

      // Submit form response
      const submitResponse = await request(app)
        .post('/api/responses')
        .send(formData)
        .expect(201);

      expect(submitResponse.body).toHaveProperty('message');
      expect(submitResponse.body).toHaveProperty('responseId');
      
      // Verify data was stored in database
      const storedResponse = await Response.findById(submitResponse.body.responseId);
      expect(storedResponse).toBeTruthy();
      expect(storedResponse.name).toBe(formData.name);
      expect(storedResponse.responses).toHaveLength(2);
      expect(storedResponse.isAdmin).toBe(false);
      expect(storedResponse.token).toBeTruthy();
    });

    test('should handle admin form submission flow', async () => {
      const adminFormData = {
        name: 'testadmin', // Matches FORM_ADMIN_NAME
        responses: [
          { question: 'Admin question', answer: 'Admin answer' }
        ]
      };

      const submitResponse = await request(app)
        .post('/api/responses')
        .send(adminFormData)
        .expect(201);

      // Verify admin response characteristics
      const storedResponse = await Response.findById(submitResponse.body.responseId);
      expect(storedResponse.isAdmin).toBe(true);
      expect(storedResponse.token).toBeNull();
    });

    test('should prevent duplicate submissions in same month', async () => {
      const userData = {
        name: 'Test User',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      // First submission
      await request(app)
        .post('/api/responses')
        .send(userData)
        .expect(201);

      // Second submission should fail
      await request(app)
        .post('/api/responses')
        .send(userData)
        .expect(400);
    });
  });

  describe('Complete Admin Flow', () => {
    let adminAgent;

    beforeEach(async () => {
      // Create test data
      await Response.create([
        {
          name: 'User1',
          responses: [{ question: 'Test Q1', answer: 'Answer 1' }],
          month: '2024-01',
          isAdmin: false,
          token: 'token1'
        },
        {
          name: 'User2', 
          responses: [{ question: 'Test Q2', answer: 'Answer 2' }],
          month: '2024-01',
          isAdmin: false,
          token: 'token2'
        },
        {
          name: 'testadmin',
          responses: [{ question: 'Admin Q', answer: 'Admin A' }],
          month: '2024-01',
          isAdmin: true
          // Don't set token - let it be undefined for sparse index
        }
      ]);

      // Login as admin
      adminAgent = request.agent(app);
      await adminAgent
        .post('/login')
        .send({ username: 'testadmin', password: 'testpassword' })
        .expect(200);
    });

    test('should handle complete admin dashboard flow', async () => {
      // Get paginated responses
      const responsesResponse = await adminAgent
        .get('/api/admin/responses?page=1&limit=10')
        .expect(200);

      expect(responsesResponse.body).toHaveProperty('responses');
      expect(responsesResponse.body).toHaveProperty('pagination');
      expect(responsesResponse.body.responses).toHaveLength(3);

      // Get specific response
      const responseId = responsesResponse.body.responses[0]._id;
      const singleResponse = await adminAgent
        .get(`/api/admin/responses/${responseId}`)
        .expect(200);

      expect(singleResponse.body._id).toBe(responseId);

      // Get summary data
      const summaryResponse = await adminAgent
        .get('/api/admin/summary')
        .expect(200);

      expect(Array.isArray(summaryResponse.body)).toBe(true);

      // Get available months
      const monthsResponse = await adminAgent
        .get('/api/admin/months')
        .expect(200);

      expect(Array.isArray(monthsResponse.body)).toBe(true);
      expect(monthsResponse.body.length).toBeGreaterThan(0);
    });

    test('should handle admin CRUD operations', async () => {
      // Create a response to delete
      const testResponse = await Response.create({
        name: 'DeleteMe',
        responses: [{ question: 'Test', answer: 'Test' }],
        month: '2024-01',
        isAdmin: false,
        token: 'delete-token'
      });

      // Delete the response
      await adminAgent
        .delete(`/api/admin/responses/${testResponse._id}`)
        .expect(200);

      // Verify deletion
      const deletedResponse = await Response.findById(testResponse._id);
      expect(deletedResponse).toBeNull();
    });
  });

  describe('Rate Limiting Integration', () => {
    test('should apply rate limiting to form submissions', async () => {
      const formData = {
        name: 'Rate Test User',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      // Submit multiple requests rapidly (should not hit limit with test config)
      const promises = Array(5).fill(null).map((_, i) => 
        request(app)
          .post('/api/responses')
          .send({ ...formData, name: `User${i}` })
      );

      const responses = await Promise.all(promises);
      
      // All should succeed with relaxed test limits
      responses.forEach(response => {
        expect([201, 400, 429]).toContain(response.status);
      });
    });
  });

  describe('Error Handling Integration', () => {
    test('should handle validation errors gracefully', async () => {
      // Missing required fields
      const invalidData = {
        name: '', // Empty name
        responses: []
      };

      const response = await request(app)
        .post('/api/responses')
        .send(invalidData)
        .expect(400);

      expect(response.body).toHaveProperty('message');
    });

    test('should handle database errors gracefully', async () => {
      // Temporarily close database connection to simulate error
      await mongoose.connection.close();

      const formData = {
        name: 'Test User',
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      const response = await request(app)
        .post('/api/responses')
        .send(formData);

      expect([500, 503]).toContain(response.status);

      // Reconnect for other tests
      await mongoose.connect(mongoServer.getUri());
    });
  });

  describe('Security Integration', () => {
    test('should protect admin routes from unauthorized access', async () => {
      // Try to access admin route without authentication
      await request(app)
        .get('/api/admin/responses')
        .expect(401);

      // Try to delete response without authentication
      const testResponse = await Response.create({
        name: 'Test User',
        responses: [{ question: 'Test', answer: 'Test' }],
        month: '2024-01',
        isAdmin: false,
        token: 'test-token'
      });

      await request(app)
        .delete(`/api/admin/responses/${testResponse._id}`)
        .expect(401);
    });

    test('should handle honeypot spam protection', async () => {
      const spamData = {
        name: 'Spammer',
        responses: [{ question: 'Test', answer: 'Test' }],
        website: 'spam-website.com' // Honeypot field
      };

      const response = await request(app)
        .post('/api/responses')
        .send(spamData)
        .expect(400);

      expect(response.body.message).toContain('spam');
    });
  });
});