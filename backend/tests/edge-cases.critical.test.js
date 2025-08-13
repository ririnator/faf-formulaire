// Critical Edge Cases for Production Readiness
const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const User = require('../models/User');
const Response = require('../models/Response');
const TokenGenerator = require('../utils/tokenGenerator');

// Mock app with actual middleware
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');

describe('Critical Edge Cases for Production', () => {
  let mongoServer;
  let app;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);

    // Setup test app with real middleware
    app = express();
    app.use(express.json());
    app.use(session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({ mongoUrl: mongoUri }),
      cookie: { maxAge: 60000 }
    }));
    
    // Import routes after DB connection
    const authRoutes = require('../routes/authRoutes');
    const responseRoutes = require('../routes/responseRoutes');
    app.use('/api/auth', authRoutes);
    app.use('/api/responses', responseRoutes);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    process.env.FORM_ADMIN_NAME = 'testadmin';
  });

  describe('Concurrent Admin Creation', () => {
    test('should prevent multiple admins in same month with race conditions', async () => {
      // Create admin user
      const adminUser = await User.create({
        username: 'admin1',
        email: 'admin1@test.com',
        password: 'AdminPass123!',
        role: 'admin'
      });

      const adminUser2 = await User.create({
        username: 'admin2', 
        email: 'admin2@test.com',
        password: 'AdminPass123!',
        role: 'admin'
      });

      // Login both admins
      const agent1 = request.agent(app);
      const agent2 = request.agent(app);

      await agent1.post('/api/auth/login').send({
        login: 'admin1',
        password: 'AdminPass123!'
      });

      await agent2.post('/api/auth/login').send({
        login: 'admin2', 
        password: 'AdminPass123!'
      });

      // Concurrent admin response submissions
      const responseData = {
        responses: [{ question: 'Q1', answer: 'A1' }]
      };

      const concurrentPromises = [
        agent1.post('/api/responses').send(responseData),
        agent2.post('/api/responses').send(responseData)
      ];

      const results = await Promise.all(concurrentPromises);

      // One should succeed, one should fail with conflict
      const successes = results.filter(r => r.status === 201);
      const conflicts = results.filter(r => r.status === 409);

      expect(successes).toHaveLength(1);
      expect(conflicts).toHaveLength(1);
      expect(conflicts[0].body.error).toContain('admin existe déjà');

      // Verify only one admin response in DB
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(1);
    });

    test('should handle legacy admin + user admin conflict', async () => {
      // Create legacy admin response first
      await Response.create({
        name: 'testadmin',
        responses: [{ question: 'Q1', answer: 'Legacy Admin' }],
        month: new Date().toISOString().slice(0, 7),
        isAdmin: true,
        authMethod: 'token'
      });

      // Now try to create user admin response
      const adminUser = await User.create({
        username: 'newadmin',
        email: 'newadmin@test.com', 
        password: 'AdminPass123!',
        role: 'admin'
      });

      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: 'newadmin',
        password: 'AdminPass123!'
      });

      const response = await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q1', answer: 'User Admin' }]
        })
        .expect(409);

      expect(response.body.error).toContain('admin existe déjà');
    });
  });

  describe('User Deactivation Edge Cases', () => {
    let testUser;
    let agent;

    beforeEach(async () => {
      testUser = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'TestPass123!'
      });

      agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: 'testuser',
        password: 'TestPass123!'
      });
    });

    test('should handle user deactivation during active session', async () => {
      // User creates a response
      await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q1', answer: 'A1' }]
        })
        .expect(201);

      // Deactivate user
      await User.findByIdAndUpdate(testUser._id, {
        'metadata.isActive': false
      });

      // Try to access profile - should fail
      const profileResponse = await agent
        .get('/api/auth/me')
        .expect(401);

      expect(profileResponse.body.error).toContain('Non authentifié');

      // Try to create another response - should fail
      await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q2', answer: 'A2' }]
        })
        .expect(401);
    });

    test('should handle user deletion during migration', async () => {
      const legacyToken = TokenGenerator.generateTestToken(32);
      
      // Create legacy response
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Q1', answer: 'A1' }],
        month: '2024-01',
        token: legacyToken,
        authMethod: 'token'
      });

      // Start registration with migration
      const registrationData = {
        username: 'migrateuser',
        email: 'migrate@test.com',
        password: 'MigratePass123!',
        migrateToken: legacyToken
      };

      // Mock user deletion during migration
      const originalSave = User.prototype.save;
      let saveCallCount = 0;
      
      User.prototype.save = async function(options) {
        saveCallCount++;
        // Delete user on second save call (during migration)
        if (saveCallCount === 2) {
          await User.findByIdAndDelete(this._id);
        }
        return originalSave.call(this, options);
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(registrationData)
        .expect(201);

      // Registration should succeed despite migration issues
      expect(response.body.message).toContain('Compte créé');

      // Restore original save method
      User.prototype.save = originalSave;
    });
  });

  describe('Session Edge Cases', () => {
    test('should handle session corruption', async () => {
      const user = await User.create({
        username: 'sessionuser',
        email: 'session@test.com',
        password: 'SessionPass123!'
      });

      const agent = request.agent(app);
      
      // Login successfully
      await agent.post('/api/auth/login').send({
        login: 'sessionuser',
        password: 'SessionPass123!'
      }).expect(200);

      // Corrupt session by deleting user
      await User.findByIdAndDelete(user._id);

      // Next request should handle corrupted session gracefully
      const response = await agent
        .get('/api/auth/me')
        .expect(401);

      expect(response.body.error).toContain('Non authentifié');
    });

    test('should handle concurrent session modifications', async () => {
      const user = await User.create({
        username: 'concurrentuser',
        email: 'concurrent@test.com',
        password: 'ConcurrentPass123!'
      });

      // Create multiple agents for same user
      const agents = Array(3).fill(null).map(() => request.agent(app));

      // Login all agents simultaneously
      const loginPromises = agents.map(agent => 
        agent.post('/api/auth/login').send({
          login: 'concurrentuser',
          password: 'ConcurrentPass123!'
        })
      );

      const loginResults = await Promise.all(loginPromises);
      loginResults.forEach(result => expect(result.status).toBe(200));

      // Concurrent profile updates
      const updatePromises = agents.map((agent, index) => 
        agent.put('/api/auth/profile').send({
          username: `UpdatedName${index}`
        })
      );

      const updateResults = await Promise.all(updatePromises);
      
      // All should succeed (last one wins)
      updateResults.forEach(result => expect(result.status).toBe(200));

      // Verify final state
      const finalUser = await User.findById(user._id);
      expect(finalUser.username).toMatch(/UpdatedName\d/);
    });
  });

  describe('Database Connection Edge Cases', () => {
    test('should handle DB disconnection gracefully', async () => {
      // Mock DB disconnection during user creation
      const originalCreate = User.create;
      User.create = jest.fn().mockRejectedValue(new Error('Database connection lost'));

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'dbtest',
          email: 'db@test.com', 
          password: 'DbTest123!'
        })
        .expect(500);

      expect(response.body.error).toBe('Erreur serveur');

      // Restore original method
      User.create = originalCreate;
    });

    test('should handle migration DB errors gracefully', async () => {
      const legacyToken = TokenGenerator.generateTestToken(32);
      
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Q1', answer: 'A1' }],
        month: '2024-01',
        token: legacyToken,
        authMethod: 'token'
      });

      // Mock DB error during migration
      const originalUpdateMany = Response.updateMany;
      Response.updateMany = jest.fn().mockRejectedValue(new Error('Migration DB error'));

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'migrationerror',
          email: 'error@test.com',
          password: 'ErrorPass123!',
          migrateToken: legacyToken
        })
        .expect(201);

      // User should still be created despite migration error
      expect(response.body.message).toContain('Compte créé');
      expect(response.body.migratedCount).toBe(0);

      // Verify user exists
      const user = await User.findOne({ username: 'migrationerror' });
      expect(user).toBeTruthy();

      // Restore original method
      Response.updateMany = originalUpdateMany;
    });
  });

  describe('Input Validation Edge Cases', () => {
    test('should handle malformed JSON gracefully', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);

      // Should not crash server
      expect(response.body).toBeDefined();
    });

    test('should handle extremely long inputs', async () => {
      const longString = 'a'.repeat(10000);
      
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: longString,
          email: 'long@test.com',
          password: 'LongTest123!'
        })
        .expect(400);

      expect(response.body.error).toBe('Données invalides');
    });

    test('should handle null/undefined values', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: null,
          email: undefined,
          password: ''
        })
        .expect(400);

      expect(response.body.error).toBe('Données invalides');
    });
  });

  describe('Memory and Resource Edge Cases', () => {
    test('should handle multiple rapid requests', async () => {
      const promises = Array(20).fill(null).map((_, i) => 
        request(app)
          .post('/api/auth/register')
          .send({
            username: `rapiduser${i}`,
            email: `rapid${i}@test.com`,
            password: 'RapidPass123!'
          })
      );

      const results = await Promise.all(promises);
      
      // All should either succeed or fail gracefully (no crashes)
      results.forEach(result => {
        expect([200, 201, 400, 409, 429, 500]).toContain(result.status);
      });

      // Check that successful registrations actually created users
      const successfulResults = results.filter(r => r.status === 201);
      const userCount = await User.countDocuments();
      expect(userCount).toBe(successfulResults.length);
    });

    test('should handle large response payloads', async () => {
      const user = await User.create({
        username: 'largeuser',
        email: 'large@test.com',
        password: 'LargePass123!'
      });

      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: 'largeuser',
        password: 'LargePass123!'
      });

      // Create response with maximum allowed data
      const largeResponses = Array(20).fill(null).map((_, i) => ({
        question: `Question ${i}`.padEnd(500, 'x'), // Max question length
        answer: 'A'.repeat(10000) // Max answer length
      }));

      const response = await agent
        .post('/api/responses')
        .send({ responses: largeResponses })
        .expect(201);

      expect(response.body.success).toBe(true);

      // Verify data was stored correctly
      const storedResponse = await Response.findOne({ userId: user._id });
      expect(storedResponse.responses).toHaveLength(20);
    });
  });

  describe('Security Edge Cases', () => {
    test('should handle authentication bypass attempts', async () => {
      // Attempt to access protected route without proper session
      const response = await request(app)
        .get('/api/auth/me')
        .set('Cookie', 'faf.session=fake-session-id')
        .expect(401);

      expect(response.body.error).toContain('Non authentifié');
    });

    test('should handle token manipulation attempts', async () => {
      const user = await User.create({
        username: 'tokenuser',
        email: 'token@test.com',
        password: 'TokenPass123!'
      });

      // Create response first
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: 'tokenuser',
        password: 'TokenPass123!'
      });

      await agent.post('/api/responses').send({
        responses: [{ question: 'Q1', answer: 'A1' }]
      });

      // Try to modify user data through response API
      const maliciousResponse = await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q2', answer: 'A2' }],
          userId: 'different-user-id', // Should be ignored
          isAdmin: true, // Should be ignored
          authMethod: 'admin' // Should be ignored
        })
        .expect(409); // Should conflict with existing response

      expect(maliciousResponse.body.error).toContain('déjà répondu');
    });
  });
});