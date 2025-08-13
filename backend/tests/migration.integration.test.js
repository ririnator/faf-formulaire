// Migration scenarios integration tests
const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const TokenGenerator = require('../utils/tokenGenerator');
const app = require('../app');
const User = require('../models/User');
const Response = require('../models/Response');

describe('Migration Integration Tests', () => {
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
  });

  describe('Legacy to User Migration', () => {
    let legacyToken;
    let legacyResponses;

    beforeEach(async () => {
      // Create legacy responses
      legacyToken = TokenGenerator.generateTestToken(32);
      
      legacyResponses = [
        {
          name: 'Jean Dupont',
          responses: [
            { question: 'Q1', answer: 'A1' },
            { question: 'Q2', answer: 'A2' }
          ],
          month: '2024-01',
          token: legacyToken,
          authMethod: 'token'
        },
        {
          name: 'Jean Dupont',
          responses: [
            { question: 'Q1', answer: 'A1' }
          ],
          month: '2024-02',
          token: TokenGenerator.generateTestToken(32),
          authMethod: 'token'
        },
        {
          name: 'Jean Dupont',
          responses: [
            { question: 'Q1', answer: 'A1' }
          ],
          month: '2024-03',
          token: TokenGenerator.generateTestToken(32),
          authMethod: 'token'
        }
      ];

      await Response.insertMany(legacyResponses);
    });

    test('should migrate legacy responses during registration', async () => {
      const newUser = {
        username: 'jeandupont',
        email: 'jean@example.com',
        password: 'SecurePass123!',
        migrateToken: legacyToken
      };

      const res = await request(app)
        .post('/api/auth/register')
        .send(newUser)
        .expect(201);

      expect(res.body.migrated).toBe(true);
      expect(res.body.migratedCount).toBe(3);

      // Verify user created
      const user = await User.findOne({ username: newUser.username });
      expect(user).toBeTruthy();
      expect(user.metadata.responseCount).toBe(3);
      expect(user.migrationData.legacyName).toBe('Jean Dupont');
      expect(user.migrationData.source).toBe('migration');

      // Verify responses migrated
      const migratedResponses = await Response.find({ userId: user._id });
      expect(migratedResponses).toHaveLength(3);
      
      migratedResponses.forEach(response => {
        expect(response.authMethod).toBe('user');
        expect(response.token).toBeUndefined();
        expect(response.name).toBeUndefined();
        expect(response.userId.toString()).toBe(user._id.toString());
      });

      // Verify original responses no longer have tokens
      const oldResponses = await Response.find({ name: 'Jean Dupont' });
      expect(oldResponses).toHaveLength(0);
    });

    test('should handle migration with invalid token', async () => {
      const newUser = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'SecurePass123!',
        migrateToken: 'invalid-token-here'
      };

      const res = await request(app)
        .post('/api/auth/register')
        .send(newUser)
        .expect(201);

      expect(res.body.migrated).toBeFalsy();
      expect(res.body.migratedCount).toBe(0);

      // User should still be created
      const user = await User.findOne({ username: newUser.username });
      expect(user).toBeTruthy();
      expect(user.metadata.responseCount).toBe(0);
      expect(user.migrationData.source).toBe('registration');
    });

    test('should handle partial migration failure gracefully', async () => {
      // Create a response that will cause issues
      await Response.create({
        name: 'Jean Dupont',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-04',
        authMethod: 'user', // Already migrated
        userId: new mongoose.Types.ObjectId()
      });

      const newUser = {
        username: 'jeandupont2',
        email: 'jean2@example.com',
        password: 'SecurePass123!',
        migrateToken: legacyToken
      };

      const res = await request(app)
        .post('/api/auth/register')
        .send(newUser)
        .expect(201);

      // Should still succeed but only migrate unmigrated responses
      expect(res.body.message).toContain('Compte créé');
      expect(res.body.migratedCount).toBe(3); // Only the token-based ones

      const user = await User.findOne({ username: newUser.username });
      expect(user).toBeTruthy();
    });

    test('should prevent duplicate migration', async () => {
      // First migration
      const user1 = {
        username: 'user1',
        email: 'user1@example.com',
        password: 'SecurePass123!',
        migrateToken: legacyToken
      };

      await request(app)
        .post('/api/auth/register')
        .send(user1)
        .expect(201);

      // Second migration attempt with same token
      const user2 = {
        username: 'user2',
        email: 'user2@example.com',
        password: 'SecurePass123!',
        migrateToken: legacyToken
      };

      const res = await request(app)
        .post('/api/auth/register')
        .send(user2)
        .expect(201);

      // User created but no responses migrated (already migrated)
      expect(res.body.migratedCount).toBe(0);
    });
  });

  describe('Hybrid Authentication', () => {
    let userAgent;
    let legacyToken;

    beforeEach(async () => {
      userAgent = request.agent(app);
      
      // Create a user account
      await userAgent
        .post('/api/auth/register')
        .send({
          username: 'hybriduser',
          email: 'hybrid@example.com',
          password: 'Pass123!'
        });

      // Create a legacy response
      legacyToken = TokenGenerator.generateTestToken(32);
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-01',
        token: legacyToken,
        authMethod: 'token'
      });
    });

    test('should handle user auth submission', async () => {
      // Login first
      await userAgent
        .post('/api/auth/login')
        .send({
          login: 'hybriduser',
          password: 'Pass123!'
        });

      // Submit response as authenticated user
      const res = await userAgent
        .post('/api/responses')
        .send({
          responses: [
            { question: 'Q1', answer: 'A1' }
          ]
        })
        .expect(201);

      expect(res.body.success).toBe(true);
      
      // Verify response in DB
      const response = await Response.findOne({ 
        authMethod: 'user'
      });
      expect(response).toBeTruthy();
      expect(response.userId).toBeTruthy();
      expect(response.token).toBeNull();
    });

    test('should handle legacy token submission', async () => {
      const res = await request(app)
        .post('/api/responses')
        .send({
          name: 'Another Legacy',
          responses: [
            { question: 'Q2', answer: 'A2' }
          ]
        })
        .expect(201);

      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeTruthy();
      expect(res.body.viewLink).toContain('/view/');

      // Verify response in DB
      const response = await Response.findOne({ 
        name: 'Another Legacy'
      });
      expect(response).toBeTruthy();
      expect(response.authMethod).toBe('token');
      expect(response.token).toBeTruthy();
      expect(response.userId).toBeUndefined();
    });

    test('should view responses with both auth methods', async () => {
      // View with token
      const tokenRes = await request(app)
        .get(`/api/view/${legacyToken}`)
        .expect(200);

      expect(tokenRes.body).toHaveProperty('name', 'Legacy User');

      // View as authenticated user
      await userAgent
        .post('/api/auth/login')
        .send({
          login: 'hybriduser',
          password: 'Pass123!'
        });

      // Create user response first
      await userAgent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q', answer: 'A' }]
        });

      const userRes = await userAgent
        .get('/api/auth/responses')
        .expect(200);

      expect(userRes.body.responses).toHaveLength(1);
    });
  });

  describe('Admin Migration Scenarios', () => {
    beforeEach(async () => {
      // Set admin environment variable
      process.env.FORM_ADMIN_NAME = 'admin';

      // Create admin user
      await User.create({
        username: 'adminuser',
        email: 'admin@example.com',
        password: await require('bcrypt').hash('AdminPass123!', 12),
        role: 'admin'
      });

      // Create legacy admin responses
      await Response.create({
        name: 'admin',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-01',
        isAdmin: true,
        authMethod: 'token'
      });
    });

    test('should handle admin response migration', async () => {
      const agent = request.agent(app);
      
      // Login as admin
      await agent
        .post('/api/auth/login')
        .send({
          login: 'adminuser',
          password: 'AdminPass123!'
        })
        .expect(200);

      // Try to submit new admin response
      const res = await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q2', answer: 'A2' }]
        })
        .expect(409); // Should conflict with existing admin response

      expect(res.body.error).toContain('admin existe déjà');
    });

    test('should prevent duplicate admin responses', async () => {
      // Try to create another legacy admin response
      const res = await request(app)
        .post('/api/responses')
        .send({
          name: 'admin',
          responses: [{ question: 'Q3', answer: 'A3' }]
        })
        .expect(409);

      expect(res.body.error).toContain('admin existe déjà');
    });
  });

  describe('Error Recovery', () => {
    test('should recover from database errors during migration', async () => {
      // Temporarily break database connection
      const originalUpdateMany = Response.updateMany;
      Response.updateMany = jest.fn().mockRejectedValue(new Error('DB Error'));

      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'errortest',
          email: 'error@test.com',
          password: 'Pass123!',
          migrateToken: 'some-token'
        })
        .expect(201);

      // User should still be created despite migration failure
      expect(res.body.message).toContain('Compte créé');
      
      const user = await User.findOne({ username: 'errortest' });
      expect(user).toBeTruthy();

      // Restore original method
      Response.updateMany = originalUpdateMany;
    });

    test('should handle session errors gracefully', async () => {
      // Mock session error
      const originalStartSession = mongoose.startSession;
      mongoose.startSession = jest.fn().mockRejectedValue(new Error('Session Error'));

      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'sessionerror',
          email: 'session@error.com',
          password: 'Pass123!'
        })
        .expect(201);

      // Registration should still succeed
      expect(res.body.message).toContain('Compte créé');

      // Restore original method
      mongoose.startSession = originalStartSession;
    });
  });
});