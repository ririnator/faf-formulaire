// Production-Ready Authentication Test Suite
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const User = require('../models/User');
const Response = require('../models/Response');
const TokenGenerator = require('../utils/tokenGenerator');

describe('🚀 Production Authentication Test Suite', () => {
  let testUser;
  let adminUser;

  beforeEach(async () => {
    // Create test users for each test
    testUser = {
      username: 'produser',
      email: 'prod@test.com',
      password: 'ProductionPass123!',
      displayName: 'Production User'
    };

    adminUser = {
      username: 'prodadmin',
      email: 'admin@test.com',
      password: 'AdminPass123!',
      displayName: 'Production Admin',
      role: 'admin'
    };

    // Set admin name for tests
    process.env.FORM_ADMIN_NAME = 'prodadmin';
  });

  describe('📝 Complete Registration Flow', () => {
    test('should register new user with validation', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(201);

      expect(response.body.message).toBe('Compte créé avec succès');
      expect(response.body.user.username).toBe(testUser.username);
      expect(response.body.user.email).toBe(testUser.email.toLowerCase());
      expect(response.body.user).not.toHaveProperty('password');

      // Verify user in database
      const dbUser = await User.findOne({ username: testUser.username });
      expect(dbUser).toBeTruthy();
      expect(dbUser.metadata.isActive).toBe(true);
      expect(dbUser.role).toBe('user');
    });

    test('should prevent duplicate registration', async () => {
      // First registration
      await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(201);

      // Duplicate attempt
      const response = await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(409);

      expect(response.body.error).toContain('déjà utilisé');
    });

    test('should validate required fields', async () => {
      const invalidUser = {
        username: 'ab', // Too short
        email: 'invalid-email',
        password: '123' // Too short
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(invalidUser)
        .expect(400);

      expect(response.body.error).toBe('Données invalides');
      expect(response.body.details).toBeInstanceOf(Array);
      expect(response.body.details.length).toBeGreaterThan(0);
    });
  });

  describe('🔐 Complete Login Flow', () => {
    beforeEach(async () => {
      // Register user first
      await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(201);
    });

    test('should login with username', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          login: testUser.username,
          password: testUser.password
        })
        .expect(200);

      expect(response.body.message).toBe('Connexion réussie');
      expect(response.body.user.username).toBe(testUser.username);
      expect(response.headers['set-cookie']).toBeDefined();
    });

    test('should login with email', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          login: testUser.email,
          password: testUser.password
        })
        .expect(200);

      expect(response.body.message).toBe('Connexion réussie');
      expect(response.body.user.email).toBe(testUser.email.toLowerCase());
    });

    test('should reject invalid credentials', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          login: testUser.username,
          password: 'wrongpassword'
        })
        .expect(401);

      expect(response.body.error).toContain('incorrect');
    });
  });

  describe('🔄 Token → User Migration Testing', () => {
    let legacyToken;
    let legacyResponses;

    beforeEach(async () => {
      legacyToken = TokenGenerator.generateTestToken(32);
      
      // Create legacy responses
      legacyResponses = [
        {
          name: 'Legacy User',
          responses: [{ question: 'Q1', answer: 'A1' }],
          month: '2024-01',
          token: legacyToken,
          authMethod: 'token'
        },
        {
          name: 'Legacy User',
          responses: [{ question: 'Q2', answer: 'A2' }],
          month: '2024-02',
          token: TokenGenerator.generateTestToken(32),
          authMethod: 'token'
        }
      ];

      await Response.insertMany(legacyResponses);
    });

    test('should migrate legacy responses during registration', async () => {
      const migrationUser = {
        ...testUser,
        username: 'migrateduser',
        email: 'migrated@test.com',
        displayName: 'Legacy User',
        migrateToken: legacyToken
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(migrationUser)
        .expect(201);

      expect(response.body.migrated).toBe(true);
      expect(response.body.migratedCount).toBeGreaterThan(0);

      // Verify migration
      const user = await User.findOne({ username: migrationUser.username });
      expect(user.metadata.responseCount).toBeGreaterThan(0);
      expect(user.migrationData.source).toBe('migration');

      // Verify responses updated
      const migratedResponses = await Response.find({ userId: user._id });
      expect(migratedResponses.length).toBeGreaterThan(0);
      
      migratedResponses.forEach(resp => {
        expect(resp.authMethod).toBe('user');
        expect(resp.token).toBeUndefined();
        expect(resp.userId).toEqual(user._id);
      });
    });

    test('should handle migration with invalid token', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          ...testUser,
          migrateToken: 'invalid-token'
        })
        .expect(201);

      expect(response.body.migrated).toBeFalsy();
      expect(response.body.migratedCount).toBe(0);
    });

    test('should prevent duplicate migration', async () => {
      // First migration
      await request(app)
        .post('/api/auth/register')
        .send({
          ...testUser,
          username: 'user1',
          email: 'user1@test.com',
          displayName: 'Legacy User',
          migrateToken: legacyToken
        })
        .expect(201);

      // Second attempt with same token
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          ...testUser,
          username: 'user2',
          email: 'user2@test.com',
          displayName: 'Legacy User',
          migrateToken: legacyToken
        })
        .expect(201);

      expect(response.body.migratedCount).toBe(0);
    });
  });

  describe('⚡ Concurrent Admin Creation Edge Cases', () => {
    test('should prevent multiple admin responses in same month', async () => {
      // Create two admin users
      const admin1 = await User.create({
        username: 'admin1',
        email: 'admin1@test.com',
        password: 'AdminPass123!',
        displayName: 'Admin One',
        role: 'admin'
      });

      const admin2 = await User.create({
        username: 'admin2',
        email: 'admin2@test.com',
        password: 'AdminPass123!',
        displayName: 'Admin Two',
        role: 'admin'
      });

      // Login both
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

      // Concurrent admin response attempts
      const responseData = {
        responses: [{ question: 'Admin Q', answer: 'Admin A' }]
      };

      const [result1, result2] = await Promise.all([
        agent1.post('/api/responses').send(responseData),
        agent2.post('/api/responses').send(responseData)
      ]);

      // One should succeed, one should fail
      const successes = [result1, result2].filter(r => r.status === 201);
      const conflicts = [result1, result2].filter(r => r.status === 409);

      expect(successes).toHaveLength(1);
      expect(conflicts).toHaveLength(1);
      expect(conflicts[0].body.error).toContain('admin existe déjà');

      // Verify only one admin response in DB
      const adminResponses = await Response.find({ isAdmin: true });
      expect(adminResponses).toHaveLength(1);
    });

    test('should handle legacy + user admin conflict', async () => {
      // Create legacy admin response
      await Response.create({
        name: 'prodadmin',
        responses: [{ question: 'Legacy Q', answer: 'Legacy A' }],
        month: new Date().toISOString().slice(0, 7),
        isAdmin: true,
        authMethod: 'token'
      });

      // Try to create user admin response
      const admin = await User.create({
        username: 'newadmin',
        email: 'newadmin@test.com',
        password: 'AdminPass123!',
        displayName: 'New Admin',
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
          responses: [{ question: 'New Q', answer: 'New A' }]
        })
        .expect(409);

      expect(response.body.error).toContain('admin existe déjà');
    });
  });

  describe('🚫 User Deactivation Edge Cases', () => {
    let user;
    let agent;

    beforeEach(async () => {
      user = await User.create(testUser);
      agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: testUser.username,
        password: testUser.password
      });
    });

    test('should handle user deactivation during active session', async () => {
      // Create response first
      await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q1', answer: 'A1' }]
        })
        .expect(201);

      // Deactivate user
      await User.findByIdAndUpdate(user._id, {
        'metadata.isActive': false
      });

      // Try to access profile
      await agent
        .get('/api/auth/me')
        .expect(401);

      // Try to create another response
      await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Q2', answer: 'A2' }]
        })
        .expect(401);
    });

    test('should handle user deletion during session', async () => {
      // Delete user while session exists
      await User.findByIdAndDelete(user._id);

      // Should handle gracefully
      const response = await agent
        .get('/api/auth/me')
        .expect(401);

      expect(response.body.error).toContain('Non authentifié');
    });
  });

  describe('🔄 Hybrid Authentication Integration', () => {
    test('should handle user auth and legacy token simultaneously', async () => {
      // Create user
      const user = await User.create(testUser);
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: testUser.username,
        password: testUser.password
      });

      // Create legacy token response
      const token = TokenGenerator.generateTestToken(32);
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Legacy Q', answer: 'Legacy A' }],
        month: '2024-01',
        token,
        authMethod: 'token'
      });

      // User creates response
      await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'User Q', answer: 'User A' }]
        })
        .expect(201);

      // Legacy user views their response
      const legacyView = await request(app)
        .get(`/api/view/${token}`)
        .expect(200);

      expect(legacyView.body.name).toBe('Legacy User');

      // User views their responses  
      const userView = await agent
        .get('/api/auth/responses')
        .expect(200);

      expect(userView.body.responses).toHaveLength(1);
    });

    test('should prioritize user auth over token when both present', async () => {
      const user = await User.create(testUser);
      const token = TokenGenerator.generateTestToken(32);
      
      await Response.create({
        name: 'Token User',
        responses: [{ question: 'Token Q', answer: 'Token A' }],
        month: '2024-01',
        token,
        authMethod: 'token'
      });

      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: testUser.username,
        password: testUser.password
      });

      // Request with both session and token - session should take priority
      const response = await agent
        .get('/api/auth/me')
        .query({ token }) // Token in query should be ignored
        .expect(200);

      expect(response.body.user.username).toBe(testUser.username);
    });
  });

  describe('⚡ Performance and Load Testing', () => {
    test('should handle concurrent registrations', async () => {
      const users = Array(10).fill(null).map((_, i) => ({
        username: `user${i}`,
        email: `user${i}@test.com`,
        password: 'TestPass123!',
        displayName: `User ${i}`
      }));

      const startTime = process.hrtime.bigint();
      
      const promises = users.map(user => 
        request(app).post('/api/auth/register').send(user)
      );

      const results = await Promise.all(promises);
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

      // All should succeed
      results.forEach(result => {
        expect(result.status).toBe(201);
      });

      // Performance check
      expect(duration / users.length).toBeLessThan(1000); // < 1s per registration

      // Verify in database
      const userCount = await User.countDocuments();
      expect(userCount).toBe(users.length);
    });

    test('should measure authentication overhead', async () => {
      const user = await User.create(testUser);
      
      // Legacy response creation
      const legacyStart = process.hrtime.bigint();
      await request(app)
        .post('/api/responses')
        .send({
          name: 'Legacy Perf User',
          responses: [{ question: 'Perf Q', answer: 'Perf A' }]
        });
      const legacyDuration = Number(process.hrtime.bigint() - legacyStart) / 1000000;

      // Clear for user auth test
      await Response.deleteMany({});

      // User auth response creation
      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: testUser.username,
        password: testUser.password
      });

      const userStart = process.hrtime.bigint();
      await agent
        .post('/api/responses')
        .send({
          responses: [{ question: 'Auth Perf Q', answer: 'Auth Perf A' }]
        });
      const userDuration = Number(process.hrtime.bigint() - userStart) / 1000000;

      const overhead = userDuration - legacyDuration;
      const overheadPercentage = (overhead / legacyDuration) * 100;

      console.log(`Legacy: ${legacyDuration}ms, User Auth: ${userDuration}ms, Overhead: ${overhead}ms (${overheadPercentage.toFixed(1)}%)`);

      // Performance assertions
      expect(overhead).toBeLessThan(500); // < 500ms overhead
      expect(overheadPercentage).toBeLessThan(100); // < 100% overhead
    });
  });

  describe('🛡️ Security Edge Cases', () => {
    test('should handle malformed requests gracefully', async () => {
      // Malformed JSON
      const response1 = await request(app)
        .post('/api/auth/register')
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);

      expect(response1.body).toBeDefined();

      // Missing required fields
      const response2 = await request(app)
        .post('/api/auth/register')
        .send({})
        .expect(400);

      expect(response2.body.error).toBe('Données invalides');
    });

    test('should prevent authentication bypass attempts', async () => {
      // Invalid session cookie
      const response = await request(app)
        .get('/api/auth/me')
        .set('Cookie', 'faf.session=fake-session-data')
        .expect(401);

      expect(response.body.error).toContain('Non authentifié');
    });

    test('should handle database errors gracefully', async () => {
      // Mock database error
      const originalCreate = User.create;
      User.create = jest.fn().mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(500);

      expect(response.body.error).toBe('Erreur serveur');

      // Restore
      User.create = originalCreate;
    });
  });
});