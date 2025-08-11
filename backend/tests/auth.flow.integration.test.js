// Comprehensive auth flow integration tests
const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../app');
const User = require('../models/User');
const Response = require('../models/Response');

describe('Authentication Flow Integration Tests', () => {
  let mongoServer;
  let testUser;

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
    
    testUser = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'SecurePass123!',
      displayName: 'Test User'
    };
  });

  describe('Complete Registration Flow', () => {
    test('should register a new user successfully', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(201);

      expect(res.body).toHaveProperty('message', 'Compte créé avec succès');
      expect(res.body.user).toHaveProperty('username', testUser.username);
      expect(res.body.user).toHaveProperty('email', testUser.email);
      expect(res.body.user).not.toHaveProperty('password');
      
      // Verify user in database
      const dbUser = await User.findOne({ username: testUser.username });
      expect(dbUser).toBeTruthy();
      expect(dbUser.email).toBe(testUser.email.toLowerCase());
    });

    test('should prevent duplicate registration', async () => {
      // First registration
      await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(201);

      // Duplicate registration attempt
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser)
        .expect(409);

      expect(res.body).toHaveProperty('error');
      expect(res.body.error).toContain('déjà utilisé');
    });

    test('should validate registration input', async () => {
      const invalidUser = {
        username: 'ab', // Too short
        email: 'invalid-email',
        password: '123', // Too short
        displayName: ''
      };

      const res = await request(app)
        .post('/api/auth/register')
        .send(invalidUser)
        .expect(400);

      expect(res.body).toHaveProperty('error', 'Données invalides');
      expect(res.body).toHaveProperty('details');
      expect(res.body.details).toBeInstanceOf(Array);
    });
  });

  describe('Complete Login Flow', () => {
    beforeEach(async () => {
      // Register a user first
      await request(app)
        .post('/api/auth/register')
        .send(testUser);
    });

    test('should login with username successfully', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          login: testUser.username,
          password: testUser.password
        })
        .expect(200);

      expect(res.body).toHaveProperty('message', 'Connexion réussie');
      expect(res.body.user).toHaveProperty('username', testUser.username);
      expect(res.headers).toHaveProperty('set-cookie');
    });

    test('should login with email successfully', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          login: testUser.email,
          password: testUser.password
        })
        .expect(200);

      expect(res.body).toHaveProperty('message', 'Connexion réussie');
      expect(res.body.user).toHaveProperty('email', testUser.email.toLowerCase());
    });

    test('should reject invalid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          login: testUser.username,
          password: 'WrongPassword'
        })
        .expect(401);

      expect(res.body).toHaveProperty('error');
      expect(res.body.error).toContain('incorrect');
    });

    test('should reject non-existent user', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          login: 'nonexistent',
          password: 'anypassword'
        })
        .expect(401);

      expect(res.body).toHaveProperty('error');
    });
  });

  describe('Session Management', () => {
    let agent;

    beforeEach(async () => {
      agent = request.agent(app);
      
      // Register and login
      await agent
        .post('/api/auth/register')
        .send(testUser);
      
      await agent
        .post('/api/auth/login')
        .send({
          login: testUser.username,
          password: testUser.password
        });
    });

    test('should access profile with valid session', async () => {
      const res = await agent
        .get('/api/auth/me')
        .expect(200);

      expect(res.body.user).toHaveProperty('username', testUser.username);
    });

    test('should logout successfully', async () => {
      // Logout
      await agent
        .post('/api/auth/logout')
        .expect(200);

      // Try to access profile after logout
      await agent
        .get('/api/auth/me')
        .expect(401);
    });

    test('should reject access without session', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .expect(401);

      expect(res.body).toHaveProperty('error', 'Non authentifié');
    });
  });

  describe('Profile Update Flow', () => {
    let agent;

    beforeEach(async () => {
      agent = request.agent(app);
      
      await agent
        .post('/api/auth/register')
        .send(testUser);
      
      await agent
        .post('/api/auth/login')
        .send({
          login: testUser.username,
          password: testUser.password
        });
    });

    test('should update profile successfully', async () => {
      const updates = {
        displayName: 'Updated Name',
        profile: {
          firstName: 'John',
          lastName: 'Doe',
          location: 'Paris'
        }
      };

      const res = await agent
        .put('/api/auth/profile')
        .send(updates)
        .expect(200);

      expect(res.body.user.displayName).toBe(updates.displayName);
      expect(res.body.user.profile.firstName).toBe(updates.profile.firstName);
    });

    test('should validate profile updates', async () => {
      const invalidUpdates = {
        displayName: '', // Too short
        email: 'invalid-email' // Should not be updatable
      };

      const res = await agent
        .put('/api/auth/profile')
        .send(invalidUpdates)
        .expect(400);

      expect(res.body).toHaveProperty('error');
    });
  });

  describe('Rate Limiting', () => {
    test('should rate limit login attempts', async () => {
      // Make 6 login attempts (limit is 5)
      const attempts = Array(6).fill(null).map(() => 
        request(app)
          .post('/api/auth/login')
          .send({
            login: 'anyuser',
            password: 'anypass'
          })
      );

      const responses = await Promise.all(attempts);
      
      // First 5 should not be rate limited
      const nonLimited = responses.slice(0, 5);
      nonLimited.forEach(res => {
        expect(res.status).not.toBe(429);
      });

      // 6th should be rate limited
      expect(responses[5].status).toBe(429);
      expect(responses[5].body).toHaveProperty('error');
      expect(responses[5].body.error).toContain('Trop de tentatives');
    });

    test('should rate limit registration attempts', async () => {
      // Make 4 registration attempts (limit is 3)
      const attempts = Array(4).fill(null).map((_, i) => 
        request(app)
          .post('/api/auth/register')
          .send({
            username: `user${i}`,
            email: `user${i}@test.com`,
            password: 'Pass123!',
            displayName: `User ${i}`
          })
      );

      const responses = await Promise.all(attempts);
      
      // First 3 should succeed
      responses.slice(0, 3).forEach(res => {
        expect(res.status).not.toBe(429);
      });

      // 4th should be rate limited
      expect(responses[3].status).toBe(429);
    });
  });
});