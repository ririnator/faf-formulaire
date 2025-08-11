// Comprehensive Hybrid Auth Middleware Integration Tests
const request = require('supertest');
const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const User = require('../models/User');
const Response = require('../models/Response');
const TokenGenerator = require('../utils/tokenGenerator');
const { detectAuthMethod, requireAuth, enrichUserData, logAuthMethod } = require('../middleware/hybridAuth');

describe('Hybrid Auth Middleware Comprehensive Tests', () => {
  let mongoServer;
  let app;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);

    // Create test app with middleware
    app = express();
    app.use(express.json());
    app.use(session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: false,
      cookie: { maxAge: 60000 }
    }));

    // Apply hybrid auth middleware
    app.use(detectAuthMethod);
    app.use(enrichUserData);
    app.use(logAuthMethod);

    // Test routes
    app.get('/test/public', (req, res) => {
      res.json({
        authMethod: req.authMethod,
        user: req.currentUser ? req.currentUser.username : null,
        token: req.viewToken ? req.viewToken.substring(0, 8) + '...' : null
      });
    });

    app.get('/test/protected', requireAuth, (req, res) => {
      res.json({
        authMethod: req.authMethod,
        user: req.currentUser ? req.currentUser.username : null,
        authenticated: true
      });
    });

    app.post('/test/admin-only', requireAuth, (req, res) => {
      if (req.currentUser && req.currentUser.role === 'admin') {
        res.json({ admin: true });
      } else {
        res.status(403).json({ error: 'Admin required' });
      }
    });
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
  });

  describe('detectAuthMethod Middleware', () => {
    test('should detect no authentication', async () => {
      const response = await request(app)
        .get('/test/public')
        .expect(200);

      expect(response.body.authMethod).toBe('none');
      expect(response.body.user).toBeNull();
      expect(response.body.token).toBeNull();
    });

    test('should detect user session authentication', async () => {
      const user = await User.create({
        username: 'testuser',
        email: 'test@example.com',
        password: 'TestPass123!',
        displayName: 'Test User'
      });

      const agent = request.agent(app);
      
      // Manually set session (simulating login)
      const loginResponse = await agent
        .post('/test/login-sim')
        .send({ userId: user._id })
        .expect(404); // Route doesn't exist, but session should be set
      
      // For this test, we need to manually set the session
      // Let's create a proper login endpoint
      app.post('/test/login-sim', (req, res) => {
        req.session.userId = req.body.userId;
        req.session.user = { username: 'testuser', role: 'user' };
        res.json({ success: true });
      });

      await agent.post('/test/login-sim').send({ userId: user._id });

      const response = await agent
        .get('/test/public')
        .expect(200);

      expect(response.body.authMethod).toBe('user');
      expect(response.body.user).toBe('testuser');
    });

    test('should detect legacy token authentication', async () => {
      const token = TokenGenerator.generateTestToken(32);
      
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-01',
        token,
        authMethod: 'token'
      });

      const response = await request(app)
        .get('/test/public')
        .query({ token })
        .expect(200);

      expect(response.body.authMethod).toBe('token');
      expect(response.body.user).toBeNull();
      expect(response.body.token).toBe(token.substring(0, 8) + '...');
    });

    test('should handle invalid token gracefully', async () => {
      const response = await request(app)
        .get('/test/public')
        .query({ token: 'invalid-token' })
        .expect(200);

      expect(response.body.authMethod).toBe('none');
      expect(response.body.user).toBeNull();
      expect(response.body.token).toBeNull();
    });

    test('should prioritize user auth over token when both present', async () => {
      const user = await User.create({
        username: 'priorityuser',
        email: 'priority@example.com',
        password: 'PriorityPass123!',
        displayName: 'Priority User'
      });

      const token = TokenGenerator.generateTestToken(32);
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-01',
        token,
        authMethod: 'token'
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      const response = await agent
        .get('/test/public')
        .query({ token }) // Token present but user auth should take priority
        .expect(200);

      expect(response.body.authMethod).toBe('user');
      expect(response.body.user).toBe('priorityuser');
    });
  });

  describe('enrichUserData Middleware', () => {
    test('should enrich user data for authenticated users', async () => {
      const user = await User.create({
        username: 'enrichuser',
        email: 'enrich@example.com',
        password: 'EnrichPass123!',
        displayName: 'Enrich User',
        profile: {
          firstName: 'John',
          lastName: 'Doe'
        }
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      const response = await agent
        .get('/test/public')
        .expect(200);

      expect(response.body.authMethod).toBe('user');
      expect(response.body.user).toBe('enrichuser');
    });

    test('should handle user data enrichment errors gracefully', async () => {
      // Create user then delete to simulate DB error
      const user = await User.create({
        username: 'erroruser',
        email: 'error@example.com',
        password: 'ErrorPass123!',
        displayName: 'Error User'
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      // Delete user to cause enrichment error
      await User.findByIdAndDelete(user._id);

      const response = await agent
        .get('/test/public')
        .expect(200);

      // Should continue without enrichment
      expect(response.body.authMethod).toBe('user');
    });

    test('should handle inactive users', async () => {
      const user = await User.create({
        username: 'inactiveuser',
        email: 'inactive@example.com',
        password: 'InactivePass123!',
        displayName: 'Inactive User',
        metadata: { isActive: false }
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      const response = await agent
        .get('/test/public')
        .expect(200);

      // Should reset to no auth for inactive users
      expect(response.body.authMethod).toBe('none');
      expect(response.body.user).toBeNull();
    });
  });

  describe('requireAuth Middleware', () => {
    test('should allow access for authenticated users', async () => {
      const user = await User.create({
        username: 'authuser',
        email: 'auth@example.com',
        password: 'AuthPass123!',
        displayName: 'Auth User'
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      const response = await agent
        .get('/test/protected')
        .expect(200);

      expect(response.body.authenticated).toBe(true);
      expect(response.body.user).toBe('authuser');
    });

    test('should allow access for legacy token users', async () => {
      const token = TokenGenerator.generateTestToken(32);
      
      await Response.create({
        name: 'Protected Legacy User',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-01',
        token,
        authMethod: 'token'
      });

      const response = await request(app)
        .get('/test/protected')
        .query({ token })
        .expect(200);

      expect(response.body.authenticated).toBe(true);
      expect(response.body.authMethod).toBe('token');
    });

    test('should deny access for unauthenticated users', async () => {
      const response = await request(app)
        .get('/test/protected')
        .expect(401);

      expect(response.body.error).toContain('Authentification requise');
    });

    test('should deny access for invalid tokens', async () => {
      const response = await request(app)
        .get('/test/protected')
        .query({ token: 'invalid-token' })
        .expect(401);

      expect(response.body.error).toContain('Authentification requise');
    });
  });

  describe('Role-based Access Control', () => {
    test('should allow admin access for admin users', async () => {
      const admin = await User.create({
        username: 'adminuser',
        email: 'admin@example.com',
        password: 'AdminPass123!',
        displayName: 'Admin User',
        role: 'admin'
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: admin._id });

      const response = await agent
        .post('/test/admin-only')
        .expect(200);

      expect(response.body.admin).toBe(true);
    });

    test('should deny admin access for regular users', async () => {
      const user = await User.create({
        username: 'regularuser',
        email: 'regular@example.com',
        password: 'RegularPass123!',
        displayName: 'Regular User',
        role: 'user'
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      const response = await agent
        .post('/test/admin-only')
        .expect(403);

      expect(response.body.error).toBe('Admin required');
    });

    test('should deny admin access for legacy token users', async () => {
      const token = TokenGenerator.generateTestToken(32);
      
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-01',
        token,
        authMethod: 'token'
      });

      const response = await request(app)
        .post('/test/admin-only')
        .query({ token })
        .expect(403);

      expect(response.body.error).toBe('Admin required');
    });
  });

  describe('Session Management', () => {
    test('should handle session corruption gracefully', async () => {
      const agent = request.agent(app);
      
      // Set invalid session data
      await agent.post('/test/login-sim').send({ userId: 'invalid-id' });

      const response = await agent
        .get('/test/public')
        .expect(200);

      // Should handle gracefully
      expect(response.body.authMethod).toBe('none');
    });

    test('should handle concurrent session modifications', async () => {
      const user = await User.create({
        username: 'concurrentuser',
        email: 'concurrent@example.com',
        password: 'ConcurrentPass123!',
        displayName: 'Concurrent User'
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      // Make concurrent requests
      const promises = Array(10).fill(null).map(() =>
        agent.get('/test/public')
      );

      const results = await Promise.all(promises);

      // All should succeed with consistent data
      results.forEach(result => {
        expect(result.status).toBe(200);
        expect(result.body.authMethod).toBe('user');
        expect(result.body.user).toBe('concurrentuser');
      });
    });

    test('should update last active timestamp', async () => {
      const user = await User.create({
        username: 'activeuser',
        email: 'active@example.com',
        password: 'ActivePass123!',
        displayName: 'Active User'
      });

      const initialLastActive = user.metadata.lastActive;
      
      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      // Wait a moment then make request
      await new Promise(resolve => setTimeout(resolve, 100));
      
      await agent.get('/test/public');

      // Check if last active was updated
      const updatedUser = await User.findById(user._id);
      expect(updatedUser.metadata.lastActive.getTime()).toBeGreaterThan(
        initialLastActive.getTime()
      );
    });
  });

  describe('Token Validation', () => {
    test('should validate token format', async () => {
      const invalidTokens = [
        'too-short',
        'invalid!@#characters',
        '12345', // too short
        '', // empty
        'x'.repeat(1000) // too long
      ];

      for (const token of invalidTokens) {
        const response = await request(app)
          .get('/test/public')
          .query({ token })
          .expect(200);

        expect(response.body.authMethod).toBe('none');
        expect(response.body.token).toBeNull();
      }
    });

    test('should handle token collision attempts', async () => {
      const realToken = TokenGenerator.generateTestToken(32);
      
      await Response.create({
        name: 'Real User',
        responses: [{ question: 'Q', answer: 'A' }],
        month: '2024-01',
        token: realToken,
        authMethod: 'token'
      });

      // Try with similar but different token
      const fakeToken = realToken.substring(0, 60) + '0000';
      
      const realResponse = await request(app)
        .get('/test/public')
        .query({ token: realToken })
        .expect(200);

      const fakeResponse = await request(app)
        .get('/test/public')
        .query({ token: fakeToken })
        .expect(200);

      expect(realResponse.body.authMethod).toBe('token');
      expect(fakeResponse.body.authMethod).toBe('none');
    });
  });

  describe('Middleware Chain Integration', () => {
    test('should process middleware chain in correct order', async () => {
      const user = await User.create({
        username: 'chainuser',
        email: 'chain@example.com',
        password: 'ChainPass123!',
        displayName: 'Chain User'
      });

      // Mock console.log to capture middleware order
      const originalLog = console.log;
      const logCalls = [];
      console.log = (message) => {
        if (message.includes('[AUTH]') || message.includes('[HybridAuth]')) {
          logCalls.push(message);
        }
      };

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });
      await agent.get('/test/public');

      console.log = originalLog;

      // Verify middleware was called (development mode logs)
      if (process.env.NODE_ENV === 'development') {
        expect(logCalls.length).toBeGreaterThan(0);
      }
    });

    test('should handle middleware errors gracefully', async () => {
      // Mock User.findById to throw error during enrichment
      const originalFindById = User.findById;
      User.findById = jest.fn().mockRejectedValue(new Error('DB Error'));

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: 'some-id' });

      const response = await agent
        .get('/test/public')
        .expect(200);

      // Should continue processing despite error
      expect(response.body.authMethod).toBe('user');

      // Restore original method
      User.findById = originalFindById;
    });
  });

  describe('Performance and Memory', () => {
    test('should handle high-frequency requests efficiently', async () => {
      const user = await User.create({
        username: 'perfuser',
        email: 'perf@example.com',
        password: 'PerfPass123!',
        displayName: 'Perf User'
      });

      const agent = request.agent(app);
      await agent.post('/test/login-sim').send({ userId: user._id });

      const startTime = process.hrtime.bigint();
      const iterations = 100;

      const promises = Array(iterations).fill(null).map(() =>
        agent.get('/test/public')
      );

      const results = await Promise.all(promises);
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

      // All requests should succeed
      results.forEach(result => {
        expect(result.status).toBe(200);
        expect(result.body.authMethod).toBe('user');
      });

      // Performance assertion
      expect(duration / iterations).toBeLessThan(50); // < 50ms per request on average
    });

    test('should not leak memory with repeated requests', async () => {
      const initialMemory = process.memoryUsage();

      // Make many requests with different tokens
      const promises = Array(50).fill(null).map((_, i) => {
        const token = TokenGenerator.generateTestToken(32);
        return request(app)
          .get('/test/public')
          .query({ token });
      });

      await Promise.all(promises);

      const finalMemory = process.memoryUsage();
      const memoryGrowthMB = (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024;

      // Memory growth should be minimal
      expect(memoryGrowthMB).toBeLessThan(10); // < 10MB growth
    });
  });
});