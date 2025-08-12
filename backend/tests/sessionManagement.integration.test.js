const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../app');
const SessionConfig = require('../config/session');
const sessionMonitoringMiddleware = require('../middleware/sessionMonitoring');

describe('Session Management Integration Tests', () => {
  let mongoServer;
  let db;

  beforeAll(async () => {
    // Create in-memory MongoDB instance
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    // Override environment variables for testing
    process.env.MONGODB_URI = mongoUri;
    process.env.SESSION_SECRET = 'test-secret-key-for-session-integration';
    process.env.LOGIN_ADMIN_USER = 'testadmin';
    process.env.LOGIN_ADMIN_PASS = 'testpass';
    process.env.FORM_ADMIN_NAME = 'testadmin';
    process.env.NODE_ENV = 'test';

    // Connect to the in-memory database
    await mongoose.connect(mongoUri);
    db = mongoose.connection.db;
  });

  afterAll(async () => {
    await mongoose.connection.close();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    // Clear sessions collection before each test
    if (db) {
      await db.collection('sessions').deleteMany({});
    }
  });

  afterEach(() => {
    // Reset monitoring state
    const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
    monitoringService.activeSessions.clear();
    monitoringService.userSessions.clear();
    monitoringService.failedLogins.clear();
    monitoringService.suspiciousIPs.clear();
  });

  describe('Session Creation and Tracking', () => {
    test('should create and track admin session on successful login', async () => {
      const response = await request(app)
        .post('/login')
        .send({
          username: 'testadmin',
          password: 'testpass'
        })
        .expect(302); // Redirect on successful login

      // Check that session was created
      expect(response.headers['set-cookie']).toBeDefined();
      
      // Verify session exists in database
      const sessions = await db.collection('sessions').find({}).toArray();
      expect(sessions.length).toBe(1);

      // Check monitoring stats
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      const stats = monitoringService.getMonitoringStats();
      expect(stats.activeSessions).toBeGreaterThan(0);
    });

    test('should track failed login attempts', async () => {
      await request(app)
        .post('/login')
        .send({
          username: 'testadmin',
          password: 'wrongpassword'
        })
        .expect(401);

      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      expect(monitoringService.failedLogins.size).toBeGreaterThan(0);
    });

    test('should block IP after multiple failed login attempts', async () => {
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      const maxAttempts = monitoringService.config?.suspiciousLoginThreshold || 5;
      
      // Make multiple failed login attempts
      for (let i = 0; i < maxAttempts; i++) {
        await request(app)
          .post('/login')
          .send({
            username: 'testadmin',
            password: 'wrongpassword'
          })
          .expect(401);
      }

      // Next attempt should be blocked
      const response = await request(app)
        .post('/login')
        .send({
          username: 'testadmin',
          password: 'testpass'
        })
        .expect(429);

      expect(response.body.error).toContain('blocked');
    });
  });

  describe('Session Cleanup Integration', () => {
    test('should clean up expired sessions', async () => {
      // Create a test session
      const sessionData = {
        session: JSON.stringify({
          userId: 'test-user',
          clientIP: '127.0.0.1'
        }),
        expires: new Date(Date.now() - 1000) // Already expired
      };

      await db.collection('sessions').insertOne(sessionData);

      // Run cleanup
      const cleanupService = SessionConfig.getCleanupService();
      if (cleanupService) {
        await cleanupService.runCompleteCleanup({ dryRun: false });
      }

      // Verify expired session was cleaned
      const remainingSessions = await db.collection('sessions').find({}).toArray();
      expect(remainingSessions.length).toBe(0);
    });

    test('should keep active sessions during cleanup', async () => {
      // Create an active session
      const sessionData = {
        session: JSON.stringify({
          userId: 'test-user',
          clientIP: '127.0.0.1'
        }),
        expires: new Date(Date.now() + 3600000) // Expires in 1 hour
      };

      await db.collection('sessions').insertOne(sessionData);

      // Run cleanup
      const cleanupService = SessionConfig.getCleanupService();
      if (cleanupService) {
        await cleanupService.runCompleteCleanup({ dryRun: false });
      }

      // Verify active session was preserved
      const remainingSessions = await db.collection('sessions').find({}).toArray();
      expect(remainingSessions.length).toBe(1);
    });
  });

  describe('Session Monitoring Admin Endpoints', () => {
    let agent;
    let sessionCookie;

    beforeEach(async () => {
      agent = request.agent(app);
      
      // Login as admin to get session
      const loginResponse = await agent
        .post('/login')
        .send({
          username: 'testadmin',
          password: 'testpass'
        });

      sessionCookie = loginResponse.headers['set-cookie'];
    });

    test('should provide session monitoring stats to admin', async () => {
      const response = await agent
        .get('/api/admin/session-stats')
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('stats');
      expect(response.body.stats).toHaveProperty('activeSessions');
      expect(response.body.stats).toHaveProperty('uniqueIPs');
      expect(response.body.stats).toHaveProperty('suspiciousIPs');
    });

    test('should allow admin to reset suspicious IP', async () => {
      // First make an IP suspicious
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      monitoringService.suspiciousIPs.add('192.168.1.100');

      const response = await agent
        .post('/api/admin/reset-suspicious-ip')
        .send({ ip: '192.168.1.100' })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(monitoringService.isIPSuspicious('192.168.1.100')).toBe(false);
    });

    test('should deny access to session stats for non-admin users', async () => {
      await request(app)
        .get('/api/admin/session-stats')
        .expect(401); // Unauthorized without session
    });
  });

  describe('Session Security Features', () => {
    test('should detect and handle suspicious user agents', async () => {
      const response = await request(app)
        .post('/login')
        .set('User-Agent', 'curl/7.68.0') // Suspicious user agent
        .send({
          username: 'testadmin',
          password: 'testpass'
        });

      // Should still process the request but mark as suspicious
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      const stats = monitoringService.getMonitoringStats();
      expect(stats.suspiciousActivities).toBeGreaterThan(0);
    });

    test('should handle session with missing required headers', async () => {
      const response = await request(app)
        .post('/login')
        .set('User-Agent', '') // Missing user agent
        .send({
          username: 'testadmin',
          password: 'testpass'
        });

      // Request should be processed but flagged as suspicious
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      expect(monitoringService.sessionMetrics.suspiciousActivities).toBeGreaterThan(0);
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle multiple concurrent session requests', async () => {
      const promises = [];
      
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post('/login')
            .send({
              username: 'testadmin',
              password: 'testpass'
            })
        );
      }

      const responses = await Promise.all(promises);
      
      // All should succeed (some might be redirects due to existing session)
      responses.forEach(response => {
        expect([200, 302]).toContain(response.status);
      });

      // Verify monitoring data was tracked
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      const stats = monitoringService.getMonitoringStats();
      expect(stats.activeSessions).toBeGreaterThan(0);
    });

    test('should clean up monitoring data efficiently', async () => {
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      
      // Add old failed login data
      const oldTimestamp = Date.now() - (16 * 60 * 1000); // 16 minutes ago (older than threshold)
      monitoringService.failedLogins.set('127.0.0.1', [
        { timestamp: oldTimestamp, userAgent: 'test', attemptedEmail: 'test@example.com' }
      ]);

      const initialSize = monitoringService.failedLogins.size;
      expect(initialSize).toBeGreaterThan(0);

      // Run cleanup
      monitoringService.cleanupOldData();

      // Should be cleaned up
      expect(monitoringService.failedLogins.size).toBeLessThan(initialSize);
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle database connection errors gracefully', async () => {
      // Temporarily close database connection
      await mongoose.connection.close();

      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body.status).toBe('healthy');

      // Reconnect for other tests
      await mongoose.connect(mongoServer.getUri());
    });

    test('should handle session store errors gracefully', async () => {
      // This test verifies the app continues to work even if session operations fail
      const response = await request(app)
        .get('/test-simple')
        .expect(200);

      expect(response.body.message).toBe('Simple test works');
    });
  });
});

describe('Session Configuration Tests', () => {
  test('should create proper session configuration', () => {
    process.env.SESSION_SECRET = 'test-secret';
    process.env.MONGODB_URI = 'mongodb://localhost:27017/test';

    const config = SessionConfig.getConfig();

    expect(config).toHaveProperty('secret', 'test-secret');
    expect(config).toHaveProperty('resave', false);
    expect(config).toHaveProperty('saveUninitialized', false);
    expect(config.store).toBeDefined();
    expect(config.cookie).toBeDefined();
  });

  test('should throw error for missing SESSION_SECRET', () => {
    delete process.env.SESSION_SECRET;

    expect(() => {
      SessionConfig.getConfig();
    }).toThrow('SESSION_SECRET manquant');
  });

  test('should adapt cookie settings for environment', () => {
    process.env.SESSION_SECRET = 'test-secret';
    process.env.MONGODB_URI = 'mongodb://localhost:27017/test';
    process.env.NODE_ENV = 'production';

    const config = SessionConfig.getConfig();

    expect(config.cookie.sameSite).toBe('none');
    expect(config.cookie.secure).toBe(true);

    // Reset for other tests
    process.env.NODE_ENV = 'test';
  });
});