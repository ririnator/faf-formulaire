const mongoose = require('mongoose');
const SessionCleanupService = require('../services/sessionCleanupService');
const User = require('../models/User');
const Response = require('../models/Response');

describe('SessionCleanupService', () => {
  let cleanupService;
  let db;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI_TEST || 'mongodb://127.0.0.1:27017/faf-test');
    }
    db = mongoose.connection.db;
    cleanupService = new SessionCleanupService();
  });

  beforeEach(async () => {
    // Clean database before each test
    await User.deleteMany({});
    await Response.deleteMany({});
    await db.collection('sessions').deleteMany({});
    
    // Reset cleanup service stats
    cleanupService.resetStats();
  });

  afterAll(async () => {
    if (cleanupService) {
      cleanupService.shutdown();
    }
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  describe('Service Initialization', () => {
    test('should initialize with default configuration', () => {
      const service = new SessionCleanupService();
      
      expect(service.config.sessionTTL).toBe(14 * 24 * 60 * 60 * 1000);
      expect(service.config.userInactivityThreshold).toBe(90 * 24 * 60 * 60 * 1000);
      expect(service.config.cleanupInterval).toBe(24 * 60 * 60 * 1000);
      expect(service.config.batchSize).toBe(1000);
    });

    test('should disable auto cleanup in test environment', () => {
      const service = new SessionCleanupService();
      expect(service.config.enableAutoCleanup).toBe(false);
    });

    test('should update configuration correctly', () => {
      const service = new SessionCleanupService();
      const newConfig = {
        sessionTTL: 7 * 24 * 60 * 60 * 1000,
        batchSize: 500
      };

      service.updateConfig(newConfig);
      
      expect(service.config.sessionTTL).toBe(7 * 24 * 60 * 60 * 1000);
      expect(service.config.batchSize).toBe(500);
      expect(service.config.userInactivityThreshold).toBe(90 * 24 * 60 * 60 * 1000); // unchanged
    });
  });

  describe('Expired Sessions Cleanup', () => {
    beforeEach(async () => {
      // Create test sessions in MongoDB
      const sessionsCollection = db.collection('sessions');
      
      const now = new Date();
      const oldDate = new Date(now.getTime() - 15 * 24 * 60 * 60 * 1000); // 15 days ago
      const recentDate = new Date(now.getTime() - 1 * 60 * 60 * 1000); // 1 hour ago
      
      await sessionsCollection.insertMany([
        {
          _id: 'expired_session_1',
          expires: oldDate,
          session: '{"userId": "test1"}',
          updatedAt: oldDate
        },
        {
          _id: 'expired_session_2',
          expires: oldDate,
          session: '{"userId": "test2"}',
          updatedAt: oldDate
        },
        {
          _id: 'active_session_1',
          expires: new Date(now.getTime() + 60 * 60 * 1000), // 1 hour from now
          session: '{"userId": "test3"}',
          updatedAt: recentDate
        },
        {
          _id: 'expired_by_activity',
          expires: new Date(now.getTime() + 60 * 60 * 1000), // valid expiry
          session: '{"userId": "test4"}',
          lastActivity: oldDate // but old activity
        }
      ]);
    });

    test('should identify expired sessions in dry run mode', async () => {
      await cleanupService.cleanupExpiredSessions(true);
      
      expect(cleanupService.cleanupStats.expiredSessions).toBeGreaterThanOrEqual(3);
      
      // Verify sessions still exist (dry run)
      const sessionCount = await db.collection('sessions').countDocuments({});
      expect(sessionCount).toBe(4);
    });

    test('should delete expired sessions', async () => {
      await cleanupService.cleanupExpiredSessions(false);
      
      expect(cleanupService.cleanupStats.expiredSessions).toBeGreaterThanOrEqual(3);
      expect(cleanupService.cleanupStats.totalCleaned).toBeGreaterThanOrEqual(3);
      
      // Verify only active session remains
      const remainingSessions = await db.collection('sessions').find({}).toArray();
      expect(remainingSessions).toHaveLength(1);
      expect(remainingSessions[0]._id).toBe('active_session_1');
    });

    test('should handle batch processing for large session counts', async () => {
      // Create many expired sessions
      const sessionsCollection = db.collection('sessions');
      const expiredSessions = [];
      const oldDate = new Date(Date.now() - 20 * 24 * 60 * 60 * 1000);
      
      for (let i = 0; i < 50; i++) {
        expiredSessions.push({
          _id: `bulk_expired_${i}`,
          expires: oldDate,
          session: `{"userId": "bulk_${i}"}`,
          updatedAt: oldDate
        });
      }
      
      await sessionsCollection.insertMany(expiredSessions);
      
      await cleanupService.cleanupExpiredSessions(false);
      
      expect(cleanupService.cleanupStats.expiredSessions).toBeGreaterThanOrEqual(50);
    });
  });

  describe('Inactive Users Cleanup', () => {
    let activeUser, inactiveUser, userWithRecentResponse;

    beforeEach(async () => {
      const now = new Date();
      const oldDate = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days ago
      const veryOldDate = new Date(now.getTime() - 200 * 24 * 60 * 60 * 1000); // 200 days ago

      // Create test users
      activeUser = await User.create({
        username: 'activeuser',
        email: 'active@test.com',
        password: 'hashedpassword',
        metadata: {
          registeredAt: oldDate,
          lastLoginAt: new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000) // 1 day ago
        }
      });

      inactiveUser = await User.create({
        username: 'inactiveuser',
        email: 'inactive@test.com',
        password: 'hashedpassword',
        metadata: {
          registeredAt: veryOldDate,
          lastLoginAt: veryOldDate
        }
      });

      userWithRecentResponse = await User.create({
        username: 'recentuser',
        email: 'recent@test.com',
        password: 'hashedpassword',
        metadata: {
          registeredAt: veryOldDate,
          lastLoginAt: veryOldDate
        }
      });

      // Create responses
      await Response.create({
        userId: userWithRecentResponse._id,
        month: '2025-01',
        responses: [{ question: 'Test?', answer: 'Yes' }],
        authMethod: 'user',
        createdAt: new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000) // 1 day ago
      });

      await Response.create({
        userId: inactiveUser._id,
        month: '2024-01',
        responses: [{ question: 'Old?', answer: 'Yes' }],
        authMethod: 'user',
        createdAt: veryOldDate
      });
    });

    test('should identify inactive users in dry run mode', async () => {
      await cleanupService.cleanupInactiveUsers(true);
      
      expect(cleanupService.cleanupStats.inactiveUsers).toBe(1);
      
      // Verify users still exist
      const userCount = await User.countDocuments({});
      expect(userCount).toBe(3);
    });

    test('should delete inactive users and their responses', async () => {
      await cleanupService.cleanupInactiveUsers(false);
      
      expect(cleanupService.cleanupStats.inactiveUsers).toBe(1);
      expect(cleanupService.cleanupStats.orphanedData).toBe(1); // old response
      
      // Verify correct users remain
      const remainingUsers = await User.find({});
      expect(remainingUsers).toHaveLength(2);
      
      const emails = remainingUsers.map(u => u.email);
      expect(emails).toContain('active@test.com');
      expect(emails).toContain('recent@test.com');
      expect(emails).not.toContain('inactive@test.com');
      
      // Verify inactive user's response was deleted
      const inactiveUserResponses = await Response.find({ userId: inactiveUser._id });
      expect(inactiveUserResponses).toHaveLength(0);
    });

    test('should not delete users with recent activity', async () => {
      await cleanupService.cleanupInactiveUsers(false);
      
      // Active user should remain
      const activeUserStillExists = await User.findById(activeUser._id);
      expect(activeUserStillExists).toBeTruthy();
      
      // User with recent response should remain
      const recentUserStillExists = await User.findById(userWithRecentResponse._id);
      expect(recentUserStillExists).toBeTruthy();
    });
  });

  describe('Orphaned Data Cleanup', () => {
    let validUser, validResponse;

    beforeEach(async () => {
      validUser = await User.create({
        username: 'validuser',
        email: 'valid@test.com',
        password: 'hashedpassword'
      });

      validResponse = await Response.create({
        userId: validUser._id,
        month: '2025-01',
        responses: [{ question: 'Valid?', answer: 'Yes' }],
        authMethod: 'user'
      });

      // Create orphaned response
      await Response.create({
        userId: new mongoose.Types.ObjectId(), // Non-existent user ID
        month: '2025-01',
        responses: [{ question: 'Orphaned?', answer: 'Yes' }],
        authMethod: 'user'
      });

      // Create duplicate token responses
      await Response.create({
        token: 'duplicate_token',
        month: '2025-01',
        responses: [{ question: 'Dup1?', answer: 'Yes' }],
        authMethod: 'token'
      });

      await Response.create({
        token: 'duplicate_token',
        month: '2025-01',
        responses: [{ question: 'Dup2?', answer: 'Yes' }],
        authMethod: 'token'
      });
    });

    test('should identify orphaned data in dry run mode', async () => {
      await cleanupService.cleanupOrphanedData(true);
      
      expect(cleanupService.cleanupStats.orphanedData).toBeGreaterThanOrEqual(1);
      
      // Verify responses still exist
      const responseCount = await Response.countDocuments({});
      expect(responseCount).toBe(4);
    });

    test('should clean orphaned responses and duplicates', async () => {
      await cleanupService.cleanupOrphanedData(false);
      
      expect(cleanupService.cleanupStats.orphanedData).toBeGreaterThanOrEqual(2);
      
      // Verify valid response remains
      const remainingResponses = await Response.find({});
      expect(remainingResponses.length).toBeGreaterThanOrEqual(2);
      
      // Valid response should still exist
      const validResponseExists = await Response.findById(validResponse._id);
      expect(validResponseExists).toBeTruthy();
      
      // Only one duplicate token response should remain
      const duplicateTokenResponses = await Response.find({ token: 'duplicate_token' });
      expect(duplicateTokenResponses).toHaveLength(1);
    });

    test('should handle responses with invalid user references', async () => {
      const initialCount = await Response.countDocuments({});
      
      await cleanupService.cleanupOrphanedData(false);
      
      const finalCount = await Response.countDocuments({});
      expect(finalCount).toBeLessThan(initialCount);
    });
  });

  describe('Complete Cleanup Process', () => {
    beforeEach(async () => {
      // Create comprehensive test data
      const oldDate = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
      
      // Expired sessions
      await db.collection('sessions').insertOne({
        _id: 'expired_test',
        expires: oldDate,
        session: '{"test": true}'
      });

      // Inactive user
      const inactiveUser = await User.create({
        username: 'cleanupuser',
        email: 'cleanup@test.com',
        password: 'hashed',
        metadata: {
          registeredAt: oldDate,
          lastLoginAt: oldDate
        }
      });

      // Orphaned response
      await Response.create({
        userId: new mongoose.Types.ObjectId(),
        month: '2025-01',
        responses: [{ question: 'Orphaned?', answer: 'Yes' }],
        authMethod: 'user'
      });
    });

    test('should run complete cleanup process', async () => {
      const report = await cleanupService.runCompleteCleanup();
      
      expect(report.stats.expiredSessions).toBeGreaterThanOrEqual(1);
      expect(report.stats.inactiveUsers).toBeGreaterThanOrEqual(1);
      expect(report.stats.orphanedData).toBeGreaterThanOrEqual(1);
      expect(report.stats.totalCleaned).toBeGreaterThan(0);
      expect(report.stats.lastCleanup).toBeTruthy();
      
      expect(report.recommendations).toEqual(expect.arrayContaining([
        expect.any(String)
      ]));
    });

    test('should run dry run without making changes', async () => {
      const initialSessionCount = await db.collection('sessions').countDocuments({});
      const initialUserCount = await User.countDocuments({});
      const initialResponseCount = await Response.countDocuments({});

      const report = await cleanupService.runCompleteCleanup({ dryRun: true });
      
      // Counts should be unchanged
      expect(await db.collection('sessions').countDocuments({})).toBe(initialSessionCount);
      expect(await User.countDocuments({})).toBe(initialUserCount);
      expect(await Response.countDocuments({})).toBe(initialResponseCount);
      
      // But stats should show what would be cleaned
      expect(report.stats.totalCleaned).toBe(0); // No actual cleaning in dry run
      expect(report.stats.expiredSessions).toBeGreaterThanOrEqual(0);
    });

    test('should handle manual cleanup trigger', async () => {
      const report = await cleanupService.runManualCleanup();
      
      expect(report).toBeTruthy();
      expect(report.stats).toBeTruthy();
      expect(report.timestamp).toBeTruthy();
    });
  });

  describe('Error Handling', () => {
    test('should handle database connection errors gracefully', async () => {
      // Mock a database error
      const originalFind = User.find;
      User.find = jest.fn().mockRejectedValue(new Error('Database connection error'));

      await expect(cleanupService.cleanupInactiveUsers()).rejects.toThrow('Database connection error');
      
      // Restore original method
      User.find = originalFind;
    });

    test('should continue cleanup after partial failures', async () => {
      // Create some valid data and some that will cause errors
      const validUser = await User.create({
        username: 'validuser',
        email: 'valid@test.com',
        password: 'hashed'
      });

      // Mock delete to fail for specific user
      const originalDeleteOne = User.deleteOne;
      User.deleteOne = jest.fn().mockImplementation((filter) => {
        if (filter._id && filter._id.toString() === validUser._id.toString()) {
          throw new Error('Delete failed for this user');
        }
        return originalDeleteOne.call(User, filter);
      });

      // Should not throw, but continue processing
      const report = await cleanupService.runCompleteCleanup();
      expect(report).toBeTruthy();
      
      // Restore original method
      User.deleteOne = originalDeleteOne;
    });
  });

  describe('Statistics and Reporting', () => {
    test('should track cleanup statistics correctly', () => {
      cleanupService.cleanupStats.expiredSessions = 10;
      cleanupService.cleanupStats.inactiveUsers = 5;
      cleanupService.cleanupStats.orphanedData = 3;
      cleanupService.cleanupStats.totalCleaned = 18;

      const stats = cleanupService.getCleanupStats();
      
      expect(stats.expiredSessions).toBe(10);
      expect(stats.inactiveUsers).toBe(5);
      expect(stats.orphanedData).toBe(3);
      expect(stats.totalCleaned).toBe(18);
    });

    test('should generate appropriate recommendations', () => {
      cleanupService.cleanupStats.expiredSessions = 1500;
      cleanupService.cleanupStats.inactiveUsers = 150;
      cleanupService.cleanupStats.orphanedData = 75;
      cleanupService.cleanupStats.totalCleaned = 1725;

      const report = cleanupService.generateCleanupReport();
      
      expect(report.recommendations).toContain('Consider reducing session TTL or increasing cleanup frequency');
      expect(report.recommendations).toContain('Review user engagement strategies to reduce inactivity');
      expect(report.recommendations).toContain('Investigate data integrity issues causing orphaned records');
    });

    test('should reset statistics correctly', () => {
      cleanupService.cleanupStats.expiredSessions = 100;
      cleanupService.cleanupStats.totalCleaned = 150;

      cleanupService.resetStats();
      
      expect(cleanupService.cleanupStats.expiredSessions).toBe(0);
      expect(cleanupService.cleanupStats.inactiveUsers).toBe(0);
      expect(cleanupService.cleanupStats.orphanedData).toBe(0);
      expect(cleanupService.cleanupStats.totalCleaned).toBe(0);
      expect(cleanupService.cleanupStats.lastCleanup).toBeNull();
    });
  });

  describe('Service Lifecycle', () => {
    test('should schedule cleanup when initialized in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const prodService = new SessionCleanupService();
      prodService.config.enableAutoCleanup = true;
      
      // Mock setInterval
      const originalSetInterval = global.setInterval;
      global.setInterval = jest.fn().mockReturnValue('mock-timer-id');

      prodService.scheduleCleanup();
      
      expect(global.setInterval).toHaveBeenCalled();
      
      // Restore
      global.setInterval = originalSetInterval;
      process.env.NODE_ENV = originalEnv;
      prodService.shutdown();
    });

    test('should shutdown gracefully', () => {
      const service = new SessionCleanupService();
      service.cleanupTimer = setInterval(() => {}, 1000);
      
      service.shutdown();
      
      expect(service.cleanupTimer).toBeNull();
    });
  });
});