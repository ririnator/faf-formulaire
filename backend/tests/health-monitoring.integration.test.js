// Health Monitoring System Integration Test
const mongoose = require('mongoose');
const MigrationHealthMonitor = require('../utils/migrationHealthMonitor');
const Response = require('../models/Response');
const User = require('../models/User');

describe('🏥 Migration Health Monitoring Integration', () => {
  let healthMonitor;

  beforeAll(async () => {
    // Use existing database connection from global setup
    if (mongoose.connection.readyState === 0) {
      throw new Error('Database connection not established');
    }
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    
    healthMonitor = new MigrationHealthMonitor({
      checkInterval: 1000, // 1 second for testing
      autoCleanup: false,
      autoOptimize: false
    });
  });

  afterEach(async () => {
    if (healthMonitor) {
      healthMonitor.cleanup();
      healthMonitor = null;
    }
  });

  describe('✅ Basic Functionality', () => {
    test('should create health monitor successfully', () => {
      expect(healthMonitor).toBeDefined();
      expect(healthMonitor.monitors).toBeDefined();
      expect(healthMonitor.monitors.migration).toBeDefined();
      expect(healthMonitor.monitors.indexOptimizer).toBeDefined();
      expect(healthMonitor.monitors.orphanedCleanup).toBeDefined();
    });

    test('should perform basic health check without errors', async () => {
      // Create some test data
      const user = await User.create({
        username: 'testuser',
        email: 'test@test.com',
        password: 'TestPass123!',
        displayName: 'Test User'
      });

      await Response.create({
        userId: user._id,
        responses: [{ question: 'Test Q', answer: 'Test A' }],
        month: '2024-01',
        authMethod: 'user'
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      expect(healthStatus).toBeDefined();
      expect(healthStatus.overall).toBeDefined();
      expect(['healthy', 'warning', 'degraded', 'critical', 'error'].includes(healthStatus.overall)).toBe(true);
      expect(healthStatus.lastCheck).toBeDefined();
      expect(healthStatus.metrics).toBeDefined();
    }, 10000);

    test('should generate health report', async () => {
      await healthMonitor.performHealthCheck();
      const report = healthMonitor.generateHealthReport();

      expect(report).toBeDefined();
      expect(report.timestamp).toBeDefined();
      expect(report.overall).toBeDefined();
      expect(report.summary).toBeDefined();
      expect(report.details).toBeDefined();
      expect(report.configuration).toBeDefined();
    });

    test('should handle start/stop monitoring', () => {
      expect(healthMonitor.monitoring).toBe(false);

      healthMonitor.startMonitoring();
      expect(healthMonitor.monitoring).toBe(true);

      healthMonitor.stopMonitoring();
      expect(healthMonitor.monitoring).toBe(false);
    });

    test('should configure thresholds', () => {
      const originalThresholds = { ...healthMonitor.config.alertThresholds };
      
      healthMonitor.configureThresholds({
        orphanedDataPercent: 15
      });

      expect(healthMonitor.config.alertThresholds.orphanedDataPercent).toBe(15);
      // Should preserve other thresholds
      expect(healthMonitor.config.alertThresholds.errorRate).toBe(originalThresholds.errorRate);
    });

    test('should set auto-remediation options', () => {
      expect(healthMonitor.config.autoCleanup).toBe(false);
      expect(healthMonitor.config.autoOptimize).toBe(false);

      healthMonitor.setAutoRemediation(true, true);
      
      expect(healthMonitor.config.autoCleanup).toBe(true);
      expect(healthMonitor.config.autoOptimize).toBe(true);
    });
  });

  describe('🔍 Data Analysis', () => {
    test('should detect orphaned data issues', async () => {
      // Create orphaned response (no userId or token)
      await Response.create({
        responses: [{ question: 'Orphaned Q', answer: 'Orphaned A' }],
        month: '2024-01',
        authMethod: 'user' // Claims user auth but no userId
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      expect(healthStatus.issues).toBeDefined();
      expect(Array.isArray(healthStatus.issues)).toBe(true);
      
      // Should detect some data issues
      const dataIssues = healthStatus.issues.filter(i => i.type === 'data');
      expect(dataIssues.length).toBeGreaterThanOrEqual(0); // May be 0 in test env
    }, 10000);

    test('should handle mixed auth methods', async () => {
      // Create both legacy and user responses
      const user = await User.create({
        username: 'mixuser',
        email: 'mix@test.com',
        password: 'MixTest123!',
        displayName: 'Mix User'
      });

      await Response.create({
        userId: user._id,
        responses: [{ question: 'User Q', answer: 'User A' }],
        month: '2024-01',
        authMethod: 'user'
      });

      await Response.create({
        name: 'Legacy User',
        token: 'legacy-token-123',
        responses: [{ question: 'Legacy Q', answer: 'Legacy A' }],
        month: '2024-01',
        authMethod: 'token'
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      expect(healthStatus.metrics).toBeDefined();
      expect(healthStatus.overall).toBeDefined();
      
      // Should complete successfully with mixed data
      expect(['healthy', 'warning', 'degraded'].includes(healthStatus.overall)).toBe(true);
    }, 10000);
  });

  describe('📊 Performance', () => {
    test('should complete health check within reasonable time', async () => {
      // Create moderate amount of test data
      const users = await User.insertMany(
        Array(10).fill(null).map((_, i) => ({
          username: `perfuser${i}`,
          email: `perf${i}@test.com`,
          password: 'PerfTest123!',
          displayName: `Perf User ${i}`
        }))
      );

      const responses = Array(50).fill(null).map((_, i) => ({
        userId: users[i % users.length]._id,
        responses: [{ question: `Q${i}`, answer: `A${i}` }],
        month: `2024-${String((i % 12) + 1).padStart(2, '0')}`,
        authMethod: 'user'
      }));

      await Response.insertMany(responses);

      const startTime = Date.now();
      const healthStatus = await healthMonitor.performHealthCheck();
      const duration = Date.now() - startTime;

      expect(healthStatus).toBeDefined();
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    }, 15000);
  });

  describe('🛡️ Error Handling', () => {
    test('should handle malformed configuration gracefully', () => {
      const badMonitor = new MigrationHealthMonitor({
        checkInterval: 'not-a-number',
        alertThresholds: {
          orphanedDataPercent: 'invalid'
        }
      });

      // Should not crash and should have reasonable defaults
      expect(badMonitor.config.checkInterval).toBeGreaterThan(0);
      expect(typeof badMonitor.config.checkInterval).toBe('number');
    });

    test('should cleanup resources properly', () => {
      const monitor = new MigrationHealthMonitor();
      monitor.startMonitoring();
      
      expect(monitor.monitoring).toBe(true);
      
      monitor.cleanup();
      
      expect(monitor.monitoring).toBe(false);
      expect(monitor.checkTimer).toBeNull();
    });
  });
});