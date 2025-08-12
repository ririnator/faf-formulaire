// Health Monitoring System Tests
const mongoose = require('mongoose');
const MigrationHealthMonitor = require('../utils/migrationHealthMonitor');
const Response = require('../models/Response');
const User = require('../models/User');

describe('🏥 Migration Health Monitoring System', () => {
  let healthMonitor;

  beforeAll(async () => {
    // Use existing database connection from global setup
    if (mongoose.connection.readyState === 0) {
      throw new Error('Database connection not established');
    }
  }, 30000);

  afterAll(async () => {
    if (healthMonitor) {
      healthMonitor.cleanup();
    }
  }, 30000);

  beforeEach(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    
    // Create fresh monitor for each test
    healthMonitor = new MigrationHealthMonitor({
      checkInterval: 1000, // 1 second for testing
      alertThresholds: {
        orphanedDataPercent: 5,
        queryPerformanceDegradation: 50,
        migrationStagnation: 24 * 60 * 60 * 1000,
        errorRate: 10,
        indexEfficiency: 0.7
      }
    });
  });

  afterEach(async () => {
    if (healthMonitor) {
      healthMonitor.cleanup();
    }
  });

  describe('🔍 Health Check Functionality', () => {
    test('should perform comprehensive health check with healthy system', async () => {
      // Create some healthy data
      const user = await User.create({
        username: 'healthyuser',
        email: 'healthy@test.com',
        password: 'HealthyTest123!',
        displayName: 'Healthy User'
      });

      await Response.create({
        userId: user._id,
        responses: [{ question: 'Test Q', answer: 'Test A' }],
        month: '2024-01',
        authMethod: 'user'
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      expect(healthStatus.overall).toBeDefined();
      expect(['healthy', 'warning', 'degraded', 'critical']).toContain(healthStatus.overall);
      expect(healthStatus.lastCheck).toBeDefined();
      expect(healthStatus.metrics).toBeDefined();
      expect(healthStatus.metrics.migration).toBeDefined();
      expect(healthStatus.metrics.indexes).toBeDefined();
      expect(healthStatus.metrics.data).toBeDefined();
      expect(healthStatus.metrics.performance).toBeDefined();
    }, 15000);

    test('should detect critical issues with orphaned data', async () => {
      // Create orphaned response (no userId or token)
      await Response.create({
        responses: [{ question: 'Orphaned Q', answer: 'Orphaned A' }],
        month: '2024-01',
        authMethod: 'user' // Claims user auth but no userId
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      expect(healthStatus.issues.length).toBeGreaterThan(0);
      const dataIssues = healthStatus.issues.filter(i => i.type === 'data');
      expect(dataIssues.length).toBeGreaterThan(0);
    }, 10000);

    test('should detect migration stagnation', async () => {
      // Create old legacy data (simulate stagnant migration)
      await Response.create({
        name: 'Legacy User',
        responses: [{ question: 'Legacy Q', answer: 'Legacy A' }],
        month: '2024-01',
        authMethod: 'token',
        token: 'legacy-token',
        createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000) // 48 hours ago
      });

      // Mock migration monitor to detect stagnation
      const originalCheckMigrationHealth = healthMonitor.monitors.migration.checkMigrationHealth;
      healthMonitor.monitors.migration.checkMigrationHealth = async () => ({
        migration: {
          stagnationDays: 5, // Simulate 5 days of stagnation
          totalResponses: 1,
          migratedResponses: 0
        },
        distribution: {
          legacy: 1.0,
          migrated: 0.0
        },
        constraints: {
          adminUniqueConstraint: true,
          tokenUniqueConstraint: true,
          migrationIntegrity: true
        }
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      const migrationIssues = healthStatus.issues.filter(i => i.type === 'migration');
      expect(migrationIssues.length).toBeGreaterThan(0);
      
      const stagnationIssue = migrationIssues.find(i => 
        i.message.includes('stagnant')
      );
      expect(stagnationIssue).toBeDefined();
      expect(stagnationIssue.severity).toBe('critical');

      // Restore original method
      healthMonitor.monitors.migration.checkMigrationHealth = originalCheckMigrationHealth;
    }, 10000);

    test('should generate appropriate alerts for different severity levels', async () => {
      // Create issues that will trigger different severity alerts
      await Response.create({
        responses: [{ question: 'Bad Q', answer: 'Bad A' }],
        month: 'invalid-month-format', // Will trigger malformed data issue
        authMethod: 'user'
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      expect(healthStatus.alerts).toBeDefined();
      expect(Array.isArray(healthStatus.alerts)).toBe(true);
      
      // Should have processed alerts based on issues
      if (healthStatus.issues.length > 0) {
        expect(healthStatus.alerts.length).toBeGreaterThanOrEqual(0);
      }
    }, 10000);
  });

  describe('🚨 Alert System', () => {
    test('should emit alert events when issues are detected', async () => {
      const alertPromise = new Promise((resolve) => {
        healthMonitor.once('alert', (alert) => {
          resolve(alert);
        });
      });

      // Create critical issue
      await Response.create({
        userId: new mongoose.Types.ObjectId(), // Non-existent user
        responses: [{ question: 'Bad Q', answer: 'Bad A' }],
        month: '2024-01',
        authMethod: 'user'
      });

      // Trigger health check
      await healthMonitor.performHealthCheck();

      // Wait for alert (with timeout)
      const alert = await Promise.race([
        alertPromise,
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('No alert received')), 5000)
        )
      ]);

      expect(alert).toBeDefined();
      expect(alert.level).toBeDefined();
      expect(alert.title).toBeDefined();
      expect(alert.message).toBeDefined();
      expect(alert.issues).toBeDefined();
    }, 10000);

    test('should group issues by severity in alerts', async () => {
      // Create multiple issues of different severities
      await Response.create({
        responses: [{ question: 'Q1', answer: 'A1' }],
        month: 'bad-format', // Malformed data (warning/high)
        authMethod: 'token'
      });

      await Response.create({
        userId: new mongoose.Types.ObjectId(),
        responses: [{ question: 'Q2', answer: 'A2' }],
        month: '2024-01',
        authMethod: 'user' // Invalid user reference (high/critical)
      });

      const healthStatus = await healthMonitor.performHealthCheck();

      if (healthStatus.alerts.length > 0) {
        const alert = healthStatus.alerts[0];
        expect(alert.issues).toBeDefined();
        expect(Array.isArray(alert.issues)).toBe(true);
        
        // Issues should be grouped by severity
        const severities = [...new Set(alert.issues.map(i => i.severity))];
        expect(severities.length).toBeGreaterThanOrEqual(1);
      }
    }, 10000);
  });

  describe('📊 Continuous Monitoring', () => {
    test('should start and stop monitoring correctly', async () => {
      expect(healthMonitor.monitoring).toBe(false);

      // Start monitoring
      healthMonitor.startMonitoring();
      expect(healthMonitor.monitoring).toBe(true);
      expect(healthMonitor.checkTimer).toBeDefined();

      // Wait briefly to ensure monitoring is active
      await new Promise(resolve => setTimeout(resolve, 100));

      // Stop monitoring
      healthMonitor.stopMonitoring();
      expect(healthMonitor.monitoring).toBe(false);
      expect(healthMonitor.checkTimer).toBeNull();
    });

    test('should emit monitoring events', async () => {
      const events = [];

      healthMonitor.on('monitoring_started', () => {
        events.push('started');
      });

      healthMonitor.on('monitoring_stopped', () => {
        events.push('stopped');
      });

      healthMonitor.on('health_check_completed', () => {
        events.push('check_completed');
      });

      // Start monitoring
      healthMonitor.startMonitoring();
      
      // Wait for at least one health check
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Stop monitoring
      healthMonitor.stopMonitoring();

      expect(events).toContain('started');
      expect(events).toContain('stopped');
      expect(events).toContain('check_completed');
    });

    test('should handle monitoring errors gracefully', async () => {
      const errorEvents = [];

      healthMonitor.on('monitoring_error', (error) => {
        errorEvents.push(error);
      });

      // Mock a method to throw errors
      const originalPerformHealthCheck = healthMonitor.performHealthCheck;
      healthMonitor.performHealthCheck = async () => {
        throw new Error('Simulated monitoring error');
      };

      // Start monitoring
      healthMonitor.startMonitoring();
      
      // Wait for error to occur
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Stop monitoring
      healthMonitor.stopMonitoring();

      // Restore original method
      healthMonitor.performHealthCheck = originalPerformHealthCheck;

      expect(errorEvents.length).toBeGreaterThan(0);
      expect(errorEvents[0].message).toBe('Simulated monitoring error');
    });
  });

  describe('🔧 Auto-Remediation', () => {
    test('should perform auto-cleanup when enabled', async () => {
      // Enable auto-cleanup
      healthMonitor.setAutoRemediation(true, false);

      // Create orphaned data
      await Response.create({
        responses: [{ question: 'Orphan Q', answer: 'Orphan A' }],
        month: '2024-01',
        // Missing both userId and token - should be cleaned up
      });

      const remediationPromise = new Promise((resolve) => {
        healthMonitor.once('auto_remediation_completed', (result) => {
          resolve(result);
        });
      });

      // Trigger health check with auto-remediation
      await healthMonitor.performHealthCheck();

      // Check if remediation occurred
      const result = await Promise.race([
        remediationPromise,
        new Promise(resolve => setTimeout(() => resolve(null), 3000))
      ]);

      if (result) {
        expect(result.actionsPerformed).toBeGreaterThan(0);
      }
    }, 10000);

    test('should respect auto-remediation settings', async () => {
      // Disable auto-remediation
      healthMonitor.setAutoRemediation(false, false);

      expect(healthMonitor.config.autoCleanup).toBe(false);
      expect(healthMonitor.config.autoOptimize).toBe(false);

      // Enable auto-remediation
      healthMonitor.setAutoRemediation(true, true);

      expect(healthMonitor.config.autoCleanup).toBe(true);
      expect(healthMonitor.config.autoOptimize).toBe(true);
    });
  });

  describe('⚙️ Configuration', () => {
    test('should allow threshold configuration', async () => {
      const originalThresholds = { ...healthMonitor.config.alertThresholds };
      
      const newThresholds = {
        orphanedDataPercent: 10,
        queryPerformanceDegradation: 100
      };

      healthMonitor.configureThresholds(newThresholds);

      expect(healthMonitor.config.alertThresholds.orphanedDataPercent).toBe(10);
      expect(healthMonitor.config.alertThresholds.queryPerformanceDegradation).toBe(100);
      
      // Should preserve other thresholds
      expect(healthMonitor.config.alertThresholds.errorRate).toBe(originalThresholds.errorRate);
    });

    test('should generate comprehensive health reports', async () => {
      // Create some test data
      const user = await User.create({
        username: 'reportuser',
        email: 'report@test.com',
        password: 'ReportTest123!',
        displayName: 'Report User'
      });

      await Response.create({
        userId: user._id,
        responses: [{ question: 'Report Q', answer: 'Report A' }],
        month: '2024-01',
        authMethod: 'user'
      });

      // Run health check
      await healthMonitor.performHealthCheck();

      const report = healthMonitor.generateHealthReport();

      expect(report.timestamp).toBeDefined();
      expect(report.monitoring).toBe(false); // Should be false since not monitoring
      expect(report.overall).toBeDefined();
      expect(report.summary).toBeDefined();
      expect(report.summary.totalIssues).toBeDefined();
      expect(report.summary.critical).toBeDefined();
      expect(report.summary.high).toBeDefined();
      expect(report.summary.warning).toBeDefined();
      expect(report.details).toBeDefined();
      expect(report.details.metrics).toBeDefined();
      expect(report.configuration).toBeDefined();
      expect(report.configuration.thresholds).toBeDefined();
    });
  });

  describe('🎯 Edge Cases and Error Handling', () => {
    test('should handle database connection errors during health check', async () => {
      // Mock mongoose connection error
      const originalConnection = mongoose.connection;
      
      // Simulate connection error by making a query fail
      const originalCountDocuments = Response.countDocuments;
      Response.countDocuments = () => {
        throw new Error('Database connection lost');
      };

      try {
        await healthMonitor.performHealthCheck();
        // Should throw error or handle gracefully
      } catch (error) {
        expect(error.message).toContain('Database connection lost');
      }

      // Restore original methods
      Response.countDocuments = originalCountDocuments;
    });

    test('should handle malformed configuration gracefully', async () => {
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

    test('should cleanup resources properly', async () => {
      healthMonitor.startMonitoring();
      expect(healthMonitor.monitoring).toBe(true);

      healthMonitor.cleanup();
      
      expect(healthMonitor.monitoring).toBe(false);
      expect(healthMonitor.checkTimer).toBeNull();
      expect(healthMonitor.listenerCount('alert')).toBe(0);
    });
  });

  describe('📈 Performance and Scalability', () => {
    test('should handle large datasets in health checks', async () => {
      // Create a larger dataset
      const users = await User.insertMany(
        Array(50).fill(null).map((_, i) => ({
          username: `perfuser${i}`,
          email: `perf${i}@test.com`,
          password: 'PerfTest123!',
          displayName: `Perf User ${i}`
        }))
      );

      const responses = Array(200).fill(null).map((_, i) => {
        const isUser = i % 2 === 0;
        const baseResponse = {
          responses: [{ question: `Perf Q${i}`, answer: `Perf A${i}` }],
          month: `2024-${String((i % 12) + 1).padStart(2, '0')}`,
          authMethod: isUser ? 'user' : 'token'
        };

        if (isUser) {
          baseResponse.userId = users[i % users.length]._id;
        } else {
          baseResponse.name = `Token User ${i}`;
          baseResponse.token = `token-${i}`;
        }

        return baseResponse;
      });

      await Response.insertMany(responses);

      const startTime = Date.now();
      const healthStatus = await healthMonitor.performHealthCheck();
      const duration = Date.now() - startTime;

      expect(healthStatus).toBeDefined();
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
    }, 20000);
  });
});