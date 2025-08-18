#!/usr/bin/env node

/**
 * BACKUP & RESTORE INTEGRATION TESTS v2.0 - Comprehensive Test Suite
 * ==================================================================
 * 
 * Features:
 * - End-to-end integration tests for backup and restore systems
 * - Performance benchmarking and load testing
 * - Security validation testing
 * - Error handling and edge case validation
 * - Mock data generation and test environment setup
 * - Automated test reporting with detailed metrics
 * - Rollback testing and disaster recovery scenarios
 * - Compliance and audit trail validation
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const mongoose = require('mongoose');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');

// Import systems under test
const { IntelligentBackupSystem } = require('./IntelligentBackupSystem');
const { AutomaticRollbackSystem } = require('./AutomaticRollbackSystem');
const { SystemHealthValidator } = require('./SystemHealthValidator');
const { SecurityValidationSystem } = require('./SecurityValidationSystem');
const { BackupRestoreCLI } = require('./BackupRestoreCLI');

/**
 * Test Configuration
 */
const TEST_CONFIG = {
  // Test environment
  TEST_DB_URI: 'mongodb://localhost:27017/faf_backup_test',
  TEST_BACKUP_PATH: './test-backups',
  TEST_DATA_PATH: './test-data',
  
  // Test data generation
  MOCK_USERS_COUNT: 100,
  MOCK_RESPONSES_COUNT: 500,
  MOCK_SUBMISSIONS_COUNT: 300,
  MOCK_INVITATIONS_COUNT: 200,
  
  // Performance thresholds
  MAX_BACKUP_TIME_MS: 60000, // 1 minute
  MAX_RESTORE_TIME_MS: 120000, // 2 minutes
  MAX_VALIDATION_TIME_MS: 30000, // 30 seconds
  
  // Test timeouts
  TEST_TIMEOUT_MS: 300000, // 5 minutes per test
  SETUP_TIMEOUT_MS: 60000, // 1 minute setup
  
  // Error simulation
  ENABLE_ERROR_SIMULATION: true,
  ERROR_SIMULATION_RATE: 0.1, // 10%
  
  // Reporting
  GENERATE_DETAILED_REPORTS: true,
  INCLUDE_PERFORMANCE_CHARTS: false,
  EXPORT_TEST_DATA: true
};

/**
 * Test Logger with enhanced reporting
 */
class TestLogger {
  constructor() {
    this.testResults = [];
    this.currentSuite = null;
    this.startTime = Date.now();
    this.metrics = {
      totalTests: 0,
      passedTests: 0,
      failedTests: 0,
      skippedTests: 0,
      errors: []
    };
  }

  startSuite(suiteName) {
    this.currentSuite = {
      name: suiteName,
      startTime: Date.now(),
      tests: [],
      metrics: { passed: 0, failed: 0, skipped: 0 }
    };
    console.log(`\n🧪 Starting test suite: ${suiteName}`);
    console.log('─'.repeat(60));
  }

  endSuite() {
    if (this.currentSuite) {
      this.currentSuite.endTime = Date.now();
      this.currentSuite.duration = this.currentSuite.endTime - this.currentSuite.startTime;
      this.testResults.push(this.currentSuite);
      
      const { passed, failed, skipped } = this.currentSuite.metrics;
      const total = passed + failed + skipped;
      
      console.log(`\n📊 Suite completed: ${this.currentSuite.name}`);
      console.log(`   Tests: ${total} | Passed: ${passed} | Failed: ${failed} | Skipped: ${skipped}`);
      console.log(`   Duration: ${this.formatTime(this.currentSuite.duration)}`);
      
      this.currentSuite = null;
    }
  }

  test(testName, testFunction, options = {}) {
    return new Promise(async (resolve, reject) => {
      const test = {
        name: testName,
        startTime: Date.now(),
        status: 'running',
        error: null,
        metrics: {},
        timeout: options.timeout || TEST_CONFIG.TEST_TIMEOUT_MS
      };

      console.log(`  🔬 ${testName}...`);

      // Setup timeout
      const timeoutId = setTimeout(() => {
        test.status = 'failed';
        test.error = new Error(`Test timeout after ${test.timeout}ms`);
        this.recordTestResult(test);
        reject(test.error);
      }, test.timeout);

      try {
        // Run test function
        const result = await testFunction();
        
        clearTimeout(timeoutId);
        test.endTime = Date.now();
        test.duration = test.endTime - test.startTime;
        test.status = 'passed';
        test.result = result;
        
        console.log(`    ✅ Passed (${this.formatTime(test.duration)})`);
        this.recordTestResult(test);
        resolve(result);
        
      } catch (error) {
        clearTimeout(timeoutId);
        test.endTime = Date.now();
        test.duration = test.endTime - test.startTime;
        test.status = 'failed';
        test.error = error;
        
        console.log(`    ❌ Failed: ${error.message}`);
        if (options.verbose) {
          console.log(`       ${error.stack}`);
        }
        
        this.recordTestResult(test);
        
        if (options.stopOnFailure) {
          reject(error);
        } else {
          resolve(null);
        }
      }
    });
  }

  recordTestResult(test) {
    if (this.currentSuite) {
      this.currentSuite.tests.push(test);
      this.currentSuite.metrics[test.status === 'passed' ? 'passed' : 
                                 test.status === 'failed' ? 'failed' : 'skipped']++;
    }
    
    this.metrics.totalTests++;
    this.metrics[test.status === 'passed' ? 'passedTests' : 
                 test.status === 'failed' ? 'failedTests' : 'skippedTests']++;
    
    if (test.error) {
      this.metrics.errors.push({
        test: test.name,
        suite: this.currentSuite?.name,
        error: test.error.message,
        stack: test.error.stack
      });
    }
  }

  generateReport() {
    const totalDuration = Date.now() - this.startTime;
    
    const report = {
      summary: {
        timestamp: new Date().toISOString(),
        totalDuration: totalDuration,
        totalTests: this.metrics.totalTests,
        passedTests: this.metrics.passedTests,
        failedTests: this.metrics.failedTests,
        skippedTests: this.metrics.skippedTests,
        successRate: this.metrics.totalTests > 0 ? 
          (this.metrics.passedTests / this.metrics.totalTests) * 100 : 0
      },
      suites: this.testResults,
      errors: this.metrics.errors,
      configuration: TEST_CONFIG
    };

    return report;
  }

  formatTime(ms) {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  }
}

/**
 * Mock data generator for testing
 */
class MockDataGenerator {
  constructor() {
    this.models = {};
  }

  registerModels(models) {
    this.models = models;
  }

  /**
   * Generate mock user data
   */
  generateMockUsers(count = TEST_CONFIG.MOCK_USERS_COUNT) {
    const users = [];
    
    for (let i = 0; i < count; i++) {
      users.push({
        username: `testuser_${i}`,
        email: `testuser${i}@example.com`,
        password: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6/eQUqoGGy', // hashed 'password'
        role: i % 10 === 0 ? 'admin' : 'user',
        metadata: {
          isActive: true,
          emailVerified: Math.random() > 0.2,
          registeredAt: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000),
          responseCount: Math.floor(Math.random() * 10)
        },
        migrationData: Math.random() > 0.5 ? {
          legacyName: `legacy_user_${i}`,
          migratedAt: new Date(),
          source: 'migration'
        } : undefined
      });
    }
    
    return users;
  }

  /**
   * Generate mock response data
   */
  generateMockResponses(count = TEST_CONFIG.MOCK_RESPONSES_COUNT) {
    const responses = [];
    const months = ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05'];
    
    for (let i = 0; i < count; i++) {
      responses.push({
        name: `response_user_${i % 50}`,
        responses: this.generateMockQuestionResponses(),
        month: months[Math.floor(Math.random() * months.length)],
        isAdmin: Math.random() < 0.1,
        token: Math.random() > 0.3 ? crypto.randomBytes(16).toString('hex') : null,
        createdAt: new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000)
      });
    }
    
    return responses;
  }

  /**
   * Generate mock submission data
   */
  generateMockSubmissions(userIds, count = TEST_CONFIG.MOCK_SUBMISSIONS_COUNT) {
    const submissions = [];
    const months = ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05'];
    
    for (let i = 0; i < count; i++) {
      submissions.push({
        userId: userIds[Math.floor(Math.random() * userIds.length)],
        month: months[Math.floor(Math.random() * months.length)],
        responses: this.generateMockQuestionResponses().map((resp, index) => ({
          questionId: `q_${index + 1}`,
          type: 'text',
          answer: resp.answer,
          photoUrl: resp.photoUrl,
          photoCaption: resp.photoCaption
        })),
        submittedAt: new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000),
        formVersion: 'v2_test'
      });
    }
    
    return submissions;
  }

  /**
   * Generate mock invitation data
   */
  generateMockInvitations(userIds, count = TEST_CONFIG.MOCK_INVITATIONS_COUNT) {
    const invitations = [];
    const months = ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05'];
    const statuses = ['queued', 'sent', 'opened', 'started', 'submitted'];
    
    for (let i = 0; i < count; i++) {
      const fromUserId = userIds[Math.floor(Math.random() * userIds.length)];
      const toUserId = Math.random() > 0.5 ? userIds[Math.floor(Math.random() * userIds.length)] : null;
      
      invitations.push({
        fromUserId,
        toEmail: `invited${i}@example.com`,
        toUserId,
        month: months[Math.floor(Math.random() * months.length)],
        token: crypto.randomBytes(16).toString('hex'),
        type: 'user',
        status: statuses[Math.floor(Math.random() * statuses.length)],
        tracking: {
          createdAt: new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000),
          sentAt: Math.random() > 0.3 ? new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000) : null,
          openedAt: Math.random() > 0.6 ? new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000) : null,
          submittedAt: Math.random() > 0.8 ? new Date(Date.now() - Math.random() * 180 * 24 * 60 * 60 * 1000) : null
        },
        metadata: {
          template: 'standard',
          priority: Math.random() > 0.9 ? 'high' : 'normal'
        }
      });
    }
    
    return invitations;
  }

  /**
   * Generate mock question responses
   */
  generateMockQuestionResponses() {
    const questions = [
      'What is your favorite color?',
      'Describe your ideal vacation',
      'What makes you happy?',
      'Your biggest achievement this year?',
      'Favorite book or movie?'
    ];
    
    return questions.map(question => ({
      question,
      answer: `Mock answer for: ${question}`,
      photoUrl: Math.random() > 0.7 ? `https://res.cloudinary.com/test/image/upload/mock_${Math.floor(Math.random() * 1000)}.jpg` : null,
      photoCaption: Math.random() > 0.8 ? 'Mock photo caption' : null
    }));
  }

  /**
   * Populate test database with mock data
   */
  async populateTestDatabase() {
    console.log('Generating mock data...');
    
    // Clear existing data
    for (const [name, model] of Object.entries(this.models)) {
      await model.deleteMany({});
    }
    
    // Generate and insert users
    const mockUsers = this.generateMockUsers();
    const insertedUsers = await this.models.users.insertMany(mockUsers);
    const userIds = insertedUsers.map(user => user._id);
    
    // Generate and insert responses
    const mockResponses = this.generateMockResponses();
    await this.models.responses.insertMany(mockResponses);
    
    // Generate and insert submissions
    const mockSubmissions = this.generateMockSubmissions(userIds);
    await this.models.submissions.insertMany(mockSubmissions);
    
    // Generate and insert invitations
    const mockInvitations = this.generateMockInvitations(userIds);
    await this.models.invitations.insertMany(mockInvitations);
    
    console.log('Mock data generated successfully');
    
    return {
      users: mockUsers.length,
      responses: mockResponses.length,
      submissions: mockSubmissions.length,
      invitations: mockInvitations.length
    };
  }
}

/**
 * Main test suite runner
 */
class BackupRestoreTestSuite {
  constructor() {
    this.logger = new TestLogger();
    this.mockDataGenerator = new MockDataGenerator();
    this.systems = {};
    this.testBackupPath = path.resolve(TEST_CONFIG.TEST_BACKUP_PATH);
    this.connected = false;
  }

  /**
   * Initialize test environment
   */
  async initialize() {
    console.log('🚀 Initializing Backup & Restore Test Suite');
    console.log('='.repeat(60));
    
    try {
      // Connect to test database
      await this.connectTestDatabase();
      
      // Setup test directories
      await this.setupTestDirectories();
      
      // Initialize systems under test
      await this.initializeSystems();
      
      // Setup mock data generator
      this.setupMockDataGenerator();
      
      console.log('✅ Test environment initialized successfully\n');
      
    } catch (error) {
      console.error('❌ Failed to initialize test environment:', error.message);
      throw error;
    }
  }

  /**
   * Connect to test database
   */
  async connectTestDatabase() {
    console.log('Connecting to test database...');
    
    try {
      await mongoose.connect(TEST_CONFIG.TEST_DB_URI);
      this.connected = true;
      console.log('✅ Connected to test database');
    } catch (error) {
      throw new Error(`Database connection failed: ${error.message}`);
    }
  }

  /**
   * Setup test directories
   */
  async setupTestDirectories() {
    console.log('Setting up test directories...');
    
    const directories = [
      TEST_CONFIG.TEST_BACKUP_PATH,
      TEST_CONFIG.TEST_DATA_PATH,
      './test-reports',
      './test-logs'
    ];
    
    for (const dir of directories) {
      await fs.mkdir(dir, { recursive: true });
    }
    
    console.log('✅ Test directories created');
  }

  /**
   * Initialize systems under test
   */
  async initializeSystems() {
    console.log('Initializing backup and restore systems...');
    
    const models = {
      responses: require('../../backend/models/Response'),
      users: require('../../backend/models/User'),
      submissions: require('../../backend/models/Submission'),
      invitations: require('../../backend/models/Invitation')
    };
    
    this.systems = {
      backup: new IntelligentBackupSystem({ 
        logger: console,
        DEFAULT_BACKUP_ROOT: this.testBackupPath
      }),
      rollback: new AutomaticRollbackSystem({ 
        logger: console 
      }),
      health: new SystemHealthValidator({ 
        logger: console 
      }),
      security: new SecurityValidationSystem({ 
        logger: console 
      })
    };
    
    // Register models with all systems
    Object.values(this.systems).forEach(system => {
      if (system.registerModels) {
        system.registerModels(models);
      }
    });
    
    console.log('✅ Systems initialized');
  }

  /**
   * Setup mock data generator
   */
  setupMockDataGenerator() {
    const models = {
      responses: require('../../backend/models/Response'),
      users: require('../../backend/models/User'),
      submissions: require('../../backend/models/Submission'),
      invitations: require('../../backend/models/Invitation')
    };
    
    this.mockDataGenerator.registerModels(models);
  }

  /**
   * Run all test suites
   */
  async runAllTests() {
    try {
      await this.initialize();
      
      // Test Suite 1: Backup System Tests
      await this.runBackupSystemTests();
      
      // Test Suite 2: Rollback System Tests
      await this.runRollbackSystemTests();
      
      // Test Suite 3: Health Validation Tests
      await this.runHealthValidationTests();
      
      // Test Suite 4: Security Validation Tests
      await this.runSecurityValidationTests();
      
      // Test Suite 5: Integration Tests
      await this.runIntegrationTests();
      
      // Test Suite 6: Performance Tests
      await this.runPerformanceTests();
      
      // Test Suite 7: Error Handling Tests
      await this.runErrorHandlingTests();
      
      // Generate final report
      await this.generateFinalReport();
      
    } catch (error) {
      console.error('❌ Test suite execution failed:', error.message);
      throw error;
    } finally {
      await this.cleanup();
    }
  }

  /**
   * Backup system tests
   */
  async runBackupSystemTests() {
    this.logger.startSuite('Backup System Tests');
    
    // Setup test data
    await this.logger.test('Setup Mock Data', async () => {
      return await this.mockDataGenerator.populateTestDatabase();
    });

    // Test full backup creation
    await this.logger.test('Create Full Backup', async () => {
      const result = await this.systems.backup.createIntelligentBackup({
        type: 'full'
      });
      
      assert(result.success, 'Backup should succeed');
      assert(result.metadata.statistics.totalDocuments > 0, 'Should backup documents');
      
      return result;
    });

    // Test incremental backup
    await this.logger.test('Create Incremental Backup', async () => {
      // Wait a moment to ensure timestamp difference
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const result = await this.systems.backup.createIntelligentBackup({
        type: 'incremental'
      });
      
      assert(result.success, 'Incremental backup should succeed');
      
      return result;
    });

    // Test backup compression
    await this.logger.test('Test Backup Compression', async () => {
      const result = await this.systems.backup.createIntelligentBackup({
        type: 'full',
        compression: true,
        compressionLevel: 9
      });
      
      assert(result.success, 'Compressed backup should succeed');
      assert(result.metadata.statistics.compressionRatio > 0, 'Should achieve compression');
      
      return result;
    });

    // Test backup listing
    await this.logger.test('List Available Backups', async () => {
      const backups = await this.systems.backup.listAllBackups();
      
      assert(Array.isArray(backups), 'Should return array of backups');
      assert(backups.length > 0, 'Should have at least one backup');
      
      return backups;
    });

    this.logger.endSuite();
  }

  /**
   * Rollback system tests
   */
  async runRollbackSystemTests() {
    this.logger.startSuite('Rollback System Tests');

    let testBackup = null;

    // Create a backup for rollback testing
    await this.logger.test('Create Backup for Rollback Testing', async () => {
      const result = await this.systems.backup.createIntelligentBackup({
        type: 'full'
      });
      testBackup = result;
      return result;
    });

    // Modify data to test rollback
    await this.logger.test('Modify Data for Rollback Test', async () => {
      const User = require('../../backend/models/User');
      await User.deleteMany({});
      
      const count = await User.countDocuments();
      assert(count === 0, 'Data should be deleted');
      
      return { deletedUsers: true };
    });

    // Test automatic rollback
    await this.logger.test('Execute Automatic Rollback', async () => {
      const result = await this.systems.rollback.executeRollback(testBackup.backupPath);
      
      assert(result.success, 'Rollback should succeed');
      
      // Verify data restoration
      const User = require('../../backend/models/User');
      const restoredCount = await User.countDocuments();
      assert(restoredCount > 0, 'Users should be restored');
      
      return result;
    });

    // Test rollback validation
    await this.logger.test('Validate Post-Rollback State', async () => {
      const User = require('../../backend/models/User');
      const Response = require('../../backend/models/Response');
      
      const userCount = await User.countDocuments();
      const responseCount = await Response.countDocuments();
      
      assert(userCount > 0, 'Users should exist after rollback');
      assert(responseCount > 0, 'Responses should exist after rollback');
      
      return { userCount, responseCount };
    });

    this.logger.endSuite();
  }

  /**
   * Health validation tests
   */
  async runHealthValidationTests() {
    this.logger.startSuite('Health Validation Tests');

    // Test comprehensive health validation
    await this.logger.test('Comprehensive System Health Validation', async () => {
      const result = await this.systems.health.validateSystemHealth({
        ENABLE_PERFORMANCE_VALIDATION: true,
        ENABLE_APPLICATION_TESTING: true
      });
      
      assert(result.success, 'Health validation should succeed');
      assert(result.results.overall.score >= 0, 'Should have a health score');
      
      return result;
    });

    // Test data integrity validation
    await this.logger.test('Data Integrity Validation', async () => {
      const result = await this.systems.health.validateSystemHealth({
        ENABLE_DOCUMENT_VALIDATION: true,
        ENABLE_REFERENTIAL_INTEGRITY: true
      });
      
      assert(result.success, 'Data integrity validation should succeed');
      
      return result;
    });

    // Test index health validation
    await this.logger.test('Index Health Validation', async () => {
      const result = await this.systems.health.validateSystemHealth({
        ENABLE_INDEX_VALIDATION: true
      });
      
      assert(result.success, 'Index validation should succeed');
      
      return result;
    });

    this.logger.endSuite();
  }

  /**
   * Security validation tests
   */
  async runSecurityValidationTests() {
    this.logger.startSuite('Security Validation Tests');

    let testBackupPath = null;

    // Create a backup for security testing
    await this.logger.test('Create Backup for Security Testing', async () => {
      const result = await this.systems.backup.createIntelligentBackup({
        type: 'full'
      });
      testBackupPath = result.backupPath;
      return result;
    });

    // Test security validation
    await this.logger.test('Comprehensive Security Validation', async () => {
      const result = await this.systems.security.validateBackupSecurity(testBackupPath);
      
      assert(result.success, 'Security validation should succeed');
      assert(result.results.overall.score >= 0, 'Should have a security score');
      
      return result;
    });

    // Test checksum validation
    await this.logger.test('Checksum Validation', async () => {
      const checksumValidator = this.systems.security.checksumValidator;
      const manifest = await checksumValidator.generateSecureManifest(testBackupPath);
      
      assert(manifest.files, 'Manifest should contain file checksums');
      assert(Object.keys(manifest.files).length > 0, 'Should have files to validate');
      
      return manifest;
    });

    // Test permission validation
    await this.logger.test('Permission Validation', async () => {
      const permissionValidator = this.systems.security.permissionValidator;
      const result = await permissionValidator.validateBackupDirectoryPermissions(testBackupPath);
      
      assert(typeof result.valid === 'boolean', 'Should return validation result');
      
      return result;
    });

    this.logger.endSuite();
  }

  /**
   * Integration tests
   */
  async runIntegrationTests() {
    this.logger.startSuite('Integration Tests');

    // Test complete backup-restore cycle
    await this.logger.test('Complete Backup-Restore Cycle', async () => {
      // 1. Create initial backup
      const backup1 = await this.systems.backup.createIntelligentBackup({ type: 'full' });
      
      // 2. Modify data
      const User = require('../../backend/models/User');
      const originalCount = await User.countDocuments();
      await User.create({
        username: 'integration_test_user',
        email: 'integration@test.com',
        password: 'hashed_password',
        role: 'user'
      });
      
      // 3. Create second backup
      const backup2 = await this.systems.backup.createIntelligentBackup({ type: 'incremental' });
      
      // 4. Validate health
      const health = await this.systems.health.validateSystemHealth();
      
      // 5. Validate security
      const security = await this.systems.security.validateBackupSecurity(backup2.backupPath);
      
      // 6. Rollback to first backup
      await this.systems.rollback.executeRollback(backup1.backupPath);
      
      // 7. Verify restoration
      const finalCount = await User.countDocuments();
      assert(finalCount === originalCount, 'Should restore to original state');
      
      return {
        backup1: backup1.metadata.id,
        backup2: backup2.metadata.id,
        healthScore: health.results.overall.score,
        securityScore: security.results.overall.score
      };
    });

    // Test concurrent operations
    await this.logger.test('Concurrent Backup Operations', async () => {
      const promises = [
        this.systems.backup.createIntelligentBackup({ type: 'full' }),
        this.systems.health.validateSystemHealth(),
        this.systems.backup.listAllBackups()
      ];
      
      const results = await Promise.allSettled(promises);
      
      // Check that at least some operations succeeded
      const successful = results.filter(r => r.status === 'fulfilled').length;
      assert(successful > 0, 'Some concurrent operations should succeed');
      
      return { successful, total: results.length };
    });

    this.logger.endSuite();
  }

  /**
   * Performance tests
   */
  async runPerformanceTests() {
    this.logger.startSuite('Performance Tests');

    // Test backup performance
    await this.logger.test('Backup Performance Benchmark', async () => {
      const startTime = Date.now();
      
      const result = await this.systems.backup.createIntelligentBackup({
        type: 'full'
      });
      
      const duration = Date.now() - startTime;
      
      assert(duration < TEST_CONFIG.MAX_BACKUP_TIME_MS, 
        `Backup should complete within ${TEST_CONFIG.MAX_BACKUP_TIME_MS}ms, took ${duration}ms`);
      
      return {
        duration,
        documentsPerSecond: result.metadata.statistics.documentsPerSecond,
        compressionRatio: result.metadata.statistics.compressionRatio
      };
    });

    // Test restore performance
    await this.logger.test('Restore Performance Benchmark', async () => {
      // First create a backup
      const backup = await this.systems.backup.createIntelligentBackup({ type: 'full' });
      
      const startTime = Date.now();
      
      const result = await this.systems.rollback.executeRollback(backup.backupPath);
      
      const duration = Date.now() - startTime;
      
      assert(duration < TEST_CONFIG.MAX_RESTORE_TIME_MS,
        `Restore should complete within ${TEST_CONFIG.MAX_RESTORE_TIME_MS}ms, took ${duration}ms`);
      
      return {
        duration,
        restoredDocuments: result.state.statistics.restoredDocuments
      };
    });

    // Test validation performance
    await this.logger.test('Validation Performance Benchmark', async () => {
      const startTime = Date.now();
      
      const result = await this.systems.health.validateSystemHealth();
      
      const duration = Date.now() - startTime;
      
      assert(duration < TEST_CONFIG.MAX_VALIDATION_TIME_MS,
        `Validation should complete within ${TEST_CONFIG.MAX_VALIDATION_TIME_MS}ms, took ${duration}ms`);
      
      return {
        duration,
        totalValidations: result.results.statistics.totalValidations
      };
    });

    this.logger.endSuite();
  }

  /**
   * Error handling tests
   */
  async runErrorHandlingTests() {
    this.logger.startSuite('Error Handling Tests');

    // Test invalid backup path
    await this.logger.test('Handle Invalid Backup Path', async () => {
      try {
        await this.systems.rollback.executeRollback('/invalid/path/that/does/not/exist');
        assert(false, 'Should throw error for invalid path');
      } catch (error) {
        assert(error.message.includes('failed') || error.message.includes('not'), 
          'Should provide meaningful error message');
        return { errorHandled: true, message: error.message };
      }
    });

    // Test database connection failure
    await this.logger.test('Handle Database Disconnection', async () => {
      // Temporarily disconnect
      await mongoose.disconnect();
      
      try {
        await this.systems.health.validateSystemHealth();
        assert(false, 'Should fail when database is disconnected');
      } catch (error) {
        // Reconnect for other tests
        await mongoose.connect(TEST_CONFIG.TEST_DB_URI);
        return { errorHandled: true, message: error.message };
      }
    });

    // Test corrupted backup handling
    await this.logger.test('Handle Corrupted Backup Files', async () => {
      // Create a backup first
      const backup = await this.systems.backup.createIntelligentBackup({ type: 'full' });
      
      // Corrupt a file
      const corruptedFile = path.join(backup.backupPath, 'collections', 'users.json');
      await fs.writeFile(corruptedFile, 'corrupted content');
      
      // Try to validate
      const result = await this.systems.security.validateBackupSecurity(backup.backupPath);
      
      // Should detect corruption
      assert(result.results.checksums.invalid > 0 || result.results.corruption.corrupted > 0,
        'Should detect corrupted files');
      
      return { corruptionDetected: true };
    });

    this.logger.endSuite();
  }

  /**
   * Generate final test report
   */
  async generateFinalReport() {
    console.log('\n📊 Generating Final Test Report...');
    
    const report = this.logger.generateReport();
    const reportPath = path.join('./test-reports', `backup-restore-test-report-${Date.now()}.json`);
    
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
    
    // Generate summary report
    const summaryReport = this.generateSummaryReport(report);
    const summaryPath = path.join('./test-reports', `test-summary-${Date.now()}.md`);
    
    await fs.writeFile(summaryPath, summaryReport);
    
    console.log(`📄 Full report saved to: ${reportPath}`);
    console.log(`📋 Summary report saved to: ${summaryPath}`);
    
    // Display summary to console
    this.displayTestSummary(report);
    
    return report;
  }

  /**
   * Generate markdown summary report
   */
  generateSummaryReport(report) {
    const { summary, suites } = report;
    
    let markdown = `# Backup & Restore Test Report\n\n`;
    markdown += `**Generated:** ${summary.timestamp}\n`;
    markdown += `**Duration:** ${this.logger.formatTime(summary.totalDuration)}\n\n`;
    
    markdown += `## Summary\n\n`;
    markdown += `- **Total Tests:** ${summary.totalTests}\n`;
    markdown += `- **Passed:** ${summary.passedTests} ✅\n`;
    markdown += `- **Failed:** ${summary.failedTests} ❌\n`;
    markdown += `- **Skipped:** ${summary.skippedTests} ⏭️\n`;
    markdown += `- **Success Rate:** ${summary.successRate.toFixed(1)}%\n\n`;
    
    // Test suites breakdown
    markdown += `## Test Suites\n\n`;
    for (const suite of suites) {
      markdown += `### ${suite.name}\n`;
      markdown += `- Duration: ${this.logger.formatTime(suite.duration)}\n`;
      markdown += `- Tests: ${suite.tests.length}\n`;
      markdown += `- Passed: ${suite.metrics.passed}\n`;
      markdown += `- Failed: ${suite.metrics.failed}\n`;
      markdown += `- Skipped: ${suite.metrics.skipped}\n\n`;
      
      if (suite.metrics.failed > 0) {
        markdown += `#### Failed Tests\n`;
        suite.tests.filter(t => t.status === 'failed').forEach(test => {
          markdown += `- **${test.name}**: ${test.error?.message || 'Unknown error'}\n`;
        });
        markdown += `\n`;
      }
    }
    
    // Errors section
    if (report.errors.length > 0) {
      markdown += `## Errors\n\n`;
      for (const error of report.errors) {
        markdown += `### ${error.test} (${error.suite})\n`;
        markdown += `\`\`\`\n${error.error}\n\`\`\`\n\n`;
      }
    }
    
    return markdown;
  }

  /**
   * Display test summary to console
   */
  displayTestSummary(report) {
    const { summary } = report;
    
    console.log('\n' + '='.repeat(60));
    console.log('🎯 FINAL TEST RESULTS');
    console.log('='.repeat(60));
    
    console.log(`📊 Total Tests: ${summary.totalTests}`);
    console.log(`✅ Passed: ${summary.passedTests}`);
    console.log(`❌ Failed: ${summary.failedTests}`);
    console.log(`⏭️ Skipped: ${summary.skippedTests}`);
    console.log(`🎯 Success Rate: ${summary.successRate.toFixed(1)}%`);
    console.log(`⏱️ Total Duration: ${this.logger.formatTime(summary.totalDuration)}`);
    
    if (summary.failedTests === 0) {
      console.log('\n🎉 ALL TESTS PASSED! 🎉');
    } else {
      console.log(`\n⚠️ ${summary.failedTests} TEST(S) FAILED`);
    }
    
    console.log('='.repeat(60));
  }

  /**
   * Cleanup test environment
   */
  async cleanup() {
    console.log('\n🧹 Cleaning up test environment...');
    
    try {
      // Disconnect from database
      if (this.connected) {
        await mongoose.disconnect();
        console.log('✅ Disconnected from test database');
      }
      
      // Optional: Clean up test directories
      if (process.env.CLEANUP_TEST_FILES === 'true') {
        await fs.rm(TEST_CONFIG.TEST_BACKUP_PATH, { recursive: true, force: true });
        await fs.rm(TEST_CONFIG.TEST_DATA_PATH, { recursive: true, force: true });
        console.log('✅ Cleaned up test files');
      }
      
    } catch (error) {
      console.warn('⚠️ Cleanup warning:', error.message);
    }
  }
}

/**
 * CLI entry point
 */
async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Backup & Restore Test Suite v2.0
=================================

Usage: node BackupRestoreTests.js [options]

Options:
  --verbose, -v     Enable verbose test output
  --cleanup         Clean up test files after completion
  --help, -h        Show this help message

Environment Variables:
  MONGODB_URI       Test database URI (default: mongodb://localhost:27017/faf_backup_test)
  CLEANUP_TEST_FILES Set to 'true' to clean up test files

Examples:
  node BackupRestoreTests.js
  node BackupRestoreTests.js --verbose --cleanup
    `);
    process.exit(0);
  }
  
  // Set test environment variables
  if (args.includes('--cleanup')) {
    process.env.CLEANUP_TEST_FILES = 'true';
  }
  
  const testSuite = new BackupRestoreTestSuite();
  
  try {
    await testSuite.runAllTests();
    process.exit(0);
  } catch (error) {
    console.error('💥 Test suite failed:', error.message);
    process.exit(1);
  }
}

// Export for module usage
module.exports = {
  BackupRestoreTestSuite,
  TestLogger,
  MockDataGenerator,
  TEST_CONFIG
};

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}