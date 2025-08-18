#!/usr/bin/env node

/**
 * FAF MIGRATION TEST SCRIPT
 * ==========================
 * 
 * Quick validation script to test the migration functionality with sample data.
 * Creates test data, runs migration in dry-run mode, and validates results.
 * 
 * Usage:
 *   node scripts/test-migration.js
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const mongoose = require('mongoose');

// Import migration components
const {
  MigrationOrchestrator,
  UsernameGenerator,
  PasswordGenerator
} = require('./migrate-to-form-a-friend');

// Import models
const Response = require('../backend/models/Response');
const User = require('../backend/models/User');
const Submission = require('../backend/models/Submission');
const Invitation = require('../backend/models/Invitation');

class MigrationTester {
  constructor() {
    this.testResults = {
      passed: 0,
      failed: 0,
      errors: []
    };
  }

  log(message, status = 'INFO') {
    const colors = {
      INFO: '\x1b[36m',
      SUCCESS: '\x1b[32m',
      ERROR: '\x1b[31m',
      WARN: '\x1b[33m'
    };
    const reset = '\x1b[0m';
    console.log(`${colors[status]}[${status}] ${message}${reset}`);
  }

  async test(name, testFn) {
    try {
      this.log(`Testing: ${name}...`);
      await testFn();
      this.testResults.passed++;
      this.log(`✅ ${name} - PASSED`, 'SUCCESS');
    } catch (error) {
      this.testResults.failed++;
      this.testResults.errors.push({ test: name, error: error.message });
      this.log(`❌ ${name} - FAILED: ${error.message}`, 'ERROR');
    }
  }

  async createTestData() {
    // Clear existing data
    await Response.deleteMany({});
    await User.deleteMany({});
    await Submission.deleteMany({});
    await Invitation.deleteMany({});

    // Create sample Response data
    const testResponses = [
      {
        name: 'Jean-François Dupont',
        responses: [
          { question: 'Votre couleur préférée?', answer: 'Bleu' },
          { question: 'Votre ville natale?', answer: 'Paris' }
        ],
        month: '2025-08',
        isAdmin: false,
        token: 'token_jean_francois_123',
        createdAt: new Date('2025-08-01T10:00:00Z')
      },
      {
        name: 'Marie Élise Durand',
        responses: [
          { question: 'Votre couleur préférée?', answer: 'Rouge' },
          { question: 'Votre ville natale?', answer: 'Lyon' }
        ],
        month: '2025-08',
        isAdmin: false,
        token: 'token_marie_elise_456',
        createdAt: new Date('2025-08-02T11:00:00Z')
      },
      {
        name: 'admin_test',
        responses: [
          { question: 'Votre couleur préférée?', answer: 'Vert' },
          { question: 'Votre ville natale?', answer: 'Marseille' }
        ],
        month: '2025-08',
        isAdmin: true,
        token: null, // Admin responses don't have tokens
        createdAt: new Date('2025-08-03T12:00:00Z')
      },
      {
        name: 'Pierre Martin',
        responses: [
          { question: 'Votre couleur préférée?', answer: 'Jaune' },
          { question: 'Votre ville natale?', answer: 'Toulouse' }
        ],
        month: '2025-07', // Different month
        isAdmin: false,
        token: 'token_pierre_martin_789',
        createdAt: new Date('2025-07-15T14:00:00Z')
      },
      {
        name: 'Jean-François Dupont', // Duplicate name (different month)
        responses: [
          { question: 'Question du mois précédent', answer: 'Réponse précédente' }
        ],
        month: '2025-07',
        isAdmin: false,
        token: 'token_jean_francois_old_999',
        createdAt: new Date('2025-07-10T09:00:00Z')
      }
    ];

    await Response.insertMany(testResponses);
    this.log(`Created ${testResponses.length} test Response documents`, 'SUCCESS');
    
    return testResponses;
  }

  async validateTestData() {
    const responseCount = await Response.countDocuments();
    const uniqueNames = await Response.distinct('name');
    const adminResponses = await Response.countDocuments({ isAdmin: true });
    const tokensCount = await Response.countDocuments({ token: { $exists: true, $ne: null } });

    this.log(`Test data validation:`, 'INFO');
    this.log(`  • Total responses: ${responseCount}`);
    this.log(`  • Unique names: ${uniqueNames.length}`);
    this.log(`  • Admin responses: ${adminResponses}`);
    this.log(`  • Responses with tokens: ${tokensCount}`);

    if (responseCount !== 5) throw new Error(`Expected 5 responses, got ${responseCount}`);
    if (uniqueNames.length !== 4) throw new Error(`Expected 4 unique names, got ${uniqueNames.length}`);
    if (adminResponses !== 1) throw new Error(`Expected 1 admin response, got ${adminResponses}`);
    if (tokensCount !== 4) throw new Error(`Expected 4 responses with tokens, got ${tokensCount}`);
  }

  async testUsernameGeneration() {
    const testCases = [
      { input: 'Jean-François Dupont', expected: 'jean_francois_dupont' },
      { input: 'Marie Élise Durand', expected: 'marie_elise_durand' },
      { input: 'admin_test', expected: 'admin_test' },
      { input: 'Pierre Martin', expected: 'pierre_martin' }
    ];

    for (const { input, expected } of testCases) {
      const result = UsernameGenerator.sanitizeUsername(input);
      if (result !== expected) {
        throw new Error(`Username generation failed: ${input} -> ${result}, expected ${expected}`);
      }
    }

    // Test collision handling
    const existingUsernames = new Set(['jean_francois_dupont']);
    const uniqueUsername = await UsernameGenerator.generateUniqueUsername('Jean-François Dupont', existingUsernames);
    if (uniqueUsername !== 'jean_francois_dupont_1') {
      throw new Error(`Collision handling failed: got ${uniqueUsername}, expected jean_francois_dupont_1`);
    }
  }

  async testPasswordGeneration() {
    const password1 = PasswordGenerator.generateSecurePassword();
    const password2 = PasswordGenerator.generateSecurePassword();

    // Check length
    if (password1.length !== 12) {
      throw new Error(`Password length incorrect: ${password1.length}, expected 12`);
    }

    // Check uniqueness
    if (password1 === password2) {
      throw new Error('Passwords are not unique');
    }

    // Check complexity
    if (!/[A-Z]/.test(password1)) throw new Error('Password missing uppercase');
    if (!/[a-z]/.test(password1)) throw new Error('Password missing lowercase');
    if (!/[0-9]/.test(password1)) throw new Error('Password missing numbers');
    if (!/[!@#$%^&*]/.test(password1)) throw new Error('Password missing special characters');

    // Test hashing
    const hash = await PasswordGenerator.hashPassword(password1);
    if (hash === password1) throw new Error('Password not hashed');
    if (!hash.startsWith('$2b$')) throw new Error('Invalid hash format');
  }

  async testDryRunMigration() {
    // Set admin name for testing
    process.env.FORM_ADMIN_NAME = 'admin_test';
    
    const migration = new MigrationOrchestrator({ 
      dryRun: true, 
      verbose: false // Reduce noise in tests
    });

    const result = await migration.execute();

    // Verify dry-run didn't create actual data
    const userCount = await User.countDocuments();
    const submissionCount = await Submission.countDocuments();
    const invitationCount = await Invitation.countDocuments();

    if (userCount !== 0) throw new Error(`Dry-run created users: ${userCount}`);
    if (submissionCount !== 0) throw new Error(`Dry-run created submissions: ${submissionCount}`);
    if (invitationCount !== 0) throw new Error(`Dry-run created invitations: ${invitationCount}`);

    // Verify statistics are correct
    if (result.statistics.usersCreated !== 4) {
      throw new Error(`Expected 4 users to be created, got ${result.statistics.usersCreated}`);
    }
    if (result.statistics.submissionsCreated !== 5) {
      throw new Error(`Expected 5 submissions to be created, got ${result.statistics.submissionsCreated}`);
    }
    if (result.statistics.invitationsCreated !== 4) {
      throw new Error(`Expected 4 invitations to be created, got ${result.statistics.invitationsCreated}`);
    }

    // Verify all phases completed
    const phases = Object.values(result.phases);
    const failedPhases = phases.filter(phase => phase.status !== 'completed');
    if (failedPhases.length > 0) {
      throw new Error(`Failed phases: ${failedPhases.map(p => p.status).join(', ')}`);
    }
  }

  async testActualMigration() {
    // Recreate test data since we'll be modifying it
    await this.createTestData();
    
    process.env.FORM_ADMIN_NAME = 'admin_test';
    
    const migration = new MigrationOrchestrator({ 
      dryRun: false, 
      verbose: false 
    });

    const result = await migration.execute();

    // Verify actual data was created
    const users = await User.find({ 'migrationData.source': 'migration' }).lean();
    const submissions = await Submission.find({}).lean();
    const invitations = await Invitation.find({ 'metadata.migrationSource': 'response_token' }).lean();

    if (users.length !== 4) throw new Error(`Expected 4 users, got ${users.length}`);
    if (submissions.length !== 5) throw new Error(`Expected 5 submissions, got ${submissions.length}`);
    if (invitations.length !== 4) throw new Error(`Expected 4 invitations, got ${invitations.length}`);

    // Verify admin role assignment
    const adminUser = users.find(u => u.role === 'admin');
    if (!adminUser) throw new Error('Admin user not found');
    if (adminUser.migrationData.legacyName !== 'admin_test') {
      throw new Error(`Wrong admin user: ${adminUser.migrationData.legacyName}`);
    }

    // Verify user-submission relationships
    for (const submission of submissions) {
      const user = users.find(u => u._id.toString() === submission.userId.toString());
      if (!user) throw new Error(`Orphaned submission: ${submission._id}`);
    }

    // Verify token preservation
    for (const invitation of invitations) {
      const originalToken = invitation.token;
      const originalResponse = await Response.findOne({ token: originalToken }).lean();
      if (!originalResponse) throw new Error(`Token not found in original responses: ${originalToken}`);
    }

    // Verify email generation
    users.forEach(user => {
      if (!user.email.endsWith('@migration.faf.local')) {
        throw new Error(`Invalid email format: ${user.email}`);
      }
    });
  }

  async testDataIntegrity() {
    // Get counts after migration
    const responseCount = await Response.countDocuments();
    const userCount = await User.countDocuments({ 'migrationData.source': 'migration' });
    const submissionCount = await Submission.countDocuments();
    const invitationCount = await Invitation.countDocuments({ 'metadata.migrationSource': 'response_token' });

    // Verify data preservation
    if (responseCount !== 5) throw new Error(`Original responses modified: ${responseCount}`);
    
    // Verify relationships
    const submissions = await Submission.find({}).lean();
    const users = await User.find({ 'migrationData.source': 'migration' }).lean();
    
    for (const submission of submissions) {
      const user = users.find(u => u._id.toString() === submission.userId.toString());
      if (!user) throw new Error(`Orphaned submission: ${submission._id}`);
      
      // Verify month preservation
      const originalResponse = await Response.findOne({ 
        name: { $regex: new RegExp(user.migrationData.legacyName, 'i') },
        month: submission.month 
      }).lean();
      if (!originalResponse) {
        throw new Error(`No matching original response for submission: ${submission._id}`);
      }
    }

    this.log(`Data integrity verified:`, 'SUCCESS');
    this.log(`  • Users: ${userCount}/4 expected`);
    this.log(`  • Submissions: ${submissionCount}/5 expected`);
    this.log(`  • Invitations: ${invitationCount}/4 expected`);
    this.log(`  • Original responses preserved: ${responseCount}`);
  }

  async runAllTests() {
    this.log('🚀 Starting FAF Migration Tests', 'INFO');
    this.log('================================', 'INFO');

    try {
      // Connect to test database
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/faf_test';
      await mongoose.connect(mongoUri);
      this.log(`Connected to MongoDB: ${mongoUri}`, 'SUCCESS');

      // Create test data
      await this.test('Create Test Data', () => this.createTestData());
      await this.test('Validate Test Data', () => this.validateTestData());

      // Test individual components
      await this.test('Username Generation', () => this.testUsernameGeneration());
      await this.test('Password Generation', () => this.testPasswordGeneration());

      // Test migration functionality
      await this.test('Dry-Run Migration', () => this.testDryRunMigration());
      await this.test('Actual Migration', () => this.testActualMigration());
      await this.test('Data Integrity', () => this.testDataIntegrity());

    } catch (error) {
      this.log(`Critical test error: ${error.message}`, 'ERROR');
      this.testResults.failed++;
    } finally {
      await mongoose.disconnect();
    }

    // Report results
    this.log('\n================================', 'INFO');
    this.log('🏁 Test Results Summary', 'INFO');
    this.log('================================', 'INFO');
    this.log(`✅ Passed: ${this.testResults.passed}`, 'SUCCESS');
    this.log(`❌ Failed: ${this.testResults.failed}`, this.testResults.failed > 0 ? 'ERROR' : 'SUCCESS');

    if (this.testResults.errors.length > 0) {
      this.log('\n❌ Failed Tests:', 'ERROR');
      this.testResults.errors.forEach(({ test, error }) => {
        this.log(`  • ${test}: ${error}`, 'ERROR');
      });
    }

    if (this.testResults.failed === 0) {
      this.log('\n🎉 All tests passed! Migration script is ready for production.', 'SUCCESS');
      process.exit(0);
    } else {
      this.log('\n💥 Some tests failed. Please review and fix issues before using migration script.', 'ERROR');
      process.exit(1);
    }
  }
}

// Run tests if called directly
if (require.main === module) {
  const tester = new MigrationTester();
  tester.runAllTests().catch(console.error);
}

module.exports = MigrationTester;