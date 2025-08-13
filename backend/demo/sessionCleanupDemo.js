#!/usr/bin/env node

/**
 * Session Cleanup Service Demonstration
 * 
 * This script demonstrates the enhanced session management capabilities
 * including automatic cleanup of expired sessions and inactive user data.
 */

const mongoose = require('mongoose');
const SessionCleanupService = require('../services/sessionCleanupService');
const User = require('../models/User');
const Response = require('../models/Response');

require('dotenv').config();

class SessionCleanupDemo {
  constructor() {
    this.cleanupService = new SessionCleanupService();
  }

  async initialize() {
    console.log('🚀 Session Cleanup Service Demo');
    console.log('=================================\n');
    
    // Connect to database
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-demo');
    console.log('✅ Connected to MongoDB\n');
  }

  async createTestData() {
    console.log('📊 Creating test data...');
    
    // Clean existing test data
    await User.deleteMany({ email: { $regex: /test\.demo$/ } });
    await Response.deleteMany({ month: '2024-demo' });
    
    const oldDate = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000); // 100 days ago
    const veryOldDate = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000); // 200 days ago

    // Create inactive user
    const inactiveUser = await User.create({
      username: 'inactive_demo',
      email: 'inactive@test.demo',
      password: 'hashedpassword',
      metadata: {
        registeredAt: veryOldDate,
        lastLoginAt: veryOldDate,
        lastActive: veryOldDate
      }
    });

    // Create active user
    const activeUser = await User.create({
      username: 'active_demo',
      email: 'active@test.demo',
      password: 'hashedpassword',
      metadata: {
        registeredAt: oldDate,
        lastLoginAt: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // 1 day ago
        lastActive: new Date()
      }
    });

    // Create responses
    await Response.create({
      userId: inactiveUser._id,
      month: '2024-demo',
      responses: [{ question: 'Old question?', answer: 'Old answer' }],
      authMethod: 'user',
      createdAt: veryOldDate
    });

    await Response.create({
      userId: activeUser._id,
      month: '2025-demo',
      responses: [{ question: 'Recent question?', answer: 'Recent answer' }],
      authMethod: 'user',
      createdAt: new Date()
    });

    // Create orphaned response
    await Response.create({
      userId: new mongoose.Types.ObjectId(), // Non-existent user
      month: '2024-demo',
      responses: [{ question: 'Orphaned?', answer: 'Yes' }],
      authMethod: 'user',
      createdAt: oldDate
    });

    console.log('✅ Test data created:');
    console.log(`   - 1 inactive user (${inactiveUser.email})`);
    console.log(`   - 1 active user (${activeUser.email})`);
    console.log(`   - 2 valid responses`);
    console.log(`   - 1 orphaned response\n`);
  }

  async demonstrateCleanup() {
    console.log('🧹 Running cleanup demonstration...\n');

    // Show initial state
    const initialUsers = await User.countDocuments({ email: { $regex: /test\.demo$/ } });
    const initialResponses = await Response.countDocuments({ month: { $regex: /demo$/ } });
    
    console.log('📈 Initial State:');
    console.log(`   - Users: ${initialUsers}`);
    console.log(`   - Responses: ${initialResponses}\n`);

    // Run dry run first
    console.log('🔍 Dry Run Analysis:');
    const dryRunReport = await this.cleanupService.runCompleteCleanup({ dryRun: true });
    
    console.log(`   - Would clean ${dryRunReport.stats.inactiveUsers} inactive users`);
    console.log(`   - Would clean ${dryRunReport.stats.orphanedData} orphaned data records`);
    console.log(`   - Would clean ${dryRunReport.stats.expiredSessions} expired sessions\n`);

    // Run actual cleanup
    console.log('⚡ Running Actual Cleanup:');
    const cleanupReport = await this.cleanupService.runCompleteCleanup({ dryRun: false });
    
    console.log(`   - Cleaned ${cleanupReport.stats.inactiveUsers} inactive users`);
    console.log(`   - Cleaned ${cleanupReport.stats.orphanedData} orphaned data records`);
    console.log(`   - Cleaned ${cleanupReport.stats.expiredSessions} expired sessions`);
    console.log(`   - Total cleaned: ${cleanupReport.stats.totalCleaned}\n`);

    // Show final state
    const finalUsers = await User.countDocuments({ email: { $regex: /test\.demo$/ } });
    const finalResponses = await Response.countDocuments({ month: { $regex: /demo$/ } });
    
    console.log('📉 Final State:');
    console.log(`   - Users: ${finalUsers} (reduced by ${initialUsers - finalUsers})`);
    console.log(`   - Responses: ${finalResponses} (reduced by ${initialResponses - finalResponses})\n`);

    // Show recommendations
    if (cleanupReport.recommendations.length > 0) {
      console.log('💡 Recommendations:');
      cleanupReport.recommendations.forEach(rec => {
        console.log(`   - ${rec}`);
      });
      console.log('');
    }
  }

  async demonstrateConfiguration() {
    console.log('⚙️  Configuration Management:');
    
    const originalConfig = { ...this.cleanupService.config };
    console.log('   Current configuration:');
    console.log(`   - Session TTL: ${Math.floor(originalConfig.sessionTTL / (24 * 60 * 60 * 1000))} days`);
    console.log(`   - User inactivity threshold: ${Math.floor(originalConfig.userInactivityThreshold / (24 * 60 * 60 * 1000))} days`);
    console.log(`   - Cleanup interval: ${Math.floor(originalConfig.cleanupInterval / (60 * 60 * 1000))} hours`);
    console.log(`   - Batch size: ${originalConfig.batchSize}`);
    console.log(`   - Auto cleanup: ${originalConfig.enableAutoCleanup}\n`);

    // Update configuration
    console.log('   Updating configuration...');
    this.cleanupService.updateConfig({
      sessionTTL: 7 * 24 * 60 * 60 * 1000, // 7 days
      userInactivityThreshold: 60 * 24 * 60 * 60 * 1000, // 60 days
      batchSize: 500
    });

    console.log('   New configuration:');
    console.log(`   - Session TTL: ${Math.floor(this.cleanupService.config.sessionTTL / (24 * 60 * 60 * 1000))} days`);
    console.log(`   - User inactivity threshold: ${Math.floor(this.cleanupService.config.userInactivityThreshold / (24 * 60 * 60 * 1000))} days`);
    console.log(`   - Batch size: ${this.cleanupService.config.batchSize}\n`);
  }

  async demonstrateStatistics() {
    console.log('📊 Cleanup Statistics:');
    
    const stats = this.cleanupService.getCleanupStats();
    console.log(`   - Expired sessions cleaned: ${stats.expiredSessions}`);
    console.log(`   - Inactive users cleaned: ${stats.inactiveUsers}`);
    console.log(`   - Orphaned data cleaned: ${stats.orphanedData}`);
    console.log(`   - Total records cleaned: ${stats.totalCleaned}`);
    console.log(`   - Last cleanup: ${stats.lastCleanup ? stats.lastCleanup.toISOString() : 'Never'}\n`);
  }

  async cleanup() {
    console.log('🔄 Demo cleanup...');
    
    // Remove demo test data
    await User.deleteMany({ email: { $regex: /test\.demo$/ } });
    await Response.deleteMany({ month: { $regex: /demo$/ } });
    
    this.cleanupService.shutdown();
    await mongoose.connection.close();
    console.log('✅ Demo completed and cleaned up\n');
  }

  async run() {
    try {
      await this.initialize();
      await this.createTestData();
      await this.demonstrateCleanup();
      await this.demonstrateConfiguration();
      await this.demonstrateStatistics();
      
      console.log('🎉 Session Cleanup Service Demo completed successfully!');
      console.log('');
      console.log('Summary of capabilities:');
      console.log('- ✅ Automatic cleanup of expired sessions');
      console.log('- ✅ Inactive user data cleanup (90+ days)');
      console.log('- ✅ Orphaned data cleanup (invalid references)');
      console.log('- ✅ Configurable cleanup intervals and thresholds');
      console.log('- ✅ Dry-run capability for safe testing');
      console.log('- ✅ Comprehensive statistics and reporting');
      console.log('- ✅ Admin API endpoints for management');
      console.log('- ✅ Graceful shutdown and error handling');
      
    } catch (error) {
      console.error('❌ Demo failed:', error.message);
      // Stack trace seulement en développement
      if (process.env.NODE_ENV !== 'production') {
        console.error('Stack:', error.stack);
      }
    } finally {
      await this.cleanup();
    }
  }
}

// Run demo if called directly
if (require.main === module) {
  const demo = new SessionCleanupDemo();
  demo.run().then(() => {
    process.exit(0);
  }).catch((error) => {
    console.error('Demo failed:', error);
    process.exit(1);
  });
}

module.exports = SessionCleanupDemo;