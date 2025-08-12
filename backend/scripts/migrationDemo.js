#!/usr/bin/env node

// Migration Management System Demo
const mongoose = require('mongoose');
const MigrationHealthMonitor = require('../utils/migrationHealthMonitor');
const MigrationRollback = require('./migrationRollback');
const Response = require('../models/Response');
const User = require('../models/User');
require('dotenv').config();

class MigrationDemo {
  constructor() {
    this.healthMonitor = null;
  }

  /**
   * Connect to database
   */
  async connect() {
    try {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('✅ Connected to database');
      return true;
    } catch (error) {
      console.error('❌ Database connection failed:', error.message);
      return false;
    }
  }

  /**
   * Demonstrate the complete migration management system
   */
  async runDemo() {
    console.log('\n🚀 FAF MIGRATION MANAGEMENT SYSTEM DEMO');
    console.log('========================================');

    // 1. Health Monitoring System
    console.log('\n📊 1. HEALTH MONITORING SYSTEM');
    console.log('------------------------------');
    
    this.healthMonitor = new MigrationHealthMonitor({
      checkInterval: 10000, // 10 seconds for demo
      alertThresholds: {
        orphanedDataPercent: 5,
        queryPerformanceDegradation: 50
      }
    });

    console.log('✅ Health monitor created');
    
    // Perform health check
    const healthStatus = await this.healthMonitor.performHealthCheck();
    console.log(`📈 System Status: ${healthStatus.overall.toUpperCase()}`);
    console.log(`🔍 Issues Found: ${healthStatus.issues.length}`);
    console.log(`⚠️  Alerts Generated: ${healthStatus.alerts.length}`);

    // 2. Migration Monitoring
    console.log('\n🔄 2. MIGRATION STATUS');
    console.log('---------------------');
    
    const [totalResponses, userResponses, legacyResponses] = await Promise.all([
      Response.countDocuments(),
      Response.countDocuments({ authMethod: 'user' }),
      Response.countDocuments({ authMethod: 'token' })
    ]);

    const migrationRate = totalResponses > 0 ? (userResponses / totalResponses) * 100 : 0;
    
    console.log(`📊 Total Responses: ${totalResponses}`);
    console.log(`👤 User Auth: ${userResponses} (${migrationRate.toFixed(1)}%)`);
    console.log(`🏷️  Token Auth: ${legacyResponses} (${(100-migrationRate).toFixed(1)}%)`);

    let phase = 'unknown';
    if (migrationRate < 10) phase = 'pre-migration';
    else if (migrationRate < 80) phase = 'active';
    else phase = 'post-migration';
    
    console.log(`📍 Migration Phase: ${phase.toUpperCase()}`);

    // 3. Index Optimization
    console.log('\n📇 3. INDEX OPTIMIZATION');
    console.log('----------------------');
    
    const indexAnalysis = await this.healthMonitor.monitors.indexOptimizer.analyzeIndexes();
    console.log(`📊 Current Indexes: ${Object.keys(indexAnalysis.current).length}`);
    console.log(`💡 Recommendations: ${indexAnalysis.recommendations.length}`);
    
    const criticalRecs = indexAnalysis.recommendations.filter(r => r.priority === 'critical');
    const highRecs = indexAnalysis.recommendations.filter(r => r.priority === 'high');
    
    if (criticalRecs.length > 0) {
      console.log(`🚨 Critical optimizations needed: ${criticalRecs.length}`);
    }
    if (highRecs.length > 0) {
      console.log(`⚠️  High priority optimizations: ${highRecs.length}`);
    }

    // 4. Data Integrity Check
    console.log('\n🧹 4. DATA INTEGRITY CHECK');
    console.log('-------------------------');
    
    const cleanupStats = await this.healthMonitor.monitors.orphanedCleanup.runCleanup({ 
      dryRun: true 
    });
    
    console.log(`🔍 Orphaned responses: ${cleanupStats.orphanedResponses}`);
    console.log(`🔗 Invalid user refs: ${cleanupStats.invalidUserReferences}`);
    console.log(`🔄 Inconsistent auth: ${cleanupStats.inconsistentAuthMethods}`);
    console.log(`📄 Malformed data: ${cleanupStats.malformedData}`);
    console.log(`🎯 Total issues: ${cleanupStats.totalCleaned}`);

    // 5. Health Report
    console.log('\n📋 5. COMPREHENSIVE HEALTH REPORT');
    console.log('----------------------------------');
    
    const report = this.healthMonitor.generateHealthReport();
    console.log(`📅 Report Timestamp: ${report.timestamp}`);
    console.log(`🏥 Overall Health: ${report.overall.toUpperCase()}`);
    console.log(`📊 Issues Summary:`);
    console.log(`   Critical: ${report.summary.critical}`);
    console.log(`   High: ${report.summary.high}`);
    console.log(`   Warning: ${report.summary.warning}`);
    console.log(`   Total: ${report.summary.totalIssues}`);

    // 6. Available Tools Summary
    console.log('\n🛠️  6. AVAILABLE MANAGEMENT TOOLS');
    console.log('----------------------------------');
    console.log('📊 Health Check CLI: node scripts/healthCheck.js');
    console.log('🔄 Migration Rollback: node scripts/migrationRollback.js');
    console.log('🧹 Data Cleanup: Run health monitor with autoCleanup enabled');
    console.log('📇 Index Optimization: Run health monitor with autoOptimize enabled');
    console.log('⚠️  Stress Testing: npm run test:stress-testing');
    console.log('📈 Production Testing: npm run test:production-auth-suite');

    // 7. Monitoring Recommendations
    console.log('\n💡 7. MONITORING RECOMMENDATIONS');
    console.log('--------------------------------');
    
    if (phase === 'active') {
      console.log('🎯 Active migration phase detected:');
      console.log('   • Run health checks every 5 minutes');
      console.log('   • Enable automated data cleanup');
      console.log('   • Monitor index performance closely');
      console.log('   • Set up alerts for migration stagnation');
    } else if (phase === 'pre-migration') {
      console.log('🚀 Pre-migration phase:');
      console.log('   • Optimize legacy token indexes');
      console.log('   • Plan user account migration strategy');
      console.log('   • Set baseline performance metrics');
    } else {
      console.log('✅ Post-migration phase:');
      console.log('   • Consider removing legacy indexes');
      console.log('   • Clean up orphaned data');
      console.log('   • Consolidate user-focused indexes');
    }

    console.log('\n✨ Demo completed! Migration system is fully operational.');
  }

  /**
   * Cleanup resources
   */
  async cleanup() {
    if (this.healthMonitor) {
      this.healthMonitor.cleanup();
    }
    await mongoose.disconnect();
  }
}

// Main execution
async function main() {
  const demo = new MigrationDemo();
  
  try {
    if (await demo.connect()) {
      await demo.runDemo();
    }
  } catch (error) {
    console.error('❌ Demo failed:', error.message);
  } finally {
    await demo.cleanup();
    process.exit(0);
  }
}

// Handle errors and interrupts
process.on('SIGINT', () => {
  console.log('\n⏹️  Demo interrupted');
  process.exit(0);
});

process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled error:', error.message);
  process.exit(1);
});

// Run if executed directly
if (require.main === module) {
  main();
}

module.exports = MigrationDemo;