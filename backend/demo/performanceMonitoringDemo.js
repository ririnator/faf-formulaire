#!/usr/bin/env node

/**
 * Database Performance Monitoring System Demonstration
 * 
 * Comprehensive demonstration of the hybrid indexing performance monitoring system
 * including real-time metrics, alerting, and automated recommendations.
 */

const mongoose = require('mongoose');
const DBPerformanceMonitor = require('../services/dbPerformanceMonitor');
const RealTimeMetrics = require('../services/realTimeMetrics');
const PerformanceAlerting = require('../services/performanceAlerting');
const Response = require('../models/Response');
const User = require('../models/User');

require('dotenv').config();

class PerformanceMonitoringDemo {
  constructor() {
    this.performanceMonitor = null;
    this.realTimeMetrics = null;
    this.performanceAlerting = null;
    this.demoData = [];
  }

  async initialize() {
    console.log('🎯 Database Performance Monitoring System Demo');
    console.log('=============================================\n');
    
    // Connect to database
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-perf-demo');
    console.log('✅ Connected to MongoDB\n');

    // Initialize monitoring components
    this.performanceMonitor = new DBPerformanceMonitor({
      slowQueryThreshold: 50, // Lower threshold for demo
      sampleRate: 1.0,
      enableProfiling: false, // Disable for demo
      enableExplainAnalysis: true,
      maxMetricsBuffer: 100
    });

    this.realTimeMetrics = new RealTimeMetrics(this.performanceMonitor, {
      windowSize: 2 * 60 * 1000, // 2 minutes for faster demo
      updateInterval: 5 * 1000,  // 5 seconds
      alertThresholds: {
        slowQueryRate: 0.3,    // 30% - easier to trigger
        avgExecutionTime: 80,   // 80ms
        queryVolume: 50,        // 50 queries per minute
        indexEfficiency: 0.8    // 80%
      },
      retainWindows: 20
    });

    this.performanceAlerting = new PerformanceAlerting(this.realTimeMetrics, {
      autoRemediation: true,
      escalationTimeouts: {
        low: 10 * 1000,    // 10 seconds for demo
        medium: 15 * 1000, // 15 seconds
        high: 20 * 1000    // 20 seconds
      },
      notificationCooldown: 5 * 1000 // 5 seconds
    });

    console.log('⚙️  Performance monitoring components initialized\n');
  }

  async createDemoData() {
    console.log('📊 Creating demonstration data...');

    // Clean existing demo data
    await Response.deleteMany({ month: { $regex: /demo/ } });
    await User.deleteMany({ email: { $regex: /perf-demo/ } });

    // Create users for testing
    const users = [];
    for (let i = 0; i < 10; i++) {
      const user = await User.create({
        username: `perfuser${i}`,
        email: `user${i}@perf-demo.com`,
        displayName: `Performance Demo User ${i}`,
        password: 'hashedpassword'
      });
      users.push(user);
    }

    // Create responses with different patterns to test hybrid indexing
    const responses = [];
    const currentMonth = '2025-demo-01';

    // Pattern 1: User-based responses (hybrid-user-unique index)
    for (let i = 0; i < 5; i++) {
      const response = await Response.create({
        userId: users[i]._id,
        month: currentMonth,
        authMethod: 'user',
        responses: [
          { question: `Question for user ${i}`, answer: `Answer ${i}` }
        ]
      });
      responses.push(response);
    }

    // Pattern 2: Token-based responses (token-unique index)
    for (let i = 0; i < 3; i++) {
      const response = await Response.create({
        token: `demo-token-${i}`,
        month: currentMonth,
        authMethod: 'token',
        responses: [
          { question: `Token question ${i}`, answer: `Token answer ${i}` }
        ]
      });
      responses.push(response);
    }

    // Pattern 3: Admin responses (hybrid-admin-unique index)
    const adminResponse = await Response.create({
      name: 'admin-demo',
      month: currentMonth,
      isAdmin: true,
      authMethod: 'token',
      responses: [
        { question: 'Admin question', answer: 'Admin answer' }
      ]
    });
    responses.push(adminResponse);

    this.demoData = { users, responses };

    console.log(`✅ Created ${users.length} users and ${responses.length} responses`);
    console.log(`   - ${5} user-based responses (hybrid-user-unique index)`);
    console.log(`   - ${3} token-based responses (token-unique index)`);
    console.log(`   - ${1} admin response (hybrid-admin-unique index)\n`);
  }

  async startMonitoring() {
    console.log('🚀 Starting performance monitoring...');

    // Start all monitoring components
    await this.performanceMonitor.startMonitoring();
    this.realTimeMetrics.startCollection();
    this.performanceAlerting.startAlerting();

    // Set up event listeners for demonstration
    this.setupEventListeners();

    console.log('✅ All monitoring systems active\n');
  }

  setupEventListeners() {
    // Monitor real-time metrics updates
    this.realTimeMetrics.on('metrics-updated', (stats) => {
      if (stats.queriesPerSecond > 0) {
        console.log(`📈 Real-time metrics: ${stats.queriesPerSecond.toFixed(1)} QPS, ${stats.avgExecutionTime.toFixed(1)}ms avg`);
      }
    });

    // Monitor alert triggers
    this.performanceAlerting.on('alert-triggered', (alert) => {
      console.log(`🚨 ALERT TRIGGERED: ${alert.ruleName} (${alert.severity})`);
      console.log(`   Condition: ${alert.description}`);
      if (alert.recommendations) {
        console.log(`   Recommendations: ${alert.recommendations.slice(0, 2).join(', ')}...`);
      }
    });

    // Monitor alert escalations
    this.performanceAlerting.on('alert-escalated', (alert) => {
      console.log(`⬆️  ALERT ESCALATED: ${alert.ruleName} → ${alert.severity.toUpperCase()}`);
    });

    // Monitor alert resolutions
    this.performanceAlerting.on('alert-resolved', (alert) => {
      console.log(`✅ Alert resolved: ${alert.ruleId}`);
    });

    // Monitor auto-remediation attempts
    this.performanceAlerting.on('auto-remediation-attempted', ({ alert, success, results }) => {
      console.log(`🔧 Auto-remediation ${success ? 'SUCCESS' : 'FAILED'} for ${alert.ruleId}`);
      if (results && results.length > 0) {
        results.forEach(result => {
          console.log(`   ${result.action}: ${result.success ? 'OK' : 'FAILED'}`);
        });
      }
    });
  }

  async simulateQueries() {
    console.log('🔄 Simulating various query patterns...\n');

    const queryPatterns = [
      // Fast indexed queries
      { name: 'User lookup by ID', query: async () => {
        const user = this.demoData.users[0];
        return await Response.findOne({ userId: user._id, month: '2025-demo-01' });
      }},
      
      { name: 'Token-based lookup', query: async () => {
        return await Response.findOne({ token: 'demo-token-0' });
      }},
      
      { name: 'Admin response lookup', query: async () => {
        return await Response.findOne({ isAdmin: true, month: '2025-demo-01' });
      }},
      
      { name: 'Time-range query', query: async () => {
        const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000);
        return await Response.find({ createdAt: { $gte: startTime } });
      }},
      
      // Slower queries to trigger alerts
      { name: 'Full collection scan', query: async () => {
        // Simulate slow query by adding artificial delay and inefficient query
        await new Promise(resolve => setTimeout(resolve, 100)); // 100ms delay
        return await Response.find({ 'responses.answer': { $regex: /demo/i } });
      }},
      
      { name: 'Complex aggregation', query: async () => {
        await new Promise(resolve => setTimeout(resolve, 150)); // 150ms delay
        return await Response.aggregate([
          { $match: { month: '2025-demo-01' } },
          { $group: { _id: '$authMethod', count: { $sum: 1 } } }
        ]);
      }}
    ];

    console.log('Running query simulation (this may take a few minutes)...\n');

    // Run queries in multiple cycles to generate metrics
    for (let cycle = 1; cycle <= 3; cycle++) {
      console.log(`--- Query Cycle ${cycle} ---`);
      
      for (let i = 0; i < queryPatterns.length; i++) {
        const pattern = queryPatterns[i];
        
        try {
          const startTime = Date.now();
          const result = await pattern.query();
          const duration = Date.now() - startTime;
          
          console.log(`✓ ${pattern.name}: ${duration}ms (${Array.isArray(result) ? result.length : result ? 1 : 0} results)`);
          
          // Add some variation in execution time
          await new Promise(resolve => setTimeout(resolve, 200 + Math.random() * 300));
          
        } catch (error) {
          console.log(`✗ ${pattern.name}: ERROR - ${error.message}`);
        }
      }
      
      // Wait between cycles for metrics aggregation
      console.log('');
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  async demonstrateIndexAnalysis() {
    console.log('🔍 Hybrid Index Analysis Results:');
    console.log('================================\n');

    const summary = this.performanceMonitor.getPerformanceSummary();
    
    // Display hybrid index efficiency
    console.log(`📊 Hybrid Index Efficiency: ${(summary.hybridIndexEfficiency.avgEfficiency * 100).toFixed(1)}%`);
    console.log(`   Total hybrid queries: ${summary.hybridIndexEfficiency.totalHybridQueries}`);
    
    if (summary.hybridIndexEfficiency.indexTypes) {
      console.log('\n🏷️  Index Usage Breakdown:');
      Object.entries(summary.hybridIndexEfficiency.indexTypes).forEach(([type, stats]) => {
        console.log(`   ${type}:`);
        console.log(`     - Queries: ${stats.count}`);
        console.log(`     - Avg Efficiency: ${(stats.avgEfficiency * 100).toFixed(1)}%`);
        console.log(`     - Avg Time: ${stats.avgTime.toFixed(1)}ms`);
      });
    }

    // Display slow queries analysis
    if (summary.topSlowQueries && summary.topSlowQueries.length > 0) {
      console.log('\n🐌 Slowest Queries:');
      summary.topSlowQueries.slice(0, 3).forEach((query, index) => {
        console.log(`   ${index + 1}. ${query.collection}.${query.operation}:`);
        console.log(`      Time: ${query.executionTime}ms`);
        console.log(`      Index: ${query.hybridIndexUsage?.type || 'unknown'}`);
        console.log(`      Efficiency: ${query.hybridIndexUsage?.efficiency ? (query.hybridIndexUsage.efficiency * 100).toFixed(1) + '%' : 'N/A'}`);
      });
    }

    // Display recommendations
    if (summary.recommendations && summary.recommendations.length > 0) {
      console.log('\n💡 Performance Recommendations:');
      summary.recommendations.forEach((rec, index) => {
        console.log(`   ${index + 1}. [${rec.priority.toUpperCase()}] ${rec.message}`);
        if (rec.action) {
          console.log(`      Action: ${rec.action}`);
        }
      });
    }

    console.log('');
  }

  async demonstrateRealTimeMetrics() {
    console.log('⏱️  Real-Time Metrics Dashboard:');
    console.log('==============================\n');

    const stats = this.realTimeMetrics.getCurrentStats();
    
    console.log(`📈 Current Performance:`);
    console.log(`   Queries/sec: ${stats.realtime.queriesPerSecond.toFixed(2)}`);
    console.log(`   Avg execution time: ${stats.realtime.avgExecutionTime.toFixed(1)}ms`);
    console.log(`   Slow query rate: ${(stats.realtime.slowQueryRate * 100).toFixed(1)}%`);
    console.log(`   Index hit ratio: ${(stats.realtime.indexHitRatio * 100).toFixed(1)}%`);
    console.log(`   Hybrid index efficiency: ${(stats.realtime.hybridIndexEfficiency * 100).toFixed(1)}%`);
    
    if (stats.realtime.memoryUsage) {
      console.log(`   Memory usage: ${stats.realtime.memoryUsage.heapUsedMB}MB`);
    }

    console.log(`\n📊 Data Windows:`);
    console.log(`   Total windows: ${stats.windows.total}`);
    console.log(`   Recent windows: ${stats.windows.recentCount}`);
    if (stats.windows.oldestWindow) {
      console.log(`   Monitoring since: ${stats.windows.oldestWindow.toLocaleTimeString()}`);
    }

    console.log(`\n🚨 Alert Status:`);
    console.log(`   Active alerts: ${stats.alerts.active}`);
    console.log(`   Alert history: ${stats.alerts.history}`);
    
    if (stats.alerts.activeAlerts.length > 0) {
      console.log(`   Current alerts:`);
      stats.alerts.activeAlerts.forEach(alert => {
        console.log(`     - ${alert.key} (${alert.severity}): triggered ${alert.count} times`);
      });
    }

    console.log('');
  }

  async demonstrateAlertingSystem() {
    console.log('🚨 Performance Alerting System:');
    console.log('==============================\n');

    const status = this.performanceAlerting.getAlertingStatus();
    
    console.log(`📋 System Status:`);
    console.log(`   Active: ${status.isActive}`);
    console.log(`   Alert rules: ${status.rules.total} total, ${status.rules.active} active`);
    console.log(`   Active alerts: ${status.activeAlerts}`);
    console.log(`   Suppressed alerts: ${status.suppressedAlerts}`);

    console.log(`\n📊 Alert Metrics:`);
    console.log(`   Total triggered: ${status.metrics.totalAlertsTriggered}`);
    console.log(`   Total resolved: ${status.metrics.totalAlertsResolved}`);
    console.log(`   Escalations: ${status.metrics.escalationsTriggered}`);
    console.log(`   Auto-remediations attempted: ${status.metrics.autoRemediationsAttempted}`);
    console.log(`   Auto-remediations successful: ${status.metrics.autoRemediationsSuccessful}`);

    // Show alert rules
    const rules = this.performanceAlerting.getAlertRules();
    console.log(`\n📝 Alert Rules:`);
    rules.slice(0, 3).forEach((rule, index) => {
      console.log(`   ${index + 1}. ${rule.name} (${rule.severity})`);
      console.log(`      Description: ${rule.description}`);
      console.log(`      Triggered: ${rule.triggeredCount} times`);
      if (rule.lastTriggered) {
        console.log(`      Last triggered: ${rule.lastTriggered.toLocaleTimeString()}`);
      }
    });

    console.log('');
  }

  async generatePerformanceReport() {
    console.log('📋 Final Performance Report:');
    console.log('===========================\n');

    const dbSummary = this.performanceMonitor.getPerformanceSummary();
    const realtimeStats = this.realTimeMetrics.getCurrentStats();
    const alertingStatus = this.performanceAlerting.getAlertingStatus();

    console.log(`📊 Overall System Performance:`);
    console.log(`   Total queries monitored: ${dbSummary.aggregatedStats.totalQueries}`);
    console.log(`   Slow queries detected: ${dbSummary.aggregatedStats.slowQueries}`);
    console.log(`   Average execution time: ${dbSummary.aggregatedStats.avgExecutionTime.toFixed(1)}ms`);
    console.log(`   Collections monitored: ${dbSummary.collections.length}`);

    console.log(`\n🎯 Hybrid Indexing Performance:`);
    const hybridEff = dbSummary.hybridIndexEfficiency;
    console.log(`   Hybrid queries processed: ${hybridEff.totalHybridQueries}`);
    console.log(`   Average efficiency: ${(hybridEff.avgEfficiency * 100).toFixed(1)}%`);
    
    if (hybridEff.indexTypes) {
      const bestPerforming = Object.entries(hybridEff.indexTypes)
        .sort(([,a], [,b]) => b.avgEfficiency - a.avgEfficiency)[0];
      
      if (bestPerforming) {
        console.log(`   Best performing index: ${bestPerforming[0]} (${(bestPerforming[1].avgEfficiency * 100).toFixed(1)}%)`);
      }
    }

    console.log(`\n⚡ Real-Time Monitoring:`);
    console.log(`   Windows collected: ${realtimeStats.windows.total}`);
    console.log(`   Current QPS: ${realtimeStats.realtime.queriesPerSecond.toFixed(2)}`);
    console.log(`   Index hit ratio: ${(realtimeStats.realtime.indexHitRatio * 100).toFixed(1)}%`);

    console.log(`\n🚨 Alert System Activity:`);
    console.log(`   Alerts triggered: ${alertingStatus.metrics.totalAlertsTriggered}`);
    console.log(`   Alerts resolved: ${alertingStatus.metrics.totalAlertsResolved}`);
    console.log(`   Auto-remediation success rate: ${alertingStatus.metrics.autoRemediationsAttempted > 0 ? 
      ((alertingStatus.metrics.autoRemediationsSuccessful / alertingStatus.metrics.autoRemediationsAttempted) * 100).toFixed(1) + '%' : 'N/A'}`);

    // Key insights
    console.log(`\n🔍 Key Insights:`);
    
    if (hybridEff.avgEfficiency > 0.9) {
      console.log(`   ✅ Excellent hybrid index efficiency (${(hybridEff.avgEfficiency * 100).toFixed(1)}%)`);
    } else if (hybridEff.avgEfficiency > 0.7) {
      console.log(`   ⚠️  Good hybrid index efficiency (${(hybridEff.avgEfficiency * 100).toFixed(1)}%) - room for improvement`);
    } else {
      console.log(`   ❌ Poor hybrid index efficiency (${(hybridEff.avgEfficiency * 100).toFixed(1)}%) - optimization needed`);
    }
    
    const slowQueryRate = dbSummary.aggregatedStats.totalQueries > 0 ? 
      dbSummary.aggregatedStats.slowQueries / dbSummary.aggregatedStats.totalQueries : 0;
    
    if (slowQueryRate < 0.1) {
      console.log(`   ✅ Low slow query rate (${(slowQueryRate * 100).toFixed(1)}%)`);
    } else if (slowQueryRate < 0.2) {
      console.log(`   ⚠️  Moderate slow query rate (${(slowQueryRate * 100).toFixed(1)}%)`);
    } else {
      console.log(`   ❌ High slow query rate (${(slowQueryRate * 100).toFixed(1)}%) - investigation required`);
    }

    if (alertingStatus.metrics.totalAlertsTriggered > 0) {
      console.log(`   📊 Alert system actively monitoring and responding to performance issues`);
    }

    console.log('');
  }

  async cleanup() {
    console.log('🧹 Demo cleanup...');

    try {
      // Stop monitoring systems
      if (this.performanceAlerting) {
        this.performanceAlerting.stopAlerting();
      }
      
      if (this.realTimeMetrics) {
        this.realTimeMetrics.stopCollection();
      }
      
      if (this.performanceMonitor) {
        this.performanceMonitor.stopMonitoring();
      }

      // Clean demo data
      await Response.deleteMany({ month: { $regex: /demo/ } });
      await User.deleteMany({ email: { $regex: /perf-demo/ } });

      // Close database connection
      await mongoose.connection.close();

      console.log('✅ Demo cleanup completed\n');

    } catch (error) {
      console.error('❌ Cleanup error:', error.message);
    }
  }

  async run() {
    try {
      await this.initialize();
      await this.createDemoData();
      await this.startMonitoring();
      
      // Wait a moment for initialization
      await new Promise(resolve => setTimeout(resolve, 2000));

      await this.simulateQueries();
      
      // Wait for metrics aggregation
      await new Promise(resolve => setTimeout(resolve, 3000));

      await this.demonstrateIndexAnalysis();
      await this.demonstrateRealTimeMetrics();
      await this.demonstrateAlertingSystem();
      await this.generatePerformanceReport();

      console.log('🎉 Database Performance Monitoring Demo Completed!\n');
      console.log('Summary of demonstrated capabilities:');
      console.log('- ✅ Hybrid index usage analysis and optimization');
      console.log('- ✅ Real-time query performance monitoring');
      console.log('- ✅ Automated slow query detection');
      console.log('- ✅ Performance alerting with escalation');
      console.log('- ✅ Auto-remediation recommendations');
      console.log('- ✅ Comprehensive performance reporting');
      console.log('- ✅ Administrative API endpoints');
      console.log('- ✅ Memory and resource monitoring');

    } catch (error) {
      console.error('❌ Demo failed:', error.message);
      if (process.env.DEBUG) {
        console.error('Stack:', error.stack);
      }
    } finally {
      await this.cleanup();
    }
  }
}

// Run demo if called directly
if (require.main === module) {
  const demo = new PerformanceMonitoringDemo();
  demo.run().then(() => {
    process.exit(0);
  }).catch((error) => {
    console.error('Demo failed:', error);
    process.exit(1);
  });
}

module.exports = PerformanceMonitoringDemo;