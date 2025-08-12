// Migration Monitoring and Health Check System
const mongoose = require('mongoose');
const Response = require('../models/Response');
const User = require('../models/User');
const SecureLogger = require('./secureLogger');

class MigrationMonitor {
  constructor() {
    this.metrics = {
      totalLegacyResponses: 0,
      totalMigratedResponses: 0,
      migrationRate: 0,
      orphanedData: 0,
      indexPerformance: {},
      lastCheck: null,
      alerts: []
    };
    
    this.thresholds = {
      slowQueryMs: 100,
      orphanedDataMax: 100,
      migrationRateMin: 0.1, // 10% minimum migration rate
      indexEfficiencyMin: 0.7 // 70% minimum index usage
    };
  }

  /**
   * Comprehensive migration health check
   */
  async checkMigrationHealth() {
    const startTime = Date.now();
    const report = {
      timestamp: new Date().toISOString(),
      checks: {},
      alerts: [],
      recommendations: []
    };

    try {
      // 1. Check legacy vs migrated data
      try {
        report.checks.dataDistribution = await this.checkDataDistribution();
      } catch (error) {
        SecureLogger.logError('Data distribution check failed', error);
        report.checks.dataDistribution = { error: error.message };
      }
      
      // 2. Check index performance
      try {
        report.checks.indexPerformance = await this.checkIndexPerformance();
      } catch (error) {
        SecureLogger.logError('Index performance check failed', error);
        report.checks.indexPerformance = { error: error.message };
      }
      
      // 3. Check for orphaned data
      try {
        report.checks.orphanedData = await this.checkOrphanedData();
      } catch (error) {
        SecureLogger.logError('Orphaned data check failed', error);
        report.checks.orphanedData = { error: error.message };
      }
      
      // 4. Check migration progress
      try {
        report.checks.migrationProgress = await this.checkMigrationProgress();
      } catch (error) {
        SecureLogger.logMigrationError('progress_check', 'query_failed', 0);
        report.checks.migrationProgress = { error: error.message };
      }
      
      // 5. Check database constraints
      report.checks.constraints = await this.checkConstraints();
      
      // 6. Check query performance
      report.checks.queryPerformance = await this.checkQueryPerformance();
      
      // Analyze results and generate alerts
      this.analyzeHealthReport(report);
      
      report.duration = Date.now() - startTime;
      this.metrics.lastCheck = report.timestamp;
      
      return report;
    } catch (error) {
      SecureLogger.logMigrationError('health_check', 'system_failure', 0);
      report.error = error.message;
      return report;
    }
  }

  /**
   * Check distribution of legacy vs migrated data
   */
  async checkDataDistribution() {
    const [legacyCount, migratedCount, hybridCount] = await Promise.all([
      Response.countDocuments({ authMethod: 'token' }),
      Response.countDocuments({ authMethod: 'user' }),
      Response.countDocuments({ 
        $and: [
          { authMethod: { $exists: true } },
          { authMethod: { $nin: ['token', 'user'] } }
        ]
      })
    ]);

    const total = legacyCount + migratedCount + hybridCount;
    const migrationRate = total > 0 ? (migratedCount / total) : 0;

    this.metrics.totalLegacyResponses = legacyCount;
    this.metrics.totalMigratedResponses = migratedCount;
    this.metrics.migrationRate = migrationRate;

    return {
      legacy: legacyCount,
      migrated: migratedCount,
      hybrid: hybridCount,
      total,
      migrationRate: `${(migrationRate * 100).toFixed(2)}%`,
      status: migrationRate > this.thresholds.migrationRateMin ? 'healthy' : 'needs_attention'
    };
  }

  /**
   * Check index performance and usage
   */
  async checkIndexPerformance() {
    const indexStats = await Response.collection.indexStats();
    const results = {};
    
    for (const [indexName, stats] of Object.entries(indexStats)) {
      const efficiency = stats.accesses ? (stats.hits / stats.accesses) : 0;
      
      results[indexName] = {
        accesses: stats.accesses || 0,
        hits: stats.hits || 0,
        efficiency: `${(efficiency * 100).toFixed(2)}%`,
        size: stats.size || 0,
        status: efficiency >= this.thresholds.indexEfficiencyMin ? 'optimal' : 'suboptimal'
      };
      
      this.metrics.indexPerformance[indexName] = efficiency;
    }
    
    return results;
  }

  /**
   * Check for orphaned data
   */
  async checkOrphanedData() {
    const orphanedChecks = {
      responsesWithoutUser: 0,
      responsesWithInvalidUser: 0,
      duplicateTokens: 0,
      inconsistentAuthMethod: 0
    };

    // Responses with userId but no matching user
    const userResponses = await Response.find({ 
      userId: { $exists: true, $ne: null } 
    }).select('userId');
    
    const userIds = [...new Set(userResponses.map(r => r.userId))];
    const existingUsers = await User.find({ 
      _id: { $in: userIds } 
    }).select('_id');
    
    const existingUserIds = new Set(existingUsers.map(u => u._id.toString()));
    orphanedChecks.responsesWithInvalidUser = userIds.filter(
      id => !existingUserIds.has(id.toString())
    ).length;

    // Check for duplicate tokens
    const tokenDuplicates = await Response.aggregate([
      { $match: { token: { $exists: true, $ne: null } } },
      { $group: { _id: '$token', count: { $sum: 1 } } },
      { $match: { count: { $gt: 1 } } }
    ]);
    orphanedChecks.duplicateTokens = tokenDuplicates.length;

    // Check for inconsistent auth methods
    const inconsistent = await Response.countDocuments({
      $or: [
        { userId: { $exists: true }, authMethod: 'token' },
        { token: { $exists: true }, authMethod: 'user' }
      ]
    });
    orphanedChecks.inconsistentAuthMethod = inconsistent;

    const totalOrphaned = Object.values(orphanedChecks).reduce((a, b) => a + b, 0);
    this.metrics.orphanedData = totalOrphaned;

    return {
      ...orphanedChecks,
      total: totalOrphaned,
      status: totalOrphaned <= this.thresholds.orphanedDataMax ? 'clean' : 'needs_cleanup'
    };
  }

  /**
   * Check migration progress over time
   */
  async checkMigrationProgress() {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    
    const recentMigrations = await Response.aggregate([
      {
        $match: {
          updatedAt: { $gte: thirtyDaysAgo },
          authMethod: 'user'
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$updatedAt' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    const trend = this.calculateTrend(recentMigrations);
    
    return {
      last30Days: recentMigrations,
      trend,
      averagePerDay: recentMigrations.length > 0 
        ? (recentMigrations.reduce((sum, r) => sum + r.count, 0) / recentMigrations.length).toFixed(2)
        : 0,
      status: trend === 'increasing' ? 'healthy' : 'slowing'
    };
  }

  /**
   * Check database constraints integrity
   */
  async checkConstraints() {
    const constraintIssues = {
      duplicateAdmins: 0,
      missingAuthMethod: 0,
      invalidMonthFormat: 0
    };

    // Check for duplicate admin responses per month
    const duplicateAdmins = await Response.aggregate([
      { $match: { isAdmin: true } },
      { $group: { 
        _id: { month: '$month' }, 
        count: { $sum: 1 } 
      }},
      { $match: { count: { $gt: 1 } } }
    ]);
    constraintIssues.duplicateAdmins = duplicateAdmins.length;

    // Check for missing auth method
    constraintIssues.missingAuthMethod = await Response.countDocuments({
      authMethod: { $exists: false }
    });

    // Check for invalid month format
    constraintIssues.invalidMonthFormat = await Response.countDocuments({
      month: { $not: /^\d{4}-\d{2}$/ }
    });

    const totalIssues = Object.values(constraintIssues).reduce((a, b) => a + b, 0);
    
    return {
      ...constraintIssues,
      total: totalIssues,
      status: totalIssues === 0 ? 'valid' : 'constraint_violations'
    };
  }

  /**
   * Check query performance
   */
  async checkQueryPerformance() {
    const testQueries = [
      {
        name: 'legacyTokenLookup',
        query: () => Response.findOne({ token: 'test-token' }).explain('executionStats')
      },
      {
        name: 'userResponseLookup',
        query: () => Response.find({ userId: new mongoose.Types.ObjectId() }).explain('executionStats')
      },
      {
        name: 'monthlyAdminCheck',
        query: () => Response.findOne({ month: '2024-01', isAdmin: true }).explain('executionStats')
      }
    ];

    const results = {};
    
    for (const test of testQueries) {
      try {
        const stats = await test.query();
        const executionTime = stats.executionStats.executionTimeMillis;
        
        results[test.name] = {
          executionTimeMs: executionTime,
          indexUsed: stats.executionStats.totalDocsExamined === 0 || 
                    stats.executionStats.totalDocsExamined === stats.executionStats.totalDocsReturned,
          status: executionTime <= this.thresholds.slowQueryMs ? 'fast' : 'slow'
        };
      } catch (error) {
        results[test.name] = {
          error: error.message,
          status: 'error'
        };
      }
    }
    
    return results;
  }

  /**
   * Calculate trend from time series data
   */
  calculateTrend(data) {
    if (data.length < 2) return 'insufficient_data';
    
    const firstHalf = data.slice(0, Math.floor(data.length / 2));
    const secondHalf = data.slice(Math.floor(data.length / 2));
    
    const firstAvg = firstHalf.reduce((sum, d) => sum + d.count, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((sum, d) => sum + d.count, 0) / secondHalf.length;
    
    if (secondAvg > firstAvg * 1.1) return 'increasing';
    if (secondAvg < firstAvg * 0.9) return 'decreasing';
    return 'stable';
  }

  /**
   * Analyze health report and generate alerts
   */
  analyzeHealthReport(report) {
    report.alerts = [];
    report.recommendations = [];

    // Check migration rate
    if (this.metrics.migrationRate < this.thresholds.migrationRateMin) {
      report.alerts.push({
        level: 'warning',
        message: `Migration rate (${(this.metrics.migrationRate * 100).toFixed(2)}%) is below threshold`,
        recommendation: 'Consider promoting user registration to accelerate migration'
      });
    }

    // Check orphaned data
    if (this.metrics.orphanedData > this.thresholds.orphanedDataMax) {
      report.alerts.push({
        level: 'warning',
        message: `Found ${this.metrics.orphanedData} orphaned records`,
        recommendation: 'Run cleanup utility to remove orphaned data'
      });
    }

    // Check index performance
    for (const [indexName, efficiency] of Object.entries(this.metrics.indexPerformance)) {
      if (efficiency < this.thresholds.indexEfficiencyMin) {
        report.alerts.push({
          level: 'info',
          message: `Index ${indexName} has low efficiency (${(efficiency * 100).toFixed(2)}%)`,
          recommendation: 'Consider rebuilding or optimizing index'
        });
      }
    }

    // Add general recommendations
    if (this.metrics.totalLegacyResponses > this.metrics.totalMigratedResponses) {
      report.recommendations.push('Legacy responses still outnumber migrated ones - consider migration campaign');
    }

    if (report.checks.constraints && report.checks.constraints.total > 0) {
      report.recommendations.push('Database constraint violations detected - run integrity check');
    }
  }

  /**
   * Get current metrics
   */
  getMetrics() {
    return { ...this.metrics };
  }

  /**
   * Reset metrics
   */
  resetMetrics() {
    this.metrics = {
      totalLegacyResponses: 0,
      totalMigratedResponses: 0,
      migrationRate: 0,
      orphanedData: 0,
      indexPerformance: {},
      lastCheck: null,
      alerts: []
    };
  }
}

// Singleton instance
const migrationMonitor = new MigrationMonitor();

module.exports = migrationMonitor;