// Index Strategy Optimization for Migration Performance
const mongoose = require('mongoose');
const Response = require('../models/Response');
const SecureLogger = require('./secureLogger');

class IndexOptimizer {
  constructor() {
    this.indexAnalysis = {
      current: {},
      recommendations: [],
      performance: {},
      migration: {
        phase: 'unknown', // pre-migration, active, post-migration
        migrationRate: 0
      }
    };
  }

  /**
   * Analyze current index usage and performance
   */
  async analyzeIndexes() {
    console.log('🔍 Analyzing index performance...');
    
    try {
      const collection = Response.collection;
      
      // Get current indexes
      const indexes = await collection.listIndexes().toArray();
      
      // Get index statistics (fallback for test environments)
      let indexStats = [];
      try {
        indexStats = await collection.indexStats();
      } catch (error) {
        console.log('⚠️  IndexStats not available (test environment)');
        indexStats = [];
      }
      
      // Analyze each index
      for (const index of indexes) {
        const indexName = index.name;
        const stats = indexStats.find(s => s.name === indexName);
        
        this.indexAnalysis.current[indexName] = {
          keys: index.key,
          options: {
            unique: index.unique || false,
            sparse: index.sparse || false,
            partial: !!index.partialFilterExpression
          },
          stats: stats ? {
            accesses: stats.accesses || 0,
            usage: stats.usage || 0,
            since: stats.since
          } : null,
          size: index.indexSize || 'unknown'
        };
      }
      
      await this.assessMigrationPhase();
      await this.generateRecommendations();
      
      return this.indexAnalysis;
    } catch (error) {
      SecureLogger.logError('Index analysis failed', error);
      throw error;
    }
  }

  /**
   * Assess current migration phase to optimize index strategy
   */
  async assessMigrationPhase() {
    try {
      const [totalResponses, userResponses, tokenResponses] = await Promise.all([
        Response.countDocuments(),
        Response.countDocuments({ authMethod: 'user' }),
        Response.countDocuments({ authMethod: 'token' })
      ]);

      const migrationRate = totalResponses > 0 ? userResponses / totalResponses : 0;
      this.indexAnalysis.migration.migrationRate = migrationRate;

      if (migrationRate < 0.1) {
        this.indexAnalysis.migration.phase = 'pre-migration';
      } else if (migrationRate < 0.8) {
        this.indexAnalysis.migration.phase = 'active';
      } else {
        this.indexAnalysis.migration.phase = 'post-migration';
      }

      console.log(`📊 Migration phase: ${this.indexAnalysis.migration.phase} (${(migrationRate * 100).toFixed(1)}% migrated)`);
      
    } catch (error) {
      SecureLogger.logError('Migration phase assessment failed', error);
    }
  }

  /**
   * Generate index optimization recommendations
   */
  async generateRecommendations() {
    const { phase, migrationRate } = this.indexAnalysis.migration;
    this.indexAnalysis.recommendations = [];

    switch (phase) {
      case 'pre-migration':
        this.generatePreMigrationRecommendations();
        break;
      case 'active':
        this.generateActiveMigrationRecommendations();
        break;
      case 'post-migration':
        this.generatePostMigrationRecommendations();
        break;
    }
  }

  /**
   * Pre-migration index recommendations
   */
  generatePreMigrationRecommendations() {
    this.indexAnalysis.recommendations.push({
      type: 'optimize',
      priority: 'high',
      action: 'strengthen_token_index',
      description: 'Optimize token lookup index for legacy performance',
      implementation: {
        create: { token: 1, month: 1 },
        rationale: 'Compound index for frequent token + month queries'
      }
    });

    this.indexAnalysis.recommendations.push({
      type: 'prepare',
      priority: 'medium',
      action: 'prepare_user_indexes',
      description: 'Pre-create user indexes for smooth migration',
      implementation: {
        create: { userId: 1, month: 1 },
        options: { background: true },
        rationale: 'Background creation to avoid migration delays'
      }
    });
  }

  /**
   * Active migration index recommendations
   */
  generateActiveMigrationRecommendations() {
    this.indexAnalysis.recommendations.push({
      type: 'optimize',
      priority: 'critical',
      action: 'dual_auth_optimization',
      description: 'Optimize for dual authentication methods',
      implementation: {
        create: { authMethod: 1, month: 1 },
        rationale: 'Fast filtering by authentication method'
      }
    });

    this.indexAnalysis.recommendations.push({
      type: 'monitor',
      priority: 'high',
      action: 'watch_partial_indexes',
      description: 'Monitor partial index effectiveness',
      implementation: {
        check: ['userId_month_user_auth', 'admin_token_constraint'],
        rationale: 'Ensure partial filters are being used effectively'
      }
    });

    this.indexAnalysis.recommendations.push({
      type: 'temporary',
      priority: 'medium',
      action: 'migration_helper_index',
      description: 'Temporary index to speed up migration queries',
      implementation: {
        create: { name: 1, month: 1, authMethod: 1 },
        temporary: true,
        rationale: 'Helps with migration matching by name and month'
      }
    });
  }

  /**
   * Post-migration index recommendations
   */
  generatePostMigrationRecommendations() {
    this.indexAnalysis.recommendations.push({
      type: 'cleanup',
      priority: 'high',
      action: 'remove_legacy_indexes',
      description: 'Remove unused legacy-focused indexes',
      implementation: {
        drop: ['token_1', 'name_1_month_1'],
        condition: 'if token usage < 5%',
        rationale: 'Free up storage and maintenance overhead'
      }
    });

    this.indexAnalysis.recommendations.push({
      type: 'optimize',
      priority: 'medium',
      action: 'consolidate_user_indexes',
      description: 'Optimize user-focused index strategy',
      implementation: {
        create: { userId: 1, month: 1, isAdmin: 1 },
        drop: ['userId_1_month_1'],
        rationale: 'Single compound index for user queries'
      }
    });
  }

  /**
   * Apply index optimizations based on recommendations
   */
  async applyOptimizations(options = {}) {
    const { dryRun = true, priorities = ['critical', 'high'] } = options;
    
    console.log(`🔧 Applying index optimizations (dryRun: ${dryRun})`);
    
    const results = {
      applied: 0,
      skipped: 0,
      errors: 0,
      details: []
    };

    for (const rec of this.indexAnalysis.recommendations) {
      if (!priorities.includes(rec.priority)) {
        results.skipped++;
        continue;
      }

      try {
        await this.applyRecommendation(rec, dryRun);
        results.applied++;
        results.details.push({
          action: rec.action,
          status: 'success',
          dryRun
        });
      } catch (error) {
        results.errors++;
        results.details.push({
          action: rec.action,
          status: 'error',
          error: error.message
        });
        SecureLogger.logError(`Failed to apply ${rec.action}`, error);
      }
    }

    return results;
  }

  /**
   * Apply a specific recommendation
   */
  async applyRecommendation(recommendation, dryRun) {
    const collection = Response.collection;
    
    switch (recommendation.type) {
      case 'optimize':
      case 'prepare':
        if (recommendation.implementation.create) {
          const indexSpec = recommendation.implementation.create;
          const options = recommendation.implementation.options || {};
          
          if (dryRun) {
            console.log(`Would create index:`, indexSpec, options);
          } else {
            await collection.createIndex(indexSpec, options);
            console.log(`✅ Created index:`, indexSpec);
          }
        }
        break;

      case 'cleanup':
        if (recommendation.implementation.drop) {
          for (const indexName of recommendation.implementation.drop) {
            if (dryRun) {
              console.log(`Would drop index: ${indexName}`);
            } else {
              try {
                await collection.dropIndex(indexName);
                console.log(`✅ Dropped index: ${indexName}`);
              } catch (error) {
                if (error.code !== 27) { // Index not found
                  throw error;
                }
              }
            }
          }
        }
        break;

      case 'temporary':
        // Create temporary indexes with TTL or manual cleanup
        if (recommendation.implementation.create) {
          const indexSpec = recommendation.implementation.create;
          const options = { background: true, ...recommendation.implementation.options };
          
          if (dryRun) {
            console.log(`Would create temporary index:`, indexSpec);
          } else {
            await collection.createIndex(indexSpec, options);
            console.log(`✅ Created temporary index:`, indexSpec);
            
            // Schedule cleanup (in production, use a job scheduler)
            if (process.env.NODE_ENV !== 'production') {
              setTimeout(async () => {
                try {
                  await this.cleanupTemporaryIndex(indexSpec);
                } catch (error) {
                  SecureLogger.logError('Failed to cleanup temporary index', error);
                }
              }, 24 * 60 * 60 * 1000); // 24 hours
            }
          }
        }
        break;
    }
  }

  /**
   * Cleanup temporary indexes
   */
  async cleanupTemporaryIndex(indexSpec) {
    try {
      const collection = Response.collection;
      const indexName = Object.keys(indexSpec).map(k => `${k}_${indexSpec[k]}`).join('_');
      await collection.dropIndex(indexName);
      console.log(`🧹 Cleaned up temporary index: ${indexName}`);
    } catch (error) {
      // Index might not exist or already dropped
      if (error.code !== 27) {
        throw error;
      }
    }
  }

  /**
   * Monitor index performance over time
   */
  async monitorPerformance(durationMs = 60000) {
    console.log(`📊 Starting ${durationMs/1000}s index performance monitoring...`);
    
    const startTime = Date.now();
    const baseline = await this.capturePerformanceMetrics();
    
    // Wait for the specified duration
    await new Promise(resolve => setTimeout(resolve, durationMs));
    
    const endMetrics = await this.capturePerformanceMetrics();
    
    return this.calculatePerformanceDiff(baseline, endMetrics);
  }

  /**
   * Capture current performance metrics
   */
  async capturePerformanceMetrics() {
    const collection = Response.collection;
    
    // Handle test environments that don't support indexStats
    let indexStats = [];
    try {
      indexStats = await collection.indexStats();
    } catch (error) {
      console.log('⚠️  IndexStats not available (test environment)');
    }
    
    const metrics = {
      timestamp: Date.now(),
      indexStats,
      queryCount: await this.getQueryCount(),
      avgQueryTime: await this.measureAverageQueryTime()
    };
    
    return metrics;
  }

  /**
   * Get approximate query count
   */
  async getQueryCount() {
    // This would typically come from MongoDB profiling or monitoring
    // For now, return a placeholder
    return {
      total: Math.floor(Math.random() * 1000),
      byIndex: {}
    };
  }

  /**
   * Measure average query time for common operations
   */
  async measureAverageQueryTime() {
    const testQueries = [
      () => Response.findOne({ token: 'test-token' }),
      () => Response.findOne({ userId: new mongoose.Types.ObjectId() }),
      () => Response.find({ month: '2024-01', isAdmin: true })
    ];
    
    const times = [];
    
    for (const queryFn of testQueries) {
      const start = Date.now();
      try {
        await queryFn();
      } catch (error) {
        // Query might fail, that's okay for timing
      }
      times.push(Date.now() - start);
    }
    
    return times.reduce((sum, time) => sum + time, 0) / times.length;
  }

  /**
   * Calculate performance difference between two measurements
   */
  calculatePerformanceDiff(baseline, current) {
    const diff = {
      duration: current.timestamp - baseline.timestamp,
      queryTimeChange: current.avgQueryTime - baseline.avgQueryTime,
      improvements: [],
      concerns: []
    };
    
    if (diff.queryTimeChange < 0) {
      diff.improvements.push(`Query time improved by ${Math.abs(diff.queryTimeChange).toFixed(2)}ms`);
    } else if (diff.queryTimeChange > 5) {
      diff.concerns.push(`Query time increased by ${diff.queryTimeChange.toFixed(2)}ms`);
    }
    
    return diff;
  }

  /**
   * Generate optimization report
   */
  generateReport() {
    return {
      timestamp: new Date().toISOString(),
      migration: this.indexAnalysis.migration,
      currentIndexes: Object.keys(this.indexAnalysis.current).length,
      recommendations: {
        total: this.indexAnalysis.recommendations.length,
        critical: this.indexAnalysis.recommendations.filter(r => r.priority === 'critical').length,
        high: this.indexAnalysis.recommendations.filter(r => r.priority === 'high').length,
        medium: this.indexAnalysis.recommendations.filter(r => r.priority === 'medium').length
      },
      details: this.indexAnalysis
    };
  }
}

module.exports = IndexOptimizer;