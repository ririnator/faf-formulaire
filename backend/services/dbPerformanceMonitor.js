const mongoose = require('mongoose');
const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');

/**
 * Database Query Performance Monitor
 * 
 * Monitors hybrid indexing strategy performance including:
 * - Query execution times and patterns
 * - Index usage and efficiency
 * - Slow query detection and analysis
 * - Real-time performance metrics
 * - Automated recommendations
 */
class DBPerformanceMonitor extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.config = {
      slowQueryThreshold: options.slowQueryThreshold || 100, // ms
      sampleRate: options.sampleRate || 1.0, // Sample 100% of queries by default
      retentionPeriod: options.retentionPeriod || 24 * 60 * 60 * 1000, // 24 hours
      maxMetricsBuffer: options.maxMetricsBuffer || 10000,
      enableProfiling: options.enableProfiling !== false,
      enableExplainAnalysis: options.enableExplainAnalysis !== false,
      ...options
    };

    // Performance metrics storage
    this.metrics = {
      queries: new Map(),
      indexes: new Map(),
      collections: new Map(),
      slowQueries: [],
      aggregatedStats: {
        totalQueries: 0,
        slowQueries: 0,
        avgExecutionTime: 0,
        indexHitRatio: 0,
        lastUpdated: new Date()
      }
    };

    // Query patterns for hybrid indexing analysis
    this.hybridIndexPatterns = {
      userAuth: /userId.*user/i,
      tokenAuth: /token.*token/i,
      monthQuery: /month.*\d{4}-\d{2}/i,
      adminQuery: /isAdmin.*true/i,
      hybridUnique: /(month.*userId)|(month.*isAdmin.*name)/i,
      timeRange: /createdAt.*(\$gte|\$lte|\$lt|\$gt)/i
    };

    this.isMonitoring = false;
    this.cleanupTimer = null;
  }

  /**
   * Start performance monitoring
   */
  async startMonitoring() {
    if (this.isMonitoring) {
      SecureLogger.logWarning('DB Performance Monitor already running');
      return;
    }

    SecureLogger.logInfo('Starting DB Performance Monitoring');

    try {
      // Enable MongoDB profiling if configured
      if (this.config.enableProfiling) {
        await this.enableMongoProfiling();
      }

      // Set up query monitoring
      this.setupQueryMonitoring();
      
      // Set up periodic cleanup
      this.scheduleCleanup();
      
      // Initialize index analysis
      await this.analyzeCurrentIndexes();
      
      this.isMonitoring = true;
      this.emit('monitoring-started');
      
      SecureLogger.logInfo('DB Performance Monitor started successfully');
      
    } catch (error) {
      SecureLogger.logError('Failed to start DB Performance Monitor', error);
      throw error;
    }
  }

  /**
   * Stop performance monitoring
   */
  stopMonitoring() {
    if (!this.isMonitoring) return;

    SecureLogger.logInfo('Stopping DB Performance Monitor');

    // Clean up timers
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    // Disable MongoDB profiling
    if (this.config.enableProfiling) {
      this.disableMongoProfiling().catch(error => {
        SecureLogger.logError('Failed to disable MongoDB profiling', error);
      });
    }

    this.isMonitoring = false;
    this.emit('monitoring-stopped');
    
    SecureLogger.logInfo('DB Performance Monitor stopped');
  }

  /**
   * Enable MongoDB profiling for query analysis
   */
  async enableMongoProfiling() {
    try {
      const db = mongoose.connection.db;
      
      // Set profiling level: 2 = profile all operations, 1 = profile slow operations only
      await db.command({ 
        profile: 1, 
        slowms: this.config.slowQueryThreshold 
      });
      
      SecureLogger.logInfo(`MongoDB profiling enabled (slowms: ${this.config.slowQueryThreshold})`);
      
    } catch (error) {
      SecureLogger.logError('Failed to enable MongoDB profiling', error);
    }
  }

  /**
   * Disable MongoDB profiling
   */
  async disableMongoProfiling() {
    try {
      const db = mongoose.connection.db;
      await db.command({ profile: 0 });
      
      SecureLogger.logInfo('MongoDB profiling disabled');
      
    } catch (error) {
      SecureLogger.logError('Failed to disable MongoDB profiling', error);
    }
  }

  /**
   * Set up query monitoring using Mongoose middleware
   */
  setupQueryMonitoring() {
    const models = [
      mongoose.models.Response,
      mongoose.models.User
    ].filter(Boolean);

    models.forEach(model => {
      // Pre-hook to start timing
      model.schema.pre(/^(find|count|aggregate|distinct)/, function() {
        this._startTime = Date.now();
        this._operation = this.op || this.getUpdate ? 'update' : 'find';
        this._collection = this.model.collection.name;
      });

      // Post-hook to measure performance
      model.schema.post(/^(find|count|aggregate|distinct)/, function(result) {
        if (!this._startTime) return;

        const executionTime = Date.now() - this._startTime;
        
        // Sample queries based on sample rate
        if (Math.random() > this.config.sampleRate) return;

        this.recordQueryMetrics({
          collection: this._collection,
          operation: this._operation,
          filter: this.getFilter ? this.getFilter() : this.getQuery(),
          executionTime,
          resultCount: Array.isArray(result) ? result.length : (result ? 1 : 0),
          timestamp: new Date()
        });
      }.bind(this));
    });
  }

  /**
   * Record query performance metrics
   */
  recordQueryMetrics(queryData) {
    const {
      collection,
      operation,
      filter,
      executionTime,
      resultCount,
      timestamp
    } = queryData;

    // Generate query signature
    const querySignature = this.generateQuerySignature(collection, operation, filter);
    
    // Update query metrics
    if (!this.metrics.queries.has(querySignature)) {
      this.metrics.queries.set(querySignature, {
        collection,
        operation,
        filter: this.sanitizeFilter(filter),
        count: 0,
        totalTime: 0,
        minTime: Infinity,
        maxTime: 0,
        avgTime: 0,
        indexPattern: this.detectIndexPattern(filter),
        hybridIndexUsage: this.analyzeHybridIndexUsage(filter),
        firstSeen: timestamp,
        lastSeen: timestamp
      });
    }

    const queryMetrics = this.metrics.queries.get(querySignature);
    queryMetrics.count++;
    queryMetrics.totalTime += executionTime;
    queryMetrics.minTime = Math.min(queryMetrics.minTime, executionTime);
    queryMetrics.maxTime = Math.max(queryMetrics.maxTime, executionTime);
    queryMetrics.avgTime = queryMetrics.totalTime / queryMetrics.count;
    queryMetrics.lastSeen = timestamp;

    // Update collection metrics
    if (!this.metrics.collections.has(collection)) {
      this.metrics.collections.set(collection, {
        totalQueries: 0,
        totalTime: 0,
        avgTime: 0,
        slowQueries: 0
      });
    }

    const collectionMetrics = this.metrics.collections.get(collection);
    collectionMetrics.totalQueries++;
    collectionMetrics.totalTime += executionTime;
    collectionMetrics.avgTime = collectionMetrics.totalTime / collectionMetrics.totalQueries;

    // Track slow queries
    if (executionTime >= this.config.slowQueryThreshold) {
      this.recordSlowQuery(queryData);
      collectionMetrics.slowQueries++;
    }

    // Update aggregated stats
    this.updateAggregatedStats(executionTime);

    // Emit events for real-time monitoring
    this.emit('query-recorded', queryData);
    
    if (executionTime >= this.config.slowQueryThreshold) {
      this.emit('slow-query-detected', queryData);
    }
  }

  /**
   * Record slow query for detailed analysis
   */
  recordSlowQuery(queryData) {
    const slowQuery = {
      ...queryData,
      id: `${queryData.collection}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    };

    this.metrics.slowQueries.push(slowQuery);

    // Keep only recent slow queries
    if (this.metrics.slowQueries.length > this.config.maxMetricsBuffer) {
      this.metrics.slowQueries = this.metrics.slowQueries.slice(-this.config.maxMetricsBuffer / 2);
    }

    // Trigger explain analysis for slow queries if enabled
    if (this.config.enableExplainAnalysis) {
      this.explainSlowQuery(queryData);
    }
  }

  /**
   * Analyze slow queries using MongoDB explain
   */
  async explainSlowQuery(queryData) {
    try {
      const { collection, filter } = queryData;
      const db = mongoose.connection.db;
      const coll = db.collection(collection);

      const explanation = await coll.find(filter).explain('executionStats');
      
      const analysis = this.analyzeExplanation(explanation);
      
      SecureLogger.logWarning('Slow query detected', {
        collection,
        filter: this.sanitizeFilter(filter),
        executionTime: queryData.executionTime,
        analysis
      });

    } catch (error) {
      SecureLogger.logError('Failed to explain slow query', error);
    }
  }

  /**
   * Analyze MongoDB explain output
   */
  analyzeExplanation(explanation) {
    const stats = explanation.executionStats;
    
    return {
      indexUsed: stats.indexName || 'COLLSCAN',
      documentsExamined: stats.totalDocsExamined,
      documentsReturned: stats.totalDocsReturned,
      executionTime: stats.executionTimeMillis,
      indexHitRatio: stats.totalDocsExamined > 0 
        ? stats.totalDocsReturned / stats.totalDocsExamined 
        : 0,
      stage: stats.stage,
      recommendation: this.generateIndexRecommendation(stats)
    };
  }

  /**
   * Generate query signature for grouping
   */
  generateQuerySignature(collection, operation, filter) {
    const normalizedFilter = this.normalizeFilter(filter);
    return `${collection}:${operation}:${JSON.stringify(normalizedFilter)}`;
  }

  /**
   * Normalize filter for consistent signatures
   */
  normalizeFilter(filter) {
    if (!filter || typeof filter !== 'object') return {};
    
    const normalized = {};
    Object.keys(filter).forEach(key => {
      if (typeof filter[key] === 'object' && filter[key] !== null) {
        normalized[key] = Object.keys(filter[key]).reduce((acc, op) => {
          acc[op] = typeof filter[key][op];
          return acc;
        }, {});
      } else {
        normalized[key] = typeof filter[key];
      }
    });
    
    return normalized;
  }

  /**
   * Sanitize filter for logging (remove sensitive data)
   */
  sanitizeFilter(filter) {
    if (!filter || typeof filter !== 'object') return filter;
    
    const sanitized = { ...filter };
    
    // Remove potential sensitive fields
    const sensitiveFields = ['password', 'token', 'secret', 'key'];
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }

  /**
   * Detect which index pattern is being used
   */
  detectIndexPattern(filter) {
    if (!filter) return 'none';
    
    const filterString = JSON.stringify(filter).toLowerCase();
    
    for (const [pattern, regex] of Object.entries(this.hybridIndexPatterns)) {
      if (regex.test(filterString)) {
        return pattern;
      }
    }
    
    return 'unknown';
  }

  /**
   * Analyze hybrid index usage for specific query
   */
  analyzeHybridIndexUsage(filter) {
    if (!filter || typeof filter !== 'object') {
      return { type: 'none', efficiency: 0 };
    }

    const hasMonth = 'month' in filter;
    const hasUserId = 'userId' in filter;
    const hasToken = 'token' in filter;
    const hasIsAdmin = 'isAdmin' in filter;
    const hasName = 'name' in filter;
    const hasAuthMethod = 'authMethod' in filter;

    // Analyze hybrid index usage patterns
    if (hasMonth && hasUserId && hasAuthMethod === 'user') {
      return { 
        type: 'hybrid-user-unique', 
        efficiency: 0.95,
        index: '{ month: 1, userId: 1 }'
      };
    }
    
    if (hasMonth && hasIsAdmin && hasName && hasAuthMethod === 'token') {
      return { 
        type: 'hybrid-admin-unique', 
        efficiency: 0.95,
        index: '{ month: 1, isAdmin: 1, name: 1 }'
      };
    }
    
    if (hasToken) {
      return { 
        type: 'token-unique', 
        efficiency: 0.98,
        index: '{ token: 1 }'
      };
    }
    
    if (hasUserId) {
      return { 
        type: 'user-time', 
        efficiency: 0.85,
        index: '{ userId: 1, createdAt: -1 }'
      };
    }
    
    if ('createdAt' in filter) {
      return { 
        type: 'time-sorted', 
        efficiency: 0.80,
        index: '{ createdAt: -1 }'
      };
    }
    
    return { 
      type: 'collection-scan', 
      efficiency: 0.10,
      index: 'none'
    };
  }

  /**
   * Generate index recommendation based on execution stats
   */
  generateIndexRecommendation(stats) {
    const efficiency = stats.totalDocsExamined > 0 
      ? stats.totalDocsReturned / stats.totalDocsExamined 
      : 0;

    if (efficiency < 0.1) {
      return 'Consider adding compound index - low selectivity detected';
    }
    
    if (stats.stage === 'COLLSCAN') {
      return 'Full collection scan detected - index missing';
    }
    
    if (stats.executionTimeMillis > 1000) {
      return 'Query execution time high - optimize index or query structure';
    }
    
    if (efficiency > 0.8) {
      return 'Index usage efficient';
    }
    
    return 'Index usage moderate - monitor for optimization opportunities';
  }

  /**
   * Analyze current database indexes
   */
  async analyzeCurrentIndexes() {
    try {
      const collections = ['responses', 'users'];
      
      for (const collName of collections) {
        const collection = mongoose.connection.db.collection(collName);
        const indexes = await collection.listIndexes().toArray();
        
        this.metrics.indexes.set(collName, {
          indexes: indexes.map(idx => ({
            name: idx.name,
            key: idx.key,
            unique: idx.unique || false,
            sparse: idx.sparse || false,
            partialFilterExpression: idx.partialFilterExpression,
            size: 0, // Will be updated by stats collection
            usageStats: {
              ops: 0,
              since: new Date()
            }
          })),
          lastAnalyzed: new Date()
        });
      }
      
      SecureLogger.logInfo('Index analysis completed', {
        collections: collections.length,
        totalIndexes: Array.from(this.metrics.indexes.values())
          .reduce((sum, coll) => sum + coll.indexes.length, 0)
      });
      
    } catch (error) {
      SecureLogger.logError('Failed to analyze indexes', error);
    }
  }

  /**
   * Update aggregated performance statistics
   */
  updateAggregatedStats(executionTime) {
    const stats = this.metrics.aggregatedStats;
    
    stats.totalQueries++;
    if (executionTime >= this.config.slowQueryThreshold) {
      stats.slowQueries++;
    }
    
    // Calculate rolling average
    const alpha = 0.1; // Smoothing factor
    stats.avgExecutionTime = stats.avgExecutionTime * (1 - alpha) + executionTime * alpha;
    
    stats.lastUpdated = new Date();
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary() {
    const summary = {
      monitoring: {
        isActive: this.isMonitoring,
        uptime: this.isMonitoring ? Date.now() - this.metrics.aggregatedStats.lastUpdated : 0,
        config: { ...this.config }
      },
      
      aggregatedStats: { ...this.metrics.aggregatedStats },
      
      collections: Array.from(this.metrics.collections.entries()).map(([name, metrics]) => ({
        name,
        ...metrics,
        slowQueryRate: metrics.totalQueries > 0 ? metrics.slowQueries / metrics.totalQueries : 0
      })),
      
      topSlowQueries: this.metrics.slowQueries
        .sort((a, b) => b.executionTime - a.executionTime)
        .slice(0, 10)
        .map(query => ({
          collection: query.collection,
          operation: query.operation,
          executionTime: query.executionTime,
          hybridIndexUsage: query.hybridIndexUsage || this.analyzeHybridIndexUsage(query.filter)
        })),
      
      indexUsage: Array.from(this.metrics.indexes.entries()).map(([collection, data]) => ({
        collection,
        indexes: data.indexes.length,
        lastAnalyzed: data.lastAnalyzed
      })),
      
      hybridIndexEfficiency: this.calculateHybridIndexEfficiency(),
      
      recommendations: this.generatePerformanceRecommendations()
    };
    
    return summary;
  }

  /**
   * Calculate hybrid index efficiency metrics
   */
  calculateHybridIndexEfficiency() {
    const hybridQueries = Array.from(this.metrics.queries.values())
      .filter(query => query.hybridIndexUsage && query.hybridIndexUsage.type !== 'none');

    if (hybridQueries.length === 0) {
      return {
        totalHybridQueries: 0,
        avgEfficiency: 0,
        indexTypes: {}
      };
    }

    const indexTypes = {};
    let totalEfficiency = 0;
    
    hybridQueries.forEach(query => {
      const type = query.hybridIndexUsage.type;
      if (!indexTypes[type]) {
        indexTypes[type] = { count: 0, avgEfficiency: 0, totalTime: 0 };
      }
      
      indexTypes[type].count++;
      indexTypes[type].totalTime += query.avgTime;
      indexTypes[type].avgEfficiency += query.hybridIndexUsage.efficiency;
      totalEfficiency += query.hybridIndexUsage.efficiency;
    });

    // Calculate averages
    Object.keys(indexTypes).forEach(type => {
      indexTypes[type].avgEfficiency /= indexTypes[type].count;
      indexTypes[type].avgTime = indexTypes[type].totalTime / indexTypes[type].count;
    });

    return {
      totalHybridQueries: hybridQueries.length,
      avgEfficiency: totalEfficiency / hybridQueries.length,
      indexTypes
    };
  }

  /**
   * Generate performance recommendations
   */
  generatePerformanceRecommendations() {
    const recommendations = [];
    const stats = this.metrics.aggregatedStats;
    
    // Slow query rate recommendation
    const slowQueryRate = stats.totalQueries > 0 ? stats.slowQueries / stats.totalQueries : 0;
    if (slowQueryRate > 0.1) {
      recommendations.push({
        type: 'high_slow_query_rate',
        priority: 'high',
        message: `${(slowQueryRate * 100).toFixed(1)}% of queries are slow (>${this.config.slowQueryThreshold}ms)`,
        action: 'Review and optimize slow queries or add appropriate indexes'
      });
    }
    
    // Average execution time recommendation
    if (stats.avgExecutionTime > this.config.slowQueryThreshold * 2) {
      recommendations.push({
        type: 'high_avg_execution_time',
        priority: 'medium',
        message: `Average query execution time is ${stats.avgExecutionTime.toFixed(1)}ms`,
        action: 'Consider optimizing frequently used queries'
      });
    }
    
    // Hybrid index efficiency recommendation
    const hybridEfficiency = this.calculateHybridIndexEfficiency();
    if (hybridEfficiency.avgEfficiency < 0.8) {
      recommendations.push({
        type: 'hybrid_index_inefficiency',
        priority: 'medium',
        message: `Hybrid index efficiency is ${(hybridEfficiency.avgEfficiency * 100).toFixed(1)}%`,
        action: 'Review hybrid index usage patterns and consider optimization'
      });
    }
    
    // Collection scan detection
    const collectionScans = Array.from(this.metrics.queries.values())
      .filter(query => query.hybridIndexUsage && query.hybridIndexUsage.type === 'collection-scan');
    
    if (collectionScans.length > 0) {
      recommendations.push({
        type: 'collection_scans_detected',
        priority: 'high',
        message: `${collectionScans.length} queries performing collection scans`,
        action: 'Add indexes for queries without proper index support'
      });
    }
    
    return recommendations;
  }

  /**
   * Schedule periodic cleanup of old metrics
   */
  scheduleCleanup() {
    this.cleanupTimer = setInterval(() => {
      this.cleanupOldMetrics();
    }, 60 * 60 * 1000); // Run every hour
  }

  /**
   * Clean up old performance metrics
   */
  cleanupOldMetrics() {
    const cutoffTime = Date.now() - this.config.retentionPeriod;
    
    // Clean slow queries
    this.metrics.slowQueries = this.metrics.slowQueries.filter(
      query => query.timestamp && query.timestamp.getTime() > cutoffTime
    );
    
    // Clean old query metrics
    for (const [signature, metrics] of this.metrics.queries.entries()) {
      if (metrics.lastSeen && metrics.lastSeen.getTime() < cutoffTime) {
        this.metrics.queries.delete(signature);
      }
    }
    
    SecureLogger.logInfo('Performance metrics cleanup completed');
  }

  /**
   * Export performance data for analysis
   */
  exportPerformanceData() {
    return {
      timestamp: new Date(),
      config: this.config,
      metrics: {
        aggregatedStats: this.metrics.aggregatedStats,
        queries: Array.from(this.metrics.queries.entries()),
        collections: Array.from(this.metrics.collections.entries()),
        indexes: Array.from(this.metrics.indexes.entries()),
        slowQueries: this.metrics.slowQueries
      }
    };
  }

  /**
   * Reset all performance metrics
   */
  resetMetrics() {
    this.metrics = {
      queries: new Map(),
      indexes: new Map(),
      collections: new Map(),
      slowQueries: [],
      aggregatedStats: {
        totalQueries: 0,
        slowQueries: 0,
        avgExecutionTime: 0,
        indexHitRatio: 0,
        lastUpdated: new Date()
      }
    };
    
    SecureLogger.logInfo('Performance metrics reset');
    this.emit('metrics-reset');
  }
}

module.exports = DBPerformanceMonitor;