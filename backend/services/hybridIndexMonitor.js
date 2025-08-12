const mongoose = require('mongoose');
const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');

/**
 * Hybrid Index Performance Monitor
 * 
 * Specialized monitoring for dual authentication system index performance:
 * - Tracks user-based vs token-based query patterns
 * - Monitors index efficiency during transition phases
 * - Provides real-time performance comparison
 * - Automated optimization recommendations
 */
class HybridIndexMonitor extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.config = {
      monitoringInterval: options.monitoringInterval || 30000, // 30 seconds
      slowQueryThreshold: options.slowQueryThreshold || 100, // ms
      indexEfficiencyThreshold: options.indexEfficiencyThreshold || 0.8, // 80%
      sampleSize: options.sampleSize || 1000, // queries to analyze
      retentionPeriod: options.retentionPeriod || 7 * 24 * 60 * 60 * 1000, // 7 days
      enableDetailedLogging: options.enableDetailedLogging !== false,
      ...options
    };

    // Hybrid index performance metrics
    this.metrics = {
      // Authentication method performance comparison
      authMethodPerformance: {
        user: { queryCount: 0, avgTime: 0, indexHits: 0, totalTime: 0 },
        token: { queryCount: 0, avgTime: 0, indexHits: 0, totalTime: 0 },
        hybrid: { queryCount: 0, avgTime: 0, indexHits: 0, totalTime: 0 }
      },
      
      // Index usage patterns
      indexUsage: {
        'responses_userId_1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_token_1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_month_1_isAdmin_1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_createdAt_-1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_compound_hybrid': { hits: 0, misses: 0, efficiency: 0 }
      },
      
      // Query pattern analysis
      queryPatterns: {
        userLookup: { count: 0, avgTime: 0, indexUsed: null },
        tokenLookup: { count: 0, avgTime: 0, indexUsed: null },
        monthlyQuery: { count: 0, avgTime: 0, indexUsed: null },
        adminQuery: { count: 0, avgTime: 0, indexUsed: null },
        hybridQuery: { count: 0, avgTime: 0, indexUsed: null }
      },
      
      // Performance trends
      trends: {
        hourlyStats: new Map(), // Last 24 hours
        performanceAlerts: [],
        recommendations: []
      },
      
      lastUpdated: new Date()
    };

    // Query pattern detection
    this.queryPatterns = {
      // User-based authentication queries
      userAuth: {
        pattern: /userId.*ObjectId|user.*populate/i,
        type: 'user',
        expectedIndex: 'responses_userId_1'
      },
      
      // Token-based authentication queries  
      tokenAuth: {
        pattern: /token.*[a-f0-9]{32,}/i,
        type: 'token', 
        expectedIndex: 'responses_token_1'
      },
      
      // Monthly data queries
      monthQuery: {
        pattern: /month.*\d{4}-\d{2}/i,
        type: 'monthly',
        expectedIndex: 'responses_month_1_isAdmin_1'
      },
      
      // Admin-specific queries
      adminQuery: {
        pattern: /isAdmin.*true|admin.*true/i,
        type: 'admin',
        expectedIndex: 'responses_month_1_isAdmin_1'
      },
      
      // Hybrid queries combining multiple auth methods
      hybridQuery: {
        pattern: /(userId|token).*month.*isAdmin/i,
        type: 'hybrid',
        expectedIndex: 'responses_compound_hybrid'
      }
    };

    this.isMonitoring = false;
    this.monitoringTimer = null;
    this.queryBuffer = [];
    
    // Debug metrics for safety checks
    this.debugMetrics = {
      invalidModelQueries: 0,
      skippedNonResponsesQueries: 0,
      invalidQueryObjects: 0,
      totalQueriesIntercepted: 0,
      lastReset: new Date()
    };
  }

  /**
   * Start hybrid index monitoring
   */
  async startMonitoring() {
    if (this.isMonitoring) {
      SecureLogger.logInfo('Hybrid Index Monitor already running');
      return;
    }

    try {
      SecureLogger.logInfo('Starting Hybrid Index Performance Monitoring');
      
      // Initialize baseline metrics
      await this.captureBaselineMetrics();
      
      // Set up query interception
      this.setupQueryInterception();
      
      // Start periodic analysis
      this.schedulePeriodicAnalysis();
      
      this.isMonitoring = true;
      this.emit('hybrid-monitoring-started');
      
      SecureLogger.logInfo('Hybrid Index Monitor started successfully', {
        monitoringInterval: this.config.monitoringInterval,
        slowQueryThreshold: this.config.slowQueryThreshold
      });
      
    } catch (error) {
      SecureLogger.logError('Failed to start Hybrid Index Monitor', error);
      throw error;
    }
  }

  /**
   * Stop hybrid index monitoring
   */
  stopMonitoring() {
    if (!this.isMonitoring) return;

    SecureLogger.logInfo('Stopping Hybrid Index Monitor');

    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
      this.monitoringTimer = null;
    }

    this.isMonitoring = false;
    this.emit('hybrid-monitoring-stopped');
    
    // Generate final performance report
    const finalReport = this.generatePerformanceReport();
    SecureLogger.logInfo('Hybrid Index Monitor final report', finalReport);
    
    SecureLogger.logInfo('Hybrid Index Monitor stopped');
  }

  /**
   * Capture baseline performance metrics
   */
  async captureBaselineMetrics() {
    try {
      // Wait for database connection to be ready
      if (mongoose.connection.readyState !== 1) {
        SecureLogger.logInfo('Database not ready for baseline metrics capture, skipping');
        return;
      }

      const db = mongoose.connection.db;
      if (!db) {
        SecureLogger.logInfo('Database connection not available, skipping baseline metrics');
        return;
      }
      
      // Get current index statistics
      const collections = await db.collections();
      
      for (const collection of collections) {
        if (collection.collectionName === 'responses') {
          const indexStats = await collection.aggregate([
            { $indexStats: {} }
          ]).toArray();
          
          // Initialize baseline metrics for each index
          for (const stat of indexStats) {
            const indexName = stat.name;
            if (this.metrics.indexUsage[indexName]) {
              this.metrics.indexUsage[indexName].baselineAccesses = stat.accesses?.ops || 0;
              this.metrics.indexUsage[indexName].baselineTime = Date.now();
            }
          }
          break;
        }
      }
      
      SecureLogger.logInfo('Baseline metrics captured for hybrid index monitoring');
      
    } catch (error) {
      SecureLogger.logError('Failed to capture baseline metrics', error);
    }
  }

  /**
   * Setup query interception for performance analysis
   */
  setupQueryInterception() {
    // Temporarily disable query interception due to compatibility issues
    // This was causing "Query must have `op` before executing" errors
    SecureLogger.logInfo('Query interception temporarily disabled for stability');
    
    // TODO: Implement alternative monitoring approach that doesn't interfere with Mongoose internals
    // Consider using Mongoose middleware or database profiler instead
    return;
  }

  /**
   * Analyze individual query performance
   */
  async analyzeQuery(query, executionTime, result, error = null) {
    if (!this.isMonitoring || !query) return;

    try {
      // Safety check for query methods
      if (!query.getQuery || typeof query.getQuery !== 'function') {
        this.debugMetrics.invalidQueryObjects++;
        if (this.config.enableDetailedLogging) {
          SecureLogger.logDebug('Query analysis skipped - invalid query object', {
            hasGetQuery: !!query.getQuery,
            getQueryType: typeof query.getQuery,
            queryConstructor: query.constructor?.name || 'unknown',
            invalidQueryCount: this.debugMetrics.invalidQueryObjects,
            timestamp: new Date().toISOString()
          });
        }
        return;
      }
      
      const queryString = JSON.stringify(query.getQuery());
      const queryType = this.categorizeQuery(queryString);
      
      // Update metrics based on query type
      this.updateQueryMetrics(queryType, executionTime, queryString);
      
      // Check for performance issues
      if (executionTime > this.config.slowQueryThreshold) {
        await this.handleSlowQuery(query, executionTime, queryType);
      }
      
      // Sample detailed analysis
      if (Math.random() < 0.1) { // 10% sampling
        await this.performDetailedAnalysis(query, executionTime, queryType);
      }
      
    } catch (analysisError) {
      SecureLogger.logError('Query analysis failed', analysisError);
    }
  }

  /**
   * Categorize query by hybrid index usage pattern
   */
  categorizeQuery(queryString) {
    for (const [patternName, config] of Object.entries(this.queryPatterns)) {
      if (config.pattern.test(queryString)) {
        return {
          name: patternName,
          type: config.type,
          expectedIndex: config.expectedIndex
        };
      }
    }
    
    return {
      name: 'unknown',
      type: 'other',
      expectedIndex: null
    };
  }

  /**
   * Update performance metrics for query type
   */
  updateQueryMetrics(queryType, executionTime, queryString) {
    const authType = queryType.type;
    
    // Update auth method performance
    if (this.metrics.authMethodPerformance[authType]) {
      const metrics = this.metrics.authMethodPerformance[authType];
      metrics.queryCount++;
      metrics.totalTime += executionTime;
      metrics.avgTime = metrics.totalTime / metrics.queryCount;
    }
    
    // Update query pattern metrics
    if (this.metrics.queryPatterns[queryType.name]) {
      const pattern = this.metrics.queryPatterns[queryType.name];
      pattern.count++;
      pattern.avgTime = ((pattern.avgTime * (pattern.count - 1)) + executionTime) / pattern.count;
    }
    
    this.metrics.lastUpdated = new Date();
  }

  /**
   * Handle slow query detection and analysis
   */
  async handleSlowQuery(query, executionTime, queryType) {
    const slowQueryData = {
      timestamp: new Date(),
      executionTime,
      queryType: queryType.name,
      authType: queryType.type,
      expectedIndex: queryType.expectedIndex,
      query: JSON.stringify(query.getQuery()),
      collection: query.model.collection.name
    };
    
    // Perform explain analysis for slow queries
    try {
      const explanation = await query.explain('executionStats');
      slowQueryData.explanation = {
        totalExamined: explanation.executionStats?.docsExamined || 0,
        totalReturned: explanation.executionStats?.nReturned || 0,
        indexUsed: explanation.executionStats?.indexName || 'COLLECTION_SCAN',
        stage: explanation.executionStats?.stage || 'UNKNOWN'
      };
      
      // Check if expected index was used
      const expectedIndex = queryType.expectedIndex;
      const actualIndex = slowQueryData.explanation.indexUsed;
      
      if (expectedIndex && actualIndex !== expectedIndex) {
        this.addPerformanceAlert({
          type: 'INDEX_MISMATCH',
          severity: 'HIGH',
          message: `Query expected ${expectedIndex} but used ${actualIndex}`,
          queryType: queryType.name,
          executionTime,
          timestamp: new Date()
        });
      }
      
    } catch (explainError) {
      SecureLogger.logError('Failed to explain slow query', explainError);
    }
    
    // Log slow query for analysis
    if (this.config.enableDetailedLogging) {
      SecureLogger.logInfo('Slow hybrid query detected', slowQueryData);
    }
    
    this.emit('slow-query-detected', slowQueryData);
  }

  /**
   * Perform detailed query analysis with explain
   */
  async performDetailedAnalysis(query, executionTime, queryType) {
    try {
      const explanation = await query.explain('executionStats');
      const stats = explanation.executionStats;
      
      // Calculate index efficiency
      const docsExamined = stats.docsExamined || 0;
      const docsReturned = stats.nReturned || 0;
      const efficiency = docsReturned > 0 ? docsReturned / Math.max(docsExamined, 1) : 0;
      
      // Update index usage statistics
      const indexName = stats.indexName || 'COLLECTION_SCAN';
      if (this.metrics.indexUsage[indexName]) {
        const indexMetrics = this.metrics.indexUsage[indexName];
        
        if (efficiency > this.config.indexEfficiencyThreshold) {
          indexMetrics.hits++;
        } else {
          indexMetrics.misses++;
        }
        
        indexMetrics.efficiency = indexMetrics.hits / (indexMetrics.hits + indexMetrics.misses);
      }
      
      // Generate recommendations for poor performance
      if (efficiency < this.config.indexEfficiencyThreshold) {
        this.generatePerformanceRecommendation(queryType, efficiency, stats);
      }
      
    } catch (error) {
      SecureLogger.logError('Detailed query analysis failed', error);
    }
  }

  /**
   * Schedule periodic performance analysis
   */
  schedulePeriodicAnalysis() {
    this.monitoringTimer = setInterval(async () => {
      try {
        await this.performPeriodicAnalysis();
      } catch (error) {
        SecureLogger.logError('Periodic analysis failed', error);
      }
    }, this.config.monitoringInterval);
  }

  /**
   * Perform periodic performance analysis
   */
  async performPeriodicAnalysis() {
    // Update hourly statistics
    this.updateHourlyStats();
    
    // Check for performance degradation
    this.checkPerformanceTrends();
    
    // Generate recommendations if needed
    this.generateAutomatedRecommendations();
    
    // Emit periodic report
    const report = this.generatePerformanceReport();
    this.emit('periodic-report', report);
    
    // Log performance summary
    SecureLogger.logInfo('Hybrid index performance summary', {
      userAuthAvgTime: this.metrics.authMethodPerformance.user.avgTime,
      tokenAuthAvgTime: this.metrics.authMethodPerformance.token.avgTime,
      totalQueries: Object.values(this.metrics.authMethodPerformance)
        .reduce((sum, auth) => sum + auth.queryCount, 0),
      alertCount: this.metrics.trends.performanceAlerts.length
    });
  }

  /**
   * Update hourly performance statistics
   */
  updateHourlyStats() {
    const currentHour = new Date().getHours();
    const hourlyStats = this.metrics.trends.hourlyStats;
    
    if (!hourlyStats.has(currentHour)) {
      hourlyStats.set(currentHour, {
        queries: 0,
        avgTime: 0,
        slowQueries: 0,
        indexHits: 0,
        indexMisses: 0
      });
    }
    
    // Keep only last 24 hours
    if (hourlyStats.size > 24) {
      const oldestHour = Math.min(...hourlyStats.keys());
      hourlyStats.delete(oldestHour);
    }
  }

  /**
   * Check for performance trends and degradation
   */
  checkPerformanceTrends() {
    const userAuth = this.metrics.authMethodPerformance.user;
    const tokenAuth = this.metrics.authMethodPerformance.token;
    
    // Check for significant performance differences
    if (userAuth.queryCount > 0 && tokenAuth.queryCount > 0) {
      const performanceDiff = Math.abs(userAuth.avgTime - tokenAuth.avgTime);
      const threshold = Math.max(userAuth.avgTime, tokenAuth.avgTime) * 0.5; // 50% difference
      
      if (performanceDiff > threshold) {
        this.addPerformanceAlert({
          type: 'AUTH_METHOD_PERFORMANCE_GAP',
          severity: 'MEDIUM',
          message: `Significant performance difference between auth methods: User(${userAuth.avgTime.toFixed(2)}ms) vs Token(${tokenAuth.avgTime.toFixed(2)}ms)`,
          timestamp: new Date(),
          data: { userAvgTime: userAuth.avgTime, tokenAvgTime: tokenAuth.avgTime }
        });
      }
    }
  }

  /**
   * Generate automated performance recommendations
   */
  generateAutomatedRecommendations() {
    const recommendations = [];
    
    // Check index efficiency
    for (const [indexName, metrics] of Object.entries(this.metrics.indexUsage)) {
      if (metrics.efficiency < this.config.indexEfficiencyThreshold && metrics.hits + metrics.misses > 10) {
        recommendations.push({
          type: 'INDEX_OPTIMIZATION',
          priority: 'HIGH',
          message: `Index ${indexName} has low efficiency (${(metrics.efficiency * 100).toFixed(1)}%). Consider optimization.`,
          indexName,
          efficiency: metrics.efficiency,
          timestamp: new Date()
        });
      }
    }
    
    // Check for unused indexes
    const totalQueries = Object.values(this.metrics.authMethodPerformance)
      .reduce((sum, auth) => sum + auth.queryCount, 0);
      
    if (totalQueries > 100) { // Only after sufficient data
      for (const [indexName, metrics] of Object.entries(this.metrics.indexUsage)) {
        if (metrics.hits === 0 && metrics.misses === 0) {
          recommendations.push({
            type: 'UNUSED_INDEX',
            priority: 'LOW',
            message: `Index ${indexName} appears unused. Consider removal if confirmed.`,
            indexName,
            timestamp: new Date()
          });
        }
      }
    }
    
    this.metrics.trends.recommendations = recommendations;
  }

  /**
   * Generate performance recommendation for specific query
   */
  generatePerformanceRecommendation(queryType, efficiency, executionStats) {
    const recommendation = {
      type: 'QUERY_OPTIMIZATION',
      queryType: queryType.name,
      efficiency,
      executionStats: {
        docsExamined: executionStats.docsExamined,
        docsReturned: executionStats.nReturned,
        indexUsed: executionStats.indexName
      },
      suggestions: [],
      timestamp: new Date()
    };
    
    // Generate specific suggestions based on query type
    if (queryType.type === 'user' && efficiency < 0.5) {
      recommendation.suggestions.push('Consider compound index on userId + createdAt for user-based queries');
    }
    
    if (queryType.type === 'token' && efficiency < 0.5) {
      recommendation.suggestions.push('Ensure token index is optimally positioned for lookup queries');
    }
    
    if (queryType.type === 'hybrid' && efficiency < 0.3) {
      recommendation.suggestions.push('Consider specialized compound index for hybrid authentication queries');
    }
    
    this.metrics.trends.recommendations.push(recommendation);
  }

  /**
   * Add performance alert
   */
  addPerformanceAlert(alert) {
    this.metrics.trends.performanceAlerts.push(alert);
    
    // Keep only recent alerts (last 100)
    if (this.metrics.trends.performanceAlerts.length > 100) {
      this.metrics.trends.performanceAlerts = this.metrics.trends.performanceAlerts.slice(-100);
    }
    
    this.emit('performance-alert', alert);
  }

  /**
   * Generate comprehensive performance report
   */
  generatePerformanceReport() {
    const report = {
      timestamp: new Date(),
      monitoringDuration: this.isMonitoring ? Date.now() - this.metrics.lastUpdated : 0,
      
      // Authentication method comparison
      authMethodComparison: {
        user: {
          ...this.metrics.authMethodPerformance.user,
          avgTime: Math.round(this.metrics.authMethodPerformance.user.avgTime * 100) / 100
        },
        token: {
          ...this.metrics.authMethodPerformance.token,
          avgTime: Math.round(this.metrics.authMethodPerformance.token.avgTime * 100) / 100
        },
        hybrid: {
          ...this.metrics.authMethodPerformance.hybrid,
          avgTime: Math.round(this.metrics.authMethodPerformance.hybrid.avgTime * 100) / 100
        }
      },
      
      // Index efficiency summary
      indexEfficiency: Object.fromEntries(
        Object.entries(this.metrics.indexUsage).map(([name, metrics]) => [
          name, 
          {
            efficiency: Math.round(metrics.efficiency * 10000) / 100, // Percentage with 2 decimals
            totalOperations: metrics.hits + metrics.misses,
            hits: metrics.hits,
            misses: metrics.misses
          }
        ])
      ),
      
      // Performance alerts summary
      alerts: {
        total: this.metrics.trends.performanceAlerts.length,
        high: this.metrics.trends.performanceAlerts.filter(a => a.severity === 'HIGH').length,
        medium: this.metrics.trends.performanceAlerts.filter(a => a.severity === 'MEDIUM').length,
        low: this.metrics.trends.performanceAlerts.filter(a => a.severity === 'LOW').length,
        recent: this.metrics.trends.performanceAlerts.slice(-5) // Last 5 alerts
      },
      
      // Recommendations summary
      recommendations: {
        total: this.metrics.trends.recommendations.length,
        high: this.metrics.trends.recommendations.filter(r => r.priority === 'HIGH').length,
        medium: this.metrics.trends.recommendations.filter(r => r.priority === 'MEDIUM').length,
        low: this.metrics.trends.recommendations.filter(r => r.priority === 'LOW').length,
        recent: this.metrics.trends.recommendations.slice(-3) // Last 3 recommendations
      }
    };
    
    return report;
  }

  /**
   * Get current performance metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      isMonitoring: this.isMonitoring,
      config: { ...this.config }
    };
  }

  /**
   * Get debug metrics for safety checks
   */
  getDebugMetrics() {
    return {
      ...this.debugMetrics,
      uptime: Date.now() - this.debugMetrics.lastReset.getTime(),
      interceptRate: this.debugMetrics.totalQueriesIntercepted > 0 
        ? (this.debugMetrics.invalidModelQueries / this.debugMetrics.totalQueriesIntercepted * 100).toFixed(2) + '%'
        : '0%'
    };
  }

  /**
   * Reset debug metrics
   */
  resetDebugMetrics() {
    this.debugMetrics = {
      invalidModelQueries: 0,
      skippedNonResponsesQueries: 0,
      invalidQueryObjects: 0,
      totalQueriesIntercepted: 0,
      lastReset: new Date()
    };
    
    SecureLogger.logInfo('Hybrid index monitor debug metrics reset');
  }

  /**
   * Reset performance metrics
   */
  resetMetrics() {
    this.metrics = {
      authMethodPerformance: {
        user: { queryCount: 0, avgTime: 0, indexHits: 0, totalTime: 0 },
        token: { queryCount: 0, avgTime: 0, indexHits: 0, totalTime: 0 },
        hybrid: { queryCount: 0, avgTime: 0, indexHits: 0, totalTime: 0 }
      },
      indexUsage: {
        'responses_userId_1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_token_1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_month_1_isAdmin_1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_createdAt_-1': { hits: 0, misses: 0, efficiency: 0 },
        'responses_compound_hybrid': { hits: 0, misses: 0, efficiency: 0 }
      },
      queryPatterns: {
        userLookup: { count: 0, avgTime: 0, indexUsed: null },
        tokenLookup: { count: 0, avgTime: 0, indexUsed: null },
        monthlyQuery: { count: 0, avgTime: 0, indexUsed: null },
        adminQuery: { count: 0, avgTime: 0, indexUsed: null },
        hybridQuery: { count: 0, avgTime: 0, indexUsed: null }
      },
      trends: {
        hourlyStats: new Map(),
        performanceAlerts: [],
        recommendations: []
      },
      lastUpdated: new Date()
    };
    
    SecureLogger.logInfo('Hybrid index performance metrics reset');
  }
}

module.exports = HybridIndexMonitor;