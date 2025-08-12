const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');

/**
 * Real-Time Performance Metrics Collector
 * 
 * Collects and aggregates real-time performance metrics from DBPerformanceMonitor
 * Provides sliding window analytics and instant alerts
 */
class RealTimeMetrics extends EventEmitter {
  constructor(dbMonitor, options = {}) {
    super();
    
    this.dbMonitor = dbMonitor;
    this.config = {
      windowSize: options.windowSize || 5 * 60 * 1000, // 5 minutes
      updateInterval: options.updateInterval || 10 * 1000, // 10 seconds
      alertThresholds: {
        slowQueryRate: options.slowQueryRate || 0.2, // 20%
        avgExecutionTime: options.avgExecutionTime || 200, // ms
        queryVolume: options.queryVolume || 1000, // queries per minute
        indexEfficiency: options.indexEfficiency || 0.7 // 70%
      },
      retainWindows: options.retainWindows || 720, // 2 hours of 10s windows
      ...options
    };

    // Sliding window data
    this.windows = [];
    this.currentWindow = this.createWindow();
    
    // Real-time aggregated metrics
    this.realtimeStats = {
      queriesPerSecond: 0,
      avgExecutionTime: 0,
      slowQueryRate: 0,
      indexHitRatio: 0,
      hybridIndexEfficiency: 0,
      activeConnections: 0,
      memoryUsage: 0,
      alertsCount: 0,
      lastUpdated: new Date()
    };

    // Alert tracking
    this.activeAlerts = new Map();
    this.alertHistory = [];
    
    this.isCollecting = false;
    this.collectionTimer = null;
  }

  /**
   * Start real-time metrics collection
   */
  startCollection() {
    if (this.isCollecting) {
      SecureLogger.logWarning('Real-time metrics collection already active');
      return;
    }

    SecureLogger.logInfo('Starting real-time metrics collection');

    // Listen to DB monitor events
    this.setupDBMonitorListeners();
    
    // Start periodic aggregation
    this.scheduleAggregation();
    
    this.isCollecting = true;
    this.emit('collection-started');
    
    SecureLogger.logInfo('Real-time metrics collection started');
  }

  /**
   * Stop real-time metrics collection
   */
  stopCollection() {
    if (!this.isCollecting) return;

    SecureLogger.logInfo('Stopping real-time metrics collection');

    // Remove DB monitor listeners
    this.removeDBMonitorListeners();
    
    // Clear timers
    if (this.collectionTimer) {
      clearInterval(this.collectionTimer);
      this.collectionTimer = null;
    }

    this.isCollecting = false;
    this.emit('collection-stopped');
    
    SecureLogger.logInfo('Real-time metrics collection stopped');
  }

  /**
   * Set up listeners for DB monitor events
   */
  setupDBMonitorListeners() {
    this.dbMonitor.on('query-recorded', this.handleQueryRecorded.bind(this));
    this.dbMonitor.on('slow-query-detected', this.handleSlowQueryDetected.bind(this));
    this.dbMonitor.on('monitoring-started', this.handleMonitoringStarted.bind(this));
    this.dbMonitor.on('monitoring-stopped', this.handleMonitoringStopped.bind(this));
  }

  /**
   * Remove DB monitor listeners
   */
  removeDBMonitorListeners() {
    this.dbMonitor.removeAllListeners('query-recorded');
    this.dbMonitor.removeAllListeners('slow-query-detected');
    this.dbMonitor.removeAllListeners('monitoring-started');
    this.dbMonitor.removeAllListeners('monitoring-stopped');
  }

  /**
   * Handle query recorded event
   */
  handleQueryRecorded(queryData) {
    this.currentWindow.queries.push({
      timestamp: queryData.timestamp || new Date(),
      executionTime: queryData.executionTime,
      collection: queryData.collection,
      operation: queryData.operation,
      hybridIndex: this.dbMonitor.analyzeHybridIndexUsage(queryData.filter)
    });

    this.currentWindow.totalQueries++;
    this.currentWindow.totalExecutionTime += queryData.executionTime;
    
    this.emit('query-added', queryData);
  }

  /**
   * Handle slow query detected event
   */
  handleSlowQueryDetected(queryData) {
    this.currentWindow.slowQueries++;
    
    // Create alert if threshold exceeded
    this.checkSlowQueryAlert();
    
    this.emit('slow-query-added', queryData);
  }

  /**
   * Handle monitoring started event
   */
  handleMonitoringStarted() {
    SecureLogger.logInfo('DB monitoring started - real-time collection active');
  }

  /**
   * Handle monitoring stopped event
   */
  handleMonitoringStopped() {
    SecureLogger.logWarning('DB monitoring stopped - real-time metrics may be incomplete');
  }

  /**
   * Create new time window
   */
  createWindow() {
    return {
      startTime: new Date(),
      endTime: null,
      queries: [],
      totalQueries: 0,
      slowQueries: 0,
      totalExecutionTime: 0,
      collections: new Map(),
      hybridIndexUsage: new Map(),
      alerts: []
    };
  }

  /**
   * Schedule periodic aggregation
   */
  scheduleAggregation() {
    this.collectionTimer = setInterval(() => {
      this.aggregateCurrentWindow();
      this.calculateRealtimeStats();
      this.checkAlerts();
      this.emit('metrics-updated', this.realtimeStats);
    }, this.config.updateInterval);
  }

  /**
   * Aggregate current window and start new one
   */
  aggregateCurrentWindow() {
    // Finalize current window
    this.currentWindow.endTime = new Date();
    this.currentWindow.duration = this.currentWindow.endTime - this.currentWindow.startTime;
    
    // Calculate window statistics
    this.calculateWindowStats(this.currentWindow);
    
    // Add to windows array
    this.windows.push(this.currentWindow);
    
    // Maintain window count limit
    if (this.windows.length > this.config.retainWindows) {
      this.windows = this.windows.slice(-this.config.retainWindows);
    }
    
    // Start new window
    this.currentWindow = this.createWindow();
  }

  /**
   * Calculate statistics for a window
   */
  calculateWindowStats(window) {
    if (window.totalQueries === 0) {
      window.stats = {
        avgExecutionTime: 0,
        queriesPerSecond: 0,
        slowQueryRate: 0,
        indexEfficiency: 0
      };
      return;
    }

    // Basic statistics
    window.stats = {
      avgExecutionTime: window.totalExecutionTime / window.totalQueries,
      queriesPerSecond: window.totalQueries / (window.duration / 1000),
      slowQueryRate: window.slowQueries / window.totalQueries,
      indexEfficiency: this.calculateWindowIndexEfficiency(window)
    };

    // Collection breakdown
    window.queries.forEach(query => {
      const collection = query.collection;
      if (!window.collections.has(collection)) {
        window.collections.set(collection, {
          count: 0,
          totalTime: 0,
          slowCount: 0
        });
      }

      const collStats = window.collections.get(collection);
      collStats.count++;
      collStats.totalTime += query.executionTime;
      
      if (query.executionTime >= this.dbMonitor.config.slowQueryThreshold) {
        collStats.slowCount++;
      }
    });

    // Hybrid index usage breakdown
    window.queries.forEach(query => {
      if (query.hybridIndex && query.hybridIndex.type !== 'none') {
        const indexType = query.hybridIndex.type;
        if (!window.hybridIndexUsage.has(indexType)) {
          window.hybridIndexUsage.set(indexType, {
            count: 0,
            totalEfficiency: 0,
            totalTime: 0
          });
        }

        const indexStats = window.hybridIndexUsage.get(indexType);
        indexStats.count++;
        indexStats.totalEfficiency += query.hybridIndex.efficiency || 0;
        indexStats.totalTime += query.executionTime;
      }
    });
  }

  /**
   * Calculate index efficiency for a window
   */
  calculateWindowIndexEfficiency(window) {
    if (window.queries.length === 0) return 1;

    let totalEfficiency = 0;
    let indexedQueries = 0;

    window.queries.forEach(query => {
      if (query.hybridIndex && query.hybridIndex.efficiency !== undefined) {
        totalEfficiency += query.hybridIndex.efficiency;
        indexedQueries++;
      }
    });

    return indexedQueries > 0 ? totalEfficiency / indexedQueries : 0.5;
  }

  /**
   * Calculate real-time aggregated statistics
   */
  calculateRealtimeStats() {
    const recentWindows = this.getRecentWindows(this.config.windowSize);
    
    if (recentWindows.length === 0) {
      return;
    }

    // Aggregate across recent windows
    let totalQueries = 0;
    let totalSlowQueries = 0;
    let totalExecutionTime = 0;
    let totalDuration = 0;
    let totalIndexEfficiency = 0;
    let windowsWithQueries = 0;

    recentWindows.forEach(window => {
      totalQueries += window.totalQueries;
      totalSlowQueries += window.slowQueries;
      totalExecutionTime += window.totalExecutionTime;
      totalDuration += window.duration || this.config.updateInterval;
      
      if (window.stats && window.totalQueries > 0) {
        totalIndexEfficiency += window.stats.indexEfficiency;
        windowsWithQueries++;
      }
    });

    // Update real-time stats
    this.realtimeStats = {
      queriesPerSecond: totalDuration > 0 ? totalQueries / (totalDuration / 1000) : 0,
      avgExecutionTime: totalQueries > 0 ? totalExecutionTime / totalQueries : 0,
      slowQueryRate: totalQueries > 0 ? totalSlowQueries / totalQueries : 0,
      indexHitRatio: this.calculateIndexHitRatio(recentWindows),
      hybridIndexEfficiency: windowsWithQueries > 0 ? totalIndexEfficiency / windowsWithQueries : 0,
      activeConnections: this.getActiveConnections(),
      memoryUsage: this.getMemoryUsage(),
      alertsCount: this.activeAlerts.size,
      lastUpdated: new Date(),
      
      // Additional breakdown stats
      breakdown: {
        totalQueries,
        totalSlowQueries,
        windowsAnalyzed: recentWindows.length,
        timespan: totalDuration
      }
    };
  }

  /**
   * Get recent windows within specified timeframe
   */
  getRecentWindows(timespan) {
    const cutoffTime = Date.now() - timespan;
    return this.windows.filter(window => 
      window.endTime && window.endTime.getTime() > cutoffTime
    );
  }

  /**
   * Calculate index hit ratio from recent windows
   */
  calculateIndexHitRatio(windows) {
    let indexedQueries = 0;
    let totalQueries = 0;

    windows.forEach(window => {
      window.queries.forEach(query => {
        totalQueries++;
        if (query.hybridIndex && 
            query.hybridIndex.type !== 'none' && 
            query.hybridIndex.type !== 'collection-scan') {
          indexedQueries++;
        }
      });
    });

    return totalQueries > 0 ? indexedQueries / totalQueries : 1;
  }

  /**
   * Get active database connections
   */
  getActiveConnections() {
    try {
      const mongoose = require('mongoose');
      return mongoose.connection.readyState === 1 ? 1 : 0;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Get memory usage information
   */
  getMemoryUsage() {
    const memUsage = process.memoryUsage();
    return {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      rss: memUsage.rss,
      external: memUsage.external,
      heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
      heapTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024)
    };
  }

  /**
   * Check for performance alerts
   */
  checkAlerts() {
    this.checkSlowQueryAlert();
    this.checkExecutionTimeAlert();
    this.checkQueryVolumeAlert();
    this.checkIndexEfficiencyAlert();
  }

  /**
   * Check slow query rate alert
   */
  checkSlowQueryAlert() {
    const threshold = this.config.alertThresholds.slowQueryRate;
    const current = this.realtimeStats.slowQueryRate;
    const alertKey = 'slow_query_rate';

    if (current > threshold) {
      this.triggerAlert(alertKey, 'high', {
        message: `Slow query rate ${(current * 100).toFixed(1)}% exceeds threshold ${(threshold * 100).toFixed(1)}%`,
        currentValue: current,
        threshold,
        recommendation: 'Review and optimize slow queries or add appropriate indexes'
      });
    } else {
      this.resolveAlert(alertKey);
    }
  }

  /**
   * Check average execution time alert
   */
  checkExecutionTimeAlert() {
    const threshold = this.config.alertThresholds.avgExecutionTime;
    const current = this.realtimeStats.avgExecutionTime;
    const alertKey = 'avg_execution_time';

    if (current > threshold) {
      this.triggerAlert(alertKey, 'medium', {
        message: `Average execution time ${current.toFixed(1)}ms exceeds threshold ${threshold}ms`,
        currentValue: current,
        threshold,
        recommendation: 'Optimize frequently used queries and verify index usage'
      });
    } else {
      this.resolveAlert(alertKey);
    }
  }

  /**
   * Check query volume alert
   */
  checkQueryVolumeAlert() {
    const threshold = this.config.alertThresholds.queryVolume / 60; // Convert to per second
    const current = this.realtimeStats.queriesPerSecond;
    const alertKey = 'query_volume';

    if (current > threshold) {
      this.triggerAlert(alertKey, 'low', {
        message: `Query volume ${current.toFixed(1)} QPS exceeds threshold ${threshold.toFixed(1)} QPS`,
        currentValue: current,
        threshold,
        recommendation: 'Monitor system resources and consider query optimization'
      });
    } else {
      this.resolveAlert(alertKey);
    }
  }

  /**
   * Check index efficiency alert
   */
  checkIndexEfficiencyAlert() {
    const threshold = this.config.alertThresholds.indexEfficiency;
    const current = this.realtimeStats.hybridIndexEfficiency;
    const alertKey = 'index_efficiency';

    if (current < threshold && current > 0) {
      this.triggerAlert(alertKey, 'medium', {
        message: `Hybrid index efficiency ${(current * 100).toFixed(1)}% below threshold ${(threshold * 100).toFixed(1)}%`,
        currentValue: current,
        threshold,
        recommendation: 'Review hybrid indexing strategy and query patterns'
      });
    } else {
      this.resolveAlert(alertKey);
    }
  }

  /**
   * Trigger performance alert
   */
  triggerAlert(alertKey, severity, details) {
    if (this.activeAlerts.has(alertKey)) {
      // Update existing alert
      const alert = this.activeAlerts.get(alertKey);
      alert.count++;
      alert.lastTriggered = new Date();
      alert.details = details;
    } else {
      // Create new alert
      const alert = {
        key: alertKey,
        severity,
        details,
        firstTriggered: new Date(),
        lastTriggered: new Date(),
        count: 1,
        resolved: false
      };
      
      this.activeAlerts.set(alertKey, alert);
      this.alertHistory.push({ ...alert });
      
      SecureLogger.logWarning(`Performance alert triggered: ${alertKey}`, details);
      this.emit('alert-triggered', alert);
    }
  }

  /**
   * Resolve performance alert
   */
  resolveAlert(alertKey) {
    if (this.activeAlerts.has(alertKey)) {
      const alert = this.activeAlerts.get(alertKey);
      alert.resolved = true;
      alert.resolvedAt = new Date();
      
      this.activeAlerts.delete(alertKey);
      
      SecureLogger.logInfo(`Performance alert resolved: ${alertKey}`);
      this.emit('alert-resolved', alert);
    }
  }

  /**
   * Get current real-time statistics
   */
  getCurrentStats() {
    return {
      realtime: { ...this.realtimeStats },
      windows: {
        total: this.windows.length,
        recentCount: this.getRecentWindows(this.config.windowSize).length,
        oldestWindow: this.windows.length > 0 ? this.windows[0].startTime : null,
        newestWindow: this.windows.length > 0 ? this.windows[this.windows.length - 1].endTime : null
      },
      alerts: {
        active: this.activeAlerts.size,
        history: this.alertHistory.length,
        activeAlerts: Array.from(this.activeAlerts.values())
      }
    };
  }

  /**
   * Get detailed window analysis
   */
  getWindowAnalysis(timespan = null) {
    const windows = timespan ? this.getRecentWindows(timespan) : this.windows;
    
    if (windows.length === 0) {
      return { error: 'No data available' };
    }

    // Collection performance breakdown
    const collectionStats = new Map();
    
    // Hybrid index usage breakdown
    const indexUsageStats = new Map();
    
    windows.forEach(window => {
      // Aggregate collection stats
      for (const [collection, stats] of window.collections.entries()) {
        if (!collectionStats.has(collection)) {
          collectionStats.set(collection, {
            totalQueries: 0,
            totalTime: 0,
            slowQueries: 0,
            windows: 0
          });
        }
        
        const collStats = collectionStats.get(collection);
        collStats.totalQueries += stats.count;
        collStats.totalTime += stats.totalTime;
        collStats.slowQueries += stats.slowCount;
        collStats.windows++;
      }
      
      // Aggregate index usage stats
      for (const [indexType, stats] of window.hybridIndexUsage.entries()) {
        if (!indexUsageStats.has(indexType)) {
          indexUsageStats.set(indexType, {
            totalQueries: 0,
            totalEfficiency: 0,
            totalTime: 0,
            windows: 0
          });
        }
        
        const indexStats = indexUsageStats.get(indexType);
        indexStats.totalQueries += stats.count;
        indexStats.totalEfficiency += stats.totalEfficiency;
        indexStats.totalTime += stats.totalTime;
        indexStats.windows++;
      }
    });

    return {
      timespan: timespan || 'all',
      windowsAnalyzed: windows.length,
      period: {
        start: windows[0].startTime,
        end: windows[windows.length - 1].endTime
      },
      
      collections: Array.from(collectionStats.entries()).map(([name, stats]) => ({
        name,
        totalQueries: stats.totalQueries,
        avgTime: stats.totalTime / stats.totalQueries,
        slowQueryRate: stats.slowQueries / stats.totalQueries,
        queriesPerWindow: stats.totalQueries / stats.windows
      })),
      
      hybridIndexUsage: Array.from(indexUsageStats.entries()).map(([type, stats]) => ({
        type,
        totalQueries: stats.totalQueries,
        avgEfficiency: stats.totalEfficiency / stats.totalQueries,
        avgTime: stats.totalTime / stats.totalQueries,
        usageRate: stats.totalQueries / windows.reduce((sum, w) => sum + w.totalQueries, 0)
      }))
    };
  }

  /**
   * Export real-time metrics data
   */
  exportMetricsData() {
    return {
      timestamp: new Date(),
      config: this.config,
      realtimeStats: this.realtimeStats,
      windows: this.windows,
      activeAlerts: Array.from(this.activeAlerts.values()),
      alertHistory: this.alertHistory
    };
  }

  /**
   * Reset all metrics data
   */
  resetMetrics() {
    this.windows = [];
    this.currentWindow = this.createWindow();
    this.activeAlerts.clear();
    this.alertHistory = [];
    
    this.realtimeStats = {
      queriesPerSecond: 0,
      avgExecutionTime: 0,
      slowQueryRate: 0,
      indexHitRatio: 0,
      hybridIndexEfficiency: 0,
      activeConnections: 0,
      memoryUsage: 0,
      alertsCount: 0,
      lastUpdated: new Date()
    };
    
    SecureLogger.logInfo('Real-time metrics reset');
    this.emit('metrics-reset');
  }
}

module.exports = RealTimeMetrics;