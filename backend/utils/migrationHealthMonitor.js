// Migration Health Monitoring and Alert System
const migrationMonitor = require('./migrationMonitor');
const IndexOptimizer = require('./indexOptimizer');
const OrphanedDataCleanup = require('./orphanedDataCleanup');
const SecureLogger = require('./secureLogger');
const EventEmitter = require('events');

class MigrationHealthMonitor extends EventEmitter {
  constructor(config = {}) {
    super();
    
    // Validate and set configuration with safe defaults
    this.config = {
      checkInterval: this.validateNumber(config.checkInterval, 300000), // 5 minutes
      alertThresholds: {
        orphanedDataPercent: this.validateNumber(config.orphanedDataPercent, 5), // Alert if >5% orphaned data
        queryPerformanceDegradation: this.validateNumber(config.queryPerformanceDegradation, 50), // >50ms average increase
        migrationStagnation: this.validateNumber(config.migrationStagnation, 24 * 60 * 60 * 1000), // 24 hours without progress
        errorRate: this.validateNumber(config.errorRate, 10), // >10% error rate in operations
        indexEfficiency: this.validateNumber(config.indexEfficiency, 0.7) // <70% index usage efficiency
      },
      autoCleanup: Boolean(config.autoCleanup),
      autoOptimize: Boolean(config.autoOptimize)
    };
    
    this.monitors = {
      migration: migrationMonitor,
      indexOptimizer: new IndexOptimizer(),
      orphanedCleanup: new OrphanedDataCleanup()
    };
    
    this.healthStatus = {
      overall: 'unknown',
      lastCheck: null,
      issues: [],
      metrics: {},
      alerts: []
    };
    
    this.monitoring = false;
    this.checkTimer = null;
  }

  /**
   * Validate and convert configuration numbers
   */
  validateNumber(value, defaultValue) {
    const num = parseFloat(value);
    return (isNaN(num) || num <= 0) ? defaultValue : num;
  }

  /**
   * Start continuous health monitoring
   */
  startMonitoring() {
    if (this.monitoring) {
      console.log('📊 Health monitoring already running');
      return;
    }

    console.log('🚀 Starting migration health monitoring...');
    console.log(`📅 Check interval: ${this.config.checkInterval/1000}s`);
    
    this.monitoring = true;
    this.emit('monitoring_started');
    
    // Initial health check
    this.performHealthCheck().catch(error => {
      console.error('❌ Initial health check failed:', error);
    });
    
    // Schedule regular checks
    this.checkTimer = setInterval(async () => {
      try {
        await this.performHealthCheck();
      } catch (error) {
        console.error('❌ Scheduled health check failed:', error);
        this.emit('monitoring_error', error);
      }
    }, this.config.checkInterval);
  }

  /**
   * Stop health monitoring
   */
  stopMonitoring() {
    if (!this.monitoring) return;
    
    console.log('⏹️  Stopping migration health monitoring');
    this.monitoring = false;
    
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }
    
    this.emit('monitoring_stopped');
  }

  /**
   * Perform comprehensive health check
   */
  async performHealthCheck() {
    console.log('🔍 Performing migration health check...');
    const startTime = Date.now();
    
    this.healthStatus.lastCheck = new Date().toISOString();
    this.healthStatus.issues = [];
    this.healthStatus.alerts = [];
    
    try {
      // 1. Migration progress check
      const migrationHealth = await this.checkMigrationHealth();
      
      // 2. Index performance check
      const indexHealth = await this.checkIndexHealth();
      
      // 3. Orphaned data check
      const dataHealth = await this.checkDataHealth();
      
      // 4. System performance check
      const performanceHealth = await this.checkPerformanceHealth();
      
      // Aggregate health status
      this.healthStatus.metrics = {
        migration: migrationHealth,
        indexes: indexHealth,
        data: dataHealth,
        performance: performanceHealth
      };
      
      // Determine overall health
      this.healthStatus.overall = this.calculateOverallHealth();
      
      // Process alerts
      await this.processAlerts();
      
      // Auto-remediation if enabled
      if (this.config.autoCleanup || this.config.autoOptimize) {
        await this.attemptAutoRemediation();
      }
      
      const duration = Date.now() - startTime;
      console.log(`✅ Health check completed in ${duration}ms - Status: ${this.healthStatus.overall.toUpperCase()}`);
      
      this.emit('health_check_completed', this.healthStatus);
      
      return this.healthStatus;
    } catch (error) {
      this.healthStatus.overall = 'error';
      this.healthStatus.issues.push({
        type: 'system',
        severity: 'critical',
        message: `Health check failed: ${error.message}`,
        timestamp: new Date().toISOString()
      });
      
      SecureLogger.logError('Health check failed', error);
      this.emit('health_check_failed', error);
      throw error;
    }
  }

  /**
   * Check migration progress and health
   */
  async checkMigrationHealth() {
    const health = await this.monitors.migration.checkMigrationHealth();
    const issues = [];
    
    // Check for basic migration issues based on available data
    if (health.checks && health.checks.dataDistribution) {
      const dist = health.checks.dataDistribution;
      if (dist.legacyPercentage > 90) {
        issues.push({
          type: 'migration',
          severity: 'warning',
          message: `High legacy token usage: ${dist.legacyPercentage.toFixed(1)}%`,
          data: dist
        });
      }
    }
    
    // Check for alerts from migration monitor
    if (health.alerts && health.alerts.length > 0) {
      health.alerts.forEach(alert => {
        issues.push({
          type: 'migration',
          severity: alert.severity || 'warning',
          message: alert.message,
          data: alert.data || {}
        });
      });
    }
    
    this.healthStatus.issues.push(...issues);
    return { ...health, issues };
  }

  /**
   * Check index performance and optimization
   */
  async checkIndexHealth() {
    const indexAnalysis = await this.monitors.indexOptimizer.analyzeIndexes();
    const issues = [];
    
    // Check for unused indexes
    const unusedIndexes = Object.entries(indexAnalysis.current)
      .filter(([name, data]) => data.stats && data.stats.accesses < 10)
      .map(([name]) => name);
    
    if (unusedIndexes.length > 0) {
      issues.push({
        type: 'index',
        severity: 'warning',
        message: `${unusedIndexes.length} underutilized indexes detected`,
        data: { unusedIndexes }
      });
    }
    
    // Check for high priority recommendations
    const criticalRecs = indexAnalysis.recommendations.filter(r => r.priority === 'critical');
    if (criticalRecs.length > 0) {
      issues.push({
        type: 'index',
        severity: 'high',
        message: `${criticalRecs.length} critical index optimizations needed`,
        data: { recommendations: criticalRecs }
      });
    }
    
    this.healthStatus.issues.push(...issues);
    return { ...indexAnalysis, issues };
  }

  /**
   * Check for orphaned and inconsistent data
   */
  async checkDataHealth() {
    // Run cleanup in dry-run mode to assess issues
    const cleanupStats = await this.monitors.orphanedCleanup.runCleanup({ dryRun: true });
    const issues = [];
    
    // Calculate orphan percentage
    const totalIssues = cleanupStats.totalCleaned;
    if (totalIssues > 0) {
      const severity = totalIssues > 100 ? 'high' : 'warning';
      issues.push({
        type: 'data',
        severity,
        message: `${totalIssues} data consistency issues detected`,
        data: cleanupStats
      });
    }
    
    // Specific issue alerts
    if (cleanupStats.duplicateTokens > 0) {
      issues.push({
        type: 'data',
        severity: 'warning',
        message: `${cleanupStats.duplicateTokens} duplicate tokens found`,
        data: { duplicates: cleanupStats.duplicateTokens }
      });
    }
    
    if (cleanupStats.invalidUserReferences > 0) {
      issues.push({
        type: 'data',
        severity: 'high',
        message: `${cleanupStats.invalidUserReferences} invalid user references`,
        data: { invalidRefs: cleanupStats.invalidUserReferences }
      });
    }
    
    this.healthStatus.issues.push(...issues);
    return { cleanupStats, issues };
  }

  /**
   * Check system performance metrics
   */
  async checkPerformanceHealth() {
    const performanceMetrics = await this.monitors.indexOptimizer.capturePerformanceMetrics();
    const issues = [];
    
    // Check query performance
    if (performanceMetrics.avgQueryTime > this.config.alertThresholds.queryPerformanceDegradation) {
      issues.push({
        type: 'performance',
        severity: 'warning',
        message: `Average query time elevated: ${performanceMetrics.avgQueryTime.toFixed(2)}ms`,
        data: { queryTime: performanceMetrics.avgQueryTime }
      });
    }
    
    this.healthStatus.issues.push(...issues);
    return { ...performanceMetrics, issues };
  }

  /**
   * Calculate overall health status
   */
  calculateOverallHealth() {
    const issues = this.healthStatus.issues;
    
    if (issues.some(i => i.severity === 'critical')) {
      return 'critical';
    }
    
    if (issues.some(i => i.severity === 'high')) {
      return 'degraded';
    }
    
    if (issues.some(i => i.severity === 'warning')) {
      return 'warning';
    }
    
    return 'healthy';
  }

  /**
   * Process and send alerts based on health status
   */
  async processAlerts() {
    const alerts = [];
    
    // Group issues by severity
    const criticalIssues = this.healthStatus.issues.filter(i => i.severity === 'critical');
    const highIssues = this.healthStatus.issues.filter(i => i.severity === 'high');
    const warningIssues = this.healthStatus.issues.filter(i => i.severity === 'warning');
    
    // Create alerts
    if (criticalIssues.length > 0) {
      alerts.push({
        level: 'critical',
        title: '🚨 CRITICAL: Migration System Issues Detected',
        message: `${criticalIssues.length} critical issues require immediate attention`,
        issues: criticalIssues,
        timestamp: new Date().toISOString()
      });
    }
    
    if (highIssues.length > 0) {
      alerts.push({
        level: 'high',
        title: '⚠️  HIGH: Migration Performance Issues',
        message: `${highIssues.length} high priority issues detected`,
        issues: highIssues,
        timestamp: new Date().toISOString()
      });
    }
    
    if (warningIssues.length > 3) {
      alerts.push({
        level: 'warning',
        title: '📋 WARNING: Multiple Migration Issues',
        message: `${warningIssues.length} warning-level issues detected`,
        issues: warningIssues.slice(0, 5), // Limit details
        timestamp: new Date().toISOString()
      });
    }
    
    this.healthStatus.alerts = alerts;
    
    // Send alerts
    for (const alert of alerts) {
      await this.sendAlert(alert);
    }
  }

  /**
   * Send alert notification
   */
  async sendAlert(alert) {
    // Log to secure logger
    SecureLogger.logInfo(`Migration Alert [${alert.level.toUpperCase()}]: ${alert.title}`, {
      message: alert.message,
      issueCount: alert.issues.length
    });
    
    // Emit event for external handling
    this.emit('alert', alert);
    
    // Console output for immediate visibility
    const icon = {
      critical: '🚨',
      high: '⚠️ ',
      warning: '📋'
    }[alert.level];
    
    console.log(`\n${icon} ${alert.title}`);
    console.log(`   ${alert.message}`);
    
    if (alert.level === 'critical') {
      console.log('   🔧 Immediate action required!');
    }
    
    console.log(`   📅 ${alert.timestamp}\n`);
  }

  /**
   * Attempt automatic remediation for known issues
   */
  async attemptAutoRemediation() {
    const issues = this.healthStatus.issues;
    let actionsPerformed = 0;
    
    console.log('🔧 Attempting automatic remediation...');
    
    // Auto-cleanup if enabled
    if (this.config.autoCleanup) {
      const dataIssues = issues.filter(i => i.type === 'data' && i.severity !== 'critical');
      if (dataIssues.length > 0) {
        try {
          console.log('  🧹 Running automatic data cleanup...');
          await this.monitors.orphanedCleanup.runCleanup({ dryRun: false });
          actionsPerformed++;
        } catch (error) {
          console.error('  ❌ Auto-cleanup failed:', error.message);
        }
      }
    }
    
    // Auto-optimize if enabled
    if (this.config.autoOptimize) {
      const indexIssues = issues.filter(i => i.type === 'index' && i.severity === 'high');
      if (indexIssues.length > 0) {
        try {
          console.log('  📊 Running automatic index optimization...');
          await this.monitors.indexOptimizer.applyOptimizations({ 
            dryRun: false, 
            priorities: ['critical', 'high'] 
          });
          actionsPerformed++;
        } catch (error) {
          console.error('  ❌ Auto-optimization failed:', error.message);
        }
      }
    }
    
    if (actionsPerformed > 0) {
      console.log(`✅ Performed ${actionsPerformed} automatic remediation actions`);
      this.emit('auto_remediation_completed', { actionsPerformed });
    }
  }

  /**
   * Generate detailed health report
   */
  generateHealthReport() {
    return {
      timestamp: this.healthStatus.lastCheck,
      monitoring: this.monitoring,
      overall: this.healthStatus.overall,
      summary: {
        totalIssues: this.healthStatus.issues.length,
        critical: this.healthStatus.issues.filter(i => i.severity === 'critical').length,
        high: this.healthStatus.issues.filter(i => i.severity === 'high').length,
        warning: this.healthStatus.issues.filter(i => i.severity === 'warning').length,
        alerts: this.healthStatus.alerts.length
      },
      details: {
        issues: this.healthStatus.issues,
        metrics: this.healthStatus.metrics,
        alerts: this.healthStatus.alerts
      },
      configuration: {
        checkInterval: this.config.checkInterval,
        thresholds: this.config.alertThresholds,
        autoRemediation: {
          cleanup: this.config.autoCleanup,
          optimize: this.config.autoOptimize
        }
      }
    };
  }

  /**
   * Get current health status
   */
  getHealthStatus() {
    return {
      status: this.healthStatus.overall,
      lastCheck: this.healthStatus.lastCheck,
      monitoring: this.monitoring,
      issues: this.healthStatus.issues.length,
      alerts: this.healthStatus.alerts.length
    };
  }

  /**
   * Configure alert thresholds
   */
  configureThresholds(thresholds) {
    this.config.alertThresholds = {
      ...this.config.alertThresholds,
      ...thresholds
    };
    console.log('📊 Alert thresholds updated');
  }

  /**
   * Enable/disable auto-remediation
   */
  setAutoRemediation(cleanup = false, optimize = false) {
    this.config.autoCleanup = cleanup;
    this.config.autoOptimize = optimize;
    console.log(`🔧 Auto-remediation: cleanup=${cleanup}, optimize=${optimize}`);
  }

  /**
   * Manual trigger for health check
   */
  async checkNow() {
    console.log('🔍 Manual health check triggered');
    return await this.performHealthCheck();
  }

  /**
   * Cleanup resources
   */
  cleanup() {
    this.stopMonitoring();
    this.removeAllListeners();
  }
}

module.exports = MigrationHealthMonitor;