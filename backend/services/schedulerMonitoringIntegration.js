const SecureLogger = require('../utils/secureLogger');

/**
 * Scheduler Monitoring Integration Service
 * 
 * Orchestrates the complete monitoring ecosystem for Form-a-Friend v2 scheduler
 * Integrates monitoring, logging, alerting, and performance services into a unified system
 * 
 * Features:
 * - Centralized service initialization and lifecycle management
 * - Cross-service event routing and correlation
 * - Unified configuration management
 * - Health monitoring across all services
 * - Graceful shutdown and error recovery
 * - Performance optimization coordination
 */
class SchedulerMonitoringIntegration {
  constructor(config = {}) {
    this.config = {
      // Service configurations
      enableMonitoring: config.enableMonitoring !== false,
      enableLogging: config.enableLogging !== false,
      enableAlerting: config.enableAlerting !== false,
      enableRealTimeMetrics: config.enableRealTimeMetrics !== false,
      enablePerformanceAlerting: config.enablePerformanceAlerting !== false,
      
      // Integration settings
      startupTimeout: config.startupTimeout || 30000,
      shutdownTimeout: config.shutdownTimeout || 15000,
      healthCheckInterval: config.healthCheckInterval || 30000,
      
      // Cross-service correlation
      enableEventCorrelation: config.enableEventCorrelation !== false,
      correlationTimeWindow: config.correlationTimeWindow || 60000, // 1 minute
      
      // Performance optimization
      enablePerformanceOptimization: config.enablePerformanceOptimization !== false,
      optimizationInterval: config.optimizationInterval || 300000, // 5 minutes
      
      ...config
    };

    // Service instances
    this.services = {
      schedulerService: null,
      schedulerMonitoring: null,
      schedulerLogger: null,
      schedulerAlerting: null,
      realTimeMetrics: null,
      performanceAlerting: null,
      dbPerformanceMonitor: null
    };

    // Integration state
    this.isInitialized = false;
    this.isStarted = false;
    this.startupErrors = [];
    this.healthCheckTimer = null;
    this.optimizationTimer = null;
    
    // Event correlation
    this.eventCorrelation = {
      enabled: this.config.enableEventCorrelation,
      correlatedEvents: new Map(),
      recentEvents: []
    };
    
    // Integration metrics
    this.integrationMetrics = {
      servicesInitialized: 0,
      servicesStarted: 0,
      totalEvents: 0,
      correlatedEvents: 0,
      healthChecks: 0,
      optimizationRuns: 0,
      lastHealthCheck: null,
      lastOptimization: null
    };

    SecureLogger.logInfo('SchedulerMonitoringIntegration initialized', {
      enabledServices: this.getEnabledServices().length,
      enableEventCorrelation: this.config.enableEventCorrelation,
      enablePerformanceOptimization: this.config.enablePerformanceOptimization
    });
  }

  /**
   * Initialize all monitoring services
   */
  async initialize(services = {}) {
    try {
      SecureLogger.logInfo('Starting scheduler monitoring integration initialization');
      
      // Store service instances
      this.services = { ...this.services, ...services };
      
      // Validate required services
      this.validateRequiredServices();
      
      // Initialize services in dependency order
      await this.initializeServicesInOrder();
      
      // Setup cross-service integrations
      await this.setupServiceIntegrations();
      
      // Setup event correlation
      if (this.config.enableEventCorrelation) {
        this.setupEventCorrelation();
      }
      
      this.isInitialized = true;
      this.integrationMetrics.servicesInitialized = this.getActiveServices().length;
      
      SecureLogger.logInfo('Scheduler monitoring integration initialized successfully', {
        servicesInitialized: this.integrationMetrics.servicesInitialized,
        startupErrors: this.startupErrors.length
      });
      
      return {
        success: true,
        servicesInitialized: this.integrationMetrics.servicesInitialized,
        errors: this.startupErrors
      };
      
    } catch (error) {
      SecureLogger.logError('Failed to initialize scheduler monitoring integration', error);
      this.startupErrors.push(error.message);
      throw error;
    }
  }

  /**
   * Start all monitoring services
   */
  async start() {
    if (!this.isInitialized) {
      throw new Error('Integration must be initialized before starting');
    }

    try {
      SecureLogger.logInfo('Starting scheduler monitoring services');
      
      // Start services in order
      await this.startServicesInOrder();
      
      // Start integration features
      this.startHealthMonitoring();
      
      if (this.config.enablePerformanceOptimization) {
        this.startPerformanceOptimization();
      }
      
      this.isStarted = true;
      this.integrationMetrics.servicesStarted = this.getRunningServices().length;
      
      SecureLogger.logInfo('Scheduler monitoring integration started successfully', {
        servicesStarted: this.integrationMetrics.servicesStarted
      });
      
      return {
        success: true,
        servicesStarted: this.integrationMetrics.servicesStarted
      };
      
    } catch (error) {
      SecureLogger.logError('Failed to start scheduler monitoring integration', error);
      throw error;
    }
  }

  /**
   * Stop all monitoring services
   */
  async stop() {
    if (!this.isStarted) {
      return;
    }

    try {
      SecureLogger.logInfo('Stopping scheduler monitoring integration');
      
      // Stop integration features
      this.stopHealthMonitoring();
      this.stopPerformanceOptimization();
      
      // Stop services in reverse order
      await this.stopServicesInOrder();
      
      this.isStarted = false;
      
      SecureLogger.logInfo('Scheduler monitoring integration stopped successfully');
      
    } catch (error) {
      SecureLogger.logError('Error stopping scheduler monitoring integration', error);
      throw error;
    }
  }

  /**
   * Validate required services are available
   */
  validateRequiredServices() {
    const requiredServices = ['schedulerService'];
    const missingServices = [];

    for (const serviceName of requiredServices) {
      if (!this.services[serviceName]) {
        missingServices.push(serviceName);
      }
    }

    if (missingServices.length > 0) {
      throw new Error(`Missing required services: ${missingServices.join(', ')}`);
    }
  }

  /**
   * Initialize services in dependency order
   */
  async initializeServicesInOrder() {
    const initOrder = [
      'schedulerLogger',
      'realTimeMetrics',
      'dbPerformanceMonitor',
      'performanceAlerting',
      'schedulerMonitoring',
      'schedulerAlerting'
    ];

    for (const serviceName of initOrder) {
      try {
        await this.initializeService(serviceName);
      } catch (error) {
        const errorMsg = `Failed to initialize ${serviceName}: ${error.message}`;
        this.startupErrors.push(errorMsg);
        SecureLogger.logError(errorMsg, error);
        
        // Continue with other services unless critical
        if (serviceName === 'schedulerMonitoring') {
          throw error; // Critical service
        }
      }
    }
  }

  /**
   * Initialize individual service
   */
  async initializeService(serviceName) {
    const service = this.services[serviceName];
    if (!service) {
      SecureLogger.logDebug(`Service ${serviceName} not available, skipping initialization`);
      return;
    }

    if (typeof service.initialize === 'function') {
      const dependencies = this.buildServiceDependencies(serviceName);
      await service.initialize(dependencies);
      SecureLogger.logInfo(`${serviceName} initialized successfully`);
    } else {
      SecureLogger.logDebug(`${serviceName} does not require initialization`);
    }
  }

  /**
   * Build dependencies for a specific service
   */
  buildServiceDependencies(serviceName) {
    const dependencies = {};

    switch (serviceName) {
      case 'schedulerMonitoring':
        dependencies.schedulerService = this.services.schedulerService;
        dependencies.realTimeMetrics = this.services.realTimeMetrics;
        dependencies.performanceAlerting = this.services.performanceAlerting;
        break;
        
      case 'schedulerAlerting':
        dependencies.schedulerLogger = this.services.schedulerLogger;
        dependencies.schedulerMonitoring = this.services.schedulerMonitoring;
        dependencies.emailService = this.services.emailService;
        break;
        
      case 'realTimeMetrics':
        dependencies.dbMonitor = this.services.dbPerformanceMonitor;
        break;
        
      case 'performanceAlerting':
        dependencies.realTimeMetrics = this.services.realTimeMetrics;
        break;
        
      default:
        // Add scheduler service to all
        dependencies.schedulerService = this.services.schedulerService;
    }

    return dependencies;
  }

  /**
   * Setup integrations between services
   */
  async setupServiceIntegrations() {
    // Integration 1: Connect RealTimeMetrics to PerformanceAlerting
    if (this.services.realTimeMetrics && this.services.performanceAlerting) {
      this.setupRealTimeMetricsIntegration();
    }

    // Integration 2: Connect SchedulerMonitoring to SchedulerAlerting
    if (this.services.schedulerMonitoring && this.services.schedulerAlerting) {
      this.setupMonitoringAlertingIntegration();
    }

    // Integration 3: Connect SchedulerService to all monitoring services
    this.setupSchedulerServiceIntegration();

    // Integration 4: Setup cross-service logging
    this.setupCrossServiceLogging();

    SecureLogger.logInfo('Service integrations configured');
  }

  /**
   * Setup RealTimeMetrics to PerformanceAlerting integration
   */
  setupRealTimeMetricsIntegration() {
    const realTimeMetrics = this.services.realTimeMetrics;
    const performanceAlerting = this.services.performanceAlerting;

    if (typeof realTimeMetrics.on === 'function' && typeof performanceAlerting.startAlerting === 'function') {
      // Start performance alerting with real-time metrics
      performanceAlerting.startAlerting();
      
      SecureLogger.logInfo('RealTimeMetrics integration with PerformanceAlerting configured');
    }
  }

  /**
   * Setup SchedulerMonitoring to SchedulerAlerting integration
   */
  setupMonitoringAlertingIntegration() {
    const monitoring = this.services.schedulerMonitoring;
    const alerting = this.services.schedulerAlerting;

    if (typeof monitoring.on === 'function' && typeof alerting.startAlerting === 'function') {
      // Cross-connect the services
      monitoring.on('alert-triggered', (alert) => {
        this.handleCrossServiceEvent('monitoring-alert', alert);
      });

      alerting.on('alert-triggered', (alert) => {
        this.handleCrossServiceEvent('alerting-alert', alert);
      });

      SecureLogger.logInfo('SchedulerMonitoring integration with SchedulerAlerting configured');
    }
  }

  /**
   * Setup SchedulerService integration with all monitoring services
   */
  setupSchedulerServiceIntegration() {
    const schedulerService = this.services.schedulerService;
    
    if (typeof schedulerService.on === 'function') {
      // Connect scheduler events to integration layer
      schedulerService.on('job-started', (data) => {
        this.handleSchedulerEvent('job-started', data);
      });

      schedulerService.on('job-completed', (data) => {
        this.handleSchedulerEvent('job-completed', data);
      });

      schedulerService.on('job-failed', (data) => {
        this.handleSchedulerEvent('job-failed', data);
      });

      schedulerService.on('alerts-triggered', (data) => {
        this.handleSchedulerEvent('scheduler-alerts', data);
      });

      SecureLogger.logInfo('SchedulerService integration configured');
    }
  }

  /**
   * Setup cross-service logging integration
   */
  setupCrossServiceLogging() {
    const logger = this.services.schedulerLogger;
    
    if (logger) {
      // Set up correlation ID for all services
      const correlationId = logger.generateCorrelationId();
      
      // Apply correlation ID to all services that support it
      Object.entries(this.services).forEach(([name, service]) => {
        if (service && typeof service.setCorrelationId === 'function') {
          service.setCorrelationId(correlationId);
        }
      });

      SecureLogger.logInfo('Cross-service logging integration configured', {
        correlationId
      });
    }
  }

  /**
   * Setup event correlation system
   */
  setupEventCorrelation() {
    this.eventCorrelation.enabled = true;
    
    // Clean up old events periodically
    setInterval(() => {
      const cutoff = Date.now() - this.config.correlationTimeWindow;
      this.eventCorrelation.recentEvents = this.eventCorrelation.recentEvents.filter(
        event => event.timestamp > cutoff
      );
    }, this.config.correlationTimeWindow);

    SecureLogger.logInfo('Event correlation system configured');
  }

  /**
   * Start services in order
   */
  async startServicesInOrder() {
    const startOrder = [
      'schedulerLogger',
      'realTimeMetrics',
      'dbPerformanceMonitor',
      'performanceAlerting',
      'schedulerMonitoring',
      'schedulerAlerting'
    ];

    for (const serviceName of startOrder) {
      try {
        await this.startService(serviceName);
      } catch (error) {
        SecureLogger.logError(`Failed to start ${serviceName}`, error);
        // Continue with other services
      }
    }
  }

  /**
   * Start individual service
   */
  async startService(serviceName) {
    const service = this.services[serviceName];
    if (!service) {
      return;
    }

    // Check for different start method names
    const startMethods = ['startMonitoring', 'startAlerting', 'startCollection', 'start'];
    
    for (const methodName of startMethods) {
      if (typeof service[methodName] === 'function') {
        await service[methodName]();
        SecureLogger.logInfo(`${serviceName} started successfully`);
        return;
      }
    }

    SecureLogger.logDebug(`${serviceName} does not require starting`);
  }

  /**
   * Stop services in reverse order
   */
  async stopServicesInOrder() {
    const stopOrder = [
      'schedulerAlerting',
      'schedulerMonitoring',
      'performanceAlerting',
      'dbPerformanceMonitor',
      'realTimeMetrics',
      'schedulerLogger'
    ];

    for (const serviceName of stopOrder) {
      try {
        await this.stopService(serviceName);
      } catch (error) {
        SecureLogger.logError(`Failed to stop ${serviceName}`, error);
      }
    }
  }

  /**
   * Stop individual service
   */
  async stopService(serviceName) {
    const service = this.services[serviceName];
    if (!service) {
      return;
    }

    // Check for different stop method names
    const stopMethods = ['stopMonitoring', 'stopAlerting', 'stopCollection', 'stop', 'shutdown'];
    
    for (const methodName of stopMethods) {
      if (typeof service[methodName] === 'function') {
        await service[methodName]();
        SecureLogger.logInfo(`${serviceName} stopped successfully`);
        return;
      }
    }

    SecureLogger.logDebug(`${serviceName} does not require stopping`);
  }

  /**
   * Handle scheduler events and distribute to monitoring services
   */
  handleSchedulerEvent(eventType, data) {
    try {
      this.integrationMetrics.totalEvents++;
      
      // Add to event correlation if enabled
      if (this.eventCorrelation.enabled) {
        this.addToEventCorrelation(eventType, data);
      }

      // Log the event
      if (this.services.schedulerLogger) {
        this.logSchedulerEvent(eventType, data);
      }

      // Emit to integrated event system
      this.emit('scheduler-event', { eventType, data, timestamp: new Date() });

    } catch (error) {
      SecureLogger.logError('Error handling scheduler event', error);
    }
  }

  /**
   * Handle cross-service events
   */
  handleCrossServiceEvent(eventType, data) {
    try {
      this.integrationMetrics.totalEvents++;
      
      // Log cross-service event
      SecureLogger.logDebug('Cross-service event', {
        eventType,
        hasData: !!data,
        timestamp: new Date()
      });

    } catch (error) {
      SecureLogger.logError('Error handling cross-service event', error);
    }
  }

  /**
   * Add event to correlation system
   */
  addToEventCorrelation(eventType, data) {
    const event = {
      type: eventType,
      data,
      timestamp: Date.now(),
      id: `${eventType}_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`
    };

    this.eventCorrelation.recentEvents.push(event);
    
    // Look for correlated events
    this.findCorrelatedEvents(event);
  }

  /**
   * Find and track correlated events
   */
  findCorrelatedEvents(newEvent) {
    const correlationWindow = this.config.correlationTimeWindow;
    const correlatedEvents = [];

    // Look for events within the correlation window
    for (const event of this.eventCorrelation.recentEvents) {
      if (event.id === newEvent.id) continue;
      
      const timeDiff = Math.abs(newEvent.timestamp - event.timestamp);
      if (timeDiff <= correlationWindow) {
        correlatedEvents.push(event);
      }
    }

    if (correlatedEvents.length > 0) {
      this.integrationMetrics.correlatedEvents++;
      
      // Store correlation
      this.eventCorrelation.correlatedEvents.set(newEvent.id, {
        primaryEvent: newEvent,
        correlatedEvents,
        correlationScore: this.calculateCorrelationScore(newEvent, correlatedEvents)
      });

      SecureLogger.logDebug('Event correlation detected', {
        primaryEvent: newEvent.type,
        correlatedCount: correlatedEvents.length,
        timeWindow: correlationWindow
      });
    }
  }

  /**
   * Calculate correlation score between events
   */
  calculateCorrelationScore(primaryEvent, correlatedEvents) {
    let score = 0;

    // Simple scoring based on event types and timing
    for (const event of correlatedEvents) {
      // Same job correlation
      if (primaryEvent.data?.jobId && event.data?.jobId && 
          primaryEvent.data.jobId === event.data.jobId) {
        score += 10;
      }

      // Error following job start
      if (primaryEvent.type === 'job-failed' && event.type === 'job-started') {
        score += 8;
      }

      // Alert following error
      if (primaryEvent.type.includes('alert') && event.type.includes('failed')) {
        score += 6;
      }

      // Time proximity bonus
      const timeDiff = Math.abs(primaryEvent.timestamp - event.timestamp);
      if (timeDiff < 5000) { // Within 5 seconds
        score += 3;
      }
    }

    return score;
  }

  /**
   * Log scheduler events appropriately
   */
  logSchedulerEvent(eventType, data) {
    const logger = this.services.schedulerLogger;
    
    switch (eventType) {
      case 'job-started':
        logger.logJobStarted(data.jobId, data.type, data);
        break;
        
      case 'job-completed':
        logger.logJobCompleted(data.jobId, data.jobType || data.type, data.duration, data.stats);
        break;
        
      case 'job-failed':
        logger.logJobFailed(data.jobId, data.jobType || data.type, new Error(data.error), data.duration);
        break;
        
      default:
        logger.info(`Scheduler event: ${eventType}`, data);
    }
  }

  /**
   * Start health monitoring for integration
   */
  startHealthMonitoring() {
    this.healthCheckTimer = setInterval(() => {
      this.performIntegrationHealthCheck();
    }, this.config.healthCheckInterval);

    SecureLogger.logInfo('Integration health monitoring started');
  }

  /**
   * Stop health monitoring
   */
  stopHealthMonitoring() {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }

  /**
   * Perform comprehensive health check across all services
   */
  performIntegrationHealthCheck() {
    try {
      const healthCheck = {
        timestamp: new Date(),
        integration: {
          isInitialized: this.isInitialized,
          isStarted: this.isStarted,
          servicesCount: this.getActiveServices().length,
          runningServicesCount: this.getRunningServices().length
        },
        services: {}
      };

      // Check each service health
      Object.entries(this.services).forEach(([name, service]) => {
        healthCheck.services[name] = this.checkServiceHealth(service);
      });

      // Update metrics
      this.integrationMetrics.healthChecks++;
      this.integrationMetrics.lastHealthCheck = healthCheck.timestamp;

      // Emit health check event
      this.emit('integration-health-check', healthCheck);

      // Log if any issues detected
      const unhealthyServices = Object.entries(healthCheck.services)
        .filter(([name, health]) => health.status !== 'healthy')
        .map(([name]) => name);

      if (unhealthyServices.length > 0) {
        SecureLogger.logWarning('Integration health check detected issues', {
          unhealthyServices,
          totalServices: Object.keys(healthCheck.services).length
        });
      }

    } catch (error) {
      SecureLogger.logError('Integration health check failed', error);
    }
  }

  /**
   * Check individual service health
   */
  checkServiceHealth(service) {
    if (!service) {
      return { status: 'unavailable', reason: 'Service not available' };
    }

    try {
      // Try various health check methods
      const healthMethods = ['getStatus', 'getMonitoringStatus', 'getAlertingStatus', 'isActive'];
      
      for (const method of healthMethods) {
        if (typeof service[method] === 'function') {
          const status = service[method]();
          return {
            status: this.determineHealthStatus(status),
            data: status,
            lastChecked: new Date()
          };
        }
      }

      // Default health check - just check if service exists
      return {
        status: 'healthy',
        reason: 'Service available',
        lastChecked: new Date()
      };

    } catch (error) {
      return {
        status: 'unhealthy',
        reason: error.message,
        lastChecked: new Date()
      };
    }
  }

  /**
   * Determine health status from service response
   */
  determineHealthStatus(status) {
    if (!status) return 'unknown';
    
    if (typeof status === 'boolean') {
      return status ? 'healthy' : 'unhealthy';
    }
    
    if (typeof status === 'object') {
      if (status.isRunning === false || status.isActive === false || status.isMonitoring === false) {
        return 'unhealthy';
      }
      
      if (status.status === 'healthy' || status.isRunning === true || status.isActive === true) {
        return 'healthy';
      }
    }
    
    return 'unknown';
  }

  /**
   * Start performance optimization
   */
  startPerformanceOptimization() {
    this.optimizationTimer = setInterval(() => {
      this.performOptimization();
    }, this.config.optimizationInterval);

    SecureLogger.logInfo('Performance optimization started');
  }

  /**
   * Stop performance optimization
   */
  stopPerformanceOptimization() {
    if (this.optimizationTimer) {
      clearInterval(this.optimizationTimer);
      this.optimizationTimer = null;
    }
  }

  /**
   * Perform cross-service performance optimization
   */
  performOptimization() {
    try {
      this.integrationMetrics.optimizationRuns++;
      this.integrationMetrics.lastOptimization = new Date();

      // Optimization 1: Memory cleanup across services
      this.optimizeMemoryUsage();

      // Optimization 2: Adjust collection intervals based on load
      this.optimizeCollectionIntervals();

      // Optimization 3: Clean up correlation data
      this.optimizeEventCorrelation();

      SecureLogger.logDebug('Performance optimization completed', {
        optimizationRun: this.integrationMetrics.optimizationRuns
      });

    } catch (error) {
      SecureLogger.logError('Performance optimization failed', error);
    }
  }

  /**
   * Optimize memory usage across services
   */
  optimizeMemoryUsage() {
    // Trigger cleanup in services that support it
    Object.entries(this.services).forEach(([name, service]) => {
      if (service && typeof service.performCleanup === 'function') {
        service.performCleanup();
      }
    });

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  }

  /**
   * Optimize collection intervals based on system load
   */
  optimizeCollectionIntervals() {
    const memUsage = process.memoryUsage();
    const memUsagePercent = memUsage.heapUsed / memUsage.heapTotal;

    // If memory usage is high, reduce collection frequency
    if (memUsagePercent > 0.8) {
      SecureLogger.logDebug('High memory usage detected, optimizing collection intervals');
      // Implementation would adjust intervals dynamically
    }
  }

  /**
   * Optimize event correlation data
   */
  optimizeEventCorrelation() {
    if (!this.eventCorrelation.enabled) return;

    const maxEvents = 1000;
    const maxCorrelations = 500;

    // Limit recent events
    if (this.eventCorrelation.recentEvents.length > maxEvents) {
      this.eventCorrelation.recentEvents = this.eventCorrelation.recentEvents.slice(-maxEvents);
    }

    // Limit correlations
    if (this.eventCorrelation.correlatedEvents.size > maxCorrelations) {
      const oldestEntries = Array.from(this.eventCorrelation.correlatedEvents.entries())
        .sort((a, b) => a[1].primaryEvent.timestamp - b[1].primaryEvent.timestamp)
        .slice(0, this.eventCorrelation.correlatedEvents.size - maxCorrelations);

      oldestEntries.forEach(([key]) => {
        this.eventCorrelation.correlatedEvents.delete(key);
      });
    }
  }

  /**
   * Get list of enabled services
   */
  getEnabledServices() {
    const enabled = [];
    if (this.config.enableMonitoring) enabled.push('schedulerMonitoring');
    if (this.config.enableLogging) enabled.push('schedulerLogger');
    if (this.config.enableAlerting) enabled.push('schedulerAlerting');
    if (this.config.enableRealTimeMetrics) enabled.push('realTimeMetrics');
    if (this.config.enablePerformanceAlerting) enabled.push('performanceAlerting');
    return enabled;
  }

  /**
   * Get list of active services
   */
  getActiveServices() {
    return Object.entries(this.services)
      .filter(([name, service]) => service !== null)
      .map(([name]) => name);
  }

  /**
   * Get list of running services
   */
  getRunningServices() {
    return Object.entries(this.services)
      .filter(([name, service]) => {
        if (!service) return false;
        
        // Check various running indicators
        if (typeof service.isMonitoring === 'boolean') return service.isMonitoring;
        if (typeof service.isActive === 'boolean') return service.isActive;
        if (typeof service.isCollecting === 'boolean') return service.isCollecting;
        if (typeof service.isRunning === 'boolean') return service.isRunning;
        
        return true; // Assume running if no clear indicator
      })
      .map(([name]) => name);
  }

  /**
   * Get integration status
   */
  getIntegrationStatus() {
    return {
      isInitialized: this.isInitialized,
      isStarted: this.isStarted,
      config: {
        enabledServices: this.getEnabledServices(),
        enableEventCorrelation: this.config.enableEventCorrelation,
        enablePerformanceOptimization: this.config.enablePerformanceOptimization
      },
      services: {
        available: this.getActiveServices(),
        running: this.getRunningServices(),
        total: Object.keys(this.services).length
      },
      metrics: this.integrationMetrics,
      eventCorrelation: {
        enabled: this.eventCorrelation.enabled,
        recentEvents: this.eventCorrelation.recentEvents.length,
        correlatedEvents: this.eventCorrelation.correlatedEvents.size
      },
      startupErrors: this.startupErrors
    };
  }

  /**
   * Get comprehensive status of all integrated services
   */
  getComprehensiveStatus() {
    const status = {
      integration: this.getIntegrationStatus(),
      services: {}
    };

    // Get status from each service
    Object.entries(this.services).forEach(([name, service]) => {
      if (service) {
        status.services[name] = this.checkServiceHealth(service);
      } else {
        status.services[name] = { status: 'unavailable' };
      }
    });

    return status;
  }

  /**
   * Export all monitoring data from integrated services
   */
  exportIntegratedData() {
    const exportData = {
      timestamp: new Date(),
      integration: this.getIntegrationStatus(),
      services: {}
    };

    // Export data from each service
    Object.entries(this.services).forEach(([name, service]) => {
      if (service && typeof service.exportData === 'function') {
        try {
          exportData.services[name] = service.exportData();
        } catch (error) {
          exportData.services[name] = { error: error.message };
        }
      } else if (service && typeof service.exportMonitoringData === 'function') {
        try {
          exportData.services[name] = service.exportMonitoringData();
        } catch (error) {
          exportData.services[name] = { error: error.message };
        }
      }
    });

    return exportData;
  }
}

// Make the class an EventEmitter
const EventEmitter = require('events');
Object.setPrototypeOf(SchedulerMonitoringIntegration.prototype, EventEmitter.prototype);

module.exports = SchedulerMonitoringIntegration;