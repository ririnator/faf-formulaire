const SchedulerMonitoringService = require('./schedulerMonitoringService');
const SchedulerLogger = require('./schedulerLogger');
const SchedulerAlerting = require('./schedulerAlerting');
const SchedulerMonitoringIntegration = require('./schedulerMonitoringIntegration');
const RealTimeMetrics = require('./realTimeMetrics');
const PerformanceAlerting = require('./performanceAlerting');
const SecureLogger = require('../utils/secureLogger');

/**
 * Scheduler Monitoring Factory
 * 
 * Factory service for creating and managing the complete scheduler monitoring ecosystem
 * Provides a unified interface for initializing, configuring, and managing all monitoring services
 * 
 * Features:
 * - Centralized service creation and configuration
 * - Dependency injection and resolution
 * - Environment-specific configuration
 * - Error handling and fallback strategies
 * - Service lifecycle management
 * - Integration orchestration
 */
class SchedulerMonitoringFactory {
  constructor(config = {}) {
    this.config = {
      // Environment settings
      environment: config.environment || process.env.NODE_ENV || 'development',
      
      // Service configurations
      monitoring: {
        metricsRetentionHours: config.monitoring?.metricsRetentionHours || 72,
        executionHistoryLimit: config.monitoring?.executionHistoryLimit || 1000,
        errorHistoryLimit: config.monitoring?.errorHistoryLimit || 500,
        metricsCollectionInterval: config.monitoring?.metricsCollectionInterval || 30000,
        healthCheckInterval: config.monitoring?.healthCheckInterval || 60000,
        alertCheckInterval: config.monitoring?.alertCheckInterval || 120000,
        trackDetailedMetrics: config.monitoring?.trackDetailedMetrics !== false,
        enableErrorAnalysis: config.monitoring?.enableErrorAnalysis !== false,
        alertThresholds: {
          jobFailureRate: config.monitoring?.alertThresholds?.jobFailureRate || 0.05,
          avgJobDuration: config.monitoring?.alertThresholds?.avgJobDuration || 3600000,
          memoryUsagePercent: config.monitoring?.alertThresholds?.memoryUsagePercent || 0.85,
          consecutiveFailures: config.monitoring?.alertThresholds?.consecutiveFailures || 3,
          stuckJobDuration: config.monitoring?.alertThresholds?.stuckJobDuration || 7200000,
          errorSpikeRate: config.monitoring?.alertThresholds?.errorSpikeRate || 10,
          ...config.monitoring?.alertThresholds
        },
        ...config.monitoring
      },
      
      logging: {
        logLevel: config.logging?.logLevel || (this.isProduction() ? 'info' : 'debug'),
        logDir: config.logging?.logDir || './logs/scheduler',
        maxSize: config.logging?.maxSize || '100m',
        maxFiles: config.logging?.maxFiles || '30d',
        enableConsoleOutput: config.logging?.enableConsoleOutput !== false,
        enableFileOutput: config.logging?.enableFileOutput !== false,
        enableJsonFormat: config.logging?.enableJsonFormat !== false,
        enableSensitiveDataFiltering: config.logging?.enableSensitiveDataFiltering !== false,
        maxLogEntrySize: config.logging?.maxLogEntrySize || 10000,
        ...config.logging
      },
      
      alerting: {
        enableAlerting: config.alerting?.enableAlerting !== false,
        alertThrottleWindow: config.alerting?.alertThrottleWindow || 5 * 60 * 1000,
        maxAlertsPerHour: config.alerting?.maxAlertsPerHour || 20,
        escalationTimeouts: {
          low: config.alerting?.escalationTimeouts?.low || 30 * 60 * 1000,
          medium: config.alerting?.escalationTimeouts?.medium || 15 * 60 * 1000,
          high: config.alerting?.escalationTimeouts?.high || 5 * 60 * 1000,
          critical: config.alerting?.escalationTimeouts?.critical || 2 * 60 * 1000,
          ...config.alerting?.escalationTimeouts
        },
        enableConsoleAlerts: config.alerting?.enableConsoleAlerts !== false,
        enableEmailAlerts: config.alerting?.enableEmailAlerts || false,
        enableWebhookAlerts: config.alerting?.enableWebhookAlerts || false,
        enableSlackAlerts: config.alerting?.enableSlackAlerts || false,
        enableAutoRemediation: config.alerting?.enableAutoRemediation || false,
        emailRecipients: config.alerting?.emailRecipients || [],
        webhookUrls: config.alerting?.webhookUrls || [],
        slackWebhookUrl: config.alerting?.slackWebhookUrl || null,
        ...config.alerting
      },
      
      integration: {
        enableEventCorrelation: config.integration?.enableEventCorrelation !== false,
        enablePerformanceOptimization: config.integration?.enablePerformanceOptimization !== false,
        correlationTimeWindow: config.integration?.correlationTimeWindow || 60000,
        optimizationInterval: config.integration?.optimizationInterval || 300000,
        startupTimeout: config.integration?.startupTimeout || 30000,
        shutdownTimeout: config.integration?.shutdownTimeout || 15000,
        ...config.integration
      },
      
      realTimeMetrics: {
        windowSize: config.realTimeMetrics?.windowSize || 5 * 60 * 1000,
        updateInterval: config.realTimeMetrics?.updateInterval || 10 * 1000,
        retainWindows: config.realTimeMetrics?.retainWindows || 720,
        alertThresholds: {
          slowQueryRate: config.realTimeMetrics?.alertThresholds?.slowQueryRate || 0.2,
          avgExecutionTime: config.realTimeMetrics?.alertThresholds?.avgExecutionTime || 200,
          queryVolume: config.realTimeMetrics?.alertThresholds?.queryVolume || 1000,
          indexEfficiency: config.realTimeMetrics?.alertThresholds?.indexEfficiency || 0.7,
          ...config.realTimeMetrics?.alertThresholds
        },
        ...config.realTimeMetrics
      },
      
      performanceAlerting: {
        maxAlerts: config.performanceAlerting?.maxAlerts || 1000,
        notificationCooldown: config.performanceAlerting?.notificationCooldown || 5 * 60 * 1000,
        enableEmailAlerts: config.performanceAlerting?.enableEmailAlerts || false,
        enableWebhooks: config.performanceAlerting?.enableWebhooks || false,
        autoRemediation: config.performanceAlerting?.autoRemediation || false,
        ...config.performanceAlerting
      },
      
      // Feature flags
      features: {
        enableMonitoring: config.features?.enableMonitoring !== false,
        enableLogging: config.features?.enableLogging !== false,
        enableAlerting: config.features?.enableAlerting !== false,
        enableRealTimeMetrics: config.features?.enableRealTimeMetrics !== false,
        enablePerformanceAlerting: config.features?.enablePerformanceAlerting !== false,
        enableIntegration: config.features?.enableIntegration !== false,
        ...config.features
      },
      
      ...config
    };

    // Service instances
    this.services = {
      monitoring: null,
      logger: null,
      alerting: null,
      realTimeMetrics: null,
      performanceAlerting: null,
      integration: null
    };

    // Factory state
    this.isInitialized = false;
    this.isStarted = false;
    this.initializationErrors = [];
    this.dependencies = new Map();

    SecureLogger.logInfo('SchedulerMonitoringFactory initialized', {
      environment: this.config.environment,
      enabledFeatures: Object.entries(this.config.features)
        .filter(([key, value]) => value === true)
        .map(([key]) => key)
    });
  }

  /**
   * Create and initialize the complete monitoring ecosystem
   */
  async createMonitoringEcosystem(externalDependencies = {}) {
    try {
      SecureLogger.logInfo('Creating scheduler monitoring ecosystem');
      
      // Store external dependencies
      this.storeDependencies(externalDependencies);
      
      // Create services in dependency order
      await this.createServices();
      
      // Create integration layer
      if (this.config.features.enableIntegration) {
        await this.createIntegration();
      }
      
      // Initialize all services
      await this.initializeServices();
      
      this.isInitialized = true;
      
      SecureLogger.logInfo('Scheduler monitoring ecosystem created successfully', {
        servicesCreated: Object.values(this.services).filter(s => s !== null).length,
        initializationErrors: this.initializationErrors.length
      });
      
      return {
        success: true,
        services: this.services,
        errors: this.initializationErrors
      };
      
    } catch (error) {
      SecureLogger.logError('Failed to create monitoring ecosystem', error);
      this.initializationErrors.push(error.message);
      throw error;
    }
  }

  /**
   * Start the monitoring ecosystem
   */
  async startMonitoringEcosystem() {
    if (!this.isInitialized) {
      throw new Error('Monitoring ecosystem must be created before starting');
    }

    try {
      SecureLogger.logInfo('Starting scheduler monitoring ecosystem');
      
      // Start integration layer first (if available)
      if (this.services.integration) {
        await this.services.integration.start();
      } else {
        // Start services individually
        await this.startServicesIndividually();
      }
      
      this.isStarted = true;
      
      SecureLogger.logInfo('Scheduler monitoring ecosystem started successfully');
      
      return {
        success: true,
        servicesStarted: Object.values(this.services).filter(s => s !== null).length
      };
      
    } catch (error) {
      SecureLogger.logError('Failed to start monitoring ecosystem', error);
      throw error;
    }
  }

  /**
   * Stop the monitoring ecosystem
   */
  async stopMonitoringEcosystem() {
    if (!this.isStarted) {
      return;
    }

    try {
      SecureLogger.logInfo('Stopping scheduler monitoring ecosystem');
      
      // Stop integration layer (which handles all services)
      if (this.services.integration) {
        await this.services.integration.stop();
      } else {
        // Stop services individually
        await this.stopServicesIndividually();
      }
      
      this.isStarted = false;
      
      SecureLogger.logInfo('Scheduler monitoring ecosystem stopped successfully');
      
    } catch (error) {
      SecureLogger.logError('Error stopping monitoring ecosystem', error);
      throw error;
    }
  }

  /**
   * Store external dependencies
   */
  storeDependencies(externalDependencies) {
    this.dependencies.set('schedulerService', externalDependencies.schedulerService);
    this.dependencies.set('emailService', externalDependencies.emailService);
    this.dependencies.set('dbPerformanceMonitor', externalDependencies.dbPerformanceMonitor);
    
    // Validate required dependencies
    if (!this.dependencies.get('schedulerService')) {
      throw new Error('SchedulerService is required for monitoring ecosystem');
    }
  }

  /**
   * Create all monitoring services
   */
  async createServices() {
    // Create services in dependency order
    if (this.config.features.enableLogging) {
      await this.createLogger();
    }
    
    if (this.config.features.enableRealTimeMetrics) {
      await this.createRealTimeMetrics();
    }
    
    if (this.config.features.enablePerformanceAlerting) {
      await this.createPerformanceAlerting();
    }
    
    if (this.config.features.enableMonitoring) {
      await this.createMonitoring();
    }
    
    if (this.config.features.enableAlerting) {
      await this.createAlerting();
    }
  }

  /**
   * Create logger service
   */
  async createLogger() {
    try {
      SecureLogger.logInfo('Creating SchedulerLogger');
      
      this.services.logger = new SchedulerLogger(this.config.logging);
      
      SecureLogger.logInfo('SchedulerLogger created successfully');
      
    } catch (error) {
      SecureLogger.logError('Failed to create SchedulerLogger', error);
      this.initializationErrors.push(`SchedulerLogger: ${error.message}`);
      
      if (!this.isProduction()) {
        throw error; // Fail fast in development
      }
    }
  }

  /**
   * Create real-time metrics service
   */
  async createRealTimeMetrics() {
    try {
      SecureLogger.logInfo('Creating RealTimeMetrics');
      
      const dbMonitor = this.dependencies.get('dbPerformanceMonitor');
      if (!dbMonitor) {
        SecureLogger.logWarning('DBPerformanceMonitor not available, RealTimeMetrics will be limited');
      }
      
      this.services.realTimeMetrics = new RealTimeMetrics(dbMonitor, this.config.realTimeMetrics);
      
      SecureLogger.logInfo('RealTimeMetrics created successfully');
      
    } catch (error) {
      SecureLogger.logError('Failed to create RealTimeMetrics', error);
      this.initializationErrors.push(`RealTimeMetrics: ${error.message}`);
      
      // RealTimeMetrics is optional
      this.services.realTimeMetrics = null;
    }
  }

  /**
   * Create performance alerting service
   */
  async createPerformanceAlerting() {
    try {
      SecureLogger.logInfo('Creating PerformanceAlerting');
      
      this.services.performanceAlerting = new PerformanceAlerting(
        this.services.realTimeMetrics,
        this.config.performanceAlerting
      );
      
      SecureLogger.logInfo('PerformanceAlerting created successfully');
      
    } catch (error) {
      SecureLogger.logError('Failed to create PerformanceAlerting', error);
      this.initializationErrors.push(`PerformanceAlerting: ${error.message}`);
      
      // PerformanceAlerting is optional
      this.services.performanceAlerting = null;
    }
  }

  /**
   * Create monitoring service
   */
  async createMonitoring() {
    try {
      SecureLogger.logInfo('Creating SchedulerMonitoringService');
      
      this.services.monitoring = new SchedulerMonitoringService(this.config.monitoring);
      
      SecureLogger.logInfo('SchedulerMonitoringService created successfully');
      
    } catch (error) {
      SecureLogger.logError('Failed to create SchedulerMonitoringService', error);
      this.initializationErrors.push(`SchedulerMonitoringService: ${error.message}`);
      throw error; // Monitoring is critical
    }
  }

  /**
   * Create alerting service
   */
  async createAlerting() {
    try {
      SecureLogger.logInfo('Creating SchedulerAlerting');
      
      this.services.alerting = new SchedulerAlerting(this.config.alerting);
      
      SecureLogger.logInfo('SchedulerAlerting created successfully');
      
    } catch (error) {
      SecureLogger.logError('Failed to create SchedulerAlerting', error);
      this.initializationErrors.push(`SchedulerAlerting: ${error.message}`);
      
      // Alerting is important but not critical
      this.services.alerting = null;
    }
  }

  /**
   * Create integration layer
   */
  async createIntegration() {
    try {
      SecureLogger.logInfo('Creating SchedulerMonitoringIntegration');
      
      this.services.integration = new SchedulerMonitoringIntegration(this.config.integration);
      
      SecureLogger.logInfo('SchedulerMonitoringIntegration created successfully');
      
    } catch (error) {
      SecureLogger.logError('Failed to create SchedulerMonitoringIntegration', error);
      this.initializationErrors.push(`SchedulerMonitoringIntegration: ${error.message}`);
      
      // Integration is optional but recommended
      this.services.integration = null;
    }
  }

  /**
   * Initialize all created services
   */
  async initializeServices() {
    if (this.services.integration) {
      // Use integration layer to initialize all services
      await this.initializeWithIntegration();
    } else {
      // Initialize services individually
      await this.initializeServicesIndividually();
    }
  }

  /**
   * Initialize services through integration layer
   */
  async initializeWithIntegration() {
    try {
      const integrationServices = {
        schedulerService: this.dependencies.get('schedulerService'),
        schedulerMonitoring: this.services.monitoring,
        schedulerLogger: this.services.logger,
        schedulerAlerting: this.services.alerting,
        realTimeMetrics: this.services.realTimeMetrics,
        performanceAlerting: this.services.performanceAlerting,
        dbPerformanceMonitor: this.dependencies.get('dbPerformanceMonitor'),
        emailService: this.dependencies.get('emailService')
      };

      await this.services.integration.initialize(integrationServices);
      
      SecureLogger.logInfo('Services initialized through integration layer');
      
    } catch (error) {
      SecureLogger.logError('Failed to initialize services through integration', error);
      
      // Fallback to individual initialization
      await this.initializeServicesIndividually();
    }
  }

  /**
   * Initialize services individually
   */
  async initializeServicesIndividually() {
    const initOrder = [
      { service: 'realTimeMetrics', dependencies: ['dbPerformanceMonitor'] },
      { service: 'performanceAlerting', dependencies: ['realTimeMetrics'] },
      { service: 'monitoring', dependencies: ['schedulerService', 'realTimeMetrics', 'performanceAlerting'] },
      { service: 'alerting', dependencies: ['schedulerLogger', 'monitoring', 'emailService'] }
    ];

    for (const { service, dependencies } of initOrder) {
      try {
        await this.initializeService(service, dependencies);
      } catch (error) {
        SecureLogger.logError(`Failed to initialize ${service}`, error);
        this.initializationErrors.push(`${service}: ${error.message}`);
        
        // Continue with other services unless critical
        if (service === 'monitoring') {
          throw error;
        }
      }
    }
  }

  /**
   * Initialize individual service
   */
  async initializeService(serviceName, dependencyNames) {
    const service = this.services[serviceName];
    if (!service || typeof service.initialize !== 'function') {
      return;
    }

    // Build dependencies
    const dependencies = {};
    for (const depName of dependencyNames) {
      const dependency = this.dependencies.get(depName) || this.services[depName];
      if (dependency) {
        dependencies[depName] = dependency;
      }
    }

    await service.initialize(dependencies);
    SecureLogger.logInfo(`${serviceName} initialized successfully`);
  }

  /**
   * Start services individually (fallback when no integration)
   */
  async startServicesIndividually() {
    const startOrder = ['logger', 'realTimeMetrics', 'performanceAlerting', 'monitoring', 'alerting'];

    for (const serviceName of startOrder) {
      try {
        await this.startService(serviceName);
      } catch (error) {
        SecureLogger.logError(`Failed to start ${serviceName}`, error);
      }
    }
  }

  /**
   * Start individual service
   */
  async startService(serviceName) {
    const service = this.services[serviceName];
    if (!service) return;

    const startMethods = ['startMonitoring', 'startAlerting', 'startCollection', 'start'];
    
    for (const method of startMethods) {
      if (typeof service[method] === 'function') {
        await service[method]();
        SecureLogger.logInfo(`${serviceName} started successfully`);
        return;
      }
    }
  }

  /**
   * Stop services individually (fallback when no integration)
   */
  async stopServicesIndividually() {
    const stopOrder = ['alerting', 'monitoring', 'performanceAlerting', 'realTimeMetrics', 'logger'];

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
    if (!service) return;

    const stopMethods = ['stopMonitoring', 'stopAlerting', 'stopCollection', 'stop', 'shutdown'];
    
    for (const method of stopMethods) {
      if (typeof service[method] === 'function') {
        await service[method]();
        SecureLogger.logInfo(`${serviceName} stopped successfully`);
        return;
      }
    }
  }

  /**
   * Get service instances
   */
  getServices() {
    return {
      monitoring: this.services.monitoring,
      logger: this.services.logger,
      alerting: this.services.alerting,
      realTimeMetrics: this.services.realTimeMetrics,
      performanceAlerting: this.services.performanceAlerting,
      integration: this.services.integration
    };
  }

  /**
   * Get factory status
   */
  getFactoryStatus() {
    return {
      isInitialized: this.isInitialized,
      isStarted: this.isStarted,
      environment: this.config.environment,
      features: this.config.features,
      services: {
        created: Object.entries(this.services)
          .filter(([name, service]) => service !== null)
          .map(([name]) => name),
        total: Object.keys(this.services).length
      },
      initializationErrors: this.initializationErrors,
      dependencies: Array.from(this.dependencies.keys())
    };
  }

  /**
   * Create environment-specific configuration
   */
  static createEnvironmentConfig(environment = process.env.NODE_ENV) {
    const baseConfig = {
      environment,
      features: {
        enableMonitoring: true,
        enableLogging: true,
        enableAlerting: true,
        enableRealTimeMetrics: true,
        enablePerformanceAlerting: true,
        enableIntegration: true
      }
    };

    switch (environment) {
      case 'production':
        return {
          ...baseConfig,
          logging: {
            logLevel: 'info',
            enableConsoleOutput: false,
            enableFileOutput: true,
            maxFiles: '90d',
            enableSensitiveDataFiltering: true
          },
          alerting: {
            enableEmailAlerts: true,
            enableWebhookAlerts: true,
            enableAutoRemediation: true,
            escalationTimeouts: {
              critical: 60000, // 1 minute in production
              high: 300000     // 5 minutes in production
            }
          },
          monitoring: {
            metricsRetentionHours: 168, // 7 days in production
            trackDetailedMetrics: false // Reduce overhead
          }
        };

      case 'development':
        return {
          ...baseConfig,
          logging: {
            logLevel: 'debug',
            enableConsoleOutput: true,
            enableFileOutput: false,
            enableSensitiveDataFiltering: false
          },
          alerting: {
            enableEmailAlerts: false,
            enableWebhookAlerts: false,
            enableAutoRemediation: false,
            escalationTimeouts: {
              critical: 30000, // 30 seconds in development
              high: 60000      // 1 minute in development
            }
          },
          monitoring: {
            metricsRetentionHours: 24, // 1 day in development
            trackDetailedMetrics: true
          }
        };

      case 'test':
        return {
          ...baseConfig,
          logging: {
            logLevel: 'error',
            enableConsoleOutput: false,
            enableFileOutput: false
          },
          alerting: {
            enableAlerting: false,
            enableEmailAlerts: false,
            enableWebhookAlerts: false
          },
          monitoring: {
            metricsRetentionHours: 1,
            metricsCollectionInterval: 1000,
            healthCheckInterval: 5000
          },
          features: {
            ...baseConfig.features,
            enableAlerting: false // Disable in tests
          }
        };

      default:
        return baseConfig;
    }
  }

  /**
   * Utility methods
   */
  isProduction() {
    return this.config.environment === 'production';
  }

  isDevelopment() {
    return this.config.environment === 'development';
  }

  isTest() {
    return this.config.environment === 'test';
  }

  /**
   * Create factory with environment-specific defaults
   */
  static createForEnvironment(environment, overrides = {}) {
    const envConfig = SchedulerMonitoringFactory.createEnvironmentConfig(environment);
    const finalConfig = this.mergeDeep(envConfig, overrides);
    
    return new SchedulerMonitoringFactory(finalConfig);
  }

  /**
   * Deep merge configuration objects
   */
  static mergeDeep(target, source) {
    const output = { ...target };
    
    if (this.isObject(target) && this.isObject(source)) {
      Object.keys(source).forEach(key => {
        if (this.isObject(source[key])) {
          if (!(key in target)) {
            Object.assign(output, { [key]: source[key] });
          } else {
            output[key] = this.mergeDeep(target[key], source[key]);
          }
        } else {
          Object.assign(output, { [key]: source[key] });
        }
      });
    }
    
    return output;
  }

  /**
   * Check if value is an object
   */
  static isObject(item) {
    return item && typeof item === 'object' && !Array.isArray(item);
  }
}

module.exports = SchedulerMonitoringFactory;