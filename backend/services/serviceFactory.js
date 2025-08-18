const EnvironmentConfig = require('../config/environment');
const ResponseService = require('./responseService');
const AuthService = require('./authService');
const UploadService = require('./uploadService');
const ContactService = require('./contactService');
const InvitationService = require('./invitationService');
const SubmissionService = require('./submissionService');
const HandshakeService = require('./handshakeService');
const NotificationService = require('./notificationService');
const EmailService = require('./emailService');
const EmailMonitoringService = require('./emailMonitoringService');
const SchedulerService = require('./schedulerService');
const RealTimeMetrics = require('./realTimeMetrics');
const SecureLogger = require('../utils/secureLogger');
const cloudinary = require('../config/cloudinary');

class ServiceFactory {
  constructor() {
    this.config = EnvironmentConfig.getConfig();
    this._services = new Map();
    this._initialized = false;
    this._initializationPromise = null;
  }

  getResponseService() {
    if (!this._services.has('response')) {
      this._services.set('response', ResponseService);
    }
    return this._services.get('response');
  }

  getAuthService() {
    if (!this._services.has('auth')) {
      this._services.set('auth', AuthService);
    }
    return this._services.get('auth');
  }

  getUploadService() {
    if (!this._services.has('upload')) {
      this._services.set('upload', UploadService);
    }
    return this._services.get('upload');
  }

  getContactService() {
    if (!this._services.has('contact')) {
      const service = new ContactService(this.config.services.contact);
      this._services.set('contact', service);
    }
    return this._services.get('contact');
  }

  getInvitationService() {
    if (!this._services.has('invitation')) {
      const service = new InvitationService(this.config.services.invitation);
      this._services.set('invitation', service);
    }
    return this._services.get('invitation');
  }

  getSubmissionService() {
    if (!this._services.has('submission')) {
      const service = new SubmissionService(this.config.services.submission);
      this._services.set('submission', service);
    }
    return this._services.get('submission');
  }

  getHandshakeService() {
    if (!this._services.has('handshake')) {
      const service = new HandshakeService(this.config.services.handshake);
      this._services.set('handshake', service);
    }
    return this._services.get('handshake');
  }

  getNotificationService() {
    if (!this._services.has('notification')) {
      const service = new NotificationService(this.config.services.notification || {});
      this._services.set('notification', service);
    }
    return this._services.get('notification');
  }

  getEmailService() {
    if (!this._services.has('email')) {
      const service = new EmailService(this.config.services.email);
      this._services.set('email', service);
    }
    return this._services.get('email');
  }

  getEmailMonitoringService() {
    if (!this._services.has('emailMonitoring')) {
      const emailMonitoringConfig = {
        bounceRateThreshold: parseFloat(process.env.EMAIL_BOUNCE_RATE_THRESHOLD) || 5,
        complaintRateThreshold: parseFloat(process.env.EMAIL_COMPLAINT_RATE_THRESHOLD) || 0.5,
        deliverabilityThreshold: parseFloat(process.env.EMAIL_DELIVERABILITY_THRESHOLD) || 95,
        monitoringInterval: parseInt(process.env.EMAIL_MONITORING_INTERVAL) || 300000,
        alertCooldown: parseInt(process.env.EMAIL_ALERT_COOLDOWN) || 1800000,
        maxBounceCount: parseInt(process.env.EMAIL_MAX_BOUNCE_COUNT) || 5,
        reputationWindow: parseInt(process.env.EMAIL_REPUTATION_WINDOW) || 86400000
      };
      
      const service = new EmailMonitoringService(emailMonitoringConfig);
      this._services.set('emailMonitoring', service);
    }
    return this._services.get('emailMonitoring');
  }

  getRealTimeMetrics() {
    if (!this._services.has('realTimeMetrics')) {
      const service = new RealTimeMetrics({
        retentionHours: this.config.services.scheduler?.metricsRetentionHours || 72,
        alertThresholds: this.config.services.scheduler?.alertThresholds || {}
      });
      this._services.set('realTimeMetrics', service);
    }
    return this._services.get('realTimeMetrics');
  }

  getSchedulerService() {
    if (!this._services.has('scheduler')) {
      const service = new SchedulerService(this.config.services.scheduler);
      this._services.set('scheduler', service);
    }
    return this._services.get('scheduler');
  }

  /**
   * Initialize all services with proper dependency injection
   * Must be called before using any services that depend on others
   */
  async initializeServices() {
    if (this._initialized) {
      return this._initializationPromise;
    }

    if (this._initializationPromise) {
      return this._initializationPromise;
    }

    this._initializationPromise = this._doInitialization();
    return this._initializationPromise;
  }

  async _doInitialization() {
    try {
      SecureLogger.logInfo('Starting service initialization with dependency injection');

      // Phase 1: Initialize core services (no dependencies)
      const realTimeMetrics = this.getRealTimeMetrics();
      const contactService = this.getContactService();
      const invitationService = this.getInvitationService();
      const submissionService = this.getSubmissionService();
      const handshakeService = this.getHandshakeService();

      // Phase 2: Initialize EmailService and inject RealTimeMetrics
      const emailService = this.getEmailService();
      emailService.setRealTimeMetrics(realTimeMetrics);

      // Phase 3: Initialize EmailMonitoringService with EmailService dependency
      const emailMonitoringService = this.getEmailMonitoringService();
      if (emailMonitoringService.setEmailService) {
        emailMonitoringService.setEmailService(emailService);
      }

      // Phase 4: Initialize SchedulerService with all dependencies
      const schedulerService = this.getSchedulerService();
      await schedulerService.initialize({
        invitationService,
        contactService,
        emailService,
        realTimeMetrics,
        submissionService,
        handshakeService
      });

      // Phase 5: Start SchedulerService
      await schedulerService.start();

      this._initialized = true;
      
      SecureLogger.logInfo('All services initialized successfully with dependency injection', {
        services: Array.from(this._services.keys()),
        schedulerRunning: schedulerService.isRunning
      });

      return {
        success: true,
        services: Array.from(this._services.keys()),
        schedulerRunning: schedulerService.isRunning
      };

    } catch (error) {
      SecureLogger.logError('Failed to initialize services', error);
      throw error;
    }
  }

  /**
   * Get all services in their initialized state
   */
  async getAllServices() {
    if (!this._initialized) {
      await this.initializeServices();
    }

    return {
      responseService: this.getResponseService(),
      authService: this.getAuthService(),
      uploadService: this.getUploadService(),
      contactService: this.getContactService(),
      invitationService: this.getInvitationService(),
      submissionService: this.getSubmissionService(),
      handshakeService: this.getHandshakeService(),
      notificationService: this.getNotificationService(),
      emailService: this.getEmailService(),
      emailMonitoringService: this.getEmailMonitoringService(),
      schedulerService: this.getSchedulerService(),
      realTimeMetrics: this.getRealTimeMetrics()
    };
  }

  /**
   * Shutdown all services gracefully
   */
  async shutdownServices() {
    try {
      SecureLogger.logInfo('Starting graceful service shutdown');

      // Stop SchedulerService first (it depends on other services)
      if (this._services.has('scheduler')) {
        const schedulerService = this._services.get('scheduler');
        if (schedulerService.isRunning) {
          await schedulerService.stop();
        }
      }

      // Shutdown EmailService
      if (this._services.has('email')) {
        const emailService = this._services.get('email');
        if (emailService.shutdown) {
          await emailService.shutdown();
        }
      }

      // Shutdown EmailMonitoringService
      if (this._services.has('emailMonitoring')) {
        const emailMonitoringService = this._services.get('emailMonitoring');
        if (emailMonitoringService.shutdown) {
          await emailMonitoringService.shutdown();
        }
      }

      // Clear all services
      this._services.clear();
      this._initialized = false;
      this._initializationPromise = null;

      SecureLogger.logInfo('All services shutdown successfully');

    } catch (error) {
      SecureLogger.logError('Error during service shutdown', error);
      throw error;
    }
  }

  /**
   * Get service initialization status
   */
  getInitializationStatus() {
    return {
      initialized: this._initialized,
      initializing: !!this._initializationPromise && !this._initialized,
      serviceCount: this._services.size,
      services: Array.from(this._services.keys())
    };
  }

  // Factory method pour créer tous les services avec la config
  static create() {
    return new ServiceFactory();
  }

  /**
   * Static method to create and initialize all services
   */
  static async createAndInitialize() {
    const factory = new ServiceFactory();
    await factory.initializeServices();
    return factory;
  }
}

module.exports = ServiceFactory;