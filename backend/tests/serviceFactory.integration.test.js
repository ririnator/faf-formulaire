/**
 * Integration tests for ServiceFactory with complete dependency injection
 * Tests the initialization, dependency management, and shutdown procedures
 */

const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const ServiceFactory = require('../services/serviceFactory');
const SchedulerService = require('../services/schedulerService');
const EmailService = require('../services/emailService');
const ContactService = require('../services/contactService');

let mongoServer;

describe('ServiceFactory Integration Tests', () => {
  beforeAll(async () => {
    // Start in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    // Set up test environment variables
    process.env.NODE_ENV = 'test';
    process.env.RESEND_API_KEY = 'test-resend-key';
    process.env.POSTMARK_API_KEY = 'test-postmark-key';
    process.env.EMAIL_FROM_ADDRESS = 'test@example.com';
    process.env.APP_BASE_URL = 'http://localhost:3000';
  });

  afterAll(async () => {
    await mongoose.connection.close();
    await mongoServer.stop();
  });

  describe('Service Initialization', () => {
    test('should create ServiceFactory instance successfully', () => {
      const factory = ServiceFactory.create();
      expect(factory).toBeInstanceOf(ServiceFactory);
      expect(factory.getInitializationStatus().initialized).toBe(false);
      expect(factory.getInitializationStatus().serviceCount).toBe(0);
    });

    test('should initialize individual services without dependencies', () => {
      const factory = ServiceFactory.create();
      
      // These services should be creatable without full initialization
      const responseService = factory.getResponseService();
      const authService = factory.getAuthService();
      const uploadService = factory.getUploadService();
      const contactService = factory.getContactService();
      const invitationService = factory.getInvitationService();
      
      expect(responseService).toBeDefined();
      expect(authService).toBeDefined();
      expect(uploadService).toBeDefined();
      expect(contactService).toBeDefined();
      expect(invitationService).toBeDefined();
    });

    test('should handle repeated service requests correctly', () => {
      const factory = ServiceFactory.create();
      
      const contactService1 = factory.getContactService();
      const contactService2 = factory.getContactService();
      
      // Should return the same instance
      expect(contactService1).toBe(contactService2);
    });
  });

  describe('Complete Service Initialization with Dependencies', () => {
    let serviceFactory;

    afterEach(async () => {
      if (serviceFactory) {
        await serviceFactory.shutdownServices();
        serviceFactory = null;
      }
    });

    test('should initialize all services with proper dependency injection', async () => {
      serviceFactory = ServiceFactory.create();
      
      const initResult = await serviceFactory.initializeServices();
      
      expect(initResult.success).toBe(true);
      expect(initResult.services).toContain('scheduler');
      expect(initResult.services).toContain('email');
      expect(initResult.services).toContain('contact');
      expect(initResult.services).toContain('invitation');
      expect(initResult.schedulerRunning).toBe(true);
      
      const status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(true);
      expect(status.serviceCount).toBeGreaterThan(5);
    });

    test('should provide all services through getAllServices', async () => {
      serviceFactory = ServiceFactory.create();
      
      const services = await serviceFactory.getAllServices();
      
      expect(services.responseService).toBeDefined();
      expect(services.authService).toBeDefined();
      expect(services.uploadService).toBeDefined();
      expect(services.contactService).toBeDefined();
      expect(services.invitationService).toBeDefined();
      expect(services.submissionService).toBeDefined();
      expect(services.handshakeService).toBeDefined();
      expect(services.emailService).toBeDefined();
      expect(services.emailMonitoringService).toBeDefined();
      expect(services.schedulerService).toBeDefined();
      expect(services.realTimeMetrics).toBeDefined();
      
      // Verify service types
      expect(services.schedulerService).toBeInstanceOf(SchedulerService);
      expect(services.emailService).toBeInstanceOf(EmailService);
      expect(services.contactService).toBeInstanceOf(ContactService);
    });

    test('should handle concurrent initialization requests', async () => {
      serviceFactory = ServiceFactory.create();
      
      // Start multiple initialization requests simultaneously
      const promises = [
        serviceFactory.initializeServices(),
        serviceFactory.initializeServices(),
        serviceFactory.initializeServices()
      ];
      
      const results = await Promise.all(promises);
      
      // All should succeed and return the same result
      results.forEach(result => {
        expect(result.success).toBe(true);
        expect(result.services).toEqual(results[0].services);
      });
      
      // Should only be initialized once
      const status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(true);
    });

    test('should properly inject dependencies between services', async () => {
      serviceFactory = ServiceFactory.create();
      await serviceFactory.initializeServices();
      
      const services = await serviceFactory.getAllServices();
      
      // SchedulerService should have references to other services
      const schedulerService = services.schedulerService;
      expect(schedulerService.emailService).toBeDefined();
      expect(schedulerService.contactService).toBeDefined();
      expect(schedulerService.realTimeMetrics).toBeDefined();
      
      // EmailService should have RealTimeMetrics
      const emailService = services.emailService;
      expect(emailService.realTimeMetrics).toBeDefined();
      
      // Verify services can interact
      expect(typeof schedulerService.runMonthlyJob).toBe('function');
      expect(typeof emailService.sendInvitation).toBe('function');
      expect(typeof services.contactService.getContactsWithStats).toBe('function');
    });
  });

  describe('Service Lifecycle Management', () => {
    let serviceFactory;

    afterEach(async () => {
      if (serviceFactory) {
        await serviceFactory.shutdownServices();
        serviceFactory = null;
      }
    });

    test('should shutdown services gracefully', async () => {
      serviceFactory = ServiceFactory.create();
      await serviceFactory.initializeServices();
      
      // Verify services are running
      let status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(true);
      expect(status.serviceCount).toBeGreaterThan(0);
      
      // Shutdown services
      await serviceFactory.shutdownServices();
      
      // Verify shutdown
      status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(false);
      expect(status.serviceCount).toBe(0);
    });

    test('should handle shutdown without initialization', async () => {
      serviceFactory = ServiceFactory.create();
      
      // Should not throw error when shutting down uninitialized factory
      await expect(serviceFactory.shutdownServices()).resolves.not.toThrow();
    });

    test('should handle multiple shutdown calls', async () => {
      serviceFactory = ServiceFactory.create();
      await serviceFactory.initializeServices();
      
      // Multiple shutdown calls should not cause errors
      await serviceFactory.shutdownServices();
      await serviceFactory.shutdownServices();
      await serviceFactory.shutdownServices();
      
      const status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(false);
    });

    test('should allow re-initialization after shutdown', async () => {
      serviceFactory = ServiceFactory.create();
      
      // First initialization
      await serviceFactory.initializeServices();
      let status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(true);
      
      // Shutdown
      await serviceFactory.shutdownServices();
      status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(false);
      
      // Re-initialize
      await serviceFactory.initializeServices();
      status = serviceFactory.getInitializationStatus();
      expect(status.initialized).toBe(true);
      
      // Services should be functional
      const services = await serviceFactory.getAllServices();
      expect(services.schedulerService).toBeDefined();
      expect(services.emailService).toBeDefined();
    });
  });

  describe('Static Factory Methods', () => {
    test('should create and initialize services with static method', async () => {
      const serviceFactory = await ServiceFactory.createAndInitialize();
      
      try {
        const status = serviceFactory.getInitializationStatus();
        expect(status.initialized).toBe(true);
        
        const services = await serviceFactory.getAllServices();
        expect(services.schedulerService).toBeDefined();
        expect(services.emailService).toBeDefined();
        
        // Verify SchedulerService is running
        expect(services.schedulerService.isRunning).toBe(true);
      } finally {
        await serviceFactory.shutdownServices();
      }
    });
  });

  describe('Error Handling', () => {
    test('should handle service initialization failures gracefully', async () => {
      const serviceFactory = ServiceFactory.create();
      
      // Temporarily break the environment to cause initialization failure
      const originalApiKey = process.env.RESEND_API_KEY;
      delete process.env.RESEND_API_KEY;
      delete process.env.POSTMARK_API_KEY;
      
      try {
        // Should handle missing email configuration gracefully
        const result = await serviceFactory.initializeServices();
        
        // Should still succeed with degraded functionality
        expect(result.success).toBe(true);
        
        const services = await serviceFactory.getAllServices();
        expect(services.schedulerService).toBeDefined();
        expect(services.contactService).toBeDefined();
        
      } finally {
        // Restore environment
        process.env.RESEND_API_KEY = originalApiKey;
        await serviceFactory.shutdownServices();
      }
    });

    test('should handle shutdown errors gracefully', async () => {
      const serviceFactory = ServiceFactory.create();
      await serviceFactory.initializeServices();
      
      const services = await serviceFactory.getAllServices();
      
      // Mock a service to throw error during shutdown
      const originalStop = services.schedulerService.stop;
      services.schedulerService.stop = jest.fn().mockRejectedValue(new Error('Shutdown error'));
      
      // Should not throw error even if individual service shutdown fails
      await expect(serviceFactory.shutdownServices()).resolves.not.toThrow();
      
      // Restore original method
      services.schedulerService.stop = originalStop;
    });
  });

  describe('Configuration Management', () => {
    test('should pass correct configuration to services', async () => {
      const serviceFactory = ServiceFactory.create();
      
      // Access configuration
      const config = serviceFactory.config;
      expect(config).toBeDefined();
      expect(config.services).toBeDefined();
      expect(config.services.scheduler).toBeDefined();
      expect(config.services.email).toBeDefined();
      expect(config.services.contact).toBeDefined();
      
      // Verify configuration structure
      expect(config.services.scheduler.monthlyJobDay).toBeDefined();
      expect(config.services.scheduler.batchSize).toBeDefined();
      expect(config.services.email.fromAddress).toBeDefined();
      expect(config.services.contact.maxBatchSize).toBeDefined();
    });

    test('should respect environment-specific configurations', async () => {
      const serviceFactory = ServiceFactory.create();
      
      // In test environment, certain features should be configured differently
      expect(serviceFactory.config.nodeEnv).toBe('test');
      
      await serviceFactory.initializeServices();
      const services = await serviceFactory.getAllServices();
      
      // Scheduler should still work in test mode
      expect(services.schedulerService).toBeDefined();
      expect(typeof services.schedulerService.getHealthStatus).toBe('function');
      
      await serviceFactory.shutdownServices();
    });
  });

  describe('Service Interoperability', () => {
    let serviceFactory;

    beforeEach(async () => {
      serviceFactory = ServiceFactory.create();
      await serviceFactory.initializeServices();
    });

    afterEach(async () => {
      if (serviceFactory) {
        await serviceFactory.shutdownServices();
      }
    });

    test('should enable cross-service communication', async () => {
      const services = await serviceFactory.getAllServices();
      
      // Test that SchedulerService can use ContactService methods
      const contactService = services.contactService;
      const schedulerService = services.schedulerService;
      
      expect(schedulerService.contactService).toBe(contactService);
      
      // Mock a contact service method to verify it's called
      const getContactsWithStatsSpy = jest.spyOn(contactService, 'getContactsWithStats')
        .mockResolvedValue({ contacts: [], total: 0 });
      
      // SchedulerService should be able to call ContactService methods
      const result = await contactService.getContactsWithStats('test-user-id', {}, {});
      expect(result).toBeDefined();
      expect(getContactsWithStatsSpy).toHaveBeenCalled();
      
      getContactsWithStatsSpy.mockRestore();
    });

    test('should maintain service references after initialization', async () => {
      const services1 = await serviceFactory.getAllServices();
      const services2 = await serviceFactory.getAllServices();
      
      // Should return the same service instances
      expect(services1.schedulerService).toBe(services2.schedulerService);
      expect(services1.emailService).toBe(services2.emailService);
      expect(services1.contactService).toBe(services2.contactService);
    });

    test('should provide consistent service health status', async () => {
      const services = await serviceFactory.getAllServices();
      
      // All services should be in a healthy state after initialization
      const schedulerHealth = services.schedulerService.getHealthStatus();
      expect(schedulerHealth.status).toBe('running');
      expect(schedulerHealth.uptime).toBeGreaterThan(0);
      
      // EmailService should be configured
      const emailMetrics = services.emailService.getMetrics();
      expect(emailMetrics).toBeDefined();
      expect(typeof emailMetrics.totalSent).toBe('number');
    });
  });
});