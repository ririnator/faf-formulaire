const EmailMonitoringService = require('../services/emailMonitoringService');
const Contact = require('../models/Contact');
const User = require('../models/User');

// Mock dependencies
jest.mock('../models/Contact');
jest.mock('../models/User');
jest.mock('../utils/secureLogger');

const SecureLogger = require('../utils/secureLogger');

describe('EmailMonitoringService', () => {
  let emailMonitoring;
  
  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Mock SecureLogger
    SecureLogger.logInfo = jest.fn();
    SecureLogger.logError = jest.fn();
    SecureLogger.logWarning = jest.fn();
    
    // Create service instance
    emailMonitoring = new EmailMonitoringService({
      bounceRateThreshold: 5,
      complaintRateThreshold: 0.5,
      deliverabilityThreshold: 95,
      monitoringInterval: 60000, // 1 minute for testing
      alertCooldown: 300000, // 5 minutes for testing
      maxBounceCount: 5
    });
  });

  afterEach(async () => {
    if (emailMonitoring.isRunning) {
      await emailMonitoring.stop();
    }
  });

  describe('Initialization', () => {
    test('should initialize with default configuration', () => {
      const service = new EmailMonitoringService();
      expect(service.config.bounceRateThreshold).toBe(5);
      expect(service.config.complaintRateThreshold).toBe(0.5);
      expect(service.config.deliverabilityThreshold).toBe(95);
    });

    test('should initialize with custom configuration', () => {
      const customConfig = {
        bounceRateThreshold: 3,
        complaintRateThreshold: 0.3,
        deliverabilityThreshold: 98
      };
      
      const service = new EmailMonitoringService(customConfig);
      expect(service.config.bounceRateThreshold).toBe(3);
      expect(service.config.complaintRateThreshold).toBe(0.3);
      expect(service.config.deliverabilityThreshold).toBe(98);
    });

    test('should initialize metrics and alerts', () => {
      expect(emailMonitoring.metrics.totalEmails).toBe(0);
      expect(emailMonitoring.metrics.deliverabilityScore).toBe(100);
      expect(emailMonitoring.alerts.alertsToday).toBe(0);
    });
  });

  describe('Service Lifecycle', () => {
    test('should start monitoring service', async () => {
      // Mock Contact queries
      Contact.countDocuments = jest.fn().mockResolvedValue(0);
      
      await emailMonitoring.start();
      
      expect(emailMonitoring.isRunning).toBe(true);
      expect(emailMonitoring.monitoringTimer).toBeDefined();
      expect(SecureLogger.logInfo).toHaveBeenCalledWith(
        'EmailMonitoringService started',
        expect.any(Object)
      );
    });

    test('should stop monitoring service', async () => {
      // Mock Contact queries
      Contact.countDocuments = jest.fn().mockResolvedValue(0);
      
      await emailMonitoring.start();
      await emailMonitoring.stop();
      
      expect(emailMonitoring.isRunning).toBe(false);
      expect(emailMonitoring.monitoringTimer).toBeNull();
    });

    test('should not start if already running', async () => {
      Contact.countDocuments = jest.fn().mockResolvedValue(0);
      
      await emailMonitoring.start();
      await emailMonitoring.start(); // Second start
      
      expect(SecureLogger.logWarning).toHaveBeenCalledWith(
        'EmailMonitoringService already running'
      );
    });
  });

  describe('Metrics Calculation', () => {
    test('should calculate metrics correctly with sample data', async () => {
      // Mock Contact queries
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(100) // total
        .mockResolvedValueOnce(85)  // delivered
        .mockResolvedValueOnce(10)  // bounced
        .mockResolvedValueOnce(2)   // complained
        .mockResolvedValueOnce(3);  // unsubscribed

      await emailMonitoring.calculateMetrics();

      expect(emailMonitoring.metrics.totalEmails).toBe(100);
      expect(emailMonitoring.metrics.deliveredEmails).toBe(85);
      expect(emailMonitoring.metrics.bouncedEmails).toBe(10);
      expect(emailMonitoring.metrics.complainedEmails).toBe(2);
      expect(emailMonitoring.metrics.unsubscribedEmails).toBe(3);
      expect(emailMonitoring.metrics.bounceRate).toBe(10);
      expect(emailMonitoring.metrics.complaintRate).toBe(2);
      expect(emailMonitoring.metrics.deliveryRate).toBe(85);
      expect(emailMonitoring.metrics.unsubscribeRate).toBe(3);
    });

    test('should handle zero emails gracefully', async () => {
      Contact.countDocuments = jest.fn().mockResolvedValue(0);

      await emailMonitoring.calculateMetrics();

      expect(emailMonitoring.metrics.totalEmails).toBe(0);
      expect(emailMonitoring.metrics.bounceRate).toBe(0);
      expect(emailMonitoring.metrics.complaintRate).toBe(0);
      expect(emailMonitoring.metrics.deliveryRate).toBe(0);
    });

    test('should calculate deliverability score correctly', async () => {
      // Perfect metrics
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(100) // total
        .mockResolvedValueOnce(100) // delivered
        .mockResolvedValueOnce(0)   // bounced
        .mockResolvedValueOnce(0)   // complained
        .mockResolvedValueOnce(0);  // unsubscribed

      await emailMonitoring.calculateMetrics();

      expect(emailMonitoring.metrics.deliverabilityScore).toBe(100);
    });

    test('should penalize high bounce and complaint rates in score', async () => {
      // High bounce and complaint rates
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(100) // total
        .mockResolvedValueOnce(70)  // delivered
        .mockResolvedValueOnce(20)  // bounced
        .mockResolvedValueOnce(10)  // complained
        .mockResolvedValueOnce(0);  // unsubscribed

      await emailMonitoring.calculateMetrics();

      // Deliverability should be significantly penalized
      expect(emailMonitoring.metrics.deliverabilityScore).toBeLessThan(50);
    });
  });

  describe('Reputation Score Calculation', () => {
    test('should calculate perfect reputation score', () => {
      const score = emailMonitoring.calculateReputationScore(0, 0, 100);
      expect(score).toBeGreaterThan(95);
    });

    test('should penalize high bounce rates', () => {
      const score = emailMonitoring.calculateReputationScore(10, 0, 90);
      expect(score).toBeLessThan(80);
    });

    test('should severely penalize complaint rates', () => {
      const score = emailMonitoring.calculateReputationScore(0, 2, 98);
      expect(score).toBeLessThan(50);
    });

    test('should not go below zero', () => {
      const score = emailMonitoring.calculateReputationScore(50, 10, 30);
      expect(score).toBe(0);
    });

    test('should not exceed 100', () => {
      const score = emailMonitoring.calculateReputationScore(0, 0, 99);
      expect(score).toBeLessThanOrEqual(100);
    });
  });

  describe('Alert System', () => {
    test('should trigger bounce rate alert', async () => {
      // Mock high bounce rate
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(100) // total
        .mockResolvedValueOnce(85)  // delivered
        .mockResolvedValueOnce(15)  // bounced (15% > 5% threshold)
        .mockResolvedValueOnce(0)   // complained
        .mockResolvedValueOnce(0);  // unsubscribed

      let alertReceived = null;
      emailMonitoring.on('alert', (alert) => {
        alertReceived = alert;
      });

      await emailMonitoring.calculateMetrics();
      await emailMonitoring.checkAlerts();

      expect(alertReceived).toBeDefined();
      expect(alertReceived.type).toBe('high-bounce-rate');
      expect(alertReceived.data.current).toBe(15);
      expect(alertReceived.data.threshold).toBe(5);
    });

    test('should trigger complaint rate alert', async () => {
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(100) // total
        .mockResolvedValueOnce(98)  // delivered
        .mockResolvedValueOnce(1)   // bounced
        .mockResolvedValueOnce(1)   // complained (1% > 0.5% threshold)
        .mockResolvedValueOnce(0);  // unsubscribed

      let alertReceived = null;
      emailMonitoring.on('alert', (alert) => {
        alertReceived = alert;
      });

      await emailMonitoring.calculateMetrics();
      await emailMonitoring.checkAlerts();

      expect(alertReceived).toBeDefined();
      expect(alertReceived.type).toBe('high-complaint-rate');
      expect(alertReceived.data.current).toBe(1);
      expect(alertReceived.data.threshold).toBe(0.5);
    });

    test('should trigger deliverability alert', async () => {
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(100) // total
        .mockResolvedValueOnce(80)  // delivered (low)
        .mockResolvedValueOnce(15)  // bounced
        .mockResolvedValueOnce(3)   // complained
        .mockResolvedValueOnce(2);  // unsubscribed

      let alertReceived = null;
      emailMonitoring.on('alert', (alert) => {
        alertReceived = alert;
      });

      await emailMonitoring.calculateMetrics();
      await emailMonitoring.checkAlerts();

      expect(alertReceived).toBeDefined();
      expect(alertReceived.type).toBe('low-deliverability');
      expect(alertReceived.data.current).toBeLessThan(95);
    });

    test('should respect alert cooldown', async () => {
      // Set up high bounce rate
      Contact.countDocuments = jest.fn()
        .mockResolvedValue(100)
        .mockResolvedValue(85)
        .mockResolvedValue(15) // High bounce rate
        .mockResolvedValue(0)
        .mockResolvedValue(0);

      let alertCount = 0;
      emailMonitoring.on('alert', () => {
        alertCount++;
      });

      // First alert should fire
      await emailMonitoring.calculateMetrics();
      await emailMonitoring.checkAlerts();
      expect(alertCount).toBe(1);

      // Second alert should be blocked by cooldown
      await emailMonitoring.calculateMetrics();
      await emailMonitoring.checkAlerts();
      expect(alertCount).toBe(1);
    });

    test('should determine correct alert severity', () => {
      const criticalBounce = emailMonitoring.getAlertSeverity('high-bounce-rate', { current: 12 });
      const warningBounce = emailMonitoring.getAlertSeverity('high-bounce-rate', { current: 7 });
      
      expect(criticalBounce).toBe('critical');
      expect(warningBounce).toBe('warning');
    });
  });

  describe('Contact Deliverability Report', () => {
    test('should generate deliverability report', async () => {
      const mockBouncers = [
        { email: 'bouncer1@test.com', bounceCount: 5 },
        { email: 'bouncer2@test.com', bounceCount: 3 }
      ];
      
      const mockComplaints = [
        { email: 'complainer@test.com', lastComplaintAt: new Date() }
      ];
      
      const mockUndeliverable = [
        { email: 'undeliverable@test.com', emailStatus: 'bounced_permanent' }
      ];

      Contact.find = jest.fn()
        .mockImplementationOnce(() => ({
          sort: jest.fn().mockReturnThis(),
          limit: jest.fn().mockReturnThis(),
          select: jest.fn().mockResolvedValue(mockBouncers)
        }))
        .mockImplementationOnce(() => ({
          sort: jest.fn().mockReturnThis(),
          limit: jest.fn().mockReturnThis(),
          select: jest.fn().mockResolvedValue(mockComplaints)
        }))
        .mockImplementationOnce(() => ({
          sort: jest.fn().mockReturnThis(),
          limit: jest.fn().mockReturnThis(),
          select: jest.fn().mockResolvedValue(mockUndeliverable)
        }));

      const report = await emailMonitoring.getContactDeliverabilityReport(50);

      expect(report.topBouncers).toEqual(mockBouncers);
      expect(report.recentComplaints).toEqual(mockComplaints);
      expect(report.undeliverable).toEqual(mockUndeliverable);
      expect(report.summary.totalBouncers).toBe(2);
      expect(report.summary.totalComplaints).toBe(1);
      expect(report.summary.totalUndeliverable).toBe(1);
    });
  });

  describe('Health Score Calculation', () => {
    test('should calculate excellent health score', async () => {
      // Perfect metrics
      emailMonitoring.metrics = {
        deliverabilityScore: 100,
        bounceRate: 0,
        complaintRate: 0
      };
      emailMonitoring.metrics.reputationScore = 100;

      const health = emailMonitoring.calculateHealthScore();

      expect(health.score).toBeGreaterThan(95);
      expect(health.grade).toBe('A+');
    });

    test('should calculate poor health score', async () => {
      // Poor metrics
      emailMonitoring.metrics = {
        deliverabilityScore: 60,
        bounceRate: 15,
        complaintRate: 2
      };
      emailMonitoring.metrics.reputationScore = 50;

      const health = emailMonitoring.calculateHealthScore();

      expect(health.score).toBeLessThan(70);
      expect(['D', 'F']).toContain(health.grade);
    });

    test('should provide correct grade mapping', () => {
      expect(emailMonitoring.getHealthGrade(98)).toBe('A+');
      expect(emailMonitoring.getHealthGrade(92)).toBe('A');
      expect(emailMonitoring.getHealthGrade(87)).toBe('B+');
      expect(emailMonitoring.getHealthGrade(82)).toBe('B');
      expect(emailMonitoring.getHealthGrade(77)).toBe('C+');
      expect(emailMonitoring.getHealthGrade(72)).toBe('C');
      expect(emailMonitoring.getHealthGrade(65)).toBe('D');
      expect(emailMonitoring.getHealthGrade(55)).toBe('F');
    });
  });

  describe('Real-time Metrics Integration', () => {
    test('should track email sent events', () => {
      const mockRealTimeMetrics = {
        on: jest.fn(),
        emit: jest.fn()
      };

      emailMonitoring.setRealTimeMetrics(mockRealTimeMetrics);
      emailMonitoring.trackEmailSent('invitation', 150);

      expect(mockRealTimeMetrics.emit).toHaveBeenCalledWith('email-sent', {
        type: 'invitation',
        duration: 150,
        timestamp: expect.any(Date)
      });
    });

    test('should track email failed events', () => {
      const mockRealTimeMetrics = {
        on: jest.fn(),
        emit: jest.fn()
      };

      const error = new Error('Send failed');
      emailMonitoring.setRealTimeMetrics(mockRealTimeMetrics);
      emailMonitoring.trackEmailFailed('reminder', error);

      expect(mockRealTimeMetrics.emit).toHaveBeenCalledWith('email-failed', {
        type: 'reminder',
        error: 'Send failed',
        timestamp: expect.any(Date)
      });
    });
  });

  describe('Status and Utilities', () => {
    test('should provide complete status', () => {
      const status = emailMonitoring.getStatus();

      expect(status).toHaveProperty('isRunning');
      expect(status).toHaveProperty('metrics');
      expect(status).toHaveProperty('alerts');
      expect(status).toHaveProperty('config');
      expect(status).toHaveProperty('lastMonitoringCycle');
    });

    test('should reset alerts', () => {
      emailMonitoring.alerts.alertsToday = 5;
      emailMonitoring.alerts.lastBounceAlert = Date.now();

      emailMonitoring.resetAlerts();

      expect(emailMonitoring.alerts.alertsToday).toBe(0);
      expect(emailMonitoring.alerts.lastBounceAlert).toBeNull();
    });

    test('should force metrics recalculation', async () => {
      Contact.countDocuments = jest.fn().mockResolvedValue(50);

      const metrics = await emailMonitoring.recalculateMetrics();

      expect(Contact.countDocuments).toHaveBeenCalled();
      expect(metrics.totalEmails).toBe(50);
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors in metrics calculation', async () => {
      Contact.countDocuments = jest.fn().mockRejectedValue(new Error('Database error'));

      await expect(emailMonitoring.calculateMetrics()).rejects.toThrow('Database error');
      expect(SecureLogger.logError).toHaveBeenCalled();
    });

    test('should handle errors in monitoring cycle gracefully', async () => {
      Contact.countDocuments = jest.fn().mockRejectedValue(new Error('Connection failed'));

      // Should not throw, just log
      await expect(emailMonitoring.runMonitoringCycle()).rejects.toThrow('Connection failed');
      expect(SecureLogger.logError).toHaveBeenCalledWith(
        'Monitoring cycle error',
        expect.objectContaining({
          error: 'Connection failed'
        })
      );
    });

    test('should handle deliverability report errors', async () => {
      Contact.find = jest.fn().mockImplementation(() => {
        throw new Error('Query failed');
      });

      await expect(emailMonitoring.getContactDeliverabilityReport()).rejects.toThrow('Query failed');
      expect(SecureLogger.logError).toHaveBeenCalled();
    });
  });

  describe('Performance Tests', () => {
    test('should complete monitoring cycle within reasonable time', async () => {
      Contact.countDocuments = jest.fn().mockResolvedValue(0);

      const startTime = Date.now();
      await emailMonitoring.runMonitoringCycle();
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(1000); // Should complete within 1 second
    });

    test('should handle large datasets efficiently', async () => {
      // Mock large dataset
      Contact.countDocuments = jest.fn()
        .mockResolvedValue(100000); // 100k emails

      const startTime = Date.now();
      await emailMonitoring.calculateMetrics();
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(500); // Should be fast with proper indexing
    });
  });
});

describe('EmailMonitoringService Integration Tests', () => {
  let emailMonitoring;

  beforeEach(() => {
    emailMonitoring = new EmailMonitoringService({
      monitoringInterval: 100, // Very short for testing
      alertCooldown: 50
    });
  });

  afterEach(async () => {
    if (emailMonitoring.isRunning) {
      await emailMonitoring.stop();
    }
  });

  test('should run complete monitoring cycle automatically', async () => {
    Contact.countDocuments = jest.fn().mockResolvedValue(0);

    let cycleCompleted = false;
    emailMonitoring.on('monitoring-cycle-completed', () => {
      cycleCompleted = true;
    });

    await emailMonitoring.start();

    // Wait for at least one cycle
    await new Promise(resolve => setTimeout(resolve, 200));

    expect(cycleCompleted).toBe(true);
  });

  test('should emit events during monitoring lifecycle', async () => {
    Contact.countDocuments = jest.fn().mockResolvedValue(0);

    const events = [];
    emailMonitoring.on('monitoring-started', () => events.push('started'));
    emailMonitoring.on('monitoring-cycle-completed', () => events.push('cycle'));
    emailMonitoring.on('monitoring-stopped', () => events.push('stopped'));

    await emailMonitoring.start();
    await new Promise(resolve => setTimeout(resolve, 150));
    await emailMonitoring.stop();

    expect(events).toContain('started');
    expect(events).toContain('cycle');
    expect(events).toContain('stopped');
  });
});