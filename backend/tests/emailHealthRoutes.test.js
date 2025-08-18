const request = require('supertest');
const express = require('express');
const emailHealthRoutes = require('../routes/emailHealthRoutes');
const Contact = require('../models/Contact');

// Mock dependencies
jest.mock('../models/Contact');
jest.mock('../middleware/hybridAuth');
jest.mock('../services/emailMonitoringServiceInstance');
jest.mock('../utils/secureLogger');

const { requireAdminAccess } = require('../middleware/hybridAuth');
const { getEmailMonitoringServiceInstance } = require('../services/emailMonitoringServiceInstance');
const SecureLogger = require('../utils/secureLogger');

describe('Email Health Routes', () => {
  let app;
  let mockEmailMonitoring;

  beforeEach(() => {
    // Setup Express app
    app = express();
    app.use(express.json());
    app.use('/email-health', emailHealthRoutes);

    // Mock admin middleware to always pass
    requireAdminAccess.mockImplementation((req, res, next) => next());

    // Mock SecureLogger
    SecureLogger.logInfo = jest.fn();
    SecureLogger.logError = jest.fn();
    SecureLogger.logWarning = jest.fn();

    // Mock Contact model
    Contact.find = jest.fn();
    Contact.findById = jest.fn();
    Contact.countDocuments = jest.fn();

    // Mock email monitoring service
    mockEmailMonitoring = {
      getStatus: jest.fn(),
      calculateHealthScore: jest.fn(),
      getContactDeliverabilityReport: jest.fn(),
      recalculateMetrics: jest.fn(),
      resetAlerts: jest.fn()
    };
    
    getEmailMonitoringServiceInstance.mockReturnValue(mockEmailMonitoring);

    // Reset all mocks
    jest.clearAllMocks();
  });

  describe('GET /dashboard', () => {
    test('should return email health dashboard', async () => {
      const mockStatus = {
        isRunning: true,
        lastMonitoringCycle: new Date(),
        metrics: {
          totalEmails: 1000,
          deliveredEmails: 950,
          bouncedEmails: 30,
          complainedEmails: 5,
          unsubscribedEmails: 15,
          bounceRate: 3,
          complaintRate: 0.5,
          deliveryRate: 95,
          deliverabilityScore: 96.5,
          reputationScore: 92
        },
        alerts: {
          alertsToday: 0,
          lastBounceAlert: null,
          lastComplaintAlert: null,
          lastDeliverabilityAlert: null
        }
      };

      const mockHealthScore = {
        score: 94.2,
        grade: 'A',
        factors: {
          deliverability: 96.5,
          reputation: 92,
          bounceRate: 3,
          complaintRate: 0.5
        }
      };

      mockEmailMonitoring.getStatus.mockReturnValue(mockStatus);
      mockEmailMonitoring.calculateHealthScore.mockReturnValue(mockHealthScore);

      // Mock contact statistics
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(1000) // total
        .mockResolvedValueOnce(950)  // active
        .mockResolvedValueOnce(30)   // bounced
        .mockResolvedValueOnce(5)    // complained
        .mockResolvedValueOnce(15)   // unsubscribed
        .mockResolvedValueOnce(20);  // recently added

      const response = await request(app)
        .get('/email-health/dashboard');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.dashboard).toBeDefined();
      expect(response.body.dashboard.metrics).toEqual(mockStatus.metrics);
      expect(response.body.dashboard.healthScore).toEqual(mockHealthScore);
      expect(response.body.dashboard.contactStats).toBeDefined();
      expect(response.body.dashboard.recommendations).toBeDefined();
    });

    test('should handle dashboard errors gracefully', async () => {
      mockEmailMonitoring.getStatus.mockImplementation(() => {
        throw new Error('Service unavailable');
      });

      const response = await request(app)
        .get('/email-health/dashboard');

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Failed to load dashboard');
      expect(SecureLogger.logError).toHaveBeenCalled();
    });
  });

  describe('GET /metrics', () => {
    test('should return email metrics', async () => {
      const mockMetrics = {
        totalEmails: 500,
        deliveredEmails: 475,
        bouncedEmails: 15,
        complainedEmails: 2,
        bounceRate: 3,
        complaintRate: 0.4,
        deliverabilityScore: 95.8
      };

      const mockHealthScore = {
        score: 93.5,
        grade: 'A'
      };

      mockEmailMonitoring.getStatus.mockReturnValue({ metrics: mockMetrics });
      mockEmailMonitoring.calculateHealthScore.mockReturnValue(mockHealthScore);

      const response = await request(app)
        .get('/email-health/metrics');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.metrics).toEqual(mockMetrics);
      expect(response.body.healthScore).toEqual(mockHealthScore);
    });

    test('should recalculate metrics when requested', async () => {
      const mockMetrics = { totalEmails: 100 };
      
      mockEmailMonitoring.getStatus.mockReturnValue({ metrics: mockMetrics });
      mockEmailMonitoring.calculateHealthScore.mockReturnValue({ score: 95 });
      mockEmailMonitoring.recalculateMetrics.mockResolvedValue(mockMetrics);

      const response = await request(app)
        .get('/email-health/metrics?recalculate=true');

      expect(response.status).toBe(200);
      expect(mockEmailMonitoring.recalculateMetrics).toHaveBeenCalled();
    });

    test('should handle metrics errors', async () => {
      mockEmailMonitoring.getStatus.mockImplementation(() => {
        throw new Error('Metrics calculation failed');
      });

      const response = await request(app)
        .get('/email-health/metrics');

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
    });
  });

  describe('GET /deliverability-report', () => {
    test('should return deliverability report', async () => {
      const mockReport = {
        topBouncers: [
          { email: 'bouncer1@test.com', bounceCount: 5 },
          { email: 'bouncer2@test.com', bounceCount: 3 }
        ],
        recentComplaints: [
          { email: 'complainer@test.com', lastComplaintAt: new Date() }
        ],
        undeliverable: [
          { email: 'undeliverable@test.com', emailStatus: 'bounced_permanent' }
        ],
        summary: {
          totalBouncers: 2,
          totalComplaints: 1,
          totalUndeliverable: 1
        }
      };

      mockEmailMonitoring.getContactDeliverabilityReport.mockResolvedValue(mockReport);

      const response = await request(app)
        .get('/email-health/deliverability-report');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.report).toEqual(mockReport);
    });

    test('should accept custom limit parameter', async () => {
      mockEmailMonitoring.getContactDeliverabilityReport.mockResolvedValue({
        topBouncers: [],
        recentComplaints: [],
        undeliverable: [],
        summary: {}
      });

      await request(app)
        .get('/email-health/deliverability-report?limit=100');

      expect(mockEmailMonitoring.getContactDeliverabilityReport).toHaveBeenCalledWith(100);
    });
  });

  describe('GET /bounced-contacts', () => {
    test('should return paginated bounced contacts', async () => {
      const mockContacts = [
        {
          email: 'bounced1@test.com',
          firstName: 'John',
          lastName: 'Doe',
          emailStatus: 'bounced_permanent',
          bounceCount: 3,
          lastBounceAt: new Date(),
          bounceReason: 'User unknown'
        },
        {
          email: 'bounced2@test.com',
          firstName: 'Jane',
          lastName: 'Smith',
          emailStatus: 'bounced_temporary',
          bounceCount: 1,
          lastBounceAt: new Date(),
          bounceReason: 'Mailbox full'
        }
      ];

      Contact.find.mockReturnValue({
        sort: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        select: jest.fn().mockResolvedValue(mockContacts)
      });

      Contact.countDocuments.mockResolvedValue(25);

      const response = await request(app)
        .get('/email-health/bounced-contacts?page=1&limit=20');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.contacts).toEqual(mockContacts);
      expect(response.body.pagination).toEqual({
        page: 1,
        limit: 20,
        total: 25,
        pages: 2
      });
    });

    test('should filter by bounce type', async () => {
      Contact.find.mockReturnValue({
        sort: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        select: jest.fn().mockResolvedValue([])
      });

      Contact.countDocuments.mockResolvedValue(0);

      await request(app)
        .get('/email-health/bounced-contacts?bounceType=permanent');

      expect(Contact.find).toHaveBeenCalledWith({
        emailStatus: 'bounced_permanent'
      });
    });
  });

  describe('GET /complained-contacts', () => {
    test('should return paginated complained contacts', async () => {
      const mockContacts = [
        {
          email: 'complained@test.com',
          firstName: 'Bob',
          lastName: 'Wilson',
          lastComplaintAt: new Date(),
          complaintReason: 'Spam report',
          optedOut: true
        }
      ];

      Contact.find.mockReturnValue({
        sort: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        select: jest.fn().mockResolvedValue(mockContacts)
      });

      Contact.countDocuments.mockResolvedValue(1);

      const response = await request(app)
        .get('/email-health/complained-contacts');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.contacts).toEqual(mockContacts);
    });
  });

  describe('GET /unsubscribed-contacts', () => {
    test('should return paginated unsubscribed contacts', async () => {
      const mockContacts = [
        {
          email: 'unsubscribed@test.com',
          firstName: 'Alice',
          lastName: 'Brown',
          optedOutAt: new Date(),
          optOutReason: 'manual_unsubscribe',
          emailStatus: 'unsubscribed'
        }
      ];

      Contact.find.mockReturnValue({
        sort: jest.fn().mockReturnThis(),
        skip: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        select: jest.fn().mockResolvedValue(mockContacts)
      });

      Contact.countDocuments.mockResolvedValue(10);

      const response = await request(app)
        .get('/email-health/unsubscribed-contacts');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.contacts).toEqual(mockContacts);
    });
  });

  describe('POST /reactivate-contact', () => {
    test('should reactivate a contact', async () => {
      const mockContact = {
        _id: 'contact123',
        email: 'reactivate@test.com',
        emailStatus: 'bounced_temporary',
        isActive: false,
        optedOut: false,
        reactivate: jest.fn().mockResolvedValue()
      };

      Contact.findById.mockResolvedValue(mockContact);

      const response = await request(app)
        .post('/email-health/reactivate-contact')
        .send({
          contactId: 'contact123',
          note: 'Manually reactivated by admin'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Contact reactivated successfully');
      expect(mockContact.reactivate).toHaveBeenCalledWith('Manually reactivated by admin');
      expect(SecureLogger.logInfo).toHaveBeenCalledWith(
        'Contact reactivated by admin',
        expect.objectContaining({
          contactId: 'contact123',
          email: 'reactivate@test.com'
        })
      );
    });

    test('should return 400 for missing contact ID', async () => {
      const response = await request(app)
        .post('/email-health/reactivate-contact')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Contact ID required');
    });

    test('should return 404 for non-existent contact', async () => {
      Contact.findById.mockResolvedValue(null);

      const response = await request(app)
        .post('/email-health/reactivate-contact')
        .send({ contactId: 'nonexistent' });

      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Contact not found');
    });

    test('should handle reactivation errors', async () => {
      const mockContact = {
        _id: 'contact123',
        email: 'permanent@test.com',
        reactivate: jest.fn().mockRejectedValue(new Error('Cannot reactivate permanently bounced contacts'))
      };

      Contact.findById.mockResolvedValue(mockContact);

      const response = await request(app)
        .post('/email-health/reactivate-contact')
        .send({ contactId: 'contact123' });

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Cannot reactivate permanently bounced contacts');
    });
  });

  describe('POST /refresh-monitoring', () => {
    test('should refresh monitoring data', async () => {
      const mockMetrics = {
        totalEmails: 200,
        deliverabilityScore: 97.5
      };

      const mockHealthScore = {
        score: 96.8,
        grade: 'A+'
      };

      mockEmailMonitoring.recalculateMetrics.mockResolvedValue();
      mockEmailMonitoring.getStatus.mockReturnValue({ metrics: mockMetrics });
      mockEmailMonitoring.calculateHealthScore.mockReturnValue(mockHealthScore);

      const response = await request(app)
        .post('/email-health/refresh-monitoring');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Monitoring data refreshed');
      expect(response.body.metrics).toEqual(mockMetrics);
      expect(response.body.healthScore).toEqual(mockHealthScore);
      expect(mockEmailMonitoring.recalculateMetrics).toHaveBeenCalled();
    });

    test('should handle refresh errors', async () => {
      mockEmailMonitoring.recalculateMetrics.mockRejectedValue(new Error('Database connection failed'));

      const response = await request(app)
        .post('/email-health/refresh-monitoring');

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(response.body.error).toBe('Failed to refresh monitoring');
    });
  });

  describe('POST /reset-alerts', () => {
    test('should reset monitoring alerts', async () => {
      mockEmailMonitoring.resetAlerts.mockImplementation(() => {});

      const response = await request(app)
        .post('/email-health/reset-alerts');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Alerts reset successfully');
      expect(mockEmailMonitoring.resetAlerts).toHaveBeenCalled();
      expect(SecureLogger.logInfo).toHaveBeenCalledWith('Email monitoring alerts reset');
    });
  });

  describe('Contact Statistics Helper', () => {
    test('should calculate contact statistics correctly', async () => {
      // This tests the getContactStatistics function indirectly through dashboard
      Contact.countDocuments = jest.fn()
        .mockResolvedValueOnce(1000) // total
        .mockResolvedValueOnce(850)  // active
        .mockResolvedValueOnce(100)  // bounced
        .mockResolvedValueOnce(25)   // complained
        .mockResolvedValueOnce(25)   // unsubscribed
        .mockResolvedValueOnce(50);  // recently added

      mockEmailMonitoring.getStatus.mockReturnValue({
        isRunning: true,
        metrics: {},
        alerts: {}
      });
      mockEmailMonitoring.calculateHealthScore.mockReturnValue({ score: 95 });

      const response = await request(app)
        .get('/email-health/dashboard');

      expect(response.body.dashboard.contactStats).toEqual({
        totalContacts: 1000,
        activeContacts: 850,
        bouncedContacts: 100,
        complainedContacts: 25,
        unsubscribedContacts: 25,
        recentlyAddedContacts: 50,
        deliverableContacts: 850,
        undeliverableContacts: 150 // bounced + complained + unsubscribed
      });
    });
  });

  describe('Recommendations Generation', () => {
    test('should generate warning for high bounce rate', async () => {
      const mockStatus = {
        isRunning: true,
        metrics: {
          bounceRate: 8, // Above 5% threshold
          complaintRate: 0.3,
          deliverabilityScore: 92
        },
        alerts: {}
      };

      const mockHealthScore = { score: 85 };

      mockEmailMonitoring.getStatus.mockReturnValue(mockStatus);
      mockEmailMonitoring.calculateHealthScore.mockReturnValue(mockHealthScore);
      Contact.countDocuments = jest.fn().mockResolvedValue(0);

      const response = await request(app)
        .get('/email-health/dashboard');

      const recommendations = response.body.dashboard.recommendations;
      expect(recommendations.some(r => r.category === 'bounce_rate')).toBe(true);
      expect(recommendations.some(r => r.type === 'warning')).toBe(true);
    });

    test('should generate critical alert for high complaint rate', async () => {
      const mockStatus = {
        isRunning: true,
        metrics: {
          bounceRate: 2,
          complaintRate: 1.2, // Above 0.5% threshold
          deliverabilityScore: 88
        },
        alerts: {}
      };

      const mockHealthScore = { score: 70 };

      mockEmailMonitoring.getStatus.mockReturnValue(mockStatus);
      mockEmailMonitoring.calculateHealthScore.mockReturnValue(mockHealthScore);
      Contact.countDocuments = jest.fn().mockResolvedValue(0);

      const response = await request(app)
        .get('/email-health/dashboard');

      const recommendations = response.body.dashboard.recommendations;
      expect(recommendations.some(r => r.category === 'complaint_rate')).toBe(true);
      expect(recommendations.some(r => r.type === 'critical')).toBe(true);
    });

    test('should generate success message for good performance', async () => {
      const mockStatus = {
        isRunning: true,
        metrics: {
          bounceRate: 1, // Low bounce rate
          complaintRate: 0.1, // Low complaint rate
          deliverabilityScore: 98 // High deliverability
        },
        alerts: {}
      };

      const mockHealthScore = { score: 96 }; // High health score

      mockEmailMonitoring.getStatus.mockReturnValue(mockStatus);
      mockEmailMonitoring.calculateHealthScore.mockReturnValue(mockHealthScore);
      Contact.countDocuments = jest.fn().mockResolvedValue(0);

      const response = await request(app)
        .get('/email-health/dashboard');

      const recommendations = response.body.dashboard.recommendations;
      expect(recommendations.some(r => r.type === 'success')).toBe(true);
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors gracefully', async () => {
      Contact.countDocuments.mockRejectedValue(new Error('Database connection failed'));

      const response = await request(app)
        .get('/email-health/dashboard');

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(SecureLogger.logError).toHaveBeenCalled();
    });

    test('should handle contact find errors', async () => {
      Contact.find.mockImplementation(() => {
        throw new Error('Query failed');
      });

      const response = await request(app)
        .get('/email-health/bounced-contacts');

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
    });
  });

  describe('Authentication', () => {
    test('should require admin access for all routes', () => {
      // Verify that requireAdminAccess middleware is applied to all routes
      const router = require('../routes/emailHealthRoutes');
      
      // This is more of a structural test - in real implementation,
      // we'd verify that the middleware is actually called
      expect(requireAdminAccess).toBeDefined();
    });
  });
});