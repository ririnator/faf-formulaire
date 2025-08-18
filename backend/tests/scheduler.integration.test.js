/**
 * Comprehensive integration tests for SchedulerService with EmailService and ContactService
 * Tests the complete automated monthly cycle workflow
 */

const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const SchedulerService = require('../services/schedulerService');
const EmailService = require('../services/emailService');
const ContactService = require('../services/contactService');
const ServiceFactory = require('../services/serviceFactory');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Invitation = require('../models/Invitation');
const RealTimeMetrics = require('../services/realTimeMetrics');

let mongoServer;
let schedulerService;
let emailService;
let contactService;
let serviceFactory;
let realTimeMetrics;

describe('SchedulerService Integration Tests', () => {
  beforeAll(async () => {
    // Start in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    // Set up environment variables for testing
    process.env.RESEND_API_KEY = 'test-key';
    process.env.EMAIL_FROM_ADDRESS = 'test@example.com';
    process.env.APP_BASE_URL = 'http://localhost:3000';
  });

  beforeEach(async () => {
    // Clear all collections
    await User.deleteMany({});
    await Contact.deleteMany({});
    await Invitation.deleteMany({});

    // Initialize services with test configuration
    serviceFactory = ServiceFactory.create();
    await serviceFactory.initializeServices();
    
    const services = await serviceFactory.getAllServices();
    schedulerService = services.schedulerService;
    emailService = services.emailService;
    contactService = services.contactService;
    realTimeMetrics = services.realTimeMetrics;
  });

  afterEach(async () => {
    if (serviceFactory) {
      await serviceFactory.shutdownServices();
    }
  });

  afterAll(async () => {
    await mongoose.connection.close();
    await mongoServer.stop();
  });

  describe('Complete Monthly Cycle Integration', () => {
    test('should process complete monthly cycle for active users with contacts', async () => {
      // Create test users
      const user1 = await User.create({
        username: 'testuser1',
        email: 'user1@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: 5,
          sendTime: '18:00',
          timezone: 'Europe/Paris',
          reminderSettings: {
            firstReminder: true,
            secondReminder: true
          }
        },
        statistics: {
          totalContacts: 0,
          totalSubmissions: 0
        }
      });

      const user2 = await User.create({
        username: 'testuser2',
        email: 'user2@example.com', 
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: 5,
          sendTime: '18:00',
          timezone: 'Europe/Paris'
        },
        statistics: {
          totalContacts: 0,
          totalSubmissions: 0
        }
      });

      // Create test contacts
      const contact1 = await Contact.create({
        ownerId: user1._id,
        email: 'contact1@example.com',
        firstName: 'John',
        lastName: 'Doe',
        isActive: true,
        status: 'active',
        tracking: {
          responseRate: 85,
          invitationsSent: 5,
          responsesReceived: 4
        }
      });

      const contact2 = await Contact.create({
        ownerId: user1._id,
        email: 'contact2@example.com',
        firstName: 'Jane',
        lastName: 'Smith',
        isActive: true,
        status: 'active',
        tracking: {
          responseRate: 90,
          invitationsSent: 3,
          responsesReceived: 3
        }
      });

      const contact3 = await Contact.create({
        ownerId: user2._id,
        email: 'contact3@example.com',
        firstName: 'Bob',
        lastName: 'Johnson',
        isActive: true,
        status: 'active',
        tracking: {
          responseRate: 75,
          invitationsSent: 2,
          responsesReceived: 1
        }
      });

      // Mock EmailService methods for testing
      const emailSendSpy = jest.spyOn(emailService, 'sendInvitation').mockResolvedValue({
        success: true,
        messageId: 'test-message-id'
      });

      // Execute monthly job
      const month = '2025-08';
      const result = await schedulerService.runMonthlyJob(month);

      // Verify job results
      expect(result.success).toBe(true);
      expect(result.processed).toBe(2); // 2 active users
      expect(result.sent).toBe(3); // 3 total contacts
      expect(result.failed).toBe(0);

      // Verify invitations were created
      const invitations = await Invitation.find({ month });
      expect(invitations).toHaveLength(3);

      // Verify invitation details
      const user1Invitations = invitations.filter(inv => inv.fromUserId.toString() === user1._id.toString());
      expect(user1Invitations).toHaveLength(2);
      expect(user1Invitations.map(inv => inv.toEmail).sort()).toEqual(['contact1@example.com', 'contact2@example.com']);

      const user2Invitations = invitations.filter(inv => inv.fromUserId.toString() === user2._id.toString());
      expect(user2Invitations).toHaveLength(1);
      expect(user2Invitations[0].toEmail).toBe('contact3@example.com');

      // Verify email service was called correctly
      expect(emailSendSpy).toHaveBeenCalledTimes(3);

      // Verify invitations are marked as sent
      for (const invitation of invitations) {
        expect(invitation.status).toBe('sent');
        expect(invitation.tracking.sentAt).toBeDefined();
      }

      // Verify user statistics were updated
      const updatedUser1 = await User.findById(user1._id);
      expect(updatedUser1.statistics.joinedCycles).toBe(1);
      expect(updatedUser1.statistics.totalInvitationsSent).toBe(2);
      expect(updatedUser1.metadata.lastMonthlyJobRun).toBeDefined();

      const updatedUser2 = await User.findById(user2._id);
      expect(updatedUser2.statistics.joinedCycles).toBe(1);
      expect(updatedUser2.statistics.totalInvitationsSent).toBe(1);

      emailSendSpy.mockRestore();
    });

    test('should handle users with no active contacts gracefully', async () => {
      // Create user with no contacts
      const user = await User.create({
        username: 'nocontacts',
        email: 'nocontacts@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      const month = '2025-08';
      const result = await schedulerService.runMonthlyJob(month);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(1);
      expect(result.sent).toBe(0);
      expect(result.total).toBe(0);

      // Verify user stats were still updated
      const updatedUser = await User.findById(user._id);
      expect(updatedUser.statistics.joinedCycles).toBe(1);
      expect(updatedUser.metadata.lastMonthlyJobRun).toBeDefined();
    });

    test('should skip inactive users and opted-out contacts', async () => {
      // Create inactive user
      const inactiveUser = await User.create({
        username: 'inactive',
        email: 'inactive@example.com',
        password: 'password123',
        metadata: { isActive: false }
      });

      // Create active user with mixed contacts
      const activeUser = await User.create({
        username: 'active',
        email: 'active@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      // Create contacts with different statuses
      await Contact.create({
        ownerId: inactiveUser._id,
        email: 'contact1@example.com',
        isActive: true,
        status: 'active'
      });

      await Contact.create({
        ownerId: activeUser._id,
        email: 'contact2@example.com',
        isActive: true,
        status: 'active'
      });

      await Contact.create({
        ownerId: activeUser._id,
        email: 'contact3@example.com',
        isActive: false,
        status: 'inactive'
      });

      await Contact.create({
        ownerId: activeUser._id,
        email: 'contact4@example.com',
        isActive: true,
        status: 'active',
        optedOut: true
      });

      // Mock email service
      const emailSendSpy = jest.spyOn(emailService, 'sendInvitation').mockResolvedValue({
        success: true,
        messageId: 'test-message-id'
      });

      const month = '2025-08';
      const result = await schedulerService.runMonthlyJob(month);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(1); // Only active user processed
      expect(result.sent).toBe(1); // Only one valid contact

      // Verify only valid invitation was created
      const invitations = await Invitation.find({ month });
      expect(invitations).toHaveLength(1);
      expect(invitations[0].toEmail).toBe('contact2@example.com');
      expect(invitations[0].fromUserId.toString()).toBe(activeUser._id.toString());

      emailSendSpy.mockRestore();
    });
  });

  describe('Reminder Processing Integration', () => {
    test('should process first reminders correctly', async () => {
      // Create user and invitation for reminder testing
      const user = await User.create({
        username: 'reminderuser',
        email: 'reminderuser@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          reminderSettings: {
            firstReminder: true,
            secondReminder: true
          }
        }
      });

      const contact = await Contact.create({
        ownerId: user._id,
        email: 'remindercontact@example.com',
        firstName: 'Reminder',
        lastName: 'Test',
        isActive: true,
        status: 'active'
      });

      // Create invitation that needs first reminder (3 days old)
      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
      const invitation = await Invitation.create({
        fromUserId: user._id,
        toEmail: contact.email,
        month: '2025-08',
        status: 'sent',
        tracking: {
          sentAt: threeDaysAgo
        }
      });

      // Mock email service
      const reminderSendSpy = jest.spyOn(emailService, 'sendReminder').mockResolvedValue({
        success: true,
        messageId: 'reminder-message-id'
      });

      // Process first reminders
      const result = await schedulerService.processReminders('first', 3);

      expect(result.sent).toBe(1);
      expect(result.errors).toHaveLength(0);

      // Verify reminder was recorded
      const updatedInvitation = await Invitation.findById(invitation._id);
      expect(updatedInvitation.reminders).toHaveLength(1);
      expect(updatedInvitation.reminders[0].type).toBe('first');
      expect(updatedInvitation.tracking.reminderCount).toBe(1);

      reminderSendSpy.mockRestore();
    });

    test('should not send duplicate reminders', async () => {
      const user = await User.create({
        username: 'noduplicates',
        email: 'noduplicates@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          reminderSettings: { firstReminder: true }
        }
      });

      const contact = await Contact.create({
        ownerId: user._id,
        email: 'contact@example.com',
        isActive: true,
        status: 'active'
      });

      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
      const invitation = await Invitation.create({
        fromUserId: user._id,
        toEmail: contact.email,
        month: '2025-08',
        status: 'sent',
        tracking: { sentAt: threeDaysAgo },
        reminders: [{
          type: 'first',
          sentAt: new Date()
        }]
      });

      const reminderSendSpy = jest.spyOn(emailService, 'sendReminder').mockResolvedValue({
        success: true
      });

      const result = await schedulerService.processReminders('first', 3);

      expect(result.sent).toBe(0); // No reminders sent
      expect(reminderSendSpy).not.toHaveBeenCalled();

      reminderSendSpy.mockRestore();
    });

    test('should handle bounced contacts during reminder processing', async () => {
      const user = await User.create({
        username: 'bounceuser',
        email: 'bounceuser@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          reminderSettings: { firstReminder: true }
        }
      });

      const bouncedContact = await Contact.create({
        ownerId: user._id,
        email: 'bounced@example.com',
        isActive: true,
        status: 'active',
        bounceCount: 5 // High bounce count should be filtered out
      });

      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
      await Invitation.create({
        fromUserId: user._id,
        toEmail: bouncedContact.email,
        month: '2025-08',
        status: 'sent',
        tracking: { 
          sentAt: threeDaysAgo,
          bounceCount: 5 
        }
      });

      const reminderSendSpy = jest.spyOn(emailService, 'sendReminder');

      const result = await schedulerService.processReminders('first', 3);

      expect(result.sent).toBe(0); // No reminders sent to bounced contacts
      expect(reminderSendSpy).not.toHaveBeenCalled();

      reminderSendSpy.mockRestore();
    });
  });

  describe('Contact Cleanup Integration', () => {
    test('should perform comprehensive contact cleanup', async () => {
      const user = await User.create({
        username: 'cleanupuser',
        email: 'cleanupuser@example.com',
        password: 'password123',
        metadata: { isActive: true }
      });

      // Create contacts with different bounce scenarios
      const recentBounceContact = await Contact.create({
        ownerId: user._id,
        email: 'recent@example.com',
        bounceCount: 2,
        lastBounceAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000), // 10 days ago
        emailStatus: 'bounced_temporary',
        status: 'active',
        isActive: true
      });

      const oldBounceContact = await Contact.create({
        ownerId: user._id,
        email: 'old@example.com',
        bounceCount: 2,
        lastBounceAt: new Date(Date.now() - 35 * 24 * 60 * 60 * 1000), // 35 days ago
        emailStatus: 'bounced_temporary',
        status: 'bounced',
        isActive: false
      });

      const highBounceContact = await Contact.create({
        ownerId: user._id,
        email: 'highbounce@example.com',
        bounceCount: 6,
        status: 'active',
        isActive: true
      });

      // Mock ContactService methods if needed
      const contactStatsSpy = jest.spyOn(contactService, 'getContactStats').mockResolvedValue({
        basic: {
          total: 3,
          active: 2,
          avgResponseRate: 75
        }
      });

      const result = await schedulerService.cleanupOldContactData();

      expect(result.reactivated).toBe(1); // Old bounce contact should be reactivated
      expect(result.deactivated).toBe(1); // High bounce contact should be deactivated

      // Verify contact statuses
      const updatedRecentBounce = await Contact.findById(recentBounceContact._id);
      expect(updatedRecentBounce.bounceCount).toBe(2); // Should remain unchanged

      const updatedOldBounce = await Contact.findById(oldBounceContact._id);
      expect(updatedOldBounce.bounceCount).toBe(0); // Should be reset
      expect(updatedOldBounce.status).toBe('active');
      expect(updatedOldBounce.isActive).toBe(true);

      const updatedHighBounce = await Contact.findById(highBounceContact._id);
      expect(updatedHighBounce.status).toBe('bounced');
      expect(updatedHighBounce.isActive).toBe(false);

      contactStatsSpy.mockRestore();
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle email service failures gracefully', async () => {
      const user = await User.create({
        username: 'erroruser',
        email: 'erroruser@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      const contact = await Contact.create({
        ownerId: user._id,
        email: 'error@example.com',
        isActive: true,
        status: 'active'
      });

      // Mock email service to fail
      const emailSendSpy = jest.spyOn(emailService, 'sendInvitation').mockRejectedValue(
        new Error('Email service unavailable')
      );

      const month = '2025-08';
      const result = await schedulerService.runMonthlyJob(month);

      expect(result.success).toBe(true); // Job should complete despite errors
      expect(result.processed).toBe(1);
      expect(result.sent).toBe(0);
      expect(result.failed).toBe(1);
      expect(result.errors).toHaveLength(1);

      // Verify invitation was created but marked as failed
      const invitations = await Invitation.find({ month });
      expect(invitations).toHaveLength(1);
      expect(invitations[0].status).toBe('failed');
      expect(invitations[0].tracking.failureReason).toBe('Email service unavailable');

      emailSendSpy.mockRestore();
    });

    test('should handle database connectivity issues', async () => {
      // Test alert system for database issues
      const healthData = {
        memoryUsage: {
          heapUsed: 100 * 1024 * 1024, // 100MB
          heapTotal: 200 * 1024 * 1024,
          external: 50 * 1024 * 1024
        }
      };

      // Temporarily disconnect database to test connectivity alert
      await mongoose.connection.close();

      const alerts = await schedulerService.checkAlertConditions(healthData);
      
      expect(alerts.some(alert => alert.type === 'database-connectivity')).toBe(true);
      
      const dbAlert = alerts.find(alert => alert.type === 'database-connectivity');
      expect(dbAlert.severity).toBe('critical');

      // Reconnect for cleanup
      await mongoose.connect(mongoServer.getUri());
    });
  });

  describe('Performance and Monitoring', () => {
    test('should track performance metrics during job execution', async () => {
      const user = await User.create({
        username: 'perfuser',
        email: 'perfuser@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      await Contact.create({
        ownerId: user._id,
        email: 'perf@example.com',
        isActive: true,
        status: 'active'
      });

      // Mock email service
      const emailSendSpy = jest.spyOn(emailService, 'sendInvitation').mockResolvedValue({
        success: true,
        messageId: 'perf-test'
      });

      const month = '2025-08';
      const startTime = Date.now();
      
      const result = await schedulerService.runMonthlyJob(month);
      
      const duration = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(result.duration).toBeDefined();
      expect(result.duration).toBeGreaterThan(0);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds for test data

      // Verify metrics are being tracked
      const metrics = schedulerService.getMetrics();
      expect(metrics.totalJobs).toBeGreaterThan(0);
      expect(metrics.successRate).toBeGreaterThan(0);

      emailSendSpy.mockRestore();
    });

    test('should generate alerts for high memory usage', async () => {
      const highMemoryUsage = {
        memoryUsage: {
          heapUsed: 450 * 1024 * 1024, // 450MB (high memory usage)
          heapTotal: 500 * 1024 * 1024,
          external: 100 * 1024 * 1024
        }
      };

      const alerts = await schedulerService.checkAlertConditions(highMemoryUsage);
      
      const memoryAlert = alerts.find(alert => alert.type === 'high-memory-usage');
      expect(memoryAlert).toBeDefined();
      expect(memoryAlert.severity).toBe('high');
      expect(memoryAlert.value).toBeGreaterThan(0.8); // 80% threshold
    });
  });
});