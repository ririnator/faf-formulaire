const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const SchedulerService = require('../services/schedulerService');
const InvitationService = require('../services/invitationService');
const EmailService = require('../services/emailService');
const ContactService = require('../services/contactService');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Invitation = require('../models/Invitation');

describe('SchedulerService Integration Tests', () => {
  let mongoServer;
  let schedulerService;
  let invitationService;
  let emailService;
  let contactService;

  // Test users and contacts
  let testUsers = [];
  let testContacts = [];

  beforeAll(async () => {
    // Setup in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    // Clear all collections
    await User.deleteMany({});
    await Contact.deleteMany({});
    await Invitation.deleteMany({});

    // Setup services
    invitationService = new InvitationService({
      tokenLength: 16,
      expirationDays: 30
    });

    // Mock email service
    emailService = {
      sendInvitation: jest.fn().mockResolvedValue({
        success: true,
        messageId: 'mock-message-id',
        provider: 'mock'
      }),
      sendReminder: jest.fn().mockResolvedValue({
        success: true,
        messageId: 'mock-reminder-id',
        provider: 'mock'
      })
    };

    contactService = new ContactService({
      maxBatchSize: 50
    });

    schedulerService = new SchedulerService({
      monthlyJobDay: 1,
      monthlyJobHour: 10,
      timezone: 'UTC',
      batchSize: 2,
      maxConcurrentWorkers: 1,
      workerTimeout: 10000,
      maxMemoryUsage: 100 * 1024 * 1024,
      healthCheckInterval: '*/30 * * * * *', // Every 30 seconds for testing
      firstReminderDays: 3,
      secondReminderDays: 7
    });

    // Initialize scheduler service
    await schedulerService.initialize({
      invitationService,
      emailService,
      contactService
    });

    // Create test data
    await createTestData();
  });

  afterEach(async () => {
    if (schedulerService.isRunning) {
      await schedulerService.stop();
    }
    jest.clearAllMocks();
  });

  async function createTestData() {
    // Create test users
    testUsers = await User.create([
      {
        username: 'user1',
        email: 'user1@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: 5,
          sendTime: '18:00',
          timezone: 'Europe/Paris',
          reminderSettings: {
            firstReminder: true,
            secondReminder: true,
            reminderChannel: 'email'
          },
          emailTemplate: 'friendly'
        },
        statistics: {
          totalSubmissions: 0,
          totalContacts: 0,
          joinedCycles: 0
        }
      },
      {
        username: 'user2',
        email: 'user2@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: 5,
          sendTime: '19:00',
          timezone: 'Europe/Paris',
          reminderSettings: {
            firstReminder: false, // No first reminder
            secondReminder: true,
            reminderChannel: 'email'
          },
          emailTemplate: 'professional'
        },
        statistics: {
          totalSubmissions: 0,
          totalContacts: 0,
          joinedCycles: 0
        }
      },
      {
        username: 'user3',
        email: 'user3@example.com',
        password: 'password123',
        metadata: { isActive: false }, // Inactive user
        preferences: {
          sendDay: 5,
          reminderSettings: {
            firstReminder: true,
            secondReminder: true
          }
        }
      }
    ]);

    // Create test contacts
    testContacts = await Contact.create([
      // User 1 contacts (3 active contacts)
      {
        ownerId: testUsers[0]._id,
        email: 'contact1@example.com',
        firstName: 'Contact',
        lastName: 'One',
        status: 'active',
        isActive: true,
        optedOut: false,
        emailStatus: 'active'
      },
      {
        ownerId: testUsers[0]._id,
        email: 'contact2@example.com',
        firstName: 'Contact',
        lastName: 'Two',
        status: 'active',
        isActive: true,
        optedOut: false,
        emailStatus: 'active'
      },
      {
        ownerId: testUsers[0]._id,
        email: 'contact3@example.com',
        firstName: 'Contact',
        lastName: 'Three',
        status: 'active',
        isActive: true,
        optedOut: false,
        emailStatus: 'active'
      },
      // User 2 contacts (2 active, 1 inactive)
      {
        ownerId: testUsers[1]._id,
        email: 'contact4@example.com',
        firstName: 'Contact',
        lastName: 'Four',
        status: 'active',
        isActive: true,
        optedOut: false,
        emailStatus: 'active'
      },
      {
        ownerId: testUsers[1]._id,
        email: 'contact5@example.com',
        firstName: 'Contact',
        lastName: 'Five',
        status: 'active',
        isActive: true,
        optedOut: false,
        emailStatus: 'active'
      },
      {
        ownerId: testUsers[1]._id,
        email: 'contact6@example.com',
        firstName: 'Contact',
        lastName: 'Six',
        status: 'opted_out',
        isActive: false,
        optedOut: true,
        emailStatus: 'unsubscribed'
      },
      // User 3 contacts (inactive user, should not be processed)
      {
        ownerId: testUsers[2]._id,
        email: 'contact7@example.com',
        firstName: 'Contact',
        lastName: 'Seven',
        status: 'active',
        isActive: true,
        optedOut: false,
        emailStatus: 'active'
      }
    ]);
  }

  describe('Monthly Invitation Job Integration', () => {
    test('should process monthly invitations for active users only', async () => {
      const currentMonth = new Date().toISOString().substring(0, 7);
      
      // Mock the getActiveUsersForInvitations to return today as sendDay
      const today = new Date().getDate();
      await User.updateMany(
        { _id: { $in: [testUsers[0]._id, testUsers[1]._id] } },
        { $set: { 'preferences.sendDay': today } }
      );

      // Run monthly job
      await schedulerService.runMonthlyInvitationJob();

      // Check that invitations were created
      const invitations = await Invitation.find({
        month: currentMonth
      }).populate('fromUserId');

      // Should have invitations for:
      // - User1: 3 active contacts = 3 invitations
      // - User2: 2 active contacts = 2 invitations  
      // - User3: 0 invitations (inactive user)
      expect(invitations).toHaveLength(5);

      // Verify invitations are for correct users and contacts
      const user1Invitations = invitations.filter(inv => 
        inv.fromUserId._id.equals(testUsers[0]._id)
      );
      const user2Invitations = invitations.filter(inv => 
        inv.fromUserId._id.equals(testUsers[1]._id)
      );

      expect(user1Invitations).toHaveLength(3);
      expect(user2Invitations).toHaveLength(2);

      // Check that all invitations have proper data
      for (const invitation of invitations) {
        expect(invitation.token).toBeDefined();
        expect(invitation.month).toBe(currentMonth);
        expect(invitation.status).toBe('queued');
        expect(invitation.type).toBe('external');
      }

      // Check that contacts tracking was updated
      const updatedContacts = await Contact.find({
        ownerId: { $in: [testUsers[0]._id, testUsers[1]._id] },
        isActive: true,
        optedOut: false
      });

      for (const contact of updatedContacts) {
        expect(contact.tracking.invitationsSent).toBe(1);
      }

      // Check that user statistics were updated
      const updatedUser1 = await User.findById(testUsers[0]._id);
      const updatedUser2 = await User.findById(testUsers[1]._id);
      
      expect(updatedUser1.statistics.joinedCycles).toBe(1);
      expect(updatedUser2.statistics.joinedCycles).toBe(1);
    });

    test('should not create duplicate invitations for same month', async () => {
      const currentMonth = new Date().toISOString().substring(0, 7);
      
      // Set sendDay to today
      const today = new Date().getDate();
      await User.updateMany(
        { _id: testUsers[0]._id },
        { $set: { 'preferences.sendDay': today } }
      );

      // Create existing invitation
      await Invitation.create({
        fromUserId: testUsers[0]._id,
        toEmail: testContacts[0].email,
        month: currentMonth,
        token: 'existing-token',
        status: 'sent'
      });

      // Run monthly job
      await schedulerService.runMonthlyInvitationJob();

      // Check invitations count - should only have 2 new + 1 existing = 3 total
      const invitations = await Invitation.find({
        fromUserId: testUsers[0]._id,
        month: currentMonth
      });

      expect(invitations).toHaveLength(3);

      // Verify the existing invitation wasn't duplicated
      const existingInvitation = invitations.find(inv => inv.token === 'existing-token');
      expect(existingInvitation).toBeDefined();
      expect(existingInvitation.status).toBe('sent'); // Status unchanged
    });
  });

  describe('Reminder Job Integration', () => {
    beforeEach(async () => {
      // Create test invitations with different send dates
      const now = new Date();
      const threeDaysAgo = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000);
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const tenDaysAgo = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000);

      await Invitation.create([
        // Should get first reminder (3 days old, no reminders sent)
        {
          fromUserId: testUsers[0]._id,
          toEmail: 'reminder1@example.com',
          month: '2024-01',
          token: 'token1',
          status: 'sent',
          tracking: { sentAt: threeDaysAgo },
          expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
          reminders: []
        },
        // Should get second reminder (7 days old, has first reminder)
        {
          fromUserId: testUsers[1]._id,
          toEmail: 'reminder2@example.com',
          month: '2024-01',
          token: 'token2',
          status: 'opened',
          tracking: { sentAt: sevenDaysAgo },
          expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
          reminders: [{ type: 'first', sentAt: new Date(now.getTime() - 4 * 24 * 60 * 60 * 1000) }]
        },
        // Should not get reminder (already has second reminder)
        {
          fromUserId: testUsers[0]._id,
          toEmail: 'reminder3@example.com',
          month: '2024-01',
          token: 'token3',
          status: 'sent',
          tracking: { sentAt: tenDaysAgo },
          expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
          reminders: [
            { type: 'first', sentAt: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000) },
            { type: 'second', sentAt: new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000) }
          ]
        },
        // Should not get reminder (already submitted)
        {
          fromUserId: testUsers[0]._id,
          toEmail: 'reminder4@example.com',
          month: '2024-01',
          token: 'token4',
          status: 'submitted',
          tracking: { sentAt: threeDaysAgo },
          expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
          reminders: []
        }
      ]);
    });

    test('should send first reminders correctly', async () => {
      await schedulerService.runReminderJob();

      // Check that first reminder was sent for token1
      const invitation1 = await Invitation.findOne({ token: 'token1' });
      expect(invitation1.reminders).toHaveLength(1);
      expect(invitation1.reminders[0].type).toBe('first');

      // Verify email service was called for first reminder
      expect(emailService.sendReminder).toHaveBeenCalledWith(
        expect.objectContaining({ token: 'token1' }),
        expect.any(Object),
        'first'
      );
    });

    test('should send second reminders correctly', async () => {
      await schedulerService.runReminderJob();

      // Check that second reminder was sent for token2
      const invitation2 = await Invitation.findOne({ token: 'token2' });
      expect(invitation2.reminders).toHaveLength(2);
      expect(invitation2.reminders[1].type).toBe('second');

      // Verify email service was called for second reminder
      expect(emailService.sendReminder).toHaveBeenCalledWith(
        expect.objectContaining({ token: 'token2' }),
        expect.any(Object),
        'second'
      );
    });

    test('should respect user reminder preferences', async () => {
      // User2 has firstReminder disabled, should not receive first reminder
      const invitation = await Invitation.findOne({ token: 'token1' });
      invitation.fromUserId = testUsers[1]._id; // User with firstReminder: false
      await invitation.save();

      await schedulerService.runReminderJob();

      const updatedInvitation = await Invitation.findOne({ token: 'token1' });
      
      // Should not have received first reminder due to user preferences
      expect(updatedInvitation.reminders).toHaveLength(0);
    });
  });

  describe('Cleanup Job Integration', () => {
    beforeEach(async () => {
      const now = new Date();
      const oldDate = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days ago
      const veryOldDate = new Date(now.getTime() - 400 * 24 * 60 * 60 * 1000); // 400 days ago

      // Create expired invitations
      await Invitation.create([
        {
          fromUserId: testUsers[0]._id,
          toEmail: 'expired1@example.com',
          month: '2023-01',
          token: 'expired-token-1',
          status: 'sent',
          expiresAt: oldDate
        },
        {
          fromUserId: testUsers[0]._id,
          toEmail: 'expired2@example.com',
          month: '2023-02',
          token: 'expired-token-2',
          status: 'expired',
          expiresAt: veryOldDate
        }
      ]);

      // Create contacts with old bounce data
      await Contact.create([
        {
          ownerId: testUsers[0]._id,
          email: 'bounced@example.com',
          bounceCount: 2,
          lastBounceAt: new Date(now.getTime() - 35 * 24 * 60 * 60 * 1000), // 35 days ago
          emailStatus: 'bounced_temporary'
        }
      ]);
    });

    test('should cleanup expired invitations', async () => {
      await schedulerService.runCleanupJob();

      // Check that expired invitation was marked as expired
      const expiredInvitation = await Invitation.findOne({ token: 'expired-token-1' });
      expect(expiredInvitation.status).toBe('expired');

      // Check that very old expired invitation was deleted
      const deletedInvitation = await Invitation.findOne({ token: 'expired-token-2' });
      expect(deletedInvitation).toBeNull();
    });

    test('should cleanup old contact bounce data', async () => {
      await schedulerService.runCleanupJob();

      // Check that bounce count was reset for old bounces
      const contact = await Contact.findOne({ email: 'bounced@example.com' });
      expect(contact.bounceCount).toBe(0);
      expect(contact.emailStatus).toBe('active');
      expect(contact.bounceReason).toBeUndefined();
    });
  });

  describe('Health Check Integration', () => {
    test('should perform complete health check', async () => {
      await schedulerService.start();

      await schedulerService.runHealthCheck();

      const healthData = schedulerService.lastHealthCheck;
      
      expect(healthData).toMatchObject({
        timestamp: expect.any(Date),
        systemHealth: {
          status: 'healthy',
          uptime: expect.any(Number),
          memoryUsage: expect.any(Object)
        },
        serviceHealth: {
          status: 'healthy',
          isRunning: true,
          activeJobs: 0,
          activeWorkers: 0
        },
        databaseHealth: {
          status: 'healthy',
          connected: true
        }
      });
    });
  });

  describe('Job Status and Metrics Integration', () => {
    test('should track job metrics correctly', async () => {
      const initialMetrics = schedulerService.getBasicMetrics();
      expect(initialMetrics.totalJobsRun).toBe(0);

      // Run a health check job
      await schedulerService.runHealthCheck();

      // Run cleanup job 
      await schedulerService.runCleanupJob();

      const updatedMetrics = schedulerService.getBasicMetrics();
      expect(updatedMetrics.totalJobsRun).toBe(1); // Only cleanup counts as tracked job
      expect(updatedMetrics.totalJobsSuccess).toBe(1);
      expect(updatedMetrics.errorRate).toBe(0);
    });

    test('should provide detailed service status', () => {
      const status = schedulerService.getStatus();

      expect(status).toMatchObject({
        isRunning: true,
        activeJobs: 0,
        activeWorkers: 0,
        cronJobs: ['monthly-invitations', 'reminders', 'cleanup', 'health-check'],
        metrics: expect.any(Object),
        lastHealthCheck: expect.any(Object)
      });
    });
  });

  describe('Error Handling Integration', () => {
    test('should handle database errors gracefully', async () => {
      // Close database connection to simulate error
      await mongoose.disconnect();

      const healthData = await schedulerService.checkDatabaseHealth();
      
      expect(healthData).toMatchObject({
        status: 'unhealthy',
        connected: false,
        error: expect.any(String)
      });

      // Reconnect for cleanup
      await mongoose.connect(mongoServer.getUri());
    });

    test('should handle email service errors in reminder job', async () => {
      // Setup invitation that needs reminder
      const now = new Date();
      const threeDaysAgo = new Date(now.getTime() - 3 * 24 * 60 * 60 * 1000);

      await Invitation.create({
        fromUserId: testUsers[0]._id,
        toEmail: 'reminder@example.com',
        month: '2024-01',
        token: 'reminder-token',
        status: 'sent',
        tracking: { sentAt: threeDaysAgo },
        expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
        reminders: []
      });

      // Make email service throw error
      emailService.sendReminder.mockRejectedValueOnce(new Error('Email service error'));

      // Should not throw, but handle error gracefully
      await expect(schedulerService.runReminderJob()).resolves.not.toThrow();

      // Check that error was logged in job results
      const jobHistory = schedulerService.getJobHistory({ type: 'reminders' });
      expect(jobHistory).toHaveLength(1);
      expect(jobHistory[0].status).toBe('success'); // Job completes even with email errors
    });
  });
});