const SchedulerService = require('../services/schedulerService');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Invitation = require('../models/Invitation');

// Mock the dependencies
jest.mock('../models/User');
jest.mock('../models/Contact');
jest.mock('../models/Invitation');
jest.mock('../utils/secureLogger');

describe('SchedulerService', () => {
  let schedulerService;
  let mockInvitationService;
  let mockEmailService;
  let mockContactService;

  beforeEach(() => {
    // Create mock services
    mockInvitationService = {
      createInvitation: jest.fn().mockResolvedValue({
        _id: 'invitation_id',
        token: 'test_token'
      }),
      cleanupExpiredInvitations: jest.fn().mockResolvedValue({
        expired: 5,
        deleted: 2
      })
    };

    mockEmailService = {
      sendInvitation: jest.fn().mockResolvedValue({
        success: true,
        messageId: 'test_message_id'
      }),
      sendReminder: jest.fn().mockResolvedValue({
        success: true,
        messageId: 'test_reminder_id'
      })
    };

    mockContactService = {
      updateTracking: jest.fn().mockResolvedValue(true)
    };

    // Initialize scheduler service with test config
    schedulerService = new SchedulerService({
      monthlyJobDay: 1,
      monthlyJobHour: 10,
      timezone: 'UTC',
      batchSize: 2,
      maxConcurrentWorkers: 1,
      workerTimeout: 5000,
      maxMemoryUsage: 100 * 1024 * 1024, // 100MB
      healthCheckInterval: '*/10 * * * * *' // Every 10 seconds for testing
    });
  });

  afterEach(async () => {
    if (schedulerService.isRunning) {
      await schedulerService.stop();
    }
    jest.clearAllMocks();
  });

  describe('Initialization', () => {
    test('should initialize correctly with required services', async () => {
      const services = {
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      };

      await schedulerService.initialize(services);

      expect(schedulerService.isRunning).toBe(true);
      expect(schedulerService.invitationService).toBe(mockInvitationService);
      expect(schedulerService.emailService).toBe(mockEmailService);
    });

    test('should throw error if required services are missing', async () => {
      const services = {
        contactService: mockContactService
        // Missing invitationService and emailService
      };

      await expect(schedulerService.initialize(services))
        .rejects.toThrow('Required services not provided');
    });
  });

  describe('Service Status and Control', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should start and stop correctly', async () => {
      await schedulerService.start();
      expect(schedulerService.isRunning).toBe(true);

      await schedulerService.stop();
      expect(schedulerService.isRunning).toBe(false);
    });

    test('should return correct status information', () => {
      const status = schedulerService.getStatus();

      expect(status).toMatchObject({
        isRunning: true,
        activeJobs: 0,
        activeWorkers: 0,
        cronJobs: expect.arrayContaining(['monthly-invitations', 'reminders', 'cleanup', 'health-check'])
      });
    });

    test('should return basic metrics', () => {
      const metrics = schedulerService.getBasicMetrics();

      expect(metrics).toMatchObject({
        totalJobsRun: 0,
        totalJobsSuccess: 0,
        totalJobsFailed: 0,
        errorRate: 0,
        totalInvitationsSent: 0,
        totalRemindersSent: 0,
        currentJobsRunning: 0
      });
    });
  });

  describe('User and Contact Queries', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should get active users for invitations', async () => {
      const mockUsers = [
        {
          _id: 'user1',
          username: 'testuser1',
          email: 'test1@example.com',
          metadata: { isActive: true },
          preferences: { sendDay: 5 }
        },
        {
          _id: 'user2',
          username: 'testuser2',
          email: 'test2@example.com',
          metadata: { isActive: true },
          preferences: { sendDay: 3 }
        }
      ];

      User.find.mockReturnValue({
        select: jest.fn().mockReturnValue({
          lean: jest.fn().mockResolvedValue(mockUsers)
        })
      });

      Contact.countDocuments
        .mockResolvedValueOnce(5) // user1 has 5 contacts
        .mockResolvedValueOnce(0); // user2 has 0 contacts

      const users = await schedulerService.getActiveUsersForInvitations();

      expect(users).toHaveLength(1);
      expect(users[0]).toMatchObject({
        _id: 'user1',
        contactCount: 5
      });
    });
  });

  describe('Reminder Processing', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should check user reminder preferences correctly', () => {
      const userWithPreferences = {
        preferences: {
          reminderSettings: {
            firstReminder: true,
            secondReminder: false
          }
        }
      };

      const userWithoutPreferences = {};

      expect(schedulerService.shouldSendReminder(userWithPreferences, 'first')).toBe(true);
      expect(schedulerService.shouldSendReminder(userWithPreferences, 'second')).toBe(false);
      expect(schedulerService.shouldSendReminder(userWithoutPreferences, 'first')).toBe(true);
      expect(schedulerService.shouldSendReminder(userWithoutPreferences, 'second')).toBe(true);
    });

    test('should process reminders with proper error handling', async () => {
      const mockInvitations = [
        {
          _id: 'inv1',
          toEmail: 'test@example.com',
          reminders: [],
          save: jest.fn().mockResolvedValue(true),
          fromUserId: {
            username: 'sender',
            email: 'sender@example.com',
            preferences: { reminderSettings: { firstReminder: true } }
          }
        }
      ];

      Invitation.find.mockReturnValue({
        populate: jest.fn().mockReturnValue({
          populate: jest.fn().mockReturnValue({
            limit: jest.fn().mockResolvedValue(mockInvitations)
          })
        })
      });

      const result = await schedulerService.processReminders('first', 3);

      expect(result).toMatchObject({
        checked: 1,
        sent: 1,
        errors: []
      });

      expect(mockEmailService.sendReminder).toHaveBeenCalledWith(
        mockInvitations[0],
        expect.any(Object),
        'first'
      );
    });
  });

  describe('Job Management', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should create batches correctly', () => {
      const items = [1, 2, 3, 4, 5, 6, 7];
      const batches = schedulerService.createBatches(items, 3);

      expect(batches).toEqual([
        [1, 2, 3],
        [4, 5, 6],
        [7]
      ]);
    });

    test('should update job progress', () => {
      const jobId = 'test-job';
      schedulerService.activeJobs.set(jobId, {
        type: 'test',
        startTime: Date.now(),
        progress: 0
      });

      schedulerService.updateJobProgress(jobId, 50);

      const job = schedulerService.activeJobs.get(jobId);
      expect(job.progress).toBe(50);
    });

    test('should complete job correctly', async () => {
      const jobId = 'test-job';
      const startTime = Date.now();
      schedulerService.activeJobs.set(jobId, {
        type: 'test',
        startTime,
        progress: 0,
        stats: {}
      });

      const stats = { processed: 10, sent: 8 };
      await schedulerService.completeJob(jobId, 'success', stats);

      expect(schedulerService.activeJobs.has(jobId)).toBe(false);
      expect(schedulerService.jobHistory).toHaveLength(1);
      expect(schedulerService.jobHistory[0]).toMatchObject({
        type: 'test',
        status: 'success',
        stats
      });
    });
  });

  describe('Health Checks', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should check system health', async () => {
      const health = await schedulerService.checkSystemHealth();

      expect(health).toMatchObject({
        status: 'healthy',
        uptime: expect.any(Number),
        memoryUsage: expect.any(Object),
        nodeVersion: expect.any(String),
        platform: expect.any(String)
      });
    });

    test('should check service health', async () => {
      const health = await schedulerService.checkServiceHealth();

      expect(health).toMatchObject({
        status: 'healthy',
        isRunning: true,
        activeJobs: 0,
        activeWorkers: 0,
        cronJobsRunning: expect.any(Number)
      });
    });

    test('should check database health', async () => {
      User.findOne.mockReturnValue({
        limit: jest.fn().mockResolvedValue({})
      });
      Contact.findOne.mockReturnValue({
        limit: jest.fn().mockResolvedValue({})
      });
      Invitation.findOne.mockReturnValue({
        limit: jest.fn().mockResolvedValue({})
      });

      const health = await schedulerService.checkDatabaseHealth();

      expect(health).toMatchObject({
        status: 'healthy',
        connected: true
      });
    });
  });

  describe('Cleanup Operations', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should cleanup expired invitations', async () => {
      Invitation.updateMany
        .mockResolvedValueOnce({ modifiedCount: 5 });
      Invitation.deleteMany
        .mockResolvedValueOnce({ deletedCount: 2 });

      const result = await schedulerService.cleanupExpiredInvitations();

      expect(result).toMatchObject({
        expired: 5,
        deleted: 2,
        errors: []
      });
    });

    test('should cleanup old contact data', async () => {
      Contact.updateMany
        .mockResolvedValueOnce({ modifiedCount: 3 });

      const result = await schedulerService.cleanupOldContactData();

      expect(result).toMatchObject({
        cleaned: 3,
        errors: []
      });
    });

    test('should cleanup memory and internal caches', async () => {
      // Add some job history
      schedulerService.jobHistory = Array(20).fill({
        startTime: Date.now() - 100000
      });

      const result = await schedulerService.cleanupMemory();

      expect(result).toMatchObject({
        freed: expect.any(Number),
        errors: []
      });
    });
  });

  describe('Error Handling', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should handle job errors correctly', async () => {
      const jobId = 'test-job';
      const error = new Error('Test error');
      const startTime = Date.now();

      schedulerService.activeJobs.set(jobId, {
        type: 'test',
        startTime,
        stats: {}
      });

      await schedulerService.handleJobError(jobId, 'test-job', error, startTime);

      expect(schedulerService.activeJobs.has(jobId)).toBe(false);
      expect(schedulerService.metrics.totalJobsFailed).toBe(1);
      expect(schedulerService.jobHistory).toHaveLength(1);
      expect(schedulerService.jobHistory[0].status).toBe('failed');
    });

    test('should update error rate correctly', () => {
      schedulerService.metrics.totalJobsSuccess = 8;
      schedulerService.metrics.totalJobsFailed = 2;

      schedulerService.updateErrorRate();

      expect(schedulerService.metrics.errorRate).toBe(0.2); // 2/10 = 20%
    });
  });

  describe('Manual Job Triggering', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });
    });

    test('should throw error for unknown job type', async () => {
      await expect(schedulerService.triggerJob('unknown-job'))
        .rejects.toThrow('Unknown job type: unknown-job');
    });

    test('should throw error if service not running', async () => {
      await schedulerService.stop();
      
      await expect(schedulerService.triggerJob('health-check'))
        .rejects.toThrow('SchedulerService is not running');
    });
  });

  describe('Job History and Filtering', () => {
    beforeEach(async () => {
      await schedulerService.initialize({
        invitationService: mockInvitationService,
        emailService: mockEmailService,
        contactService: mockContactService
      });

      // Add some job history
      schedulerService.jobHistory = [
        { type: 'monthly-invitations', status: 'success', startTime: Date.now() - 1000 },
        { type: 'reminders', status: 'failed', startTime: Date.now() - 2000 },
        { type: 'cleanup', status: 'success', startTime: Date.now() - 3000 },
        { type: 'monthly-invitations', status: 'success', startTime: Date.now() - 4000 }
      ];
    });

    test('should filter job history by type', () => {
      const filtered = schedulerService.getJobHistory({ type: 'monthly-invitations' });
      
      expect(filtered).toHaveLength(2);
      expect(filtered.every(job => job.type === 'monthly-invitations')).toBe(true);
    });

    test('should filter job history by status', () => {
      const filtered = schedulerService.getJobHistory({ status: 'failed' });
      
      expect(filtered).toHaveLength(1);
      expect(filtered[0].type).toBe('reminders');
    });

    test('should limit job history results', () => {
      const filtered = schedulerService.getJobHistory({ limit: 2 });
      
      expect(filtered).toHaveLength(2);
      // Should return the last 2 jobs
      expect(filtered[0].type).toBe('cleanup');
      expect(filtered[1].type).toBe('monthly-invitations');
    });
  });
});