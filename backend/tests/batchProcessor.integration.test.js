/**
 * Integration tests for batch processor worker with full email and contact integration
 * Tests the worker thread functionality for automated monthly cycles
 */

const { Worker } = require('worker_threads');
const path = require('path');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Invitation = require('../models/Invitation');

let mongoServer;

describe('Batch Processor Worker Integration Tests', () => {
  beforeAll(async () => {
    // Start in-memory MongoDB
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    // Set up test environment
    process.env.MONGODB_URI = mongoUri;
    process.env.NODE_ENV = 'test';
    process.env.RESEND_API_KEY = 'test-resend-key';
    process.env.EMAIL_FROM_ADDRESS = 'test@example.com';
    process.env.APP_BASE_URL = 'http://localhost:3000';
  });

  beforeEach(async () => {
    // Clear all collections before each test
    await User.deleteMany({});
    await Contact.deleteMany({});
    await Invitation.deleteMany({});
  });

  afterAll(async () => {
    await mongoose.connection.close();
    await mongoServer.stop();
  });

  describe('Monthly Invitations Processing', () => {
    test('should process monthly invitations for a batch of users', async () => {
      // Create test data
      const user1 = await User.create({
        username: 'batchuser1',
        email: 'batchuser1@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: 5,
          timezone: 'Europe/Paris',
          emailTemplate: 'friendly'
        }
      });

      const user2 = await User.create({
        username: 'batchuser2',
        email: 'batchuser2@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: 5,
          timezone: 'Europe/Paris',
          emailTemplate: 'professional'
        }
      });

      // Create contacts for users
      await Contact.create({
        ownerId: user1._id,
        email: 'contact1@example.com',
        firstName: 'John',
        lastName: 'Doe',
        isActive: true,
        status: 'active',
        tracking: {
          responseRate: 85,
          invitationsSent: 3,
          responsesReceived: 2
        }
      });

      await Contact.create({
        ownerId: user1._id,
        email: 'contact2@example.com',
        firstName: 'Jane',
        lastName: 'Smith',
        isActive: true,
        status: 'active',
        tracking: {
          responseRate: 90,
          invitationsSent: 2,
          responsesReceived: 2
        }
      });

      await Contact.create({
        ownerId: user2._id,
        email: 'contact3@example.com',
        firstName: 'Bob',
        lastName: 'Johnson',
        isActive: true,
        status: 'active',
        tracking: {
          responseRate: 75,
          invitationsSent: 4,
          responsesReceived: 3
        }
      });

      // Prepare worker data
      const workerData = {
        batch: [user1, user2],
        jobType: 'monthly-invitations',
        options: {
          month: '2025-08',
          jobId: 'test-job-1'
        },
        config: {
          invitation: {
            tokenLength: 32,
            expirationDays: 60,
            maxRetries: 3,
            retryDelays: [1000, 2000, 3000]
          },
          email: {
            fromAddress: 'test@example.com',
            fromName: 'Test Sender',
            batchSize: 50,
            maxRetries: 3,
            timeout: 30000
          },
          contact: {
            maxBatchSize: 100,
            maxNameLength: 100
          }
        }
      };

      // Run worker
      const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
      const result = await runWorker(workerPath, workerData);

      // Verify results
      expect(result.success).toBe(true);
      expect(result.processed).toBe(2);
      expect(result.sent).toBe(3); // Total contacts processed
      expect(result.failed).toBe(0);
      expect(result.batchSize).toBe(2);

      // Verify invitations were created
      const invitations = await Invitation.find({ month: '2025-08' });
      expect(invitations).toHaveLength(3);

      // Verify invitation details
      const user1Invitations = invitations.filter(inv => inv.fromUserId.toString() === user1._id.toString());
      expect(user1Invitations).toHaveLength(2);
      expect(user1Invitations.map(inv => inv.toEmail).sort()).toEqual(['contact1@example.com', 'contact2@example.com']);

      const user2Invitations = invitations.filter(inv => inv.fromUserId.toString() === user2._id.toString());
      expect(user2Invitations).toHaveLength(1);
      expect(user2Invitations[0].toEmail).toBe('contact3@example.com');

      // Verify invitations have correct metadata
      for (const invitation of invitations) {
        expect(invitation.metadata.workerProcessed).toBe(true);
        expect(invitation.metadata.batchId).toBe('monthly-2025-08');
        expect(invitation.type).toBe('external');
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
    }, 15000); // Increased timeout for worker processing

    test('should filter out problematic contacts during processing', async () => {
      const user = await User.create({
        username: 'filteruser',
        email: 'filteruser@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      // Create contacts with various issues
      await Contact.create({
        ownerId: user._id,
        email: 'good@example.com',
        isActive: true,
        status: 'active',
        bounceCount: 0
      });

      await Contact.create({
        ownerId: user._id,
        email: 'bounced@example.com',
        isActive: true,
        status: 'active',
        bounceCount: 5, // High bounce count - should be filtered
        optedOut: false
      });

      await Contact.create({
        ownerId: user._id,
        email: 'optedout@example.com',
        isActive: true,
        status: 'active',
        bounceCount: 0,
        optedOut: true // Opted out - should be filtered
      });

      await Contact.create({
        ownerId: user._id,
        email: 'inactive@example.com',
        isActive: false, // Inactive - should be filtered
        status: 'inactive',
        bounceCount: 0,
        optedOut: false
      });

      const workerData = {
        batch: [user],
        jobType: 'monthly-invitations',
        options: { month: '2025-08' },
        config: {
          invitation: { tokenLength: 32, expirationDays: 60 },
          email: { fromAddress: 'test@example.com', batchSize: 50 },
          contact: { maxBatchSize: 100 }
        }
      };

      const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
      const result = await runWorker(workerPath, workerData);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(1);
      expect(result.sent).toBe(1); // Only one good contact
      expect(result.failed).toBe(0);

      // Verify only good invitation was created
      const invitations = await Invitation.find({ month: '2025-08' });
      expect(invitations).toHaveLength(1);
      expect(invitations[0].toEmail).toBe('good@example.com');
    }, 15000);

    test('should handle users with no active contacts', async () => {
      const userWithNoContacts = await User.create({
        username: 'nocontacts',
        email: 'nocontacts@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      const userWithInactiveContacts = await User.create({
        username: 'inactivecontacts',
        email: 'inactivecontacts@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      // Create only inactive contacts for second user
      await Contact.create({
        ownerId: userWithInactiveContacts._id,
        email: 'inactive@example.com',
        isActive: false,
        status: 'inactive'
      });

      const workerData = {
        batch: [userWithNoContacts, userWithInactiveContacts],
        jobType: 'monthly-invitations',
        options: { month: '2025-08' },
        config: {
          invitation: { tokenLength: 32, expirationDays: 60 },
          email: { fromAddress: 'test@example.com', batchSize: 50 },
          contact: { maxBatchSize: 100 }
        }
      };

      const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
      const result = await runWorker(workerPath, workerData);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(2);
      expect(result.sent).toBe(0); // No invitations sent
      expect(result.total).toBe(1); // One contact total (but inactive)

      // Verify no invitations were created
      const invitations = await Invitation.find({ month: '2025-08' });
      expect(invitations).toHaveLength(0);

      // Verify users were still marked as processed
      const updatedUser1 = await User.findById(userWithNoContacts._id);
      expect(updatedUser1.statistics.joinedCycles).toBe(1);

      const updatedUser2 = await User.findById(userWithInactiveContacts._id);
      expect(updatedUser2.statistics.joinedCycles).toBe(1);
    }, 15000);

    test('should skip inactive users during processing', async () => {
      const activeUser = await User.create({
        username: 'active',
        email: 'active@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { sendDay: 5 }
      });

      const inactiveUser = await User.create({
        username: 'inactive',
        email: 'inactive@example.com',
        password: 'password123',
        metadata: { isActive: false }, // Inactive user
        preferences: { sendDay: 5 }
      });

      const optedOutUser = await User.create({
        username: 'optedout',
        email: 'optedout@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: { 
          sendDay: 5,
          optedOut: true // Opted out user
        }
      });

      // Create contacts for all users
      await Contact.create({
        ownerId: activeUser._id,
        email: 'active-contact@example.com',
        isActive: true,
        status: 'active'
      });

      await Contact.create({
        ownerId: inactiveUser._id,
        email: 'inactive-contact@example.com',
        isActive: true,
        status: 'active'
      });

      await Contact.create({
        ownerId: optedOutUser._id,
        email: 'optedout-contact@example.com',
        isActive: true,
        status: 'active'
      });

      const workerData = {
        batch: [activeUser, inactiveUser, optedOutUser],
        jobType: 'monthly-invitations',
        options: { month: '2025-08' },
        config: {
          invitation: { tokenLength: 32, expirationDays: 60 },
          email: { fromAddress: 'test@example.com', batchSize: 50 },
          contact: { maxBatchSize: 100 }
        }
      };

      const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
      const result = await runWorker(workerPath, workerData);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(1); // Only active user processed
      expect(result.sent).toBe(1); // Only one invitation sent

      // Verify only active user's invitation was created
      const invitations = await Invitation.find({ month: '2025-08' });
      expect(invitations).toHaveLength(1);
      expect(invitations[0].fromUserId.toString()).toBe(activeUser._id.toString());
      expect(invitations[0].toEmail).toBe('active-contact@example.com');
    }, 15000);
  });

  describe('Contact Synchronization Processing', () => {
    test('should sync contact statistics and status', async () => {
      const user1 = await User.create({
        username: 'syncuser1',
        email: 'syncuser1@example.com',
        password: 'password123',
        metadata: { isActive: true }
      });

      const user2 = await User.create({
        username: 'syncuser2', 
        email: 'syncuser2@example.com',
        password: 'password123',
        metadata: { isActive: true }
      });

      // Create contacts with different status scenarios
      await Contact.create({
        ownerId: user1._id,
        email: 'tempbounce@example.com',
        bounceCount: 3,
        emailStatus: 'bounced_temporary',
        isActive: true,
        status: 'active'
      });

      await Contact.create({
        ownerId: user1._id,
        email: 'permabounce@example.com',
        bounceCount: 8,
        emailStatus: 'bounced_temporary',
        isActive: true,
        status: 'active'
      });

      await Contact.create({
        ownerId: user2._id,
        email: 'complained@example.com',
        emailStatus: 'complained',
        isActive: true,
        status: 'active',
        optedOut: false
      });

      const workerData = {
        batch: [user1, user2],
        jobType: 'contact-sync',
        options: {},
        config: {
          contact: { maxBatchSize: 100 }
        }
      };

      const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
      const result = await runWorker(workerPath, workerData);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(2);
      expect(result.synced).toBeGreaterThan(0);

      // Verify contact status updates
      const tempBounce = await Contact.findOne({ email: 'tempbounce@example.com' });
      expect(tempBounce.status).toBe('active'); // Should remain active (< 5 bounces)

      const permaBounce = await Contact.findOne({ email: 'permabounce@example.com' });
      expect(permaBounce.status).toBe('bounced');
      expect(permaBounce.isActive).toBe(false);

      const complained = await Contact.findOne({ email: 'complained@example.com' });
      expect(complained.status).toBe('opted_out');
      expect(complained.isActive).toBe(false);
      expect(complained.optedOut).toBe(true);
    }, 15000);
  });

  describe('Error Handling', () => {
    test('should handle worker initialization errors', async () => {
      const workerData = {
        batch: [],
        jobType: 'monthly-invitations',
        options: { month: '2025-08' },
        config: {}
      };

      // Use invalid MongoDB URI to trigger initialization error
      const originalUri = process.env.MONGODB_URI;
      process.env.MONGODB_URI = 'mongodb://invalid:27017/test';

      try {
        const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
        const result = await runWorker(workerPath, workerData);

        expect(result.success).toBe(false);
        expect(result.error).toContain('Worker initialization failed');
        expect(result.processed).toBe(0);
        expect(result.failed).toBeGreaterThan(0);
      } finally {
        process.env.MONGODB_URI = originalUri;
      }
    }, 15000);

    test('should handle unknown job types', async () => {
      const user = await User.create({
        username: 'erroruser',
        email: 'erroruser@example.com',
        password: 'password123',
        metadata: { isActive: true }
      });

      const workerData = {
        batch: [user],
        jobType: 'unknown-job-type',
        options: {},
        config: {
          invitation: { tokenLength: 32 },
          email: { fromAddress: 'test@example.com' },
          contact: { maxBatchSize: 100 }
        }
      };

      const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
      const result = await runWorker(workerPath, workerData);

      expect(result.success).toBe(false);
      expect(result.error).toContain('Unknown job type');
    }, 15000);
  });

  describe('Memory Management', () => {
    test('should monitor memory usage during processing', async () => {
      // Create a larger batch to test memory monitoring
      const users = [];
      for (let i = 0; i < 10; i++) {
        const user = await User.create({
          username: `memuser${i}`,
          email: `memuser${i}@example.com`,
          password: 'password123',
          metadata: { isActive: true },
          preferences: { sendDay: 5 }
        });
        users.push(user);

        // Create contacts for each user
        for (let j = 0; j < 5; j++) {
          await Contact.create({
            ownerId: user._id,
            email: `contact${i}-${j}@example.com`,
            firstName: `Contact${j}`,
            isActive: true,
            status: 'active'
          });
        }
      }

      const workerData = {
        batch: users,
        jobType: 'monthly-invitations',
        options: { month: '2025-08' },
        config: {
          invitation: { tokenLength: 32, expirationDays: 60 },
          email: { fromAddress: 'test@example.com', batchSize: 50 },
          contact: { maxBatchSize: 100 }
        }
      };

      const workerPath = path.join(__dirname, '../services/workers/batchProcessor.js');
      const result = await runWorker(workerPath, workerData);

      expect(result.success).toBe(true);
      expect(result.processed).toBe(10);
      expect(result.sent).toBe(50); // 10 users × 5 contacts each
      expect(result.duration).toBeDefined();
      expect(result.workerId).toBeDefined();

      // Verify all invitations were created
      const invitations = await Invitation.find({ month: '2025-08' });
      expect(invitations).toHaveLength(50);
    }, 30000); // Extended timeout for larger batch
  });
});

/**
 * Helper function to run worker and return results as a Promise
 */
function runWorker(workerPath, workerData) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerPath, { workerData });
    
    worker.on('message', (result) => {
      resolve(result);
    });
    
    worker.on('error', (error) => {
      reject(error);
    });
    
    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Worker stopped with exit code ${code}`));
      }
    });
  });
}