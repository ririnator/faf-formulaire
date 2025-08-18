const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');
const Invitation = require('../models/Invitation');
const User = require('../models/User');
const Submission = require('../models/Submission');

describe('Invitation Model Tests', () => {
  let testUser1, testUser2;

  beforeEach(async () => {
    await cleanupBetweenTests();

    // Create test users
    testUser1 = await User.create({
      username: 'sender',
      email: 'sender@example.com',
      password: 'password123'
    });

    testUser2 = await User.create({
      username: 'receiver',
      email: 'receiver@example.com',
      password: 'password123'
    });
  });

  describe('Schema Validation', () => {
    test('should create valid invitation with required fields', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      };

      const invitation = new Invitation(invitationData);
      const savedInvitation = await invitation.save();

      expect(savedInvitation.fromUserId).toEqual(testUser1._id);
      expect(savedInvitation.toEmail).toBe('recipient@example.com');
      expect(savedInvitation.month).toBe('2025-01');
      expect(savedInvitation.token).toBeDefined();
      expect(savedInvitation.token).toHaveLength(64); // 32 bytes -> 64 hex chars
      expect(savedInvitation.shortCode).toBeDefined();
      expect(savedInvitation.shortCode).toHaveLength(6);
      expect(savedInvitation.type).toBe('external');
      expect(savedInvitation.status).toBe('queued');
    });

    test('should fail validation without required fromUserId', async () => {
      const invitationData = {
        toEmail: 'recipient@example.com',
        month: '2025-01'
      };

      const invitation = new Invitation(invitationData);

      await expect(invitation.save()).rejects.toThrow();
    });

    test('should fail validation without required toEmail', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        month: '2025-01'
      };

      const invitation = new Invitation(invitationData);

      await expect(invitation.save()).rejects.toThrow();
    });

    test('should fail validation without required month', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com'
      };

      const invitation = new Invitation(invitationData);

      await expect(invitation.save()).rejects.toThrow();
    });

    test('should lowercase toEmail', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'RECIPIENT@EXAMPLE.COM',
        month: '2025-01'
      };

      const invitation = new Invitation(invitationData);
      const savedInvitation = await invitation.save();

      expect(savedInvitation.toEmail).toBe('recipient@example.com');
    });

    test('should validate month format', async () => {
      const invalidMonths = ['2025', '2025-1', '25-01', 'January 2025', '2025/01'];

      for (const invalidMonth of invalidMonths) {
        const invitation = new Invitation({
          fromUserId: testUser1._id,
          toEmail: 'recipient@example.com',
          month: invalidMonth
        });

        const error = invitation.validateSync();
        expect(error.errors.month).toBeDefined();
      }
    });

    test('should accept valid month formats', async () => {
      const validMonths = ['2025-01', '2025-12', '2024-06'];

      for (const validMonth of validMonths) {
        const invitation = new Invitation({
          fromUserId: testUser1._id,
          toEmail: `recipient${validMonth}@example.com`,
          month: validMonth
        });

        await expect(invitation.save()).resolves.toBeDefined();
      }
    });

    test('should validate type enum', async () => {
      const invitation = new Invitation({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        type: 'invalid_type'
      });

      const error = invitation.validateSync();
      expect(error.errors.type).toBeDefined();
    });

    test('should validate status enum', async () => {
      const invitation = new Invitation({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        status: 'invalid_status'
      });

      const error = invitation.validateSync();
      expect(error.errors.status).toBeDefined();
    });

    test('should validate metadata.priority enum', async () => {
      const invitation = new Invitation({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        metadata: {
          priority: 'invalid_priority'
        }
      });

      const error = invitation.validateSync();
      expect(error.errors['metadata.priority']).toBeDefined();
    });

    test('should validate reminder.type enum', async () => {
      const invitation = new Invitation({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        reminders: [{
          type: 'invalid_reminder_type',
          sentAt: new Date()
        }]
      });

      const error = invitation.validateSync();
      expect(error.errors['reminders.0.type']).toBeDefined();
    });
  });

  describe('Unique Constraints', () => {
    test('should enforce unique token', async () => {
      const token = 'duplicate_token_123456789012345678901234567890123456789012345678901234';
      
      // Create first invitation
      const invitation1 = new Invitation({
        fromUserId: testUser1._id,
        toEmail: 'recipient1@example.com',
        month: '2025-01',
        token: token
      });
      await invitation1.save();

      // Try to create second invitation with same token
      const invitation2 = new Invitation({
        fromUserId: testUser1._id,
        toEmail: 'recipient2@example.com',
        month: '2025-01',
        token: token
      });

      await expect(invitation2.save()).rejects.toThrow();
    });

    test('should enforce unique combination of fromUserId, toEmail, month', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      };

      // Create first invitation
      const invitation1 = new Invitation(invitationData);
      await invitation1.save();

      // Try to create duplicate
      const invitation2 = new Invitation(invitationData);

      await expect(invitation2.save()).rejects.toThrow();
    });

    test('should allow same fromUserId-toEmail for different months', async () => {
      const baseData = {
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com'
      };

      const invitation1 = new Invitation({ ...baseData, month: '2025-01' });
      const invitation2 = new Invitation({ ...baseData, month: '2025-02' });

      await invitation1.save();
      await expect(invitation2.save()).resolves.toBeDefined();
    });

    test('should allow same toEmail-month for different fromUserId', async () => {
      const baseData = {
        toEmail: 'recipient@example.com',
        month: '2025-01'
      };

      const invitation1 = new Invitation({ ...baseData, fromUserId: testUser1._id });
      const invitation2 = new Invitation({ ...baseData, fromUserId: testUser2._id });

      await invitation1.save();
      await expect(invitation2.save()).resolves.toBeDefined();
    });
  });

  describe('Indexes', () => {
    test('should have unique index on token', async () => {
      const indexes = await Invitation.collection.getIndexes();
      const tokenIndex = Object.keys(indexes).find(key => 
        indexes[key].some(index => index[0] === 'token')
      );
      expect(tokenIndex).toBeDefined();
    });

    test('should have index on fromUserId', async () => {
      const indexes = await Invitation.collection.getIndexes();
      const fromUserIndex = Object.keys(indexes).find(key => 
        indexes[key].some(index => index[0] === 'fromUserId')
      );
      expect(fromUserIndex).toBeDefined();
    });

    test('should have compound index on month and status', async () => {
      const indexes = await Invitation.collection.getIndexes();
      const monthStatusIndex = Object.keys(indexes).find(key => {
        const index = indexes[key];
        return index.some(field => field[0] === 'month') && 
               index.some(field => field[0] === 'status');
      });
      expect(monthStatusIndex).toBeDefined();
    });

    test('should have index on expiresAt', async () => {
      const indexes = await Invitation.collection.getIndexes();
      const expiresIndex = Object.keys(indexes).find(key => 
        indexes[key].some(index => index[0] === 'expiresAt')
      );
      expect(expiresIndex).toBeDefined();
    });

    test('should have compound unique index on fromUserId, toEmail, month', async () => {
      const indexes = await Invitation.collection.getIndexes();
      const compoundIndex = Object.keys(indexes).find(key => {
        const index = indexes[key];
        return index.some(field => field[0] === 'fromUserId') && 
               index.some(field => field[0] === 'toEmail') &&
               index.some(field => field[0] === 'month');
      });
      expect(compoundIndex).toBeDefined();
    });
  });

  describe('Default Values', () => {
    test('should set default values correctly', async () => {
      const invitation = new Invitation({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      });

      expect(invitation.token).toHaveLength(64);
      expect(invitation.shortCode).toHaveLength(6);
      expect(invitation.type).toBe('external');
      expect(invitation.status).toBe('queued');
      expect(invitation.tracking.createdAt).toBeInstanceOf(Date);
      expect(invitation.metadata.priority).toBe('normal');
      
      // ExpiresAt should be 60 days from now
      const expectedExpiry = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000);
      const timeDiff = Math.abs(invitation.expiresAt.getTime() - expectedExpiry.getTime());
      expect(timeDiff).toBeLessThan(1000); // Within 1 second
    });

    test('should generate unique tokens', async () => {
      const tokens = new Set();
      
      for (let i = 0; i < 10; i++) {
        const invitation = new Invitation({
          fromUserId: testUser1._id,
          toEmail: `recipient${i}@example.com`,
          month: '2025-01'
        });
        tokens.add(invitation.token);
      }

      expect(tokens.size).toBe(10); // All tokens should be unique
    });

    test('should generate unique shortCodes', async () => {
      const shortCodes = new Set();
      
      for (let i = 0; i < 10; i++) {
        const invitation = new Invitation({
          fromUserId: testUser1._id,
          toEmail: `recipient${i}@example.com`,
          month: '2025-01'
        });
        shortCodes.add(invitation.shortCode);
      }

      expect(shortCodes.size).toBe(10); // All short codes should be unique
    });
  });

  describe('Instance Methods', () => {
    let invitation;

    beforeEach(async () => {
      invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      });
    });

    describe('isExpired method', () => {
      test('should return false for non-expired invitation', () => {
        expect(invitation.isExpired()).toBe(false);
      });

      test('should return true for expired invitation', () => {
        invitation.expiresAt = new Date(Date.now() - 1000); // 1 second ago
        expect(invitation.isExpired()).toBe(true);
      });

      test('should return false for invitation expiring exactly now', () => {
        invitation.expiresAt = new Date();
        expect(invitation.isExpired()).toBe(false);
      });
    });

    describe('canSendReminder method', () => {
      test('should return true when no reminder exists', () => {
        expect(invitation.canSendReminder('first')).toBe(true);
        expect(invitation.canSendReminder('second')).toBe(true);
        expect(invitation.canSendReminder('final')).toBe(true);
      });

      test('should return false when reminder already sent', () => {
        invitation.reminders.push({
          type: 'first',
          sentAt: new Date()
        });

        expect(invitation.canSendReminder('first')).toBe(false);
        expect(invitation.canSendReminder('second')).toBe(true);
      });

      test('should return false for expired invitation', () => {
        invitation.expiresAt = new Date(Date.now() - 1000);

        expect(invitation.canSendReminder('first')).toBe(false);
      });

      test('should return false for submitted invitation', () => {
        invitation.status = 'submitted';

        expect(invitation.canSendReminder('first')).toBe(false);
      });
    });

    describe('markAction method', () => {
      test('should mark sent action correctly', async () => {
        await invitation.markAction('sent');

        expect(invitation.tracking.sentAt).toBeInstanceOf(Date);
        expect(invitation.status).toBe('sent');
      });

      test('should mark opened action correctly', async () => {
        const metadata = {
          ipAddress: '192.168.1.1',
          userAgent: 'Mozilla/5.0'
        };

        await invitation.markAction('opened', metadata);

        expect(invitation.tracking.openedAt).toBeInstanceOf(Date);
        expect(invitation.status).toBe('opened');
        expect(invitation.tracking.ipAddress).toBe('192.168.1.1');
        expect(invitation.tracking.userAgent).toBe('Mozilla/5.0');
      });

      test('should only set openedAt once', async () => {
        await invitation.markAction('opened');
        const firstOpenedAt = invitation.tracking.openedAt;

        await new Promise(resolve => setTimeout(resolve, 10));
        await invitation.markAction('opened');

        expect(invitation.tracking.openedAt).toEqual(firstOpenedAt);
      });

      test('should mark started action correctly', async () => {
        await invitation.markAction('started');

        expect(invitation.tracking.startedAt).toBeInstanceOf(Date);
        expect(invitation.status).toBe('started');
      });

      test('should only set startedAt once', async () => {
        await invitation.markAction('started');
        const firstStartedAt = invitation.tracking.startedAt;

        await new Promise(resolve => setTimeout(resolve, 10));
        await invitation.markAction('started');

        expect(invitation.tracking.startedAt).toEqual(firstStartedAt);
      });

      test('should mark submitted action correctly', async () => {
        const submissionId = new mongoose.Types.ObjectId();

        await invitation.markAction('submitted', { submissionId });

        expect(invitation.tracking.submittedAt).toBeInstanceOf(Date);
        expect(invitation.status).toBe('submitted');
        expect(invitation.submissionId).toEqual(submissionId);
      });

      test('should save changes to database', async () => {
        await invitation.markAction('opened');

        const savedInvitation = await Invitation.findById(invitation._id);
        expect(savedInvitation.status).toBe('opened');
        expect(savedInvitation.tracking.openedAt).toBeInstanceOf(Date);
      });
    });
  });

  describe('Static Methods', () => {
    describe('findPendingReminders method', () => {
      beforeEach(async () => {
        // Create invitations with different sent dates
        const baseDate = new Date();
        
        // Invitation sent 7 days ago - eligible for first reminder
        await Invitation.create({
          fromUserId: testUser1._id,
          toEmail: 'reminder1@example.com',
          month: '2025-01',
          status: 'sent',
          tracking: {
            sentAt: new Date(baseDate.getTime() - 7 * 24 * 60 * 60 * 1000)
          }
        });

        // Invitation sent 14 days ago with first reminder - eligible for second
        await Invitation.create({
          fromUserId: testUser1._id,
          toEmail: 'reminder2@example.com',
          month: '2025-01',
          status: 'opened',
          tracking: {
            sentAt: new Date(baseDate.getTime() - 14 * 24 * 60 * 60 * 1000)
          },
          reminders: [{
            type: 'first',
            sentAt: new Date(baseDate.getTime() - 7 * 24 * 60 * 60 * 1000)
          }]
        });

        // Invitation sent recently - not eligible for reminders
        await Invitation.create({
          fromUserId: testUser1._id,
          toEmail: 'recent@example.com',
          month: '2025-01',
          status: 'sent',
          tracking: {
            sentAt: new Date(baseDate.getTime() - 1 * 24 * 60 * 60 * 1000)
          }
        });

        // Submitted invitation - not eligible
        await Invitation.create({
          fromUserId: testUser1._id,
          toEmail: 'submitted@example.com',
          month: '2025-01',
          status: 'submitted',
          tracking: {
            sentAt: new Date(baseDate.getTime() - 10 * 24 * 60 * 60 * 1000)
          }
        });
      });

      test('should find invitations eligible for first reminder', async () => {
        const pendingReminders = await Invitation.findPendingReminders('first', 5);

        expect(pendingReminders).toHaveLength(1);
        expect(pendingReminders[0].toEmail).toBe('reminder1@example.com');
      });

      test('should find invitations eligible for second reminder', async () => {
        const pendingReminders = await Invitation.findPendingReminders('second', 10);

        expect(pendingReminders).toHaveLength(1);
        expect(pendingReminders[0].toEmail).toBe('reminder2@example.com');
      });

      test('should return empty array when no eligible invitations', async () => {
        const pendingReminders = await Invitation.findPendingReminders('final', 30);

        expect(pendingReminders).toHaveLength(0);
      });
    });
  });

  describe('Relations', () => {
    test('should populate fromUserId reference', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      });

      const populatedInvitation = await Invitation.findById(invitation._id).populate('fromUserId');

      expect(populatedInvitation.fromUserId.username).toBe('sender');
      expect(populatedInvitation.fromUserId.email).toBe('sender@example.com');
    });

    test('should populate toUserId reference', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        toUserId: testUser2._id,
        month: '2025-01'
      });

      const populatedInvitation = await Invitation.findById(invitation._id).populate('toUserId');

      expect(populatedInvitation.toUserId.username).toBe('receiver');
    });

    test('should populate submissionId reference', async () => {
      const submission = await Submission.create({
        userId: testUser2._id,
        month: '2025-01',
        responses: [{
          questionId: 'q1',
          type: 'text',
          answer: 'Test answer'
        }]
      });

      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        submissionId: submission._id,
        status: 'submitted'
      });

      const populatedInvitation = await Invitation.findById(invitation._id).populate('submissionId');

      expect(populatedInvitation.submissionId.month).toBe('2025-01');
      expect(populatedInvitation.submissionId.responses).toHaveLength(1);
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty strings in optional fields', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        tracking: {
          ipAddress: '',
          userAgent: '',
          referrer: ''
        },
        metadata: {
          template: '',
          customMessage: ''
        }
      });

      expect(invitation.tracking.ipAddress).toBe('');
      expect(invitation.metadata.template).toBe('');
    });

    test('should handle null values in optional fields', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        toUserId: null,
        tracking: {
          ipAddress: null,
          userAgent: null
        }
      });

      expect(invitation.toUserId).toBeNull();
      expect(invitation.tracking.ipAddress).toBeNull();
    });

    test('should handle maximum reminder array', async () => {
      const reminders = [
        { type: 'first', sentAt: new Date() },
        { type: 'second', sentAt: new Date() },
        { type: 'final', sentAt: new Date() }
      ];

      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        reminders: reminders
      });

      expect(invitation.reminders).toHaveLength(3);
      expect(invitation.reminders[0].type).toBe('first');
      expect(invitation.reminders[2].type).toBe('final');
    });

    test('should handle custom expiry date', async () => {
      const customExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        expiresAt: customExpiry
      });

      expect(invitation.expiresAt).toEqual(customExpiry);
    });

    test('should handle invalid ObjectId references', async () => {
      const invalidId = new mongoose.Types.ObjectId();

      const invitation = await Invitation.create({
        fromUserId: invalidId,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        toUserId: invalidId,
        submissionId: invalidId
      });

      expect(invitation.fromUserId).toEqual(invalidId);
      expect(invitation.toUserId).toEqual(invalidId);
      expect(invitation.submissionId).toEqual(invalidId);
    });

    test('should handle complex metadata', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01',
        metadata: {
          template: 'custom_template_v2',
          customMessage: 'Please join us for this month!',
          priority: 'high'
        }
      });

      expect(invitation.metadata.template).toBe('custom_template_v2');
      expect(invitation.metadata.customMessage).toContain('Please join');
      expect(invitation.metadata.priority).toBe('high');
    });

    test('should handle all status transitions', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      });

      const statusFlow = ['queued', 'sent', 'opened', 'started', 'submitted'];

      for (let i = 0; i < statusFlow.length - 1; i++) {
        invitation.status = statusFlow[i + 1];
        await invitation.save();
        expect(invitation.status).toBe(statusFlow[i + 1]);
      }
    });

    test('should handle bounced and cancelled statuses', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      });

      invitation.status = 'bounced';
      invitation.tracking.bounceReason = 'Invalid email address';
      await invitation.save();

      expect(invitation.status).toBe('bounced');
      expect(invitation.tracking.bounceReason).toBe('Invalid email address');

      invitation.status = 'cancelled';
      await invitation.save();

      expect(invitation.status).toBe('cancelled');
    });
  });

  describe('Timestamps', () => {
    test('should automatically set createdAt and updatedAt', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      });

      expect(invitation.createdAt).toBeInstanceOf(Date);
      expect(invitation.updatedAt).toBeInstanceOf(Date);
      expect(invitation.tracking.createdAt).toBeInstanceOf(Date);
    });

    test('should update updatedAt on save', async () => {
      const invitation = await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'recipient@example.com',
        month: '2025-01'
      });

      const originalUpdatedAt = invitation.updatedAt;

      // Wait and update
      await new Promise(resolve => setTimeout(resolve, 10));
      
      invitation.status = 'sent';
      await invitation.save();

      expect(invitation.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt.getTime());
    });
  });
});