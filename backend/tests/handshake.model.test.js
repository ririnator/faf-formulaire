const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');
const Handshake = require('../models/Handshake');
const User = require('../models/User');

describe('Handshake Model Tests', () => {
  let testUser1, testUser2, testUser3;

  beforeEach(async () => {
    await cleanupBetweenTests();

    // Create test users
    testUser1 = await User.create({
      username: 'user1',
      email: 'user1@example.com',
      password: 'password123'
    });

    testUser2 = await User.create({
      username: 'user2',
      email: 'user2@example.com',
      password: 'password123'
    });

    testUser3 = await User.create({
      username: 'user3',
      email: 'user3@example.com',
      password: 'password123'
    });
  });

  describe('Schema Validation', () => {
    test('should create valid handshake with required fields', async () => {
      const handshakeData = {
        requesterId: testUser1._id,
        targetId: testUser2._id
      };

      const handshake = new Handshake(handshakeData);
      const savedHandshake = await handshake.save();

      expect(savedHandshake.requesterId).toEqual(testUser1._id);
      expect(savedHandshake.targetId).toEqual(testUser2._id);
      expect(savedHandshake.status).toBe('pending');
      expect(savedHandshake.requestedAt).toBeInstanceOf(Date);
      expect(savedHandshake.expiresAt).toBeInstanceOf(Date);
      expect(savedHandshake.metadata.initiatedBy).toBe('manual');
    });

    test('should fail validation without required requesterId', async () => {
      const handshakeData = {
        targetId: testUser2._id
      };

      const handshake = new Handshake(handshakeData);

      await expect(handshake.save()).rejects.toThrow();
    });

    test('should fail validation without required targetId', async () => {
      const handshakeData = {
        requesterId: testUser1._id
      };

      const handshake = new Handshake(handshakeData);

      await expect(handshake.save()).rejects.toThrow();
    });

    test('should validate status enum', async () => {
      const handshakeData = {
        requesterId: testUser1._id,
        targetId: testUser2._id,
        status: 'invalid_status'
      };

      const handshake = new Handshake(handshakeData);

      await expect(handshake.save()).rejects.toThrow();
    });

    test('should validate message maxlength', async () => {
      const handshakeData = {
        requesterId: testUser1._id,
        targetId: testUser2._id,
        message: 'a'.repeat(501)
      };

      const handshake = new Handshake(handshakeData);

      await expect(handshake.save()).rejects.toThrow();
    });

    test('should validate responseMessage maxlength', async () => {
      const handshakeData = {
        requesterId: testUser1._id,
        targetId: testUser2._id,
        responseMessage: 'b'.repeat(501)
      };

      const handshake = new Handshake(handshakeData);

      await expect(handshake.save()).rejects.toThrow();
    });

    test('should validate metadata.initiatedBy enum', async () => {
      const handshakeData = {
        requesterId: testUser1._id,
        targetId: testUser2._id,
        metadata: {
          initiatedBy: 'invalid_initiation'
        }
      };

      const handshake = new Handshake(handshakeData);

      await expect(handshake.save()).rejects.toThrow();
    });
  });

  describe('Unique Constraints', () => {
    test('should enforce unique requesterId-targetId combination', async () => {
      const handshakeData = {
        requesterId: testUser1._id,
        targetId: testUser2._id
      };

      // Create first handshake
      const handshake1 = new Handshake(handshakeData);
      await handshake1.save();

      // Try to create duplicate
      const handshake2 = new Handshake(handshakeData);

      await expect(handshake2.save()).rejects.toThrow();
    });

    test('should allow reverse relationship as separate handshake', async () => {
      // Create handshake from user1 to user2
      const handshake1 = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });
      await handshake1.save();

      // Create handshake from user2 to user1 (reverse should be allowed)
      const handshake2 = new Handshake({
        requesterId: testUser2._id,
        targetId: testUser1._id
      });

      await expect(handshake2.save()).resolves.toBeDefined();
    });

    test('should allow different user combinations', async () => {
      const handshake1 = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });
      await handshake1.save();

      const handshake2 = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser3._id
      });

      await expect(handshake2.save()).resolves.toBeDefined();
    });
  });

  describe('Indexes', () => {
    test('should have compound unique index on requesterId and targetId', async () => {
      const indexes = await Handshake.collection.getIndexes();
      const compoundIndex = Object.keys(indexes).find(key => {
        const index = indexes[key];
        return index.some(field => field[0] === 'requesterId') && 
               index.some(field => field[0] === 'targetId');
      });
      expect(compoundIndex).toBeDefined();
    });

    test('should have index on targetId and status', async () => {
      const indexes = await Handshake.collection.getIndexes();
      const targetStatusIndex = Object.keys(indexes).find(key => {
        const index = indexes[key];
        return index.some(field => field[0] === 'targetId') && 
               index.some(field => field[0] === 'status');
      });
      expect(targetStatusIndex).toBeDefined();
    });

    test('should have index on requesterId and status', async () => {
      const indexes = await Handshake.collection.getIndexes();
      const requesterStatusIndex = Object.keys(indexes).find(key => {
        const index = indexes[key];
        return index.some(field => field[0] === 'requesterId') && 
               index.some(field => field[0] === 'status');
      });
      expect(requesterStatusIndex).toBeDefined();
    });

    test('should have index on expiresAt', async () => {
      const indexes = await Handshake.collection.getIndexes();
      const expiresIndex = Object.keys(indexes).find(key => 
        indexes[key].some(index => index[0] === 'expiresAt')
      );
      expect(expiresIndex).toBeDefined();
    });
  });

  describe('Default Values', () => {
    test('should set default values correctly', async () => {
      const handshake = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });

      expect(handshake.status).toBe('pending');
      expect(handshake.requestedAt).toBeInstanceOf(Date);
      expect(handshake.expiresAt).toBeInstanceOf(Date);
      expect(handshake.metadata.initiatedBy).toBe('manual');
      
      // ExpiresAt should be 30 days from now
      const expectedExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const timeDiff = Math.abs(handshake.expiresAt.getTime() - expectedExpiry.getTime());
      expect(timeDiff).toBeLessThan(1000); // Within 1 second
    });
  });

  describe('Instance Methods', () => {
    let handshake;

    beforeEach(async () => {
      handshake = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });
      await handshake.save();
    });

    describe('accept method', () => {
      test('should accept handshake successfully', async () => {
        const responseMessage = 'Happy to connect!';
        
        await handshake.accept(responseMessage);

        expect(handshake.status).toBe('accepted');
        expect(handshake.respondedAt).toBeInstanceOf(Date);
        expect(handshake.responseMessage).toBe(responseMessage);
      });

      test('should accept without response message', async () => {
        await handshake.accept();

        expect(handshake.status).toBe('accepted');
        expect(handshake.respondedAt).toBeInstanceOf(Date);
        expect(handshake.responseMessage).toBeUndefined();
      });

      test('should save changes to database', async () => {
        await handshake.accept('Accepted!');

        const savedHandshake = await Handshake.findById(handshake._id);
        expect(savedHandshake.status).toBe('accepted');
        expect(savedHandshake.responseMessage).toBe('Accepted!');
      });
    });

    describe('decline method', () => {
      test('should decline handshake successfully', async () => {
        const responseMessage = 'Not interested, sorry.';
        
        await handshake.decline(responseMessage);

        expect(handshake.status).toBe('declined');
        expect(handshake.respondedAt).toBeInstanceOf(Date);
        expect(handshake.responseMessage).toBe(responseMessage);
      });

      test('should decline without response message', async () => {
        await handshake.decline();

        expect(handshake.status).toBe('declined');
        expect(handshake.respondedAt).toBeInstanceOf(Date);
        expect(handshake.responseMessage).toBeUndefined();
      });

      test('should save changes to database', async () => {
        await handshake.decline('Declined!');

        const savedHandshake = await Handshake.findById(handshake._id);
        expect(savedHandshake.status).toBe('declined');
        expect(savedHandshake.responseMessage).toBe('Declined!');
      });
    });

    describe('isExpired method', () => {
      test('should return false for non-expired handshake', () => {
        expect(handshake.isExpired()).toBe(false);
      });

      test('should return true for expired handshake', () => {
        handshake.expiresAt = new Date(Date.now() - 1000); // 1 second ago
        expect(handshake.isExpired()).toBe(true);
      });

      test('should return false for handshake expiring exactly now', () => {
        handshake.expiresAt = new Date();
        // Should be false because current time should be slightly after
        expect(handshake.isExpired()).toBe(false);
      });
    });
  });

  describe('Static Methods', () => {
    describe('createMutual method', () => {
      test('should create mutual handshake successfully', async () => {
        const handshake = await Handshake.createMutual(
          testUser1._id, 
          testUser2._id, 
          1 // User1 is initiator
        );

        expect(handshake.requesterId).toEqual(testUser1._id);
        expect(handshake.targetId).toEqual(testUser2._id);
        expect(handshake.metadata.initiatedBy).toBe('manual');
        expect(handshake.status).toBe('pending');
      });

      test('should create handshake with second user as initiator', async () => {
        const handshake = await Handshake.createMutual(
          testUser1._id, 
          testUser2._id, 
          2 // User2 is initiator
        );

        expect(handshake.requesterId).toEqual(testUser2._id);
        expect(handshake.targetId).toEqual(testUser1._id);
        expect(handshake.metadata.initiatedBy).toBe('manual');
      });

      test('should throw error if handshake already exists (same direction)', async () => {
        // Create initial handshake
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id
        });

        await expect(
          Handshake.createMutual(testUser1._id, testUser2._id, 1)
        ).rejects.toThrow('Handshake déjà existant');
      });

      test('should throw error if handshake already exists (reverse direction)', async () => {
        // Create initial handshake
        await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser1._id
        });

        await expect(
          Handshake.createMutual(testUser1._id, testUser2._id, 1)
        ).rejects.toThrow('Handshake déjà existant');
      });
    });

    describe('checkPermission method', () => {
      test('should return true for accepted handshake (requester to target)', async () => {
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'accepted'
        });

        const hasPermission = await Handshake.checkPermission(testUser1._id, testUser2._id);
        expect(hasPermission).toBe(true);
      });

      test('should return true for accepted handshake (target to requester)', async () => {
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'accepted'
        });

        const hasPermission = await Handshake.checkPermission(testUser2._id, testUser1._id);
        expect(hasPermission).toBe(true);
      });

      test('should return false for pending handshake', async () => {
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'pending'
        });

        const hasPermission = await Handshake.checkPermission(testUser1._id, testUser2._id);
        expect(hasPermission).toBe(false);
      });

      test('should return false for declined handshake', async () => {
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'declined'
        });

        const hasPermission = await Handshake.checkPermission(testUser1._id, testUser2._id);
        expect(hasPermission).toBe(false);
      });

      test('should return false for non-existent handshake', async () => {
        const hasPermission = await Handshake.checkPermission(testUser1._id, testUser2._id);
        expect(hasPermission).toBe(false);
      });

      test('should return false for blocked handshake', async () => {
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'blocked'
        });

        const hasPermission = await Handshake.checkPermission(testUser1._id, testUser2._id);
        expect(hasPermission).toBe(false);
      });

      test('should return false for expired handshake', async () => {
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'expired'
        });

        const hasPermission = await Handshake.checkPermission(testUser1._id, testUser2._id);
        expect(hasPermission).toBe(false);
      });
    });
  });

  describe('Relations', () => {
    test('should populate requesterId reference', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });

      const populatedHandshake = await Handshake.findById(handshake._id).populate('requesterId');

      expect(populatedHandshake.requesterId.username).toBe('user1');
      expect(populatedHandshake.requesterId.email).toBe('user1@example.com');
    });

    test('should populate targetId reference', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });

      const populatedHandshake = await Handshake.findById(handshake._id).populate('targetId');

      expect(populatedHandshake.targetId.username).toBe('user2');
      expect(populatedHandshake.targetId.email).toBe('user2@example.com');
    });

    test('should populate both requesterId and targetId', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });

      const populatedHandshake = await Handshake.findById(handshake._id)
        .populate('requesterId')
        .populate('targetId');

      expect(populatedHandshake.requesterId.username).toBe('user1');
      expect(populatedHandshake.targetId.username).toBe('user2');
    });

    test('should populate mutualContacts references', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        metadata: {
          mutualContacts: [testUser3._id]
        }
      });

      const populatedHandshake = await Handshake.findById(handshake._id)
        .populate('metadata.mutualContacts');

      expect(populatedHandshake.metadata.mutualContacts).toHaveLength(1);
      expect(populatedHandshake.metadata.mutualContacts[0].username).toBe('user3');
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty message fields', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        message: '',
        responseMessage: ''
      });

      expect(handshake.message).toBe('');
      expect(handshake.responseMessage).toBe('');
    });

    test('should handle null message fields', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        message: null,
        responseMessage: null
      });

      expect(handshake.message).toBeNull();
      expect(handshake.responseMessage).toBeNull();
    });

    test('should handle maximum length messages', async () => {
      const maxMessage = 'a'.repeat(500);
      const maxResponseMessage = 'b'.repeat(500);

      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        message: maxMessage,
        responseMessage: maxResponseMessage
      });

      expect(handshake.message).toHaveLength(500);
      expect(handshake.responseMessage).toHaveLength(500);
    });

    test('should handle empty mutualContacts array', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        metadata: {
          mutualContacts: []
        }
      });

      expect(handshake.metadata.mutualContacts).toEqual([]);
    });

    test('should handle multiple mutualContacts', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        metadata: {
          mutualContacts: [testUser3._id, testUser1._id]
        }
      });

      expect(handshake.metadata.mutualContacts).toHaveLength(2);
      expect(handshake.metadata.mutualContacts[0]).toEqual(testUser3._id);
      expect(handshake.metadata.mutualContacts[1]).toEqual(testUser1._id);
    });

    test('should handle custom expiry date', async () => {
      const customExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        expiresAt: customExpiry
      });

      expect(handshake.expiresAt).toEqual(customExpiry);
    });

    test('should handle invalid ObjectId references', async () => {
      const invalidId = new mongoose.Types.ObjectId();

      const handshake = await Handshake.create({
        requesterId: invalidId,
        targetId: testUser2._id
      });

      expect(handshake.requesterId).toEqual(invalidId);
    });

    test('should handle same user as requester and target (edge case)', async () => {
      // This should be allowed at schema level but might be handled at business logic level
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser1._id
      });

      expect(handshake.requesterId).toEqual(testUser1._id);
      expect(handshake.targetId).toEqual(testUser1._id);
    });
  });

  describe('Timestamps', () => {
    test('should automatically set createdAt and updatedAt', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });

      expect(handshake.createdAt).toBeInstanceOf(Date);
      expect(handshake.updatedAt).toBeInstanceOf(Date);
      expect(handshake.createdAt).toEqual(handshake.updatedAt);
    });

    test('should update updatedAt on save', async () => {
      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id
      });

      const originalUpdatedAt = handshake.updatedAt;

      // Wait a bit and then update
      await new Promise(resolve => setTimeout(resolve, 10));

      handshake.message = 'Updated message';
      await handshake.save();

      expect(handshake.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt.getTime());
    });
  });
});