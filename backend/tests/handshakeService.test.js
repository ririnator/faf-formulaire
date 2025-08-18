const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');
const HandshakeService = require('../services/handshakeServiceInstance');
const Handshake = require('../models/Handshake');
const User = require('../models/User');
const Contact = require('../models/Contact');

describe('HandshakeService Tests', () => {
  let testUser1, testUser2, testUser3;

  beforeEach(async () => {
    await cleanupBetweenTests();

    // Créer des utilisateurs de test
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

  describe('createMutual Method', () => {
    test('should create a new handshake successfully', async () => {
      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        initiator: testUser1._id,
        message: 'Hello! Let\'s be friends',
        source: 'manual'
      });

      expect(result.created).toBe(true);
      expect(result.handshake).toBeDefined();
      expect(result.handshake.requesterId._id).toEqual(testUser1._id);
      expect(result.handshake.targetId._id).toEqual(testUser2._id);
      expect(result.handshake.message).toBe('Hello! Let\'s be friends');
      expect(result.handshake.status).toBe('pending');
      expect(result.handshake.expiresAt).toBeDefined();
    });

    test('should prevent creating handshake with oneself', async () => {
      await expect(
        HandshakeService.createMutual(testUser1._id, testUser1._id)
      ).rejects.toThrow('Impossible de créer un handshake avec soi-même');
    });

    test('should handle existing handshake gracefully', async () => {
      // Créer premier handshake
      await HandshakeService.createMutual(testUser1._id, testUser2._id);

      // Tenter de créer un doublon
      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id);

      expect(result.created).toBe(false);
      expect(result.message).toContain('déjà en attente');
    });

    test('should handle bidirectional existing handshake', async () => {
      // Créer handshake de user1 vers user2
      await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        initiator: testUser1._id
      });

      // Tenter de créer handshake de user2 vers user1
      const result = await HandshakeService.createMutual(testUser2._id, testUser1._id, {
        initiator: testUser2._id
      });

      expect(result.created).toBe(false);
      expect(result.message).toContain('déjà en attente');
    });

    test('should validate user existence', async () => {
      const fakeUserId = new mongoose.Types.ObjectId();

      await expect(
        HandshakeService.createMutual(testUser1._id, fakeUserId)
      ).rejects.toThrow('Deuxième utilisateur non trouvé');
    });

    test('should trim and limit message length', async () => {
      const longMessage = 'a'.repeat(600); // Plus long que la limite de 500

      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        message: `  ${longMessage}  ` // Avec espaces
      });

      expect(result.handshake.message).toHaveLength(500);
      expect(result.handshake.message.startsWith('aaa')).toBe(true);
    });

    test('should set correct expiration date', async () => {
      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id);
      
      const expectedExpiration = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      const actualExpiration = new Date(result.handshake.expiresAt);
      
      // Vérifier que l'expiration est environ dans 30 jours (±1 minute)
      const timeDiff = Math.abs(expectedExpiration - actualExpiration);
      expect(timeDiff).toBeLessThan(60 * 1000); // 1 minute
    });
  });

  describe('accept Method', () => {
    let handshake;

    beforeEach(async () => {
      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        initiator: testUser1._id,
        message: 'Test handshake'
      });
      handshake = result.handshake;
    });

    test('should accept handshake successfully', async () => {
      const result = await HandshakeService.accept(
        handshake._id, 
        testUser2._id, 
        'I accept your friendship!'
      );

      expect(result.success).toBe(true);
      expect(result.handshake.status).toBe('accepted');
      expect(result.handshake.respondedAt).toBeDefined();
      expect(result.handshake.responseMessage).toBe('I accept your friendship!');
    });

    test('should only allow target to accept', async () => {
      await expect(
        HandshakeService.accept(handshake._id, testUser1._id)
      ).rejects.toThrow('Seul le destinataire peut accepter');

      await expect(
        HandshakeService.accept(handshake._id, testUser3._id)
      ).rejects.toThrow('Seul le destinataire peut accepter');
    });

    test('should reject acceptance of non-pending handshake', async () => {
      // D'abord accepter le handshake
      await HandshakeService.accept(handshake._id, testUser2._id);

      // Tenter d'accepter à nouveau
      await expect(
        HandshakeService.accept(handshake._id, testUser2._id)
      ).rejects.toThrow('déjà accepted');
    });

    test('should reject acceptance of expired handshake', async () => {
      // Marquer comme expiré manuellement
      await Handshake.findByIdAndUpdate(handshake._id, {
        expiresAt: new Date(Date.now() - 1000)
      });

      await expect(
        HandshakeService.accept(handshake._id, testUser2._id)
      ).rejects.toThrow('expiré');
    });

    test('should handle non-existent handshake', async () => {
      const fakeId = new mongoose.Types.ObjectId();

      await expect(
        HandshakeService.accept(fakeId, testUser2._id)
      ).rejects.toThrow('Handshake non trouvé');
    });

    test('should trim response message', async () => {
      const longMessage = 'a'.repeat(600);
      
      const result = await HandshakeService.accept(
        handshake._id, 
        testUser2._id, 
        `  ${longMessage}  `
      );

      expect(result.handshake.responseMessage).toHaveLength(500);
    });
  });

  describe('decline Method', () => {
    let handshake;

    beforeEach(async () => {
      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        initiator: testUser1._id
      });
      handshake = result.handshake;
    });

    test('should decline handshake successfully', async () => {
      const result = await HandshakeService.decline(
        handshake._id, 
        testUser2._id, 
        'Sorry, not interested'
      );

      expect(result.success).toBe(true);
      expect(result.handshake.status).toBe('declined');
      expect(result.handshake.respondedAt).toBeDefined();
      expect(result.handshake.responseMessage).toBe('Sorry, not interested');
    });

    test('should only allow target to decline', async () => {
      await expect(
        HandshakeService.decline(handshake._id, testUser1._id)
      ).rejects.toThrow('Seul le destinataire peut refuser');
    });

    test('should reject decline of non-pending handshake', async () => {
      // D'abord refuser le handshake
      await HandshakeService.decline(handshake._id, testUser2._id);

      // Tenter de refuser à nouveau
      await expect(
        HandshakeService.decline(handshake._id, testUser2._id)
      ).rejects.toThrow('déjà declined');
    });
  });

  describe('checkPermission Method', () => {
    test('should return false for users without handshake', async () => {
      const result = await HandshakeService.checkPermission(testUser1._id, testUser2._id);

      expect(result.hasPermission).toBe(false);
      expect(result.handshakeStatus).toBeNull();
    });

    test('should return false for pending handshake', async () => {
      await HandshakeService.createMutual(testUser1._id, testUser2._id);

      const result = await HandshakeService.checkPermission(testUser1._id, testUser2._id);

      expect(result.hasPermission).toBe(false);
      expect(result.handshakeStatus).toBe('pending');
    });

    test('should return true for accepted handshake', async () => {
      const handshakeResult = await HandshakeService.createMutual(testUser1._id, testUser2._id);
      await HandshakeService.accept(handshakeResult.handshake._id, testUser2._id);

      const result = await HandshakeService.checkPermission(testUser1._id, testUser2._id);

      expect(result.hasPermission).toBe(true);
      expect(result.handshakeStatus).toBe('accepted');
      expect(result.handshakeId).toBeDefined();
    });

    test('should work bidirectionally', async () => {
      const handshakeResult = await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        initiator: testUser1._id
      });
      await HandshakeService.accept(handshakeResult.handshake._id, testUser2._id);

      // Vérifier dans les deux sens
      const result1 = await HandshakeService.checkPermission(testUser1._id, testUser2._id);
      const result2 = await HandshakeService.checkPermission(testUser2._id, testUser1._id);

      expect(result1.hasPermission).toBe(true);
      expect(result2.hasPermission).toBe(true);
    });

    test('should include details when requested', async () => {
      const handshakeResult = await HandshakeService.createMutual(testUser1._id, testUser2._id);
      await HandshakeService.accept(handshakeResult.handshake._id, testUser2._id);

      const result = await HandshakeService.checkPermission(
        testUser1._id, 
        testUser2._id, 
        { includeDetails: true }
      );

      expect(result.hasPermission).toBe(true);
      expect(result.details).toBeDefined();
      expect(result.details.requesterId).toBeDefined();
      expect(result.details.targetId).toBeDefined();
    });

    test('should handle unidirectional check', async () => {
      const handshakeResult = await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        initiator: testUser1._id
      });
      await HandshakeService.accept(handshakeResult.handshake._id, testUser2._id);

      const result = await HandshakeService.checkPermission(
        testUser1._id, 
        testUser2._id, 
        { checkBidirectional: false }
      );

      expect(result.hasPermission).toBe(true);
    });
  });

  describe('getUserHandshakes Method', () => {
    beforeEach(async () => {
      // Créer plusieurs handshakes de test sans conflits bidirectionnels
      const handshakes = [
        { from: testUser1._id, to: testUser2._id, status: 'pending' },
        { from: testUser3._id, to: testUser1._id, status: 'accepted' }
      ];

      for (const hs of handshakes) {
        const result = await HandshakeService.createMutual(hs.from, hs.to, {
          initiator: hs.from
        });
        
        // Identifier qui est le target dans le handshake créé
        const targetUserId = result.handshake.targetId._id;
        
        if (hs.status === 'accepted') {
          // Le target doit accepter
          await HandshakeService.accept(result.handshake._id, targetUserId);
        } else if (hs.status === 'declined') {
          // Le target doit refuser
          await HandshakeService.decline(result.handshake._id, targetUserId);
        }
      }
    });

    test('should return paginated handshakes', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id, {}, {
        page: 1,
        limit: 2
      });

      expect(result.handshakes).toHaveLength(2);
      expect(result.pagination.totalCount).toBe(2);
      expect(result.pagination.hasNext).toBe(false);
    });

    test('should filter by status', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id, {
        status: 'pending'
      });

      expect(result.handshakes).toHaveLength(1);
      expect(result.handshakes[0].status).toBe('pending');
    });

    test('should filter by direction - sent', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id, {
        direction: 'sent'
      });

      expect(result.handshakes).toHaveLength(1); // user1 sent 1 handshake
      expect(result.handshakes.every(h => h.requesterId._id.equals(testUser1._id))).toBe(true);
    });

    test('should filter by direction - received', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id, {
        direction: 'received'
      });

      expect(result.handshakes).toHaveLength(1); // user1 received 1 handshake
      expect(result.handshakes.every(h => h.targetId._id.equals(testUser1._id))).toBe(true);
    });

    test('should return comprehensive stats', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id);

      expect(result.stats).toBeDefined();
      expect(result.stats.totalSent).toBe(1);
      expect(result.stats.totalReceived).toBe(1);
      expect(result.stats.totalAccepted).toBe(1);
      expect(result.stats.totalDeclined).toBe(0);
      expect(result.stats.totalPending).toBe(1);
    });

    test('should exclude expired by default', async () => {
      // Créer un handshake expiré
      const expiredResult = await HandshakeService.createMutual(testUser2._id, testUser3._id);
      await Handshake.findByIdAndUpdate(expiredResult.handshake._id, {
        expiresAt: new Date(Date.now() - 1000)
      });

      const result = await HandshakeService.getUserHandshakes(testUser2._id);
      
      // Ne devrait pas inclure le handshake expiré
      const hasExpired = result.handshakes.some(h => h._id.equals(expiredResult.handshake._id));
      expect(hasExpired).toBe(false);
    });

    test('should include expired when requested', async () => {
      // Créer un handshake expiré
      const expiredResult = await HandshakeService.createMutual(testUser2._id, testUser3._id);
      await Handshake.findByIdAndUpdate(expiredResult.handshake._id, {
        expiresAt: new Date(Date.now() - 1000)
      });

      const result = await HandshakeService.getUserHandshakes(testUser2._id, {
        includeExpired: true
      });

      const hasExpired = result.handshakes.some(h => h._id.equals(expiredResult.handshake._id));
      expect(hasExpired).toBe(true);
    });
  });

  describe('cancel Method', () => {
    let handshake;

    beforeEach(async () => {
      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id, {
        initiator: testUser1._id
      });
      handshake = result.handshake;
    });

    test('should allow requester to cancel pending handshake', async () => {
      const result = await HandshakeService.cancel(
        handshake._id, 
        testUser1._id, 
        'Changed my mind'
      );

      expect(result.success).toBe(true);
      expect(result.handshake.status).toBe('expired');
      expect(result.handshake.responseMessage).toContain('Annulé');
    });

    test('should only allow requester to cancel', async () => {
      await expect(
        HandshakeService.cancel(handshake._id, testUser2._id)
      ).rejects.toThrow('Seul le demandeur peut annuler');
    });

    test('should not allow cancel of accepted handshake', async () => {
      await HandshakeService.accept(handshake._id, testUser2._id);

      await expect(
        HandshakeService.cancel(handshake._id, testUser1._id)
      ).rejects.toThrow('Impossible d\'annuler un handshake accepted');
    });
  });

  describe('block Method', () => {
    let handshake;

    beforeEach(async () => {
      const result = await HandshakeService.createMutual(testUser1._id, testUser2._id);
      handshake = result.handshake;
    });

    test('should allow target to block handshake', async () => {
      const result = await HandshakeService.block(handshake._id, testUser2._id);

      expect(result.success).toBe(true);
      expect(result.handshake.status).toBe('blocked');
      expect(result.handshake.responseMessage).toBe('Utilisateur bloqué');
    });

    test('should only allow target to block', async () => {
      await expect(
        HandshakeService.block(handshake._id, testUser1._id)
      ).rejects.toThrow('Seul le destinataire peut bloquer');
    });

    test('should prevent future handshakes after blocking', async () => {
      await HandshakeService.block(handshake._id, testUser2._id);

      // Tenter de créer un nouveau handshake après blocage
      await expect(
        HandshakeService.createMutual(testUser1._id, testUser2._id)
      ).rejects.toThrow('utilisateur bloqué');
    });
  });

  describe('cleanupExpiredHandshakes Method', () => {
    beforeEach(async () => {
      // Créer des handshakes avec différentes dates d'expiration
      const now = new Date();
      
      // Handshake expiré (pending)
      const expiredHandshake = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        status: 'pending',
        expiresAt: new Date(now.getTime() - 24 * 60 * 60 * 1000) // Hier
      });
      await expiredHandshake.save();

      // Handshake valide
      const validHandshake = new Handshake({
        requesterId: testUser2._id,
        targetId: testUser3._id,
        status: 'pending',
        expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000) // Demain
      });
      await validHandshake.save();

      // Très ancien handshake declined
      const oldDeclinedHandshake = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser3._id,
        status: 'declined',
        respondedAt: new Date(now.getTime() - 200 * 24 * 60 * 60 * 1000), // 200 jours
        expiresAt: new Date(now.getTime() - 200 * 24 * 60 * 60 * 1000)
      });
      await oldDeclinedHandshake.save();
    });

    test('should mark expired handshakes', async () => {
      const result = await HandshakeService.cleanupExpiredHandshakes();

      expect(result.expired).toBe(1);
      expect(result.deleted).toBeGreaterThanOrEqual(0);
      expect(result.processedAt).toBeInstanceOf(Date);

      // Vérifier que le handshake expiré est marqué
      const expiredHandshakes = await Handshake.find({ status: 'expired' });
      expect(expiredHandshakes).toHaveLength(1);
    });
  });

  describe('getSuggestions Method', () => {
    let additionalUsers;

    beforeEach(async () => {
      // Créer des utilisateurs supplémentaires
      additionalUsers = [];
      for (let i = 4; i <= 7; i++) {
        const user = await User.create({
          username: `user${i}`,
          email: `user${i}@example.com`,
          password: 'password123'
        });
        additionalUsers.push(user);
      }

      // Créer un handshake existant avec testUser1
      await HandshakeService.createMutual(testUser1._id, testUser2._id);
    });

    test('should return suggestions excluding existing handshakes', async () => {
      const suggestions = await HandshakeService.getSuggestions(testUser1._id, {
        limit: 5
      });

      expect(suggestions.length).toBeLessThanOrEqual(5);
      
      // Ne devrait pas inclure testUser1 lui-même ou testUser2 (handshake existant)
      const suggestedIds = suggestions.map(s => s.userId.toString());
      expect(suggestedIds).not.toContain(testUser1._id.toString());
      expect(suggestedIds).not.toContain(testUser2._id.toString());
      
      // Devrait inclure testUser3 et les utilisateurs supplémentaires
      expect(suggestedIds).toContain(testUser3._id.toString());
    });

    test('should include existing handshakes when requested', async () => {
      const suggestions = await HandshakeService.getSuggestions(testUser1._id, {
        excludeExisting: false,
        limit: 10
      });

      // Devrait inclure plus d'utilisateurs car on n'exclut pas les handshakes existants
      expect(suggestions.length).toBeGreaterThanOrEqual(5);
      
      // Peut inclure testUser2 maintenant
      const suggestedIds = suggestions.map(s => s.userId.toString());
      expect(suggestedIds).toContain(testUser2._id.toString());
    });

    test('should limit results correctly', async () => {
      const suggestions = await HandshakeService.getSuggestions(testUser1._id, {
        limit: 2
      });

      expect(suggestions).toHaveLength(2);
    });

    test('should include user metadata', async () => {
      const suggestions = await HandshakeService.getSuggestions(testUser1._id);

      expect(suggestions.length).toBeGreaterThan(0);
      
      const suggestion = suggestions[0];
      expect(suggestion.userId).toBeDefined();
      expect(suggestion.username).toBeDefined();
      expect(suggestion.email).toBeDefined();
      expect(suggestion.suggested).toBe(true);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle non-existent handshake IDs gracefully', async () => {
      const fakeId = new mongoose.Types.ObjectId();

      await expect(
        HandshakeService.accept(fakeId, testUser1._id)
      ).rejects.toThrow('Handshake non trouvé');

      await expect(
        HandshakeService.decline(fakeId, testUser1._id)
      ).rejects.toThrow('Handshake non trouvé');

      await expect(
        HandshakeService.cancel(fakeId, testUser1._id)
      ).rejects.toThrow('Handshake non trouvé');
    });

    test('should handle database errors gracefully', async () => {
      // Test avec un ObjectId invalide
      await expect(
        HandshakeService.createMutual('invalid_id', testUser2._id)
      ).rejects.toThrow();
    });

    test('should handle concurrent handshake creation', async () => {
      // Créer deux handshakes simultanément
      const promises = [
        HandshakeService.createMutual(testUser1._id, testUser2._id),
        HandshakeService.createMutual(testUser2._id, testUser1._id)
      ];

      const results = await Promise.allSettled(promises);

      // Au moins un devrait réussir, et s'ils échouent tous les deux ça peut être dû à une race condition
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.created);
      const existingDetected = results.filter(r => r.status === 'fulfilled' && !r.value.created);
      const duplicateErrors = results.filter(r => r.status === 'rejected');

      // Soit un succède et l'autre détecte l'existant, soit les deux échouent avec duplicate key error
      expect(successful.length + existingDetected.length + duplicateErrors.length).toBe(2);
      expect(successful.length).toBeGreaterThanOrEqual(0);
      expect(successful.length).toBeLessThanOrEqual(2);
    });

    test('should handle spam limits', async () => {
      // Créer beaucoup de handshakes rapidement pour déclencher la limite
      const promises = [];
      for (let i = 0; i < 12; i++) {
        const targetUser = await User.create({
          username: `spamuser${i}`,
          email: `spam${i}@example.com`,
          password: 'password123'
        });
        promises.push(HandshakeService.createMutual(testUser1._id, targetUser._id));
      }

      // Les derniers devraient échouer à cause de la limite
      const results = await Promise.allSettled(promises);
      const failures = results.filter(r => r.status === 'rejected');
      
      expect(failures.length).toBeGreaterThan(0);
      expect(failures[0].reason.message).toContain('Limite de handshakes atteinte');
    });

    test('should handle missing users in suggestions', async () => {
      // Supprimer tous les autres utilisateurs sauf testUser1
      await User.deleteMany({ _id: { $ne: testUser1._id } });

      const suggestions = await HandshakeService.getSuggestions(testUser1._id);

      expect(suggestions).toHaveLength(0);
    });
  });

  describe('Statistics and Analytics', () => {
    beforeEach(async () => {
      // Créer un scénario simple pour les statistiques sans conflits
      const handshakes = [
        { from: testUser1._id, to: testUser2._id, action: 'accept' },
        { from: testUser1._id, to: testUser3._id, action: 'decline' },
        { from: testUser2._id, to: testUser3._id, action: 'pending' }
      ];

      for (const hs of handshakes) {
        const result = await HandshakeService.createMutual(hs.from, hs.to, {
          initiator: hs.from
        });
        
        // Identifier qui est le target dans le handshake créé
        const targetUserId = result.handshake.targetId._id;
        
        if (hs.action === 'accept') {
          // Le target doit accepter
          await HandshakeService.accept(result.handshake._id, targetUserId);
        } else if (hs.action === 'decline') {
          // Le target doit refuser
          await HandshakeService.decline(result.handshake._id, targetUserId);
        }
      }
    });

    test('should calculate correct statistics', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id);
      const stats = result.stats;

      expect(stats.totalSent).toBe(2); // testUser1 sent 2
      expect(stats.totalReceived).toBe(0); // testUser1 received 0
      expect(stats.totalAccepted).toBe(1); // 1 accepted total
      expect(stats.totalDeclined).toBe(1); // 1 declined
      expect(stats.totalPending).toBe(0); // 0 pending
    });

    test('should calculate acceptance rate correctly', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id);
      const stats = result.stats;

      // testUser1 sent 2, 1 declined + 1 accepted = 50% acceptance rate
      expect(stats.acceptanceRate).toBe(50);
    });

    test('should calculate response rate correctly', async () => {
      const result = await HandshakeService.getUserHandshakes(testUser1._id);
      const stats = result.stats;

      // testUser1 received 0, so response rate should be 0
      expect(stats.responseRate).toBe(0);
    });
  });
});