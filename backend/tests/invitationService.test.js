const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');
const InvitationService = require('../services/invitationServiceInstance');
const Invitation = require('../models/Invitation');
const User = require('../models/User');
const Submission = require('../models/Submission');

describe('InvitationService Tests', () => {
  let testUser1, testUser2;
  let securityContext;

  beforeEach(async () => {
    await cleanupBetweenTests();

    // Créer des utilisateurs de test
    testUser1 = await User.create({
      username: 'sender',
      email: 'sender@example.com',
      password: 'password123'
    });

    testUser2 = await User.create({
      username: 'recipient',
      email: 'recipient@example.com',
      password: 'password123'
    });

    // Contexte de sécurité par défaut
    securityContext = {
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      referrer: 'https://example.com'
    };
  });

  describe('Token Generation', () => {
    test('should generate secure tokens with correct properties', () => {
      const tokens = InvitationService.generateSecureTokens();

      expect(tokens.token).toBeDefined();
      expect(tokens.token).toHaveLength(64); // 32 bytes * 2 (hex)
      expect(tokens.shortCode).toBeDefined();
      expect(tokens.shortCode).toHaveLength(8);
      expect(tokens.entropy).toBeGreaterThan(200); // Haute entropie
      expect(tokens.createdAt).toBeInstanceOf(Date);
    });

    test('should generate unique tokens', () => {
      const tokens1 = InvitationService.generateSecureTokens();
      const tokens2 = InvitationService.generateSecureTokens();

      expect(tokens1.token).not.toBe(tokens2.token);
      expect(tokens1.shortCode).not.toBe(tokens2.shortCode);
    });

    test('should generate short codes without ambiguous characters', () => {
      const tokens = InvitationService.generateSecureTokens();
      const ambiguousChars = ['0', '1', 'I', 'O'];
      
      ambiguousChars.forEach(char => {
        expect(tokens.shortCode).not.toContain(char);
      });
    });

    test('should generate anti-transfer codes', () => {
      const token = 'test_token_123';
      const ip = '192.168.1.1';
      const userAgent = 'Test Browser';

      const code1 = InvitationService.generateAntiTransferCode(token, ip, userAgent);
      const code2 = InvitationService.generateAntiTransferCode(token, ip, userAgent);
      const code3 = InvitationService.generateAntiTransferCode(token, ip, 'Different Browser');

      expect(code1).toBe(code2); // Même contexte = même code
      expect(code1).not.toBe(code3); // Contexte différent = code différent
      expect(code1).toHaveLength(16);
    });
  });

  describe('createInvitation Method', () => {
    test('should create invitation for external user', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'external@example.com',
        month: '2025-01',
        metadata: {
          customMessage: 'Please join us!'
        }
      };

      const invitation = await InvitationService.createInvitation(invitationData, securityContext);

      expect(invitation.fromUserId._id).toEqual(testUser1._id);
      expect(invitation.toEmail).toBe('external@example.com');
      expect(invitation.month).toBe('2025-01');
      expect(invitation.type).toBe('external');
      expect(invitation.token).toBeDefined();
      expect(invitation.shortCode).toBeDefined();
      expect(invitation.tracking.ipAddress).toBe(securityContext.ipAddress);
      expect(invitation.metadata.antiTransferCode).toBeDefined();
      expect(invitation.metadata.originalIp).toBe(securityContext.ipAddress);
    });

    test('should create invitation for existing user', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: testUser2.email,
        month: '2025-01'
      };

      const invitation = await InvitationService.createInvitation(invitationData, securityContext);

      expect(invitation.type).toBe('user');
      expect(invitation.toUserId._id).toEqual(testUser2._id);
    });

    test('should prevent duplicate invitations', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'duplicate@example.com',
        month: '2025-01'
      };

      // Créer première invitation
      await InvitationService.createInvitation(invitationData, securityContext);

      // Tenter de créer un doublon
      await expect(
        InvitationService.createInvitation(invitationData, securityContext)
      ).rejects.toThrow('Invitation déjà envoyée');
    });

    test('should validate required fields', async () => {
      await expect(
        InvitationService.createInvitation({}, securityContext)
      ).rejects.toThrow('fromUserId, toEmail et month sont requis');

      await expect(
        InvitationService.createInvitation({
          fromUserId: testUser1._id,
          month: '2025-01'
        }, securityContext)
      ).rejects.toThrow('fromUserId, toEmail et month sont requis');
    });

    test('should handle custom expiration', async () => {
      const customExpiration = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 jours
      
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'custom@example.com',
        month: '2025-01',
        customExpiration
      };

      const invitation = await InvitationService.createInvitation(invitationData, securityContext);

      expect(invitation.expiresAt.getTime()).toBeCloseTo(customExpiration.getTime(), -3);
    });

    test('should calculate security level', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'security@example.com',
        month: '2025-01'
      };

      const highSecurityContext = {
        ipAddress: '8.8.8.8', // IP publique
        userAgent: 'Mozilla/5.0 Chrome/120.0',
        referrer: 'https://trusted-site.com'
      };

      const invitation = await InvitationService.createInvitation(invitationData, highSecurityContext);

      expect(invitation.metadata.securityLevel).toBeDefined();
      expect(['low', 'medium', 'high']).toContain(invitation.metadata.securityLevel);
    });
  });

  describe('validateInvitationToken Method', () => {
    let validInvitation;

    beforeEach(async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'valid@example.com',
        month: '2025-01'
      };

      validInvitation = await InvitationService.createInvitation(invitationData, securityContext);
    });

    test('should validate valid token', async () => {
      const result = await InvitationService.validateInvitationToken(
        validInvitation.token,
        securityContext
      );

      expect(result.valid).toBe(true);
      expect(result.invitation).toBeDefined();
      expect(result.securityLevel).toBeDefined();
      expect(result.remaining.days).toBeGreaterThan(0);
    });

    test('should reject invalid token', async () => {
      const result = await InvitationService.validateInvitationToken('invalid_token');

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('TOKEN_NOT_FOUND');
      expect(result.message).toContain('invalide');
    });

    test('should reject expired token', async () => {
      // Mettre l'invitation comme expirée
      validInvitation.expiresAt = new Date(Date.now() - 1000);
      await validInvitation.save();

      const result = await InvitationService.validateInvitationToken(
        validInvitation.token,
        securityContext
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('TOKEN_EXPIRED');
      expect(result.message).toContain('expiré');
    });

    test('should reject already submitted token', async () => {
      // Marquer comme soumis
      validInvitation.status = 'submitted';
      await validInvitation.save();

      const result = await InvitationService.validateInvitationToken(
        validInvitation.token,
        securityContext
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('ALREADY_SUBMITTED');
      expect(result.message).toContain('déjà été utilisée');
    });

    test('should reject cancelled token', async () => {
      // Marquer comme annulé
      validInvitation.status = 'cancelled';
      await validInvitation.save();

      const result = await InvitationService.validateInvitationToken(
        validInvitation.token,
        securityContext
      );

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('CANCELLED');
      expect(result.message).toContain('annulée');
    });

    test('should update status to opened on first validation', async () => {
      expect(validInvitation.status).toBe('queued');

      await InvitationService.validateInvitationToken(
        validInvitation.token,
        securityContext
      );

      const updatedInvitation = await Invitation.findById(validInvitation._id);
      expect(updatedInvitation.status).toBe('opened');
      expect(updatedInvitation.tracking.openedAt).toBeInstanceOf(Date);
    });

    test('should perform security checks', async () => {
      // Contexte de sécurité différent
      const differentContext = {
        ipAddress: '10.0.0.1',
        userAgent: 'Different Browser/1.0'
      };

      const result = await InvitationService.validateInvitationToken(
        validInvitation.token,
        differentContext
      );

      // Devrait passer mais avec niveau de sécurité élevé
      expect(result.valid).toBe(true);
      expect(result.securityLevel).toBeDefined();
    });
  });

  describe('validateShortCode Method', () => {
    let validInvitation;

    beforeEach(async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'shortcode@example.com',
        month: '2025-01'
      };

      validInvitation = await InvitationService.createInvitation(invitationData, securityContext);
    });

    test('should validate valid short code', async () => {
      const result = await InvitationService.validateShortCode(validInvitation.shortCode);

      expect(result.valid).toBe(true);
      expect(result.invitation).toBeDefined();
    });

    test('should reject invalid short code format', async () => {
      const result = await InvitationService.validateShortCode('INVALID');

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('INVALID_FORMAT');
    });

    test('should reject non-existent short code', async () => {
      const result = await InvitationService.validateShortCode('NOTFOUND');

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('CODE_NOT_FOUND');
    });

    test('should work with month filter', async () => {
      const result = await InvitationService.validateShortCode(
        validInvitation.shortCode,
        '2025-01'
      );

      expect(result.valid).toBe(true);
    });
  });

  describe('markInvitationStarted Method', () => {
    let validInvitation;

    beforeEach(async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'started@example.com',
        month: '2025-01'
      };

      validInvitation = await InvitationService.createInvitation(invitationData, securityContext);
    });

    test('should mark invitation as started', async () => {
      const result = await InvitationService.markInvitationStarted(
        validInvitation.token,
        securityContext
      );

      expect(result.status).toBe('started');
      expect(result.tracking.startedAt).toBeInstanceOf(Date);
    });

    test('should reject invalid token', async () => {
      await expect(
        InvitationService.markInvitationStarted('invalid_token', securityContext)
      ).rejects.toThrow();
    });
  });

  describe('markInvitationSubmitted Method', () => {
    let validInvitation, testSubmission;

    beforeEach(async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'submitted@example.com',
        month: '2025-01'
      };

      validInvitation = await InvitationService.createInvitation(invitationData, securityContext);

      // Créer une submission de test
      testSubmission = await Submission.create({
        userId: testUser2._id,
        month: '2025-01',
        responses: [{
          questionId: 'q1',
          type: 'text',
          answer: 'Test answer'
        }]
      });
    });

    test('should mark invitation as submitted', async () => {
      const result = await InvitationService.markInvitationSubmitted(
        validInvitation.token,
        testSubmission._id,
        securityContext
      );

      expect(result.status).toBe('submitted');
      expect(result.tracking.submittedAt).toBeInstanceOf(Date);
      expect(result.submissionId._id).toEqual(testSubmission._id);
    });

    test('should reject non-existent submission', async () => {
      const fakeSubmissionId = new mongoose.Types.ObjectId();

      await expect(
        InvitationService.markInvitationSubmitted(
          validInvitation.token,
          fakeSubmissionId,
          securityContext
        )
      ).rejects.toThrow('Submission non trouvée');
    });
  });

  describe('cancelInvitation Method', () => {
    let validInvitation;

    beforeEach(async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'cancel@example.com',
        month: '2025-01'
      };

      validInvitation = await InvitationService.createInvitation(invitationData, securityContext);
    });

    test('should cancel invitation successfully', async () => {
      const result = await InvitationService.cancelInvitation(
        validInvitation._id,
        testUser1._id,
        'user_requested'
      );

      expect(result.status).toBe('cancelled');
      expect(result.metadata.cancelledAt).toBeInstanceOf(Date);
      expect(result.metadata.cancelReason).toBe('user_requested');
    });

    test('should reject unauthorized cancellation', async () => {
      await expect(
        InvitationService.cancelInvitation(
          validInvitation._id,
          testUser2._id, // Utilisateur différent
          'unauthorized'
        )
      ).rejects.toThrow('Non autorisé');
    });

    test('should reject cancellation of submitted invitation', async () => {
      // Marquer comme soumis
      validInvitation.status = 'submitted';
      await validInvitation.save();

      await expect(
        InvitationService.cancelInvitation(
          validInvitation._id,
          testUser1._id
        )
      ).rejects.toThrow('Impossible d\'annuler une invitation déjà soumise');
    });
  });

  describe('extendInvitation Method', () => {
    let validInvitation;

    beforeEach(async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'extend@example.com',
        month: '2025-01'
      };

      validInvitation = await InvitationService.createInvitation(invitationData, securityContext);
    });

    test('should extend invitation expiration', async () => {
      const originalExpiration = validInvitation.expiresAt;
      const additionalDays = 15;

      const result = await InvitationService.extendInvitation(
        validInvitation._id,
        testUser1._id,
        additionalDays
      );

      const expectedExpiration = new Date(originalExpiration.getTime() + additionalDays * 24 * 60 * 60 * 1000);
      
      expect(result.expiresAt.getTime()).toBeCloseTo(expectedExpiration.getTime(), -3);
      expect(result.metadata.extendedAt).toBeInstanceOf(Date);
      expect(result.metadata.additionalDays).toBe(additionalDays);
    });

    test('should reject unauthorized extension', async () => {
      await expect(
        InvitationService.extendInvitation(
          validInvitation._id,
          testUser2._id, // Utilisateur différent
          30
        )
      ).rejects.toThrow('Non autorisé');
    });

    test('should reject extension of submitted invitation', async () => {
      validInvitation.status = 'submitted';
      await validInvitation.save();

      await expect(
        InvitationService.extendInvitation(
          validInvitation._id,
          testUser1._id,
          30
        )
      ).rejects.toThrow('Impossible de prolonger');
    });
  });

  describe('getInvitations Method', () => {
    beforeEach(async () => {
      // Créer plusieurs invitations de test
      const invitations = [
        { toEmail: 'test1@example.com', month: '2025-01' },
        { toEmail: 'test2@example.com', status: 'opened', month: '2025-01' },
        { toEmail: 'test3@example.com', status: 'submitted', month: '2025-02' },
        { toEmail: 'test4@example.com', status: 'expired', month: '2025-01' }
      ];

      for (const inv of invitations) {
        const invitation = await InvitationService.createInvitation({
          fromUserId: testUser1._id,
          toEmail: inv.toEmail,
          month: inv.month
        }, securityContext);
        
        // Mettre à jour le statut si spécifié
        if (inv.status && inv.status !== 'queued') {
          await Invitation.findByIdAndUpdate(invitation._id, { status: inv.status });
        }
      }
    });

    test('should return paginated invitations', async () => {
      const result = await InvitationService.getInvitations(testUser1._id, {}, {
        page: 1,
        limit: 2
      });

      expect(result.invitations).toHaveLength(2);
      expect(result.pagination.totalCount).toBe(4);
      expect(result.pagination.totalPages).toBe(2);
      expect(result.pagination.hasNext).toBe(true);
    });

    test('should filter by status', async () => {
      const result = await InvitationService.getInvitations(testUser1._id, {
        status: 'queued'
      });

      expect(result.invitations).toHaveLength(1);
      expect(result.invitations[0].status).toBe('queued');
    });

    test('should filter by month', async () => {
      const result = await InvitationService.getInvitations(testUser1._id, {
        month: '2025-01'
      });

      expect(result.invitations).toHaveLength(3);
      expect(result.invitations.every(inv => inv.month === '2025-01')).toBe(true);
    });

    test('should search by email', async () => {
      const result = await InvitationService.getInvitations(testUser1._id, {
        search: 'test1'
      });

      expect(result.invitations).toHaveLength(1);
      expect(result.invitations[0].toEmail).toBe('test1@example.com');
    });

    test('should return comprehensive stats', async () => {
      const result = await InvitationService.getInvitations(testUser1._id);

      expect(result.stats).toBeDefined();
      expect(result.stats.basic).toBeDefined();
      expect(result.stats.basic.total).toBe(4);
      expect(result.stats.byStatus).toBeDefined();
      expect(result.stats.monthly).toBeDefined();
    });
  });

  describe('Security Utility Methods', () => {
    test('should calculate security level correctly', () => {
      const highSecurityContext = {
        ipAddress: '8.8.8.8',
        userAgent: 'Mozilla/5.0',
        referrer: 'https://trusted.com'
      };

      const lowSecurityContext = {
        ipAddress: '192.168.1.1'
      };

      const highLevel = InvitationService.calculateSecurityLevel(highSecurityContext);
      const lowLevel = InvitationService.calculateSecurityLevel(lowSecurityContext);

      expect(['high', 'medium']).toContain(highLevel);
      expect(['low', 'medium']).toContain(lowLevel);
    });

    test('should calculate token entropy', () => {
      const token = 'abcdef123456'; // Token simple pour test
      const entropy = InvitationService.calculateEntropy(token);

      expect(entropy).toBeGreaterThan(0);
      expect(typeof entropy).toBe('number');
    });

    test('should calculate user agent similarity', () => {
      const ua1 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0';
      const ua2 = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0';
      const ua3 = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/120.0';

      const similarity1 = InvitationService.calculateUserAgentSimilarity(ua1, ua2);
      const similarity2 = InvitationService.calculateUserAgentSimilarity(ua1, ua3);

      expect(similarity1).toBeGreaterThan(similarity2);
      expect(similarity1).toBeGreaterThanOrEqual(0.5);
    });

    test('should detect public vs private IPs', () => {
      expect(InvitationService.isPublicIP('8.8.8.8')).toBe(true);
      expect(InvitationService.isPublicIP('192.168.1.1')).toBe(false);
      expect(InvitationService.isPublicIP('10.0.0.1')).toBe(false);
      expect(InvitationService.isPublicIP('127.0.0.1')).toBe(false);
    });
  });

  describe('cleanupExpiredInvitations Method', () => {
    beforeEach(async () => {
      // Créer invitations expirées
      const expiredDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // Hier
      
      await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'expired1@example.com',
        month: '2025-01',
        token: 'expired_token_1',
        expiresAt: expiredDate,
        status: 'sent'
      });

      await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'expired2@example.com',
        month: '2025-01',
        token: 'expired_token_2',
        expiresAt: expiredDate,
        status: 'opened'
      });
    });

    test('should mark expired invitations', async () => {
      const result = await InvitationService.cleanupExpiredInvitations();

      expect(result.expired).toBe(2);
      expect(result.processedAt).toBeInstanceOf(Date);

      // Vérifier que les invitations sont marquées comme expirées
      const expiredInvitations = await Invitation.find({ status: 'expired' });
      expect(expiredInvitations).toHaveLength(2);
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors gracefully', async () => {
      // Tenter de créer une invitation avec un ID utilisateur invalide
      await expect(
        InvitationService.createInvitation({
          fromUserId: 'invalid-id',
          toEmail: 'test@example.com',
          month: '2025-01'
        }, securityContext)
      ).rejects.toThrow();
    });

    test('should handle missing invitation gracefully', async () => {
      const fakeId = new mongoose.Types.ObjectId();

      await expect(
        InvitationService.cancelInvitation(fakeId, testUser1._id)
      ).rejects.toThrow('Invitation non trouvée');
    });

    test('should validate token format', async () => {
      await expect(
        InvitationService.validateInvitationToken('')
      ).rejects.toThrow('Token requis');
    });
  });
});