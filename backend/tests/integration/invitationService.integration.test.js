const mongoose = require('mongoose');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./setup-integration');

const InvitationService = require('../../services/invitationService');
const Invitation = require('../../models/Invitation');
const User = require('../../models/User');
const Submission = require('../../models/Submission');
const Contact = require('../../models/Contact');

describe('InvitationService - Tests d\'intégration', () => {
  
  let invitationService;
  let testUser1, testUser2, testUser3;
  const currentMonth = new Date().toISOString().slice(0, 7);

  beforeAll(async () => {
    await setupTestDatabase();
    
    

    // Initialiser le service avec config de test
    const config = {
      tokenLength: 32,
      shortCodeLength: 8,
      maxTokenAgeHours: 60 * 24,
      antiTransferWindowHours: 24,
      maxIpChanges: 3,
      rateLimitAttempts: 5
    };
    invitationService = new InvitationService(config);
  });

  beforeEach(async () => {
    await cleanupDatabase();

    testUser1 = await User.create({
      username: 'sender1',
      email: 'sender1@test.com',
      password: 'password123'
    });

    testUser2 = await User.create({
      username: 'recipient1',
      email: 'recipient1@test.com',
      password: 'password123'
    });

    testUser3 = await User.create({
      username: 'sender2',
      email: 'sender2@test.com',
      password: 'password123'
    });
  });

  afterAll(async () => {
    await teardownTestDatabase();
    
    
  });

  describe('createInvitation', () => {
    it('devrait créer une invitation avec tokens sécurisés', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'external@test.com',
        month: currentMonth,
        metadata: { message: 'Invitation personnalisée' }
      };

      const securityContext = {
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
        referrer: 'https://app.test.com'
      };

      const invitation = await invitationService.createInvitation(
        invitationData,
        securityContext
      );

      expect(invitation).toBeDefined();
      expect(invitation.token).toHaveLength(64); // 32 bytes hex
      expect(invitation.shortCode).toHaveLength(8);
      expect(invitation.type).toBe('external');
      expect(invitation.metadata.antiTransferCode).toBeDefined();
      expect(invitation.metadata.originalIp).toBe('192.168.1.1');
      expect(invitation.metadata.securityLevel).toBe('high');
    });

    it('devrait détecter un utilisateur existant et créer une invitation "user"', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: testUser2.email,
        month: currentMonth
      };

      const invitation = await invitationService.createInvitation(invitationData);

      expect(invitation.type).toBe('user');
      expect(invitation.toUserId.toString()).toBe(testUser2._id.toString());
    });

    it('devrait empêcher les invitations dupliquées pour le même mois', async () => {
      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'duplicate@test.com',
        month: currentMonth
      };

      await invitationService.createInvitation(invitationData);

      await expect(
        invitationService.createInvitation(invitationData)
      ).rejects.toThrow(`Invitation déjà envoyée à duplicate@test.com pour ${currentMonth}`);
    });

    it('devrait mettre à jour le tracking du contact si existant', async () => {
      // Créer un contact d'abord
      const contact = await Contact.create({
        ownerId: testUser1._id,
        email: 'contact@test.com',
        firstName: 'Contact',
        status: 'active'
      });

      const invitationData = {
        fromUserId: testUser1._id,
        toEmail: 'contact@test.com',
        month: currentMonth
      };

      await invitationService.createInvitation(invitationData);

      // Vérifier que le tracking est mis à jour
      const updatedContact = await Contact.findById(contact._id);
      expect(updatedContact.tracking.invitationsSent).toBe(1);
    });
  });

  describe('validateInvitationToken', () => {
    let testInvitation;

    beforeEach(async () => {
      testInvitation = await invitationService.createInvitation({
        fromUserId: testUser1._id,
        toEmail: 'validate@test.com',
        month: currentMonth
      }, {
        ipAddress: '192.168.1.1',
        userAgent: 'TestBrowser/1.0'
      });
    });

    it('devrait valider un token valide', async () => {
      const validation = await invitationService.validateInvitationToken(
        testInvitation.token,
        {
          ipAddress: '192.168.1.1',
          userAgent: 'TestBrowser/1.0'
        }
      );

      expect(validation.valid).toBe(true);
      expect(validation.invitation).toBeDefined();
      expect(validation.securityLevel).toBeDefined();
      expect(validation.remaining.days).toBeGreaterThan(0);
    });

    it('devrait rejeter un token invalide', async () => {
      const validation = await invitationService.validateInvitationToken(
        'invalid-token-12345'
      );

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('TOKEN_NOT_FOUND');
    });

    it('devrait détecter une invitation expirée', async () => {
      // Forcer l'expiration
      testInvitation.expiresAt = new Date(Date.now() - 1000);
      await testInvitation.save();

      const validation = await invitationService.validateInvitationToken(
        testInvitation.token
      );

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('TOKEN_EXPIRED');
    });

    it('devrait rejeter une invitation déjà utilisée', async () => {
      testInvitation.status = 'submitted';
      await testInvitation.save();

      const validation = await invitationService.validateInvitationToken(
        testInvitation.token
      );

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('ALREADY_SUBMITTED');
    });

    it('devrait marquer comme "opened" lors de la première validation', async () => {
      await invitationService.validateInvitationToken(
        testInvitation.token,
        { ipAddress: '192.168.1.1' }
      );

      const updated = await Invitation.findById(testInvitation._id);
      expect(updated.status).toBe('opened');
      expect(updated.tracking.openedAt).toBeDefined();
    });
  });

  describe('Sécurité anti-transfert', () => {
    let secureInvitation;

    beforeEach(async () => {
      secureInvitation = await invitationService.createInvitation({
        fromUserId: testUser1._id,
        toEmail: 'secure@test.com',
        month: currentMonth
      }, {
        ipAddress: '192.168.1.1',
        userAgent: 'Chrome/100.0'
      });
    });

    it('devrait permettre l\'accès depuis la même IP', async () => {
      const validation = await invitationService.validateInvitationToken(
        secureInvitation.token,
        {
          ipAddress: '192.168.1.1',
          userAgent: 'Chrome/100.0'
        }
      );

      expect(validation.valid).toBe(true);
      expect(validation.securityLevel).toBe('normal');
    });

    it('devrait détecter un changement d\'IP mais permettre l\'accès', async () => {
      const validation = await invitationService.validateInvitationToken(
        secureInvitation.token,
        {
          ipAddress: '192.168.2.1', // IP différente
          userAgent: 'Chrome/100.0'
        }
      );

      expect(validation.valid).toBe(true);
      expect(validation.securityLevel).toBe('elevated');
    });

    it('devrait calculer la similarité des User-Agents', async () => {
      const validation = await invitationService.validateInvitationToken(
        secureInvitation.token,
        {
          ipAddress: '192.168.1.1',
          userAgent: 'Firefox/95.0' // Navigateur différent
        }
      );

      expect(validation.valid).toBe(true);
      // Le niveau de sécurité peut être élevé à cause du changement de navigateur
    });
  });

  describe('markInvitationSubmitted', () => {
    let invitation;
    let submission;

    beforeEach(async () => {
      invitation = await invitationService.createInvitation({
        fromUserId: testUser1._id,
        toEmail: 'submit@test.com',
        month: currentMonth
      });

      submission = await Submission.create({
        userId: testUser2._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Réponse 1' }
        ]
      });
    });

    it('devrait marquer une invitation comme soumise', async () => {
      const updated = await invitationService.markInvitationSubmitted(
        invitation.token,
        submission._id,
        { ipAddress: '192.168.1.1' }
      );

      expect(updated.status).toBe('submitted');
      expect(updated.submissionId.toString()).toBe(submission._id.toString());
      expect(updated.tracking.submittedAt).toBeDefined();
    });

    it('devrait empêcher la double soumission', async () => {
      await invitationService.markInvitationSubmitted(
        invitation.token,
        submission._id
      );

      const validation = await invitationService.validateInvitationToken(
        invitation.token
      );

      expect(validation.valid).toBe(false);
      expect(validation.reason).toBe('ALREADY_SUBMITTED');
    });

    it('devrait mettre à jour le tracking du contact', async () => {
      // Créer un contact associé
      const contact = await Contact.create({
        ownerId: testUser1._id,
        email: 'submit@test.com',
        status: 'active'
      });

      await invitationService.markInvitationSubmitted(
        invitation.token,
        submission._id
      );

      const updatedContact = await Contact.findOne({ email: 'submit@test.com' });
      expect(updatedContact.tracking.responsesReceived).toBe(1);
    });
  });

  describe('extendInvitation', () => {
    let invitation;

    beforeEach(async () => {
      invitation = await invitationService.createInvitation({
        fromUserId: testUser1._id,
        toEmail: 'extend@test.com',
        month: currentMonth
      });
    });

    it('devrait prolonger une invitation', async () => {
      const originalExpiration = invitation.expiresAt;
      
      const extended = await invitationService.extendInvitation(
        invitation._id,
        testUser1._id,
        30 // 30 jours supplémentaires
      );

      expect(extended.expiresAt > originalExpiration).toBe(true);
      expect(extended.metadata.extendedAt).toBeDefined();
      expect(extended.metadata.additionalDays).toBe(30);
    });

    it('devrait empêcher la prolongation par un non-propriétaire', async () => {
      await expect(
        invitationService.extendInvitation(
          invitation._id,
          testUser2._id,
          30
        )
      ).rejects.toThrow('Non autorisé à prolonger cette invitation');
    });

    it('devrait empêcher la prolongation d\'une invitation soumise', async () => {
      invitation.status = 'submitted';
      await invitation.save();

      await expect(
        invitationService.extendInvitation(
          invitation._id,
          testUser1._id,
          30
        )
      ).rejects.toThrow('Impossible de prolonger cette invitation');
    });
  });

  describe('getInvitations avec filtres et pagination', () => {
    beforeEach(async () => {
      // Créer plusieurs invitations pour les tests
      const invitations = [];
      
      for (let i = 0; i < 5; i++) {
        invitations.push({
          fromUserId: testUser1._id,
          toEmail: `user${i}@test.com`,
          month: currentMonth,
          status: i < 2 ? 'sent' : i < 4 ? 'opened' : 'submitted',
          type: i % 2 === 0 ? 'external' : 'user',
          toUserId: i % 2 === 1 ? testUser2._id : null,
          token: `token${i}`,
          shortCode: `CODE${i}`,
          expiresAt: new Date(Date.now() + (i + 1) * 24 * 60 * 60 * 1000)
        });
      }

      await Invitation.insertMany(invitations);
    });

    it('devrait récupérer les invitations avec pagination', async () => {
      const result = await invitationService.getInvitations(
        testUser1._id,
        {},
        { page: 1, limit: 3 }
      );

      expect(result.invitations).toHaveLength(3);
      expect(result.pagination.totalCount).toBe(5);
      expect(result.pagination.hasNext).toBe(true);
    });

    it('devrait filtrer par statut', async () => {
      const result = await invitationService.getInvitations(
        testUser1._id,
        { status: 'opened' }
      );

      expect(result.invitations).toHaveLength(2);
      expect(result.invitations.every(i => i.status === 'opened')).toBe(true);
    });

    it('devrait filtrer par type', async () => {
      const result = await invitationService.getInvitations(
        testUser1._id,
        { type: 'user' }
      );

      expect(result.invitations.every(i => i.type === 'user')).toBe(true);
    });

    it('devrait calculer les statistiques correctement', async () => {
      const result = await invitationService.getInvitations(testUser1._id);

      expect(result.stats.basic.total).toBe(5);
      expect(result.stats.basic.sent).toBe(5);
      expect(result.stats.basic.opened).toBe(3); // opened + submitted
      expect(result.stats.basic.submitted).toBe(1);
    });
  });

  describe('cleanupExpiredInvitations', () => {
    beforeEach(async () => {
      // Créer des invitations avec différents statuts et dates d'expiration
      await Invitation.insertMany([
        {
          fromUserId: testUser1._id,
          toEmail: 'expired1@test.com',
          month: currentMonth,
          status: 'sent',
          token: 'expired1',
          expiresAt: new Date(Date.now() - 1000) // Expiré
        },
        {
          fromUserId: testUser1._id,
          toEmail: 'expired2@test.com',
          month: currentMonth,
          status: 'opened',
          token: 'expired2',
          expiresAt: new Date(Date.now() - 2000) // Expiré
        },
        {
          fromUserId: testUser1._id,
          toEmail: 'valid@test.com',
          month: currentMonth,
          status: 'sent',
          token: 'valid',
          expiresAt: new Date(Date.now() + 86400000) // Valide
        }
      ]);
    });

    it('devrait marquer les invitations expirées', async () => {
      const result = await invitationService.cleanupExpiredInvitations();

      expect(result.expired).toBe(2);
      expect(result.deleted).toBe(0);

      // Vérifier que les invitations sont marquées comme expirées
      const expired = await Invitation.find({ status: 'expired' });
      expect(expired).toHaveLength(2);
    });

    it('devrait supprimer les très anciennes invitations', async () => {
      // Créer une très ancienne invitation expirée
      await Invitation.create({
        fromUserId: testUser1._id,
        toEmail: 'veryold@test.com',
        month: '2023-01',
        status: 'expired',
        token: 'veryold',
        expiresAt: new Date('2023-01-01'),
        respondedAt: new Date('2023-02-01')
      });

      const result = await invitationService.cleanupExpiredInvitations();

      // Vérifier la suppression
      const veryOld = await Invitation.findOne({ token: 'veryold' });
      expect(veryOld).toBeNull();
    });
  });

  describe('Scénarios d\'intégration complets', () => {
    it('Scénario 1: Cycle complet invitation → validation → soumission', async () => {
      // 1. Créer une invitation
      const invitation = await invitationService.createInvitation({
        fromUserId: testUser1._id,
        toEmail: testUser2.email,
        month: currentMonth,
        metadata: { campaignName: 'Test Campaign' }
      }, {
        ipAddress: '10.0.0.1',
        userAgent: 'TestAgent/1.0'
      });

      expect(invitation.type).toBe('user');
      expect(invitation.status).toBe('queued');

      // 2. Valider le token (ouvrir l'invitation)
      const validation1 = await invitationService.validateInvitationToken(
        invitation.token,
        { ipAddress: '10.0.0.1', userAgent: 'TestAgent/1.0' }
      );

      expect(validation1.valid).toBe(true);
      
      // Vérifier le changement de statut
      let updated = await Invitation.findById(invitation._id);
      expect(updated.status).toBe('opened');

      // 3. Marquer comme commencée
      await invitationService.markInvitationStarted(
        invitation.token,
        { ipAddress: '10.0.0.1' }
      );

      updated = await Invitation.findById(invitation._id);
      expect(updated.status).toBe('started');

      // 4. Créer une soumission
      const submission = await Submission.create({
        userId: testUser2._id,
        month: currentMonth,
        responses: [
          { questionId: 'q1', type: 'text', answer: 'Test answer' }
        ]
      });

      // 5. Marquer l'invitation comme soumise
      const final = await invitationService.markInvitationSubmitted(
        invitation.token,
        submission._id,
        { ipAddress: '10.0.0.1' }
      );

      expect(final.status).toBe('submitted');
      expect(final.submissionId).toBeDefined();

      // 6. Vérifier que le token ne peut plus être utilisé
      const validation2 = await invitationService.validateInvitationToken(
        invitation.token
      );

      expect(validation2.valid).toBe(false);
      expect(validation2.reason).toBe('ALREADY_SUBMITTED');
    });

    it('Scénario 2: Gestion de sécurité avec changements d\'IP', async () => {
      // 1. Créer une invitation avec contexte de sécurité
      const invitation = await invitationService.createInvitation({
        fromUserId: testUser1._id,
        toEmail: 'security@test.com',
        month: currentMonth
      }, {
        ipAddress: '192.168.1.100',
        userAgent: 'Chrome/100.0',
        referrer: 'https://trusted.com'
      });

      expect(invitation.metadata.securityLevel).toBe('high');

      // 2. Première validation depuis la même IP
      const validation1 = await invitationService.validateInvitationToken(
        invitation.token,
        {
          ipAddress: '192.168.1.100',
          userAgent: 'Chrome/100.0'
        }
      );

      expect(validation1.valid).toBe(true);
      expect(validation1.securityLevel).toBe('normal');

      // 3. Deuxième validation depuis une IP différente
      const validation2 = await invitationService.validateInvitationToken(
        invitation.token,
        {
          ipAddress: '192.168.2.200', // IP différente
          userAgent: 'Chrome/100.0'
        }
      );

      expect(validation2.valid).toBe(true);
      expect(validation2.securityLevel).toBe('elevated');

      // 4. Tentative depuis un user-agent très différent
      const validation3 = await invitationService.validateInvitationToken(
        invitation.token,
        {
          ipAddress: '192.168.3.300',
          userAgent: 'PostmanRuntime/7.0' // Bot/outil automatisé
        }
      );

      expect(validation3.valid).toBe(true);
      // Le niveau de risque pourrait être plus élevé
    });

    it('Scénario 3: Invitations multiples et statistiques', async () => {
      // 1. Créer plusieurs invitations pour différents mois
      const months = ['2024-01', '2024-02', '2024-03'];
      const recipients = [
        'recipient1@test.com',
        'recipient2@test.com',
        testUser2.email
      ];

      const invitations = [];
      for (const month of months) {
        for (const email of recipients) {
          const inv = await invitationService.createInvitation({
            fromUserId: testUser1._id,
            toEmail: email,
            month
          });
          invitations.push(inv);
        }
      }

      expect(invitations).toHaveLength(9);

      // 2. Simuler des interactions
      // Ouvrir quelques invitations
      await invitationService.validateInvitationToken(invitations[0].token);
      await invitationService.validateInvitationToken(invitations[1].token);
      await invitationService.validateInvitationToken(invitations[3].token);

      // Soumettre quelques invitations
      const submission1 = await Submission.create({
        userId: testUser2._id,
        month: '2024-01',
        responses: []
      });

      await invitationService.markInvitationSubmitted(
        invitations[0].token,
        submission1._id
      );

      // 3. Récupérer les statistiques
      const stats = await invitationService.getInvitationStats(testUser1._id);

      expect(stats.basic.total).toBe(9);
      expect(stats.basic.opened).toBeGreaterThanOrEqual(3);
      expect(stats.basic.submitted).toBe(1);
      expect(stats.responseRate).toBeGreaterThan(0);

      // 4. Vérifier les stats par mois
      expect(stats.monthly).toBeDefined();
      expect(stats.monthly.length).toBeGreaterThan(0);
      
      const jan2024 = stats.monthly.find(m => m._id === '2024-01');
      expect(jan2024).toBeDefined();
      expect(jan2024.count).toBe(3);
      expect(jan2024.submitted).toBe(1);
    });
  });
});