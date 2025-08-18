const mongoose = require('mongoose');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./setup-integration');

const HandshakeService = require('../../services/handshakeService');
const Handshake = require('../../models/Handshake');
const User = require('../../models/User');
const Contact = require('../../models/Contact');

describe('HandshakeService - Tests d\'intégration', () => {
  
  let handshakeService;
  let testUser1, testUser2, testUser3, testUser4, testUser5;

  beforeAll(async () => {
    await setupTestDatabase();
    
    

    // Initialiser le service avec config de test
    const config = {
      defaultExpirationDays: 30,
      maxMessageLength: 500,
      maxPendingHandshakes: 50,
      cleanupIntervalHours: 6,
      notificationBeforeExpiryDays: 3
    };
    handshakeService = new HandshakeService(config);
  });

  beforeEach(async () => {
    await cleanupDatabase();

    // Créer des utilisateurs avec des profils variés
    testUser1 = await User.create({
      username: 'alice_connector',
      email: 'alice@network.com',
      password: 'password123',
      profile: {
        firstName: 'Alice',
        lastName: 'Network'
      },
      metadata: {
        isActive: true,
        responseCount: 5,
        lastActive: new Date()
      }
    });

    testUser2 = await User.create({
      username: 'bob_social',
      email: 'bob@network.com',
      password: 'password123',
      profile: {
        firstName: 'Bob',
        lastName: 'Social'
      },
      metadata: {
        isActive: true,
        responseCount: 3,
        lastActive: new Date()
      }
    });

    testUser3 = await User.create({
      username: 'charlie_friendly',
      email: 'charlie@network.com',
      password: 'password123',
      profile: {
        firstName: 'Charlie',
        lastName: 'Friendly'
      },
      metadata: {
        isActive: true,
        responseCount: 8,
        lastActive: new Date()
      }
    });

    testUser4 = await User.create({
      username: 'diana_selective',
      email: 'diana@network.com',
      password: 'password123',
      profile: {
        firstName: 'Diana',
        lastName: 'Selective'
      },
      metadata: {
        isActive: true,
        responseCount: 2,
        lastActive: new Date()
      }
    });

    testUser5 = await User.create({
      username: 'eve_inactive',
      email: 'eve@network.com',
      password: 'password123',
      profile: {
        firstName: 'Eve',
        lastName: 'Inactive'
      },
      metadata: {
        isActive: false,
        responseCount: 0,
        lastActive: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
      }
    });
  });

  afterAll(async () => {
    await teardownTestDatabase();
    
    
  });

  describe('createMutual', () => {
    it('devrait créer un handshake mutuel avec succès', async () => {
      const options = {
        message: 'Salut ! J\'aimerais faire ta connaissance.',
        source: 'manual',
        metadata: { platform: 'web' }
      };

      const result = await handshakeService.createMutual(
        testUser1._id,
        testUser2._id,
        options
      );

      expect(result.created).toBe(true);
      expect(result.handshake).toBeDefined();
      expect(result.handshake.requesterId.toString()).toBe(testUser1._id.toString());
      expect(result.handshake.targetId.toString()).toBe(testUser2._id.toString());
      expect(result.handshake.message).toBe(options.message);
      expect(result.handshake.status).toBe('pending');
      expect(result.handshake.expiresAt).toBeDefined();
    });

    it('devrait empêcher les handshakes avec soi-même', async () => {
      await expect(
        handshakeService.createMutual(testUser1._id, testUser1._id)
      ).rejects.toThrow('Impossible de créer un handshake avec soi-même');
    });

    it('devrait empêcher les doublons de handshakes', async () => {
      // Créer un premier handshake
      await handshakeService.createMutual(testUser1._id, testUser2._id);

      // Tentative de créer un doublon
      const result = await handshakeService.createMutual(testUser2._id, testUser1._id);

      expect(result.created).toBe(false);
      expect(result.message).toContain('déjà en attente');
    });

    it('devrait respecter les limites anti-spam', async () => {
      // Créer plusieurs handshakes pour dépasser la limite
      const promises = [];
      for (let i = 0; i < 11; i++) {
        const tempUser = await User.create({
          username: `temp${i}`,
          email: `temp${i}@test.com`,
          password: 'password123'
        });
        promises.push(handshakeService.createMutual(testUser1._id, tempUser._id));
      }

      // Le 11ème devrait échouer (limite de 10 par jour)
      await expect(Promise.all(promises)).rejects.toThrow('Limite de handshakes atteinte');
    });

    it('devrait mettre à jour les contacts existants', async () => {
      // Créer un contact d'abord
      const contact = await Contact.create({
        ownerId: testUser1._id,
        contactUserId: testUser2._id,
        email: testUser2.email,
        status: 'pending'
      });

      const result = await handshakeService.createMutual(testUser1._id, testUser2._id);

      expect(result.created).toBe(true);

      // Vérifier que le contact est mis à jour
      const updatedContact = await Contact.findById(contact._id);
      expect(updatedContact.handshakeId.toString()).toBe(result.handshake._id.toString());
      expect(updatedContact.status).toBe('active');
    });
  });

  describe('accept', () => {
    let pendingHandshake;

    beforeEach(async () => {
      const result = await handshakeService.createMutual(
        testUser1._id,
        testUser2._id,
        { message: 'Hello!' }
      );
      pendingHandshake = result.handshake;
    });

    it('devrait accepter un handshake valide', async () => {
      const result = await handshakeService.accept(
        pendingHandshake._id,
        testUser2._id,
        'Salut ! Ravi de te connaître !'
      );

      expect(result.success).toBe(true);
      expect(result.handshake.status).toBe('accepted');
      expect(result.handshake.respondedAt).toBeDefined();
      expect(result.handshake.responseMessage).toBe('Salut ! Ravi de te connaître !');
    });

    it('devrait créer des contacts mutuels après acceptation', async () => {
      await handshakeService.accept(pendingHandshake._id, testUser2._id);

      // Vérifier que les contacts mutuels sont créés
      const contact1to2 = await Contact.findOne({
        ownerId: testUser1._id,
        contactUserId: testUser2._id
      });
      
      const contact2to1 = await Contact.findOne({
        ownerId: testUser2._id,
        contactUserId: testUser1._id
      });

      expect(contact1to2).toBeDefined();
      expect(contact1to2.status).toBe('active');
      expect(contact1to2.source).toBe('handshake');

      expect(contact2to1).toBeDefined();
      expect(contact2to1.status).toBe('active');
      expect(contact2to1.source).toBe('handshake');
    });

    it('devrait empêcher l\'acceptation par une personne non autorisée', async () => {
      await expect(
        handshakeService.accept(pendingHandshake._id, testUser3._id)
      ).rejects.toThrow('Seul le destinataire peut accepter');
    });

    it('devrait empêcher l\'acceptation d\'un handshake déjà traité', async () => {
      // Accepter une première fois
      await handshakeService.accept(pendingHandshake._id, testUser2._id);

      // Tentative d'acceptation une seconde fois
      await expect(
        handshakeService.accept(pendingHandshake._id, testUser2._id)
      ).rejects.toThrow('déjà accepted');
    });

    it('devrait mettre à jour les statistiques des utilisateurs', async () => {
      await handshakeService.accept(pendingHandshake._id, testUser2._id);

      // Vérifier les mises à jour des métadonnées
      const updatedUser1 = await User.findById(testUser1._id);
      const updatedUser2 = await User.findById(testUser2._id);

      expect(updatedUser1.metadata.handshakesSent).toBe(1);
      expect(updatedUser1.metadata.handshakesAccepted).toBe(1);
      expect(updatedUser2.metadata.handshakesReceived).toBe(1);
      expect(updatedUser2.metadata.handshakesAccepted).toBe(1);
    });
  });

  describe('decline', () => {
    let pendingHandshake;

    beforeEach(async () => {
      const result = await handshakeService.createMutual(
        testUser1._id,
        testUser2._id,
        { message: 'Hello!' }
      );
      pendingHandshake = result.handshake;
    });

    it('devrait refuser un handshake avec un message', async () => {
      const result = await handshakeService.decline(
        pendingHandshake._id,
        testUser2._id,
        'Merci mais pas intéressé pour le moment.'
      );

      expect(result.success).toBe(true);
      expect(result.handshake.status).toBe('declined');
      expect(result.handshake.responseMessage).toBe('Merci mais pas intéressé pour le moment.');
    });

    it('devrait nettoyer les contacts associés après refus', async () => {
      // Créer des contacts au préalable
      await Contact.create({
        ownerId: testUser1._id,
        contactUserId: testUser2._id,
        email: testUser2.email,
        handshakeId: pendingHandshake._id,
        status: 'active'
      });

      await handshakeService.decline(pendingHandshake._id, testUser2._id);

      // Vérifier que le contact est marqué comme refusé
      const contact = await Contact.findOne({
        ownerId: testUser1._id,
        contactUserId: testUser2._id
      });

      expect(contact.status).toBe('declined');
      expect(contact.handshakeId).toBeNull();
    });
  });

  describe('checkPermission', () => {
    it('devrait vérifier les permissions entre utilisateurs connectés', async () => {
      // Créer et accepter un handshake
      const result = await handshakeService.createMutual(testUser1._id, testUser2._id);
      await handshakeService.accept(result.handshake._id, testUser2._id);

      // Vérifier les permissions
      const permission1to2 = await handshakeService.checkPermission(
        testUser1._id,
        testUser2._id
      );

      const permission2to1 = await handshakeService.checkPermission(
        testUser2._id,
        testUser1._id
      );

      expect(permission1to2.hasPermission).toBe(true);
      expect(permission1to2.handshakeStatus).toBe('accepted');
      expect(permission2to1.hasPermission).toBe(true);
    });

    it('devrait détecter un handshake en attente', async () => {
      const result = await handshakeService.createMutual(testUser1._id, testUser2._id);

      const permission = await handshakeService.checkPermission(
        testUser1._id,
        testUser2._id
      );

      expect(permission.hasPermission).toBe(false);
      expect(permission.handshakeStatus).toBe('pending');
      expect(permission.handshakeId.toString()).toBe(result.handshake._id.toString());
    });

    it('devrait retourner les détails si demandé', async () => {
      const result = await handshakeService.createMutual(testUser1._id, testUser2._id);

      const permission = await handshakeService.checkPermission(
        testUser1._id,
        testUser2._id,
        { includeDetails: true }
      );

      expect(permission.details).toBeDefined();
      expect(permission.details.message).toBeDefined();
      expect(permission.details.requestedAt).toBeDefined();
    });
  });

  describe('getUserHandshakes', () => {
    beforeEach(async () => {
      // Créer plusieurs handshakes avec différents statuts
      const handshakes = [];
      
      // Alice → Bob (pending)
      let result = await handshakeService.createMutual(testUser1._id, testUser2._id);
      handshakes.push(result.handshake);

      // Alice → Charlie (pending, puis accepté)
      result = await handshakeService.createMutual(testUser1._id, testUser3._id);
      await handshakeService.accept(result.handshake._id, testUser3._id);
      handshakes.push(result.handshake);

      // Diana → Alice (pending, puis refusé)
      result = await handshakeService.createMutual(testUser4._id, testUser1._id);
      await handshakeService.decline(result.handshake._id, testUser1._id);
      handshakes.push(result.handshake);

      // Bob → Charlie (pending)
      result = await handshakeService.createMutual(testUser2._id, testUser3._id);
      handshakes.push(result.handshake);
    });

    it('devrait récupérer tous les handshakes d\'un utilisateur', async () => {
      const result = await handshakeService.getUserHandshakes(testUser1._id);

      expect(result.handshakes.length).toBe(3); // Alice impliquée dans 3 handshakes
      expect(result.stats.totalSent).toBe(2); // Alice a envoyé 2 demandes
      expect(result.stats.totalReceived).toBe(1); // Alice a reçu 1 demande
    });

    it('devrait filtrer par direction (sent/received)', async () => {
      const sentResult = await handshakeService.getUserHandshakes(
        testUser1._id,
        { direction: 'sent' }
      );

      const receivedResult = await handshakeService.getUserHandshakes(
        testUser1._id,
        { direction: 'received' }
      );

      expect(sentResult.handshakes.length).toBe(2);
      expect(receivedResult.handshakes.length).toBe(1);
    });

    it('devrait filtrer par statut', async () => {
      const acceptedResult = await handshakeService.getUserHandshakes(
        testUser1._id,
        { status: 'accepted' }
      );

      const declinedResult = await handshakeService.getUserHandshakes(
        testUser1._id,
        { status: 'declined' }
      );

      expect(acceptedResult.handshakes.length).toBe(1);
      expect(declinedResult.handshakes.length).toBe(1);
    });

    it('devrait paginer les résultats', async () => {
      const page1 = await handshakeService.getUserHandshakes(
        testUser1._id,
        {},
        { page: 1, limit: 2 }
      );

      const page2 = await handshakeService.getUserHandshakes(
        testUser1._id,
        {},
        { page: 2, limit: 2 }
      );

      expect(page1.handshakes.length).toBe(2);
      expect(page2.handshakes.length).toBe(1);
      expect(page1.pagination.hasNext).toBe(true);
      expect(page2.pagination.hasPrev).toBe(true);
    });
  });

  describe('getSuggestions', () => {
    it('devrait suggérer des utilisateurs pour les handshakes', async () => {
      const suggestions = await handshakeService.getSuggestions(testUser1._id);

      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions.every(s => s.userId.toString() !== testUser1._id.toString())).toBe(true);
      expect(suggestions.every(s => s.suggested === true)).toBe(true);
    });

    it('devrait exclure les utilisateurs avec handshakes existants', async () => {
      // Créer un handshake avec testUser2
      await handshakeService.createMutual(testUser1._id, testUser2._id);

      const suggestions = await handshakeService.getSuggestions(
        testUser1._id,
        { excludeExisting: true }
      );

      expect(suggestions.every(s => s.userId.toString() !== testUser2._id.toString())).toBe(true);
    });

    it('devrait exclure les utilisateurs inactifs par défaut', async () => {
      const suggestions = await handshakeService.getSuggestions(testUser1._id);

      // testUser5 est marqué comme inactif
      expect(suggestions.every(s => s.userId.toString() !== testUser5._id.toString())).toBe(true);
    });

    it('devrait respecter la limite de suggestions', async () => {
      const suggestions = await handshakeService.getSuggestions(
        testUser1._id,
        { limit: 2 }
      );

      expect(suggestions.length).toBeLessThanOrEqual(2);
    });
  });

  describe('cleanupExpiredHandshakes', () => {
    beforeEach(async () => {
      // Créer des handshakes avec différentes dates d'expiration
      await Handshake.insertMany([
        {
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'pending',
          expiresAt: new Date(Date.now() - 1000), // Expiré
          requestedAt: new Date(Date.now() - 24 * 60 * 60 * 1000)
        },
        {
          requesterId: testUser1._id,
          targetId: testUser3._id,
          status: 'pending',
          expiresAt: new Date(Date.now() - 2000), // Expiré
          requestedAt: new Date(Date.now() - 48 * 60 * 60 * 1000)
        },
        {
          requesterId: testUser2._id,
          targetId: testUser3._id,
          status: 'pending',
          expiresAt: new Date(Date.now() + 86400000), // Valide
          requestedAt: new Date()
        },
        {
          requesterId: testUser1._id,
          targetId: testUser4._id,
          status: 'declined',
          respondedAt: new Date(Date.now() - 200 * 24 * 60 * 60 * 1000) // Très ancien
        }
      ]);
    });

    it('devrait marquer les handshakes expirés et supprimer les anciens', async () => {
      const result = await handshakeService.cleanupExpiredHandshakes();

      expect(result.expired).toBe(2); // 2 handshakes expirés
      expect(result.deleted).toBe(1); // 1 très ancien supprimé
      expect(result.processedAt).toBeDefined();

      // Vérifier que les handshakes sont marqués comme expirés
      const expiredHandshakes = await Handshake.find({ status: 'expired' });
      expect(expiredHandshakes.length).toBe(2);
    });
  });

  describe('Scénarios d\'intégration complets', () => {
    it('Scénario 1: Réseau social complet avec handshakes multiples', async () => {
      // 1. Alice initie des connexions avec Bob et Charlie
      const aliceToBob = await handshakeService.createMutual(
        testUser1._id,
        testUser2._id,
        { message: 'Salut Bob ! Connectons-nous !', initiatedBy: 'manual' }
      );

      const aliceToCharlie = await handshakeService.createMutual(
        testUser1._id,
        testUser3._id,
        { message: 'Hey Charlie, on se connecte ?', source: 'mutual_friend' }
      );

      expect(aliceToBob.created).toBe(true);
      expect(aliceToCharlie.created).toBe(true);

      // 2. Bob accepte, Charlie refuse
      const bobAccepts = await handshakeService.accept(
        aliceToBob.handshake._id,
        testUser2._id,
        'Salut Alice ! Avec plaisir !'
      );

      const charlieDeclines = await handshakeService.decline(
        aliceToCharlie.handshake._id,
        testUser3._id,
        'Merci Alice, mais pas pour le moment.'
      );

      expect(bobAccepts.success).toBe(true);
      expect(charlieDeclines.success).toBe(true);

      // 3. Vérifier les permissions résultantes
      const aliceBobPermission = await handshakeService.checkPermission(
        testUser1._id,
        testUser2._id,
        { includeDetails: true }
      );

      const aliceCharliePermission = await handshakeService.checkPermission(
        testUser1._id,
        testUser3._id
      );

      expect(aliceBobPermission.hasPermission).toBe(true);
      expect(aliceBobPermission.handshakeStatus).toBe('accepted');
      expect(aliceCharliePermission.hasPermission).toBe(false);
      expect(aliceCharliePermission.handshakeStatus).toBe('declined');

      // 4. Vérifier la création des contacts mutuels Alice-Bob
      const aliceBobContact = await Contact.findOne({
        ownerId: testUser1._id,
        contactUserId: testUser2._id
      });

      const bobAliceContact = await Contact.findOne({
        ownerId: testUser2._id,
        contactUserId: testUser1._id
      });

      expect(aliceBobContact).toBeDefined();
      expect(aliceBobContact.status).toBe('active');
      expect(bobAliceContact).toBeDefined();
      expect(bobAliceContact.status).toBe('active');

      // 5. Diana demande une connexion à Alice
      const dianaToAlice = await handshakeService.createMutual(
        testUser4._id,
        testUser1._id,
        { message: 'Hello Alice ! J\'aimerais te connaître.' }
      );

      expect(dianaToAlice.created).toBe(true);

      // 6. Vérifier les statistiques d'Alice
      const aliceHandshakes = await handshakeService.getUserHandshakes(testUser1._id);

      expect(aliceHandshakes.stats.totalSent).toBe(2); // Alice → Bob, Charlie
      expect(aliceHandshakes.stats.totalReceived).toBe(1); // Diana → Alice
      expect(aliceHandshakes.stats.totalAccepted).toBe(1); // Alice-Bob
      expect(aliceHandshakes.stats.totalDeclined).toBe(1); // Alice-Charlie
      expect(aliceHandshakes.stats.totalPending).toBe(1); // Diana-Alice

      // 7. Test du système de suggestions
      const suggestions = await handshakeService.getSuggestions(testUser1._id);

      // Alice devrait voir Diana et d'autres, mais pas Bob (déjà connecté) ni Charlie (refusé récemment)
      expect(suggestions.some(s => s.userId.toString() === testUser4._id.toString())).toBe(false); // Diana a déjà une demande pending
      expect(suggestions.every(s => s.userId.toString() !== testUser2._id.toString())).toBe(true); // Bob exclu (connecté)
    });

    it('Scénario 2: Gestion complète du cycle de vie des handshakes', async () => {
      // 1. Créer plusieurs handshakes avec différents timing
      const handshakes = [];

      // Handshake récent (Alice → Bob)
      handshakes.push(await handshakeService.createMutual(
        testUser1._id,
        testUser2._id,
        { message: 'Recent handshake' }
      ));

      // Handshake qui sera expiré manuellement
      const oldHandshakeData = {
        requesterId: testUser1._id,
        targetId: testUser3._id,
        status: 'pending',
        message: 'Old handshake',
        expiresAt: new Date(Date.now() - 1000), // Déjà expiré
        requestedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000)
      };

      const oldHandshake = await Handshake.create(oldHandshakeData);

      // 2. Nettoyer les handshakes expirés
      const cleanupResult = await handshakeService.cleanupExpiredHandshakes();
      expect(cleanupResult.expired).toBe(1);

      // 3. Vérifier que le handshake expiré est marqué correctement
      const expiredHandshake = await Handshake.findById(oldHandshake._id);
      expect(expiredHandshake.status).toBe('expired');

      // 4. Bob accepte le handshake récent
      const recentHandshake = handshakes[0].handshake;
      await handshakeService.accept(
        recentHandshake._id,
        testUser2._id,
        'Super ! Connectons-nous !'
      );

      // 5. Charlie initie avec Diana
      const charlieToDiana = await handshakeService.createMutual(
        testUser3._id,
        testUser4._id,
        { message: 'Hello Diana !' }
      );

      // 6. Diana bloque Charlie
      await handshakeService.block(
        charlieToDiana.handshake._id,
        testUser4._id
      );

      // 7. Vérifier que Charlie ne peut plus contacter Diana
      const blockedAttempt = await handshakeService.createMutual(
        testUser3._id,
        testUser4._id
      );

      expect(blockedAttempt.created).toBe(false);
      expect(blockedAttempt.message).toContain('bloqué');

      // 8. Analyser les statistiques globales
      const aliceStats = await handshakeService.getUserHandshakeStats(testUser1._id);
      const bobStats = await handshakeService.getUserHandshakeStats(testUser2._id);

      expect(aliceStats.totalSent).toBe(2); // Alice → Bob, Charlie
      expect(aliceStats.totalAccepted).toBe(1); // Alice-Bob accepté
      expect(bobStats.totalReceived).toBe(1); // Bob ← Alice
      expect(bobStats.acceptanceRate).toBe(100); // Bob a accepté sa seule demande reçue
    });

    it('Scénario 3: Système anti-spam et limites avancées', async () => {
      // 1. Tester la limite de handshakes pending
      const pendingHandshakes = [];
      
      // Créer des utilisateurs temporaires pour les tests
      const tempUsers = [];
      for (let i = 0; i < 15; i++) {
        const user = await User.create({
          username: `temp_user_${i}`,
          email: `temp${i}@test.com`,
          password: 'password123',
          metadata: { isActive: true }
        });
        tempUsers.push(user);
      }

      // Créer des handshakes jusqu'à la limite
      for (let i = 0; i < 10; i++) {
        const result = await handshakeService.createMutual(
          testUser1._id,
          tempUsers[i]._id
        );
        pendingHandshakes.push(result.handshake);
        expect(result.created).toBe(true);
      }

      // Le 11ème devrait échouer à cause de la limite quotidienne
      await expect(
        handshakeService.createMutual(testUser1._id, tempUsers[10]._id)
      ).rejects.toThrow('Limite de handshakes atteinte');

      // 2. Accepter quelques handshakes pour libérer la limite pending
      await handshakeService.accept(pendingHandshakes[0]._id, tempUsers[0]._id);
      await handshakeService.accept(pendingHandshakes[1]._id, tempUsers[1]._id);
      await handshakeService.decline(pendingHandshakes[2]._id, tempUsers[2]._id);

      // 3. Vérifier les statistiques après nettoyage
      const stats = await handshakeService.getUserHandshakeStats(testUser1._id);
      
      expect(stats.totalSent).toBe(10);
      expect(stats.totalAccepted).toBe(2);
      expect(stats.totalDeclined).toBe(1);
      expect(stats.totalPending).toBe(7);

      // 4. Test de cancel par l'expéditeur
      const cancelResult = await handshakeService.cancel(
        pendingHandshakes[3]._id,
        testUser1._id,
        'Changed my mind'
      );

      expect(cancelResult.success).toBe(true);
      expect(cancelResult.handshake.status).toBe('expired');

      // 5. Vérifier que seul l'expéditeur peut annuler
      await expect(
        handshakeService.cancel(
          pendingHandshakes[4]._id,
          tempUsers[4]._id // Destinataire tente d'annuler
        )
      ).rejects.toThrow('Seul le demandeur peut annuler');

      // 6. Test des suggestions avec exclusions
      const suggestions = await handshakeService.getSuggestions(
        testUser1._id,
        { 
          limit: 5,
          excludeExisting: true 
        }
      );

      // Les suggestions ne devraient inclure aucun utilisateur avec qui Alice a déjà un handshake
      const connectedUserIds = [
        ...tempUsers.slice(0, 3).map(u => u._id.toString()),
        testUser2._id.toString(),
        testUser3._id.toString()
      ];

      expect(suggestions.every(s => 
        !connectedUserIds.includes(s.userId.toString())
      )).toBe(true);

      // 7. Simuler le passage du temps et nouveau nettoyage
      // Marquer d'autres handshakes comme expirés manuellement
      await Handshake.updateMany(
        { 
          requesterId: testUser1._id, 
          status: 'pending',
          _id: { $in: pendingHandshakes.slice(5, 7).map(h => h._id) }
        },
        { 
          expiresAt: new Date(Date.now() - 1000),
          status: 'expired',
          respondedAt: new Date(),
          responseMessage: 'Expiré automatiquement'
        }
      );

      const finalStats = await handshakeService.getUserHandshakeStats(testUser1._id);
      expect(finalStats.totalPending).toBeLessThan(stats.totalPending);
    });
  });

  describe('Intégration avec ContactService', () => {
    it('devrait synchroniser handshakes et contacts', async () => {
      // 1. Créer un contact d'abord
      const contact = await Contact.create({
        ownerId: testUser1._id,
        contactUserId: testUser2._id,
        email: testUser2.email,
        firstName: testUser2.username,
        status: 'pending'
      });

      // 2. Créer un handshake
      const handshakeResult = await handshakeService.createMutual(
        testUser1._id,
        testUser2._id,
        { message: 'Connectons-nous !' }
      );

      // 3. Vérifier que le contact est mis à jour
      const updatedContact = await Contact.findById(contact._id);
      expect(updatedContact.handshakeId.toString()).toBe(handshakeResult.handshake._id.toString());
      expect(updatedContact.status).toBe('active');

      // 4. Accepter le handshake
      await handshakeService.accept(handshakeResult.handshake._id, testUser2._id);

      // 5. Vérifier que les contacts mutuels sont créés
      const mutualContacts = await Contact.find({
        $or: [
          { ownerId: testUser1._id, contactUserId: testUser2._id },
          { ownerId: testUser2._id, contactUserId: testUser1._id }
        ]
      });

      expect(mutualContacts.length).toBe(2);
      expect(mutualContacts.every(c => c.status === 'active')).toBe(true);
      expect(mutualContacts.every(c => c.source === 'handshake')).toBe(true);
    });
  });
});