const mongoose = require('mongoose');
const ContactService = require('../../services/contactService');
const Contact = require('../../models/Contact');
const User = require('../../models/User');
const Handshake = require('../../models/Handshake');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./setup-integration');

describe('ContactService - Tests d\'intégration', () => {
  let contactService;
  let testUser1, testUser2, testUser3;

  beforeAll(async () => {
    // Démarrer MongoDB en mémoire
    await setupTestDatabase();

    // Initialiser le service avec config de test
    const config = {
      maxCsvSize: 5242880,
      maxBatchSize: 100,
      maxTags: 10,
      maxNameLength: 100,
      maxNotesLength: 1000
    };
    contactService = new ContactService(config);
  });

  beforeEach(async () => {
    // Nettoyer la base de données
    await cleanupDatabase();

    // Créer des utilisateurs de test
    testUser1 = await User.create({
      username: 'user1',
      email: 'user1@test.com',
      password: 'password123'
    });

    testUser2 = await User.create({
      username: 'user2',
      email: 'user2@test.com',
      password: 'password123'
    });

    testUser3 = await User.create({
      username: 'user3',
      email: 'user3@test.com',
      password: 'password123'
    });
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  describe('addContact', () => {
    it('devrait créer un nouveau contact avec succès', async () => {
      const contactData = {
        email: 'newcontact@test.com',
        firstName: 'Jean',
        lastName: 'Dupont',
        tags: ['ami', 'travail'],
        notes: 'Contact professionnel',
        source: 'manual'
      };

      const result = await contactService.addContact(contactData, testUser1._id);

      expect(result.contact).toBeDefined();
      expect(result.contact.email).toBe('newcontact@test.com');
      expect(result.contact.firstName).toBe('Jean');
      expect(result.contact.tags).toContain('ami');
      expect(result.userExists).toBe(false);
      expect(result.handshakeCreated).toBe(false);
    });

    it('devrait créer un handshake automatique si l\'utilisateur existe', async () => {
      const contactData = {
        email: testUser2.email,
        firstName: 'User',
        lastName: 'Two'
      };

      const result = await contactService.addContact(contactData, testUser1._id);

      expect(result.contact).toBeDefined();
      expect(result.contact.contactUserId).toBeDefined();
      expect(result.contact.contactUserId._id.toString()).toBe(testUser2._id.toString());
      expect(result.contact.status).toBe('active');
      expect(result.userExists).toBe(true);
      expect(result.handshakeCreated).toBe(true);
      expect(result.contact.handshakeId).toBeDefined();

      // Vérifier que le handshake existe en base
      const handshake = await Handshake.findById(result.contact.handshakeId);
      expect(handshake).toBeDefined();
      expect(handshake.status).toBe('pending');
    });

    it('devrait rejeter un contact avec email invalide', async () => {
      const contactData = {
        email: 'email-invalide',
        firstName: 'Test'
      };

      await expect(
        contactService.addContact(contactData, testUser1._id)
      ).rejects.toThrow('Email invalide');
    });

    it('devrait empêcher les doublons pour le même propriétaire', async () => {
      const contactData = {
        email: 'duplicate@test.com',
        firstName: 'Test'
      };

      await contactService.addContact(contactData, testUser1._id);

      await expect(
        contactService.addContact(contactData, testUser1._id)
      ).rejects.toThrow('Contact avec l\'email duplicate@test.com existe déjà');
    });
  });

  describe('importCSV', () => {
    it('devrait importer des contacts depuis un CSV valide', async () => {
      const csvData = `email,firstName,lastName,tags,notes
contact1@test.com,Contact,Un,ami,Note 1
contact2@test.com,Contact,Deux,"ami,famille",Note 2
user3@test.com,User,Three,travail,Note 3`;

      const result = await contactService.importCSV(csvData, testUser1._id);

      expect(result.total).toBe(3);
      expect(result.imported).toBe(3);
      expect(result.skipped).toBe(0);
      expect(result.errors).toHaveLength(0);
      expect(result.handshakesCreated).toBe(1); // user3 existe
    });

    it('devrait gérer les erreurs et duplicatas dans le CSV', async () => {
      // Créer un contact existant
      await contactService.addContact({ email: 'existing@test.com' }, testUser1._id);

      const csvData = `email,firstName,lastName
existing@test.com,Should,Skip
invalid-email,Invalid,Entry
valid@test.com,Valid,Entry`;

      const result = await contactService.importCSV(csvData, testUser1._id, {
        skipDuplicates: true
      });

      expect(result.total).toBe(2); // Only processed valid entries
      expect(result.imported).toBe(1); // Seulement valid@test.com
      expect(result.skipped).toBe(1); // existing@test.com
    });

    it('devrait respecter la limite de batch size', async () => {
      // Générer un CSV avec beaucoup de contacts
      const contacts = Array.from({ length: 150 }, (_, i) => 
        `contact${i}@test.com,Contact,${i},tag,note`
      );
      const csvData = 'email,firstName,lastName,tags,notes\n' + contacts.join('\n');

      const result = await contactService.importCSV(csvData, testUser1._id, {
        batchSize: 50
      });

      expect(result.total).toBe(150);
      expect(result.imported).toBe(150);
      // Vérifier que les contacts ont été traités par lots
    });
  });

  describe('getContactsWithStats', () => {
    beforeEach(async () => {
      // Créer plusieurs contacts pour les tests
      await Contact.create([
        {
          ownerId: testUser1._id,
          email: 'active1@test.com',
          firstName: 'Active',
          status: 'active',
          tags: ['ami'],
          source: 'manual'
        },
        {
          ownerId: testUser1._id,
          email: 'active2@test.com',
          firstName: 'Active2',
          status: 'active',
          tags: ['travail'],
          source: 'csv'
        },
        {
          ownerId: testUser1._id,
          email: 'pending@test.com',
          firstName: 'Pending',
          status: 'pending',
          tags: ['ami', 'travail'],
          source: 'manual'
        },
        {
          ownerId: testUser2._id,
          email: 'other@test.com',
          firstName: 'Other',
          status: 'active',
          source: 'manual'
        }
      ]);
    });

    it('devrait récupérer les contacts avec pagination', async () => {
      const result = await contactService.getContactsWithStats(
        testUser1._id,
        {},
        { page: 1, limit: 2 }
      );

      expect(result.contacts).toHaveLength(2);
      expect(result.pagination.totalCount).toBe(3);
      expect(result.pagination.totalPages).toBe(2);
      expect(result.pagination.hasNext).toBe(true);
    });

    it('devrait filtrer les contacts par statut', async () => {
      const result = await contactService.getContactsWithStats(
        testUser1._id,
        { status: 'active' }
      );

      expect(result.contacts).toHaveLength(2);
      expect(result.contacts.every(c => c.status === 'active')).toBe(true);
    });

    it('devrait filtrer les contacts par tags', async () => {
      const result = await contactService.getContactsWithStats(
        testUser1._id,
        { tags: ['ami'] }
      );

      expect(result.contacts).toHaveLength(2);
      expect(result.contacts.every(c => c.tags.includes('ami'))).toBe(true);
    });

    it('devrait rechercher les contacts par texte', async () => {
      const result = await contactService.getContactsWithStats(
        testUser1._id,
        { search: 'Active' }
      );

      expect(result.contacts).toHaveLength(2);
      expect(result.contacts.every(c => c.firstName.includes('Active'))).toBe(true);
    });

    it('devrait calculer les statistiques correctement', async () => {
      const result = await contactService.getContactsWithStats(testUser1._id);

      expect(result.stats.basic.total).toBe(3);
      expect(result.stats.bySource).toBeDefined();
      expect(result.stats.byStatus).toBeDefined();
      
      const manualSource = result.stats.bySource.find(s => s._id === 'manual');
      expect(manualSource.count).toBe(2);
    });
  });

  describe('updateTracking', () => {
    let testContact;

    beforeEach(async () => {
      testContact = await Contact.create({
        ownerId: testUser1._id,
        email: 'tracking@test.com',
        firstName: 'Track',
        status: 'active'
      });
    });

    it('devrait mettre à jour le tracking pour un événement "sent"', async () => {
      const updated = await contactService.updateTracking(
        testContact._id,
        'sent',
        { campaignId: 'campaign123' }
      );

      expect(updated.tracking.invitationsSent).toBe(1);
      expect(updated.tracking.lastSentAt).toBeDefined();
    });

    it('devrait calculer le temps de réponse pour "submitted"', async () => {
      // D'abord marquer comme envoyé
      await contactService.updateTracking(testContact._id, 'sent');
      
      // Puis marquer comme soumis
      const updated = await contactService.updateTracking(
        testContact._id,
        'submitted',
        { formId: 'form123' }
      );

      expect(updated.tracking.responsesReceived).toBe(1);
      expect(updated.tracking.responseRate).toBeGreaterThan(0);
      expect(updated.tracking.lastSubmittedAt).toBeDefined();
    });
  });

  describe('searchContacts', () => {
    beforeEach(async () => {
      await Contact.create([
        {
          ownerId: testUser1._id,
          email: 'jean.dupont@test.com',
          firstName: 'Jean',
          lastName: 'Dupont',
          tags: ['ami', 'sport'],
          status: 'active',
          tracking: { responseRate: 80 }
        },
        {
          ownerId: testUser1._id,
          email: 'marie.martin@test.com',
          firstName: 'Marie',
          lastName: 'Martin',
          tags: ['travail'],
          status: 'active',
          tracking: { responseRate: 60 }
        },
        {
          ownerId: testUser1._id,
          email: 'pierre.bernard@test.com',
          firstName: 'Pierre',
          lastName: 'Bernard',
          tags: ['famille'],
          status: 'opted_out'
        }
      ]);
    });

    it('devrait rechercher par nom', async () => {
      const results = await contactService.searchContacts(
        testUser1._id,
        'jean'
      );

      expect(results).toHaveLength(1);
      expect(results[0].firstName).toBe('Jean');
    });

    it('devrait rechercher par tag', async () => {
      const results = await contactService.searchContacts(
        testUser1._id,
        'travail'
      );

      expect(results).toHaveLength(1);
      expect(results[0].tags).toContain('travail');
    });

    it('devrait exclure les contacts opted_out par défaut', async () => {
      const results = await contactService.searchContacts(
        testUser1._id,
        'Bernard'
      );

      expect(results).toHaveLength(0);
    });

    it('devrait inclure les opted_out si demandé', async () => {
      const results = await contactService.searchContacts(
        testUser1._id,
        'Bernard',
        { includeInactive: true }
      );

      expect(results).toHaveLength(1);
      expect(results[0].lastName).toBe('Bernard');
    });

    it('devrait trier par taux de réponse', async () => {
      const results = await contactService.searchContacts(
        testUser1._id,
        'a', // Correspondra à plusieurs contacts
        { limit: 10 }
      );

      // Vérifier que les résultats sont triés par responseRate décroissant
      expect(results[0].tracking.responseRate).toBe(80); // Jean
      expect(results[1].tracking.responseRate).toBe(60); // Marie
    });
  });

  describe('deleteContact', () => {
    it('devrait supprimer un contact et nettoyer les références', async () => {
      // Créer un contact avec handshake
      const contact = await Contact.create({
        ownerId: testUser1._id,
        email: 'todelete@test.com',
        firstName: 'ToDelete'
      });

      const handshake = await Handshake.create({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        status: 'pending'
      });

      contact.handshakeId = handshake._id;
      await contact.save();

      // Supprimer le contact
      const result = await contactService.deleteContact(contact._id, testUser1._id);

      expect(result).toBe(true);

      // Vérifier que le contact est supprimé
      const deletedContact = await Contact.findById(contact._id);
      expect(deletedContact).toBeNull();

      // Vérifier que le handshake est supprimé
      const deletedHandshake = await Handshake.findById(handshake._id);
      expect(deletedHandshake).toBeNull();
    });

    it('devrait empêcher la suppression par un non-propriétaire', async () => {
      const contact = await Contact.create({
        ownerId: testUser1._id,
        email: 'protected@test.com',
        firstName: 'Protected'
      });

      await expect(
        contactService.deleteContact(contact._id, testUser2._id)
      ).rejects.toThrow('Contact non trouvé ou non autorisé');
    });
  });

  describe('Scénarios d\'intégration complets', () => {
    it('Scénario 1: Import CSV → Handshake automatique → Tracking', async () => {
      // 1. Importer des contacts dont certains sont des utilisateurs
      const csvData = `email,firstName,lastName,tags
${testUser2.email},User,Two,ami
${testUser3.email},User,Three,travail
newcontact@test.com,New,Contact,ami`;

      const importResult = await contactService.importCSV(csvData, testUser1._id);
      
      expect(importResult.imported).toBe(3);
      expect(importResult.handshakesCreated).toBe(2); // user2 et user3

      // 2. Vérifier que les handshakes sont créés
      const contacts = await Contact.find({ ownerId: testUser1._id });
      const userContacts = contacts.filter(c => c.contactUserId);
      
      expect(userContacts).toHaveLength(2);
      expect(userContacts.every(c => c.status === 'active')).toBe(true);
      expect(userContacts.every(c => c.handshakeId)).toBe(true);

      // 3. Simuler l'envoi d'invitations et tracking
      for (const contact of contacts) {
        await contactService.updateTracking(contact._id, 'sent');
      }

      // 4. Simuler des réponses
      await contactService.updateTracking(contacts[0]._id, 'submitted');
      await contactService.updateTracking(contacts[1]._id, 'submitted');

      // 5. Vérifier les statistiques finales
      const stats = await contactService.getContactStats(testUser1._id);
      
      expect(stats.basic.total).toBe(3);
      expect(stats.basic.withHandshake).toBe(2);
      expect(stats.basic.totalInvitationsSent).toBe(3);
      expect(stats.basic.totalResponsesReceived).toBe(2);
    });

    it('Scénario 2: Gestion complète du cycle de vie d\'un contact', async () => {
      // 1. Ajouter un contact non-utilisateur
      const contact1 = await contactService.addContact({
        email: 'lifecycle@test.com',
        firstName: 'Lifecycle',
        tags: ['test']
      }, testUser1._id);

      expect(contact1.contact.status).toBe('pending');
      expect(contact1.userExists).toBe(false);

      // 2. L'utilisateur s'inscrit plus tard
      const newUser = await User.create({
        username: 'lifecycle',
        email: 'lifecycle@test.com',
        password: 'password123'
      });

      // 3. Ajouter à nouveau devrait détecter l'utilisateur
      await expect(
        contactService.addContact({
          email: 'lifecycle@test.com'
        }, testUser1._id)
      ).rejects.toThrow('existe déjà');

      // 4. Mettre à jour manuellement le contact
      const contact = await Contact.findById(contact1.contact._id);
      contact.contactUserId = newUser._id;
      contact.status = 'active';
      await contact.save();

      // 5. Créer un handshake
      const handshake = await contactService.createAutomaticHandshake(
        testUser1._id,
        newUser._id,
        'manual'
      );

      expect(handshake).toBeDefined();
      expect(handshake.status).toBe('pending');

      // 6. Tracking complet
      await contactService.updateTracking(contact._id, 'sent');
      await contactService.updateTracking(contact._id, 'opened');
      await contactService.updateTracking(contact._id, 'submitted');

      // 7. Vérifier l'état final
      const finalContact = await Contact.findById(contact._id);
      expect(finalContact.tracking.invitationsSent).toBe(1);
      expect(finalContact.tracking.responsesReceived).toBe(1);
      expect(finalContact.tracking.responseRate).toBeGreaterThan(0);
    });
  });
});