const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');
const ContactService = require('../services/contactServiceInstance');
const Contact = require('../models/Contact');
const User = require('../models/User');
const Handshake = require('../models/Handshake');

describe('ContactService Tests', () => {
  let testUser, testUser2;

  beforeEach(async () => {
    await cleanupBetweenTests();

    // Créer des utilisateurs de test
    testUser = await User.create({
      username: 'testowner',
      email: 'owner@example.com',
      password: 'password123'
    });

    testUser2 = await User.create({
      username: 'contactuser',
      email: 'contact@example.com', 
      password: 'password123'
    });
  });

  describe('addContact Method', () => {
    test('should create a new contact successfully', async () => {
      const contactData = {
        email: 'newcontact@example.com',
        firstName: 'John',
        lastName: 'Doe',
        tags: ['friend', 'work'],
        notes: 'Test contact'
      };

      const result = await ContactService.addContact(contactData, testUser._id);

      expect(result.contact).toBeDefined();
      expect(result.contact.email).toBe('newcontact@example.com');
      expect(result.contact.firstName).toBe('John');
      expect(result.contact.lastName).toBe('Doe');
      expect(result.contact.tags).toEqual(['friend', 'work']);
      expect(result.contact.status).toBe('pending');
      expect(result.userExists).toBe(false);
      expect(result.handshakeCreated).toBe(false);
    });

    test('should create contact and handshake when user exists', async () => {
      const contactData = {
        email: testUser2.email, // Email d'un utilisateur existant
        firstName: 'Jane',
        lastName: 'Doe'
      };

      const result = await ContactService.addContact(contactData, testUser._id);

      expect(result.contact.contactUserId._id.toString()).toBe(testUser2._id.toString());
      expect(result.contact.status).toBe('active');
      expect(result.userExists).toBe(true);
      expect(result.handshakeCreated).toBe(true);
      expect(result.contact.handshakeId).toBeDefined();
    });

    test('should throw error for duplicate contact', async () => {
      const contactData = {
        email: 'duplicate@example.com',
        firstName: 'Test'
      };

      // Créer le premier contact
      await ContactService.addContact(contactData, testUser._id);

      // Tenter de créer un doublon
      await expect(
        ContactService.addContact(contactData, testUser._id)
      ).rejects.toThrow('Contact avec l\'email duplicate@example.com existe déjà');
    });

    test('should validate required fields', async () => {
      await expect(
        ContactService.addContact({}, testUser._id)
      ).rejects.toThrow('Email et ownerId sont requis');

      await expect(
        ContactService.addContact({ email: 'test@example.com' }, null)
      ).rejects.toThrow('Email et ownerId sont requis');
    });

    test('should trim and normalize data', async () => {
      const contactData = {
        email: '  CONTACT@EXAMPLE.COM  ',
        firstName: '  John  ',
        lastName: '  Doe  ',
        tags: ['  tag1  ', '  tag2  ', ''],
        notes: '  Some notes  '
      };

      const result = await ContactService.addContact(contactData, testUser._id);

      expect(result.contact.email).toBe('contact@example.com');
      expect(result.contact.firstName).toBe('John');
      expect(result.contact.lastName).toBe('Doe');
      expect(result.contact.tags).toEqual(['tag1', 'tag2']);
      expect(result.contact.notes).toBe('Some notes');
    });
  });

  describe('importCSV Method', () => {
    test('should import contacts from CSV data', async () => {
      const csvData = `email,firstname,lastname,tags
john@example.com,John,Doe,"friend,work"
jane@example.com,Jane,Smith,colleague
invalid-email,Test,User,friend`;

      const result = await ContactService.importCSV(csvData, testUser._id);

      expect(result.total).toBe(2); // Invalid email excluded during parsing
      expect(result.imported).toBe(2);
      expect(result.skipped).toBe(0);
      expect(result.errors).toHaveLength(0);
    });

    test('should handle CSV with different column names', async () => {
      const csvData = `mail,prenom,nom_famille,note
test@example.com,Test,User,Some notes`;

      const result = await ContactService.importCSV(csvData, testUser._id);

      expect(result.imported).toBe(1);
      
      const contact = await Contact.findOne({ email: 'test@example.com' });
      expect(contact.firstName).toBe('Test');
      expect(contact.lastName).toBe('User');
      expect(contact.notes).toBe('Some notes');
    });

    test('should skip duplicates when option enabled', async () => {
      // Créer un contact existant
      await ContactService.addContact({
        email: 'existing@example.com',
        firstName: 'Existing'
      }, testUser._id);

      const csvData = `email,firstname,lastname
existing@example.com,Existing,User
new@example.com,New,User`;

      const result = await ContactService.importCSV(csvData, testUser._id, {
        skipDuplicates: true
      });

      expect(result.imported).toBe(1);
      expect(result.skipped).toBe(1);
    });

    test('should process in batches', async () => {
      // Générer un CSV avec beaucoup de contacts
      let csvData = 'email,firstname,lastname\n';
      for (let i = 1; i <= 250; i++) {
        csvData += `user${i}@example.com,User,${i}\n`;
      }

      const result = await ContactService.importCSV(csvData, testUser._id, {
        batchSize: 100
      });

      expect(result.imported).toBe(250);
      expect(result.total).toBe(250);
    });
  });

  describe('getContactsWithStats Method', () => {
    beforeEach(async () => {
      // Créer des contacts de test avec différents statuts et sources
      const contacts = [
        { email: 'active1@example.com', status: 'active', source: 'manual', firstName: 'Active', tags: ['friend'] },
        { email: 'active2@example.com', status: 'active', source: 'csv', firstName: 'User', tags: ['work'] },
        { email: 'pending@example.com', status: 'pending', source: 'manual', firstName: 'Pending' },
        { email: 'opted@example.com', status: 'opted_out', source: 'csv', firstName: 'Opted' }
      ];

      for (const contactData of contacts) {
        await Contact.create({ ...contactData, ownerId: testUser._id });
      }
    });

    test('should return contacts with pagination', async () => {
      const result = await ContactService.getContactsWithStats(testUser._id, {}, {
        page: 1,
        limit: 2
      });

      expect(result.contacts).toHaveLength(2);
      expect(result.pagination.totalCount).toBe(4);
      expect(result.pagination.totalPages).toBe(2);
      expect(result.pagination.hasNext).toBe(true);
      expect(result.pagination.hasPrev).toBe(false);
    });

    test('should filter by search term', async () => {
      const result = await ContactService.getContactsWithStats(testUser._id, {
        search: 'Active'
      });

      expect(result.contacts).toHaveLength(2); // Active1 and Active2 (User)
      expect(result.contacts.every(c => 
        c.firstName.includes('Active') || c.firstName.includes('User')
      )).toBe(true);
    });

    test('should filter by status', async () => {
      const result = await ContactService.getContactsWithStats(testUser._id, {
        status: 'active'
      });

      expect(result.contacts).toHaveLength(2);
      expect(result.contacts.every(c => c.status === 'active')).toBe(true);
    });

    test('should filter by tags', async () => {
      const result = await ContactService.getContactsWithStats(testUser._id, {
        tags: ['friend']
      });

      expect(result.contacts).toHaveLength(1);
      expect(result.contacts[0].tags).toContain('friend');
    });

    test('should filter by source', async () => {
      const result = await ContactService.getContactsWithStats(testUser._id, {
        source: 'csv'
      });

      expect(result.contacts).toHaveLength(2);
      expect(result.contacts.every(c => c.source === 'csv')).toBe(true);
    });

    test('should return comprehensive stats', async () => {
      const result = await ContactService.getContactsWithStats(testUser._id);

      expect(result.stats).toBeDefined();
      expect(result.stats.basic).toBeDefined();
      expect(result.stats.basic.total).toBe(4);
      expect(result.stats.bySource).toBeDefined();
      expect(result.stats.byStatus).toBeDefined();
    });
  });

  describe('updateTracking Method', () => {
    let contact;

    beforeEach(async () => {
      contact = await Contact.create({
        ownerId: testUser._id,
        email: 'tracking@example.com',
        firstName: 'Track',
        lastName: 'Test'
      });
    });

    test('should update tracking for sent event', async () => {
      const result = await ContactService.updateTracking(contact._id, 'sent');

      expect(result.tracking.lastSentAt).toBeInstanceOf(Date);
      expect(result.tracking.invitationsSent).toBe(1);
    });

    test('should update tracking for opened event', async () => {
      const result = await ContactService.updateTracking(contact._id, 'opened');

      expect(result.tracking.lastOpenedAt).toBeInstanceOf(Date);
    });

    test('should update tracking for submitted event with response time', async () => {
      // D'abord marquer comme envoyé
      await ContactService.updateTracking(contact._id, 'sent');
      
      // Attendre un peu puis marquer comme soumis
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const result = await ContactService.updateTracking(contact._id, 'submitted');

      expect(result.tracking.lastSubmittedAt).toBeInstanceOf(Date);
      expect(result.tracking.responsesReceived).toBe(1);
      expect(result.tracking.averageResponseTime).toBeGreaterThanOrEqual(0);
    });

    test('should calculate response rate correctly', async () => {
      // Envoyer 3 invitations
      await ContactService.updateTracking(contact._id, 'sent');
      await ContactService.updateTracking(contact._id, 'sent');
      await ContactService.updateTracking(contact._id, 'sent');

      // Recevoir 1 réponse
      const result = await ContactService.updateTracking(contact._id, 'submitted');

      expect(result.tracking.invitationsSent).toBe(3);
      expect(result.tracking.responsesReceived).toBe(1);
      expect(result.tracking.responseRate).toBe(33); // 1/3 * 100 = 33%
    });

    test('should throw error for non-existent contact', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      
      await expect(
        ContactService.updateTracking(fakeId, 'sent')
      ).rejects.toThrow('Contact non trouvé');
    });
  });

  describe('createAutomaticHandshake Method', () => {
    test('should create handshake between two users', async () => {
      const handshake = await ContactService.createAutomaticHandshake(
        testUser._id, 
        testUser2._id, 
        'contact_add'
      );

      expect(handshake.requesterId._id.toString()).toBe(testUser._id.toString());
      expect(handshake.targetId._id.toString()).toBe(testUser2._id.toString());
      expect(handshake.status).toBe('pending');
      expect(handshake.metadata.initiatedBy).toBe('contact_add');
    });

    test('should throw error if handshake already exists', async () => {
      // Créer le premier handshake
      await ContactService.createAutomaticHandshake(testUser._id, testUser2._id);

      // Tenter de créer un doublon
      await expect(
        ContactService.createAutomaticHandshake(testUser._id, testUser2._id)
      ).rejects.toThrow('Une demande de handshake est déjà en cours');
    });

    test('should detect reverse handshake', async () => {
      // Créer handshake de user2 vers user1
      await ContactService.createAutomaticHandshake(testUser2._id, testUser._id);

      // Tenter de créer handshake de user1 vers user2
      await expect(
        ContactService.createAutomaticHandshake(testUser._id, testUser2._id)
      ).rejects.toThrow('Une demande de handshake est déjà en cours');
    });
  });

  describe('searchContacts Method', () => {
    beforeEach(async () => {
      await Contact.insertMany([
        {
          ownerId: testUser._id,
          email: 'john.doe@example.com',
          firstName: 'John',
          lastName: 'Doe',
          tags: ['developer'],
          status: 'active'
        },
        {
          ownerId: testUser._id,
          email: 'jane.smith@example.com',
          firstName: 'Jane',
          lastName: 'Smith',
          tags: ['designer'],
          status: 'active'
        },
        {
          ownerId: testUser._id,
          email: 'bob.developer@example.com',
          firstName: 'Bob',
          lastName: 'Wilson',
          tags: ['developer'],
          status: 'opted_out'
        }
      ]);
    });

    test('should search by first name', async () => {
      const results = await ContactService.searchContacts(testUser._id, 'John');

      expect(results).toHaveLength(1);
      expect(results[0].firstName).toBe('John');
    });

    test('should search by email', async () => {
      const results = await ContactService.searchContacts(testUser._id, 'jane.smith');

      expect(results).toHaveLength(1);
      expect(results[0].email).toBe('jane.smith@example.com');
    });

    test('should search by tags', async () => {
      const results = await ContactService.searchContacts(testUser._id, 'developer');

      expect(results).toHaveLength(1); // Only active contact with developer tag
      expect(results[0].tags).toContain('developer');
      expect(results[0].status).toBe('active');
    });

    test('should include inactive contacts when option enabled', async () => {
      const results = await ContactService.searchContacts(testUser._id, 'developer', {
        includeInactive: true
      });

      expect(results).toHaveLength(2); // Both active and opted_out contacts
    });

    test('should limit results', async () => {
      const results = await ContactService.searchContacts(testUser._id, 'example', {
        limit: 1
      });

      expect(results).toHaveLength(1);
    });
  });

  describe('deleteContact Method', () => {
    let contact, handshake;

    beforeEach(async () => {
      contact = await Contact.create({
        ownerId: testUser._id,
        email: 'delete@example.com',
        firstName: 'Delete',
        lastName: 'Test'
      });

      handshake = await Handshake.create({
        requesterId: testUser._id,
        targetId: testUser2._id
      });

      contact.handshakeId = handshake._id;
      await contact.save();
    });

    test('should delete contact and associated handshake', async () => {
      const result = await ContactService.deleteContact(contact._id, testUser._id);

      expect(result).toBe(true);

      // Vérifier que le contact est supprimé
      const deletedContact = await Contact.findById(contact._id);
      expect(deletedContact).toBeNull();

      // Vérifier que le handshake est supprimé
      const deletedHandshake = await Handshake.findById(handshake._id);
      expect(deletedHandshake).toBeNull();
    });

    test('should throw error for non-existent contact', async () => {
      const fakeId = new mongoose.Types.ObjectId();

      await expect(
        ContactService.deleteContact(fakeId, testUser._id)
      ).rejects.toThrow('Contact non trouvé ou non autorisé');
    });

    test('should throw error for unauthorized deletion', async () => {
      await expect(
        ContactService.deleteContact(contact._id, testUser2._id)
      ).rejects.toThrow('Contact non trouvé ou non autorisé');
    });
  });

  describe('Utility Methods', () => {
    describe('isValidEmail', () => {
      test('should validate correct email formats', () => {
        const validEmails = [
          'test@example.com',
          'user.name@domain.co.uk',
          'user@example.org'
        ];

        validEmails.forEach(email => {
          expect(ContactService.isValidEmail(email)).toBe(true);
        });
      });

      test('should reject invalid email formats', () => {
        const invalidEmails = [
          'invalid-email',
          '@domain.com',
          'user@',
          'user..name@domain.com',
          '',
          null,
          undefined,
          '.user@domain.com',
          'user@domain.com.'
        ];

        invalidEmails.forEach(email => {
          expect(ContactService.isValidEmail(email)).toBe(false);
        });
      });
    });

    describe('parseTags', () => {
      test('should parse comma-separated tags', () => {
        const result = ContactService.parseTags('tag1, tag2 , tag3');
        expect(result).toEqual(['tag1', 'tag2', 'tag3']);
      });

      test('should handle empty string', () => {
        const result = ContactService.parseTags('');
        expect(result).toEqual([]);
      });

      test('should limit to 10 tags', () => {
        const manyTags = Array(15).fill().map((_, i) => `tag${i}`).join(',');
        const result = ContactService.parseTags(manyTags);
        expect(result).toHaveLength(10);
      });
    });

    describe('validateContactData', () => {
      test('should validate correct contact data', () => {
        const contactData = {
          email: 'TEST@EXAMPLE.COM',
          firstName: '  John  ',
          lastName: '  Doe  ',
          tags: ['tag1', 'tag2'],
          notes: 'Test notes'
        };

        const result = ContactService.validateContactData(contactData);

        expect(result.email).toBe('test@example.com');
        expect(result.firstName).toBe('John');
        expect(result.lastName).toBe('Doe');
        expect(result.tags).toEqual(['tag1', 'tag2']);
        expect(result.notes).toBe('Test notes');
      });

      test('should throw error for missing email', () => {
        expect(() => {
          ContactService.validateContactData({});
        }).toThrow('Email est requis');
      });

      test('should throw error for invalid email', () => {
        expect(() => {
          ContactService.validateContactData({ email: 'invalid' });
        }).toThrow('Format d\'email invalide');
      });

      test('should throw error for too long fields', () => {
        expect(() => {
          ContactService.validateContactData({
            email: 'test@example.com',
            firstName: 'a'.repeat(101)
          });
        }).toThrow('Prénom trop long');

        expect(() => {
          ContactService.validateContactData({
            email: 'test@example.com',
            notes: 'a'.repeat(1001)
          });
        }).toThrow('Notes trop longues');

        expect(() => {
          ContactService.validateContactData({
            email: 'test@example.com',
            tags: ['a'.repeat(51)]
          });
        }).toThrow('Tag trop long');
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors gracefully', async () => {
      // Tenter d'ajouter un contact avec un ownerId invalide
      await expect(
        ContactService.addContact({
          email: 'test@example.com'
        }, 'invalid-id')
      ).rejects.toThrow();
    });

    test('should handle invalid CSV data gracefully', async () => {
      const invalidCSV = 'invalid,csv,format\nwith,wrong,"quote';

      const result = await ContactService.importCSV(invalidCSV, testUser._id);
      
      // CSV parser is tolerant, so it should not throw but return empty results
      expect(result.total).toBe(0);
      expect(result.imported).toBe(0);
    });
  });
});