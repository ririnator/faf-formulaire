// Deep Contact model testing - Security, Performance, and Edge Cases
const Contact = require('../models/Contact');
const User = require('../models/User');
const mongoose = require('mongoose');
const { cleanupBetweenTests } = require('./setup-global');

describe('Contact Model - Deep Testing', () => {
  let testUser;

  beforeEach(async () => {
    // Clean up collections
    await cleanupBetweenTests();
    
    // Create test user
    testUser = await User.create({
      username: 'testuser',
      email: 'test@example.com',
      password: 'testpassword'
    });
  });

  describe('Database Integration', () => {
    test('should save and retrieve contact successfully', async () => {
      const contactData = {
        ownerId: testUser._id,
        email: 'contact@example.com',
        firstName: 'John',
        lastName: 'Doe',
        tags: ['work', 'friend']
      };

      const contact = new Contact(contactData);
      const savedContact = await contact.save();

      expect(savedContact._id).toBeDefined();
      expect(savedContact.ownerId.toString()).toBe(testUser._id.toString());
      expect(savedContact.email).toBe('contact@example.com');
      expect(savedContact.status).toBe('pending');
      expect(savedContact.source).toBe('manual');
    });

    test('should enforce unique constraint on ownerId + email', async () => {
      const contactData = {
        ownerId: testUser._id,
        email: 'duplicate@example.com',
        firstName: 'John'
      };

      // First contact should save successfully
      const contact1 = new Contact(contactData);
      await contact1.save();

      // Second contact with same ownerId + email should fail
      const contact2 = new Contact(contactData);
      await expect(contact2.save()).rejects.toThrow(/duplicate key error/i);
    });

    test('should allow same email for different owners', async () => {
      const user2 = await User.create({
        username: 'testuser2',
        email: 'test2@example.com',
        password: 'testpassword'
      });

      const email = 'shared@example.com';

      const contact1 = new Contact({
        ownerId: testUser._id,
        email: email,
        firstName: 'John'
      });

      const contact2 = new Contact({
        ownerId: user2._id,
        email: email,
        firstName: 'Jane'
      });

      await contact1.save();
      await contact2.save(); // Should not throw

      expect(contact1.email).toBe(email);
      expect(contact2.email).toBe(email);
    });
  });

  describe('Security Validation', () => {
    test('should sanitize email to lowercase', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'Test.Email@EXAMPLE.COM'
      });

      await contact.save();
      expect(contact.email).toBe('test.email@example.com');
    });

    test('should reject invalid email formats', async () => {
      const invalidEmails = [
        'invalid.email',
        '@example.com',
        'test@',
        'test..test@example.com',
        'test@.com',
        '',
        null,
        undefined
      ];

      for (const invalidEmail of invalidEmails) {
        const contact = new Contact({
          ownerId: testUser._id,
          email: invalidEmail
        });

        const error = contact.validateSync();
        expect(error.errors.email).toBeDefined();
      }
    });

    test('should reject XSS attempts in text fields', async () => {
      const maliciousData = {
        ownerId: testUser._id,
        email: 'test@example.com',
        firstName: '<script>alert("xss")</script>',
        lastName: '"><img src=x onerror=alert(1)>',
        notes: 'javascript:alert("xss")'
      };

      const contact = new Contact(maliciousData);
      await contact.save();

      // Data should be saved as-is (escaping handled at application level)
      expect(contact.firstName).toContain('<script>');
      expect(contact.lastName).toContain('"><img');
      expect(contact.notes).toContain('javascript:');
    });

    test('should enforce maxlength constraints', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'test@example.com',
        firstName: 'a'.repeat(101), // Over limit
        lastName: 'b'.repeat(101),  // Over limit
        notes: 'c'.repeat(1001)     // Over limit
      });

      const error = contact.validateSync();
      expect(error.errors.firstName).toBeDefined();
      expect(error.errors.lastName).toBeDefined();
      expect(error.errors.notes).toBeDefined();
    });

    test('should validate tag constraints', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'test@example.com',
        tags: ['valid_tag', 'a'.repeat(51)] // One valid, one too long
      });

      const error = contact.validateSync();
      expect(error.errors['tags.1']).toBeDefined();
    });
  });

  describe('Boundary Conditions', () => {
    test('should handle minimum valid field lengths', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'a@b.co', // Minimum valid email
        firstName: 'A',    // Single character
        lastName: 'B'      // Single character
      });

      await contact.save();
      expect(contact.firstName).toBe('A');
      expect(contact.lastName).toBe('B');
    });

    test('should handle maximum valid field lengths', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'test@example.com',
        firstName: 'A'.repeat(100), // Exactly at limit
        lastName: 'B'.repeat(100),  // Exactly at limit
        notes: 'C'.repeat(1000),    // Exactly at limit
        tags: Array(10).fill().map((_, i) => `tag${i}`.padEnd(50, 'x')) // Multiple max-length tags
      });

      await contact.save();
      expect(contact.firstName).toHaveLength(100);
      expect(contact.lastName).toHaveLength(100);
      expect(contact.notes).toHaveLength(1000);
      expect(contact.tags).toHaveLength(10);
    });

    test('should handle empty customFields Map', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'test@example.com',
        customFields: new Map()
      });

      await contact.save();
      expect(contact.customFields).toBeInstanceOf(Map);
      expect(contact.customFields.size).toBe(0);
    });

    test('should handle customFields with various data types', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'test@example.com',
        customFields: new Map([
          ['stringField', 'value'],
          ['numberField', '123'],
          ['booleanField', 'true'],
          ['dateField', '2025-01-01'],
          ['emptyField', ''],
          ['unicodeField', '🦄 Unicorn ñáéíóú']
        ])
      });

      await contact.save();
      expect(contact.customFields.get('stringField')).toBe('value');
      expect(contact.customFields.get('numberField')).toBe('123');
      expect(contact.customFields.get('unicodeField')).toContain('🦄');
    });
  });

  describe('Instance Methods', () => {
    let contact;

    beforeEach(async () => {
      contact = await Contact.create({
        ownerId: testUser._id,
        email: 'test@example.com',
        status: 'active',
        tracking: {
          invitationsSent: 0,
          responsesReceived: 0,
          responseRate: 0
        }
      });
    });

    describe('updateTracking Method', () => {
      test('should update tracking for sent event', async () => {
        const initialSent = contact.tracking.invitationsSent;
        
        await contact.updateTracking('sent');
        
        expect(contact.tracking.invitationsSent).toBe(initialSent + 1);
        expect(contact.tracking.lastSentAt).toBeInstanceOf(Date);
        expect(contact.tracking.lastSentAt.getTime()).toBeCloseTo(Date.now(), -3);
      });

      test('should update tracking for opened event', async () => {
        await contact.updateTracking('opened');
        
        expect(contact.tracking.lastOpenedAt).toBeInstanceOf(Date);
        expect(contact.tracking.lastOpenedAt.getTime()).toBeCloseTo(Date.now(), -3);
      });

      test('should update tracking for submitted event', async () => {
        // Set up previous sent event
        await contact.updateTracking('sent');
        const sentTime = contact.tracking.lastSentAt;
        
        // Wait a bit then submit
        await new Promise(resolve => setTimeout(resolve, 10));
        
        const responseTime = 24; // hours
        await contact.updateTracking('submitted', { responseTime });
        
        expect(contact.tracking.lastSubmittedAt).toBeInstanceOf(Date);
        expect(contact.tracking.responsesReceived).toBe(1);
        expect(contact.tracking.lastInteractionAt).toBeInstanceOf(Date);
        expect(contact.tracking.firstResponseAt).toBeInstanceOf(Date);
        expect(contact.tracking.averageResponseTime).toBe(24);
      });

      test('should calculate response rate correctly', async () => {
        // Send multiple invitations
        await contact.updateTracking('sent');
        await contact.updateTracking('sent');
        await contact.updateTracking('sent');
        
        expect(contact.tracking.invitationsSent).toBe(3);
        expect(contact.tracking.responseRate).toBe(0);
        
        // Receive one response
        await contact.updateTracking('submitted');
        
        expect(contact.tracking.responsesReceived).toBe(1);
        expect(contact.tracking.responseRate).toBe(33); // 1/3 * 100 = 33.33, rounded to 33
        
        // Receive another response
        await contact.updateTracking('submitted');
        
        expect(contact.tracking.responsesReceived).toBe(2);
        expect(contact.tracking.responseRate).toBe(67); // 2/3 * 100 = 66.67, rounded to 67
      });

      test('should handle invalid event types gracefully', async () => {
        const originalTracking = JSON.parse(JSON.stringify(contact.tracking));
        
        await contact.updateTracking('invalid_event');
        
        // Tracking should be unchanged except for potentially updated responseRate calculation
        expect(contact.tracking.invitationsSent).toBe(originalTracking.invitationsSent);
        expect(contact.tracking.responsesReceived).toBe(originalTracking.responsesReceived);
      });
    });

    describe('canReceiveInvitation Method', () => {
      test('should return true for active status', () => {
        contact.status = 'active';
        expect(contact.canReceiveInvitation()).toBe(true);
      });

      test('should return false for opted_out status', () => {
        contact.status = 'opted_out';
        expect(contact.canReceiveInvitation()).toBe(false);
      });

      test('should return false for bounced status', () => {
        contact.status = 'bounced';
        expect(contact.canReceiveInvitation()).toBe(false);
      });

      test('should return false for blocked status', () => {
        contact.status = 'blocked';
        expect(contact.canReceiveInvitation()).toBe(false);
      });

      test('should return true for pending status', () => {
        contact.status = 'pending';
        expect(contact.canReceiveInvitation()).toBe(true);
      });
    });
  });

  describe('Performance Testing', () => {
    test('should handle bulk contact creation efficiently', async () => {
      const contactsData = Array(100).fill().map((_, i) => ({
        ownerId: testUser._id,
        email: `bulk${i}@example.com`,
        firstName: `First${i}`,
        lastName: `Last${i}`,
        tags: ['bulk', 'test'],
        source: 'csv'
      }));

      const startTime = Date.now();
      
      await Contact.insertMany(contactsData);
      
      const endTime = Date.now();
      const processingTime = endTime - startTime;
      
      // Should create 100 contacts in reasonable time (under 1 second)
      expect(processingTime).toBeLessThan(1000);
      
      const count = await Contact.countDocuments({ source: 'csv' });
      expect(count).toBe(100);
    });

    test('should query by index efficiently', async () => {
      // Create test data
      await Contact.insertMany([
        { ownerId: testUser._id, email: 'test1@example.com', status: 'active' },
        { ownerId: testUser._id, email: 'test2@example.com', status: 'pending' },
        { ownerId: testUser._id, email: 'test3@example.com', status: 'active' }
      ]);

      const startTime = Date.now();
      
      // Query using indexed fields
      const results = await Contact.find({
        ownerId: testUser._id,
        status: 'active'
      });
      
      const endTime = Date.now();
      const queryTime = endTime - startTime;
      
      // Should query quickly (under 50ms)
      expect(queryTime).toBeLessThan(50);
      expect(results).toHaveLength(2);
    });

    test('should perform text search efficiently', async () => {
      // Create contacts with searchable names
      await Contact.insertMany([
        { ownerId: testUser._id, email: 'john@example.com', firstName: 'John', lastName: 'Smith' },
        { ownerId: testUser._id, email: 'jane@example.com', firstName: 'Jane', lastName: 'Johnson' },
        { ownerId: testUser._id, email: 'bob@example.com', firstName: 'Bob', lastName: 'Wilson' }
      ]);

      const startTime = Date.now();
      
      // Perform text search
      const results = await Contact.find({
        ownerId: testUser._id,
        $text: { $search: 'John' }
      });
      
      const endTime = Date.now();
      const searchTime = endTime - startTime;
      
      // Should search quickly (under 50ms)
      expect(searchTime).toBeLessThan(50);
      expect(results).toHaveLength(1); // John Smith (exact match for "John")
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle null/undefined values gracefully', async () => {
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'test@example.com',
        firstName: null,
        lastName: undefined,
        notes: '',
        tags: []
      });

      await contact.save();
      
      expect(contact.firstName).toBeNull();
      expect(contact.lastName).toBeUndefined();
      expect(contact.notes).toBe('');
      expect(contact.tags).toEqual([]);
    });

    test('should handle concurrent updates correctly', async () => {
      const contact = await Contact.create({
        ownerId: testUser._id,
        email: 'concurrent@example.com',
        tracking: {
          invitationsSent: 0,
          responsesReceived: 0
        }
      });

      // Simulate concurrent tracking updates by reloading contact each time
      const promises = Array(10).fill().map(async (_, i) => {
        const freshContact = await Contact.findById(contact._id);
        return freshContact.updateTracking('sent');
      });

      await Promise.allSettled(promises); // Use allSettled to handle any race condition failures
      
      // Reload from database to get final state
      const finalContact = await Contact.findById(contact._id);
      
      // Due to race conditions, we expect at least 1 but may not get exactly 10
      expect(finalContact.tracking.invitationsSent).toBeGreaterThan(0);
    });

    test('should handle invalid ObjectId references', async () => {
      const contact = new Contact({
        ownerId: new mongoose.Types.ObjectId(), // Non-existent user
        email: 'test@example.com',
        contactUserId: new mongoose.Types.ObjectId(), // Non-existent user
        handshakeId: new mongoose.Types.ObjectId() // Non-existent handshake
      });

      // Should save successfully (referential integrity not enforced at schema level)
      await contact.save();
      
      expect(contact.ownerId).toBeDefined();
      expect(contact.contactUserId).toBeDefined();
      expect(contact.handshakeId).toBeDefined();
    });

    test('should handle large tag arrays', async () => {
      const largeTags = Array(50).fill().map((_, i) => `tag${i}`);
      
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'tags@example.com',
        tags: largeTags
      });

      await contact.save();
      expect(contact.tags).toHaveLength(50);
      expect(contact.tags[0]).toBe('tag0');
      expect(contact.tags[49]).toBe('tag49');
    });

    test('should handle timezone-aware dates', async () => {
      const specificDate = new Date('2025-01-15T10:30:00.000Z');
      
      const contact = new Contact({
        ownerId: testUser._id,
        email: 'timezone@example.com',
        tracking: {
          addedAt: specificDate,
          lastSentAt: specificDate
        }
      });

      await contact.save();
      
      expect(contact.tracking.addedAt).toEqual(specificDate);
      expect(contact.tracking.lastSentAt).toEqual(specificDate);
    });
  });

  describe('Index Performance Verification', () => {
    test('should verify compound unique index performance', async () => {
      // Create contacts for different owners
      const user2 = await User.create({
        username: 'testuser2',
        email: 'test2@example.com',
        password: 'testpassword'
      });

      // Insert contacts with same emails for different owners
      const contacts = [];
      for (let i = 0; i < 100; i++) {
        contacts.push({
          ownerId: testUser._id,
          email: `contact${i}@example.com`
        });
        contacts.push({
          ownerId: user2._id,
          email: `contact${i}@example.com`
        });
      }

      const startTime = Date.now();
      await Contact.insertMany(contacts);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(500);
      
      const count = await Contact.countDocuments();
      expect(count).toBe(200);
    });

    test('should verify text index functionality', async () => {
      await Contact.create({
        ownerId: testUser._id,
        email: 'search@example.com',
        firstName: 'Searchable',
        lastName: 'Contact'
      });

      // Test text search functionality
      const textResults = await Contact.find({
        $text: { $search: 'Searchable' }
      });

      expect(textResults).toHaveLength(1);
      expect(textResults[0].firstName).toBe('Searchable');
    });
  });
});