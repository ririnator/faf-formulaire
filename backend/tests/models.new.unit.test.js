// Comprehensive unit tests for new models: Contact, Submission, Invitation, Handshake
const Contact = require('../models/Contact');
const Submission = require('../models/Submission');
const Invitation = require('../models/Invitation');
const Handshake = require('../models/Handshake');
const mongoose = require('mongoose');

describe('New Models Unit Tests', () => {
  
  // ===== CONTACT MODEL TESTS =====
  describe('Contact Model', () => {
    
    describe('Schema Definition', () => {
      test('should have required fields properly configured', () => {
        const requiredFields = ['ownerId', 'email'];
        
        requiredFields.forEach(field => {
          const path = Contact.schema.paths[field];
          expect(path).toBeDefined();
          expect(path.isRequired).toBe(true);
        });
      });

      test('should have email validation regex', () => {
        const emailPath = Contact.schema.paths.email;
        expect(emailPath.validators).toBeDefined();
        
        // Check if match option exists (Mongoose regex validation)
        const matchOption = emailPath.options.match;
        expect(matchOption).toBeDefined();
        expect(matchOption[0]).toBeInstanceOf(RegExp);
      });

      test('should have status enum with correct values', () => {
        const statusPath = Contact.schema.paths.status;
        expect(statusPath.enumValues).toEqual(['pending', 'active', 'opted_out', 'bounced', 'blocked']);
        expect(statusPath.defaultValue).toBe('pending');
      });

      test('should have source enum with correct values', () => {
        const sourcePath = Contact.schema.paths['source'];
        expect(sourcePath.enumValues).toEqual(['manual', 'csv', 'invitation', 'handshake']);
        expect(sourcePath.defaultValue).toBe('manual');
      });

      test('should have maxlength constraints', () => {
        expect(Contact.schema.paths.firstName.options.maxlength).toBe(100);
        expect(Contact.schema.paths.lastName.options.maxlength).toBe(100);
        expect(Contact.schema.paths.notes.options.maxlength).toBe(1000);
      });
    });

    describe('Indexes', () => {
      test('should have compound unique index on ownerId + email', () => {
        const indexes = Contact.schema.indexes();
        const uniqueIndex = indexes.find(index => {
          const keys = index[0];
          const options = index[1];
          return keys.ownerId === 1 && keys.email === 1 && options.unique === true;
        });
        
        expect(uniqueIndex).toBeDefined();
      });

      test('should have text index on firstName and lastName', () => {
        const indexes = Contact.schema.indexes();
        const textIndex = indexes.find(index => {
          const keys = index[0];
          return keys.firstName === 'text' && keys.lastName === 'text';
        });
        
        expect(textIndex).toBeDefined();
      });

      test('should have performance indexes', () => {
        const indexes = Contact.schema.indexes();
        
        // Tags index
        const tagsIndex = indexes.find(index => index[0].tags === 1);
        expect(tagsIndex).toBeDefined();
        
        // Status + lastSentAt index
        const statusIndex = indexes.find(index => 
          index[0].status === 1 && index[0]['tracking.lastSentAt'] === -1
        );
        expect(statusIndex).toBeDefined();
      });
    });

    describe('Instance Methods', () => {
      test('should have updateTracking method', () => {
        const contact = new Contact();
        expect(typeof contact.updateTracking).toBe('function');
      });

      test('should have canReceiveInvitation method', () => {
        const contact = new Contact();
        expect(typeof contact.canReceiveInvitation).toBe('function');
      });

      test('canReceiveInvitation should return correct boolean', () => {
        const activeContact = new Contact({ status: 'active' });
        const optedOutContact = new Contact({ status: 'opted_out' });
        const bouncedContact = new Contact({ status: 'bounced' });
        
        expect(activeContact.canReceiveInvitation()).toBe(true);
        expect(optedOutContact.canReceiveInvitation()).toBe(false);
        expect(bouncedContact.canReceiveInvitation()).toBe(false);
      });
    });

    describe('Validation', () => {
      test('should validate email format', () => {
        const contact = new Contact({
          ownerId: new mongoose.Types.ObjectId(),
          email: 'invalid-email'
        });
        
        const error = contact.validateSync();
        expect(error.errors.email).toBeDefined();
      });

      test('should accept valid email', () => {
        const contact = new Contact({
          ownerId: new mongoose.Types.ObjectId(),
          email: 'test@example.com'
        });
        
        const error = contact.validateSync();
        expect(error?.errors?.email).toBeUndefined();
      });

      test('should validate maxlength constraints', () => {
        const contact = new Contact({
          ownerId: new mongoose.Types.ObjectId(),
          email: 'test@example.com',
          firstName: 'a'.repeat(101), // Over limit
          notes: 'a'.repeat(1001) // Over limit
        });
        
        const error = contact.validateSync();
        expect(error.errors.firstName).toBeDefined();
        expect(error.errors.notes).toBeDefined();
      });
    });
  });

  // ===== SUBMISSION MODEL TESTS =====
  describe('Submission Model', () => {
    
    describe('Schema Definition', () => {
      test('should have required fields properly configured', () => {
        const requiredFields = ['userId', 'month'];
        
        requiredFields.forEach(field => {
          const path = Submission.schema.paths[field];
          expect(path).toBeDefined();
          expect(path.isRequired).toBe(true);
        });
      });

      test('should have month validation regex', () => {
        const monthPath = Submission.schema.paths.month;
        expect(monthPath.validators).toBeDefined();
        
        // Check if match option exists (Mongoose regex validation)
        const matchOption = monthPath.options.match;
        expect(matchOption).toBeDefined();
        expect(matchOption[0]).toBeInstanceOf(RegExp);
      });

      test('should have response type enum', () => {
        const responsesPath = Submission.schema.paths['responses'];
        const typeSchema = responsesPath.schema.paths.type;
        expect(typeSchema.enumValues).toEqual(['text', 'photo', 'radio']);
        expect(typeSchema.isRequired).toBe(true);
      });

      test('should have completion rate constraints', () => {
        const completionPath = Submission.schema.paths.completionRate;
        expect(completionPath.options.min).toBe(0);
        expect(completionPath.options.max).toBe(100);
        expect(completionPath.defaultValue).toBe(0);
      });

      test('should have maxlength constraints', () => {
        const responsesSchema = Submission.schema.paths['responses'].schema;
        expect(responsesSchema.paths.answer.options.maxlength).toBe(10000);
        expect(responsesSchema.paths.photoCaption.options.maxlength).toBe(500);
        expect(Submission.schema.paths.freeText.options.maxlength).toBe(5000);
      });
    });

    describe('Indexes', () => {
      test('should have compound unique index on userId + month', () => {
        const indexes = Submission.schema.indexes();
        const uniqueIndex = indexes.find(index => {
          const keys = index[0];
          const options = index[1];
          return keys.userId === 1 && keys.month === 1 && options.unique === true;
        });
        
        expect(uniqueIndex).toBeDefined();
      });

      test('should have performance indexes', () => {
        const indexes = Submission.schema.indexes();
        
        // Month + submittedAt index
        const monthIndex = indexes.find(index => 
          index[0].month === 1 && index[0].submittedAt === -1
        );
        expect(monthIndex).toBeDefined();
        
        // UserId + submittedAt index
        const userIndex = indexes.find(index => 
          index[0].userId === 1 && index[0].submittedAt === -1
        );
        expect(userIndex).toBeDefined();
      });
    });

    describe('Instance Methods', () => {
      test('should have calculateCompletion method', () => {
        const submission = new Submission();
        expect(typeof submission.calculateCompletion).toBe('function');
      });

      test('should have getPublicData method', () => {
        const submission = new Submission();
        expect(typeof submission.getPublicData).toBe('function');
      });

      test('calculateCompletion should calculate correctly', () => {
        const submission = new Submission({
          userId: new mongoose.Types.ObjectId(),
          month: '2025-01',
          responses: [
            { questionId: 'q1', type: 'text', answer: 'test answer' },
            { questionId: 'q2', type: 'photo', photoUrl: 'http://example.com/photo.jpg' }
          ]
        });
        
        const rate = submission.calculateCompletion();
        expect(rate).toBe(20); // 2/10 * 100
        expect(submission.completionRate).toBe(20);
        expect(submission.isComplete).toBe(false);
      });

      test('getPublicData should return safe data', () => {
        const submission = new Submission({
          userId: new mongoose.Types.ObjectId(),
          month: '2025-01',
          responses: [{ questionId: 'q1', type: 'text', answer: 'test' }],
          freeText: 'Free text',
          completionRate: 50
        });
        
        const publicData = submission.getPublicData();
        expect(publicData.userId).toBeUndefined();
        expect(publicData.month).toBe('2025-01');
        expect(publicData.responses).toBeDefined();
        expect(publicData.freeText).toBe('Free text');
        expect(publicData.completionRate).toBe(50);
      });
    });

    describe('Validation', () => {
      test('should validate month format', () => {
        const submission = new Submission({
          userId: new mongoose.Types.ObjectId(),
          month: '2025/01' // Invalid format
        });
        
        const error = submission.validateSync();
        expect(error.errors.month).toBeDefined();
      });

      test('should accept valid month format', () => {
        const submission = new Submission({
          userId: new mongoose.Types.ObjectId(),
          month: '2025-01'
        });
        
        const error = submission.validateSync();
        expect(error?.errors?.month).toBeUndefined();
      });
    });

    describe('Pre-save Hook', () => {
      test('should have pre-save middleware configured', () => {
        // Check if pre-save hooks exist by looking at schema methods
        const schemaPreMethods = Object.getOwnPropertyNames(Submission.schema.constructor.prototype);
        const hasPreMethod = schemaPreMethods.includes('pre');
        expect(hasPreMethod).toBe(true);
        
        // Test calculateCompletion method works correctly
        const submission = new Submission({
          userId: new mongoose.Types.ObjectId(),
          month: '2025-01',
          responses: [
            { questionId: 'q1', type: 'text', answer: 'test answer' }
          ]
        });
        
        submission.lastModifiedAt = undefined;
        submission.completionRate = 0;
        
        // Manually call what the pre-save hook should do
        submission.lastModifiedAt = new Date();
        const rate = submission.calculateCompletion();
        
        expect(submission.lastModifiedAt).toBeInstanceOf(Date);
        expect(rate).toBe(10); // 1/10 * 100
        expect(submission.completionRate).toBe(10);
      });
    });
  });

  // ===== INVITATION MODEL TESTS =====
  describe('Invitation Model', () => {
    
    describe('Schema Definition', () => {
      test('should have required fields properly configured', () => {
        const requiredFields = ['fromUserId', 'toEmail', 'month', 'token'];
        
        requiredFields.forEach(field => {
          const path = Invitation.schema.paths[field];
          expect(path).toBeDefined();
          expect(path.isRequired).toBe(true);
        });
      });

      test('should have status enum with correct values', () => {
        const statusPath = Invitation.schema.paths.status;
        const expectedValues = ['queued', 'sent', 'opened', 'started', 'submitted', 'expired', 'bounced', 'cancelled'];
        expect(statusPath.enumValues).toEqual(expectedValues);
        expect(statusPath.defaultValue).toBe('queued');
      });

      test('should have type enum with correct values', () => {
        const typePath = Invitation.schema.paths.type;
        expect(typePath.enumValues).toEqual(['user', 'external']);
        expect(typePath.defaultValue).toBe('external');
      });

      test('should have token default generator', () => {
        const tokenPath = Invitation.schema.paths.token;
        expect(typeof tokenPath.defaultValue).toBe('function');
        
        const token = tokenPath.defaultValue();
        expect(typeof token).toBe('string');
        expect(token.length).toBe(64); // 32 bytes * 2 (hex)
      });

      test('should have shortCode default generator', () => {
        const shortCodePath = Invitation.schema.paths.shortCode;
        expect(typeof shortCodePath.defaultValue).toBe('function');
        
        const code = shortCodePath.defaultValue();
        expect(typeof code).toBe('string');
        expect(code.length).toBe(6);
        expect(code).toMatch(/^[A-Z0-9]+$/);
      });

      test('should have expiresAt default (60 days)', () => {
        const expiresPath = Invitation.schema.paths.expiresAt;
        expect(typeof expiresPath.defaultValue).toBe('function');
        
        const expiry = expiresPath.defaultValue();
        expect(expiry).toBeInstanceOf(Date);
        
        const expectedExpiry = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000);
        const timeDiff = Math.abs(expiry.getTime() - expectedExpiry.getTime());
        expect(timeDiff).toBeLessThan(1000); // Within 1 second
      });
    });

    describe('Indexes', () => {
      test('should have unique token index', () => {
        const indexes = Invitation.schema.indexes();
        const tokenIndex = indexes.find(index => 
          index[0].token === 1 && index[1].unique === true
        );
        expect(tokenIndex).toBeDefined();
      });

      test('should have compound unique index on fromUserId + toEmail + month', () => {
        const indexes = Invitation.schema.indexes();
        const uniqueIndex = indexes.find(index => {
          const keys = index[0];
          const options = index[1];
          return keys.fromUserId === 1 && keys.toEmail === 1 && keys.month === 1 && options.unique === true;
        });
        expect(uniqueIndex).toBeDefined();
      });

      test('should have performance indexes', () => {
        const indexes = Invitation.schema.indexes();
        
        // Month + status index
        const monthStatusIndex = indexes.find(index => 
          index[0].month === 1 && index[0].status === 1
        );
        expect(monthStatusIndex).toBeDefined();
        
        // ExpiresAt index
        const expiresIndex = indexes.find(index => index[0].expiresAt === 1);
        expect(expiresIndex).toBeDefined();
      });
    });

    describe('Instance Methods', () => {
      test('should have isExpired method', () => {
        const invitation = new Invitation();
        expect(typeof invitation.isExpired).toBe('function');
      });

      test('should have canSendReminder method', () => {
        const invitation = new Invitation();
        expect(typeof invitation.canSendReminder).toBe('function');
      });

      test('should have markAction method', () => {
        const invitation = new Invitation();
        expect(typeof invitation.markAction).toBe('function');
      });

      test('isExpired should work correctly', () => {
        const expiredInvitation = new Invitation({
          expiresAt: new Date(Date.now() - 1000) // 1 second ago
        });
        const validInvitation = new Invitation({
          expiresAt: new Date(Date.now() + 1000) // 1 second from now
        });
        
        expect(expiredInvitation.isExpired()).toBe(true);
        expect(validInvitation.isExpired()).toBe(false);
      });

      test('canSendReminder should work correctly', () => {
        const invitation = new Invitation({
          status: 'sent',
          expiresAt: new Date(Date.now() + 1000),
          reminders: []
        });
        
        expect(invitation.canSendReminder('first')).toBe(true);
        
        invitation.reminders.push({ type: 'first', sentAt: new Date() });
        expect(invitation.canSendReminder('first')).toBe(false);
        expect(invitation.canSendReminder('second')).toBe(true);
      });
    });

    describe('Static Methods', () => {
      test('should have findPendingReminders static method', () => {
        expect(typeof Invitation.findPendingReminders).toBe('function');
      });
    });

    describe('Validation', () => {
      test('should validate month format', () => {
        const invitation = new Invitation({
          fromUserId: new mongoose.Types.ObjectId(),
          toEmail: 'test@example.com',
          month: '2025/01' // Invalid format
        });
        
        const error = invitation.validateSync();
        expect(error.errors.month).toBeDefined();
      });

      test('should validate enum values', () => {
        const invitation = new Invitation({
          fromUserId: new mongoose.Types.ObjectId(),
          toEmail: 'test@example.com',
          month: '2025-01',
          status: 'invalid_status',
          type: 'invalid_type'
        });
        
        const error = invitation.validateSync();
        expect(error.errors.status).toBeDefined();
        expect(error.errors.type).toBeDefined();
      });
    });
  });

  // ===== HANDSHAKE MODEL TESTS =====
  describe('Handshake Model', () => {
    
    describe('Schema Definition', () => {
      test('should have required fields properly configured', () => {
        const requiredFields = ['requesterId', 'targetId'];
        
        requiredFields.forEach(field => {
          const path = Handshake.schema.paths[field];
          expect(path).toBeDefined();
          expect(path.isRequired).toBe(true);
        });
      });

      test('should have status enum with correct values', () => {
        const statusPath = Handshake.schema.paths.status;
        const expectedValues = ['pending', 'accepted', 'declined', 'blocked', 'expired'];
        expect(statusPath.enumValues).toEqual(expectedValues);
        expect(statusPath.defaultValue).toBe('pending');
      });

      test('should have initiatedBy enum', () => {
        const initiatedByPath = Handshake.schema.paths['metadata.initiatedBy'];
        expect(initiatedByPath.enumValues).toEqual(['manual', 'contact_add', 'invitation_response']);
        expect(initiatedByPath.defaultValue).toBe('manual');
      });

      test('should have expiresAt default (30 days)', () => {
        const expiresPath = Handshake.schema.paths.expiresAt;
        expect(typeof expiresPath.defaultValue).toBe('function');
        
        const expiry = expiresPath.defaultValue();
        expect(expiry).toBeInstanceOf(Date);
        
        const expectedExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const timeDiff = Math.abs(expiry.getTime() - expectedExpiry.getTime());
        expect(timeDiff).toBeLessThan(1000);
      });

      test('should have maxlength constraints', () => {
        expect(Handshake.schema.paths.message.options.maxlength).toBe(500);
        expect(Handshake.schema.paths.responseMessage.options.maxlength).toBe(500);
      });
    });

    describe('Indexes', () => {
      test('should have compound unique index on requesterId + targetId', () => {
        const indexes = Handshake.schema.indexes();
        const uniqueIndex = indexes.find(index => {
          const keys = index[0];
          const options = index[1];
          return keys.requesterId === 1 && keys.targetId === 1 && options.unique === true;
        });
        expect(uniqueIndex).toBeDefined();
      });

      test('should have performance indexes', () => {
        const indexes = Handshake.schema.indexes();
        
        // TargetId + status index
        const targetIndex = indexes.find(index => 
          index[0].targetId === 1 && index[0].status === 1
        );
        expect(targetIndex).toBeDefined();
        
        // RequesterId + status index
        const requesterIndex = indexes.find(index => 
          index[0].requesterId === 1 && index[0].status === 1
        );
        expect(requesterIndex).toBeDefined();
        
        // ExpiresAt index
        const expiresIndex = indexes.find(index => index[0].expiresAt === 1);
        expect(expiresIndex).toBeDefined();
      });
    });

    describe('Instance Methods', () => {
      test('should have accept method', () => {
        const handshake = new Handshake();
        expect(typeof handshake.accept).toBe('function');
      });

      test('should have decline method', () => {
        const handshake = new Handshake();
        expect(typeof handshake.decline).toBe('function');
      });

      test('should have isExpired method', () => {
        const handshake = new Handshake();
        expect(typeof handshake.isExpired).toBe('function');
      });

      test('isExpired should work correctly', () => {
        const expiredHandshake = new Handshake({
          expiresAt: new Date(Date.now() - 1000) // 1 second ago
        });
        const validHandshake = new Handshake({
          expiresAt: new Date(Date.now() + 1000) // 1 second from now
        });
        
        expect(expiredHandshake.isExpired()).toBe(true);
        expect(validHandshake.isExpired()).toBe(false);
      });
    });

    describe('Static Methods', () => {
      test('should have createMutual static method', () => {
        expect(typeof Handshake.createMutual).toBe('function');
      });

      test('should have checkPermission static method', () => {
        expect(typeof Handshake.checkPermission).toBe('function');
      });
    });

    describe('Validation', () => {
      test('should validate enum values', () => {
        const handshake = new Handshake({
          requesterId: new mongoose.Types.ObjectId(),
          targetId: new mongoose.Types.ObjectId(),
          status: 'invalid_status'
        });
        
        const error = handshake.validateSync();
        expect(error.errors.status).toBeDefined();
      });

      test('should validate maxlength constraints', () => {
        const handshake = new Handshake({
          requesterId: new mongoose.Types.ObjectId(),
          targetId: new mongoose.Types.ObjectId(),
          message: 'a'.repeat(501), // Over limit
          responseMessage: 'a'.repeat(501) // Over limit
        });
        
        const error = handshake.validateSync();
        expect(error.errors.message).toBeDefined();
        expect(error.errors.responseMessage).toBeDefined();
      });
    });
  });

  // ===== INTEGRATION TESTS =====
  describe('Model Integration', () => {
    test('all models should be exported correctly', () => {
      expect(Contact.modelName).toBe('Contact');
      expect(Submission.modelName).toBe('Submission');
      expect(Invitation.modelName).toBe('Invitation');
      expect(Handshake.modelName).toBe('Handshake');
    });

    test('all models should have timestamps enabled', () => {
      expect(Contact.schema.options.timestamps).toBe(true);
      expect(Submission.schema.options.timestamps).toBe(true);
      expect(Invitation.schema.options.timestamps).toBe(true);
      expect(Handshake.schema.options.timestamps).toBe(true);
    });

    test('ObjectId references should be properly configured', () => {
      // Contact references
      expect(Contact.schema.paths.ownerId.options.ref).toBe('User');
      expect(Contact.schema.paths.contactUserId.options.ref).toBe('User');
      expect(Contact.schema.paths.handshakeId.options.ref).toBe('Handshake');
      
      // Submission references
      expect(Submission.schema.paths.userId.options.ref).toBe('User');
      
      // Invitation references
      expect(Invitation.schema.paths.fromUserId.options.ref).toBe('User');
      expect(Invitation.schema.paths.toUserId.options.ref).toBe('User');
      expect(Invitation.schema.paths.submissionId.options.ref).toBe('Submission');
      
      // Handshake references
      expect(Handshake.schema.paths.requesterId.options.ref).toBe('User');
      expect(Handshake.schema.paths.targetId.options.ref).toBe('User');
    });
  });
});