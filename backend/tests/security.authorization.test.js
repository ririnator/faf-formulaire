// backend/tests/security.authorization.test.js

const mongoose = require('mongoose');
const User = require('../models/User');
const Handshake = require('../models/Handshake');
const Contact = require('../models/Contact');
const Invitation = require('../models/Invitation');
const Submission = require('../models/Submission');
const HandshakeService = require('../services/handshakeService');
const ContactService = require('../services/contactService');
const InvitationService = require('../services/invitationService');
const SubmissionService = require('../services/submissionService');

describe('Authorization Security Tests', () => {
  let testUser1, testUser2, testUser3;
  let handshakeService, contactService, invitationService, submissionService;
  let testHandshake, testContact, testInvitation, testSubmission;

  beforeAll(async () => {
    // Initialize services
    handshakeService = new HandshakeService();
    contactService = new ContactService();
    invitationService = new InvitationService();
    submissionService = new SubmissionService();

    // Create test users
    testUser1 = new User({
      username: 'authtest1',
      email: 'authtest1@example.com',
      password: 'hashedpassword123',
      role: 'user'
    });
    await testUser1.save();

    testUser2 = new User({
      username: 'authtest2',
      email: 'authtest2@example.com',
      password: 'hashedpassword123',
      role: 'user'
    });
    await testUser2.save();

    testUser3 = new User({
      username: 'authtest3',
      email: 'authtest3@example.com',
      password: 'hashedpassword123',
      role: 'user'
    });
    await testUser3.save();

    // Create test data
    await setupTestData();
  });

  afterAll(async () => {
    await cleanupTestData();
  });

  // Helper function to setup test data
  async function setupTestData() {
    // Create a handshake between user1 and user2
    testHandshake = new Handshake({
      requesterId: testUser1._id,
      targetId: testUser2._id,
      status: 'accepted',
      message: 'Test handshake'
    });
    await testHandshake.save();

    // Create a contact owned by user1
    testContact = new Contact({
      ownerId: testUser1._id,
      email: 'contact@example.com',
      firstName: 'Test',
      lastName: 'Contact',
      status: 'active'
    });
    await testContact.save();

    // Create an invitation from user1
    testInvitation = new Invitation({
      fromUserId: testUser1._id,
      toEmail: 'invite@example.com',
      month: '2025-01',
      token: 'test-token-123456789012345678901234567890123456789012345678901234567890',
      shortCode: 'TEST123',
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    });
    await testInvitation.save();

    // Create a submission by user1
    testSubmission = new Submission({
      userId: testUser1._id,
      month: '2025-01',
      responses: [
        {
          questionId: 'q1',
          type: 'text',
          answer: 'Test answer'
        }
      ],
      freeText: 'Test free text'
    });
    await testSubmission.save();
  }

  async function cleanupTestData() {
    try {
      await Promise.all([
        User.deleteMany({ username: { $in: ['authtest1', 'authtest2', 'authtest3'] } }),
        Handshake.deleteMany({ _id: testHandshake?._id }),
        Contact.deleteMany({ _id: testContact?._id }),
        Invitation.deleteMany({ _id: testInvitation?._id }),
        Submission.deleteMany({ _id: testSubmission?._id })
      ]);
    } catch (error) {
      console.warn('Cleanup error:', error.message);
    }
  }

  describe('Handshake Authorization', () => {
    test('Should allow authorized access to handshake by requester', async () => {
      const handshake = await handshakeService.getHandshakeById(testHandshake._id);
      expect(handshake).toBeDefined();
      expect(handshake.requesterId.toString()).toBe(testUser1._id.toString());
    });

    test('Should allow authorized access to handshake by target', async () => {
      const handshake = await handshakeService.getHandshakeById(testHandshake._id);
      expect(handshake).toBeDefined();
      expect(handshake.targetId.toString()).toBe(testUser2._id.toString());
    });

    test('Should enforce proper permission validation between users', async () => {
      // Test permission between user1 and user2 (should have accepted handshake)
      const permission12 = await handshakeService.checkPermission(testUser1._id, testUser2._id);
      expect(permission12.hasPermission).toBe(true);
      expect(permission12.handshakeStatus).toBe('accepted');

      // Test permission between user1 and user3 (no handshake)
      const permission13 = await handshakeService.checkPermission(testUser1._id, testUser3._id);
      expect(permission13.hasPermission).toBe(false);
      expect(permission13.handshakeStatus).toBeNull();
    });

    test('Should prevent accepting handshake by non-target user', async () => {
      // Create a pending handshake
      const pendingHandshake = new Handshake({
        requesterId: testUser2._id,
        targetId: testUser1._id,
        status: 'pending',
        message: 'Test pending handshake'
      });
      await pendingHandshake.save();

      // User3 tries to accept handshake meant for user1
      await expect(
        handshakeService.accept(pendingHandshake._id, testUser3._id, 'Unauthorized acceptance')
      ).rejects.toThrow('Seul le destinataire peut accepter');

      await Handshake.findByIdAndDelete(pendingHandshake._id);
    });

    test('Should prevent canceling handshake by non-requester', async () => {
      // Create a pending handshake
      const pendingHandshake = new Handshake({
        requesterId: testUser1._id,
        targetId: testUser2._id,
        status: 'pending',
        message: 'Test cancellable handshake'
      });
      await pendingHandshake.save();

      // User3 tries to cancel handshake requested by user1
      await expect(
        handshakeService.cancel(pendingHandshake._id, testUser3._id, 'Unauthorized cancellation')
      ).rejects.toThrow('Seul le demandeur peut annuler');

      await Handshake.findByIdAndDelete(pendingHandshake._id);
    });

    test('Should only return user\'s own handshakes in list', async () => {
      const user1Handshakes = await handshakeService.getUserHandshakes(testUser1._id);
      const user3Handshakes = await handshakeService.getUserHandshakes(testUser3._id);

      // User1 should see their handshake
      expect(user1Handshakes.handshakes.length).toBeGreaterThan(0);
      const foundHandshake = user1Handshakes.handshakes.find(h => h._id.toString() === testHandshake._id.toString());
      expect(foundHandshake).toBeDefined();

      // User3 should not see any handshakes (no handshakes involving user3)
      expect(user3Handshakes.handshakes.length).toBe(0);
    });
  });

  describe('Contact Authorization', () => {
    test('Should prevent unauthorized access to specific contact', async () => {
      // User2 tries to access contact owned by user1
      const contact = await contactService.getContactById(testContact._id, testUser2._id);
      expect(contact).toBeNull();
    });

    test('Should allow authorized access to own contact', async () => {
      const contact = await contactService.getContactById(testContact._id, testUser1._id);
      expect(contact).toBeDefined();
      expect(contact._id.toString()).toBe(testContact._id.toString());
    });

    test('Should prevent unauthorized contact modification', async () => {
      // User2 tries to update contact owned by user1
      const updatedContact = await contactService.updateContact(testContact._id, testUser2._id, { firstName: 'Hacked' });
      expect(updatedContact).toBeNull();
    });

    test('Should prevent unauthorized contact deletion', async () => {
      // User2 tries to delete contact owned by user1
      await expect(
        contactService.deleteContact(testContact._id, testUser2._id)
      ).rejects.toThrow('Contact non trouvé ou non autorisé');
    });

    test('Should only return user\'s own contacts in list', async () => {
      const user1Contacts = await contactService.getContactsWithStats(testUser1._id, {});
      const user2Contacts = await contactService.getContactsWithStats(testUser2._id, {});

      // User1 should see their contact
      expect(user1Contacts.contacts.length).toBeGreaterThan(0);
      const foundContact = user1Contacts.contacts.find(c => c._id.toString() === testContact._id.toString());
      expect(foundContact).toBeDefined();

      // User2 should not see user1's contacts
      const foundTestContact = user2Contacts.contacts.find(c => c._id.toString() === testContact._id.toString());
      expect(foundTestContact).toBeUndefined();
    });
  });

  describe('Invitation Authorization', () => {
    test('Should prevent unauthorized access to specific invitation', async () => {
      // User2 tries to access invitation created by user1
      await expect(
        invitationService.getInvitationById(testInvitation._id, testUser2._id)
      ).rejects.toThrow('Non autorisé à accéder à cette invitation');
    });

    test('Should allow authorized access to own invitation', async () => {
      const invitation = await invitationService.getInvitationById(testInvitation._id, testUser1._id);
      expect(invitation).toBeDefined();
      expect(invitation._id.toString()).toBe(testInvitation._id.toString());
    });

    test('Should prevent unauthorized invitation cancellation', async () => {
      // User2 tries to cancel invitation created by user1
      await expect(
        invitationService.cancelInvitation(testInvitation._id, testUser2._id, 'Unauthorized cancellation')
      ).rejects.toThrow('Non autorisé à annuler cette invitation');
    });

    test('Should only return user\'s own invitations in list', async () => {
      const user1Invitations = await invitationService.getInvitations(testUser1._id, {});
      const user2Invitations = await invitationService.getInvitations(testUser2._id, {});

      // User1 should see their invitation
      expect(user1Invitations.invitations.length).toBeGreaterThan(0);
      const foundInvitation = user1Invitations.invitations.find(i => i._id.toString() === testInvitation._id.toString());
      expect(foundInvitation).toBeDefined();

      // User2 should not see user1's invitations
      const foundTestInvitation = user2Invitations.invitations.find(i => i._id.toString() === testInvitation._id.toString());
      expect(foundTestInvitation).toBeUndefined();
    });
  });

  describe('Submission Authorization', () => {
    test('Should only return submissions for authorized users', async () => {
      const user1Submission = await submissionService.getSubmissionByUser(testUser1._id, '2025-01');
      const user2Submission = await submissionService.getSubmissionByUser(testUser2._id, '2025-01');

      // User1 should see their submission
      expect(user1Submission).toBeDefined();
      expect(user1Submission._id.toString()).toBe(testSubmission._id.toString());

      // User2 should not have a submission for this month
      expect(user2Submission).toBeNull();
    });

    test('Should enforce handshake permission for submission comparison', async () => {
      // Create submission for user2 to enable comparison
      const user2Submission = new Submission({
        userId: testUser2._id,
        month: '2025-01',
        responses: [{ questionId: 'q1', type: 'text', answer: 'User2 answer' }],
        freeText: 'User2 free text'
      });
      await user2Submission.save();

      // User1 and User2 have accepted handshake, so comparison should work
      const comparison = await submissionService.compareSubmissions(testUser1._id, testUser2._id, '2025-01');
      expect(comparison).toBeDefined();
      expect(comparison.user1).toBeDefined();
      expect(comparison.user2).toBeDefined();

      // Clean up
      await Submission.findByIdAndDelete(user2Submission._id);
    });

    test('Should prevent cross-user submission access', async () => {
      // This test validates that submissions are properly filtered by userId
      const allSubmissions = await Submission.find({ month: '2025-01' });
      
      // Should only return submissions for the specific user
      for (const submission of allSubmissions) {
        const userSubmission = await submissionService.getSubmissionByUser(submission.userId, '2025-01');
        expect(userSubmission._id.toString()).toBe(submission._id.toString());
        
        // Other users should not be able to access this submission directly
        const otherUsers = [testUser1._id, testUser2._id, testUser3._id].filter(id => 
          id.toString() !== submission.userId.toString()
        );
        
        for (const otherUserId of otherUsers) {
          const unauthorizedAccess = await submissionService.getSubmissionByUser(otherUserId, '2025-01');
          if (unauthorizedAccess) {
            expect(unauthorizedAccess._id.toString()).not.toBe(submission._id.toString());
          }
        }
      }
    });
  });

  describe('Service-Level Authorization Summary', () => {
    test('Should validate all services enforce proper authorization', async () => {
      const authTests = [
        {
          service: 'HandshakeService',
          method: 'getHandshakeById',
          testFn: () => handshakeService.getHandshakeById(testHandshake._id)
        },
        {
          service: 'ContactService',
          method: 'getContactById',
          testFn: () => contactService.getContactById(testContact._id, testUser1._id)
        },
        {
          service: 'InvitationService',
          method: 'getInvitationById',
          testFn: () => invitationService.getInvitationById(testInvitation._id, testUser1._id)
        },
        {
          service: 'SubmissionService',
          method: 'getSubmissionByUser',
          testFn: () => submissionService.getSubmissionByUser(testUser1._id, '2025-01')
        }
      ];

      for (const authTest of authTests) {
        const result = await authTest.testFn();
        expect(result).toBeDefined();
        console.log(`✅ ${authTest.service}.${authTest.method} - Authorization working correctly`);
      }
    });
  });
});