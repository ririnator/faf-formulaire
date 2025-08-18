// tests/api.end-to-end.integration.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./integration/setup-integration');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Handshake = require('../models/Handshake');
const Invitation = require('../models/Invitation');
const Submission = require('../models/Submission');
const { HTTP_STATUS } = require('../constants');

describe('API End-to-End Integration Tests - Complete User Workflows', () => {
  let testUsers = {};
  let authCookies = {};
  let csrfTokens = {};

  beforeAll(async () => {
    // Setup test database
    await setupTestDatabase();
    
    // Set environment to test
    process.env.NODE_ENV = 'test';
    process.env.DISABLE_RATE_LIMITING = 'true';
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  beforeEach(async () => {
    // Clean database
    await cleanupDatabase();

    // Create test users for complete workflows
    const userConfigs = [
      { key: 'alice', username: 'alice', email: 'alice@test.com' },
      { key: 'bob', username: 'bob', email: 'bob@test.com' },
      { key: 'charlie', username: 'charlie', email: 'charlie@test.com' },
      { key: 'diana', username: 'diana', email: 'diana@test.com' },
      { key: 'admin', username: 'admin', email: 'admin@test.com', role: 'admin' }
    ];

    testUsers = {};
    authCookies = {};
    csrfTokens = {};

    for (const config of userConfigs) {
      // Create user
      testUsers[config.key] = await User.create({
        username: config.username,
        login: config.email,
        password: 'password123',
        role: config.role || 'user'
      });

      // Setup authentication
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          login: config.email,
          password: 'password123'
        })
        .expect(HTTP_STATUS.OK);

      authCookies[config.key] = loginResponse.headers['set-cookie'];
      
      const csrfResponse = await request(app)
        .get('/api/csrf-token')
        .set('Cookie', authCookies[config.key])
        .expect(HTTP_STATUS.OK);
      
      csrfTokens[config.key] = csrfResponse.body.csrfToken;
    }
  });

  describe('Complete User Onboarding and Social Connection Workflow', () => {
    it('should handle complete user journey from invitation to active participation', async () => {
      // Step 1: Admin creates invitation for new user
      const invitationResponse = await request(app)
        .post('/api/invitations')
        .set('Cookie', authCookies.admin)
        .set('X-CSRF-Token', csrfTokens.admin)
        .send({
          email: 'newuser@test.com',
          name: 'New User',
          message: 'Welcome to our Form-a-Friend community!'
        })
        .expect(HTTP_STATUS.CREATED);

      const invitation = invitationResponse.body.data.invitation;
      expect(invitation.token).toBeDefined();
      expect(invitation.email).toBe('newuser@test.com');

      // Step 2: New user validates invitation
      const validationResponse = await request(app)
        .get(`/api/invitations/validate/${invitation.token}`)
        .expect(HTTP_STATUS.OK);

      expect(validationResponse.body.success).toBe(true);
      expect(validationResponse.body.data.valid).toBe(true);

      // Step 3: New user registers through invitation
      const registrationResponse = await request(app)
        .post(`/api/invitations/public/${invitation.token}/submit`)
        .send({
          username: 'newuser',
          password: 'newuserpassword123',
          firstName: 'New',
          lastName: 'User'
        })
        .expect(HTTP_STATUS.CREATED);

      expect(registrationResponse.body.success).toBe(true);
      const newUserId = registrationResponse.body.data.user.id;

      // Step 4: New user logs in
      const newUserLogin = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'newuser@test.com',
          password: 'newuserpassword123'
        })
        .expect(HTTP_STATUS.OK);

      const newUserCookie = newUserLogin.headers['set-cookie'];
      
      const newUserCsrfResponse = await request(app)
        .get('/api/csrf-token')
        .set('Cookie', newUserCookie)
        .expect(HTTP_STATUS.OK);
      
      const newUserCsrfToken = newUserCsrfResponse.body.csrfToken;

      // Step 5: New user creates their first submission
      const submissionResponse = await request(app)
        .post('/api/submissions')
        .set('Cookie', newUserCookie)
        .set('X-CSRF-Token', newUserCsrfToken)
        .send({
          responses: [
            { question: 'What\'s your favorite hobby?', answer: 'Photography and hiking' },
            { question: 'Describe your ideal weekend', answer: 'Exploring nature trails with my camera' },
            { question: 'What motivates you?', answer: 'Creating beautiful memories and connecting with others' }
          ]
        })
        .expect(HTTP_STATUS.CREATED);

      expect(submissionResponse.body.success).toBe(true);
      const submission = submissionResponse.body.data.submission;

      // Step 6: Alice discovers new user and sends handshake
      const handshakeResponse = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          recipientId: newUserId,
          message: 'Hi! I saw your submission about photography. I\'d love to connect!'
        })
        .expect(HTTP_STATUS.CREATED);

      expect(handshakeResponse.body.success).toBe(true);
      const handshake = handshakeResponse.body.data.handshake;

      // Step 7: New user sees and accepts handshake
      const receivedHandshakesResponse = await request(app)
        .get('/api/handshakes/received')
        .set('Cookie', newUserCookie)
        .expect(HTTP_STATUS.OK);

      expect(receivedHandshakesResponse.body.data.handshakes).toHaveLength(1);
      const receivedHandshake = receivedHandshakesResponse.body.data.handshakes[0];

      const acceptResponse = await request(app)
        .post(`/api/handshakes/${receivedHandshake._id}/accept`)
        .set('Cookie', newUserCookie)
        .set('X-CSRF-Token', newUserCsrfToken)
        .send({
          message: 'Thanks for reaching out! I\'d love to share photography tips!'
        })
        .expect(HTTP_STATUS.OK);

      expect(acceptResponse.body.success).toBe(true);
      expect(acceptResponse.body.data.handshake.status).toBe('accepted');

      // Step 8: Verify mutual contacts were created
      const aliceContactsResponse = await request(app)
        .get('/api/contacts')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      const newUserContactsResponse = await request(app)
        .get('/api/contacts')
        .set('Cookie', newUserCookie)
        .expect(HTTP_STATUS.OK);

      // Both users should now have each other as contacts
      const aliceContacts = aliceContactsResponse.body.data.contacts;
      const newUserContacts = newUserContactsResponse.body.data.contacts;

      expect(aliceContacts.some(c => c.linkedUserId === newUserId)).toBe(true);
      expect(newUserContacts.some(c => c.linkedUserId === testUsers.alice._id.toString())).toBe(true);

      // Step 9: Verify new user appears in Alice's submission timeline
      const timelineResponse = await request(app)
        .get('/api/submissions')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(timelineResponse.body.success).toBe(true);
      const timeline = timelineResponse.body.data.timeline;
      expect(timeline.some(s => s.userId === newUserId)).toBe(true);

      // Step 10: Verify invitation was marked as accepted
      const updatedInvitation = await Invitation.findById(invitation._id);
      expect(updatedInvitation.status).toBe('accepted');
      expect(updatedInvitation.acceptedAt).toBeDefined();
    });
  });

  describe('Social Network Formation and Content Sharing Workflow', () => {
    it('should handle complex social network formation with multiple connections and submissions', async () => {
      // Step 1: Create initial submissions for all users
      const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
      
      const submissionPromises = Object.keys(testUsers).filter(key => key !== 'admin').map(async (userKey, index) => {
        const questions = [
          ['What\'s your favorite color?', 'Favorite hobby?', 'Dream destination?'],
          ['Best childhood memory?', 'Favorite book?', 'Ideal superpower?'],
          ['Favorite season?', 'Dream job?', 'Best advice received?'],
          ['Favorite food?', 'Hidden talent?', 'Bucket list item?']
        ];

        return request(app)
          .post('/api/submissions')
          .set('Cookie', authCookies[userKey])
          .set('X-CSRF-Token', csrfTokens[userKey])
          .send({
            responses: questions[index].map((q, i) => ({
              question: q,
              answer: `${userKey}'s answer to ${q.replace('?', '')}`
            }))
          })
          .expect(HTTP_STATUS.CREATED);
      });

      const submissions = await Promise.all(submissionPromises);
      expect(submissions.every(s => s.body.success)).toBe(true);

      // Step 2: Create a network of handshake connections
      // Alice connects to Bob and Charlie
      const aliceToBob = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          recipientId: testUsers.bob._id.toString(),
          message: 'Hi Bob! Let\'s connect!'
        })
        .expect(HTTP_STATUS.CREATED);

      const aliceToCharlie = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          recipientId: testUsers.charlie._id.toString(),
          message: 'Hi Charlie! Your submission was interesting!'
        })
        .expect(HTTP_STATUS.CREATED);

      // Bob connects to Diana
      const bobToDiana = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.bob)
        .set('X-CSRF-Token', csrfTokens.bob)
        .send({
          recipientId: testUsers.diana._id.toString(),
          message: 'Hi Diana! Would love to get to know you better!'
        })
        .expect(HTTP_STATUS.CREATED);

      // Step 3: Accept handshakes to form connections
      await request(app)
        .post(`/api/handshakes/${aliceToBob.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.bob)
        .set('X-CSRF-Token', csrfTokens.bob)
        .send({ message: 'Great to connect, Alice!' })
        .expect(HTTP_STATUS.OK);

      await request(app)
        .post(`/api/handshakes/${aliceToCharlie.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.charlie)
        .set('X-CSRF-Token', csrfTokens.charlie)
        .send({ message: 'Thanks for reaching out!' })
        .expect(HTTP_STATUS.OK);

      await request(app)
        .post(`/api/handshakes/${bobToDiana.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.diana)
        .set('X-CSRF-Token', csrfTokens.diana)
        .send({ message: 'Looking forward to our friendship!' })
        .expect(HTTP_STATUS.OK);

      // Step 4: Verify network connectivity through timeline views
      const aliceTimeline = await request(app)
        .get('/api/submissions')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      const bobTimeline = await request(app)
        .get('/api/submissions')
        .set('Cookie', authCookies.bob)
        .expect(HTTP_STATUS.OK);

      // Alice should see her own submission plus connected users
      expect(aliceTimeline.body.data.timeline.length).toBeGreaterThan(0);
      const aliceVisibleUsers = new Set(aliceTimeline.body.data.timeline.map(s => s.userId));
      expect(aliceVisibleUsers.has(testUsers.alice._id.toString())).toBe(true);
      expect(aliceVisibleUsers.has(testUsers.bob._id.toString())).toBe(true);
      expect(aliceVisibleUsers.has(testUsers.charlie._id.toString())).toBe(true);

      // Step 5: Test comparison functionality across the network
      const comparisonResponse = await request(app)
        .get(`/api/submissions/compare/${currentMonth}`)
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      const comparison = comparisonResponse.body.data.comparison;
      expect(comparison.submissions.length).toBeGreaterThan(1);
      expect(comparison.statistics.totalSubmissions).toBeGreaterThan(0);

      // Step 6: Verify handshake statistics reflect network growth
      const aliceHandshakeStats = await request(app)
        .get('/api/handshakes/stats')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(aliceHandshakeStats.body.data.stats.sent.accepted).toBe(2);

      const bobHandshakeStats = await request(app)
        .get('/api/handshakes/stats')
        .set('Cookie', authCookies.bob)
        .expect(HTTP_STATUS.OK);

      expect(bobHandshakeStats.body.data.stats.sent.accepted).toBe(1);
      expect(bobHandshakeStats.body.data.stats.received.accepted).toBe(1);

      // Step 7: Test contact management across the network
      const aliceContacts = await request(app)
        .get('/api/contacts')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(aliceContacts.body.data.contacts).toHaveLength(2); // Bob and Charlie
      
      // Alice adds notes to her contacts
      const bobContact = aliceContacts.body.data.contacts.find(
        c => c.linkedUserId === testUsers.bob._id.toString()
      );

      await request(app)
        .put(`/api/contacts/${bobContact._id}`)
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          notes: 'Great photographer, loves hiking. Connected through handshake.',
          tags: ['friend', 'photography', 'hiking']
        })
        .expect(HTTP_STATUS.OK);

      // Step 8: Verify global statistics reflect network activity
      const globalStats = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(globalStats.body.data.stats.totalSubmissions).toBe(4);
      expect(globalStats.body.data.stats.totalUsers).toBe(4);
    });
  });

  describe('Content Discovery and Interaction Workflow', () => {
    it('should handle content discovery, interaction, and community building', async () => {
      // Step 1: Multiple users create rich submissions
      const userSubmissions = {
        alice: {
          responses: [
            { question: 'What\'s your biggest passion?', answer: 'Environmental conservation and sustainable living' },
            { question: 'Describe your ideal project', answer: 'Creating a community garden with renewable energy systems' },
            { question: 'What skill do you want to learn?', answer: 'Permaculture design and solar panel installation' }
          ]
        },
        bob: {
          responses: [
            { question: 'What\'s your biggest passion?', answer: 'Digital photography and nature documentation' },
            { question: 'Describe your ideal project', answer: 'A photo series documenting climate change effects on local ecosystems' },
            { question: 'What skill do you want to learn?', answer: 'Drone photography and video editing' }
          ]
        },
        charlie: {
          responses: [
            { question: 'What\'s your biggest passion?', answer: 'Community organizing and social justice' },
            { question: 'Describe your ideal project', answer: 'Building affordable housing with sustainable materials' },
            { question: 'What skill do you want to learn?', answer: 'Green building techniques and community fundraising' }
          ]
        }
      };

      // Create submissions
      const submissionResults = {};
      for (const [userKey, submissionData] of Object.entries(userSubmissions)) {
        const response = await request(app)
          .post('/api/submissions')
          .set('Cookie', authCookies[userKey])
          .set('X-CSRF-Token', csrfTokens[userKey])
          .send(submissionData)
          .expect(HTTP_STATUS.CREATED);

        submissionResults[userKey] = response.body.data.submission;
      }

      // Step 2: Users discover each other through common interests
      // Alice reviews timeline and identifies potential connections
      const timelineResponse = await request(app)
        .get('/api/submissions')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(timelineResponse.body.data.timeline.length).toBeGreaterThan(0);

      // Step 3: Alice reaches out to users with similar interests
      const aliceToBobHandshake = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          recipientId: testUsers.bob._id.toString(),
          message: 'Hi Bob! I loved your submission about nature documentation. I\'m working on environmental projects and think your photography skills could help with awareness campaigns!'
        })
        .expect(HTTP_STATUS.CREATED);

      const aliceToCharlieHandshake = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          recipientId: testUsers.charlie._id.toString(),
          message: 'Hi Charlie! Your community organizing experience could be invaluable for my sustainable community garden project. Would you be interested in collaborating?'
        })
        .expect(HTTP_STATUS.CREATED);

      // Step 4: Recipients respond positively and accept
      await request(app)
        .post(`/api/handshakes/${aliceToBobHandshake.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.bob)
        .set('X-CSRF-Token', csrfTokens.bob)
        .send({
          message: 'Absolutely! I\'d love to document your environmental projects. This sounds like a perfect collaboration opportunity!'
        })
        .expect(HTTP_STATUS.OK);

      await request(app)
        .post(`/api/handshakes/${aliceToCharlieHandshake.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.charlie)
        .set('X-CSRF-Token', csrfTokens.charlie)
        .send({
          message: 'This sounds amazing! Community gardens are so important for sustainable neighborhoods. Let\'s definitely work together!'
        })
        .expect(HTTP_STATUS.OK);

      // Step 5: Bob and Charlie discover each other through Alice's network
      const bobToCharlieHandshake = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.bob)
        .set('X-CSRF-Token', csrfTokens.bob)
        .send({
          recipientId: testUsers.charlie._id.toString(),
          message: 'Hi Charlie! Alice mentioned we\'re both interested in community projects. I\'d love to photograph your housing initiatives for documentation and promotion!'
        })
        .expect(HTTP_STATUS.CREATED);

      await request(app)
        .post(`/api/handshakes/${bobToCharlieHandshake.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.charlie)
        .set('X-CSRF-Token', csrfTokens.charlie)
        .send({
          message: 'Perfect! Visual documentation is exactly what our housing projects need. This will be a great partnership!'
        })
        .expect(HTTP_STATUS.OK);

      // Step 6: Network effects - Users can now see expanded timeline
      const expandedTimeline = await request(app)
        .get('/api/submissions')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(expandedTimeline.body.data.timeline.length).toBeGreaterThan(1);

      // Step 7: Users manage their growing contact network
      const aliceContactsResponse = await request(app)
        .get('/api/contacts')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(aliceContactsResponse.body.data.contacts).toHaveLength(2);

      // Alice organizes contacts with tags and notes
      const bobContact = aliceContactsResponse.body.data.contacts.find(
        c => c.linkedUserId === testUsers.bob._id.toString()
      );

      await request(app)
        .put(`/api/contacts/${bobContact._id}`)
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          tags: ['collaborator', 'photographer', 'environmentalist'],
          notes: 'Skilled nature photographer. Collaborating on environmental awareness campaigns. Interested in documenting community garden project.'
        })
        .expect(HTTP_STATUS.OK);

      // Step 8: Verify community statistics show healthy network growth
      const finalStats = await request(app)
        .get('/api/handshakes/stats')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(finalStats.body.data.stats.sent.accepted).toBe(2);

      const networkStats = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(networkStats.body.data.stats.totalUsers).toBe(3);
    });
  });

  describe('Admin Management and Oversight Workflow', () => {
    it('should handle admin oversight of community growth and invitation management', async () => {
      // Step 1: Admin monitors community stats
      const initialStats = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(initialStats.body.success).toBe(true);

      // Step 2: Admin creates strategic invitations for community growth
      const strategicInvitations = [
        {
          email: 'expert1@example.com',
          name: 'Dr. Sarah Thompson',
          message: 'Your expertise in sustainable agriculture would be valuable to our growing community of environmentally conscious individuals.'
        },
        {
          email: 'expert2@example.com',
          name: 'Mike Rodriguez',
          message: 'We\'d love to have your urban planning expertise in our community focused on sustainable living and community building.'
        },
        {
          email: 'connector@example.com',
          name: 'Lisa Chen',
          message: 'Your experience in community organizing would help strengthen connections within our growing network.'
        }
      ];

      const invitationPromises = strategicInvitations.map(invitationData =>
        request(app)
          .post('/api/invitations')
          .set('Cookie', authCookies.admin)
          .set('X-CSRF-Token', csrfTokens.admin)
          .send(invitationData)
          .expect(HTTP_STATUS.CREATED)
      );

      const invitationResponses = await Promise.all(invitationPromises);
      const invitationTokens = invitationResponses.map(r => r.body.data.invitation.token);

      // Step 3: Admin monitors invitation status
      const adminInvitations = await request(app)
        .get('/api/invitations')
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(adminInvitations.body.data.invitations).toHaveLength(3);
      expect(adminInvitations.body.data.invitations.every(inv => inv.status === 'pending')).toBe(true);

      // Step 4: Simulate expert accepting invitation and registering
      const expertRegistration = await request(app)
        .post(`/api/invitations/public/${invitationTokens[0]}/submit`)
        .send({
          username: 'sarahthompson',
          password: 'expertpassword123',
          firstName: 'Sarah',
          lastName: 'Thompson'
        })
        .expect(HTTP_STATUS.CREATED);

      expect(expertRegistration.body.success).toBe(true);
      const expertUserId = expertRegistration.body.data.user.id;

      // Step 5: Expert logs in and creates submission
      const expertLogin = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'expert1@example.com',
          password: 'expertpassword123'
        })
        .expect(HTTP_STATUS.OK);

      const expertCookie = expertLogin.headers['set-cookie'];
      
      const expertCsrfResponse = await request(app)
        .get('/api/csrf-token')
        .set('Cookie', expertCookie)
        .expect(HTTP_STATUS.OK);
      
      const expertCsrfToken = expertCsrfResponse.body.csrfToken;

      const expertSubmission = await request(app)
        .post('/api/submissions')
        .set('Cookie', expertCookie)
        .set('X-CSRF-Token', expertCsrfToken)
        .send({
          responses: [
            { 
              question: 'What\'s your area of expertise?', 
              answer: 'I specialize in regenerative agriculture, soil health, and sustainable farming practices with 15 years of research experience.' 
            },
            { 
              question: 'How can you help the community?', 
              answer: 'I can provide guidance on establishing community gardens, composting systems, and sustainable food production methods.' 
            },
            { 
              question: 'What do you hope to learn from others?', 
              answer: 'I\'m interested in learning about community organizing strategies and how to scale sustainable practices to urban environments.' 
            }
          ]
        })
        .expect(HTTP_STATUS.CREATED);

      expect(expertSubmission.body.success).toBe(true);

      // Step 6: Existing community members discover and connect with expert
      const aliceConnectsToExpert = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          recipientId: expertUserId,
          message: 'Dr. Thompson! Your expertise in regenerative agriculture is exactly what our community garden project needs. Would you be willing to provide guidance?'
        })
        .expect(HTTP_STATUS.CREATED);

      // Expert accepts and responds
      await request(app)
        .post(`/api/handshakes/${aliceConnectsToExpert.body.data.handshake._id}/accept`)
        .set('Cookie', expertCookie)
        .set('X-CSRF-Token', expertCsrfToken)
        .send({
          message: 'I\'d be delighted to help! Community gardens are one of my favorite applications of sustainable agriculture. Let\'s schedule some time to discuss your project in detail.'
        })
        .expect(HTTP_STATUS.OK);

      // Step 7: Admin monitors community growth metrics
      const updatedStats = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(updatedStats.body.data.stats.totalUsers).toBeGreaterThan(initialStats.body.data.stats.totalUsers);

      const invitationStats = await request(app)
        .get('/api/invitations/stats')
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(invitationStats.body.data.stats.accepted).toBe(1);
      expect(invitationStats.body.data.stats.pending).toBe(2);

      // Step 8: Admin extends expiry of pending invitations
      const pendingInvitations = adminInvitations.body.data.invitations.filter(inv => inv.status === 'pending');
      
      await request(app)
        .post(`/api/invitations/${pendingInvitations[1]._id}/extend`)
        .set('Cookie', authCookies.admin)
        .set('X-CSRF-Token', csrfTokens.admin)
        .send({ days: 14 })
        .expect(HTTP_STATUS.OK);

      // Step 9: Admin views comprehensive community timeline
      const adminTimeline = await request(app)
        .get('/api/submissions')
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(adminTimeline.body.data.timeline.length).toBeGreaterThan(0);

      // Step 10: Admin analyzes current month's activity for insights
      const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
      
      const monthlyComparison = await request(app)
        .get(`/api/submissions/compare/${currentMonth}`)
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(monthlyComparison.body.data.comparison.statistics.totalSubmissions).toBeGreaterThan(0);
      expect(monthlyComparison.body.data.comparison.statistics.participationRate).toBeGreaterThan(0);
    });
  });

  describe('Error Recovery and Edge Case Workflows', () => {
    it('should handle complex error scenarios and recovery workflows', async () => {
      // Step 1: User attempts to connect with non-existent user (should fail gracefully)
      const nonExistentId = new mongoose.Types.ObjectId();
      
      const failedHandshake = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          recipientId: nonExistentId.toString(),
          message: 'This should fail'
        })
        .expect(HTTP_STATUS.NOT_FOUND);

      expect(failedHandshake.body.success).toBe(false);

      // Step 2: User tries to submit duplicate submission in same month
      const initialSubmission = await request(app)
        .post('/api/submissions')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          responses: [
            { question: 'Test question', answer: 'Test answer' }
          ]
        })
        .expect(HTTP_STATUS.CREATED);

      const duplicateSubmission = await request(app)
        .post('/api/submissions')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          responses: [
            { question: 'Another question', answer: 'Another answer' }
          ]
        })
        .expect(HTTP_STATUS.CONFLICT);

      expect(duplicateSubmission.body.success).toBe(false);

      // Step 3: User attempts to accept handshake not meant for them
      const bobToDianaHandshake = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.bob)
        .set('X-CSRF-Token', csrfTokens.bob)
        .send({
          recipientId: testUsers.diana._id.toString(),
          message: 'Hi Diana!'
        })
        .expect(HTTP_STATUS.CREATED);

      // Alice tries to accept handshake meant for Diana
      const unauthorizedAccept = await request(app)
        .post(`/api/handshakes/${bobToDianaHandshake.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .expect(HTTP_STATUS.FORBIDDEN);

      expect(unauthorizedAccept.body.success).toBe(false);

      // Step 4: Proper user accepts the handshake
      const properAccept = await request(app)
        .post(`/api/handshakes/${bobToDianaHandshake.body.data.handshake._id}/accept`)
        .set('Cookie', authCookies.diana)
        .set('X-CSRF-Token', csrfTokens.diana)
        .send({ message: 'Hi Bob! Nice to meet you!' })
        .expect(HTTP_STATUS.OK);

      expect(properAccept.body.success).toBe(true);

      // Step 5: User tries to access expired invitation
      const expiredInvitation = await Invitation.create({
        email: 'expired@example.com',
        inviterName: 'Test Inviter',
        inviterId: testUsers.admin._id,
        token: 'expired-token-123',
        status: 'pending',
        expiresAt: new Date(Date.now() - 1000) // Already expired
      });

      const expiredAccess = await request(app)
        .get(`/api/invitations/public/${expiredInvitation.token}`)
        .expect(HTTP_STATUS.BAD_REQUEST);

      expect(expiredAccess.body.success).toBe(false);
      expect(expiredAccess.body.error).toContain('expired');

      // Step 6: User attempts malicious input - should be sanitized
      const maliciousSubmission = await request(app)
        .post('/api/submissions')
        .set('Cookie', authCookies.bob)
        .set('X-CSRF-Token', csrfTokens.bob)
        .send({
          responses: [
            { 
              question: 'Safe question', 
              answer: '<script>alert("This should be sanitized")</script>' 
            }
          ]
        })
        .expect(HTTP_STATUS.CREATED);

      expect(maliciousSubmission.body.success).toBe(true);
      expect(maliciousSubmission.body.data.submission.responses[0].answer).not.toContain('<script');

      // Step 7: User cancels their own handshake request
      const cancelableHandshake = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookies.charlie)
        .set('X-CSRF-Token', csrfTokens.charlie)
        .send({
          recipientId: testUsers.diana._id.toString(),
          message: 'Changed my mind about this'
        })
        .expect(HTTP_STATUS.CREATED);

      const cancelResponse = await request(app)
        .post(`/api/handshakes/${cancelableHandshake.body.data.handshake._id}/cancel`)
        .set('Cookie', authCookies.charlie)
        .set('X-CSRF-Token', csrfTokens.charlie)
        .expect(HTTP_STATUS.OK);

      expect(cancelResponse.body.success).toBe(true);
      expect(cancelResponse.body.data.handshake.status).toBe('cancelled');

      // Step 8: Verify system integrity after all edge cases
      const finalSystemCheck = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(finalSystemCheck.body.success).toBe(true);
      expect(finalSystemCheck.body.data.stats.totalSubmissions).toBeGreaterThan(0);

      // Verify handshake stats are accurate
      const handshakeSystemCheck = await request(app)
        .get('/api/handshakes/stats')
        .set('Cookie', authCookies.bob)
        .expect(HTTP_STATUS.OK);

      expect(handshakeSystemCheck.body.success).toBe(true);
      
      // Bob should have 1 sent accepted and 0 cancelled (since he didn't cancel any)
      expect(handshakeSystemCheck.body.data.stats.sent.accepted).toBe(1);
    });
  });

  describe('Performance Under Load Workflows', () => {
    it('should maintain performance and consistency under concurrent load', async () => {
      // Step 1: Concurrent submission creation by multiple users
      const concurrentSubmissions = Object.keys(testUsers).filter(key => key !== 'admin').map(userKey => 
        request(app)
          .post('/api/submissions')
          .set('Cookie', authCookies[userKey])
          .set('X-CSRF-Token', csrfTokens[userKey])
          .send({
            responses: [
              { question: `${userKey}'s concurrent question 1`, answer: `${userKey}'s concurrent answer 1` },
              { question: `${userKey}'s concurrent question 2`, answer: `${userKey}'s concurrent answer 2` }
            ]
          })
      );

      const submissionResults = await Promise.all(concurrentSubmissions);
      expect(submissionResults.every(r => r.status === HTTP_STATUS.CREATED)).toBe(true);

      // Step 2: Concurrent handshake requests
      const concurrentHandshakes = [
        request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send({
            recipientId: testUsers.bob._id.toString(),
            message: 'Concurrent handshake from Alice to Bob'
          }),
        request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send({
            recipientId: testUsers.charlie._id.toString(),
            message: 'Concurrent handshake from Alice to Charlie'
          }),
        request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookies.bob)
          .set('X-CSRF-Token', csrfTokens.bob)
          .send({
            recipientId: testUsers.diana._id.toString(),
            message: 'Concurrent handshake from Bob to Diana'
          })
      ];

      const handshakeResults = await Promise.all(concurrentHandshakes);
      expect(handshakeResults.every(r => r.status === HTTP_STATUS.CREATED)).toBe(true);

      // Step 3: Concurrent timeline requests
      const concurrentTimelineRequests = Object.keys(authCookies).map(userKey =>
        request(app)
          .get('/api/submissions')
          .set('Cookie', authCookies[userKey])
      );

      const timelineResults = await Promise.all(concurrentTimelineRequests);
      expect(timelineResults.every(r => r.status === HTTP_STATUS.OK)).toBe(true);

      // Step 4: Concurrent statistics requests
      const concurrentStatsRequests = [
        request(app).get('/api/submissions/stats').set('Cookie', authCookies.admin),
        request(app).get('/api/handshakes/stats').set('Cookie', authCookies.alice),
        request(app).get('/api/invitations/stats').set('Cookie', authCookies.admin),
        request(app).get('/api/contacts/stats/global').set('Cookie', authCookies.bob)
      ];

      const statsResults = await Promise.all(concurrentStatsRequests);
      expect(statsResults.every(r => r.status === HTTP_STATUS.OK)).toBe(true);

      // Step 5: Verify data consistency after concurrent operations
      const finalVerification = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies.admin)
        .expect(HTTP_STATUS.OK);

      expect(finalVerification.body.data.stats.totalSubmissions).toBe(4); // One per non-admin user
      expect(finalVerification.body.data.stats.totalUsers).toBe(4);

      // Verify handshake consistency
      const handshakeVerification = await request(app)
        .get('/api/handshakes/stats')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(handshakeVerification.body.data.stats.sent.pending).toBe(2); // Alice sent 2 pending handshakes
    });
  });
});