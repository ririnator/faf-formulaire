// tests/api.invitations.integration.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./integration/setup-integration');
const User = require('../models/User');
const Invitation = require('../models/Invitation');
const Contact = require('../models/Contact');
const { HTTP_STATUS } = require('../constants');

describe('API Integration Tests - /api/invitations', () => {
  let testUser1, testUser2, testUser3, adminUser;
  let authCookie1, authCookie2, adminCookie;
  let csrfToken1, csrfToken2, adminCsrfToken;

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

    // Create test users
    testUser1 = await User.create({
      username: 'user1',
      email: 'user1@test.com',
      password: 'password123',
      role: 'user'
    });

    testUser2 = await User.create({
      username: 'user2',
      email: 'user2@test.com',
      password: 'password123',
      role: 'user'
    });

    testUser3 = await User.create({
      username: 'user3',
      email: 'user3@test.com',
      password: 'password123',
      role: 'user'
    });

    adminUser = await User.create({
      username: 'admin',
      email: 'admin@test.com',
      password: 'password123',
      role: 'admin'
    });

    // Setup authentication for user1
    const loginResponse1 = await request(app)
      .post('/api/auth/login')
      .send({
        login: testUser1.email,
        password: 'password123'
      })
      .expect(HTTP_STATUS.OK);

    authCookie1 = loginResponse1.headers['set-cookie'];
    
    const csrfResponse1 = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', authCookie1)
      .expect(HTTP_STATUS.OK);
    
    csrfToken1 = csrfResponse1.body.csrfToken;

    // Setup authentication for user2
    const loginResponse2 = await request(app)
      .post('/api/auth/login')
      .send({
        login: testUser2.email,
        password: 'password123'
      })
      .expect(HTTP_STATUS.OK);

    authCookie2 = loginResponse2.headers['set-cookie'];
    
    const csrfResponse2 = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', authCookie2)
      .expect(HTTP_STATUS.OK);
    
    csrfToken2 = csrfResponse2.body.csrfToken;

    // Setup authentication for admin
    const adminResponse = await request(app)
      .post('/api/auth/login')
      .send({
        email: adminUser.email,
        password: 'password123'
      })
      .expect(HTTP_STATUS.OK);

    adminCookie = adminResponse.headers['set-cookie'];
    
    const adminCsrfResponse = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', adminCookie)
      .expect(HTTP_STATUS.OK);
    
    adminCsrfToken = adminCsrfResponse.body.csrfToken;
  });

  describe('Nominal Cases - Happy Path', () => {
    describe('POST /api/invitations', () => {
      it('should create a new invitation successfully', async () => {
        const invitationData = {
          email: 'newuser@example.com',
          name: 'New User',
          message: 'Join our platform!',
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        };

        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(invitationData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation).toMatchObject({
          email: invitationData.email,
          inviterName: invitationData.name,
          message: invitationData.message,
          inviterId: testUser1._id.toString(),
          status: 'pending'
        });
        expect(response.body.data.invitation).toHaveProperty('token');
        expect(response.body.data.invitation).toHaveProperty('_id');
        expect(response.body.data.invitation).toHaveProperty('createdAt');
      });

      it('should create invitation with minimal required fields', async () => {
        const invitationData = {
          email: 'minimal@example.com'
        };

        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(invitationData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation.email).toBe(invitationData.email);
        expect(response.body.data.invitation.inviterId).toBe(testUser1._id.toString());
        expect(response.body.data.invitation.status).toBe('pending');
        expect(response.body.data.invitation.token).toBeDefined();
      });

      it('should handle French characters in invitation message', async () => {
        const invitationData = {
          email: 'français@example.com',
          name: 'François Müller',
          message: 'Salut! Je t\'invite à rejoindre notre plateforme. Ça va être génial!'
        };

        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(invitationData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation.email).toBe(invitationData.email);
        expect(response.body.data.invitation.inviterName).toBe(invitationData.name);
        expect(response.body.data.invitation.message).toBe(invitationData.message);
      });
    });

    describe('GET /api/invitations', () => {
      beforeEach(async () => {
        // Create test invitations
        await Invitation.create([
          {
            email: 'invite1@example.com',
            inviterName: 'User1 Invitation',
            inviterId: testUser1._id,
            token: 'token1',
            status: 'pending'
          },
          {
            email: 'invite2@example.com',
            inviterName: 'User1 Invitation 2',
            inviterId: testUser1._id,
            token: 'token2',
            status: 'accepted'
          },
          {
            email: 'invite3@example.com',
            inviterName: 'User2 Invitation',
            inviterId: testUser2._id, // Different user - shouldn't appear
            token: 'token3',
            status: 'pending'
          }
        ]);
      });

      it('should retrieve all invitations for authenticated user', async () => {
        const response = await request(app)
          .get('/api/invitations')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitations).toHaveLength(2);
        
        // Verify user isolation
        response.body.data.invitations.forEach(invitation => {
          expect(invitation.inviterId).toBe(testUser1._id.toString());
        });
      });

      it('should support pagination', async () => {
        const response = await request(app)
          .get('/api/invitations?page=1&limit=1')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitations).toHaveLength(1);
        expect(response.body.data.pagination).toMatchObject({
          currentPage: 1,
          totalPages: 2,
          totalItems: 2,
          limit: 1
        });
      });

      it('should support filtering by status', async () => {
        const response = await request(app)
          .get('/api/invitations?status=pending')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitations).toHaveLength(1);
        expect(response.body.data.invitations[0].status).toBe('pending');
      });
    });

    describe('GET /api/invitations/validate/:token', () => {
      let testInvitation;

      beforeEach(async () => {
        testInvitation = await Invitation.create({
          email: 'validate@example.com',
          inviterName: 'Test Inviter',
          inviterId: testUser1._id,
          token: 'validation-token-123',
          status: 'pending',
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });
      });

      it('should validate valid invitation token', async () => {
        const response = await request(app)
          .get(`/api/invitations/validate/${testInvitation.token}`)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation).toMatchObject({
          email: 'validate@example.com',
          inviterName: 'Test Inviter',
          status: 'pending'
        });
        expect(response.body.data.valid).toBe(true);
      });

      it('should reject expired invitation token', async () => {
        // Update invitation to be expired
        await Invitation.findByIdAndUpdate(testInvitation._id, {
          expiresAt: new Date(Date.now() - 1000) // 1 second ago
        });

        const response = await request(app)
          .get(`/api/invitations/validate/${testInvitation.token}`)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('expired');
      });

      it('should reject already used invitation token', async () => {
        // Update invitation to be accepted
        await Invitation.findByIdAndUpdate(testInvitation._id, {
          status: 'accepted'
        });

        const response = await request(app)
          .get(`/api/invitations/validate/${testInvitation.token}`)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('already been used');
      });
    });

    describe('POST /api/invitations/:id/cancel', () => {
      let testInvitation;

      beforeEach(async () => {
        testInvitation = await Invitation.create({
          email: 'cancel@example.com',
          inviterName: 'Test Inviter',
          inviterId: testUser1._id,
          token: 'cancel-token-123',
          status: 'pending'
        });
      });

      it('should cancel invitation successfully', async () => {
        const response = await request(app)
          .post(`/api/invitations/${testInvitation._id}/cancel`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation.status).toBe('cancelled');
        expect(response.body.data.invitation).toHaveProperty('cancelledAt');

        // Verify database update
        const updatedInvitation = await Invitation.findById(testInvitation._id);
        expect(updatedInvitation.status).toBe('cancelled');
        expect(updatedInvitation.cancelledAt).toBeDefined();
      });
    });

    describe('POST /api/invitations/:id/extend', () => {
      let testInvitation;

      beforeEach(async () => {
        const originalExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day
        testInvitation = await Invitation.create({
          email: 'extend@example.com',
          inviterName: 'Test Inviter',
          inviterId: testUser1._id,
          token: 'extend-token-123',
          status: 'pending',
          expiresAt: originalExpiry
        });
      });

      it('should extend invitation expiry successfully', async () => {
        const extensionDays = 7;
        
        const response = await request(app)
          .post(`/api/invitations/${testInvitation._id}/extend`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({ days: extensionDays })
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation.status).toBe('pending');
        
        // Verify expiry was extended
        const newExpiryDate = new Date(response.body.data.invitation.expiresAt);
        const expectedMinimum = new Date(Date.now() + (extensionDays - 1) * 24 * 60 * 60 * 1000);
        expect(newExpiryDate.getTime()).toBeGreaterThan(expectedMinimum.getTime());
      });

      it('should extend invitation with default 7 days if no days specified', async () => {
        const response = await request(app)
          .post(`/api/invitations/${testInvitation._id}/extend`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({})
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        
        // Verify default 7-day extension
        const newExpiryDate = new Date(response.body.data.invitation.expiresAt);
        const expectedMinimum = new Date(Date.now() + 6 * 24 * 60 * 60 * 1000);
        expect(newExpiryDate.getTime()).toBeGreaterThan(expectedMinimum.getTime());
      });
    });

    describe('GET /api/invitations/stats', () => {
      beforeEach(async () => {
        await Invitation.create([
          { email: 'stats1@example.com', inviterId: testUser1._id, token: 'token1', status: 'pending' },
          { email: 'stats2@example.com', inviterId: testUser1._id, token: 'token2', status: 'accepted' },
          { email: 'stats3@example.com', inviterId: testUser1._id, token: 'token3', status: 'cancelled' },
          { email: 'stats4@example.com', inviterId: testUser1._id, token: 'token4', status: 'expired' },
          { email: 'stats5@example.com', inviterId: testUser2._id, token: 'token5', status: 'accepted' } // Different user
        ]);
      });

      it('should get invitation statistics for user', async () => {
        const response = await request(app)
          .get('/api/invitations/stats')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.stats).toMatchObject({
          total: 4,
          pending: 1,
          accepted: 1,
          cancelled: 1,
          expired: 1,
          acceptanceRate: 0.25 // 1/4
        });
      });
    });

    describe('POST /api/invitations/bulk-send', () => {
      it('should send multiple invitations in bulk', async () => {
        const bulkData = {
          invitations: [
            { email: 'bulk1@example.com', name: 'Bulk User 1' },
            { email: 'bulk2@example.com', name: 'Bulk User 2' },
            { email: 'bulk3@example.com', name: 'Bulk User 3' }
          ],
          message: 'Join our platform today!'
        };

        const response = await request(app)
          .post('/api/invitations/bulk-send')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(bulkData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.sent).toHaveLength(3);
        expect(response.body.data.failed).toHaveLength(0);
        expect(response.body.data.summary.total).toBe(3);
        expect(response.body.data.summary.successful).toBe(3);
        expect(response.body.data.summary.failed).toBe(0);

        // Verify invitations were created
        const createdInvitations = await Invitation.find({
          inviterId: testUser1._id,
          message: bulkData.message
        });
        expect(createdInvitations).toHaveLength(3);
      });
    });

    describe('GET /api/invitations/:id', () => {
      let testInvitation;

      beforeEach(async () => {
        testInvitation = await Invitation.create({
          email: 'specific@example.com',
          inviterName: 'Test Inviter',
          inviterId: testUser1._id,
          token: 'specific-token-123',
          status: 'pending'
        });
      });

      it('should retrieve specific invitation by ID', async () => {
        const response = await request(app)
          .get(`/api/invitations/${testInvitation._id}`)
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation).toMatchObject({
          _id: testInvitation._id.toString(),
          email: 'specific@example.com',
          inviterName: 'Test Inviter',
          inviterId: testUser1._id.toString(),
          status: 'pending'
        });
      });
    });

    describe('Public Invitation Access', () => {
      let publicInvitation;

      beforeEach(async () => {
        publicInvitation = await Invitation.create({
          email: 'public@example.com',
          inviterName: 'Public Inviter',
          inviterId: testUser1._id,
          token: 'public-token-123',
          status: 'pending',
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });
      });

      describe('GET /api/invitations/public/:token', () => {
        it('should retrieve public invitation details', async () => {
          const response = await request(app)
            .get(`/api/invitations/public/${publicInvitation.token}`)
            .expect(HTTP_STATUS.OK);

          expect(response.body.success).toBe(true);
          expect(response.body.data.invitation).toMatchObject({
            email: 'public@example.com',
            inviterName: 'Public Inviter',
            status: 'pending'
          });
          expect(response.body.data.invitation).not.toHaveProperty('inviterId'); // Should be filtered out
        });
      });

      describe('GET /api/invitations/public/:token/form', () => {
        it('should retrieve registration form for valid invitation', async () => {
          const response = await request(app)
            .get(`/api/invitations/public/${publicInvitation.token}/form`)
            .expect(HTTP_STATUS.OK);

          expect(response.body.success).toBe(true);
          expect(response.body.data.form).toMatchObject({
            email: 'public@example.com',
            inviterName: 'Public Inviter',
            token: publicInvitation.token
          });
        });
      });

      describe('POST /api/invitations/public/:token/submit', () => {
        it('should accept invitation and register user', async () => {
          const registrationData = {
            username: 'newuser',
            password: 'newpassword123',
            firstName: 'New',
            lastName: 'User'
          };

          const response = await request(app)
            .post(`/api/invitations/public/${publicInvitation.token}/submit`)
            .send(registrationData)
            .expect(HTTP_STATUS.CREATED);

          expect(response.body.success).toBe(true);
          expect(response.body.data.user).toMatchObject({
            username: registrationData.username,
            email: 'public@example.com'
          });

          // Verify invitation was marked as accepted
          const updatedInvitation = await Invitation.findById(publicInvitation._id);
          expect(updatedInvitation.status).toBe('accepted');
          expect(updatedInvitation.acceptedAt).toBeDefined();

          // Verify user was created
          const newUser = await User.findOne({ username: registrationData.username });
          expect(newUser).toBeTruthy();
          expect(newUser.email).toBe('public@example.com');
        });
      });

      describe('POST /api/invitations/public/:token/verify', () => {
        it('should verify invitation token validity', async () => {
          const response = await request(app)
            .post(`/api/invitations/public/${publicInvitation.token}/verify`)
            .expect(HTTP_STATUS.OK);

          expect(response.body.success).toBe(true);
          expect(response.body.data.valid).toBe(true);
          expect(response.body.data.invitation).toMatchObject({
            email: 'public@example.com',
            inviterName: 'Public Inviter'
          });
        });
      });
    });
  });

  describe('Error Scenarios', () => {
    describe('Authentication and Authorization', () => {
      it('should reject requests without authentication', async () => {
        const response = await request(app)
          .get('/api/invitations')
          .expect(HTTP_STATUS.UNAUTHORIZED);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('authentication');
      });

      it('should reject POST requests without CSRF token', async () => {
        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .send({ email: 'test@example.com' })
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      });

      it('should prevent access to other users invitations', async () => {
        // Create invitation for user2
        const otherInvitation = await Invitation.create({
          email: 'other@example.com',
          inviterId: testUser2._id,
          token: 'other-token'
        });

        const response = await request(app)
          .get(`/api/invitations/${otherInvitation._id}`)
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Input Validation Errors', () => {
      it('should reject invitation with invalid email', async () => {
        const invalidData = {
          email: 'invalid-email'
        };

        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(invalidData)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.errors).toBeDefined();
      });

      it('should reject invitation with empty email', async () => {
        const invalidData = {
          email: ''
        };

        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(invalidData)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });

      it('should reject invitation with message too long', async () => {
        const invalidData = {
          email: 'test@example.com',
          message: 'a'.repeat(1001) // Assuming 1000 char limit
        };

        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(invalidData)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });

      it('should reject bulk invitations with invalid data', async () => {
        const invalidData = {
          invitations: [
            { email: 'valid@example.com' },
            { email: 'invalid-email' }, // Invalid email
            { name: 'No Email' } // Missing email
          ]
        };

        const response = await request(app)
          .post('/api/invitations/bulk-send')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(invalidData)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Business Logic Errors', () => {
      it('should prevent duplicate invitations to same email', async () => {
        const email = 'duplicate@example.com';
        
        // Create first invitation
        await Invitation.create({
          email: email,
          inviterId: testUser1._id,
          token: 'first-token',
          status: 'pending'
        });

        // Try to create duplicate
        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({ email: email })
          .expect(HTTP_STATUS.CONFLICT);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('already has a pending invitation');
      });

      it('should prevent inviting existing users', async () => {
        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({ email: testUser2.email })
          .expect(HTTP_STATUS.CONFLICT);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('already registered');
      });

      it('should prevent extending non-pending invitations', async () => {
        const invitation = await Invitation.create({
          email: 'accepted@example.com',
          inviterId: testUser1._id,
          token: 'accepted-token',
          status: 'accepted' // Not pending
        });

        const response = await request(app)
          .post(`/api/invitations/${invitation._id}/extend`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({ days: 7 })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('can only extend pending invitations');
      });

      it('should prevent canceling already processed invitations', async () => {
        const invitation = await Invitation.create({
          email: 'accepted@example.com',
          inviterId: testUser1._id,
          token: 'accepted-token',
          status: 'accepted' // Already processed
        });

        const response = await request(app)
          .post(`/api/invitations/${invitation._id}/cancel`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('cannot cancel processed invitation');
      });
    });

    describe('Resource Not Found', () => {
      it('should return 404 for non-existent invitation', async () => {
        const nonExistentId = new mongoose.Types.ObjectId();
        
        const response = await request(app)
          .get(`/api/invitations/${nonExistentId}`)
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.NOT_FOUND);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('not found');
      });

      it('should return 400 for invalid ObjectId format', async () => {
        const response = await request(app)
          .get('/api/invitations/invalid-id')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });

      it('should return 404 for non-existent public invitation token', async () => {
        const response = await request(app)
          .get('/api/invitations/public/non-existent-token')
          .expect(HTTP_STATUS.NOT_FOUND);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('not found');
      });
    });
  });

  describe('Security Testing', () => {
    describe('XSS Protection', () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '"><script>alert("xss")</script>',
        '<img src="x" onerror="alert(\'xss\')">',
        'javascript:alert("xss")',
        '<svg/onload=alert("xss")>',
        '<iframe src="javascript:alert(\'xss\')"></iframe>'
      ];

      xssPayloads.forEach((payload, index) => {
        it(`should escape XSS payload ${index + 1} in invitation message`, async () => {
          const response = await request(app)
            .post('/api/invitations')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              email: 'xss@example.com',
              name: `Test ${payload}`,
              message: `Message with ${payload}`
            })
            .expect(HTTP_STATUS.CREATED);

          expect(response.body.success).toBe(true);
          
          // Verify that dangerous characters are escaped
          expect(response.body.data.invitation.inviterName).not.toContain('<script');
          expect(response.body.data.invitation.message).not.toContain('<script');
          expect(response.body.data.invitation.inviterName).not.toContain('javascript:');
          expect(response.body.data.invitation.message).not.toContain('javascript:');
        });
      });
    });

    describe('Token Security', () => {
      it('should generate unique secure tokens', async () => {
        const invitations = await Promise.all([
          request(app)
            .post('/api/invitations')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({ email: 'token1@example.com' }),
          request(app)
            .post('/api/invitations')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({ email: 'token2@example.com' }),
          request(app)
            .post('/api/invitations')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({ email: 'token3@example.com' })
        ]);

        const tokens = invitations.map(r => r.body.data.invitation.token);
        
        // All tokens should be unique
        expect(new Set(tokens).size).toBe(3);
        
        // Tokens should be reasonably long and secure
        tokens.forEach(token => {
          expect(token.length).toBeGreaterThan(20);
          expect(token).toMatch(/^[a-zA-Z0-9]+$/); // Only alphanumeric
        });
      });

      it('should not expose sensitive invitation details in public endpoints', async () => {
        const invitation = await Invitation.create({
          email: 'sensitive@example.com',
          inviterId: testUser1._id,
          token: 'sensitive-token',
          status: 'pending',
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });

        const response = await request(app)
          .get(`/api/invitations/public/${invitation.token}`)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.invitation).not.toHaveProperty('inviterId');
        expect(response.body.data.invitation).not.toHaveProperty('token');
        expect(response.body.data.invitation).not.toHaveProperty('_id');
      });
    });

    describe('SQL/NoSQL Injection Protection', () => {
      const injectionPayloads = [
        { $ne: null },
        { $regex: '.*' },
        '"; DROP COLLECTION invitations; --',
        "'; DELETE * FROM invitations; --"
      ];

      injectionPayloads.forEach((payload, index) => {
        it(`should prevent injection payload ${index + 1} in email field`, async () => {
          const response = await request(app)
            .post('/api/invitations')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              email: payload
            })
            .expect(HTTP_STATUS.BAD_REQUEST);

          expect(response.body.success).toBe(false);
        });
      });
    });

    describe('Rate Limiting', () => {
      it('should enforce rate limiting on invitation creation', async () => {
        if (process.env.DISABLE_RATE_LIMITING === 'true') {
          return;
        }

        const promises = Array(15).fill().map((_, i) => 
          request(app)
            .post('/api/invitations')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              email: `ratelimit${i}@example.com`
            })
        );

        const responses = await Promise.all(promises);
        
        // Should have some rate limit responses
        const rateLimited = responses.filter(r => r.status === HTTP_STATUS.TOO_MANY_REQUESTS);
        expect(rateLimited.length).toBeGreaterThan(0);
      });

      it('should enforce rate limiting on bulk invitation sending', async () => {
        if (process.env.DISABLE_RATE_LIMITING === 'true') {
          return;
        }

        const promises = Array(5).fill().map(() => 
          request(app)
            .post('/api/invitations/bulk-send')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              invitations: Array(10).fill().map((_, i) => ({
                email: `bulk${Date.now()}-${i}@example.com`
              }))
            })
        );

        const responses = await Promise.all(promises);
        
        // Should have some rate limit responses for bulk operations
        const rateLimited = responses.filter(r => r.status === HTTP_STATUS.TOO_MANY_REQUESTS);
        expect(rateLimited.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Performance and Load Testing', () => {
    describe('Response Time Validation', () => {
      it('should respond to GET /api/invitations within acceptable time', async () => {
        const startTime = Date.now();
        
        await request(app)
          .get('/api/invitations')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        expect(responseTime).toBeLessThan(1000); // 1 second threshold
      });

      it('should handle invitation creation within acceptable time', async () => {
        const startTime = Date.now();
        
        await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            email: 'performance@example.com',
            message: 'Performance test invitation'
          })
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        expect(responseTime).toBeLessThan(2000); // 2 second threshold
      });
    });

    describe('Concurrent Request Handling', () => {
      it('should handle multiple concurrent GET requests', async () => {
        const concurrentRequests = 5;
        const promises = Array(concurrentRequests).fill().map(() =>
          request(app)
            .get('/api/invitations')
            .set('Cookie', authCookie1)
            .expect(HTTP_STATUS.OK)
        );

        const responses = await Promise.all(promises);
        
        responses.forEach(response => {
          expect(response.body.success).toBe(true);
        });
      });

      it('should handle concurrent invitation creation', async () => {
        const concurrentRequests = 3;
        const promises = Array(concurrentRequests).fill().map((_, i) =>
          request(app)
            .post('/api/invitations')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              email: `concurrent${i}@example.com`,
              message: `Concurrent test ${i}`
            })
            .expect(HTTP_STATUS.CREATED)
        );

        const responses = await Promise.all(promises);
        
        responses.forEach(response => {
          expect(response.body.success).toBe(true);
        });

        // Verify all invitations were created
        const allInvitations = await Invitation.find({ inviterId: testUser1._id });
        const concurrentInvitations = allInvitations.filter(i => 
          i.email.startsWith('concurrent')
        );
        expect(concurrentInvitations).toHaveLength(concurrentRequests);
      });
    });

    describe('Database Query Performance', () => {
      beforeEach(async () => {
        // Create many test invitations for performance testing
        const invitations = Array(100).fill().map((_, i) => ({
          email: `perf${i}@example.com`,
          inviterName: `Perf User ${i}`,
          inviterId: testUser1._id,
          token: `perf-token-${i}`,
          status: i % 4 === 0 ? 'accepted' : i % 4 === 1 ? 'pending' : i % 4 === 2 ? 'cancelled' : 'expired'
        }));

        await Invitation.insertMany(invitations);
      });

      it('should handle pagination efficiently with large dataset', async () => {
        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/invitations?page=5&limit=20')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.invitations).toHaveLength(20);
        expect(responseTime).toBeLessThan(1000); // Should be fast with indexes
      });

      it('should handle status filtering efficiently', async () => {
        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/invitations?status=pending')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.invitations.length).toBeGreaterThan(0);
        expect(responseTime).toBeLessThan(1500); // Should be reasonably fast
      });
    });
  });

  describe('Integration with Other Services', () => {
    it('should maintain data consistency in invitation lifecycle', async () => {
      // Create invitation
      const createResponse = await request(app)
        .post('/api/invitations')
        .set('Cookie', authCookie1)
        .set('X-CSRF-Token', csrfToken1)
        .send({
          email: 'lifecycle@example.com',
          name: 'Lifecycle Test',
          message: 'Integration test invitation'
        })
        .expect(HTTP_STATUS.CREATED);

      const invitationId = createResponse.body.data.invitation._id;
      const token = createResponse.body.data.invitation.token;

      // Extend invitation
      const extendResponse = await request(app)
        .post(`/api/invitations/${invitationId}/extend`)
        .set('Cookie', authCookie1)
        .set('X-CSRF-Token', csrfToken1)
        .send({ days: 14 })
        .expect(HTTP_STATUS.OK);

      // Verify consistency
      expect(extendResponse.body.data.invitation._id).toBe(invitationId);
      expect(extendResponse.body.data.invitation.status).toBe('pending');

      // Accept invitation through public endpoint
      const acceptResponse = await request(app)
        .post(`/api/invitations/public/${token}/submit`)
        .send({
          username: 'lifecycleuser',
          password: 'lifecyclepassword123',
          firstName: 'Lifecycle',
          lastName: 'User'
        })
        .expect(HTTP_STATUS.CREATED);

      // Verify user was created and invitation was accepted
      expect(acceptResponse.body.success).toBe(true);
      expect(acceptResponse.body.data.user.username).toBe('lifecycleuser');

      // Verify database consistency
      const dbInvitation = await Invitation.findById(invitationId);
      expect(dbInvitation.status).toBe('accepted');
      expect(dbInvitation.acceptedAt).toBeDefined();

      const newUser = await User.findOne({ username: 'lifecycleuser' });
      expect(newUser).toBeTruthy();
      expect(newUser.email).toBe('lifecycle@example.com');
    });

    it('should handle bulk invitation statistics correctly', async () => {
      // Send bulk invitations
      const bulkResponse = await request(app)
        .post('/api/invitations/bulk-send')
        .set('Cookie', authCookie1)
        .set('X-CSRF-Token', csrfToken1)
        .send({
          invitations: [
            { email: 'stats1@example.com', name: 'Stats User 1' },
            { email: 'stats2@example.com', name: 'Stats User 2' },
            { email: 'stats3@example.com', name: 'Stats User 3' }
          ],
          message: 'Statistics test invitations'
        })
        .expect(HTTP_STATUS.CREATED);

      expect(bulkResponse.body.data.summary.successful).toBe(3);

      // Accept one invitation
      const invitations = await Invitation.find({ 
        inviterId: testUser1._id,
        email: { $in: ['stats1@example.com', 'stats2@example.com', 'stats3@example.com'] }
      });

      await Invitation.findByIdAndUpdate(invitations[0]._id, { 
        status: 'accepted',
        acceptedAt: new Date()
      });

      // Cancel one invitation
      await request(app)
        .post(`/api/invitations/${invitations[1]._id}/cancel`)
        .set('Cookie', authCookie1)
        .set('X-CSRF-Token', csrfToken1)
        .expect(HTTP_STATUS.OK);

      // Check statistics
      const statsResponse = await request(app)
        .get('/api/invitations/stats')
        .set('Cookie', authCookie1)
        .expect(HTTP_STATUS.OK);

      expect(statsResponse.body.success).toBe(true);
      expect(statsResponse.body.data.stats).toMatchObject({
        total: 3,
        pending: 1,
        accepted: 1,
        cancelled: 1,
        expired: 0
      });
    });

    it('should prevent registration with invitation of existing user', async () => {
      // Create invitation for existing user's email
      const invitation = await Invitation.create({
        email: testUser2.email, // Existing user
        inviterId: testUser1._id,
        token: 'existing-user-token',
        status: 'pending',
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      });

      // Try to register with existing email
      const response = await request(app)
        .post(`/api/invitations/public/${invitation.token}/submit`)
        .send({
          username: 'newusername',
          password: 'newpassword123',
          firstName: 'New',
          lastName: 'User'
        })
        .expect(HTTP_STATUS.CONFLICT);

      expect(response.body.success).toBe(false);
      expect(response.body.error).toContain('already registered');
    });
  });
});