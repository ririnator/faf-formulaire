// tests/api.handshakes.integration.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./integration/setup-integration');
const User = require('../models/User');
const Handshake = require('../models/Handshake');
const Contact = require('../models/Contact');
const { HTTP_STATUS } = require('../constants');

describe('API Integration Tests - /api/handshakes', () => {
  let testUser1, testUser2, testUser3, testUser4;
  let authCookie1, authCookie2;
  let csrfToken1, csrfToken2;

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

    testUser4 = await User.create({
      username: 'user4',
      email: 'user4@test.com',
      password: 'password123',
      role: 'user'
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
  });

  describe('Nominal Cases - Happy Path', () => {
    describe('POST /api/handshakes/request', () => {
      it('should create a handshake request successfully', async () => {
        const handshakeData = {
          userId: testUser2._id.toString(),
          message: 'Hey, let\'s connect!'
        };

        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send(handshakeData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.requesterId).toBe(testUser1._id.toString());
        expect(response.body.handshake.targetId).toBe(testUser2._id.toString());
        expect(response.body.handshake.message).toBe(handshakeData.message);
        expect(response.body.handshake.status).toBe('pending');
        expect(response.body.handshake).toHaveProperty('_id');
        expect(response.body.handshake).toHaveProperty('requestedAt');
        expect(response.body.created).toBe(true);
      });

      it('should create handshake request without message', async () => {
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: testUser2._id.toString()
          })
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.requesterId).toBe(testUser1._id.toString());
        expect(response.body.handshake.targetId).toBe(testUser2._id.toString());
        expect(response.body.handshake.status).toBe('pending');
      });

      it('should handle French characters in message', async () => {
        const message = 'Salut! J\'aimerais me connecter avec toi. Comment ça va?';
        
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: testUser2._id.toString(),
            message: message
          })
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.message).toBe(message);
      });
    });

    describe('GET /api/handshakes/received', () => {
      beforeEach(async () => {
        // Create test handshakes
        await Handshake.create([
          {
            requesterId: testUser2._id,
            targetId: testUser1._id,
            message: 'First request',
            status: 'pending'
          },
          {
            requesterId: testUser3._id,
            targetId: testUser1._id,
            message: 'Second request',
            status: 'pending'
          },
          {
            requesterId: testUser4._id,
            targetId: testUser1._id,
            message: 'Third request',
            status: 'accepted'
          },
          {
            requesterId: testUser1._id,
            targetId: testUser4._id, // Different recipient - shouldn't appear
            message: 'Outgoing request',
            status: 'pending'
          }
        ]);
      });

      it('should retrieve received handshake requests', async () => {
        const response = await request(app)
          .get('/api/handshakes/received')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshakes).toHaveLength(3);
        
        // Verify all are received by testUser1
        response.body.handshakes.forEach(handshake => {
          expect(handshake.targetId).toBe(testUser1._id.toString());
        });

        // Verify population of user data
        expect(response.body.handshakes[0]).toHaveProperty('requesterDetails');
        expect(response.body.handshakes[0].requesterDetails).toHaveProperty('username');
      });

      it('should support filtering by status', async () => {
        const response = await request(app)
          .get('/api/handshakes/received?status=pending')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshakes).toHaveLength(2);
        
        response.body.handshakes.forEach(handshake => {
          expect(handshake.status).toBe('pending');
        });
      });

      it('should support pagination', async () => {
        const response = await request(app)
          .get('/api/handshakes/received?page=1&limit=2')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshakes).toHaveLength(2);
        expect(response.body.pagination).toMatchObject({
          currentPage: 1,
          totalPages: 2,
          totalItems: 3,
          limit: 2
        });
      });
    });

    describe('GET /api/handshakes/sent', () => {
      beforeEach(async () => {
        await Handshake.create([
          {
            requesterId: testUser1._id,
            targetId: testUser2._id,
            message: 'Sent to user2',
            status: 'pending'
          },
          {
            requesterId: testUser1._id,
            targetId: testUser3._id,
            message: 'Sent to user3',
            status: 'accepted'
          },
          {
            requesterId: testUser2._id,
            targetId: testUser1._id, // Different requester - shouldn't appear
            message: 'Received from user2',
            status: 'pending'
          }
        ]);
      });

      it('should retrieve sent handshake requests', async () => {
        const response = await request(app)
          .get('/api/handshakes/sent')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshakes).toHaveLength(2);
        
        // Verify all are sent by testUser1
        response.body.handshakes.forEach(handshake => {
          expect(handshake.requesterId).toBe(testUser1._id.toString());
        });

        // Verify population of recipient data
        expect(response.body.handshakes[0]).toHaveProperty('targetDetails');
        expect(response.body.handshakes[0].targetDetails).toHaveProperty('username');
      });
    });

    describe('POST /api/handshakes/:id/accept', () => {
      let testHandshake;

      beforeEach(async () => {
        testHandshake = await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser1._id,
          message: 'Request to accept',
          status: 'pending'
        });
      });

      it('should accept a handshake request successfully', async () => {
        const response = await request(app)
          .post(`/api/handshakes/${testHandshake._id}/accept`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({ message: 'Sure, let\'s connect!' })
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.status).toBe('accepted');
        expect(response.body.handshake.responseMessage).toBe('Sure, let\'s connect!');
        expect(response.body.handshake).toHaveProperty('respondedAt');

        // Verify database update
        const updatedHandshake = await Handshake.findById(testHandshake._id);
        expect(updatedHandshake.status).toBe('accepted');
        expect(updatedHandshake.respondedAt).toBeDefined();
      });

      it('should accept handshake without response message', async () => {
        const response = await request(app)
          .post(`/api/handshakes/${testHandshake._id}/accept`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({})
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.status).toBe('accepted');
      });

      it('should create mutual contacts after acceptance', async () => {
        await request(app)
          .post(`/api/handshakes/${testHandshake._id}/accept`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({})
          .expect(HTTP_STATUS.OK);

        // Check if contacts were created
        const contact1 = await Contact.findOne({
          userId: testUser1._id,
          linkedUserId: testUser2._id
        });

        const contact2 = await Contact.findOne({
          userId: testUser2._id,
          linkedUserId: testUser1._id
        });

        expect(contact1).toBeTruthy();
        expect(contact2).toBeTruthy();
        expect(contact1.name).toBe(testUser2.username);
        expect(contact2.name).toBe(testUser1.username);
      });
    });

    describe('POST /api/handshakes/:id/decline', () => {
      let testHandshake;

      beforeEach(async () => {
        testHandshake = await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser1._id,
          message: 'Request to decline',
          status: 'pending'
        });
      });

      it('should decline a handshake request successfully', async () => {
        const response = await request(app)
          .post(`/api/handshakes/${testHandshake._id}/decline`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({ responseMessage: 'Not interested at the moment' })
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.status).toBe('declined');
        expect(response.body.handshake.responseMessage).toBe('Not interested at the moment');
        expect(response.body.handshake).toHaveProperty('respondedAt');
      });

      it('should decline handshake without reason', async () => {
        const response = await request(app)
          .post(`/api/handshakes/${testHandshake._id}/decline`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({})
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.status).toBe('declined');
      });
    });

    describe('GET /api/handshakes/:id', () => {
      let testHandshake;

      beforeEach(async () => {
        testHandshake = await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          message: 'Test handshake',
          status: 'pending'
        });
      });

      it('should retrieve specific handshake by ID', async () => {
        const response = await request(app)
          .get(`/api/handshakes/${testHandshake._id}`)
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake).toMatchObject({
          _id: testHandshake._id.toString(),
          requesterId: testUser1._id.toString(),
          targetId: testUser2._id.toString(),
          message: 'Test handshake',
          status: 'pending'
        });
      });
    });

    describe('POST /api/handshakes/:id/cancel', () => {
      let testHandshake;

      beforeEach(async () => {
        testHandshake = await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          message: 'Request to cancel',
          status: 'pending'
        });
      });

      it('should cancel own handshake request successfully', async () => {
        const response = await request(app)
          .post(`/api/handshakes/${testHandshake._id}/cancel`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.status).toBe('cancelled');
        expect(response.body.handshake).toHaveProperty('cancelledAt');
      });
    });

    describe('POST /api/handshakes/:id/block', () => {
      let testHandshake;

      beforeEach(async () => {
        testHandshake = await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser1._id,
          message: 'Request to block',
          status: 'pending'
        });
      });

      it('should block user and mark handshake as blocked', async () => {
        const response = await request(app)
          .post(`/api/handshakes/${testHandshake._id}/block`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({ blockReason: 'Inappropriate behavior' })
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.handshake.status).toBe('blocked');
        expect(response.body.handshake.blockReason).toBe('Inappropriate behavior');
      });
    });

    describe('GET /api/handshakes/suggestions', () => {
      beforeEach(async () => {
        // Create some existing connections to affect suggestions
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'accepted'
        });
      });

      it('should get handshake suggestions', async () => {
        const response = await request(app)
          .get('/api/handshakes/suggestions')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.suggestions).toBeDefined();
        expect(Array.isArray(response.body.suggestions)).toBe(true);

        // Should not include already connected users or self
        response.body.suggestions.forEach(suggestion => {
          expect(suggestion._id).not.toBe(testUser1._id.toString());
          expect(suggestion._id).not.toBe(testUser2._id.toString()); // Already connected
        });
      });

      it('should support limiting number of suggestions', async () => {
        const response = await request(app)
          .get('/api/handshakes/suggestions?limit=2')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.suggestions.length).toBeLessThanOrEqual(2);
      });
    });

    describe('GET /api/handshakes/stats', () => {
      beforeEach(async () => {
        await Handshake.create([
          { requesterId: testUser1._id, targetId: testUser2._id, status: 'pending' },
          { requesterId: testUser1._id, targetId: testUser3._id, status: 'accepted' },
          { requesterId: testUser4._id, targetId: testUser1._id, status: 'declined' },
          { requesterId: testUser2._id, targetId: testUser1._id, status: 'accepted' }
        ]);
      });

      it('should get handshake statistics', async () => {
        const response = await request(app)
          .get('/api/handshakes/stats')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.stats).toMatchObject({
          sent: expect.objectContaining({
            total: 2,
            pending: 1,
            accepted: 1,
            declined: 0
          }),
          received: expect.objectContaining({
            total: 2,
            pending: 0,
            accepted: 1,
            declined: 1
          })
        });
      });
    });
  });

  describe('Error Scenarios', () => {
    describe('Authentication and Authorization', () => {
      it('should reject requests without authentication', async () => {
        const response = await request(app)
          .get('/api/handshakes/received')
          .expect(HTTP_STATUS.UNAUTHORIZED);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('authentication');
      });

      it('should reject POST requests without CSRF token', async () => {
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .send({ recipientId: testUser2._id.toString() })
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      });

      it('should prevent access to other users handshakes', async () => {
        // Create handshake between user2 and user3
        const handshake = await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser3._id,
          status: 'pending'
        });

        // User1 should not be able to access it
        const response = await request(app)
          .get(`/api/handshakes/${handshake._id}`)
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      });

      it('should prevent accepting handshakes not addressed to user', async () => {
        const handshake = await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser3._id, // Not user1
          status: 'pending'
        });

        const response = await request(app)
          .post(`/api/handshakes/${handshake._id}/accept`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      });

      it('should prevent canceling handshakes not sent by user', async () => {
        const handshake = await Handshake.create({
          requesterId: testUser2._id, // Not user1
          targetId: testUser3._id,
          status: 'pending'
        });

        const response = await request(app)
          .post(`/api/handshakes/${handshake._id}/cancel`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Input Validation Errors', () => {
      it('should reject handshake request with invalid recipient ID', async () => {
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: 'invalid-id'
          })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.errors).toBeDefined();
      });

      it('should reject handshake request to non-existent user', async () => {
        const nonExistentId = new mongoose.Types.ObjectId();
        
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: nonExistentId.toString()
          })
          .expect(HTTP_STATUS.NOT_FOUND);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('not found');
      });

      it('should reject handshake request to self', async () => {
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: testUser1._id.toString()
          })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('cannot send handshake to yourself');
      });

      it('should reject message that is too long', async () => {
        const longMessage = 'a'.repeat(1001); // Assuming 1000 char limit
        
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: testUser2._id.toString(),
            message: longMessage
          })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Business Logic Errors', () => {
      it('should prevent duplicate handshake requests', async () => {
        // Create first handshake
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'pending'
        });

        // Try to create duplicate
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: testUser2._id.toString()
          })
          .expect(HTTP_STATUS.CONFLICT);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('already exists');
      });

      it('should prevent accepting already processed handshake', async () => {
        const handshake = await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser1._id,
          status: 'accepted' // Already accepted
        });

        const response = await request(app)
          .post(`/api/handshakes/${handshake._id}/accept`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('already been processed');
      });

      it('should prevent declining already processed handshake', async () => {
        const handshake = await Handshake.create({
          requesterId: testUser2._id,
          targetId: testUser1._id,
          status: 'declined' // Already declined
        });

        const response = await request(app)
          .post(`/api/handshakes/${handshake._id}/decline`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('already been processed');
      });

      it('should prevent canceling non-pending handshake', async () => {
        const handshake = await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'accepted' // Not pending
        });

        const response = await request(app)
          .post(`/api/handshakes/${handshake._id}/cancel`)
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('can only cancel pending');
      });
    });

    describe('Resource Not Found', () => {
      it('should return 404 for non-existent handshake', async () => {
        const nonExistentId = new mongoose.Types.ObjectId();
        
        const response = await request(app)
          .get(`/api/handshakes/${nonExistentId}`)
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.NOT_FOUND);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('not found');
      });

      it('should return 400 for invalid ObjectId format', async () => {
        const response = await request(app)
          .get('/api/handshakes/invalid-id')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
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
        it(`should escape XSS payload ${index + 1} in handshake message`, async () => {
          const response = await request(app)
            .post('/api/handshakes/request')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              userId: testUser2._id.toString(),
              message: payload
            })
            .expect(HTTP_STATUS.CREATED);

          expect(response.body.success).toBe(true);
          
          // Verify that dangerous characters are escaped
          expect(response.body.handshake.message).not.toContain('<script');
          expect(response.body.handshake.message).not.toContain('javascript:');
          expect(response.body.handshake.message).not.toContain('onerror=');
        });

        it(`should escape XSS payload ${index + 1} in response message`, async () => {
          const handshake = await Handshake.create({
            requesterId: testUser2._id,
            targetId: testUser1._id,
            status: 'pending'
          });

          const response = await request(app)
            .post(`/api/handshakes/${handshake._id}/accept`)
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              responseMessage: payload
            })
            .expect(HTTP_STATUS.OK);

          expect(response.body.success).toBe(true);
          expect(response.body.handshake.responseMessage).not.toContain('<script');
          expect(response.body.handshake.responseMessage).not.toContain('javascript:');
        });
      });
    });

    describe('SQL/NoSQL Injection Protection', () => {
      const injectionPayloads = [
        { $ne: null },
        { $regex: '.*' },
        '"; DROP COLLECTION handshakes; --',
        "'; DELETE * FROM handshakes; --"
      ];

      injectionPayloads.forEach((payload, index) => {
        it(`should prevent injection payload ${index + 1} in recipientId`, async () => {
          const response = await request(app)
            .post('/api/handshakes/request')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              userId: payload
            })
            .expect(HTTP_STATUS.BAD_REQUEST);

          expect(response.body.success).toBe(false);
        });
      });
    });

    describe('Rate Limiting', () => {
      it('should enforce rate limiting on handshake requests', async () => {
        if (process.env.DISABLE_RATE_LIMITING === 'true') {
          return;
        }

        const promises = Array(10).fill().map((_, i) => 
          request(app)
            .post('/api/handshakes/request')
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .send({
              userId: testUser2._id.toString(),
              message: `Rate limit test ${i}`
            })
        );

        const responses = await Promise.all(promises);
        
        // Should have some rate limit responses
        const rateLimited = responses.filter(r => r.status === HTTP_STATUS.TOO_MANY_REQUESTS);
        expect(rateLimited.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Performance and Load Testing', () => {
    describe('Response Time Validation', () => {
      it('should respond to GET /api/handshakes/received within acceptable time', async () => {
        const startTime = Date.now();
        
        await request(app)
          .get('/api/handshakes/received')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        expect(responseTime).toBeLessThan(1000); // 1 second threshold
      });

      it('should handle handshake creation within acceptable time', async () => {
        const startTime = Date.now();
        
        await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookie1)
          .set('X-CSRF-Token', csrfToken1)
          .send({
            userId: testUser2._id.toString(),
            message: 'Performance test handshake'
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
            .get('/api/handshakes/received')
            .set('Cookie', authCookie1)
            .expect(HTTP_STATUS.OK)
        );

        const responses = await Promise.all(promises);
        
        responses.forEach(response => {
          expect(response.body.success).toBe(true);
        });
      });

      it('should handle concurrent handshake acceptance', async () => {
        // Create multiple pending handshakes
        const handshakes = await Promise.all(
          Array(3).fill().map((_, i) => 
            Handshake.create({
              requesterId: testUser2._id,
              targetId: testUser1._id,
              message: `Concurrent test ${i}`,
              status: 'pending'
            })
          )
        );

        // Accept them concurrently
        const promises = handshakes.map(handshake =>
          request(app)
            .post(`/api/handshakes/${handshake._id}/accept`)
            .set('Cookie', authCookie1)
            .set('X-CSRF-Token', csrfToken1)
            .expect(HTTP_STATUS.OK)
        );

        const responses = await Promise.all(promises);
        
        responses.forEach(response => {
          expect(response.body.success).toBe(true);
          expect(response.body.handshake.status).toBe('accepted');
        });

        // Verify all were properly updated
        const updatedHandshakes = await Handshake.find({
          _id: { $in: handshakes.map(h => h._id) }
        });
        
        updatedHandshakes.forEach(handshake => {
          expect(handshake.status).toBe('accepted');
        });
      });
    });

    describe('Database Query Performance', () => {
      beforeEach(async () => {
        // Create many test handshakes for performance testing
        const handshakes = Array(100).fill().map((_, i) => ({
          requesterId: testUser2._id,
          targetId: testUser1._id,
          message: `Performance handshake ${i}`,
          status: i % 3 === 0 ? 'accepted' : i % 3 === 1 ? 'pending' : 'declined'
        }));

        await Handshake.insertMany(handshakes);
      });

      it('should handle pagination efficiently with large dataset', async () => {
        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/handshakes/received?page=5&limit=20')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.handshakes).toHaveLength(20);
        expect(responseTime).toBeLessThan(1000); // Should be fast with indexes
      });

      it('should handle status filtering efficiently', async () => {
        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/handshakes/received?status=accepted')
          .set('Cookie', authCookie1)
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.handshakes.length).toBeGreaterThan(0);
        expect(responseTime).toBeLessThan(1500); // Should be reasonably fast
      });
    });
  });

  describe('Integration with Other Services', () => {
    it('should maintain data consistency in handshake lifecycle', async () => {
      // Create handshake
      const createResponse = await request(app)
        .post('/api/handshakes/request')
        .set('Cookie', authCookie1)
        .set('X-CSRF-Token', csrfToken1)
        .send({
          userId: testUser2._id.toString(),
          message: 'Integration test handshake'
        })
        .expect(HTTP_STATUS.CREATED);

      const handshakeId = createResponse.body.handshake._id;

      // Accept handshake
      const acceptResponse = await request(app)
        .post(`/api/handshakes/${handshakeId}/accept`)
        .set('Cookie', authCookie2) // User2 accepting
        .set('X-CSRF-Token', csrfToken2)
        .send({
          responseMessage: 'Great to connect!'
        })
        .expect(HTTP_STATUS.OK);

      // Verify consistency
      expect(acceptResponse.body.handshake._id).toBe(handshakeId);
      expect(acceptResponse.body.handshake.status).toBe('accepted');
      expect(acceptResponse.body.handshake.responseMessage).toBe('Great to connect!');

      // Verify in database
      const dbHandshake = await Handshake.findById(handshakeId);
      expect(dbHandshake.status).toBe('accepted');
      expect(dbHandshake.responseMessage).toBe('Great to connect!');
      expect(dbHandshake.respondedAt).toBeDefined();

      // Verify contacts were created
      const contact1 = await Contact.findOne({
        userId: testUser1._id,
        linkedUserId: testUser2._id
      });

      const contact2 = await Contact.findOne({
        userId: testUser2._id,
        linkedUserId: testUser1._id
      });

      expect(contact1).toBeTruthy();
      expect(contact2).toBeTruthy();
    });

    it('should handle handshake statistics calculation', async () => {
      // Create various handshakes
      await Handshake.create([
        { requesterId: testUser1._id, targetId: testUser2._id, status: 'pending' },
        { requesterId: testUser1._id, targetId: testUser3._id, status: 'accepted' },
        { requesterId: testUser1._id, targetId: testUser4._id, status: 'declined' },
        { requesterId: testUser2._id, targetId: testUser1._id, status: 'accepted' },
        { requesterId: testUser3._id, targetId: testUser1._id, status: 'pending' }
      ]);

      const response = await request(app)
        .get('/api/handshakes/stats')
        .set('Cookie', authCookie1)
        .expect(HTTP_STATUS.OK);

      expect(response.body.success).toBe(true);
      expect(response.body.stats).toMatchObject({
        sent: {
          total: 3,
          pending: 1,
          accepted: 1,
          declined: 1
        },
        received: {
          total: 2,
          pending: 1,
          accepted: 1,
          declined: 0
        }
      });
    });

    it('should handle suggestions algorithm correctly', async () => {
      // Create some connections to test suggestion logic
      await Handshake.create([
        { requesterId: testUser1._id, targetId: testUser2._id, status: 'accepted' },
        { requesterId: testUser1._id, targetId: testUser3._id, status: 'blocked' }
      ]);

      const response = await request(app)
        .get('/api/handshakes/suggestions?limit=10')
        .set('Cookie', authCookie1)
        .expect(HTTP_STATUS.OK);

      expect(response.body.success).toBe(true);
      
      const suggestionIds = response.body.suggestions.map(s => s._id);
      
      // Should not include self, already connected, or blocked users
      expect(suggestionIds).not.toContain(testUser1._id.toString());
      expect(suggestionIds).not.toContain(testUser2._id.toString()); // Connected
      expect(suggestionIds).not.toContain(testUser3._id.toString()); // Blocked
    });
  });
});