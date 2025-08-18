// Minimal API integration test to validate our fixes
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./integration/setup-integration');
const User = require('../models/User');
const Contact = require('../models/Contact');
const { HTTP_STATUS } = require('../constants');
const { createAuthenticatedAgent } = require('./helpers/testAuth');

describe('Minimal API Integration Tests', () => {
  let testUser, authAgent;

  beforeAll(async () => {
    await setupTestDatabase();
    process.env.NODE_ENV = 'test';
    process.env.DISABLE_RATE_LIMITING = 'true';
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  beforeEach(async () => {
    await cleanupDatabase();
    
    // Create test user
    testUser = await User.create({
      username: 'testuser',
      email: 'test@example.com',
      password: 'password123',
      role: 'user'
    });

    // Create authenticated agent
    authAgent = await createAuthenticatedAgent(app, testUser);
  });

  describe('Basic API Functionality', () => {
    it('should get CSRF token', async () => {
      const response = await request(app)
        .get('/api/csrf-token')
        .expect(HTTP_STATUS.OK);

      expect(response.body).toHaveProperty('csrfToken');
      expect(response.body).toHaveProperty('token');
      expect(response.body.csrfToken).toBeTruthy();
    });

    it('should authenticate user successfully', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          login: testUser.email,
          password: 'password123'
        })
        .expect(HTTP_STATUS.OK);

      expect(response.body.message).toBe('Connexion réussie');
      expect(response.body.user).toBeDefined();
      expect(response.body.user.email).toBe(testUser.email);
    });

    it('should create a contact successfully', async () => {
      const contactData = {
        firstName: 'Test',
        lastName: 'Contact',
        email: 'contact@example.com'
      };

      const response = await authAgent
        .post('/api/contacts')
        .send(contactData)
        .expect(HTTP_STATUS.CREATED);

      expect(response.body.success).toBe(true);
      expect(response.body.contact).toMatchObject({
        firstName: contactData.firstName,
        lastName: contactData.lastName,
        email: contactData.email,
        ownerId: {
          _id: testUser._id.toString(),
          username: testUser.username,
          email: testUser.email
        }
      });
    });

    it('should retrieve contacts successfully', async () => {
      // Create a test contact first
      await Contact.create({
        firstName: 'Existing',
        lastName: 'Contact',
        email: 'existing@example.com',
        ownerId: testUser._id
      });

      const response = await authAgent
        .get('/api/contacts')
        .expect(HTTP_STATUS.OK);

      expect(response.body.success).toBe(true);
      expect(response.body.contacts).toHaveLength(1);
      expect(response.body.contacts[0].firstName).toBe('Existing');
    });

    it('should reject unauthorized access', async () => {
      const response = await request(app)
        .get('/api/contacts')
        .expect(HTTP_STATUS.UNAUTHORIZED);

      expect(response.body.success).toBe(false);
    });

    it('should reject requests without CSRF token', async () => {
      const response = await request(app)
        .post('/api/contacts')
        .set('Cookie', authAgent.agent._jar.getCookies('http://localhost'))
        .send({ firstName: 'Test', lastName: 'Contact', email: 'test@example.com' })
        .expect(HTTP_STATUS.FORBIDDEN);

      expect(response.body.success).toBe(false);
    });
  });
});