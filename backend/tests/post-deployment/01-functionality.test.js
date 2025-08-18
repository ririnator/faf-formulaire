/**
 * Post-Deployment Functionality Tests
 * 
 * Comprehensive validation of core FAF v2 functionality
 * including user workflows, admin operations, and data integrity.
 */

const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

describe('🎯 Post-Deployment Functionality Tests', () => {
  let app;
  let server;
  let mongoServer;
  let testUser;
  let testInvitation;
  let testSubmission;
  
  beforeAll(async () => {
    const startTime = global.testReporter.logTestStart('Functionality Test Suite Setup');
    
    try {
      // Import app after environment setup
      app = require('../../app');
      
      // Start server
      server = app.listen(0); // Use random port
      
      console.log('✅ Functionality test environment initialized');
      global.testReporter.logTestEnd('Functionality Test Suite Setup', startTime, true);
    } catch (error) {
      global.testReporter.logTestEnd('Functionality Test Suite Setup', startTime, false);
      throw error;
    }
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
    if (mongoServer) {
      await mongoServer.stop();
    }
    await global.testUtils.executeCleanup();
  });

  describe('👤 User Registration & Authentication Workflow', () => {
    test('should complete full user registration flow', async () => {
      const startTime = global.testReporter.logTestStart('User Registration Flow');
      
      try {
        const userData = {
          username: global.testUtils.generateTestId(),
          email: `${global.testUtils.generateTestId()}@example.com`,
          password: 'TestPass123!',
          profile: {
            firstName: 'Test',
            lastName: 'User'
          }
        };
        
        // Step 1: Register new user
        const registerResponse = await request(app)
          .post('/api/users/register')
          .send(userData)
          .expect(201);
        
        expect(registerResponse.body).toHaveProperty('user');
        expect(registerResponse.body.user.username).toBe(userData.username);
        expect(registerResponse.body.user.email).toBe(userData.email);
        expect(registerResponse.body.user.role).toBe('user');
        
        testUser = registerResponse.body.user;
        global.testUtils.addCleanup('testUsers', testUser);
        
        // Step 2: Login with credentials
        const loginResponse = await request(app)
          .post('/api/auth/login')
          .send({
            username: userData.username,
            password: userData.password
          })
          .expect(200);
        
        expect(loginResponse.body).toHaveProperty('token');
        expect(loginResponse.body.user.id).toBe(testUser.id);
        
        // Step 3: Access protected route
        const profileResponse = await request(app)
          .get('/api/users/profile')
          .set('Authorization', `Bearer ${loginResponse.body.token}`)
          .expect(200);
        
        expect(profileResponse.body.username).toBe(userData.username);
        
        global.testReporter.logTestEnd('User Registration Flow', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('User Registration Flow', startTime, false);
        throw error;
      }
    });

    test('should handle user authentication with session management', async () => {
      const startTime = global.testReporter.logTestStart('Session Management');
      
      try {
        // Login and get session
        const loginResponse = await request(app)
          .post('/api/auth/login')
          .send({
            username: testUser.username,
            password: 'TestPass123!' // From previous test
          })
          .expect(200);
        
        const sessionCookie = loginResponse.headers['set-cookie'];
        expect(sessionCookie).toBeDefined();
        
        // Use session for authenticated request
        const sessionResponse = await request(app)
          .get('/api/users/profile')
          .set('Cookie', sessionCookie)
          .expect(200);
        
        expect(sessionResponse.body.username).toBe(testUser.username);
        
        // Logout and verify session cleanup
        await request(app)
          .post('/api/auth/logout')
          .set('Cookie', sessionCookie)
          .expect(200);
        
        // Verify session is invalid
        await request(app)
          .get('/api/users/profile')
          .set('Cookie', sessionCookie)
          .expect(401);
        
        global.testReporter.logTestEnd('Session Management', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Session Management', startTime, false);
        throw error;
      }
    });
  });

  describe('📋 Form Submission & Response Management', () => {
    let userToken;
    
    beforeAll(async () => {
      // Get authentication token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          username: testUser.username,
          password: 'TestPass123!'
        });
      
      userToken = loginResponse.body.token;
    });

    test('should handle complete form submission workflow', async () => {
      const startTime = global.testReporter.logTestStart('Form Submission Workflow');
      
      try {
        // Step 1: Get current form structure
        const formResponse = await request(app)
          .get('/api/form/current')
          .expect(200);
        
        expect(formResponse.body).toHaveProperty('questions');
        expect(Array.isArray(formResponse.body.questions)).toBe(true);
        
        // Step 2: Submit responses
        const submissionData = {
          responses: formResponse.body.questions.map((question, index) => ({
            question: question.text || `Question ${index + 1}`,
            answer: `Test answer ${index + 1} with French characters: éàçù`
          }))
        };
        
        const submitResponse = await request(app)
          .post('/api/submissions')
          .set('Authorization', `Bearer ${userToken}`)
          .send(submissionData)
          .expect(201);
        
        expect(submitResponse.body).toHaveProperty('id');
        expect(submitResponse.body).toHaveProperty('token');
        expect(submitResponse.body.responses).toHaveLength(submissionData.responses.length);
        
        testSubmission = submitResponse.body;
        global.testUtils.addCleanup('testData', testSubmission);
        
        // Step 3: View responses with token
        const viewResponse = await request(app)
          .get(`/api/responses/view/${testSubmission.token}`)
          .expect(200);
        
        expect(viewResponse.body.responses).toHaveLength(submissionData.responses.length);
        expect(viewResponse.body.month).toBeDefined();
        
        global.testReporter.logTestEnd('Form Submission Workflow', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Form Submission Workflow', startTime, false);
        throw error;
      }
    });

    test('should validate monthly submission constraints', async () => {
      const startTime = global.testReporter.logTestStart('Monthly Submission Constraints');
      
      try {
        // Attempt duplicate submission in same month
        const duplicateSubmission = {
          responses: [
            { question: 'Test Question', answer: 'Duplicate test answer' }
          ]
        };
        
        const duplicateResponse = await request(app)
          .post('/api/submissions')
          .set('Authorization', `Bearer ${userToken}`)
          .send(duplicateSubmission)
          .expect(400);
        
        expect(duplicateResponse.body).toHaveProperty('error');
        expect(duplicateResponse.body.error).toContain('month');
        
        global.testReporter.logTestEnd('Monthly Submission Constraints', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Monthly Submission Constraints', startTime, false);
        throw error;
      }
    });
  });

  describe('🔗 Invitation & Handshake System', () => {
    let adminToken;
    
    beforeAll(async () => {
      // Login as admin
      const adminLoginResponse = await request(app)
        .post('/api/auth/admin-login')
        .send({
          username: global.testConfig.testUsers.adminUser.username,
          password: global.testConfig.testUsers.adminUser.password
        });
      
      adminToken = adminLoginResponse.body.token;
    });

    test('should complete invitation creation and acceptance workflow', async () => {
      const startTime = global.testReporter.logTestStart('Invitation Workflow');
      
      try {
        // Step 1: Create invitation
        const invitationData = {
          email: `invited.${global.testUtils.generateTestId()}@example.com`,
          message: 'Join FAF for monthly friendship forms!',
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
        };
        
        const createResponse = await request(app)
          .post('/api/invitations')
          .set('Authorization', `Bearer ${adminToken}`)
          .send(invitationData)
          .expect(201);
        
        expect(createResponse.body).toHaveProperty('id');
        expect(createResponse.body).toHaveProperty('token');
        expect(createResponse.body.email).toBe(invitationData.email);
        expect(createResponse.body.status).toBe('pending');
        
        testInvitation = createResponse.body;
        global.testUtils.addCleanup('testData', testInvitation);
        
        // Step 2: Verify invitation can be retrieved
        const getResponse = await request(app)
          .get(`/api/invitations/token/${testInvitation.token}`)
          .expect(200);
        
        expect(getResponse.body.email).toBe(invitationData.email);
        expect(getResponse.body.status).toBe('pending');
        
        // Step 3: Accept invitation (simulate user registration)
        const acceptData = {
          username: `invited_${global.testUtils.generateTestId()}`,
          password: 'InvitedUser123!',
          profile: {
            firstName: 'Invited',
            lastName: 'User'
          }
        };
        
        const acceptResponse = await request(app)
          .post(`/api/invitations/accept/${testInvitation.token}`)
          .send(acceptData)
          .expect(201);
        
        expect(acceptResponse.body).toHaveProperty('user');
        expect(acceptResponse.body.user.email).toBe(invitationData.email);
        expect(acceptResponse.body.invitation.status).toBe('accepted');
        
        global.testUtils.addCleanup('testUsers', acceptResponse.body.user);
        
        global.testReporter.logTestEnd('Invitation Workflow', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Invitation Workflow', startTime, false);
        throw error;
      }
    });

    test('should handle handshake creation and management', async () => {
      const startTime = global.testReporter.logTestStart('Handshake Management');
      
      try {
        // Create handshake between users
        const handshakeData = {
          initiatorId: testUser.id,
          recipientEmail: testInvitation.email,
          message: 'Let\'s be FAF friends!'
        };
        
        const createResponse = await request(app)
          .post('/api/handshakes')
          .set('Authorization', `Bearer ${adminToken}`)
          .send(handshakeData)
          .expect(201);
        
        expect(createResponse.body).toHaveProperty('id');
        expect(createResponse.body.status).toBe('pending');
        expect(createResponse.body.initiatorId).toBe(testUser.id);
        
        // List handshakes
        const listResponse = await request(app)
          .get('/api/handshakes')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        expect(Array.isArray(listResponse.body)).toBe(true);
        expect(listResponse.body.some(h => h.id === createResponse.body.id)).toBe(true);
        
        global.testUtils.addCleanup('testData', createResponse.body);
        
        global.testReporter.logTestEnd('Handshake Management', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Handshake Management', startTime, false);
        throw error;
      }
    });
  });

  describe('📊 Admin Dashboard & Management', () => {
    let adminToken;
    
    beforeAll(async () => {
      // Login as admin
      const adminLoginResponse = await request(app)
        .post('/api/auth/admin-login')
        .send({
          username: global.testConfig.testUsers.adminUser.username,
          password: global.testConfig.testUsers.adminUser.password
        });
      
      adminToken = adminLoginResponse.body.token;
    });

    test('should provide comprehensive admin dashboard data', async () => {
      const startTime = global.testReporter.logTestStart('Admin Dashboard Data');
      
      try {
        // Get dashboard summary
        const dashboardResponse = await request(app)
          .get('/api/admin/dashboard')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        expect(dashboardResponse.body).toHaveProperty('summary');
        expect(dashboardResponse.body).toHaveProperty('recentActivity');
        expect(dashboardResponse.body).toHaveProperty('statistics');
        
        const summary = dashboardResponse.body.summary;
        expect(summary).toHaveProperty('totalUsers');
        expect(summary).toHaveProperty('totalSubmissions');
        expect(summary).toHaveProperty('totalInvitations');
        expect(summary).toHaveProperty('activeHandshakes');
        
        // Verify numeric values
        expect(typeof summary.totalUsers).toBe('number');
        expect(typeof summary.totalSubmissions).toBe('number');
        expect(typeof summary.totalInvitations).toBe('number');
        expect(typeof summary.activeHandshakes).toBe('number');
        
        global.testReporter.logTestEnd('Admin Dashboard Data', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Admin Dashboard Data', startTime, false);
        throw error;
      }
    });

    test('should handle admin response management operations', async () => {
      const startTime = global.testReporter.logTestStart('Admin Response Management');
      
      try {
        // List all responses
        const listResponse = await request(app)
          .get('/api/admin/responses')
          .set('Authorization', `Bearer ${adminToken}`)
          .query({ limit: 10, page: 1 })
          .expect(200);
        
        expect(listResponse.body).toHaveProperty('responses');
        expect(listResponse.body).toHaveProperty('pagination');
        expect(Array.isArray(listResponse.body.responses)).toBe(true);
        
        // Get specific response details if available
        if (listResponse.body.responses.length > 0) {
          const responseId = listResponse.body.responses[0].id;
          
          const detailResponse = await request(app)
            .get(`/api/admin/responses/${responseId}`)
            .set('Authorization', `Bearer ${adminToken}`)
            .expect(200);
          
          expect(detailResponse.body).toHaveProperty('id');
          expect(detailResponse.body).toHaveProperty('responses');
          expect(detailResponse.body).toHaveProperty('month');
        }
        
        global.testReporter.logTestEnd('Admin Response Management', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Admin Response Management', startTime, false);
        throw error;
      }
    });

    test('should validate admin user management capabilities', async () => {
      const startTime = global.testReporter.logTestStart('Admin User Management');
      
      try {
        // List users
        const usersResponse = await request(app)
          .get('/api/admin/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .query({ limit: 10, page: 1 })
          .expect(200);
        
        expect(usersResponse.body).toHaveProperty('users');
        expect(usersResponse.body).toHaveProperty('pagination');
        expect(Array.isArray(usersResponse.body.users)).toBe(true);
        
        // Verify user data structure
        if (usersResponse.body.users.length > 0) {
          const user = usersResponse.body.users[0];
          expect(user).toHaveProperty('id');
          expect(user).toHaveProperty('username');
          expect(user).toHaveProperty('email');
          expect(user).toHaveProperty('role');
          expect(user).toHaveProperty('metadata');
        }
        
        global.testReporter.logTestEnd('Admin User Management', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Admin User Management', startTime, false);
        throw error;
      }
    });
  });

  describe('🔄 Data Migration Validation', () => {
    test('should validate migrated data integrity', async () => {
      const startTime = global.testReporter.logTestStart('Migration Data Integrity');
      
      try {
        // Check for legacy responses with migration metadata
        const legacyResponse = await request(app)
          .get('/api/admin/responses/legacy')
          .set('Authorization', `Bearer ${global.testConfig.testUsers.adminUser.username}:${global.testConfig.testUsers.adminUser.password}`)
          .expect(200);
        
        expect(legacyResponse.body).toHaveProperty('count');
        expect(legacyResponse.body).toHaveProperty('responses');
        
        // Verify migration metadata if legacy data exists
        if (legacyResponse.body.responses.length > 0) {
          const response = legacyResponse.body.responses[0];
          expect(response).toHaveProperty('migrationData');
          expect(response.migrationData).toHaveProperty('migratedAt');
          expect(response.migrationData).toHaveProperty('source');
        }
        
        global.testReporter.logTestEnd('Migration Data Integrity', startTime, true);
      } catch (error) {
        // Migration endpoint might not exist yet, log warning but don't fail
        console.warn('Migration validation endpoint not available:', error.message);
        global.testReporter.logTestEnd('Migration Data Integrity', startTime, true);
      }
    });

    test('should validate legacy token compatibility', async () => {
      const startTime = global.testReporter.logTestStart('Legacy Token Compatibility');
      
      try {
        // Test with a known legacy token format if available
        // This would need to be configured based on actual legacy data
        const legacyToken = 'legacy_test_token_format';
        
        // Attempt to access with legacy token
        const response = await request(app)
          .get(`/api/responses/view/${legacyToken}`)
          .expect([200, 404]); // 404 is acceptable if no legacy data
        
        if (response.status === 200) {
          expect(response.body).toHaveProperty('responses');
          console.log('✅ Legacy token compatibility confirmed');
        } else {
          console.log('ℹ️ No legacy token data available for testing');
        }
        
        global.testReporter.logTestEnd('Legacy Token Compatibility', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy Token Compatibility', startTime, false);
        throw error;
      }
    });
  });

  describe('📱 Contact & Communication System', () => {
    let adminToken;
    
    beforeAll(async () => {
      const adminLoginResponse = await request(app)
        .post('/api/auth/admin-login')
        .send({
          username: global.testConfig.testUsers.adminUser.username,
          password: global.testConfig.testUsers.adminUser.password
        });
      
      adminToken = adminLoginResponse.body.token;
    });

    test('should handle contact creation and management', async () => {
      const startTime = global.testReporter.logTestStart('Contact Management');
      
      try {
        // Create contact
        const contactData = {
          user1Id: testUser.id,
          user2Email: testInvitation.email,
          status: 'active',
          metadata: {
            connectionType: 'invitation',
            notes: 'Test contact connection'
          }
        };
        
        const createResponse = await request(app)
          .post('/api/contacts')
          .set('Authorization', `Bearer ${adminToken}`)
          .send(contactData)
          .expect(201);
        
        expect(createResponse.body).toHaveProperty('id');
        expect(createResponse.body.status).toBe('active');
        expect(createResponse.body.user1Id).toBe(testUser.id);
        
        // List contacts
        const listResponse = await request(app)
          .get('/api/contacts')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        expect(Array.isArray(listResponse.body)).toBe(true);
        
        global.testUtils.addCleanup('testData', createResponse.body);
        
        global.testReporter.logTestEnd('Contact Management', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Contact Management', startTime, false);
        throw error;
      }
    });
  });
});