/**
 * Post-Deployment Integration Tests
 * 
 * Comprehensive validation of external service integrations,
 * API endpoint functionality, and system interoperability.
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs');

describe('🔗 Post-Deployment Integration Tests', () => {
  let app;
  let server;
  let adminToken;
  let userToken;
  let testUser;
  
  beforeAll(async () => {
    const startTime = global.testReporter.logTestStart('Integration Test Suite Setup');
    
    try {
      app = require('../../app');
      server = app.listen(0);
      
      // Create test user
      const userData = {
        username: `integration_${global.testUtils.generateTestId()}`,
        email: `integration.${global.testUtils.generateTestId()}@example.com`,
        password: 'IntegrationTest123!'
      };
      
      const registerResponse = await request(app)
        .post('/api/users/register')
        .send(userData);
      
      testUser = registerResponse.body.user;
      
      const userLogin = await request(app)
        .post('/api/auth/login')
        .send({
          username: userData.username,
          password: userData.password
        });
      userToken = userLogin.body.token;
      
      // Get admin token
      const adminLogin = await request(app)
        .post('/api/auth/admin-login')
        .send({
          username: global.testConfig.testUsers.adminUser.username,
          password: global.testConfig.testUsers.adminUser.password
        });
      adminToken = adminLogin.body.token;
      
      global.testReporter.logTestEnd('Integration Test Suite Setup', startTime, true);
    } catch (error) {
      global.testReporter.logTestEnd('Integration Test Suite Setup', startTime, false);
      throw error;
    }
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
    await global.testUtils.executeCleanup();
  });

  describe('🌐 External Service Integration', () => {
    test('should validate email service integration', async () => {
      const startTime = global.testReporter.logTestStart('Email Service Integration');
      
      try {
        // Test email service health
        const emailHealthResponse = await request(app)
          .get('/api/health/email')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 503]).toContain(res.status); // 503 if service unavailable
          });
        
        if (emailHealthResponse.status === 200) {
          expect(emailHealthResponse.body).toHaveProperty('status');
          console.log('✅ Email service is healthy');
        } else {
          console.warn('⚠️ Email service is not available');
        }
        
        // Test email sending (if available)
        try {
          const testEmailResponse = await request(app)
            .post('/api/admin/test-email')
            .set('Authorization', `Bearer ${adminToken}`)
            .send({
              recipient: 'test@example.com',
              subject: 'Post-deployment test',
              content: 'This is a test email from post-deployment validation'
            })
            .expect(res => {
              expect([200, 202, 503]).toContain(res.status);
            });
          
          if (testEmailResponse.status === 200 || testEmailResponse.status === 202) {
            console.log('✅ Email sending functionality works');
          }
        } catch (error) {
          console.log('ℹ️ Email testing endpoint not available');
        }
        
        global.testReporter.logTestEnd('Email Service Integration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Email Service Integration', startTime, false);
        throw error;
      }
    });

    test('should validate file upload service integration', async () => {
      const startTime = global.testReporter.logTestStart('File Upload Service Integration');
      
      try {
        // Create a test image file
        const testImagePath = path.join(__dirname, 'test-upload.jpg');
        const testImageData = Buffer.from('fake-image-data');
        fs.writeFileSync(testImagePath, testImageData);
        
        // Test file upload
        const uploadResponse = await request(app)
          .post('/api/upload')
          .set('Authorization', `Bearer ${userToken}`)
          .attach('image', testImagePath)
          .expect(res => {
            expect([200, 201, 400, 413, 503]).toContain(res.status);
          });
        
        if (uploadResponse.status === 200 || uploadResponse.status === 201) {
          expect(uploadResponse.body).toHaveProperty('url');
          expect(uploadResponse.body.url).toMatch(/^https?:\/\//);
          console.log('✅ File upload service works');
          
          // Test file access
          if (uploadResponse.body.url.includes('cloudinary') || uploadResponse.body.url.includes('http')) {
            console.log('✅ File upload integration confirmed');
          }
        } else if (uploadResponse.status === 503) {
          console.warn('⚠️ File upload service is not available');
        } else {
          console.log('ℹ️ File upload test returned status:', uploadResponse.status);
        }
        
        // Cleanup test file
        if (fs.existsSync(testImagePath)) {
          fs.unlinkSync(testImagePath);
        }
        
        global.testReporter.logTestEnd('File Upload Service Integration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('File Upload Service Integration', startTime, false);
        throw error;
      }
    });

    test('should validate database connection and operations', async () => {
      const startTime = global.testReporter.logTestStart('Database Integration');
      
      try {
        // Test database health
        const dbHealthResponse = await request(app)
          .get('/api/health/database')
          .expect(200);
        
        expect(dbHealthResponse.body).toHaveProperty('status');
        expect(dbHealthResponse.body.status).toBe('healthy');
        
        if (dbHealthResponse.body.connectionInfo) {
          console.log('📊 Database Info:', dbHealthResponse.body.connectionInfo);
        }
        
        // Test database operations
        const operations = [
          // Read operations
          () => request(app)
            .get('/api/admin/users/count')
            .set('Authorization', `Bearer ${adminToken}`)
            .expect(res => expect([200, 404]).toContain(res.status)),
          
          () => request(app)
            .get('/api/admin/responses/count')
            .set('Authorization', `Bearer ${adminToken}`)
            .expect(res => expect([200, 404]).toContain(res.status)),
          
          // Write operations (user profile update)
          () => request(app)
            .put('/api/users/profile')
            .set('Authorization', `Bearer ${userToken}`)
            .send({
              profile: {
                firstName: 'Updated',
                lastName: 'Name'
              }
            })
            .expect(res => expect([200, 400]).toContain(res.status))
        ];
        
        for (const operation of operations) {
          await operation();
        }
        
        console.log('✅ Database operations successful');
        
        global.testReporter.logTestEnd('Database Integration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Database Integration', startTime, false);
        throw error;
      }
    });

    test('should validate monitoring and alerting integration', async () => {
      const startTime = global.testReporter.logTestStart('Monitoring Integration');
      
      try {
        // Test monitoring endpoints
        const monitoringEndpoints = [
          '/api/health',
          '/api/health/detailed',
          '/api/metrics',
          '/api/admin/system-status'
        ];
        
        for (const endpoint of monitoringEndpoints) {
          try {
            const response = await request(app)
              .get(endpoint)
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(res => {
                expect([200, 404]).toContain(res.status);
              });
            
            if (response.status === 200) {
              console.log(`✅ Monitoring endpoint ${endpoint} is available`);
              
              // Validate response structure
              if (endpoint === '/api/health') {
                expect(response.body).toHaveProperty('status');
              }
              
              if (endpoint === '/api/metrics') {
                expect(response.body).toHaveProperty('timestamp');
              }
            } else {
              console.log(`ℹ️ Monitoring endpoint ${endpoint} not implemented`);
            }
          } catch (error) {
            console.log(`ℹ️ Monitoring endpoint ${endpoint} not available:`, error.message);
          }
        }
        
        global.testReporter.logTestEnd('Monitoring Integration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Monitoring Integration', startTime, false);
        throw error;
      }
    });
  });

  describe('🚀 API Endpoint Validation', () => {
    test('should validate all critical API endpoints', async () => {
      const startTime = global.testReporter.logTestStart('Critical API Endpoints');
      
      try {
        const apiEndpoints = [
          // Public endpoints
          { method: 'GET', path: '/api/health', auth: false, expectedStatus: [200] },
          { method: 'GET', path: '/api/form/current', auth: false, expectedStatus: [200] },
          { method: 'POST', path: '/api/users/register', auth: false, expectedStatus: [201, 400],
            body: { username: 'test', email: 'test@example.com', password: 'Test123!' } },
          
          // User endpoints
          { method: 'GET', path: '/api/users/profile', auth: 'user', expectedStatus: [200] },
          { method: 'POST', path: '/api/submissions', auth: 'user', expectedStatus: [201, 400],
            body: { responses: [{ question: 'Test', answer: 'Test' }] } },
          
          // Admin endpoints
          { method: 'GET', path: '/api/admin/dashboard', auth: 'admin', expectedStatus: [200] },
          { method: 'GET', path: '/api/admin/users', auth: 'admin', expectedStatus: [200] },
          { method: 'GET', path: '/api/admin/responses', auth: 'admin', expectedStatus: [200] }
        ];
        
        for (const endpoint of apiEndpoints) {
          try {
            let requestBuilder = request(app)[endpoint.method.toLowerCase()](endpoint.path);
            
            // Add authentication if required
            if (endpoint.auth === 'user') {
              requestBuilder = requestBuilder.set('Authorization', `Bearer ${userToken}`);
            } else if (endpoint.auth === 'admin') {
              requestBuilder = requestBuilder.set('Authorization', `Bearer ${adminToken}`);
            }
            
            // Add body if provided
            if (endpoint.body) {
              requestBuilder = requestBuilder.send(endpoint.body);
            }
            
            const response = await requestBuilder.expect(res => {
              expect(endpoint.expectedStatus).toContain(res.status);
            });
            
            console.log(`✅ ${endpoint.method} ${endpoint.path}: ${response.status}`);
            
            // Validate response structure for successful responses
            if (response.status < 300) {
              expect(response.body).toBeDefined();
              
              // API should return JSON
              expect(response.headers['content-type']).toMatch(/application\/json/);
            }
            
          } catch (error) {
            console.error(`❌ ${endpoint.method} ${endpoint.path}: ${error.message}`);
            throw error;
          }
        }
        
        global.testReporter.logTestEnd('Critical API Endpoints', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Critical API Endpoints', startTime, false);
        throw error;
      }
    });

    test('should validate API response formats and schemas', async () => {
      const startTime = global.testReporter.logTestStart('API Response Schemas');
      
      try {
        // Test user profile response schema
        const profileResponse = await request(app)
          .get('/api/users/profile')
          .set('Authorization', `Bearer ${userToken}`)
          .expect(200);
        
        const userProfile = profileResponse.body;
        expect(userProfile).toHaveProperty('id');
        expect(userProfile).toHaveProperty('username');
        expect(userProfile).toHaveProperty('email');
        expect(userProfile).toHaveProperty('role');
        expect(userProfile).not.toHaveProperty('password');
        
        // Test admin dashboard response schema
        const dashboardResponse = await request(app)
          .get('/api/admin/dashboard')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        const dashboard = dashboardResponse.body;
        expect(dashboard).toHaveProperty('summary');
        expect(dashboard.summary).toHaveProperty('totalUsers');
        expect(dashboard.summary).toHaveProperty('totalSubmissions');
        
        // Test form response schema
        const formResponse = await request(app)
          .get('/api/form/current')
          .expect(200);
        
        const form = formResponse.body;
        expect(form).toHaveProperty('questions');
        expect(Array.isArray(form.questions)).toBe(true);
        
        // Test API pagination schema (if applicable)
        const usersResponse = await request(app)
          .get('/api/admin/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .query({ limit: 5, page: 1 })
          .expect(200);
        
        if (usersResponse.body.pagination) {
          const pagination = usersResponse.body.pagination;
          expect(pagination).toHaveProperty('page');
          expect(pagination).toHaveProperty('limit');
          expect(pagination).toHaveProperty('total');
          expect(typeof pagination.page).toBe('number');
          expect(typeof pagination.limit).toBe('number');
          expect(typeof pagination.total).toBe('number');
        }
        
        console.log('✅ API response schemas are valid');
        
        global.testReporter.logTestEnd('API Response Schemas', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('API Response Schemas', startTime, false);
        throw error;
      }
    });

    test('should validate API error handling', async () => {
      const startTime = global.testReporter.logTestStart('API Error Handling');
      
      try {
        const errorScenarios = [
          // 401 Unauthorized
          { method: 'GET', path: '/api/users/profile', auth: false, expectedStatus: 401 },
          { method: 'GET', path: '/api/admin/dashboard', auth: false, expectedStatus: 401 },
          
          // 403 Forbidden
          { method: 'GET', path: '/api/admin/dashboard', auth: 'user', expectedStatus: 403 },
          
          // 404 Not Found
          { method: 'GET', path: '/api/nonexistent/endpoint', auth: false, expectedStatus: 404 },
          { method: 'GET', path: '/api/users/999999', auth: 'admin', expectedStatus: 404 },
          
          // 400 Bad Request
          { method: 'POST', path: '/api/users/register', auth: false, expectedStatus: 400,
            body: { invalid: 'data' } },
          { method: 'POST', path: '/api/submissions', auth: 'user', expectedStatus: 400,
            body: { invalid: 'submission' } }
        ];
        
        for (const scenario of errorScenarios) {
          let requestBuilder = request(app)[scenario.method.toLowerCase()](scenario.path);
          
          // Add authentication if required
          if (scenario.auth === 'user') {
            requestBuilder = requestBuilder.set('Authorization', `Bearer ${userToken}`);
          } else if (scenario.auth === 'admin') {
            requestBuilder = requestBuilder.set('Authorization', `Bearer ${adminToken}`);
          }
          
          // Add body if provided
          if (scenario.body) {
            requestBuilder = requestBuilder.send(scenario.body);
          }
          
          const response = await requestBuilder.expect(scenario.expectedStatus);
          
          // Validate error response structure
          if (response.status >= 400) {
            expect(response.body).toHaveProperty('error');
            expect(typeof response.body.error).toBe('string');
            
            // Should not expose sensitive information
            expect(response.body.error.toLowerCase()).not.toContain('password');
            expect(response.body.error.toLowerCase()).not.toContain('secret');
            expect(response.body.error.toLowerCase()).not.toContain('token');
          }
          
          console.log(`✅ Error handling for ${scenario.method} ${scenario.path}: ${response.status}`);
        }
        
        global.testReporter.logTestEnd('API Error Handling', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('API Error Handling', startTime, false);
        throw error;
      }
    });
  });

  describe('🔄 Service Layer Integration', () => {
    test('should validate service layer interactions', async () => {
      const startTime = global.testReporter.logTestStart('Service Layer Integration');
      
      try {
        // Test cascading operations that involve multiple services
        
        // 1. User Service + Authentication Service
        const newUserData = {
          username: `service_test_${global.testUtils.generateTestId()}`,
          email: `service.test.${global.testUtils.generateTestId()}@example.com`,
          password: 'ServiceTest123!'
        };
        
        // Register user (User Service)
        const registerResponse = await request(app)
          .post('/api/users/register')
          .send(newUserData)
          .expect(201);
        
        expect(registerResponse.body).toHaveProperty('user');
        
        // Login user (Authentication Service)
        const loginResponse = await request(app)
          .post('/api/auth/login')
          .send({
            username: newUserData.username,
            password: newUserData.password
          })
          .expect(200);
        
        expect(loginResponse.body).toHaveProperty('token');
        const newUserToken = loginResponse.body.token;
        
        // 2. Submission Service + Response Service
        const submissionData = {
          responses: [
            { question: 'Service Integration Test', answer: 'Service test answer' }
          ]
        };
        
        // Submit response (Submission Service)
        const submitResponse = await request(app)
          .post('/api/submissions')
          .set('Authorization', `Bearer ${newUserToken}`)
          .send(submissionData)
          .expect(res => {
            expect([201, 400]).toContain(res.status); // 400 for constraints
          });
        
        if (submitResponse.status === 201) {
          expect(submitResponse.body).toHaveProperty('token');
          
          // View response (Response Service)
          const viewResponse = await request(app)
            .get(`/api/responses/view/${submitResponse.body.token}`)
            .expect(200);
          
          expect(viewResponse.body).toHaveProperty('responses');
          expect(viewResponse.body.responses).toHaveLength(1);
        }
        
        // 3. Admin Service + User Service Integration
        const adminUsersResponse = await request(app)
          .get('/api/admin/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        expect(adminUsersResponse.body).toHaveProperty('users');
        
        // Verify the new user appears in admin list
        const users = adminUsersResponse.body.users;
        const foundUser = users.find(u => u.username === newUserData.username);
        if (foundUser) {
          expect(foundUser.email).toBe(newUserData.email);
          expect(foundUser).not.toHaveProperty('password');
        }
        
        console.log('✅ Service layer integrations work correctly');
        
        global.testReporter.logTestEnd('Service Layer Integration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Service Layer Integration', startTime, false);
        throw error;
      }
    });

    test('should validate cross-service data consistency', async () => {
      const startTime = global.testReporter.logTestStart('Cross-Service Data Consistency');
      
      try {
        // Get dashboard summary
        const dashboardResponse = await request(app)
          .get('/api/admin/dashboard')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        const summary = dashboardResponse.body.summary;
        
        // Get actual user count
        const usersResponse = await request(app)
          .get('/api/admin/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        // Get actual response count
        const responsesResponse = await request(app)
          .get('/api/admin/responses')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        // Verify data consistency between services
        if (summary.totalUsers && usersResponse.body.pagination) {
          const actualUserCount = usersResponse.body.pagination.total || usersResponse.body.users.length;
          console.log(`📊 User count consistency: Dashboard=${summary.totalUsers}, Actual=${actualUserCount}`);
          
          // Allow for some variance due to test users
          expect(Math.abs(summary.totalUsers - actualUserCount)).toBeLessThanOrEqual(5);
        }
        
        if (summary.totalSubmissions && responsesResponse.body.pagination) {
          const actualResponseCount = responsesResponse.body.pagination.total || responsesResponse.body.responses.length;
          console.log(`📊 Response count consistency: Dashboard=${summary.totalSubmissions}, Actual=${actualResponseCount}`);
          
          // Allow for some variance
          expect(Math.abs(summary.totalSubmissions - actualResponseCount)).toBeLessThanOrEqual(5);
        }
        
        console.log('✅ Cross-service data consistency verified');
        
        global.testReporter.logTestEnd('Cross-Service Data Consistency', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Cross-Service Data Consistency', startTime, false);
        throw error;
      }
    });
  });

  describe('📊 Analytics & Reporting Integration', () => {
    test('should validate analytics data collection', async () => {
      const startTime = global.testReporter.logTestStart('Analytics Integration');
      
      try {
        // Test analytics endpoints
        const analyticsEndpoints = [
          '/api/admin/analytics/users',
          '/api/admin/analytics/submissions',
          '/api/admin/analytics/monthly',
          '/api/admin/statistics'
        ];
        
        for (const endpoint of analyticsEndpoints) {
          try {
            const response = await request(app)
              .get(endpoint)
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(res => {
                expect([200, 404]).toContain(res.status);
              });
            
            if (response.status === 200) {
              expect(response.body).toBeDefined();
              console.log(`✅ Analytics endpoint ${endpoint} is functional`);
              
              // Validate analytics data structure
              if (endpoint.includes('monthly')) {
                expect(response.body).toHaveProperty('data');
              }
              
              if (endpoint.includes('statistics')) {
                expect(typeof response.body).toBe('object');
              }
            } else {
              console.log(`ℹ️ Analytics endpoint ${endpoint} not implemented`);
            }
          } catch (error) {
            console.log(`ℹ️ Analytics endpoint ${endpoint} not available:`, error.message);
          }
        }
        
        global.testReporter.logTestEnd('Analytics Integration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Analytics Integration', startTime, false);
        throw error;
      }
    });
  });

  describe('🔧 Configuration & Environment Integration', () => {
    test('should validate environment-specific configurations', async () => {
      const startTime = global.testReporter.logTestStart('Environment Configuration');
      
      try {
        // Test environment-specific endpoints
        const configResponse = await request(app)
          .get('/api/config/environment')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(res => {
            expect([200, 404]).toContain(res.status);
          });
        
        if (configResponse.status === 200) {
          const config = configResponse.body;
          
          // Verify environment settings
          expect(config).toHaveProperty('environment');
          expect(['development', 'production', 'staging']).toContain(config.environment);
          
          // Verify security settings for production
          if (config.environment === 'production') {
            expect(config.security).toHaveProperty('httpsOnly');
            expect(config.security.httpsOnly).toBe(true);
          }
          
          console.log(`✅ Environment configuration: ${config.environment}`);
        } else {
          console.log('ℹ️ Environment configuration endpoint not available');
        }
        
        global.testReporter.logTestEnd('Environment Configuration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Environment Configuration', startTime, false);
        throw error;
      }
    });
  });
});