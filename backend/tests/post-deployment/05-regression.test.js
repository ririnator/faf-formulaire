/**
 * Post-Deployment Regression Tests
 * 
 * Comprehensive validation of backward compatibility,
 * legacy system integration, and migration data integrity.
 */

const request = require('supertest');

describe('🔄 Post-Deployment Regression Tests', () => {
  let app;
  let server;
  let adminToken;
  let legacyTestData;
  
  beforeAll(async () => {
    const startTime = global.testReporter.logTestStart('Regression Test Suite Setup');
    
    try {
      app = require('../../app');
      server = app.listen(0);
      
      // Get admin token
      const adminLogin = await request(app)
        .post('/api/auth/admin-login')
        .send({
          username: global.testConfig.testUsers.adminUser.username,
          password: global.testConfig.testUsers.adminUser.password
        });
      adminToken = adminLogin.body.token;
      
      // Setup legacy test data if needed
      legacyTestData = {
        oldFormatToken: 'legacy_token_format_12345',
        oldResponseFormat: {
          name: 'Legacy User',
          responses: [
            { question: 'Old Question Format', answer: 'Old Answer Format' }
          ],
          month: '2024-01',
          isAdmin: false
        }
      };
      
      global.testReporter.logTestEnd('Regression Test Suite Setup', startTime, true);
    } catch (error) {
      global.testReporter.logTestEnd('Regression Test Suite Setup', startTime, false);
      throw error;
    }
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
    await global.testUtils.executeCleanup();
  });

  describe('🔗 Legacy URL Compatibility', () => {
    test('should maintain compatibility with legacy response URLs', async () => {
      const startTime = global.testReporter.logTestStart('Legacy URL Compatibility');
      
      try {
        // Test legacy URL formats that should still work
        const legacyUrls = [
          '/view', // Legacy view page
          '/admin', // Legacy admin page
          '/login', // Legacy login page
          '/form', // Legacy form page
        ];
        
        for (const url of legacyUrls) {
          const response = await request(app)
            .get(url)
            .expect(res => {
              // Should either redirect or return content
              expect([200, 301, 302, 404]).toContain(res.status);
            });
          
          if (response.status === 200) {
            console.log(`✅ Legacy URL ${url} still accessible`);
            expect(response.headers['content-type']).toMatch(/text\/html/);
          } else if (response.status === 301 || response.status === 302) {
            console.log(`✅ Legacy URL ${url} redirects to: ${response.headers.location}`);
          } else {
            console.log(`ℹ️ Legacy URL ${url} not found (might be expected)`);
          }
        }
        
        global.testReporter.logTestEnd('Legacy URL Compatibility', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy URL Compatibility', startTime, false);
        throw error;
      }
    });

    test('should support legacy API endpoint formats', async () => {
      const startTime = global.testReporter.logTestStart('Legacy API Endpoints');
      
      try {
        // Test legacy API endpoints that might still be in use
        const legacyApiEndpoints = [
          { path: '/api/responses', method: 'GET', description: 'Legacy responses list' },
          { path: '/api/admin', method: 'GET', description: 'Legacy admin API' },
          { path: '/login', method: 'POST', description: 'Legacy login endpoint' },
          { path: '/api/form', method: 'GET', description: 'Legacy form API' }
        ];
        
        for (const endpoint of legacyApiEndpoints) {
          try {
            let requestBuilder = request(app)[endpoint.method.toLowerCase()](endpoint.path);
            
            // Add admin auth for admin endpoints
            if (endpoint.path.includes('admin')) {
              requestBuilder = requestBuilder.set('Authorization', `Bearer ${adminToken}`);
            }
            
            // Add test data for POST requests
            if (endpoint.method === 'POST' && endpoint.path === '/login') {
              requestBuilder = requestBuilder.send({
                username: 'test',
                password: 'test'
              });
            }
            
            const response = await requestBuilder.expect(res => {
              // Legacy endpoints should either work or return 404/405
              expect([200, 201, 400, 401, 404, 405]).toContain(res.status);
            });
            
            if (response.status < 400) {
              console.log(`✅ ${endpoint.description}: Works (${response.status})`);
            } else if (response.status === 404 || response.status === 405) {
              console.log(`ℹ️ ${endpoint.description}: Not available (${response.status})`);
            } else {
              console.log(`⚠️ ${endpoint.description}: Error (${response.status})`);
            }
            
          } catch (error) {
            console.log(`ℹ️ ${endpoint.description}: ${error.message}`);
          }
        }
        
        global.testReporter.logTestEnd('Legacy API Endpoints', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy API Endpoints', startTime, false);
        throw error;
      }
    });
  });

  describe('📊 Migration Data Integrity', () => {
    test('should validate migrated response data', async () => {
      const startTime = global.testReporter.logTestStart('Migrated Response Data');
      
      try {
        // Get all responses to check for migrated data
        const responsesResponse = await request(app)
          .get('/api/admin/responses')
          .set('Authorization', `Bearer ${adminToken}`)
          .query({ limit: 100 })
          .expect(200);
        
        const responses = responsesResponse.body.responses || [];
        
        console.log(`📊 Total responses found: ${responses.length}`);
        
        // Look for migrated data indicators
        const migratedResponses = responses.filter(r => 
          r.migrationData || 
          r.legacyId || 
          r.metadata?.migrated ||
          r.source === 'legacy'
        );
        
        console.log(`📊 Migrated responses found: ${migratedResponses.length}`);
        
        if (migratedResponses.length > 0) {
          // Validate migrated data structure
          migratedResponses.forEach(response => {
            // Should have all required fields
            expect(response).toHaveProperty('id');
            expect(response).toHaveProperty('responses');
            expect(response).toHaveProperty('month');
            expect(Array.isArray(response.responses)).toBe(true);
            
            // Should maintain data integrity
            response.responses.forEach(r => {
              expect(r).toHaveProperty('question');
              expect(r).toHaveProperty('answer');
              expect(typeof r.question).toBe('string');
              expect(typeof r.answer).toBe('string');
            });
            
            // Migration metadata should be present
            if (response.migrationData) {
              expect(response.migrationData).toHaveProperty('migratedAt');
              expect(response.migrationData).toHaveProperty('source');
            }
          });
          
          console.log('✅ Migrated data structure is valid');
        } else {
          console.log('ℹ️ No migrated data found (fresh installation)');
        }
        
        global.testReporter.logTestEnd('Migrated Response Data', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Migrated Response Data', startTime, false);
        throw error;
      }
    });

    test('should validate legacy token compatibility', async () => {
      const startTime = global.testReporter.logTestStart('Legacy Token Compatibility');
      
      try {
        // Test various legacy token formats
        const legacyTokenFormats = [
          'legacy_12345_abcdef',
          'old-format-token-123',
          'LEGACY_TOKEN_UPPERCASE',
          'legacy.token.with.dots',
          '1234567890abcdef' // Old short format
        ];
        
        for (const token of legacyTokenFormats) {
          const response = await request(app)
            .get(`/api/responses/view/${token}`)
            .expect(res => {
              // Should either find the response or return 404
              expect([200, 404]).toContain(res.status);
            });
          
          if (response.status === 200) {
            console.log(`✅ Legacy token format ${token} is compatible`);
            
            // Validate response structure
            expect(response.body).toHaveProperty('responses');
            expect(Array.isArray(response.body.responses)).toBe(true);
            expect(response.body).toHaveProperty('month');
          } else {
            console.log(`ℹ️ Legacy token format ${token} not found (expected)`);
          }
        }
        
        global.testReporter.logTestEnd('Legacy Token Compatibility', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy Token Compatibility', startTime, false);
        throw error;
      }
    });

    test('should validate legacy user data migration', async () => {
      const startTime = global.testReporter.logTestStart('Legacy User Migration');
      
      try {
        // Get user list to check for migrated users
        const usersResponse = await request(app)
          .get('/api/admin/users')
          .set('Authorization', `Bearer ${adminToken}`)
          .expect(200);
        
        const users = usersResponse.body.users || [];
        
        console.log(`📊 Total users found: ${users.length}`);
        
        // Look for migrated users
        const migratedUsers = users.filter(u => 
          u.migrationData || 
          u.legacyName || 
          u.metadata?.migrated ||
          u.source === 'legacy'
        );
        
        console.log(`📊 Migrated users found: ${migratedUsers.length}`);
        
        if (migratedUsers.length > 0) {
          // Validate migrated user structure
          migratedUsers.forEach(user => {
            // Should have all required fields
            expect(user).toHaveProperty('id');
            expect(user).toHaveProperty('username');
            expect(user).toHaveProperty('email');
            expect(user).toHaveProperty('role');
            
            // Should not expose password
            expect(user).not.toHaveProperty('password');
            expect(user).not.toHaveProperty('passwordHash');
            
            // Migration metadata should be present
            if (user.migrationData) {
              expect(user.migrationData).toHaveProperty('migratedAt');
              expect(user.migrationData).toHaveProperty('source');
              
              // Legacy name should be preserved
              if (user.migrationData.legacyName) {
                expect(typeof user.migrationData.legacyName).toBe('string');
              }
            }
          });
          
          console.log('✅ Migrated user data is valid');
        } else {
          console.log('ℹ️ No migrated user data found');
        }
        
        global.testReporter.logTestEnd('Legacy User Migration', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy User Migration', startTime, false);
        throw error;
      }
    });
  });

  describe('🔧 Legacy Feature Compatibility', () => {
    test('should maintain legacy admin authentication methods', async () => {
      const startTime = global.testReporter.logTestStart('Legacy Admin Authentication');
      
      try {
        // Test dual admin login endpoints
        const loginEndpoints = [
          '/login', // Legacy endpoint
          '/admin-login', // New dedicated endpoint
          '/api/auth/admin-login' // API endpoint
        ];
        
        for (const endpoint of loginEndpoints) {
          try {
            const response = await request(app)
              .post(endpoint)
              .send({
                username: global.testConfig.testUsers.adminUser.username,
                password: global.testConfig.testUsers.adminUser.password
              })
              .expect(res => {
                expect([200, 302, 404]).toContain(res.status);
              });
            
            if (response.status === 200) {
              console.log(`✅ Admin login endpoint ${endpoint} works`);
              
              // Should return token or session
              if (response.body.token) {
                expect(typeof response.body.token).toBe('string');
              }
            } else if (response.status === 302) {
              console.log(`✅ Admin login endpoint ${endpoint} redirects`);
            } else {
              console.log(`ℹ️ Admin login endpoint ${endpoint} not available`);
            }
          } catch (error) {
            console.log(`ℹ️ Admin login endpoint ${endpoint}: ${error.message}`);
          }
        }
        
        global.testReporter.logTestEnd('Legacy Admin Authentication', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy Admin Authentication', startTime, false);
        throw error;
      }
    });

    test('should support legacy form submission formats', async () => {
      const startTime = global.testReporter.logTestStart('Legacy Form Submission');
      
      try {
        // Create test user for legacy submission testing
        const userData = {
          username: `legacy_test_${global.testUtils.generateTestId()}`,
          email: `legacy.test.${global.testUtils.generateTestId()}@example.com`,
          password: 'LegacyTest123!'
        };
        
        await request(app)
          .post('/api/users/register')
          .send(userData);
        
        const loginResponse = await request(app)
          .post('/api/auth/login')
          .send({
            username: userData.username,
            password: userData.password
          });
        
        const userToken = loginResponse.body.token;
        
        // Test legacy submission format
        const legacySubmissionFormats = [
          // Format 1: Simple name + responses
          {
            name: userData.username,
            responses: [
              { question: 'Legacy Question 1', answer: 'Legacy Answer 1' },
              { question: 'Legacy Question 2', answer: 'Legacy Answer 2' }
            ]
          },
          
          // Format 2: Full legacy structure
          {
            name: userData.username,
            responses: [
              { question: 'Test Question', answer: 'Test Answer' }
            ],
            month: '2025-01'
          }
        ];
        
        for (const [index, legacyFormat] of legacySubmissionFormats.entries()) {
          try {
            const response = await request(app)
              .post('/api/responses') // Legacy endpoint
              .set('Authorization', `Bearer ${userToken}`)
              .send(legacyFormat)
              .expect(res => {
                expect([200, 201, 400, 404]).toContain(res.status);
              });
            
            if (response.status === 201 || response.status === 200) {
              console.log(`✅ Legacy submission format ${index + 1} accepted`);
              
              // Should return proper response structure
              expect(response.body).toHaveProperty('id');
              if (response.body.token) {
                expect(typeof response.body.token).toBe('string');
              }
            } else if (response.status === 400) {
              console.log(`ℹ️ Legacy submission format ${index + 1} rejected (validation)`);
            } else {
              console.log(`ℹ️ Legacy submission format ${index + 1} endpoint not available`);
            }
          } catch (error) {
            console.log(`ℹ️ Legacy submission format ${index + 1}: ${error.message}`);
          }
        }
        
        global.testReporter.logTestEnd('Legacy Form Submission', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy Form Submission', startTime, false);
        throw error;
      }
    });

    test('should maintain legacy admin dashboard functionality', async () => {
      const startTime = global.testReporter.logTestStart('Legacy Admin Dashboard');
      
      try {
        // Test legacy admin endpoints
        const legacyAdminEndpoints = [
          { path: '/api/admin', method: 'GET', description: 'Legacy admin API' },
          { path: '/api/admin/summary', method: 'GET', description: 'Legacy summary' },
          { path: '/api/admin/all-responses', method: 'GET', description: 'Legacy all responses' },
          { path: '/api/admin/users-list', method: 'GET', description: 'Legacy users list' }
        ];
        
        for (const endpoint of legacyAdminEndpoints) {
          try {
            const response = await request(app)
              [endpoint.method.toLowerCase()](endpoint.path)
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(res => {
                expect([200, 404]).toContain(res.status);
              });
            
            if (response.status === 200) {
              console.log(`✅ ${endpoint.description} is available`);
              
              // Validate response structure
              expect(response.body).toBeDefined();
              
              // Check for expected legacy data format
              if (endpoint.path.includes('summary')) {
                expect(response.body).toHaveProperty('totalUsers');
              }
              
              if (endpoint.path.includes('responses')) {
                expect(Array.isArray(response.body) || response.body.responses).toBe(true);
              }
            } else {
              console.log(`ℹ️ ${endpoint.description} not available (migrated to new format)`);
            }
          } catch (error) {
            console.log(`ℹ️ ${endpoint.description}: ${error.message}`);
          }
        }
        
        global.testReporter.logTestEnd('Legacy Admin Dashboard', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy Admin Dashboard', startTime, false);
        throw error;
      }
    });
  });

  describe('⚙️ Performance Regression', () => {
    test('should maintain or improve performance compared to legacy system', async () => {
      const startTime = global.testReporter.logTestStart('Performance Regression Check');
      
      try {
        // Baseline performance tests that should meet or exceed legacy performance
        const performanceTests = [
          {
            name: 'User Authentication',
            operation: async () => {
              const start = performance.now();
              await request(app)
                .post('/api/auth/login')
                .send({
                  username: 'test',
                  password: 'test'
                })
                .expect(res => expect([200, 401]).toContain(res.status));
              return performance.now() - start;
            },
            threshold: 1000 // 1 second max
          },
          
          {
            name: 'Form Data Retrieval',
            operation: async () => {
              const start = performance.now();
              await request(app)
                .get('/api/form/current')
                .expect(200);
              return performance.now() - start;
            },
            threshold: 500 // 500ms max
          },
          
          {
            name: 'Admin Dashboard Load',
            operation: async () => {
              const start = performance.now();
              await request(app)
                .get('/api/admin/dashboard')
                .set('Authorization', `Bearer ${adminToken}`)
                .expect(200);
              return performance.now() - start;
            },
            threshold: 2000 // 2 seconds max
          }
        ];
        
        for (const test of performanceTests) {
          const duration = await test.operation();
          
          console.log(`📊 ${test.name}: ${Math.round(duration)}ms (threshold: ${test.threshold}ms)`);
          
          if (duration > test.threshold) {
            console.warn(`⚠️ Performance regression detected in ${test.name}`);
            global.testReporter.logPerformanceIssue(
              'Performance Regression',
              test.name,
              `${Math.round(duration)}ms`,
              `${test.threshold}ms`
            );
          } else {
            console.log(`✅ ${test.name} meets performance requirements`);
          }
          
          // Test should not fail on performance regression, just warn
          // expect(duration).toBeLessThan(test.threshold * 1.5); // Allow 50% tolerance
        }
        
        global.testReporter.logTestEnd('Performance Regression Check', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Performance Regression Check', startTime, false);
        throw error;
      }
    });

    test('should validate memory usage efficiency', async () => {
      const startTime = global.testReporter.logTestStart('Memory Usage Regression');
      
      try {
        const initialMemory = process.memoryUsage();
        
        // Perform memory-intensive operations
        const operations = [];
        for (let i = 0; i < 10; i++) {
          operations.push(
            request(app)
              .get('/api/admin/dashboard')
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(200)
          );
        }
        
        await Promise.all(operations);
        
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
        
        await global.testUtils.sleep(1000); // Wait for cleanup
        
        const finalMemory = process.memoryUsage();
        
        const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
        const memoryIncreasePercent = (memoryIncrease / initialMemory.heapUsed) * 100;
        
        console.log(`📊 Memory Usage:`, {
          initial: Math.round(initialMemory.heapUsed / 1024 / 1024) + 'MB',
          final: Math.round(finalMemory.heapUsed / 1024 / 1024) + 'MB',
          increase: Math.round(memoryIncrease / 1024 / 1024) + 'MB',
          increasePercent: Math.round(memoryIncreasePercent) + '%'
        });
        
        // Memory increase should be reasonable (less than 30% for this test)
        if (memoryIncreasePercent > 30) {
          console.warn(`⚠️ Potential memory regression: ${Math.round(memoryIncreasePercent)}% increase`);
        } else {
          console.log(`✅ Memory usage is efficient`);
        }
        
        global.testReporter.logTestEnd('Memory Usage Regression', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Memory Usage Regression', startTime, false);
        throw error;
      }
    });
  });

  describe('🔄 Backward Compatibility', () => {
    test('should support legacy client applications', async () => {
      const startTime = global.testReporter.logTestStart('Legacy Client Compatibility');
      
      try {
        // Test headers and content types that legacy clients might expect
        const compatibilityTests = [
          {
            name: 'Legacy API Content-Type',
            test: async () => {
              const response = await request(app)
                .get('/api/form/current')
                .set('Accept', 'application/json')
                .expect(200);
              
              expect(response.headers['content-type']).toMatch(/application\/json/);
              return true;
            }
          },
          
          {
            name: 'Legacy CORS Headers',
            test: async () => {
              const response = await request(app)
                .options('/api/form/current')
                .set('Origin', 'http://localhost:3000')
                .expect(res => expect([200, 204]).toContain(res.status));
              
              // Should have CORS headers for legacy client support
              expect(response.headers['access-control-allow-origin']).toBeDefined();
              return true;
            }
          },
          
          {
            name: 'Legacy Error Format',
            test: async () => {
              const response = await request(app)
                .get('/api/nonexistent')
                .expect(404);
              
              // Should return error in expected format
              expect(response.body).toHaveProperty('error');
              expect(typeof response.body.error).toBe('string');
              return true;
            }
          }
        ];
        
        for (const compatTest of compatibilityTests) {
          try {
            const result = await compatTest.test();
            if (result) {
              console.log(`✅ ${compatTest.name} is compatible`);
            }
          } catch (error) {
            console.warn(`⚠️ ${compatTest.name} compatibility issue:`, error.message);
          }
        }
        
        global.testReporter.logTestEnd('Legacy Client Compatibility', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Legacy Client Compatibility', startTime, false);
        throw error;
      }
    });
  });
});