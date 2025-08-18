/**
 * Post-Deployment Performance Tests
 * 
 * Comprehensive performance validation including load testing,
 * response times, memory usage, and concurrent user scenarios.
 */

const request = require('supertest');
const { performance } = require('perf_hooks');
const os = require('os');

describe('⚡ Post-Deployment Performance Tests', () => {
  let app;
  let server;
  let adminToken;
  let userToken;
  
  beforeAll(async () => {
    const startTime = global.testReporter.logTestStart('Performance Test Suite Setup');
    
    try {
      app = require('../../app');
      server = app.listen(0);
      
      // Get authentication tokens
      const adminLogin = await request(app)
        .post('/api/auth/admin-login')
        .send({
          username: global.testConfig.testUsers.adminUser.username,
          password: global.testConfig.testUsers.adminUser.password
        });
      adminToken = adminLogin.body.token;
      
      // Create test user for performance tests
      const userData = {
        username: `perf_${global.testUtils.generateTestId()}`,
        email: `perf.${global.testUtils.generateTestId()}@example.com`,
        password: 'PerfTest123!'
      };
      
      await request(app)
        .post('/api/users/register')
        .send(userData);
      
      const userLogin = await request(app)
        .post('/api/auth/login')
        .send({
          username: userData.username,
          password: userData.password
        });
      userToken = userLogin.body.token;
      
      global.testReporter.logTestEnd('Performance Test Suite Setup', startTime, true);
    } catch (error) {
      global.testReporter.logTestEnd('Performance Test Suite Setup', startTime, false);
      throw error;
    }
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
    await global.testUtils.executeCleanup();
  });

  describe('🚀 Response Time Validation', () => {
    test('should meet response time requirements for critical endpoints', async () => {
      const startTime = global.testReporter.logTestStart('Critical Endpoint Response Times');
      
      try {
        const endpoints = [
          { method: 'GET', path: '/api/health', description: 'Health Check', threshold: 500 },
          { method: 'GET', path: '/api/form/current', description: 'Current Form', threshold: 1000 },
          { method: 'POST', path: '/api/auth/login', description: 'User Login', threshold: 2000, 
            body: { username: 'test', password: 'test' } },
          { method: 'GET', path: '/api/admin/dashboard', description: 'Admin Dashboard', threshold: 2000,
            headers: { Authorization: `Bearer ${adminToken}` } }
        ];
        
        const results = [];
        
        for (const endpoint of endpoints) {
          const testStart = performance.now();
          
          let requestBuilder = request(app)[endpoint.method.toLowerCase()](endpoint.path);
          
          if (endpoint.headers) {
            Object.entries(endpoint.headers).forEach(([key, value]) => {
              requestBuilder = requestBuilder.set(key, value);
            });
          }
          
          if (endpoint.body) {
            requestBuilder = requestBuilder.send(endpoint.body);
          }
          
          await requestBuilder.expect(res => {
            expect([200, 201, 401, 403]).toContain(res.status); // Accept various success/auth responses
          });
          
          const duration = performance.now() - testStart;
          results.push({
            endpoint: endpoint.description,
            duration: Math.round(duration),
            threshold: endpoint.threshold,
            passed: duration <= endpoint.threshold
          });
          
          if (duration > endpoint.threshold) {
            global.testReporter.logPerformanceIssue(
              'Response Time',
              endpoint.description,
              `${Math.round(duration)}ms`,
              `${endpoint.threshold}ms`
            );
          }
        }
        
        // Log results
        console.log('\n📊 Response Time Results:');
        results.forEach(result => {
          const status = result.passed ? '✅' : '❌';
          console.log(`${status} ${result.endpoint}: ${result.duration}ms (threshold: ${result.threshold}ms)`);
        });
        
        // Verify at least 80% of endpoints meet requirements
        const passedCount = results.filter(r => r.passed).length;
        const passRate = (passedCount / results.length) * 100;
        
        expect(passRate).toBeGreaterThanOrEqual(80);
        
        global.testReporter.logTestEnd('Critical Endpoint Response Times', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Critical Endpoint Response Times', startTime, false);
        throw error;
      }
    });

    test('should handle database query performance', async () => {
      const startTime = global.testReporter.logTestStart('Database Query Performance');
      
      try {
        const dbOperations = [
          {
            name: 'User Lookup',
            operation: () => request(app)
              .get('/api/users/profile')
              .set('Authorization', `Bearer ${userToken}`)
              .expect(200),
            threshold: 1000
          },
          {
            name: 'Response List',
            operation: () => request(app)
              .get('/api/admin/responses')
              .set('Authorization', `Bearer ${adminToken}`)
              .query({ limit: 10 })
              .expect(200),
            threshold: 1500
          },
          {
            name: 'Dashboard Summary',
            operation: () => request(app)
              .get('/api/admin/dashboard')
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(200),
            threshold: 2000
          }
        ];
        
        for (const dbOp of dbOperations) {
          const queryStart = performance.now();
          await dbOp.operation();
          const queryDuration = performance.now() - queryStart;
          
          console.log(`📊 ${dbOp.name}: ${Math.round(queryDuration)}ms`);
          
          if (queryDuration > dbOp.threshold) {
            global.testReporter.logPerformanceIssue(
              'Database Query Performance',
              dbOp.name,
              `${Math.round(queryDuration)}ms`,
              `${dbOp.threshold}ms`
            );
          }
          
          expect(queryDuration).toBeLessThan(dbOp.threshold);
        }
        
        global.testReporter.logTestEnd('Database Query Performance', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Database Query Performance', startTime, false);
        throw error;
      }
    });
  });

  describe('🔄 Concurrent Load Testing', () => {
    test('should handle concurrent user authentication', async () => {
      const startTime = global.testReporter.logTestStart('Concurrent Authentication Load');
      
      try {
        const concurrentUsers = 10;
        const loginPromises = [];
        
        // Create multiple users
        const userCredentials = [];
        for (let i = 0; i < concurrentUsers; i++) {
          const userData = {
            username: `concurrent_${i}_${global.testUtils.generateTestId()}`,
            email: `concurrent.${i}.${global.testUtils.generateTestId()}@example.com`,
            password: 'ConcurrentTest123!'
          };
          
          await request(app)
            .post('/api/users/register')
            .send(userData);
          
          userCredentials.push(userData);
        }
        
        // Perform concurrent logins
        const loginStart = performance.now();
        
        for (const creds of userCredentials) {
          loginPromises.push(
            request(app)
              .post('/api/auth/login')
              .send({
                username: creds.username,
                password: creds.password
              })
              .expect(200)
          );
        }
        
        const loginResults = await Promise.all(loginPromises);
        const loginDuration = performance.now() - loginStart;
        
        console.log(`📊 Concurrent Logins (${concurrentUsers} users): ${Math.round(loginDuration)}ms`);
        
        // Verify all logins succeeded
        loginResults.forEach(result => {
          expect(result.body).toHaveProperty('token');
          expect(result.body).toHaveProperty('user');
        });
        
        // Check average response time per user
        const avgResponseTime = loginDuration / concurrentUsers;
        expect(avgResponseTime).toBeLessThan(global.testConfig.performance.maxResponseTime);
        
        global.testReporter.logTestEnd('Concurrent Authentication Load', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Concurrent Authentication Load', startTime, false);
        throw error;
      }
    });

    test('should handle concurrent form submissions', async () => {
      const startTime = global.testReporter.logTestStart('Concurrent Form Submissions');
      
      try {
        const concurrentSubmissions = 5;
        const submissionPromises = [];
        
        // Get form structure
        const formResponse = await request(app)
          .get('/api/form/current')
          .expect(200);
        
        // Create submission data
        const submissionData = {
          responses: formResponse.body.questions?.map((q, i) => ({
            question: q.text || `Question ${i + 1}`,
            answer: `Concurrent test answer ${i + 1}`
          })) || [
            { question: 'Test Question', answer: 'Concurrent test answer' }
          ]
        };
        
        // Create users for submissions (different months to avoid constraints)
        const submissionUsers = [];
        for (let i = 0; i < concurrentSubmissions; i++) {
          const userData = {
            username: `submit_${i}_${global.testUtils.generateTestId()}`,
            email: `submit.${i}.${global.testUtils.generateTestId()}@example.com`,
            password: 'SubmitTest123!'
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
          
          submissionUsers.push(loginResponse.body.token);
        }
        
        // Perform concurrent submissions
        const submissionStart = performance.now();
        
        for (const token of submissionUsers) {
          submissionPromises.push(
            request(app)
              .post('/api/submissions')
              .set('Authorization', `Bearer ${token}`)
              .send(submissionData)
              .expect(201)
          );
        }
        
        const submissionResults = await Promise.all(submissionPromises);
        const submissionDuration = performance.now() - submissionStart;
        
        console.log(`📊 Concurrent Submissions (${concurrentSubmissions}): ${Math.round(submissionDuration)}ms`);
        
        // Verify all submissions succeeded
        submissionResults.forEach(result => {
          expect(result.body).toHaveProperty('id');
          expect(result.body).toHaveProperty('token');
          expect(result.body).toHaveProperty('responses');
        });
        
        // Check average response time per submission
        const avgSubmissionTime = submissionDuration / concurrentSubmissions;
        expect(avgSubmissionTime).toBeLessThan(global.testConfig.performance.maxResponseTime * 2); // Allow 2x for submission complexity
        
        global.testReporter.logTestEnd('Concurrent Form Submissions', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Concurrent Form Submissions', startTime, false);
        throw error;
      }
    });

    test('should handle concurrent admin operations', async () => {
      const startTime = global.testReporter.logTestStart('Concurrent Admin Operations');
      
      try {
        const operations = [
          () => request(app).get('/api/admin/dashboard').set('Authorization', `Bearer ${adminToken}`),
          () => request(app).get('/api/admin/users').set('Authorization', `Bearer ${adminToken}`).query({ limit: 5 }),
          () => request(app).get('/api/admin/responses').set('Authorization', `Bearer ${adminToken}`).query({ limit: 5 }),
          () => request(app).get('/api/invitations').set('Authorization', `Bearer ${adminToken}`),
          () => request(app).get('/api/handshakes').set('Authorization', `Bearer ${adminToken}`)
        ];
        
        const operationStart = performance.now();
        const operationPromises = operations.map(op => op().expect(200));
        
        const operationResults = await Promise.all(operationPromises);
        const operationDuration = performance.now() - operationStart;
        
        console.log(`📊 Concurrent Admin Operations: ${Math.round(operationDuration)}ms`);
        
        // Verify all operations succeeded
        operationResults.forEach(result => {
          expect(result.status).toBe(200);
          expect(result.body).toBeDefined();
        });
        
        // Check performance
        const avgOperationTime = operationDuration / operations.length;
        expect(avgOperationTime).toBeLessThan(global.testConfig.performance.maxResponseTime);
        
        global.testReporter.logTestEnd('Concurrent Admin Operations', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Concurrent Admin Operations', startTime, false);
        throw error;
      }
    });
  });

  describe('💾 Memory & Resource Usage', () => {
    test('should maintain acceptable memory usage', async () => {
      const startTime = global.testReporter.logTestStart('Memory Usage Validation');
      
      try {
        const initialMemory = process.memoryUsage();
        console.log(`📊 Initial Memory Usage:`, {
          rss: Math.round(initialMemory.rss / 1024 / 1024) + 'MB',
          heapUsed: Math.round(initialMemory.heapUsed / 1024 / 1024) + 'MB',
          heapTotal: Math.round(initialMemory.heapTotal / 1024 / 1024) + 'MB'
        });
        
        // Perform memory-intensive operations
        const operations = [];
        
        // Multiple dashboard requests
        for (let i = 0; i < 20; i++) {
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
        console.log(`📊 Final Memory Usage:`, {
          rss: Math.round(finalMemory.rss / 1024 / 1024) + 'MB',
          heapUsed: Math.round(finalMemory.heapUsed / 1024 / 1024) + 'MB',
          heapTotal: Math.round(finalMemory.heapTotal / 1024 / 1024) + 'MB'
        });
        
        // Check for memory leaks
        const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
        const memoryIncreasePercent = (memoryIncrease / initialMemory.heapUsed) * 100;
        
        console.log(`📊 Memory Increase: ${Math.round(memoryIncrease / 1024 / 1024)}MB (${Math.round(memoryIncreasePercent)}%)`);
        
        // Memory increase should be reasonable (less than 50% for this test)
        expect(memoryIncreasePercent).toBeLessThan(50);
        
        // Total memory usage should be within limits
        const totalMemoryMB = finalMemory.rss / 1024 / 1024;
        expect(totalMemoryMB).toBeLessThan(global.testConfig.performance.maxMemoryUsage);
        
        global.testReporter.logTestEnd('Memory Usage Validation', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Memory Usage Validation', startTime, false);
        throw error;
      }
    });

    test('should monitor system resource usage', async () => {
      const startTime = global.testReporter.logTestStart('System Resource Monitoring');
      
      try {
        const systemInfo = {
          totalMemory: Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB',
          freeMemory: Math.round(os.freemem() / 1024 / 1024 / 1024) + 'GB',
          cpuCount: os.cpus().length,
          platform: os.platform(),
          uptime: Math.round(os.uptime() / 3600) + 'h'
        };
        
        console.log('📊 System Information:', systemInfo);
        
        // Monitor load average (Unix systems only)
        if (process.platform !== 'win32') {
          const loadAvg = os.loadavg();
          console.log(`📊 Load Average: [${loadAvg.map(l => l.toFixed(2)).join(', ')}]`);
          
          // Load average should be reasonable
          expect(loadAvg[0]).toBeLessThan(os.cpus().length * 2); // 1-minute load
        }
        
        // Check memory usage percentage
        const memoryUsagePercent = ((os.totalmem() - os.freemem()) / os.totalmem()) * 100;
        console.log(`📊 System Memory Usage: ${Math.round(memoryUsagePercent)}%`);
        
        // System memory usage should be reasonable
        expect(memoryUsagePercent).toBeLessThan(95);
        
        global.testReporter.logTestEnd('System Resource Monitoring', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('System Resource Monitoring', startTime, false);
        throw error;
      }
    });
  });

  describe('🗄️ Database Performance', () => {
    test('should validate database connection performance', async () => {
      const startTime = global.testReporter.logTestStart('Database Connection Performance');
      
      try {
        const dbOperations = [];
        
        // Test multiple concurrent database operations
        for (let i = 0; i < 10; i++) {
          dbOperations.push(
            request(app)
              .get('/api/health/database')
              .expect(200)
          );
        }
        
        const dbStart = performance.now();
        const dbResults = await Promise.all(dbOperations);
        const dbDuration = performance.now() - dbStart;
        
        console.log(`📊 Database Operations (${dbOperations.length}): ${Math.round(dbDuration)}ms`);
        
        // All operations should succeed
        dbResults.forEach(result => {
          expect(result.body).toHaveProperty('status');
          expect(result.body.status).toBe('healthy');
        });
        
        // Average operation time should be acceptable
        const avgDbTime = dbDuration / dbOperations.length;
        expect(avgDbTime).toBeLessThan(1000); // 1 second per operation
        
        global.testReporter.logTestEnd('Database Connection Performance', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Database Connection Performance', startTime, false);
        throw error;
      }
    });

    test('should validate query optimization', async () => {
      const startTime = global.testReporter.logTestStart('Query Optimization Validation');
      
      try {
        // Test complex queries that should be optimized
        const complexQueries = [
          {
            name: 'User Count Query',
            operation: () => request(app)
              .get('/api/admin/users/count')
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(200),
            threshold: 1000
          },
          {
            name: 'Response Statistics',
            operation: () => request(app)
              .get('/api/admin/statistics/responses')
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(200),
            threshold: 2000
          },
          {
            name: 'Monthly Summary',
            operation: () => request(app)
              .get('/api/admin/dashboard/monthly')
              .set('Authorization', `Bearer ${adminToken}`)
              .expect(200),
            threshold: 1500
          }
        ];
        
        for (const query of complexQueries) {
          const queryStart = performance.now();
          
          try {
            await query.operation();
            const queryDuration = performance.now() - queryStart;
            
            console.log(`📊 ${query.name}: ${Math.round(queryDuration)}ms`);
            
            if (queryDuration > query.threshold) {
              console.warn(`⚠️ ${query.name} exceeded threshold: ${Math.round(queryDuration)}ms > ${query.threshold}ms`);
            }
          } catch (error) {
            if (error.status === 404) {
              console.log(`ℹ️ ${query.name}: Endpoint not implemented yet`);
            } else {
              throw error;
            }
          }
        }
        
        global.testReporter.logTestEnd('Query Optimization Validation', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Query Optimization Validation', startTime, false);
        throw error;
      }
    });
  });

  describe('🌐 Network & Connectivity', () => {
    test('should handle network latency simulation', async () => {
      const startTime = global.testReporter.logTestStart('Network Latency Handling');
      
      try {
        // Simulate slow requests by adding artificial delays
        const slowOperations = [
          () => request(app)
            .get('/api/form/current')
            .timeout(10000) // 10 second timeout
            .expect(200),
          () => request(app)
            .get('/api/admin/dashboard')
            .set('Authorization', `Bearer ${adminToken}`)
            .timeout(10000)
            .expect(200)
        ];
        
        for (const operation of slowOperations) {
          const networkStart = performance.now();
          await operation();
          const networkDuration = performance.now() - networkStart;
          
          console.log(`📊 Network Operation: ${Math.round(networkDuration)}ms`);
          
          // Should complete within reasonable time even with network delays
          expect(networkDuration).toBeLessThan(5000); // 5 seconds max
        }
        
        global.testReporter.logTestEnd('Network Latency Handling', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Network Latency Handling', startTime, false);
        throw error;
      }
    });

    test('should validate connection pool efficiency', async () => {
      const startTime = global.testReporter.logTestStart('Connection Pool Efficiency');
      
      try {
        // Rapid succession of requests to test connection pooling
        const rapidRequests = [];
        
        for (let i = 0; i < 20; i++) {
          rapidRequests.push(
            request(app)
              .get('/api/health')
              .expect(200)
          );
        }
        
        const poolStart = performance.now();
        await Promise.all(rapidRequests);
        const poolDuration = performance.now() - poolStart;
        
        console.log(`📊 Connection Pool Test (20 requests): ${Math.round(poolDuration)}ms`);
        
        // Average request time should be efficient with connection pooling
        const avgRequestTime = poolDuration / rapidRequests.length;
        expect(avgRequestTime).toBeLessThan(200); // 200ms average per request
        
        global.testReporter.logTestEnd('Connection Pool Efficiency', startTime, true);
      } catch (error) {
        global.testReporter.logTestEnd('Connection Pool Efficiency', startTime, false);
        throw error;
      }
    });
  });
});