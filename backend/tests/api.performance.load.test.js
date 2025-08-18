// tests/api.performance.load.test.js
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

describe('API Performance and Load Testing Suite', () => {
  let testUsers = [];
  let authCookies = [];
  let csrfTokens = [];

  const PERFORMANCE_THRESHOLDS = {
    fast: 500,      // 500ms for simple operations
    moderate: 1000,  // 1s for moderate operations  
    slow: 2000,     // 2s for complex operations
    batch: 5000     // 5s for batch operations
  };

  const LOAD_TEST_SIZES = {
    small: 10,
    medium: 25,
    large: 50,
    xlarge: 100
  };

  beforeAll(async () => {
    // Setup test database
    await setupTestDatabase();
    
    // Set environment to test
    process.env.NODE_ENV = 'test';
    process.env.DISABLE_RATE_LIMITING = 'true';

    // Create multiple test users for load testing
    for (let i = 1; i <= 20; i++) {
      const user = await User.create({
        username: `testuser${i}`,
        email: `testuser${i}@test.com`,
        password: 'password123',
        role: 'user'
      });

      // Setup authentication
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: user.email,
          password: 'password123'
        })
        .expect(HTTP_STATUS.OK);

      const authCookie = loginResponse.headers['set-cookie'];
      
      const csrfResponse = await request(app)
        .get('/api/csrf-token')
        .set('Cookie', authCookie)
        .expect(HTTP_STATUS.OK);
      
      testUsers.push(user);
      authCookies.push(authCookie);
      csrfTokens.push(csrfResponse.body.csrfToken);
    }
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  beforeEach(async () => {
    // Clean data but keep users
    await Contact.deleteMany({});
    await Handshake.deleteMany({});
    await Invitation.deleteMany({});
    await Submission.deleteMany({});
  });

  describe('Response Time Performance Tests', () => {
    describe('Contact Operations', () => {
      it('should handle single contact creation within performance threshold', async () => {
        const startTime = Date.now();
        
        const response = await request(app)
          .post('/api/contacts')
          .set('Cookie', authCookies[0])
          .set('X-CSRF-Token', csrfTokens[0])
          .send({
            name: 'Performance Test Contact',
            email: 'performance@test.com',
            tags: ['test', 'performance']
          })
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.fast);
      });

      it('should handle contact listing with pagination within threshold', async () => {
        // Create test data
        const contacts = Array(20).fill().map((_, i) => ({
          name: `Contact ${i}`,
          email: `contact${i}@test.com`,
          userId: testUsers[0]._id
        }));
        await Contact.insertMany(contacts);

        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/contacts?page=1&limit=10')
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.contacts).toHaveLength(10);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.fast);
      });

      it('should handle contact search efficiently', async () => {
        // Create searchable contacts
        const contacts = Array(50).fill().map((_, i) => ({
          name: i % 10 === 0 ? `Performance Contact ${i}` : `Regular Contact ${i}`,
          email: `searchtest${i}@test.com`,
          userId: testUsers[0]._id,
          tags: i % 5 === 0 ? ['performance', 'test'] : ['regular']
        }));
        await Contact.insertMany(contacts);

        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/contacts/search?q=Performance')
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.contacts.length).toBe(5); // Should find 5 Performance contacts
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
      });

      it('should handle bulk contact operations within threshold', async () => {
        const bulkContacts = Array(25).fill().map((_, i) => ({
          name: `Bulk Contact ${i}`,
          email: `bulk${i}@test.com`
        }));

        const startTime = Date.now();
        
        const response = await request(app)
          .post('/api/contacts/bulk')
          .set('Cookie', authCookies[0])
          .set('X-CSRF-Token', csrfTokens[0])
          .send({ contacts: bulkContacts })
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.created).toHaveLength(25);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
      });
    });

    describe('Handshake Operations', () => {
      it('should handle handshake creation within threshold', async () => {
        const startTime = Date.now();
        
        const response = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookies[0])
          .set('X-CSRF-Token', csrfTokens[0])
          .send({
            recipientId: testUsers[1]._id.toString(),
            message: 'Performance test handshake'
          })
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.fast);
      });

      it('should handle handshake listing efficiently with large dataset', async () => {
        // Create many handshakes for user
        const handshakes = Array(100).fill().map((_, i) => ({
          requesterId: i % 2 === 0 ? testUsers[0]._id : testUsers[i % 10]._id,
          recipientId: i % 2 === 0 ? testUsers[i % 10]._id : testUsers[0]._id,
          message: `Handshake ${i}`,
          status: ['pending', 'accepted', 'declined'][i % 3]
        }));
        await Handshake.insertMany(handshakes);

        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/handshakes/received?page=1&limit=20')
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
      });

      it('should handle handshake statistics calculation efficiently', async () => {
        // Create diverse handshake data
        const handshakes = Array(200).fill().map((_, i) => ({
          requesterId: testUsers[i % 10]._id,
          recipientId: testUsers[(i + 1) % 10]._id,
          status: ['pending', 'accepted', 'declined', 'cancelled'][i % 4],
          createdAt: new Date(Date.now() - i * 60 * 60 * 1000) // Spread over time
        }));
        await Handshake.insertMany(handshakes);

        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/handshakes/stats')
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.stats).toBeDefined();
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
      });

      it('should generate suggestions efficiently', async () => {
        // Create existing connections to test suggestion algorithm
        const connections = Array(50).fill().map((_, i) => ({
          requesterId: testUsers[0]._id,
          recipientId: testUsers[i % 15]._id,
          status: 'accepted'
        }));
        await Handshake.insertMany(connections);

        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/handshakes/suggestions?limit=10')
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
      });
    });

    describe('Submission Operations', () => {
      it('should handle submission creation within threshold', async () => {
        const submissionData = {
          responses: Array(10).fill().map((_, i) => ({
            question: `Performance test question ${i + 1}?`,
            answer: `This is a performance test answer ${i + 1} with enough content to simulate real usage patterns and test system performance under typical load conditions.`
          }))
        };

        const startTime = Date.now();
        
        const response = await request(app)
          .post('/api/submissions')
          .set('Cookie', authCookies[0])
          .set('X-CSRF-Token', csrfTokens[0])
          .send(submissionData)
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.fast);
      });

      it('should handle timeline retrieval efficiently with large dataset', async () => {
        // Create many submissions across users and months
        const submissions = [];
        const months = ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05'];
        
        for (let i = 0; i < 200; i++) {
          submissions.push({
            userId: testUsers[i % 10]._id,
            userName: testUsers[i % 10].username,
            month: months[i % months.length],
            responses: [
              { question: `Question ${i}`, answer: `Answer ${i}` }
            ],
            submittedAt: new Date(Date.now() - i * 60 * 60 * 1000)
          });
        }
        await Submission.insertMany(submissions);

        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/submissions?page=1&limit=20')
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
      });

      it('should handle monthly comparison efficiently', async () => {
        // Create submissions for specific month
        const targetMonth = '2024-06';
        const submissions = Array(30).fill().map((_, i) => ({
          userId: testUsers[i % 10]._id,
          userName: testUsers[i % 10].username,
          month: targetMonth,
          responses: Array(5).fill().map((_, j) => ({
            question: `Question ${j + 1}`,
            answer: `Answer ${j + 1} from user ${i}`
          })),
          submittedAt: new Date(`${targetMonth}-${String((i % 28) + 1).padStart(2, '0')}`)
        }));
        await Submission.insertMany(submissions);

        const startTime = Date.now();
        
        const response = await request(app)
          .get(`/api/submissions/compare/${targetMonth}`)
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.comparison.submissions.length).toBeGreaterThan(0);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.slow);
      });

      it('should calculate global statistics efficiently', async () => {
        // Create diverse submission data
        const submissions = [];
        const months = ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05', '2024-06'];
        
        for (let i = 0; i < 300; i++) {
          submissions.push({
            userId: testUsers[i % 15]._id,
            userName: testUsers[i % 15].username,
            month: months[i % months.length],
            responses: Array(Math.floor(Math.random() * 10) + 1).fill().map((_, j) => ({
              question: `Question ${j + 1}`,
              answer: `Answer ${j + 1}`.repeat(Math.floor(Math.random() * 5) + 1)
            })),
            submittedAt: new Date(Date.now() - i * 24 * 60 * 60 * 1000)
          });
        }
        await Submission.insertMany(submissions);

        const startTime = Date.now();
        
        const response = await request(app)
          .get('/api/submissions/stats')
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.stats.totalSubmissions).toBe(300);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.slow);
      });
    });

    describe('Invitation Operations', () => {
      it('should handle invitation creation within threshold', async () => {
        const startTime = Date.now();
        
        const response = await request(app)
          .post('/api/invitations')
          .set('Cookie', authCookies[0])
          .set('X-CSRF-Token', csrfTokens[0])
          .send({
            email: 'performance@test.com',
            name: 'Performance Test User',
            message: 'Performance testing invitation'
          })
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.fast);
      });

      it('should handle bulk invitation sending within threshold', async () => {
        const invitations = Array(20).fill().map((_, i) => ({
          email: `bulk${i}@test.com`,
          name: `Bulk User ${i}`
        }));

        const startTime = Date.now();
        
        const response = await request(app)
          .post('/api/invitations/bulk-send')
          .set('Cookie', authCookies[0])
          .set('X-CSRF-Token', csrfTokens[0])
          .send({
            invitations: invitations,
            message: 'Bulk performance test'
          })
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.sent).toHaveLength(20);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
      });
    });
  });

  describe('Concurrent Load Tests', () => {
    it('should handle concurrent contact creation', async () => {
      const concurrentRequests = LOAD_TEST_SIZES.medium;
      const startTime = Date.now();
      
      const promises = Array(concurrentRequests).fill().map((_, i) =>
        request(app)
          .post('/api/contacts')
          .set('Cookie', authCookies[i % authCookies.length])
          .set('X-CSRF-Token', csrfTokens[i % csrfTokens.length])
          .send({
            name: `Concurrent Contact ${i}`,
            email: `concurrent${i}@test.com`
          })
      );

      const responses = await Promise.all(promises);
      const totalTime = Date.now() - startTime;
      
      const successCount = responses.filter(r => r.status === HTTP_STATUS.CREATED).length;
      expect(successCount).toBe(concurrentRequests);
      expect(totalTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
      
      // Calculate average response time per request
      const avgResponseTime = totalTime / concurrentRequests;
      expect(avgResponseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
    });

    it('should handle concurrent handshake requests', async () => {
      const concurrentRequests = LOAD_TEST_SIZES.small;
      const startTime = Date.now();
      
      const promises = Array(concurrentRequests).fill().map((_, i) =>
        request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookies[i % authCookies.length])
          .set('X-CSRF-Token', csrfTokens[i % csrfTokens.length])
          .send({
            recipientId: testUsers[(i + 1) % testUsers.length]._id.toString(),
            message: `Concurrent handshake ${i}`
          })
      );

      const responses = await Promise.all(promises);
      const totalTime = Date.now() - startTime;
      
      const successCount = responses.filter(r => r.status === HTTP_STATUS.CREATED).length;
      expect(successCount).toBeGreaterThan(0); // Some should succeed
      expect(totalTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
    });

    it('should handle concurrent timeline requests', async () => {
      // Create some baseline data
      const submissions = Array(50).fill().map((_, i) => ({
        userId: testUsers[i % 10]._id,
        userName: testUsers[i % 10].username,
        month: '2024-06',
        responses: [{ question: `Q${i}`, answer: `A${i}` }]
      }));
      await Submission.insertMany(submissions);

      const concurrentRequests = LOAD_TEST_SIZES.medium;
      const startTime = Date.now();
      
      const promises = Array(concurrentRequests).fill().map((_, i) =>
        request(app)
          .get('/api/submissions?page=1&limit=10')
          .set('Cookie', authCookies[i % authCookies.length])
      );

      const responses = await Promise.all(promises);
      const totalTime = Date.now() - startTime;
      
      const successCount = responses.filter(r => r.status === HTTP_STATUS.OK).length;
      expect(successCount).toBe(concurrentRequests);
      expect(totalTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
      
      // Verify all responses are valid
      responses.forEach(response => {
        expect(response.body.success).toBe(true);
        expect(response.body.data.timeline).toBeDefined();
      });
    });

    it('should handle concurrent statistics requests', async () => {
      // Create diverse data for statistics
      await Promise.all([
        Submission.insertMany(Array(100).fill().map((_, i) => ({
          userId: testUsers[i % 10]._id,
          userName: testUsers[i % 10].username,
          month: '2024-06',
          responses: [{ question: 'Q', answer: 'A' }]
        }))),
        Handshake.insertMany(Array(50).fill().map((_, i) => ({
          requesterId: testUsers[i % 10]._id,
          recipientId: testUsers[(i + 1) % 10]._id,
          status: ['pending', 'accepted'][i % 2]
        })))
      ]);

      const concurrentRequests = LOAD_TEST_SIZES.small;
      const startTime = Date.now();
      
      const promises = Array(concurrentRequests).fill().map((_, i) => {
        const endpoint = ['/api/submissions/stats', '/api/handshakes/stats'][i % 2];
        return request(app)
          .get(endpoint)
          .set('Cookie', authCookies[i % authCookies.length]);
      });

      const responses = await Promise.all(promises);
      const totalTime = Date.now() - startTime;
      
      const successCount = responses.filter(r => r.status === HTTP_STATUS.OK).length;
      expect(successCount).toBe(concurrentRequests);
      expect(totalTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
    });
  });

  describe('Memory and Resource Usage Tests', () => {
    it('should handle large payload submission without memory issues', async () => {
      const largeSubmission = {
        responses: Array(20).fill().map((_, i) => ({
          question: `Large payload question ${i + 1}?`.repeat(10),
          answer: `This is a very detailed answer for question ${i + 1}. `.repeat(100) // ~4KB per answer
        }))
      };

      const startTime = Date.now();
      const initialMemory = process.memoryUsage();
      
      const response = await request(app)
        .post('/api/submissions')
        .set('Cookie', authCookies[0])
        .set('X-CSRF-Token', csrfTokens[0])
        .send(largeSubmission)
        .expect(HTTP_STATUS.CREATED);

      const responseTime = Date.now() - startTime;
      const finalMemory = process.memoryUsage();
      
      expect(response.body.success).toBe(true);
      expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.slow);
      
      // Memory should not increase dramatically
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // 50MB threshold
    });

    it('should handle batch operations without excessive memory usage', async () => {
      const batchSize = 100;
      const contacts = Array(batchSize).fill().map((_, i) => ({
        name: `Memory Test Contact ${i}`,
        email: `memtest${i}@test.com`,
        notes: 'Standard contact notes for memory testing'.repeat(10)
      }));

      const initialMemory = process.memoryUsage();
      const startTime = Date.now();
      
      const response = await request(app)
        .post('/api/contacts/bulk')
        .set('Cookie', authCookies[0])
        .set('X-CSRF-Token', csrfTokens[0])
        .send({ contacts })
        .expect(HTTP_STATUS.CREATED);

      const responseTime = Date.now() - startTime;
      const finalMemory = process.memoryUsage();
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.created).toHaveLength(batchSize);
      expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
      
      // Memory usage should be reasonable
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // 100MB threshold
    });

    it('should handle large dataset queries efficiently', async () => {
      // Create large dataset
      const largeDataset = [];
      for (let i = 0; i < 500; i++) {
        largeDataset.push({
          userId: testUsers[i % 10]._id,
          userName: testUsers[i % 10].username,
          month: `2024-${String((i % 12) + 1).padStart(2, '0')}`,
          responses: Array(5).fill().map((_, j) => ({
            question: `Dataset question ${j + 1}`,
            answer: `Dataset answer ${j + 1}`.repeat(20)
          })),
          submittedAt: new Date(Date.now() - i * 60 * 60 * 1000)
        });
      }
      await Submission.insertMany(largeDataset);

      const initialMemory = process.memoryUsage();
      const startTime = Date.now();
      
      // Test pagination with large dataset
      const response = await request(app)
        .get('/api/submissions?page=5&limit=25')
        .set('Cookie', authCookies[0])
        .expect(HTTP_STATUS.OK);

      const responseTime = Date.now() - startTime;
      const finalMemory = process.memoryUsage();
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.timeline).toHaveLength(25);
      expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
      
      // Memory should not increase significantly for paginated queries
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      expect(memoryIncrease).toBeLessThan(20 * 1024 * 1024); // 20MB threshold
    });
  });

  describe('Database Performance Tests', () => {
    it('should maintain query performance with indexed fields', async () => {
      // Create data with indexed fields
      const testData = Array(1000).fill().map((_, i) => ({
        userId: testUsers[i % 10]._id,
        userName: testUsers[i % 10].username,
        month: `2024-${String((i % 12) + 1).padStart(2, '0')}`,
        responses: [{ question: 'Q', answer: 'A' }],
        submittedAt: new Date(Date.now() - i * 60 * 60 * 1000)
      }));
      await Submission.insertMany(testData);

      // Test queries that should use indexes
      const queries = [
        { url: '/api/submissions?userId=' + testUsers[0]._id, description: 'User ID filter' },
        { url: '/api/submissions?month=2024-06', description: 'Month filter' },
        { url: '/api/submissions?page=10&limit=20', description: 'Pagination' }
      ];

      for (const query of queries) {
        const startTime = Date.now();
        
        const response = await request(app)
          .get(query.url)
          .set('Cookie', authCookies[0])
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.moderate);
      }
    });

    it('should handle aggregation queries efficiently', async () => {
      // Create diverse data for aggregation
      const aggregationData = [];
      const months = ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05', '2024-06'];
      
      for (let i = 0; i < 600; i++) {
        aggregationData.push({
          userId: testUsers[i % 15]._id,
          userName: testUsers[i % 15].username,
          month: months[i % months.length],
          responses: Array(Math.floor(Math.random() * 8) + 2).fill().map((_, j) => ({
            question: `Q${j}`,
            answer: `Answer ${j}`.repeat(Math.floor(Math.random() * 10) + 1)
          }))
        });
      }
      await Submission.insertMany(aggregationData);

      const startTime = Date.now();
      
      const response = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies[0])
        .expect(HTTP_STATUS.OK);

      const responseTime = Date.now() - startTime;
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.stats.totalSubmissions).toBe(600);
      expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.slow);
    });

    it('should handle complex comparison queries efficiently', async () => {
      // Create month-specific data for comparison
      const month = '2024-07';
      const comparisonData = Array(100).fill().map((_, i) => ({
        userId: testUsers[i % 12]._id,
        userName: testUsers[i % 12].username,
        month: month,
        responses: Array(8).fill().map((_, j) => ({
          question: `Common question ${j + 1}`,
          answer: `User ${i % 12} answer to question ${j + 1}`
        }))
      }));
      await Submission.insertMany(comparisonData);

      const startTime = Date.now();
      
      const response = await request(app)
        .get(`/api/submissions/compare/${month}`)
        .set('Cookie', authCookies[0])
        .expect(HTTP_STATUS.OK);

      const responseTime = Date.now() - startTime;
      
      expect(response.body.success).toBe(true);
      expect(response.body.data.comparison.submissions.length).toBeGreaterThan(0);
      expect(response.body.data.comparison.questions).toHaveLength(8);
      expect(responseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.slow);
    });
  });

  describe('Stress Testing', () => {
    it('should handle rapid successive requests', async () => {
      const rapidRequests = LOAD_TEST_SIZES.large;
      const requests = [];

      // Fire requests rapidly
      for (let i = 0; i < rapidRequests; i++) {
        requests.push(
          request(app)
            .get('/api/submissions')
            .set('Cookie', authCookies[i % authCookies.length])
        );
      }

      const startTime = Date.now();
      const responses = await Promise.allSettled(requests);
      const totalTime = Date.now() - startTime;

      const successfulResponses = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status === HTTP_STATUS.OK
      );

      // Most requests should succeed
      expect(successfulResponses.length).toBeGreaterThan(rapidRequests * 0.8);
      expect(totalTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch * 2);
    });

    it('should recover from high load gracefully', async () => {
      // Create high load scenario
      const highLoadRequests = LOAD_TEST_SIZES.xlarge;
      const mixed_operations = Array(highLoadRequests).fill().map((_, i) => {
        const operation = i % 4;
        const userIndex = i % authCookies.length;

        switch (operation) {
          case 0:
            return request(app)
              .get('/api/submissions')
              .set('Cookie', authCookies[userIndex]);
          case 1:
            return request(app)
              .get('/api/handshakes/received')
              .set('Cookie', authCookies[userIndex]);
          case 2:
            return request(app)
              .get('/api/contacts')
              .set('Cookie', authCookies[userIndex]);
          case 3:
            return request(app)
              .get('/api/submissions/stats')
              .set('Cookie', authCookies[userIndex]);
          default:
            return request(app)
              .get('/api/submissions')
              .set('Cookie', authCookies[userIndex]);
        }
      });

      const startTime = Date.now();
      const results = await Promise.allSettled(mixed_operations);
      const totalTime = Date.now() - startTime;

      const successful = results.filter(r => 
        r.status === 'fulfilled' && r.value.status === HTTP_STATUS.OK
      ).length;

      const errorRate = (results.length - successful) / results.length;

      // Should handle high load with reasonable success rate
      expect(errorRate).toBeLessThan(0.2); // Less than 20% error rate
      expect(totalTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch * 3);

      // Verify system is still responsive after high load
      const recoveryResponse = await request(app)
        .get('/api/submissions/stats')
        .set('Cookie', authCookies[0])
        .expect(HTTP_STATUS.OK);

      expect(recoveryResponse.body.success).toBe(true);
    });
  });

  describe('Resource Cleanup and Optimization', () => {
    it('should not leak memory during extended operations', async () => {
      const initialMemory = process.memoryUsage();
      
      // Perform many operations
      for (let batch = 0; batch < 10; batch++) {
        const batchOperations = Array(20).fill().map((_, i) =>
          request(app)
            .get('/api/submissions?page=1&limit=5')
            .set('Cookie', authCookies[i % authCookies.length])
        );
        
        await Promise.all(batchOperations);
        
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
      }

      const finalMemory = process.memoryUsage();
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Memory growth should be minimal
      expect(memoryGrowth).toBeLessThan(100 * 1024 * 1024); // 100MB threshold
    });

    it('should maintain performance consistency across multiple batches', async () => {
      const batchSize = 20;
      const numBatches = 5;
      const responseTimes = [];

      for (let batch = 0; batch < numBatches; batch++) {
        const batchStartTime = Date.now();
        
        const batchRequests = Array(batchSize).fill().map((_, i) =>
          request(app)
            .post('/api/contacts')
            .set('Cookie', authCookies[i % authCookies.length])
            .set('X-CSRF-Token', csrfTokens[i % csrfTokens.length])
            .send({
              name: `Batch ${batch} Contact ${i}`,
              email: `batch${batch}-contact${i}@test.com`
            })
        );

        const responses = await Promise.all(batchRequests);
        const batchTime = Date.now() - batchStartTime;
        
        responseTimes.push(batchTime);
        
        // All requests in batch should succeed
        expect(responses.every(r => r.status === HTTP_STATUS.CREATED)).toBe(true);
      }

      // Response times should be consistent across batches
      const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
      const maxResponseTime = Math.max(...responseTimes);
      const minResponseTime = Math.min(...responseTimes);
      
      // Variation should not be excessive
      expect(maxResponseTime - minResponseTime).toBeLessThan(avgResponseTime);
      expect(avgResponseTime).toBeLessThan(PERFORMANCE_THRESHOLDS.batch);
    });
  });
});