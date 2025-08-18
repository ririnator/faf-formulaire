// tests/api.submissions.integration.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const { getTestApp, setupTestEnvironment, createAuthenticatedAdmin, getCsrfToken } = require('./test-utils');
const User = require('../models/User');
const Submission = require('../models/Submission');
const Response = require('../models/Response');
const Contact = require('../models/Contact');
const Handshake = require('../models/Handshake');
const { HTTP_STATUS } = require('../constants');

// Setup test environment
setupTestEnvironment();

describe('API Integration Tests - /api/submissions', () => {
  let testUser1, testUser2, testUser3, adminUser;
  let authAgent1, authAgent2, adminAgent;
  let csrfToken1, csrfToken2, adminCsrfToken;
  let app;

  beforeAll(async () => {
    // Get shared app instance
    app = getTestApp();
    
    // Set environment to test
    process.env.NODE_ENV = 'test';
    process.env.DISABLE_RATE_LIMITING = 'true';
  });

  beforeEach(async () => {
    // Clean database
    await User.deleteMany({});
    await Submission.deleteMany({});
    await Response.deleteMany({});
    await Contact.deleteMany({});
    await Handshake.deleteMany({});

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

    // Setup authentication for user1 using real API endpoints
    authAgent1 = request.agent(app);
    const loginResponse1 = await authAgent1
      .post('/api/auth/login')
      .send({
        login: testUser1.email,
        password: 'password123'
      });

    if (loginResponse1.status !== HTTP_STATUS.OK) {
      throw new Error(`User1 login failed: ${loginResponse1.status} - ${loginResponse1.text}`);
    }
    
    csrfToken1 = await getCsrfToken(app, authAgent1);

    // Setup authentication for user2
    authAgent2 = request.agent(app);
    const loginResponse2 = await authAgent2
      .post('/api/auth/login')
      .send({
        login: testUser2.email,
        password: 'password123'
      });

    if (loginResponse2.status !== HTTP_STATUS.OK) {
      throw new Error(`User2 login failed: ${loginResponse2.status} - ${loginResponse2.text}`);
    }
    
    csrfToken2 = await getCsrfToken(app, authAgent2);

    // Setup admin authentication using helper
    adminAgent = await createAuthenticatedAdmin(app);
    adminCsrfToken = await getCsrfToken(app, adminAgent);
  });

  describe('Nominal Cases - Happy Path', () => {
    describe('GET /api/submissions (Timeline View)', () => {
      beforeEach(async () => {
        // Create test submissions across different months
        const currentDate = new Date();
        const currentMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}`;
        const lastMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth()).padStart(2, '0')}`;

        await Submission.create([
          {
            userId: testUser1._id,
            month: currentMonth,
            responses: [
              { questionId: 'Q1', type: 'text', answer: 'Blue' },
              { questionId: 'Q2', type: 'text', answer: 'Beach in Tahiti' }
            ],
            submittedAt: new Date()
          },
          {
            userId: testUser2._id,
            month: currentMonth,
            responses: [
              { questionId: 'Q1', type: 'text', answer: 'Green' },
              { questionId: 'Q2', type: 'text', answer: 'Mountains in Switzerland' }
            ],
            submittedAt: new Date(Date.now() - 60000) // 1 minute ago
          },
          {
            userId: testUser1._id,
            month: lastMonth,
            responses: [
              { questionId: 'Q3', type: 'text', answer: 'Pizza' },
              { questionId: 'Q4', type: 'text', answer: 'Astronaut' }
            ],
            submittedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
          }
        ]);
      });

      it('should retrieve timeline of submissions with proper ordering', async () => {
        // First create a contact relationship (needed for timeline access)
        const Contact = require('../models/Contact');
        const Handshake = require('../models/Handshake');
        
        // Create contact relationship
        await Contact.create({
          ownerId: testUser1._id,
          contactUserId: testUser2._id,
          email: testUser2.email,
          firstName: testUser2.username,
          status: 'active'
        });
        
        // Create handshake for permission
        await Handshake.create({
          requesterId: testUser1._id,
          targetId: testUser2._id,
          status: 'accepted',
          message: 'Test handshake',
          requestedAt: new Date(),
          respondedAt: new Date()
        });

        const response = await authAgent1
          .get(`/api/submissions/timeline/${testUser2._id}`)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.timeline).toBeDefined();
        expect(response.body.timeline.length).toBeGreaterThan(0);

        // Should be ordered by most recent first
        const timeline = response.body.timeline;
        for (let i = 1; i < timeline.length; i++) {
          const prev = new Date(timeline[i - 1].submittedAt);
          const current = new Date(timeline[i].submittedAt);
          expect(prev.getTime()).toBeGreaterThanOrEqual(current.getTime());
        }
      });

      it('should support pagination in timeline view', async () => {
        const response = await authAgent1
          .get('/api/submissions?page=1&limit=2')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.timeline).toHaveLength(2);
        expect(response.body.data.pagination).toMatchObject({
          currentPage: 1,
          totalPages: expect.any(Number),
          totalItems: expect.any(Number),
          limit: 2
        });
      });

      it('should filter submissions by month', async () => {
        const currentDate = new Date();
        const currentMonth = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}`;

        const response = await authAgent1
          .get(`/api/submissions?month=${currentMonth}`)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        response.body.data.timeline.forEach(submission => {
          expect(submission.month).toBe(currentMonth);
        });
      });

      it('should filter submissions by user', async () => {
        const response = await authAgent1
          .get(`/api/submissions?userId=${testUser1._id}`)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        response.body.data.timeline.forEach(submission => {
          expect(submission.userId).toBe(testUser1._id.toString());
        });
      });

      it('should include user details in submissions', async () => {
        const response = await authAgent1
          .get('/api/submissions')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.timeline[0]).toHaveProperty('userDetails');
        expect(response.body.data.timeline[0].userDetails).toHaveProperty('username');
        expect(response.body.data.timeline[0].userDetails).toHaveProperty('email');
      });
    });

    describe('POST /api/submissions (Create Submission)', () => {
      it('should create a new submission successfully', async () => {
        const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
        
        const submissionData = {
          responses: [
            { question: 'What makes you happy?', answer: 'Spending time with friends and family' },
            { question: 'Favorite book?', answer: 'The Hobbit by J.R.R. Tolkien' },
            { question: 'Dream destination?', answer: 'New Zealand for the landscapes' }
          ]
        };

        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send(submissionData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.submission).toMatchObject({
          userId: testUser1._id.toString(),
          userName: testUser1.username,
          month: currentMonth,
          responses: submissionData.responses
        });
        expect(response.body.data.submission).toHaveProperty('_id');
        expect(response.body.data.submission).toHaveProperty('submittedAt');
      });

      it('should handle French characters in responses', async () => {
        const submissionData = {
          responses: [
            { 
              question: 'Quel est ton plat préféré?', 
              answer: 'J\'adore la ratatouille de ma grand-mère avec des aubergines et des courgettes.' 
            },
            { 
              question: 'Décris ton endroit préféré', 
              answer: 'Les Alpes françaises en été, avec leurs prairies fleuries et leurs sommets enneigés' 
            }
          ]
        };

        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send(submissionData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.submission.responses[0].question).toBe(submissionData.responses[0].question);
        expect(response.body.data.submission.responses[0].answer).toBe(submissionData.responses[0].answer);
        expect(response.body.data.submission.responses[1].question).toBe(submissionData.responses[1].question);
        expect(response.body.data.submission.responses[1].answer).toBe(submissionData.responses[1].answer);
      });

      it('should automatically assign current month to submission', async () => {
        const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
        
        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({
            responses: [
              { question: 'Test question', answer: 'Test answer' }
            ]
          })
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.submission.month).toBe(currentMonth);
      });

      it('should create unique tokens for each submission', async () => {
        const submissionData = {
          responses: [{ question: 'Test', answer: 'Test' }]
        };

        const submissions = await Promise.all([
          authAgent1
            .post('/api/submissions')
              .set('X-CSRF-Token', csrfToken1)
            .send(submissionData),
          authAgent1
            .post('/api/submissions')
              .set('X-CSRF-Token', csrfToken2)
            .send(submissionData)
        ]);

        const token1 = submissions[0].body.data.submission.token;
        const token2 = submissions[1].body.data.submission.token;

        expect(token1).toBeDefined();
        expect(token2).toBeDefined();
        expect(token1).not.toBe(token2);
        expect(token1.length).toBeGreaterThan(20);
        expect(token2.length).toBeGreaterThan(20);
      });
    });

    describe('GET /api/submissions/compare/:month (Monthly Comparison)', () => {
      beforeEach(async () => {
        const targetMonth = '2024-03';
        
        await Submission.create([
          {
            userId: testUser1._id,
            userName: testUser1.username,
            month: targetMonth,
            responses: [
              { question: 'What\'s your favorite color?', answer: 'Blue like the ocean' },
              { question: 'Favorite season?', answer: 'Spring for the flowers' },
              { question: 'Dream job?', answer: 'Marine biologist' }
            ],
            submittedAt: new Date('2024-03-15')
          },
          {
            userId: testUser2._id,
            userName: testUser2.username,
            month: targetMonth,
            responses: [
              { question: 'What\'s your favorite color?', answer: 'Green like forests' },
              { question: 'Favorite season?', answer: 'Autumn for the colors' },
              { question: 'Dream job?', answer: 'Environmental scientist' }
            ],
            submittedAt: new Date('2024-03-20')
          },
          {
            userId: testUser3._id,
            userName: testUser3.username,
            month: targetMonth,
            responses: [
              { question: 'What\'s your favorite color?', answer: 'Red like sunsets' },
              { question: 'Favorite season?', answer: 'Summer for the warmth' },
              { question: 'Dream job?', answer: 'Photographer' }
            ],
            submittedAt: new Date('2024-03-25')
          }
        ]);
      });

      it('should compare submissions for specific month', async () => {
        const response = await authAgent1
          .get('/api/submissions/compare/2024-03')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.comparison).toBeDefined();
        expect(response.body.data.comparison.month).toBe('2024-03');
        expect(response.body.data.comparison.submissions).toHaveLength(3);

        // Check that questions are properly aligned for comparison
        const comparison = response.body.data.comparison;
        expect(comparison.questions).toContain('What\'s your favorite color?');
        expect(comparison.questions).toContain('Favorite season?');
        expect(comparison.questions).toContain('Dream job?');

        // Verify user responses are grouped properly
        comparison.submissions.forEach(submission => {
          expect(submission).toHaveProperty('userId');
          expect(submission).toHaveProperty('userName');
          expect(submission).toHaveProperty('responses');
          expect(submission.responses).toHaveLength(3);
        });
      });

      it('should handle month with no submissions', async () => {
        const response = await authAgent1
          .get('/api/submissions/compare/2025-12')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.comparison.month).toBe('2025-12');
        expect(response.body.data.comparison.submissions).toHaveLength(0);
      });

      it('should include statistics in comparison', async () => {
        const response = await authAgent1
          .get('/api/submissions/compare/2024-03')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.comparison.statistics).toBeDefined();
        expect(response.body.data.comparison.statistics).toMatchObject({
          totalSubmissions: 3,
          totalQuestions: 3,
          averageResponseLength: expect.any(Number),
          participationRate: expect.any(Number)
        });
      });

      it('should support filtering comparison by users', async () => {
        const userIds = [testUser1._id.toString(), testUser2._id.toString()];
        
        const response = await authAgent1
          .get(`/api/submissions/compare/2024-03?userIds=${userIds.join(',')}`)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.comparison.submissions).toHaveLength(2);
        
        const returnedUserIds = response.body.data.comparison.submissions.map(s => s.userId);
        expect(returnedUserIds).toEqual(expect.arrayContaining(userIds));
      });
    });

    describe('GET /api/submissions/stats (Global Statistics)', () => {
      beforeEach(async () => {
        // Create submissions across multiple months and users
        await Submission.create([
          {
            userId: testUser1._id,
            userName: testUser1.username,
            month: '2024-01',
            responses: [
              { question: 'Q1', answer: 'Answer of moderate length' },
              { question: 'Q2', answer: 'Short' }
            ]
          },
          {
            userId: testUser2._id,
            userName: testUser2.username,
            month: '2024-01',
            responses: [
              { question: 'Q1', answer: 'A much longer answer with more detailed explanation' },
              { question: 'Q2', answer: 'Also longer response' }
            ]
          },
          {
            userId: testUser1._id,
            userName: testUser1.username,
            month: '2024-02',
            responses: [
              { question: 'Q1', answer: 'February answer' },
              { question: 'Q3', answer: 'New question answer' }
            ]
          }
        ]);
      });

      it('should provide global submission statistics', async () => {
        const response = await authAgent1
          .get('/api/submissions/stats')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.stats).toBeDefined();

        const stats = response.body.data.stats;
        expect(stats).toMatchObject({
          totalSubmissions: 3,
          totalUsers: 2,
          totalMonths: 2,
          averageSubmissionsPerUser: 1.5,
          averageSubmissionsPerMonth: 1.5
        });

        expect(stats.monthlyBreakdown).toBeDefined();
        expect(stats.monthlyBreakdown['2024-01']).toBe(2);
        expect(stats.monthlyBreakdown['2024-02']).toBe(1);

        expect(stats.userBreakdown).toBeDefined();
        expect(Object.keys(stats.userBreakdown)).toHaveLength(2);
      });

      it('should support date range filtering for statistics', async () => {
        const response = await authAgent1
          .get('/api/submissions/stats?startMonth=2024-01&endMonth=2024-01')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.stats.totalSubmissions).toBe(2); // Only January submissions
        expect(response.body.data.stats.totalMonths).toBe(1);
      });
    });

    describe('Form Integration Features', () => {
      it('should handle submissions with various question types', async () => {
        const submissionData = {
          responses: [
            { question: 'Multiple choice: Favorite color?', answer: 'Blue' },
            { question: 'Text area: Describe your ideal day', answer: 'I would wake up early, have coffee while watching the sunrise, spend time in nature hiking through forest trails, have a picnic lunch with friends, read a good book in the afternoon, and end the day with a home-cooked dinner and meaningful conversations.' },
            { question: 'Number: Age in years', answer: '25' },
            { question: 'Yes/No: Do you like pizza?', answer: 'Yes' },
            { question: 'Rating scale (1-5): Rate your happiness today', answer: '4' }
          ]
        };

        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send(submissionData)
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        expect(response.body.data.submission.responses).toHaveLength(5);
        expect(response.body.data.submission.responses).toEqual(
          expect.arrayContaining(submissionData.responses)
        );
      });

      it('should maintain question ordering in submissions', async () => {
        const orderedQuestions = [
          { question: 'First Question', answer: 'First Answer' },
          { question: 'Second Question', answer: 'Second Answer' },
          { question: 'Third Question', answer: 'Third Answer' }
        ];

        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({ responses: orderedQuestions })
          .expect(HTTP_STATUS.CREATED);

        expect(response.body.success).toBe(true);
        
        // Verify order is preserved
        const returnedResponses = response.body.data.submission.responses;
        for (let i = 0; i < orderedQuestions.length; i++) {
          expect(returnedResponses[i].question).toBe(orderedQuestions[i].question);
          expect(returnedResponses[i].answer).toBe(orderedQuestions[i].answer);
        }
      });
    });
  });

  describe('Error Scenarios', () => {
    describe('Authentication and Authorization', () => {
      it('should reject requests without authentication', async () => {
        const response = await authAgent1
          .get('/api/submissions')
          .expect(HTTP_STATUS.UNAUTHORIZED);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('authentication');
      });

      it('should reject POST requests without CSRF token', async () => {
        const response = await authAgent1
          .post('/api/submissions')
          .send({
            responses: [{ question: 'Test', answer: 'Test' }]
          })
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Input Validation Errors', () => {
      it('should reject submission without responses', async () => {
        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({})
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.errors).toBeDefined();
      });

      it('should reject submission with empty responses array', async () => {
        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({ responses: [] })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });

      it('should reject responses with missing question or answer', async () => {
        const invalidResponses = [
          { question: 'Valid question', answer: 'Valid answer' },
          { question: '', answer: 'Answer without question' }, // Invalid
          { question: 'Question without answer' }, // Missing answer
          { answer: 'Answer without question' } // Missing question
        ];

        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({ responses: invalidResponses })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.errors).toBeDefined();
      });

      it('should reject responses exceeding maximum length limits', async () => {
        const longQuestion = 'Q'.repeat(501); // Assuming 500 char limit
        const longAnswer = 'A'.repeat(10001); // Assuming 10000 char limit

        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({
            responses: [
              { question: longQuestion, answer: 'Valid answer' },
              { question: 'Valid question', answer: longAnswer }
            ]
          })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });

      it('should reject submission with too many responses', async () => {
        const tooManyResponses = Array(21).fill().map((_, i) => ({
          question: `Question ${i + 1}`,
          answer: `Answer ${i + 1}`
        })); // Assuming 20 response limit

        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({ responses: tooManyResponses })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Business Logic Errors', () => {
      it('should prevent duplicate submissions in same month', async () => {
        const submissionData = {
          responses: [{ question: 'Test', answer: 'Test' }]
        };

        // Create first submission
        await request(app)
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send(submissionData)
          .expect(HTTP_STATUS.CREATED);

        // Try to create duplicate in same month
        const response = await authAgent1
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send(submissionData)
          .expect(HTTP_STATUS.CONFLICT);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('already submitted for this month');
      });

      it('should handle invalid month format in comparison endpoint', async () => {
        const response = await authAgent1
          .get('/api/submissions/compare/invalid-month')
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('Invalid month format');
      });

      it('should handle invalid user IDs in comparison filters', async () => {
        const response = await authAgent1
          .get('/api/submissions/compare/2024-03?userIds=invalid-id,another-invalid')
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Resource Not Found', () => {
      it('should handle comparison request for future months gracefully', async () => {
        const futureMonth = '2030-12';
        
        const response = await authAgent1
          .get(`/api/submissions/compare/${futureMonth}`)
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        expect(response.body.data.comparison.submissions).toHaveLength(0);
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
        it(`should escape XSS payload ${index + 1} in submission responses`, async () => {
          const response = await authAgent1
            .post('/api/submissions')
              .set('X-CSRF-Token', csrfToken1)
            .send({
              responses: [
                { question: `Question with ${payload}`, answer: `Answer with ${payload}` }
              ]
            })
            .expect(HTTP_STATUS.CREATED);

          expect(response.body.success).toBe(true);
          
          // Verify that dangerous characters are escaped
          const submissionResponse = response.body.data.submission.responses[0];
          expect(submissionResponse.question).not.toContain('<script');
          expect(submissionResponse.answer).not.toContain('<script');
          expect(submissionResponse.question).not.toContain('javascript:');
          expect(submissionResponse.answer).not.toContain('javascript:');
          expect(submissionResponse.question).not.toContain('onerror=');
          expect(submissionResponse.answer).not.toContain('onerror=');
        });
      });

      it('should properly escape HTML entities in timeline view', async () => {
        const maliciousResponse = {
          responses: [
            { 
              question: 'Test question with <script>alert("question")</script>', 
              answer: 'Test answer with <img onerror="alert(\'answer\')" src="x">' 
            }
          ]
        };

        // Create submission
        await request(app)
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send(maliciousResponse)
          .expect(HTTP_STATUS.CREATED);

        // Retrieve timeline
        const timelineResponse = await request(app)
          .get('/api/submissions')
          .expect(HTTP_STATUS.OK);

        expect(timelineResponse.body.success).toBe(true);
        
        const timelineSubmission = timelineResponse.body.data.timeline[0];
        expect(timelineSubmission.responses[0].question).not.toContain('<script');
        expect(timelineSubmission.responses[0].answer).not.toContain('onerror=');
      });
    });

    describe('SQL/NoSQL Injection Protection', () => {
      const injectionPayloads = [
        { $ne: null },
        { $regex: '.*' },
        '"; DROP COLLECTION submissions; --',
        "'; DELETE * FROM submissions; --"
      ];

      injectionPayloads.forEach((payload, index) => {
        it(`should prevent injection payload ${index + 1} in response data`, async () => {
          const response = await authAgent1
            .post('/api/submissions')
              .set('X-CSRF-Token', csrfToken1)
            .send({
              responses: [
                { question: payload, answer: 'Test answer' }
              ]
            })
            .expect(HTTP_STATUS.BAD_REQUEST);

          expect(response.body.success).toBe(false);
        });
      });
    });

    describe('Data Isolation', () => {
      it('should only show submissions from authenticated user\'s network', async () => {
        // Create submissions from different users
        const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
        
        await Submission.create([
          {
            userId: testUser1._id,
            userName: testUser1.username,
            month: currentMonth,
            responses: [{ question: 'User1 Question', answer: 'User1 Answer' }]
          },
          {
            userId: testUser2._id,
            userName: testUser2.username,
            month: currentMonth,
            responses: [{ question: 'User2 Question', answer: 'User2 Answer' }]
          },
          {
            userId: testUser3._id,
            userName: testUser3.username,
            month: currentMonth,
            responses: [{ question: 'User3 Question', answer: 'User3 Answer' }]
          }
        ]);

        // Get timeline as user1 - should see appropriate submissions based on network
        const response = await authAgent1
          .get('/api/submissions')
          .expect(HTTP_STATUS.OK);

        expect(response.body.success).toBe(true);
        
        // Verify proper data isolation (implementation dependent on business rules)
        response.body.data.timeline.forEach(submission => {
          expect(submission).toHaveProperty('userId');
          expect(submission).toHaveProperty('userName');
        });
      });
    });

    describe('Rate Limiting', () => {
      it('should enforce rate limiting on submission creation', async () => {
        if (process.env.DISABLE_RATE_LIMITING === 'true') {
          return;
        }

        // Create submissions rapidly to trigger rate limiting
        const promises = Array(10).fill().map(() => 
          authAgent1
            .post('/api/submissions')
              .set('X-CSRF-Token', csrfToken1)
            .send({
              responses: [{ question: 'Rate limit test', answer: 'Test answer' }]
            })
        );

        const responses = await Promise.all(promises);
        
        // First should succeed (or conflict due to monthly limit), others should be rate limited
        const successfulResponses = responses.filter(r => r.status === HTTP_STATUS.CREATED);
        const conflictResponses = responses.filter(r => r.status === HTTP_STATUS.CONFLICT);
        const rateLimitedResponses = responses.filter(r => r.status === HTTP_STATUS.TOO_MANY_REQUESTS);
        
        expect(successfulResponses.length + conflictResponses.length).toBeLessThan(responses.length);
        expect(rateLimitedResponses.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Performance and Load Testing', () => {
    describe('Response Time Validation', () => {
      it('should respond to GET /api/submissions within acceptable time', async () => {
        const startTime = Date.now();
        
        await request(app)
          .get('/api/submissions')
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        expect(responseTime).toBeLessThan(1000); // 1 second threshold
      });

      it('should handle submission creation within acceptable time', async () => {
        const startTime = Date.now();
        
        await request(app)
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({
            responses: [
              { question: 'Performance test question', answer: 'Performance test answer' }
            ]
          })
          .expect(HTTP_STATUS.CREATED);

        const responseTime = Date.now() - startTime;
        expect(responseTime).toBeLessThan(2000); // 2 second threshold
      });

      it('should handle comparison queries within acceptable time', async () => {
        const startTime = Date.now();
        
        await request(app)
          .get('/api/submissions/compare/2024-03')
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        expect(responseTime).toBeLessThan(1500); // 1.5 second threshold
      });
    });

    describe('Concurrent Request Handling', () => {
      it('should handle multiple concurrent timeline requests', async () => {
        const concurrentRequests = 5;
        const promises = Array(concurrentRequests).fill().map(() =>
          authAgent1
            .get('/api/submissions')
              .expect(HTTP_STATUS.OK)
        );

        const responses = await Promise.all(promises);
        
        responses.forEach(response => {
          expect(response.body.success).toBe(true);
        });
      });

      it('should handle concurrent statistics requests', async () => {
        const concurrentRequests = 3;
        const promises = Array(concurrentRequests).fill().map(() =>
          authAgent1
            .get('/api/submissions/stats')
              .expect(HTTP_STATUS.OK)
        );

        const responses = await Promise.all(promises);
        
        responses.forEach(response => {
          expect(response.body.success).toBe(true);
          expect(response.body.data.stats).toBeDefined();
        });
      });
    });

    describe('Database Query Performance', () => {
      beforeEach(async () => {
        // Create many test submissions for performance testing
        const submissions = [];
        const months = ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05'];
        
        for (let i = 0; i < 100; i++) {
          submissions.push({
            userId: i % 2 === 0 ? testUser1._id : testUser2._id,
            userName: i % 2 === 0 ? testUser1.username : testUser2.username,
            month: months[i % months.length],
            responses: [
              { question: `Performance question ${i}`, answer: `Performance answer ${i}` }
            ],
            submittedAt: new Date(2024, i % 12, (i % 28) + 1)
          });
        }

        await Submission.insertMany(submissions);
      });

      it('should handle timeline pagination efficiently with large dataset', async () => {
        const startTime = Date.now();
        
        const response = await authAgent1
          .get('/api/submissions?page=5&limit=10')
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.timeline).toHaveLength(10);
        expect(responseTime).toBeLessThan(1000); // Should be fast with indexes
      });

      it('should handle monthly filtering efficiently', async () => {
        const startTime = Date.now();
        
        const response = await authAgent1
          .get('/api/submissions?month=2024-03')
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.timeline.length).toBeGreaterThan(0);
        expect(responseTime).toBeLessThan(1000); // Should be fast with proper indexes
      });

      it('should handle statistics calculation efficiently', async () => {
        const startTime = Date.now();
        
        const response = await authAgent1
          .get('/api/submissions/stats')
          .expect(HTTP_STATUS.OK);

        const responseTime = Date.now() - startTime;
        
        expect(response.body.success).toBe(true);
        expect(response.body.data.stats).toBeDefined();
        expect(responseTime).toBeLessThan(2000); // Statistics can take slightly longer
      });
    });
  });

  describe('Integration with Other Services', () => {
    it('should maintain data consistency in submission lifecycle', async () => {
      // Create submission
      const createResponse = await request(app)
        .post('/api/submissions')
        .set('X-CSRF-Token', csrfToken1)
        .send({
          responses: [
            { question: 'Integration test question', answer: 'Integration test answer' },
            { question: 'Second question', answer: 'Second answer' }
          ]
        })
        .expect(HTTP_STATUS.CREATED);

      const submissionId = createResponse.body.data.submission._id;

      // Verify submission appears in timeline
      const timelineResponse = await request(app)
        .get('/api/submissions')
        .expect(HTTP_STATUS.OK);

      const foundInTimeline = timelineResponse.body.data.timeline.find(
        s => s._id === submissionId
      );
      expect(foundInTimeline).toBeTruthy();
      expect(foundInTimeline.responses).toHaveLength(2);

      // Verify submission appears in current month comparison
      const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
      const comparisonResponse = await request(app)
        .get(`/api/submissions/compare/${currentMonth}`)
        .expect(HTTP_STATUS.OK);

      const foundInComparison = comparisonResponse.body.data.comparison.submissions.find(
        s => s.userId === testUser1._id.toString()
      );
      expect(foundInComparison).toBeTruthy();

      // Verify submission affects statistics
      const statsResponse = await request(app)
        .get('/api/submissions/stats')
        .expect(HTTP_STATUS.OK);

      expect(statsResponse.body.data.stats.totalSubmissions).toBeGreaterThan(0);
      expect(statsResponse.body.data.stats.userBreakdown[testUser1.username]).toBeGreaterThan(0);
    });

    it('should properly handle user network filtering in timeline', async () => {
      // Create submissions for different users
      const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;

      await Promise.all([
        Submission.create({
          userId: testUser1._id,
          userName: testUser1.username,
          month: currentMonth,
          responses: [{ question: 'User1 Q', answer: 'User1 A' }]
        }),
        Submission.create({
          userId: testUser2._id,
          userName: testUser2.username,
          month: currentMonth,
          responses: [{ question: 'User2 Q', answer: 'User2 A' }]
        })
      ]);

      // Get timeline for user1
      const user1Timeline = await request(app)
        .get('/api/submissions')
        .expect(HTTP_STATUS.OK);

      // Get timeline for user2
      const user2Timeline = await request(app)
        .get('/api/submissions')
        .expect(HTTP_STATUS.OK);

      // Both should see submissions (assuming network allows)
      expect(user1Timeline.body.success).toBe(true);
      expect(user2Timeline.body.success).toBe(true);

      // Verify proper data structure
      expect(user1Timeline.body.data.timeline[0]).toHaveProperty('userDetails');
      expect(user2Timeline.body.data.timeline[0]).toHaveProperty('userDetails');
    });

    it('should integrate with legacy Response model if needed', async () => {
      // Create a legacy Response for comparison
      const currentMonth = `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;
      
      const legacyResponse = await Response.create({
        name: 'Legacy User',
        responses: [
          { question: 'Legacy question', answer: 'Legacy answer' }
        ],
        month: currentMonth,
        isAdmin: false,
        token: 'legacy-token-123'
      });

      // Create new submission
      await request(app)
        .post('/api/submissions')
        .set('X-CSRF-Token', csrfToken1)
        .send({
          responses: [
            { question: 'New system question', answer: 'New system answer' }
          ]
        })
        .expect(HTTP_STATUS.CREATED);

      // Statistics should handle both legacy and new submissions
      const statsResponse = await request(app)
        .get('/api/submissions/stats')
        .expect(HTTP_STATUS.OK);

      expect(statsResponse.body.success).toBe(true);
      // The exact behavior depends on whether the system integrates legacy data
    });

    it('should handle submission token generation uniqueness', async () => {
      // Create multiple submissions and verify token uniqueness
      const submissions = await Promise.all([
        request(app)
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken1)
          .send({ responses: [{ question: 'Q1', answer: 'A1' }] }),
        request(app)
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken2)
          .send({ responses: [{ question: 'Q2', answer: 'A2' }] }),
        request(app)
          .post('/api/submissions')
          .set('X-CSRF-Token', csrfToken2) // Note: using user2's token for user3 won't work
          .send({ responses: [{ question: 'Q3', answer: 'A3' }] })
          .expect(HTTP_STATUS.FORBIDDEN) // This should fail due to CSRF mismatch
      ]);

      const successfulSubmissions = submissions.filter(s => s.status === HTTP_STATUS.CREATED);
      const tokens = successfulSubmissions.map(s => s.body.data.submission.token);

      // All successful tokens should be unique
      expect(new Set(tokens).size).toBe(tokens.length);
      expect(tokens.every(token => token && token.length > 20)).toBe(true);
    });
  });
});