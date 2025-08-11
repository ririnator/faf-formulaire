// Performance Tests for Dual Authentication System
const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const User = require('../models/User');
const Response = require('../models/Response');
const TokenGenerator = require('../utils/tokenGenerator');
const SecureLogger = require('../utils/secureLogger');

// Import actual app for realistic testing
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');

describe('Dual Authentication Performance Tests', () => {
  let mongoServer;
  let app;
  let performanceData = {};

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);

    // Setup test app with realistic middleware
    app = express();
    app.use(express.json());
    app.use(session({
      secret: 'perf-test-secret',
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({ mongoUrl: mongoUri }),
      cookie: { maxAge: 300000 } // 5 minutes
    }));

    // Add performance monitoring middleware
    app.use((req, res, next) => {
      req.startTime = process.hrtime.bigint();
      const originalSend = res.send;
      res.send = function(...args) {
        const duration = Number(process.hrtime.bigint() - req.startTime) / 1000000; // Convert to ms
        SecureLogger.logPerformance(`${req.method} ${req.path}`, duration, {
          authMethod: req.authMethod,
          statusCode: res.statusCode
        });
        return originalSend.apply(this, args);
      };
      next();
    });

    // Import routes
    const authRoutes = require('../routes/authRoutes');
    const responseRoutes = require('../routes/responseRoutes');
    app.use('/api/auth', authRoutes);
    app.use('/api/responses', responseRoutes);
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    process.env.FORM_ADMIN_NAME = 'perfadmin';
    performanceData = {};
  });

  describe('Authentication Performance', () => {
    test('should measure registration performance', async () => {
      const users = Array(10).fill(null).map((_, i) => ({
        username: `perfuser${i}`,
        email: `perf${i}@test.com`,
        password: 'PerfPass123!',
        displayName: `Perf User ${i}`
      }));

      const startTime = process.hrtime.bigint();
      
      const promises = users.map(user => 
        request(app)
          .post('/api/auth/register')
          .send(user)
      );

      const results = await Promise.all(promises);
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

      performanceData.registration = {
        totalDuration: duration,
        averagePerRequest: duration / users.length,
        successCount: results.filter(r => r.status === 201).length,
        errorCount: results.filter(r => r.status !== 201).length
      };

      console.log('Registration Performance:', performanceData.registration);

      // Performance assertions
      expect(performanceData.registration.averagePerRequest).toBeLessThan(1000); // < 1 second per registration
      expect(performanceData.registration.successCount).toBe(users.length);
    });

    test('should measure login performance', async () => {
      // Create users first
      const users = Array(10).fill(null).map((_, i) => ({
        username: `loginuser${i}`,
        email: `login${i}@test.com`,
        password: 'LoginPass123!',
        displayName: `Login User ${i}`
      }));

      for (const user of users) {
        await User.create(user);
      }

      const startTime = process.hrtime.bigint();
      
      const promises = users.map(user => 
        request(app)
          .post('/api/auth/login')
          .send({
            login: user.username,
            password: user.password
          })
      );

      const results = await Promise.all(promises);
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

      performanceData.login = {
        totalDuration: duration,
        averagePerRequest: duration / users.length,
        successCount: results.filter(r => r.status === 200).length
      };

      console.log('Login Performance:', performanceData.login);

      // Performance assertions
      expect(performanceData.login.averagePerRequest).toBeLessThan(500); // < 500ms per login
      expect(performanceData.login.successCount).toBe(users.length);
    });

    test('should measure session validation performance', async () => {
      // Create and login a user
      const user = await User.create({
        username: 'sessionuser',
        email: 'session@test.com',
        password: 'SessionPass123!',
        displayName: 'Session User'
      });

      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: 'sessionuser',
        password: 'SessionPass123!'
      });

      // Measure profile access performance
      const iterations = 50;
      const startTime = process.hrtime.bigint();

      const promises = Array(iterations).fill(null).map(() =>
        agent.get('/api/auth/me')
      );

      const results = await Promise.all(promises);
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

      performanceData.sessionValidation = {
        totalDuration: duration,
        averagePerRequest: duration / iterations,
        successCount: results.filter(r => r.status === 200).length
      };

      console.log('Session Validation Performance:', performanceData.sessionValidation);

      // Performance assertions
      expect(performanceData.sessionValidation.averagePerRequest).toBeLessThan(100); // < 100ms per validation
      expect(performanceData.sessionValidation.successCount).toBe(iterations);
    });
  });

  describe('Response Creation Performance', () => {
    test('should measure user auth response performance vs legacy', async () => {
      // Create authenticated user
      const user = await User.create({
        username: 'respuser',
        email: 'resp@test.com',
        password: 'RespPass123!',
        displayName: 'Response User'
      });

      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: 'respuser',
        password: 'RespPass123!'
      });

      const responseData = {
        responses: Array(10).fill(null).map((_, i) => ({
          question: `Question ${i}`,
          answer: `Answer ${i}`
        }))
      };

      // Measure user auth response creation
      const userAuthStart = process.hrtime.bigint();
      const userAuthResult = await agent
        .post('/api/responses')
        .send(responseData);
      const userAuthDuration = Number(process.hrtime.bigint() - userAuthStart) / 1000000;

      // Clear data for legacy test
      await Response.deleteMany({});

      // Measure legacy response creation
      const legacyStart = process.hrtime.bigint();
      const legacyResult = await request(app)
        .post('/api/responses')
        .send({
          name: 'Legacy User',
          ...responseData
        });
      const legacyDuration = Number(process.hrtime.bigint() - legacyStart) / 1000000;

      performanceData.responseTimes = {
        userAuth: userAuthDuration,
        legacy: legacyDuration,
        overhead: userAuthDuration - legacyDuration,
        overheadPercentage: ((userAuthDuration - legacyDuration) / legacyDuration) * 100
      };

      console.log('Response Creation Performance:', performanceData.responseTimes);

      // Performance assertions
      expect(userAuthResult.status).toBe(201);
      expect(legacyResult.status).toBe(201);
      expect(performanceData.responseTimes.overhead).toBeLessThan(200); // < 200ms overhead
      expect(performanceData.responseTimes.overheadPercentage).toBeLessThan(50); // < 50% overhead
    });

    test('should measure admin response performance', async () => {
      const admin = await User.create({
        username: 'adminperf',
        email: 'adminperf@test.com',
        password: 'AdminPerf123!',
        displayName: 'Admin Perf',
        role: 'admin'
      });

      const agent = request.agent(app);
      await agent.post('/api/auth/login').send({
        login: 'adminperf',
        password: 'AdminPerf123!'
      });

      const responseData = {
        responses: [{ question: 'Admin Q', answer: 'Admin A' }]
      };

      // Measure admin response with atomic operation
      const startTime = process.hrtime.bigint();
      const result = await agent
        .post('/api/responses')
        .send(responseData);
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

      performanceData.adminResponse = {
        duration,
        status: result.status
      };

      console.log('Admin Response Performance:', performanceData.adminResponse);

      // Performance assertions
      expect(result.status).toBe(201);
      expect(performanceData.adminResponse.duration).toBeLessThan(1000); // < 1 second for atomic operation
    });
  });

  describe('Migration Performance', () => {
    test('should measure migration performance with varying data sizes', async () => {
      const testCases = [
        { responseCount: 1, name: 'Small Migration' },
        { responseCount: 10, name: 'Medium Migration' },
        { responseCount: 50, name: 'Large Migration' }
      ];

      for (const testCase of testCases) {
        // Clear previous test data
        await Response.deleteMany({});

        const legacyToken = TokenGenerator.generateTestToken(32);

        // Create legacy responses
        const legacyResponses = Array(testCase.responseCount).fill(null).map((_, i) => ({
          name: 'Migration User',
          responses: [{ question: `Q${i}`, answer: `A${i}` }],
          month: `2024-${String(i + 1).padStart(2, '0')}`,
          token: i === 0 ? legacyToken : TokenGenerator.generateTestToken(32),
          authMethod: 'token'
        }));

        await Response.insertMany(legacyResponses);

        // Measure migration performance
        const startTime = process.hrtime.bigint();
        
        const result = await request(app)
          .post('/api/auth/register')
          .send({
            username: `migrateuser${testCase.responseCount}`,
            email: `migrate${testCase.responseCount}@test.com`,
            password: 'MigratePass123!',
            displayName: 'Migration User',
            migrateToken: legacyToken
          });

        const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

        performanceData[`migration_${testCase.responseCount}`] = {
          duration,
          responseCount: testCase.responseCount,
          status: result.status,
          migratedCount: result.body.migratedCount || 0
        };

        console.log(`${testCase.name} Performance:`, performanceData[`migration_${testCase.responseCount}`]);

        // Performance assertions
        expect(result.status).toBe(201);
        expect(duration).toBeLessThan(testCase.responseCount * 100); // Linear scaling assumption
      }
    });

    test('should measure concurrent migration performance', async () => {
      // Create multiple legacy users with responses
      const migrationUsers = Array(5).fill(null).map((_, i) => {
        const token = TokenGenerator.generateTestToken(32);
        return {
          name: `ConcurrentUser${i}`,
          token,
          responses: Array(3).fill(null).map((_, j) => ({
            name: `ConcurrentUser${i}`,
            responses: [{ question: `Q${j}`, answer: `A${j}` }],
            month: `2024-0${j + 1}`,
            token: j === 0 ? token : TokenGenerator.generateTestToken(32),
            authMethod: 'token'
          }))
        };
      });

      // Insert all legacy responses
      const allResponses = migrationUsers.flatMap(user => user.responses);
      await Response.insertMany(allResponses);

      // Concurrent migrations
      const startTime = process.hrtime.bigint();
      
      const promises = migrationUsers.map((user, i) =>
        request(app)
          .post('/api/auth/register')
          .send({
            username: `concurrent${i}`,
            email: `concurrent${i}@test.com`,
            password: 'ConcurrentPass123!',
            displayName: user.name,
            migrateToken: user.token
          })
      );

      const results = await Promise.all(promises);
      const duration = Number(process.hrtime.bigint() - startTime) / 1000000;

      performanceData.concurrentMigration = {
        totalDuration: duration,
        averagePerMigration: duration / migrationUsers.length,
        successCount: results.filter(r => r.status === 201).length,
        totalMigrated: results.reduce((sum, r) => sum + (r.body.migratedCount || 0), 0)
      };

      console.log('Concurrent Migration Performance:', performanceData.concurrentMigration);

      // Performance assertions
      expect(performanceData.concurrentMigration.successCount).toBe(migrationUsers.length);
      expect(performanceData.concurrentMigration.averagePerMigration).toBeLessThan(2000); // < 2 seconds per concurrent migration
    });
  });

  describe('Database Performance', () => {
    test('should measure query performance with hybrid indexes', async () => {
      // Create mixed data (user auth + legacy)
      const users = Array(20).fill(null).map((_, i) => ({
        username: `dbuser${i}`,
        email: `db${i}@test.com`,
        password: 'DbPass123!',
        displayName: `DB User ${i}`
      }));

      const createdUsers = await User.insertMany(users);

      const responses = [
        // User auth responses
        ...createdUsers.slice(0, 10).map((user, i) => ({
          userId: user._id,
          responses: [{ question: `Q${i}`, answer: `A${i}` }],
          month: '2024-01',
          isAdmin: false,
          authMethod: 'user'
        })),
        // Legacy responses
        ...Array(10).fill(null).map((_, i) => ({
          name: `Legacy${i}`,
          responses: [{ question: `LQ${i}`, answer: `LA${i}` }],
          month: '2024-01',
          token: TokenGenerator.generateTestToken(32),
          authMethod: 'token'
        }))
      ];

      await Response.insertMany(responses);

      // Measure different query patterns
      const queryTests = [
        {
          name: 'User auth query',
          query: () => Response.find({ authMethod: 'user', month: '2024-01' })
        },
        {
          name: 'Legacy query',
          query: () => Response.find({ authMethod: 'token', month: '2024-01' })
        },
        {
          name: 'Mixed month query',
          query: () => Response.find({ month: '2024-01' })
        },
        {
          name: 'Admin query',
          query: () => Response.find({ isAdmin: true, month: '2024-01' })
        }
      ];

      for (const test of queryTests) {
        const iterations = 10;
        const startTime = process.hrtime.bigint();
        
        const promises = Array(iterations).fill(null).map(() => test.query());
        await Promise.all(promises);
        
        const duration = Number(process.hrtime.bigint() - startTime) / 1000000;
        
        performanceData[`query_${test.name.replace(' ', '_')}`] = {
          totalDuration: duration,
          averagePerQuery: duration / iterations
        };

        console.log(`${test.name} Performance:`, performanceData[`query_${test.name.replace(' ', '_')}`]);

        // Performance assertions
        expect(duration / iterations).toBeLessThan(50); // < 50ms per query on average
      }
    });

    test('should measure memory usage patterns', async () => {
      const initialMemory = process.memoryUsage();
      
      // Create substantial test data
      const users = Array(100).fill(null).map((_, i) => ({
        username: `memuser${i}`,
        email: `mem${i}@test.com`,
        password: 'MemPass123!',
        displayName: `Mem User ${i}`
      }));

      await User.insertMany(users);
      
      const midMemory = process.memoryUsage();
      
      // Create many responses
      const responses = Array(500).fill(null).map((_, i) => ({
        name: `MemUser${i}`,
        responses: Array(5).fill(null).map((_, j) => ({
          question: `Q${j}`,
          answer: `A${j}`.repeat(100) // Larger answers
        })),
        month: '2024-01',
        token: TokenGenerator.generateTestToken(32),
        authMethod: 'token'
      }));

      await Response.insertMany(responses);
      
      const finalMemory = process.memoryUsage();

      performanceData.memoryUsage = {
        initial: initialMemory.heapUsed,
        afterUsers: midMemory.heapUsed,
        final: finalMemory.heapUsed,
        userDataOverhead: midMemory.heapUsed - initialMemory.heapUsed,
        responseDataOverhead: finalMemory.heapUsed - midMemory.heapUsed
      };

      console.log('Memory Usage:', performanceData.memoryUsage);

      // Memory assertions
      const memoryGrowthMB = (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024;
      expect(memoryGrowthMB).toBeLessThan(100); // < 100MB growth for test data
    });
  });

  describe('Performance Summary', () => {
    test('should generate performance report', () => {
      console.log('\n=== DUAL AUTHENTICATION PERFORMANCE REPORT ===');
      console.log(JSON.stringify(performanceData, null, 2));
      
      // Verify we have performance data
      expect(Object.keys(performanceData).length).toBeGreaterThan(0);
      
      // Performance summary assertions
      if (performanceData.registration) {
        expect(performanceData.registration.averagePerRequest).toBeLessThan(2000);
      }
      
      if (performanceData.login) {
        expect(performanceData.login.averagePerRequest).toBeLessThan(1000);
      }
    });
  });
});