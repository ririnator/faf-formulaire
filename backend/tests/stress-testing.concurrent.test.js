// Stress Testing for High-Concurrency Migration Scenarios
const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const app = require('../app');
const User = require('../models/User');
const Response = require('../models/Response');
const TokenGenerator = require('../utils/tokenGenerator');

describe('🚀 High-Concurrency Migration Stress Tests', () => {
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const mongoUri = mongoServer.getUri();
    await mongoose.connect(mongoUri);
  }, 30000);

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  }, 30000);

  beforeEach(async () => {
    await User.deleteMany({});
    await Response.deleteMany({});
    process.env.FORM_ADMIN_NAME = 'stressadmin';
  });

  describe('⚡ Concurrent User Registration with Migration', () => {
    test('should handle 100 simultaneous registrations with migrations', async () => {
      console.log('🏁 Starting 100 concurrent registration stress test...');
      const startTime = Date.now();

      // Pre-create legacy data for migration
      const legacyData = Array(100).fill(null).map((_, i) => {
        const token = TokenGenerator.generateTestToken(32);
        return {
          responses: [{
            name: `Legacy User ${i}`,
            responses: [
              { question: `Q${i}1`, answer: `A${i}1` },
              { question: `Q${i}2`, answer: `A${i}2` }
            ],
            month: `2024-${String((i % 12) + 1).padStart(2, '0')}`,
            token,
            authMethod: 'token'
          }],
          token
        };
      });

      // Insert legacy responses
      const legacyResponses = legacyData.map(d => d.responses[0]);
      await Response.insertMany(legacyResponses);

      // Create concurrent registration requests
      const registrationPromises = legacyData.map((data, i) => {
        const userData = {
          username: `stressuser${i}`,
          email: `stress${i}@test.com`,
          password: 'StressTest123!',
          migrateToken: data.token
        };

        return request(app)
          .post('/api/auth/register')
          .send(userData)
          .timeout(30000);
      });

      // Execute all requests concurrently
      const results = await Promise.allSettled(registrationPromises);
      const duration = Date.now() - startTime;

      // Analyze results
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.status === 201);
      const failed = results.filter(r => r.status === 'rejected' || r.value.status !== 201);
      const rateLimited = results.filter(r => r.status === 'fulfilled' && r.value.status === 429);
      
      console.log(`✅ Completed in ${duration}ms`);
      console.log(`✅ Successful: ${successful.length}`);
      console.log(`❌ Failed: ${failed.length}`);
      console.log(`⏸️  Rate Limited: ${rateLimited.length}`);

      // Verify database integrity
      const userCount = await User.countDocuments();
      const migratedResponseCount = await Response.countDocuments({ authMethod: 'user' });
      const legacyResponseCount = await Response.countDocuments({ authMethod: 'token' });

      console.log(`👥 Users created: ${userCount}`);
      console.log(`🔄 Responses migrated: ${migratedResponseCount}`);
      console.log(`🏷️  Legacy responses remaining: ${legacyResponseCount}`);

      // Performance assertions
      expect(successful.length).toBeGreaterThan(50); // At least 50% success under stress
      expect(userCount).toBe(successful.length);
      expect(duration).toBeLessThan(60000); // Complete within 60 seconds
      expect(migratedResponseCount).toBeGreaterThan(0); // Some migrations occurred
      
    }, 120000); // 2 minute timeout

    test('should handle concurrent admin registrations with conflict resolution', async () => {
      console.log('👑 Testing concurrent admin registration conflicts...');
      
      // Create legacy admin response
      await Response.create({
        name: 'stressadmin',
        responses: [{ question: 'Admin Q', answer: 'Admin A' }],
        month: new Date().toISOString().slice(0, 7),
        isAdmin: true,
        authMethod: 'token'
      });

      // Create multiple admin users trying to register simultaneously
      const adminPromises = Array(20).fill(null).map((_, i) => {
        const adminData = {
          username: `admin${i}`,
          email: `admin${i}@test.com`,
          password: 'AdminTest123!',
          role: 'admin'
        };

        return request(app)
          .post('/api/auth/register')
          .send(adminData)
          .timeout(15000);
      });

      const results = await Promise.allSettled(adminPromises);
      
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.status === 201);
      const conflicts = results.filter(r => r.status === 'fulfilled' && r.value.status === 409);

      console.log(`✅ Admin registrations successful: ${successful.length}`);
      console.log(`⚠️  Admin registrations conflicted: ${conflicts.length}`);

      // Verify only one admin response per month constraint is maintained
      const adminResponsesCount = await Response.countDocuments({ 
        isAdmin: true, 
        month: new Date().toISOString().slice(0, 7)
      });
      
      expect(adminResponsesCount).toBe(1); // Constraint maintained
      expect(successful.length).toBeGreaterThan(0); // Some admins registered
      
    }, 60000);
  });

  describe('🔄 Concurrent Response Creation Stress', () => {
    test('should handle 50 users creating responses simultaneously', async () => {
      console.log('📝 Testing concurrent response creation...');
      
      // Pre-create users
      const users = await User.insertMany(
        Array(50).fill(null).map((_, i) => ({
          username: `respuser${i}`,
          email: `resp${i}@test.com`,
          password: 'ResponseTest123!'
        }))
      );

      // Create authenticated agents
      const agents = await Promise.all(
        users.map(async (user, i) => {
          const agent = request.agent(app);
          await agent
            .post('/api/auth/login')
            .send({
              login: `respuser${i}`,
              password: 'ResponseTest123!'
            });
          return agent;
        })
      );

      const startTime = Date.now();

      // Concurrent response creation
      const responsePromises = agents.map((agent, i) => {
        const responseData = {
          responses: [
            { question: `Stress Q${i}`, answer: `Stress A${i}` }
          ]
        };

        return agent
          .post('/api/responses')
          .send(responseData)
          .timeout(15000);
      });

      const results = await Promise.allSettled(responsePromises);
      const duration = Date.now() - startTime;
      
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.status === 201);
      const duplicates = results.filter(r => r.status === 'fulfilled' && r.value.status === 409);

      console.log(`✅ Responses created: ${successful.length}`);
      console.log(`⚠️  Duplicate responses: ${duplicates.length}`);
      console.log(`⏱️  Duration: ${duration}ms`);

      // Verify database integrity
      const totalResponses = await Response.countDocuments({ authMethod: 'user' });
      expect(totalResponses).toBe(successful.length);
      expect(duration).toBeLessThan(30000); // Within 30 seconds
      
    }, 60000);

    test('should stress test migration with concurrent legacy and user responses', async () => {
      console.log('🔀 Testing mixed concurrent legacy and user responses...');
      
      // Create some users
      const users = await User.insertMany(
        Array(25).fill(null).map((_, i) => ({
          username: `mixuser${i}`,
          email: `mix${i}@test.com`,
          password: 'MixTest123!'
        }))
      );

      const agents = await Promise.all(
        users.slice(0, 25).map(async (user, i) => {
          const agent = request.agent(app);
          await agent.post('/api/auth/login').send({
            login: `mixuser${i}`,
            password: 'MixTest123!'
          });
          return agent;
        })
      );

      const startTime = Date.now();

      // Mixed concurrent requests - 25 user auth, 25 legacy token
      const mixedPromises = [
        // User authenticated responses
        ...agents.map((agent, i) => 
          agent.post('/api/responses').send({
            responses: [{ question: `User Q${i}`, answer: `User A${i}` }]
          })
        ),
        // Legacy token responses
        ...Array(25).fill(null).map((_, i) => 
          request(app).post('/api/responses').send({
            name: `Legacy ${i}`,
            responses: [{ question: `Legacy Q${i}`, answer: `Legacy A${i}` }]
          })
        )
      ];

      const results = await Promise.allSettled(mixedPromises);
      const duration = Date.now() - startTime;

      const successful = results.filter(r => r.status === 'fulfilled' && r.value.status === 201);
      
      console.log(`✅ Mixed responses created: ${successful.length}/50`);
      console.log(`⏱️  Duration: ${duration}ms`);

      // Verify both auth methods work simultaneously
      const userResponses = await Response.countDocuments({ authMethod: 'user' });
      const legacyResponses = await Response.countDocuments({ authMethod: 'token' });

      console.log(`👤 User auth responses: ${userResponses}`);
      console.log(`🏷️  Token auth responses: ${legacyResponses}`);

      expect(userResponses + legacyResponses).toBe(successful.length);
      expect(userResponses).toBeGreaterThan(0); // Some user responses
      expect(legacyResponses).toBeGreaterThan(0); // Some legacy responses
      
    }, 60000);
  });

  describe('📊 Database Performance Under Load', () => {
    test('should maintain query performance under concurrent load', async () => {
      console.log('🔍 Testing query performance under load...');
      
      // Pre-populate database with mixed data
      const users = await User.insertMany(
        Array(100).fill(null).map((_, i) => ({
          username: `perfuser${i}`,
          email: `perf${i}@test.com`,
          password: 'PerfTest123!'
        }))
      );

      const responses = Array(500).fill(null).map((_, i) => {
        const isUser = i % 2 === 0;
        const baseResponse = {
          responses: [{ question: `Q${i}`, answer: `A${i}` }],
          month: `2024-${String((i % 12) + 1).padStart(2, '0')}`,
          authMethod: isUser ? 'user' : 'token'
        };

        if (isUser) {
          baseResponse.userId = users[i % users.length]._id;
        } else {
          baseResponse.name = `Token User ${i}`;
          baseResponse.token = TokenGenerator.generateTestToken(32);
        }

        return baseResponse;
      });

      await Response.insertMany(responses);

      // Concurrent query load test
      const queryPromises = Array(100).fill(null).map(async (_, i) => {
        const isTokenQuery = i % 2 === 0;
        const startTime = Date.now();
        
        let result;
        if (isTokenQuery) {
          // Token lookup query
          result = await Response.findOne({ 
            token: { $exists: true },
            authMethod: 'token'
          });
        } else {
          // User lookup query
          result = await Response.findOne({
            userId: users[i % users.length]._id,
            authMethod: 'user'
          });
        }
        
        return {
          type: isTokenQuery ? 'token' : 'user',
          duration: Date.now() - startTime,
          found: !!result
        };
      });

      const queryResults = await Promise.all(queryPromises);
      
      const avgDuration = queryResults.reduce((sum, r) => sum + r.duration, 0) / queryResults.length;
      const maxDuration = Math.max(...queryResults.map(r => r.duration));
      const tokenQueries = queryResults.filter(r => r.type === 'token');
      const userQueries = queryResults.filter(r => r.type === 'user');

      console.log(`📊 Query Performance Results:`);
      console.log(`   Average duration: ${avgDuration.toFixed(2)}ms`);
      console.log(`   Max duration: ${maxDuration}ms`);
      console.log(`   Token queries avg: ${(tokenQueries.reduce((sum, r) => sum + r.duration, 0) / tokenQueries.length).toFixed(2)}ms`);
      console.log(`   User queries avg: ${(userQueries.reduce((sum, r) => sum + r.duration, 0) / userQueries.length).toFixed(2)}ms`);

      // Performance assertions
      expect(avgDuration).toBeLessThan(50); // Average under 50ms
      expect(maxDuration).toBeLessThan(200); // No query over 200ms
      
    }, 60000);

    test('should handle index stress under concurrent operations', async () => {
      console.log('📇 Testing index performance under stress...');
      
      const startTime = Date.now();
      
      // Create concurrent operations that stress different indexes
      const operations = [
        // Admin constraint checks (month + isAdmin index)
        ...Array(20).fill(null).map(() =>
          Response.findOne({ 
            month: new Date().toISOString().slice(0, 7),
            isAdmin: true 
          })
        ),
        // Token lookups (token index)
        ...Array(30).fill(null).map(() =>
          Response.findOne({ token: TokenGenerator.generateTestToken(32) })
        ),
        // User lookups (userId + month index) 
        ...Array(25).fill(null).map(() =>
          Response.find({ 
            userId: new mongoose.Types.ObjectId(),
            month: '2024-01'
          })
        ),
        // Date range queries (createdAt index)
        ...Array(25).fill(null).map(() =>
          Response.find({
            createdAt: { 
              $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) 
            }
          })
        )
      ];

      const results = await Promise.allSettled(operations);
      const duration = Date.now() - startTime;
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      
      console.log(`📊 Index Stress Results:`);
      console.log(`   Total operations: ${operations.length}`);
      console.log(`   Successful: ${successful}`);
      console.log(`   Failed: ${failed}`);
      console.log(`   Duration: ${duration}ms`);
      console.log(`   Avg per operation: ${(duration / operations.length).toFixed(2)}ms`);

      expect(successful).toBe(operations.length); // All operations should succeed
      expect(duration).toBeLessThan(10000); // Complete within 10 seconds
      
    }, 30000);
  });

  describe('⚠️ Error Handling Under Stress', () => {
    test('should gracefully handle database errors during concurrent operations', async () => {
      console.log('💥 Testing error handling under concurrent load...');
      
      // Create some users first
      const users = Array(10).fill(null).map((_, i) => ({
        username: `erroruser${i}`,
        email: `error${i}@test.com`,
        password: 'ErrorTest123!'
      }));
      
      await User.insertMany(users);
      
      // Mock intermittent database errors
      const originalSave = Response.prototype.save;
      let saveCallCount = 0;
      
      Response.prototype.save = async function(options) {
        saveCallCount++;
        // Fail every 5th save operation
        if (saveCallCount % 5 === 0) {
          throw new Error('Simulated database error');
        }
        return originalSave.call(this, options);
      };

      // Concurrent operations with simulated errors
      const operations = Array(50).fill(null).map((_, i) =>
        request(app)
          .post('/api/responses')
          .send({
            name: `Error Test ${i}`,
            responses: [{ question: `Q${i}`, answer: `A${i}` }]
          })
          .timeout(10000)
      );

      const results = await Promise.allSettled(operations);
      
      // Restore original save method
      Response.prototype.save = originalSave;
      
      const successful = results.filter(r => 
        r.status === 'fulfilled' && r.value.status === 201
      ).length;
      
      const errors = results.filter(r => 
        r.status === 'fulfilled' && r.value.status === 500
      ).length;

      console.log(`✅ Successful operations: ${successful}`);
      console.log(`❌ Error responses: ${errors}`);
      console.log(`🔄 Expected errors: ~${Math.floor(operations.length / 5)}`);

      // Verify system gracefully handled errors
      expect(successful + errors).toBe(operations.length);
      expect(errors).toBeGreaterThan(5); // Some errors should have occurred
      expect(successful).toBeGreaterThan(30); // But most should succeed
      
    }, 60000);
  });
});