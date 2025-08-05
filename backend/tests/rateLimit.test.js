const request = require('supertest');
const express = require('express');
const rateLimit = require('express-rate-limit');
const responseRoutes = require('../routes/responseRoutes');

// Create test app with rate limiting
const createRateLimitedApp = () => {
  const app = express();
  app.use(express.json());

  // Create rate limiter matching production config
  const formLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 3,                     // 3 requests per window
    message: { message: "Trop de soumissions. Réessaie dans 15 minutes." },
    standardHeaders: true,
    legacyHeaders: false,
  });

  app.use('/api/response', formLimiter, responseRoutes);
  return app;
};

describe('Rate Limiting', () => {
  let app;

  beforeEach(() => {
    app = createRateLimitedApp();
    // Reset rate limit store before each test
    jest.clearAllMocks();
  });

  const validResponseData = {
    name: 'TestUser',
    responses: [
      { question: 'Test question 1', answer: 'Test answer 1' },
      { question: 'Test question 2', answer: 'Test answer 2' }
    ]
  };

  describe('Rate limit enforcement', () => {
    test('should allow up to 3 requests within 15 minutes', async () => {
      // First request - should succeed
      await request(app)
        .post('/api/response')
        .send(validResponseData)
        .expect(201);

      // Second request - should succeed
      await request(app)
        .post('/api/response')
        .send({ ...validResponseData, name: 'TestUser2' })
        .expect(201);

      // Third request - should succeed
      await request(app)
        .post('/api/response')
        .send({ ...validResponseData, name: 'TestUser3' })
        .expect(201);
    });

    test('should block 4th request within 15 minutes', async () => {
      // Make 3 successful requests
      for (let i = 1; i <= 3; i++) {
        await request(app)
          .post('/api/response')
          .send({ ...validResponseData, name: `TestUser${i}` })
          .expect(201);
      }

      // 4th request should be rate limited
      const response = await request(app)
        .post('/api/response')
        .send({ ...validResponseData, name: 'TestUser4' })
        .expect(429);

      expect(response.body.message).toBe('Trop de soumissions. Réessaie dans 15 minutes.');
    });

    test('should include rate limit headers', async () => {
      const response = await request(app)
        .post('/api/response')
        .send(validResponseData)
        .expect(201);

      expect(response.headers).toHaveProperty('ratelimit-limit');
      expect(response.headers).toHaveProperty('ratelimit-remaining');
      expect(response.headers).toHaveProperty('ratelimit-reset');
    });

    test('should have rate limit configuration', async () => {
      // Test that rate limit headers are present
      const response = await request(app)
        .post('/api/response')
        .send(validResponseData)
        .expect(201);

      expect(response.headers).toHaveProperty('ratelimit-limit');
      expect(response.headers).toHaveProperty('ratelimit-remaining');
    });
  });

  describe('Rate limit scope', () => {
    test('should only apply rate limit to protected endpoints', async () => {
      // Create simple test app
      const testApp = express();
      testApp.use(express.json());
      
      const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 2,
        message: { message: "Rate limited" }
      });

      testApp.use('/protected', limiter, (req, res) => 
        res.json({ message: 'protected' }));
      testApp.get('/public', (req, res) => 
        res.json({ message: 'public' }));

      // Hit rate limit on protected endpoint
      await request(testApp).get('/protected').expect(200);
      await request(testApp).get('/protected').expect(200);
      await request(testApp).get('/protected').expect(429);

      // Public endpoint should still work
      await request(testApp).get('/public').expect(200);
    });
  });

  describe('Rate limit error handling', () => {
    test('should return proper error format when rate limited', async () => {
      // Simple rate limit test
      const testApp = express();
      testApp.use(express.json());
      
      const limiter = rateLimit({
        windowMs: 60000,
        max: 1,
        message: { message: "Rate limited" }
      });

      testApp.post('/test', limiter, (req, res) => res.json({ ok: true }));

      // First request succeeds
      await request(testApp)
        .post('/test')
        .send({})
        .expect(200);

      // Second request is rate limited
      const response = await request(testApp)
        .post('/test')
        .send({})
        .expect(429);

      expect(response.body).toHaveProperty('message');
      expect(response.headers['content-type']).toMatch(/json/);
    });
  });
});