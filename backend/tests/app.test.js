const request = require('supertest');
const express = require('express');

// Mock the app setup without starting the server
const mockApp = () => {
  const app = express();
  app.use(express.json());
  
  // Mock basic CORS middleware
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
  });

  // Mock routes for testing
  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  return app;
};

describe('App Configuration', () => {
  let app;

  beforeEach(() => {
    app = mockApp();
  });

  test('should respond to health check', async () => {
    const response = await request(app)
      .get('/health')
      .expect(200);

    expect(response.body).toEqual({ status: 'ok' });
  });

  test('should handle JSON requests', async () => {
    app.post('/test', (req, res) => {
      res.json({ received: req.body });
    });

    const testData = { test: 'data' };
    const response = await request(app)
      .post('/test')
      .send(testData)
      .expect(200);

    expect(response.body.received).toEqual(testData);
  });

  test('should set CORS headers', async () => {
    const response = await request(app)
      .get('/health');

    expect(response.headers['access-control-allow-origin']).toBe('*');
  });
});