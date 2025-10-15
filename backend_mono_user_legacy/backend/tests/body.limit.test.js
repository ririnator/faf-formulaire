const request = require('supertest');
const express = require('express');

describe('Body Parser Limit Configuration', () => {
  test('should verify 10MB limit is configured in app', () => {
    // This test verifies that our app.js has the correct configuration
    const appContent = require('fs').readFileSync(require('path').join(__dirname, '../app.js'), 'utf8');
    
    // Check that 10mb limit is set, not 50mb
    expect(appContent).toContain("limit: '10mb'");
    expect(appContent).not.toContain("limit: '50mb'");
  });

  test('should handle normal sized JSON requests', async () => {
    const app = express();
    app.use(express.json({ limit: '10mb' }));
    
    app.post('/test', (req, res) => {
      res.json({ received: true, size: JSON.stringify(req.body).length });
    });

    const normalData = {
      name: 'Test User',
      data: 'A'.repeat(1000) // 1KB of data
    };

    const response = await request(app)
      .post('/test')
      .send(normalData)
      .expect(200);

    expect(response.body.received).toBe(true);
    expect(response.body.size).toBeGreaterThan(0);
  });

  test('should handle moderately large JSON requests', async () => {
    const app = express();
    app.use(express.json({ limit: '10mb' }));
    
    app.post('/test', (req, res) => {
      res.json({ received: true, size: JSON.stringify(req.body).length });
    });

    const largeData = {
      name: 'Large Test User',
      data: 'B'.repeat(100000) // 100KB of data - well within 10MB
    };

    const response = await request(app)
      .post('/test')
      .send(largeData)
      .expect(200);

    expect(response.body.received).toBe(true);
    expect(response.body.size).toBeGreaterThan(100000);
  });

  test('should configure Express built-in parsers correctly', () => {
    // Verify we're using Express built-in parsers, not body-parser package
    const appContent = require('fs').readFileSync(require('path').join(__dirname, '../app.js'), 'utf8');
    
    // Should use express.json(), not bodyParser.json()
    expect(appContent).toContain('express.json(');
    expect(appContent).toContain('express.urlencoded(');
    expect(appContent).not.toContain('bodyParser.json(');
    expect(appContent).not.toContain('bodyParser.urlencoded(');
  });
});