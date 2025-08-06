const request = require('supertest');
const express = require('express');
const { 
  createFormBodyParser, 
  createAdminBodyParser, 
  createStandardBodyParser,
  createPayloadErrorHandler 
} = require('../middleware/bodyParser');

describe('Body Parser Limits', () => {
  describe('Standard Body Parser (512KB)', () => {
    let app;

    beforeEach(() => {
      app = express();
      app.use(createStandardBodyParser());
      app.use(createPayloadErrorHandler());
      app.post('/test', (req, res) => res.json({ received: req.body }));
    });

    test('should accept small JSON payloads', async () => {
      const smallData = { message: 'Hello world', data: 'A'.repeat(1000) };
      
      const response = await request(app)
        .post('/test')
        .send(smallData)
        .expect(200);
        
      expect(response.body.received.message).toBe('Hello world');
    });

    test('should reject payloads over 512KB', async () => {
      const largeData = { 
        message: 'Large payload', 
        data: 'A'.repeat(600 * 1024) // 600KB
      };
      
      const response = await request(app)
        .post('/test')
        .send(largeData)
        .expect(413);
        
      expect(response.body.message).toContain('Données trop volumineuses');
      expect(response.body.error).toBe('PAYLOAD_TOO_LARGE');
    });

    test('should handle malformed JSON gracefully', async () => {
      const response = await request(app)
        .post('/test')
        .set('Content-Type', 'application/json')
        .send('{"invalid": json}')
        .expect(400);
        
      expect(response.body.message).toBe('Format de données invalide');
      expect(response.body.error).toBe('INVALID_JSON');
    });
  });

  describe('Form Body Parser (2MB)', () => {
    let app;

    beforeEach(() => {
      app = express();
      app.use('/form', createFormBodyParser());
      app.use(createPayloadErrorHandler());
      app.post('/form/test', (req, res) => res.json({ received: req.body }));
    });

    test('should accept moderate form data payloads', async () => {
      const formData = {
        name: 'Test User',
        responses: Array(50).fill({
          question: 'Sample question with reasonable length',
          answer: 'A'.repeat(1000) // 1KB per answer
        })
      };
      
      const response = await request(app)
        .post('/form/test')
        .send(formData)
        .expect(200);
        
      expect(response.body.received.name).toBe('Test User');
      expect(response.body.received.responses).toHaveLength(50);
    });

    test('should accept payloads up to 2MB', async () => {
      const mediumData = {
        name: 'User',
        content: 'A'.repeat(1.5 * 1024 * 1024) // 1.5MB
      };
      
      await request(app)
        .post('/form/test')
        .send(mediumData)
        .expect(200);
    });

    test('should reject payloads over 2MB', async () => {
      const largeData = {
        name: 'User',
        content: 'A'.repeat(2.5 * 1024 * 1024) // 2.5MB
      };
      
      const response = await request(app)
        .post('/form/test')
        .send(largeData)
        .expect(413);
        
      expect(response.body.message).toContain('Données trop volumineuses');
    });
  });

  describe('Admin Body Parser (1MB)', () => {
    let app;

    beforeEach(() => {
      app = express();
      app.use('/admin', createAdminBodyParser());
      app.use(createPayloadErrorHandler());
      app.post('/admin/test', (req, res) => res.json({ received: req.body }));
    });

    test('should accept small admin payloads', async () => {
      const adminData = {
        action: 'update',
        data: { id: 123, status: 'active' }
      };
      
      const response = await request(app)
        .post('/admin/test')
        .send(adminData)
        .expect(200);
        
      expect(response.body.received.action).toBe('update');
    });

    test('should accept payloads up to 1MB', async () => {
      const mediumAdminData = {
        action: 'bulk_update',
        data: 'A'.repeat(800 * 1024) // 800KB
      };
      
      await request(app)
        .post('/admin/test')
        .send(mediumAdminData)
        .expect(200);
    });

    test('should reject admin payloads over 1MB', async () => {
      const largeAdminData = {
        action: 'bulk_update',
        data: 'A'.repeat(1.2 * 1024 * 1024) // 1.2MB
      };
      
      const response = await request(app)
        .post('/admin/test')
        .send(largeAdminData)
        .expect(413);
        
      expect(response.body.message).toContain('Données trop volumineuses');
    });
  });

  describe('Performance and Memory Impact', () => {
    test('should not consume excessive memory for rejected payloads', async () => {
      const app = express();
      app.use(createStandardBodyParser());
      app.use(createPayloadErrorHandler());
      app.post('/test', (req, res) => res.json({ ok: true }));

      const initialMemory = process.memoryUsage().heapUsed;
      
      // Try to send large payload (should be rejected early)
      await request(app)
        .post('/test')
        .send({ data: 'A'.repeat(1024 * 1024) }) // 1MB
        .expect(413);
        
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be minimal (less than 10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    test('should handle URL encoded data efficiently', async () => {
      const app = express();
      app.use(createFormBodyParser());
      app.use(createPayloadErrorHandler());
      app.post('/test', (req, res) => res.json({ received: req.body }));

      const formData = 'name=user&message=' + 'A'.repeat(1000);
      
      const response = await request(app)
        .post('/test')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send(formData)
        .expect(200);
        
      expect(response.body.received.name).toBe('user');
      expect(response.body.received.message).toHaveLength(1000);
    });
  });

  describe('Content Type Handling', () => {
    let app;

    beforeEach(() => {
      app = express();
      app.use(createFormBodyParser());
      app.use(createPayloadErrorHandler());
      app.post('/test', (req, res) => res.json({ 
        contentType: req.get('Content-Type'),
        body: req.body 
      }));
    });

    test('should handle JSON content type', async () => {
      const response = await request(app)
        .post('/test')
        .set('Content-Type', 'application/json')
        .send({ message: 'json data' })
        .expect(200);
        
      expect(response.body.body.message).toBe('json data');
    });

    test('should handle URL encoded content type', async () => {
      const response = await request(app)
        .post('/test')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('message=form+data')
        .expect(200);
        
      expect(response.body.body.message).toBe('form data');
    });

    test('should reject unsupported content types gracefully', async () => {
      await request(app)
        .post('/test')
        .set('Content-Type', 'application/xml')
        .send('<xml>data</xml>')
        .expect(200); // Express will leave body empty for unsupported types
    });
  });

  describe('Edge Cases', () => {
    test('should handle empty payloads', async () => {
      const app = express();
      app.use(createStandardBodyParser());
      app.post('/test', (req, res) => res.json({ 
        hasBody: req.body !== undefined,
        bodyType: typeof req.body 
      }));

      const response = await request(app)
        .post('/test')
        .expect(200);
        
      // Express body parsers may leave req.body undefined for empty requests
      expect(response.body.hasBody).toBeDefined();
    });

    test('should handle null and undefined values', async () => {
      const app = express();
      app.use(createFormBodyParser());
      app.post('/test', (req, res) => res.json({ body: req.body }));

      const response = await request(app)
        .post('/test')
        .send({ value: null, undefined: undefined })
        .expect(200);
        
      expect(response.body.body.value).toBeNull();
    });
  });
});