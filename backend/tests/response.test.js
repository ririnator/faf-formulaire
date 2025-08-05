const request = require('supertest');
const express = require('express');
const responseRoutes = require('../routes/responseRoutes');
const Response = require('../models/Response');

// Create test app
const app = express();
app.use(express.json());
app.use('/api/response', responseRoutes);

describe('Response API', () => {
  const validResponseData = {
    name: 'TestUser',
    responses: [
      { question: 'Test question 1', answer: 'Test answer 1' },
      { question: 'Test question 2', answer: 'Test answer 2' }
    ]
  };

  describe('POST /api/response', () => {
    test('should create response with valid data', async () => {
      const response = await request(app)
        .post('/api/response')
        .send(validResponseData)
        .expect(201);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('link');
      expect(response.body.message).toBe('Réponse enregistrée avec succès !');
    });

    test('should reject empty name', async () => {
      const invalidData = { ...validResponseData, name: '' };
      
      const response = await request(app)
        .post('/api/response')
        .send(invalidData)
        .expect(400);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('caractères');
    });

    test('should reject empty responses array', async () => {
      const invalidData = { ...validResponseData, responses: [] };
      
      const response = await request(app)
        .post('/api/response')
        .send(invalidData)
        .expect(400);

      expect(response.body).toHaveProperty('message');
    });

    test('should detect spam via honeypot', async () => {
      const spamData = { ...validResponseData, website: 'spam.com' };
      
      const response = await request(app)
        .post('/api/response')
        .send(spamData)
        .expect(400);

      expect(response.body.message).toBe('Spam détecté');
    });

    test('should prevent duplicate admin responses', async () => {
      // Create first admin response
      await request(app)
        .post('/api/response')
        .send({ ...validResponseData, name: 'riri' })
        .expect(201);

      // Try to create second admin response
      const response = await request(app)
        .post('/api/response')
        .send({ ...validResponseData, name: 'riri' })
        .expect(409);

      expect(response.body.message).toBe('Une réponse admin existe déjà pour ce mois.');
    });
  });
});