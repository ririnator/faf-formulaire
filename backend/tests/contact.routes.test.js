// tests/contact.routes.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const User = require('../models/User');
const Contact = require('../models/Contact');
const bcrypt = require('bcrypt');

describe('Contact Routes - API Tests', () => {
  let server;
  let authenticatedAgent;
  let testUser;
  let testContact;
  let authCookie;

  beforeAll(async () => {
    server = app.listen(0);
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(async () => {
    // Créer un utilisateur de test
    const hashedPassword = await bcrypt.hash('password123', 10);
    testUser = await User.create({
      username: 'testuser',
      email: 'test@example.com',
      password: hashedPassword,
      role: 'user'
    });

    // Créer un agent authentifié
    authenticatedAgent = request.agent(app);
    const loginRes = await authenticatedAgent
      .post('/api/auth/login')
      .send({ username: 'testuser', password: 'password123' });

    authCookie = loginRes.headers['set-cookie'];

    // Créer un contact de test
    testContact = await Contact.create({
      ownerId: testUser._id,
      email: 'contact@example.com',
      firstName: 'John',
      lastName: 'Doe',
      status: 'active',
      tags: ['friend', 'work']
    });
  });

  afterEach(async () => {
    await Contact.deleteMany({});
    await User.deleteMany({});
  });

  describe('GET /api/contacts', () => {
    it('devrait retourner la liste des contacts avec pagination', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts')
        .query({ page: 1, limit: 10 })
        .expect(200);

      expect(res.body.contacts).toBeDefined();
      expect(res.body.contacts).toHaveLength(1);
      expect(res.body.total).toBe(1);
      expect(res.body.page).toBe(1);
    });

    it('devrait filtrer les contacts par statut', async () => {
      await Contact.create({
        ownerId: testUser._id,
        email: 'inactive@example.com',
        status: 'inactive'
      });

      const res = await authenticatedAgent
        .get('/api/contacts')
        .query({ status: 'active' })
        .expect(200);

      expect(res.body.contacts).toHaveLength(1);
      expect(res.body.contacts[0].status).toBe('active');
    });

    it('devrait rechercher les contacts', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts')
        .query({ search: 'John' })
        .expect(200);

      expect(res.body.contacts).toHaveLength(1);
      expect(res.body.contacts[0].firstName).toBe('John');
    });

    it('devrait rejeter sans authentification', async () => {
      await request(app)
        .get('/api/contacts')
        .expect(401);
    });

    it('devrait valider les paramètres de pagination', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts')
        .query({ page: 'invalid', limit: 'invalid' })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('POST /api/contacts', () => {
    it('devrait créer un nouveau contact', async () => {
      const res = await authenticatedAgent
        .post('/api/contacts')
        .send({
          email: 'new@example.com',
          firstName: 'Jane',
          lastName: 'Smith',
          tags: ['family'],
          notes: 'Met at conference'
        })
        .expect(201);

      expect(res.body.success).toBe(true);
      expect(res.body.contact.email).toBe('new@example.com');
      expect(res.body.contact.firstName).toBe('Jane');
    });

    it('devrait valider l\'email', async () => {
      const res = await authenticatedAgent
        .post('/api/contacts')
        .send({
          email: 'invalid-email',
          firstName: 'Test'
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('devrait empêcher les doublons', async () => {
      const res = await authenticatedAgent
        .post('/api/contacts')
        .send({
          email: 'contact@example.com',
          firstName: 'Duplicate'
        })
        .expect(409);

      expect(res.body.code).toBe('DUPLICATE_CONTACT');
    });

    it('devrait protéger contre XSS', async () => {
      const res = await authenticatedAgent
        .post('/api/contacts')
        .send({
          email: 'xss@example.com',
          firstName: '<script>alert("XSS")</script>',
          notes: '<img src=x onerror=alert(1)>'
        })
        .expect(201);

      expect(res.body.contact.firstName).not.toContain('<script>');
      expect(res.body.contact.notes).not.toContain('<img');
    });
  });

  describe('GET /api/contacts/:id', () => {
    it('devrait retourner un contact spécifique', async () => {
      const res = await authenticatedAgent
        .get(`/api/contacts/${testContact._id}`)
        .expect(200);

      expect(res.body.contact.email).toBe('contact@example.com');
      expect(res.body.contact.firstName).toBe('John');
    });

    it('devrait retourner 404 pour un contact inexistant', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const res = await authenticatedAgent
        .get(`/api/contacts/${fakeId}`)
        .expect(404);

      expect(res.body.code).toBe('NOT_FOUND');
    });

    it('devrait valider l\'ID MongoDB', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts/invalid-id')
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('PUT /api/contacts/:id', () => {
    it('devrait mettre à jour un contact', async () => {
      const res = await authenticatedAgent
        .put(`/api/contacts/${testContact._id}`)
        .send({
          firstName: 'Johnny',
          lastName: 'Updated',
          notes: 'Updated notes'
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.contact.firstName).toBe('Johnny');
      expect(res.body.contact.lastName).toBe('Updated');
    });

    it('devrait valider les données de mise à jour', async () => {
      const res = await authenticatedAgent
        .put(`/api/contacts/${testContact._id}`)
        .send({
          email: 'invalid-email',
          firstName: 'a'.repeat(101)
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });

    it('devrait protéger contre XSS dans les mises à jour', async () => {
      const res = await authenticatedAgent
        .put(`/api/contacts/${testContact._id}`)
        .send({
          notes: '<script>alert("XSS")</script>'
        })
        .expect(200);

      const updated = await Contact.findById(testContact._id);
      expect(updated.notes).not.toContain('<script>');
    });
  });

  describe('DELETE /api/contacts/:id', () => {
    it('devrait supprimer un contact', async () => {
      const res = await authenticatedAgent
        .delete(`/api/contacts/${testContact._id}`)
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('deleted');

      const deleted = await Contact.findById(testContact._id);
      expect(deleted).toBeNull();
    });

    it('devrait retourner 404 pour un contact inexistant', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const res = await authenticatedAgent
        .delete(`/api/contacts/${fakeId}`)
        .expect(404);

      expect(res.body.code).toBe('NOT_FOUND');
    });
  });

  describe('POST /api/contacts/import', () => {
    it('devrait importer des contacts depuis CSV', async () => {
      const csvData = `email,firstName,lastName,tags
alice@example.com,Alice,Johnson,friend
bob@example.com,Bob,Wilson,work colleague`;

      const res = await authenticatedAgent
        .post('/api/contacts/import')
        .send({
          csvData,
          options: {
            skipDuplicates: true
          }
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.imported).toHaveLength(2);
      expect(res.body.total).toBe(2);
    });

    it('devrait gérer les duplicatas dans l\'import', async () => {
      const csvData = `email,firstName,lastName
contact@example.com,Duplicate,Test
new@example.com,New,Contact`;

      const res = await authenticatedAgent
        .post('/api/contacts/import')
        .send({
          csvData,
          options: {
            skipDuplicates: true
          }
        })
        .expect(200);

      expect(res.body.imported).toHaveLength(1);
      expect(res.body.duplicates).toHaveLength(1);
    });

    it('devrait valider le format CSV', async () => {
      const res = await authenticatedAgent
        .post('/api/contacts/import')
        .send({
          csvData: ''
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('GET /api/contacts/search', () => {
    beforeEach(async () => {
      await Contact.create([
        {
          ownerId: testUser._id,
          email: 'alice@example.com',
          firstName: 'Alice',
          lastName: 'Smith'
        },
        {
          ownerId: testUser._id,
          email: 'bob@example.com',
          firstName: 'Bob',
          lastName: 'Johnson'
        }
      ]);
    });

    it('devrait rechercher dans les contacts', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts/search')
        .query({ q: 'Alice' })
        .expect(200);

      expect(res.body.contacts).toHaveLength(1);
      expect(res.body.contacts[0].firstName).toBe('Alice');
    });

    it('devrait rechercher par email', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts/search')
        .query({ 
          q: 'bob@example.com',
          fields: 'email'
        })
        .expect(200);

      expect(res.body.contacts).toHaveLength(1);
      expect(res.body.contacts[0].email).toBe('bob@example.com');
    });

    it('devrait valider la requête de recherche', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts/search')
        .query({ q: '' })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('GET /api/contacts/stats/global', () => {
    beforeEach(async () => {
      await Contact.create([
        {
          ownerId: testUser._id,
          email: 'active1@example.com',
          status: 'active'
        },
        {
          ownerId: testUser._id,
          email: 'active2@example.com',
          status: 'active'
        },
        {
          ownerId: testUser._id,
          email: 'inactive@example.com',
          status: 'inactive'
        }
      ]);
    });

    it('devrait retourner les statistiques globales', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts/stats/global')
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.stats).toBeDefined();
      expect(res.body.stats.total).toBe(4); // 3 nouveaux + 1 de base
    });

    it('devrait filtrer par période', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts/stats/global')
        .query({ period: '7d' })
        .expect(200);

      expect(res.body.period).toBe('7d');
    });

    it('devrait grouper par statut', async () => {
      const res = await authenticatedAgent
        .get('/api/contacts/stats/global')
        .query({ groupBy: 'status' })
        .expect(200);

      expect(res.body.groupBy).toBe('status');
    });
  });

  describe('POST /api/contacts/:id/tracking', () => {
    it('devrait mettre à jour le tracking d\'un contact', async () => {
      const res = await authenticatedAgent
        .post(`/api/contacts/${testContact._id}/tracking`)
        .send({
          event: 'sent',
          metadata: {
            campaign: 'november-2024'
          }
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      expect(res.body.message).toContain('sent');
    });

    it('devrait valider l\'événement', async () => {
      const res = await authenticatedAgent
        .post(`/api/contacts/${testContact._id}/tracking`)
        .send({
          event: 'invalid-event'
        })
        .expect(400);

      expect(res.body.code).toBe('VALIDATION_ERROR');
    });
  });
});