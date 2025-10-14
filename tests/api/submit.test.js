/**
 * Tests pour /api/response/submit
 *
 * Tests couverts :
 * - Soumission par un ami (génère token + lien)
 * - Soumission par l'admin (pas de token)
 * - XSS escaping
 * - Préservation URLs Cloudinary
 * - Rate limiting
 * - Honeypot
 * - Validation des champs
 */

const { createClient } = require('../../config/supabase');
const handler = require('../../api/response/submit');
const { resetStore } = require('../../middleware/rateLimit');
const bcrypt = require('bcrypt');

// Mock request et response
function createMockReq(method = 'POST', body = {}, headers = {}) {
  return {
    method,
    body,
    headers: {
      'x-forwarded-for': '127.0.0.1',
      ...headers
    },
    connection: { remoteAddress: '127.0.0.1' }
  };
}

function createMockRes() {
  const res = {
    statusCode: 200,
    data: null,
    headers: {},
    status: function(code) {
      this.statusCode = code;
      return this;
    },
    json: function(data) {
      this.data = data;
      return this;
    },
    setHeader: function(key, value) {
      this.headers[key] = value;
      return this;
    }
  };
  return res;
}

describe('API: /api/response/submit', () => {
  let supabase;
  let testAdminId;
  const testUsername = 'submitadmin' + Math.random().toString(36).substring(2, 8);

  beforeAll(async () => {
    supabase = createClient();

    // Créer un admin de test
    const passwordHash = await bcrypt.hash('Password123!', 10);
    const { data, error } = await supabase
      .from('admins')
      .insert({
        username: testUsername,
        email: `${testUsername}@test.com`,
        password_hash: passwordHash
      })
      .select()
      .single();

    if (error) {
      console.error('Failed to create test admin:', error);
      throw error;
    }

    testAdminId = data.id;
  });

  afterAll(async () => {
    // Nettoyer : supprimer les réponses et l'admin de test
    if (testAdminId) {
      await supabase
        .from('responses')
        .delete()
        .eq('owner_id', testAdminId);

      await supabase
        .from('admins')
        .delete()
        .eq('id', testAdminId);
    }
  });

  beforeEach(() => {
    // Réinitialiser le rate limiter avant chaque test
    resetStore();
  });

  describe('POST /api/response/submit', () => {
    const validResponses = [
      { question: 'Q1', answer: 'A1' },
      { question: 'Q2', answer: 'A2' },
      { question: 'Q3', answer: 'A3' },
      { question: 'Q4', answer: 'A4' },
      { question: 'Q5', answer: 'A5' },
      { question: 'Q6', answer: 'A6' },
      { question: 'Q7', answer: 'A7' },
      { question: 'Q8', answer: 'A8' },
      { question: 'Q9', answer: 'A9' },
      { question: 'Q10', answer: 'A10' }
    ];

    test('should return 405 for non-POST methods', async () => {
      const req = createMockReq('GET');
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(405);
      expect(res.data.success).toBe(false);
    });

    test('should reject spam (honeypot filled)', async () => {
      const req = createMockReq('POST', {
        username: testUsername,
        name: 'Friend',
        responses: validResponses,
        website: 'http://spam.com' // Honeypot rempli = spam
      });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.data.error).toBe('Spam detected');
    });

    test('should return 400 if required fields are missing', async () => {
      const req = createMockReq('POST', {
        username: testUsername
        // name et responses manquants
      });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.data.error).toBe('Missing required fields');
    });

    test('should return 400 for invalid name', async () => {
      const req = createMockReq('POST', {
        username: testUsername,
        name: 'A', // Trop court (min 2)
        responses: validResponses,
        website: ''
      });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.data.error).toBe('Invalid name');
    });

    test('should return 400 for invalid responses count', async () => {
      const req = createMockReq('POST', {
        username: testUsername,
        name: 'Friend',
        responses: [
          { question: 'Q1', answer: 'A1' }
          // Pas assez de réponses (min 10)
        ],
        website: ''
      });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.data.error).toBe('Invalid responses');
    });

    test('should return 404 if admin not found', async () => {
      const req = createMockReq('POST', {
        username: 'nonexistent999',
        name: 'Friend',
        responses: validResponses,
        website: ''
      });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(404);
      expect(res.data.error).toBe('Admin not found');
    });

    test('should accept friend submission and generate token', async () => {
      const req = createMockReq('POST', {
        username: testUsername,
        name: 'FriendName',
        responses: validResponses,
        website: ''
      });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(201);
      expect(res.data.success).toBe(true);
      expect(res.data.link).toBeDefined();
      expect(res.data.link).toContain('/view/');
      expect(res.data.userName).toBe('FriendName');
      expect(res.data.adminName).toBe(testUsername);

      // Vérifier que le token est de 64 caractères
      const token = res.data.link.split('/view/')[1];
      expect(token).toHaveLength(64);
    });

    test('should accept admin submission without token', async () => {
      const req = createMockReq('POST', {
        username: testUsername,
        name: testUsername, // Même nom que l'admin
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': '127.0.0.2' }); // IP différente pour éviter rate limit

      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(201);
      expect(res.data.success).toBe(true);
      expect(res.data.link).toBeUndefined(); // Pas de lien pour l'admin
      expect(res.data.userName).toBe(testUsername);
      expect(res.data.adminName).toBe(testUsername);
    });

    test('should escape XSS in responses', async () => {
      const xssResponses = [
        { question: 'Q1', answer: '<script>alert("XSS")</script>' },
        { question: 'Q2', answer: '<img src=x onerror=alert(1)>' },
        { question: 'Q3', answer: 'Normal text' },
        { question: 'Q4', answer: 'A4' },
        { question: 'Q5', answer: 'A5' },
        { question: 'Q6', answer: 'A6' },
        { question: 'Q7', answer: 'A7' },
        { question: 'Q8', answer: 'A8' },
        { question: 'Q9', answer: 'A9' },
        { question: 'Q10', answer: 'A10' }
      ];

      const req = createMockReq('POST', {
        username: testUsername,
        name: 'XSSTester',
        responses: xssResponses,
        website: ''
      }, { 'x-forwarded-for': '127.0.0.3' });

      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(201);

      // Vérifier dans la DB que le XSS a été échappé
      const token = res.data.link.split('/view/')[1];
      const { data: response } = await supabase
        .from('responses')
        .select('responses')
        .eq('token', token)
        .single();

      expect(response.responses[0].answer).toContain('&lt;script&gt;');
      expect(response.responses[1].answer).toContain('&lt;img');
    });

    test('should preserve Cloudinary URLs', async () => {
      const cloudinaryResponses = [
        { question: 'Q1', answer: 'Text answer' },
        { question: 'Q2', answer: 'https://res.cloudinary.com/mycloud/image/upload/v123/photo.jpg' },
        { question: 'Q3', answer: 'A3' },
        { question: 'Q4', answer: 'A4' },
        { question: 'Q5', answer: 'A5' },
        { question: 'Q6', answer: 'A6' },
        { question: 'Q7', answer: 'A7' },
        { question: 'Q8', answer: 'A8' },
        { question: 'Q9', answer: 'A9' },
        { question: 'Q10', answer: 'A10' }
      ];

      const req = createMockReq('POST', {
        username: testUsername,
        name: 'CloudinaryUser',
        responses: cloudinaryResponses,
        website: ''
      }, { 'x-forwarded-for': '127.0.0.4' });

      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(201);

      // Vérifier que l'URL Cloudinary n'a pas été échappée
      const token = res.data.link.split('/view/')[1];
      const { data: response } = await supabase
        .from('responses')
        .select('responses')
        .eq('token', token)
        .single();

      expect(response.responses[1].answer).toBe('https://res.cloudinary.com/mycloud/image/upload/v123/photo.jpg');
    });

    test('should enforce rate limiting (3 submissions max)', async () => {
      const ip = '127.0.0.10';

      // Première soumission
      const req1 = createMockReq('POST', {
        username: testUsername,
        name: 'User1',
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': ip });
      const res1 = createMockRes();
      await handler(req1, res1);
      expect(res1.statusCode).toBe(201);

      // Deuxième soumission
      const req2 = createMockReq('POST', {
        username: testUsername,
        name: 'User2',
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': ip });
      const res2 = createMockRes();
      await handler(req2, res2);
      expect(res2.statusCode).toBe(201);

      // Troisième soumission
      const req3 = createMockReq('POST', {
        username: testUsername,
        name: 'User3',
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': ip });
      const res3 = createMockRes();
      await handler(req3, res3);
      expect(res3.statusCode).toBe(201);

      // Quatrième soumission = rate limit exceeded
      const req4 = createMockReq('POST', {
        username: testUsername,
        name: 'User4',
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': ip });
      const res4 = createMockRes();
      await handler(req4, res4);
      expect(res4.statusCode).toBe(429);
      expect(res4.data.error).toBe('Rate limit exceeded');
      expect(res4.headers['Retry-After']).toBeDefined();
    });

    test('should prevent admin from submitting twice in same month', async () => {
      // Nettoyer les réponses de l'admin pour ce mois
      const now = new Date();
      const month = now.toISOString().slice(0, 7);
      await supabase
        .from('responses')
        .delete()
        .eq('owner_id', testAdminId)
        .eq('is_owner', true)
        .eq('month', month);

      // Première soumission de l'admin
      const req1 = createMockReq('POST', {
        username: testUsername,
        name: testUsername,
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': '127.0.0.20' });
      const res1 = createMockRes();
      await handler(req1, res1);
      expect(res1.statusCode).toBe(201);

      // Deuxième tentative = rejet
      const req2 = createMockReq('POST', {
        username: testUsername,
        name: testUsername,
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': '127.0.0.21' });
      const res2 = createMockRes();
      await handler(req2, res2);
      expect(res2.statusCode).toBe(409);
      expect(res2.data.error).toBe('Already submitted');
    });

    test('should add rate limit headers', async () => {
      const req = createMockReq('POST', {
        username: testUsername,
        name: 'HeaderTester',
        responses: validResponses,
        website: ''
      }, { 'x-forwarded-for': '127.0.0.30' });
      const res = createMockRes();

      await handler(req, res);

      expect(res.headers['X-RateLimit-Limit']).toBe(3);
      expect(res.headers['X-RateLimit-Remaining']).toBe(2);
      expect(res.headers['X-RateLimit-Reset']).toBeDefined();
    });
  });
});
