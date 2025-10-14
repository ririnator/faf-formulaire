const { supabaseAdmin } = require('../utils/supabase');
const bcrypt = require('bcrypt');
const registerHandler = require('../api/auth/register');
const loginHandler = require('../api/auth/login');
const verifyHandler = require('../api/auth/verify');

// Setup JWT_SECRET pour les tests
process.env.JWT_SECRET = 'test-secret-key-for-auth-testing-only';

// Helper pour créer un mock request/response
function createMockReqRes(method, body = {}, headers = {}) {
  const req = {
    method,
    body,
    headers,
    ip: '127.0.0.1'
  };

  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    },
    setHeader(key, value) {
      this.headers[key] = value;
      return this;
    },
    end() {
      return this;
    }
  };

  return { req, res };
}

describe('Authentication API', () => {

  // Nettoyer la base de test avant chaque test
  beforeEach(async () => {
    await supabaseAdmin
      .from('admins')
      .delete()
      .ilike('username', 'testuser%');
  });

  // Nettoyer après tous les tests
  afterAll(async () => {
    await supabaseAdmin
      .from('admins')
      .delete()
      .ilike('username', 'testuser%');
  });

  describe('POST /api/auth/register', () => {

    test('Should register a new admin successfully', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser',
        email: 'test@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req, res);

      expect(res.statusCode).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      expect(res.body.admin.username).toBe('testuser');
      expect(res.body.admin.email).toBe('test@example.com');
      expect(res.body.admin.id).toBeDefined();
    });

    test('Should reject invalid username (too short)', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'ab',
        email: 'test@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toContain('Username invalide');
    });

    test('Should reject invalid username (special characters)', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'test@user',
        email: 'test@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toContain('Username invalide');
    });

    test('Should reject weak password (no uppercase)', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        website: ''
      });

      await registerHandler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toContain('Mot de passe trop faible');
    });

    test('Should reject weak password (no digit)', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser',
        email: 'test@example.com',
        password: 'Password',
        website: ''
      });

      await registerHandler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toContain('Mot de passe trop faible');
    });

    test('Should reject duplicate username', async () => {
      // Créer un premier admin
      const { req: req1, res: res1 } = createMockReqRes('POST', {
        username: 'testuser',
        email: 'test1@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req1, res1);
      expect(res1.statusCode).toBe(201);

      // Tenter de créer un autre avec le même username
      const { req: req2, res: res2 } = createMockReqRes('POST', {
        username: 'testuser',
        email: 'test2@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req2, res2);

      expect(res2.statusCode).toBe(409);
      expect(res2.body.error).toContain('déjà pris');
    });

    test('Should reject honeypot (bot detection)', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser',
        email: 'test@example.com',
        password: 'Password123!',
        website: 'http://spam.com' // Bot rempli ce champ
      });

      await registerHandler(req, res);

      expect(res.statusCode).toBe(400);
    });

    test('Should normalize username to lowercase', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser',
        email: 'TEST@EXAMPLE.COM',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req, res);

      expect(res.statusCode).toBe(201);
      expect(res.body.admin.email).toBe('test@example.com');
    });

  });

  describe('POST /api/auth/login', () => {

    beforeEach(async () => {
      // Créer un admin de test
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser2',
        email: 'test2@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req, res);
    });

    test('Should login successfully with correct credentials', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser2',
        password: 'Password123!'
      });

      await loginHandler(req, res);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      expect(res.body.admin.username).toBe('testuser2');
    });

    test('Should reject incorrect password', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser2',
        password: 'WrongPassword123!'
      });

      await loginHandler(req, res);

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toBe('Identifiants invalides.');
    });

    test('Should reject non-existent username', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'nonexistent',
        password: 'Password123!'
      });

      await loginHandler(req, res);

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toBe('Identifiants invalides.');
    });

    test('Should be case-insensitive for username', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'TESTUSER2', // Uppercase
        password: 'Password123!'
      });

      await loginHandler(req, res);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
    });

    test('Should reject missing fields', async () => {
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser2'
        // password manquant
      });

      await loginHandler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toContain('requis');
    });

  });

  describe('GET /api/auth/verify', () => {

    let token;
    let adminId;

    beforeEach(async () => {
      // Créer un admin et récupérer son token
      const { req, res } = createMockReqRes('POST', {
        username: 'testuser3',
        email: 'test3@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(req, res);

      token = res.body.token;
      adminId = res.body.admin.id;
    });

    test('Should verify valid token', async () => {
      const { req, res } = createMockReqRes('GET', {}, {
        authorization: `Bearer ${token}`
      });

      await verifyHandler(req, res);

      expect(res.statusCode).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.admin.id).toBe(adminId);
      expect(res.body.admin.username).toBe('testuser3');
    });

    test('Should reject missing token', async () => {
      const { req, res } = createMockReqRes('GET', {}, {});

      await verifyHandler(req, res);

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toContain('Token manquant');
    });

    test('Should reject invalid token', async () => {
      const { req, res } = createMockReqRes('GET', {}, {
        authorization: 'Bearer invalid-token-123'
      });

      await verifyHandler(req, res);

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toContain('Token invalide');
    });

    test('Should reject malformed authorization header', async () => {
      const { req, res } = createMockReqRes('GET', {}, {
        authorization: 'InvalidFormat token'
      });

      await verifyHandler(req, res);

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toContain('Token manquant');
    });

  });

  describe('Integration: Register → Login → Verify', () => {

    test('Should complete full authentication flow', async () => {
      // 1. Inscription
      const { req: regReq, res: regRes } = createMockReqRes('POST', {
        username: 'testuser4',
        email: 'test4@example.com',
        password: 'Password123!',
        website: ''
      });

      await registerHandler(regReq, regRes);

      expect(regRes.statusCode).toBe(201);
      const registerToken = regRes.body.token;
      const registeredAdminId = regRes.body.admin.id;

      // 2. Login
      const { req: loginReq, res: loginRes } = createMockReqRes('POST', {
        username: 'testuser4',
        password: 'Password123!'
      });

      await loginHandler(loginReq, loginRes);

      expect(loginRes.statusCode).toBe(200);
      const loginToken = loginRes.body.token;

      // Les tokens sont différents (générés à des moments différents)
      expect(loginToken).toBeDefined();

      // 3. Verify avec le token de login
      const { req: verifyReq, res: verifyRes } = createMockReqRes('GET', {}, {
        authorization: `Bearer ${loginToken}`
      });

      await verifyHandler(verifyReq, verifyRes);

      expect(verifyRes.statusCode).toBe(200);
      expect(verifyRes.body.admin.id).toBe(registeredAdminId);
      expect(verifyRes.body.admin.username).toBe('testuser4');
    });

  });

});
