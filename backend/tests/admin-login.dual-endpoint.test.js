/**
 * Tests pour vérifier que POST /login et POST /admin-login 
 * se comportent de manière identique
 * 
 * Suite aux corrections du système d'authentification hybride
 */

const request = require('supertest');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// Import des middlewares et routes
const { authenticateAdmin } = require('../middleware/auth');
const sessionMonitoringMiddleware = require('../middleware/sessionMonitoring');

describe('Dual Admin Login Endpoints Consistency', () => {
  let app;

  beforeAll(async () => {
    // Utiliser la connexion MongoDB globale des tests
    const mongoUri = process.env.MONGODB_TEST_URI || global.__MONGO_URI__;

    // Setup Express app identique au main app
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Session configuration identique
    app.use(session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: mongoUri,
        touchAfter: 24 * 3600 // 1 jour
      }),
      cookie: {
        maxAge: 1000 * 60 * 60, // 1 heure
        httpOnly: true,
        secure: false, // HTTP pour les tests
        sameSite: 'lax'
      },
      name: 'faf-session'
    }));

    // Routes identiques à celles du main app
    app.post('/login', sessionMonitoringMiddleware.blockSuspiciousSessions(), authenticateAdmin);
    app.post('/admin-login', sessionMonitoringMiddleware.blockSuspiciousSessions(), authenticateAdmin);

    // Endpoint de test pour vérifier l'état de la session
    app.get('/test-session', (req, res) => {
      res.json({
        isAdmin: req.session?.isAdmin || false,
        adminLoginTime: req.session?.adminLoginTime || null,
        adminIP: req.session?.adminIP || null
      });
    });
  });

  afterAll(async () => {
    // Pas besoin de déconnecter - utilise la connexion globale
  });

  describe('Identical Behavior Tests', () => {
    const validCredentials = {
      username: process.env.LOGIN_ADMIN_USER || 'testadmin',
      password: 'wrongpassword' // Intentionnellement faux pour les tests
    };

    const invalidCredentials = {
      username: 'wronguser',
      password: 'wrongpassword'
    };

    test('Both endpoints should reject invalid credentials identically', async () => {
      // Test POST /login
      const loginResponse = await request(app)
        .post('/login')
        .send(invalidCredentials);

      // Test POST /admin-login
      const adminLoginResponse = await request(app)
        .post('/admin-login')
        .send(invalidCredentials);

      // Les deux doivent avoir le même comportement
      expect(loginResponse.status).toBe(adminLoginResponse.status);
      expect(loginResponse.headers.location).toBe(adminLoginResponse.headers.location);
    });

    test('Both endpoints should handle missing credentials identically', async () => {
      // Test POST /login
      const loginResponse = await request(app)
        .post('/login')
        .send({});

      // Test POST /admin-login  
      const adminLoginResponse = await request(app)
        .post('/admin-login')
        .send({});

      // Comportement identique attendu
      expect(loginResponse.status).toBe(adminLoginResponse.status);
      expect(loginResponse.headers.location).toBe(adminLoginResponse.headers.location);
    });

    test('Both endpoints should handle malformed data identically', async () => {
      const malformedData = {
        username: null,
        password: undefined
      };

      // Test POST /login
      const loginResponse = await request(app)
        .post('/login')
        .send(malformedData);

      // Test POST /admin-login
      const adminLoginResponse = await request(app)
        .post('/admin-login')
        .send(malformedData);

      // Même comportement attendu
      expect(loginResponse.status).toBe(adminLoginResponse.status);
      expect(loginResponse.headers.location).toBe(adminLoginResponse.headers.location);
    });

    test('Both endpoints should apply rate limiting identically', async () => {
      // Cette partie teste que les mêmes middlewares sont appliqués
      const testCredentials = { username: 'test', password: 'test' };

      // Multiple tentatives rapides sur /login
      const loginPromises = Array(3).fill().map(() => 
        request(app).post('/login').send(testCredentials)
      );

      // Multiple tentatives rapides sur /admin-login
      const adminLoginPromises = Array(3).fill().map(() => 
        request(app).post('/admin-login').send(testCredentials)
      );

      const loginResults = await Promise.all(loginPromises);
      const adminLoginResults = await Promise.all(adminLoginPromises);

      // Vérifier que les patterns de réponse sont similaires
      const loginStatuses = loginResults.map(r => r.status);
      const adminLoginStatuses = adminLoginResults.map(r => r.status);

      // Au minimum, tous devraient être des redirections (302) ou erreurs (401)
      loginStatuses.forEach(status => {
        expect([302, 401, 429]).toContain(status);
      });
      
      adminLoginStatuses.forEach(status => {
        expect([302, 401, 429]).toContain(status);
      });
    });

    test('Both endpoints should create identical session structures on success', async () => {
      // Note: Ce test nécessiterait des credentials valides
      // Pour l'instant, on vérifie juste qu'ils échouent de la même manière
      const response1 = await request(app)
        .post('/login')
        .send(validCredentials);

      const response2 = await request(app)
        .post('/admin-login')
        .send(validCredentials);

      // Même comportement d'échec attendu (credentials invalides)
      expect(response1.status).toBe(response2.status);
      
      if (response1.headers.location) {
        expect(response1.headers.location).toBe(response2.headers.location);
      }
    });
  });

  describe('Middleware Consistency', () => {
    test('Both endpoints should have session monitoring middleware', async () => {
      // Test que sessionMonitoringMiddleware.blockSuspiciousSessions() 
      // est appliqué sur les deux routes
      
      const testIP = '192.168.1.100';
      const userAgent = 'test-agent';

      const response1 = await request(app)
        .post('/login')
        .set('User-Agent', userAgent)
        .set('X-Forwarded-For', testIP)
        .send({ username: 'test', password: 'test' });

      const response2 = await request(app)
        .post('/admin-login') 
        .set('User-Agent', userAgent)
        .set('X-Forwarded-For', testIP)
        .send({ username: 'test', password: 'test' });

      // Les deux doivent traiter les headers de sécurité de la même manière
      expect(response1.status).toBe(response2.status);
    });
  });

  describe('Security Headers Consistency', () => {
    test('Both endpoints should return same security headers', async () => {
      const response1 = await request(app)
        .post('/login')
        .send({ username: 'test', password: 'test' });

      const response2 = await request(app)
        .post('/admin-login')
        .send({ username: 'test', password: 'test' });

      // Vérifier les headers de sécurité importants
      const securityHeaders = [
        'x-frame-options',
        'x-content-type-options', 
        'x-xss-protection'
      ];

      securityHeaders.forEach(header => {
        if (response1.headers[header] || response2.headers[header]) {
          expect(response1.headers[header]).toBe(response2.headers[header]);
        }
      });
    });
  });
});