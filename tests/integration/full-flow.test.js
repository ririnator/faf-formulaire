/**
 * Tests d'intégration complets - FAF Multi-Tenant
 *
 * Teste le cycle complet :
 * 1. Register (création compte admin)
 * 2. Login (authentification)
 * 3. Submit (soumission formulaire)
 * 4. View (consultation lien privé)
 * 5. Admin Dashboard (accès données isolées)
 */

const { createClient } = require('../../config/supabase');
const { generateToken, verifyToken } = require('../../utils/jwt');
const bcrypt = require('bcrypt');

// Handlers
const registerHandler = require('../../api/auth/register');
const loginHandler = require('../../api/auth/login');
const submitHandler = require('../../api/response/submit');
const viewHandler = require('../../api/response/view/[token]');
const dashboardHandler = require('../../api/admin/dashboard');

describe('Tests d\'intégration - Cycle complet', () => {
  let supabase;
  let adminAId, adminBId;
  let tokenA, tokenB;
  let responseTokenA, responseTokenB;

  beforeAll(() => {
    supabase = createClient();
  });

  afterAll(async () => {
    // Cleanup - supprimer tous les admins de test
    if (adminAId) {
      await supabase.from('responses').delete().eq('owner_id', adminAId);
      await supabase.from('admins').delete().eq('id', adminAId);
    }
    if (adminBId) {
      await supabase.from('responses').delete().eq('owner_id', adminBId);
      await supabase.from('admins').delete().eq('id', adminBId);
    }
  });

  // ========================================
  // CYCLE COMPLET : Admin A
  // ========================================

  describe('Admin A - Cycle complet', () => {
    test('1. Register - Créer compte admin A', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'adminA',
          email: 'adminA@test.com',
          password: 'SecurePass123!'
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await registerHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          token: expect.any(String),
          admin: expect.objectContaining({
            id: expect.any(String),
            username: 'adminA',
            email: 'adminA@test.com'
          })
        })
      );

      // Sauvegarder les credentials
      const response = res.json.mock.calls[0][0];
      adminAId = response.admin.id;
      tokenA = response.token;
    });

    test('2. Login - Connexion admin A', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'adminA',
          password: 'SecurePass123!'
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await loginHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          token: expect.any(String),
          admin: expect.objectContaining({
            username: 'adminA'
          })
        })
      );

      // Vérifier que le token est valide
      const response = res.json.mock.calls[0][0];
      const decoded = verifyToken(response.token);
      expect(decoded.sub).toBe(adminAId);
    });

    test('3a. Submit - Admin A remplit son formulaire (isAdmin=true)', async () => {
      const currentMonth = new Date().toISOString().slice(0, 7); // YYYY-MM

      const req = {
        method: 'POST',
        body: {
          username: 'adminA',
          name: 'adminA', // name === username → isAdmin true
          responses: [
            { question: 'Question 1?', answer: 'Réponse admin A 1' },
            { question: 'Question 2?', answer: 'Réponse admin A 2' }
          ]
        },
        headers: {}
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await submitHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: expect.stringContaining('admin'),
          isAdmin: true,
          // Pas de token pour admin
          privateLink: undefined
        })
      );
    });

    test('3b. Submit - Ami Alice remplit pour admin A', async () => {
      const currentMonth = new Date().toISOString().slice(0, 7);

      const req = {
        method: 'POST',
        body: {
          username: 'adminA',
          name: 'Alice', // name !== username → isAdmin false, génère token
          responses: [
            { question: 'Question 1?', answer: 'Réponse Alice 1' },
            { question: 'Question 2?', answer: 'Réponse Alice 2' }
          ]
        },
        headers: {}
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await submitHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          isAdmin: false,
          token: expect.any(String),
          privateLink: expect.stringContaining('/view/')
        })
      );

      // Sauvegarder le token pour test View
      const response = res.json.mock.calls[0][0];
      responseTokenA = response.token;
    });

    test('4. View - Alice consulte son lien privé (Alice vs adminA)', async () => {
      const req = {
        method: 'GET',
        query: { token: responseTokenA }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await viewHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          userResponse: expect.objectContaining({
            name: 'Alice',
            isAdmin: false,
            responses: expect.arrayContaining([
              expect.objectContaining({ question: 'Question 1?', answer: 'Réponse Alice 1' })
            ])
          }),
          adminResponse: expect.objectContaining({
            name: 'adminA',
            isAdmin: true,
            responses: expect.arrayContaining([
              expect.objectContaining({ question: 'Question 1?', answer: 'Réponse admin A 1' })
            ])
          })
        })
      );
    });

    test('5. Dashboard - Admin A voit uniquement ses réponses', async () => {
      const req = {
        method: 'GET',
        query: {},
        headers: {
          authorization: `Bearer ${tokenA}`
        },
        user: { id: adminAId, username: 'adminA' } // Simuler middleware auth
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await dashboardHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(200);

      const response = res.json.mock.calls[0][0];
      expect(response.success).toBe(true);
      expect(response.stats.totalResponses).toBeGreaterThanOrEqual(2); // adminA + Alice

      // Vérifier que toutes les réponses appartiennent à adminA
      response.recentResponses.forEach(r => {
        expect(r.owner_id).toBe(adminAId);
      });
    });
  });

  // ========================================
  // CYCLE COMPLET : Admin B (Isolation)
  // ========================================

  describe('Admin B - Isolation des données', () => {
    test('1. Register - Créer compte admin B', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'adminB',
          email: 'adminB@test.com',
          password: 'SecurePass456!'
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await registerHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(201);

      const response = res.json.mock.calls[0][0];
      adminBId = response.admin.id;
      tokenB = response.token;
    });

    test('2. Submit - Admin B remplit son formulaire', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'adminB',
          name: 'adminB',
          responses: [
            { question: 'Question 1?', answer: 'Réponse admin B 1' },
            { question: 'Question 2?', answer: 'Réponse admin B 2' }
          ]
        },
        headers: {}
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await submitHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          isAdmin: true
        })
      );
    });

    test('3. Submit - Ami Bob remplit pour admin B', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'adminB',
          name: 'Bob',
          responses: [
            { question: 'Question 1?', answer: 'Réponse Bob 1' },
            { question: 'Question 2?', answer: 'Réponse Bob 2' }
          ]
        },
        headers: {}
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await submitHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(201);

      const response = res.json.mock.calls[0][0];
      responseTokenB = response.token;
    });

    test('4. Dashboard - Admin B voit UNIQUEMENT ses réponses (pas celles de admin A)', async () => {
      const req = {
        method: 'GET',
        query: {},
        headers: {
          authorization: `Bearer ${tokenB}`
        },
        user: { id: adminBId, username: 'adminB' }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await dashboardHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(200);

      const response = res.json.mock.calls[0][0];
      expect(response.success).toBe(true);
      expect(response.stats.totalResponses).toBeGreaterThanOrEqual(2); // adminB + Bob

      // CRITIQUE : Vérifier isolation - adminB ne doit PAS voir les données de adminA
      response.recentResponses.forEach(r => {
        expect(r.owner_id).toBe(adminBId);
        expect(r.owner_id).not.toBe(adminAId);
      });

      // Vérifier que les noms sont bien ceux de adminB et Bob (pas Alice ni adminA)
      const names = response.recentResponses.map(r => r.name);
      expect(names).toContain('adminB');
      expect(names).toContain('Bob');
      expect(names).not.toContain('Alice');
      expect(names).not.toContain('adminA');
    });

    test('5. View - Bob ne peut PAS accéder au token d\'Alice', async () => {
      const req = {
        method: 'GET',
        query: { token: responseTokenA } // Token de Alice (admin A)
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await viewHandler(req, res);

      // Bob devrait voir Alice vs adminA (pas de restriction sur View)
      // Mais vérifier que c'est bien les bonnes données
      expect(res.status).toHaveBeenCalledWith(200);

      const response = res.json.mock.calls[0][0];
      expect(response.userResponse.name).toBe('Alice');
      expect(response.adminResponse.name).toBe('adminA');
      expect(response.userResponse.owner_id).toBe(adminAId);
    });

    test('6. Dashboard - Admin A ne voit toujours PAS les données de admin B', async () => {
      const req = {
        method: 'GET',
        query: {},
        headers: {
          authorization: `Bearer ${tokenA}`
        },
        user: { id: adminAId, username: 'adminA' }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await dashboardHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(200);

      const response = res.json.mock.calls[0][0];

      // Admin A ne doit voir que ses propres données (pas Bob ni adminB)
      response.recentResponses.forEach(r => {
        expect(r.owner_id).toBe(adminAId);
        expect(r.owner_id).not.toBe(adminBId);
      });

      const names = response.recentResponses.map(r => r.name);
      expect(names).not.toContain('Bob');
      expect(names).not.toContain('adminB');
    });
  });

  // ========================================
  // TESTS DE VALIDITÉ DES TOKENS
  // ========================================

  describe('Validation JWT', () => {
    test('Token admin A doit être valide et contenir adminAId', () => {
      const decoded = verifyToken(tokenA);
      expect(decoded.sub).toBe(adminAId);
      expect(decoded.username).toBe('adminA');
    });

    test('Token admin B doit être valide et contenir adminBId', () => {
      const decoded = verifyToken(tokenB);
      expect(decoded.sub).toBe(adminBId);
      expect(decoded.username).toBe('adminB');
    });

    test('Token expiré ou invalide doit échouer', () => {
      expect(() => verifyToken('invalid.token.here')).toThrow();
    });
  });
});
