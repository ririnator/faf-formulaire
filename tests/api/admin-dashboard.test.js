/**
 * Tests pour /api/admin/dashboard
 */

const handler = require('../../api/admin/dashboard');
const { createClient } = require('../../config/supabase');
const { generateToken } = require('../../utils/jwt');
const bcrypt = require('bcrypt');
const { createValidResponses, generateUniqueToken } = require('../helpers/testData');

// Mock du middleware auth
jest.mock('../../middleware/auth', () => ({
  verifyJWT: jest.fn()
}));

const { verifyJWT } = require('../../middleware/auth');

describe('GET /api/admin/dashboard', () => {
  let testAdminId;
  let testToken;
  let supabase;

  beforeAll(async () => {
    supabase = createClient();

    // Créer un admin de test avec password_hash bcrypt valide
    const passwordHash = await bcrypt.hash('TestPassword123!', 10);

    const { data: admin, error} = await supabase
      .from('admins')
      .insert({
        username: 'dashboardadmin',
        email: 'dashboard@test.com',
        password_hash: passwordHash
      })
      .select()
      .single();

    if (error) throw error;

    testAdminId = admin.id;
    testToken = generateToken({ sub: testAdminId, username: 'dashboardadmin' });
  });

  afterAll(async () => {
    // Cleanup : supprimer toutes les réponses de test
    await supabase
      .from('responses')
      .delete()
      .eq('owner_id', testAdminId);

    // Supprimer l'admin de test
    await supabase
      .from('admins')
      .delete()
      .eq('id', testAdminId);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ===========================
  // Tests de validation HTTP
  // ===========================

  test('Retourne 405 pour méthode POST', async () => {
    const req = { method: 'POST', query: {} };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(405);
    expect(res.json).toHaveBeenCalledWith({ error: 'Method not allowed' });
  });

  test('Retourne 401 si JWT invalide', async () => {
    verifyJWT.mockReturnValue(null); // Simule JWT invalide

    const req = {
      method: 'GET',
      query: {},
      headers: { authorization: 'Bearer invalid_token' }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Unauthorized - Invalid or missing token'
    });
  });

  test('Retourne 400 si format de mois invalide', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: { month: '2025/10' }, // Format invalide
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Invalid month format. Expected YYYY-MM'
    });
  });

  // ===========================
  // Tests de récupération données
  // ===========================

  test('Retourne un dashboard vide si aucune réponse', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: {},
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        stats: expect.objectContaining({
          totalResponses: 0
        }),
        responses: [],
        months: [],
        adminHasFilled: false
      })
    );
  });

  test('Retourne les réponses filtrées par owner_id', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    // Créer des réponses pour cet admin
    await supabase.from('responses').insert([
      {
        owner_id: testAdminId,
        name: 'Alice',
        responses: createValidResponses({ q1: 'ça va' }),
        month: '2025-10',
        is_owner: false,
        token: generateUniqueToken()
      },
      {
        owner_id: testAdminId,
        name: 'Bob',
        responses: createValidResponses({ q1: "WE'RE BARACK" }),
        month: '2025-10',
        is_owner: false,
        token: generateUniqueToken()
      }
    ]);

    const req = {
      method: 'GET',
      query: {},
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    expect(responseData.success).toBe(true);
    expect(responseData.stats.totalResponses).toBe(2);
    expect(responseData.responses).toHaveLength(2);
    expect(responseData.responses[0]).toHaveProperty('id');
    expect(responseData.responses[0]).toHaveProperty('name');
    expect(responseData.responses[0]).toHaveProperty('createdAt');
    expect(responseData.responses[0]).toHaveProperty('preview');
  });

  test('Filtre les réponses par mois correctement', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    // Créer une réponse dans un mois différent
    await supabase.from('responses').insert({
      owner_id: testAdminId,
      name: 'Charlie',
      responses: createValidResponses({ q1: 'a connu meilleur mois' }),
      month: '2025-09',
      is_owner: false,
      token: generateUniqueToken()
    });

    const req = {
      method: 'GET',
      query: { month: '2025-09' },
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    expect(responseData.success).toBe(true);
    expect(responseData.stats.totalResponses).toBe(1);
    expect(responseData.responses[0].name).toBe('Charlie');
  });

  test('Calcule correctement la distribution de la question 1', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: { month: '2025-10' },
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    expect(responseData.stats.question1Distribution).toEqual({
      'ça va': 1,
      'WE\'RE BARACK': 1
    });
  });

  test('Détecte si l\'admin a rempli son formulaire', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    // Ajouter une réponse de l'admin
    await supabase.from('responses').insert({
      owner_id: testAdminId,
      name: 'dashboardadmin',
      responses: createValidResponses({ q1: 'ça va' }),
      month: '2025-10',
      is_owner: true,
      token: null
    });

    const req = {
      method: 'GET',
      query: {},
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    expect(responseData.adminHasFilled).toBe(true);
  });

  test('Retourne la liste des mois disponibles', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: {},
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    expect(responseData.months).toContain('2025-10');
    expect(responseData.months).toContain('2025-09');
  });

  test('N\'expose pas les tokens dans les réponses', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: {},
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    responseData.responses.forEach(response => {
      expect(response).not.toHaveProperty('token');
    });
  });

  test('Tronque les longs previews à 50 caractères', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    // Créer une réponse avec une longue première réponse
    // Note: Le preview est basé sur la Q1 (responses[0].answer)
    const longOption = 'ITS JOEVER ' + 'x'.repeat(100); // Option longue pour Q1
    await supabase.from('responses').insert({
      owner_id: testAdminId,
      name: 'LongAnswer',
      responses: createValidResponses({ q1: longOption }),
      month: '2025-10',
      is_owner: false,
      token: generateUniqueToken()
    });

    const req = {
      method: 'GET',
      query: {},
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    const longResponse = responseData.responses.find(r => r.name === 'LongAnswer');
    expect(longResponse.preview).toHaveLength(53); // 50 chars + '...'
    expect(longResponse.preview).toMatch(/\.\.\.$/);
  });
});
