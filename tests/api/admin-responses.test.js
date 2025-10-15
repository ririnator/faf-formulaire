/**
 * Tests pour /api/admin/responses
 */

const handler = require('../../api/admin/responses');
const { createClient } = require('../../config/supabase');
const { generateToken } = require('../../utils/jwt');
const bcrypt = require('bcrypt');
const { createValidResponses, generateUniqueToken } = require('../helpers/testData');

// Mock du middleware auth
jest.mock('../../middleware/auth', () => ({
  verifyJWT: jest.fn()
}));

const { verifyJWT } = require('../../middleware/auth');

describe('GET /api/admin/responses', () => {
  let testAdminId;
  let testToken;
  let supabase;

  beforeAll(async () => {
    supabase = createClient();

    // Créer un admin de test avec password_hash bcrypt valide
    const passwordHash = await bcrypt.hash('TestPassword123!', 10);

    const { data: admin, error } = await supabase
      .from('admins')
      .insert({
        username: 'responsesadmin',
        email: 'responses@test.com',
        password_hash: passwordHash
      })
      .select()
      .single();

    if (error) throw error;

    testAdminId = admin.id;
    testToken = generateToken({ sub: testAdminId, username: 'responsesadmin' });
  });

  afterAll(async () => {
    // Cleanup
    await supabase
      .from('responses')
      .delete()
      .eq('owner_id', testAdminId);

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
    verifyJWT.mockReturnValue(null);

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
      query: { month: '2025/10' },
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

  test('Retourne 400 si page invalide', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: { page: '0' },
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Invalid page number'
    });
  });

  test('Retourne 400 si limit invalide (> 100)', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: { limit: '150' },
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      error: 'Invalid limit. Must be between 1 and 100'
    });
  });

  // ===========================
  // Tests de pagination
  // ===========================

  test('Retourne liste vide si aucune réponse', async () => {
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
    expect(res.json).toHaveBeenCalledWith({
      success: true,
      responses: [],
      pagination: {
        page: 1,
        limit: 50,
        total: 0,
        totalPages: 0
      }
    });
  });

  test('Pagine correctement les réponses', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    // Créer 5 réponses
    const responses = [];
    for (let i = 1; i <= 5; i++) {
      responses.push({
        owner_id: testAdminId,
        name: `User${i}`,
        responses: createValidResponses({ q1: 'ça va', q2: `Answer ${i}` }),
        month: '2025-10',
        is_owner: false,
        token: generateUniqueToken()
      });
    }
    await supabase.from('responses').insert(responses);

    // Page 1, limit 2
    const req = {
      method: 'GET',
      query: { page: '1', limit: '2' },
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
    expect(responseData.responses).toHaveLength(2);
    expect(responseData.pagination).toEqual({
      page: 1,
      limit: 2,
      total: 5,
      totalPages: 3
    });
  });

  test('Retourne la deuxième page correctement', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: { page: '2', limit: '2' },
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
    expect(responseData.responses).toHaveLength(2);
    expect(responseData.pagination.page).toBe(2);
  });

  test('Filtre par mois correctement', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    // Ajouter une réponse dans un mois différent
    await supabase.from('responses').insert({
      owner_id: testAdminId,
      name: 'UserSeptember',
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
    expect(responseData.responses).toHaveLength(1);
    expect(responseData.responses[0].name).toBe('UserSeptember');
  });

  // ===========================
  // Tests de sécurité
  // ===========================

  test('Exclut les réponses de l\'admin (is_owner=true)', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    // Ajouter une réponse de l'admin
    await supabase.from('responses').insert({
      owner_id: testAdminId,
      name: 'responsesadmin',
      responses: createValidResponses({ q1: 'ITS JOEVER' }),
      month: '2025-10',
      is_owner: true,
      token: null
    });

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

    // Vérifier que la réponse admin n'est pas dans les résultats
    const adminResponse = responseData.responses.find(r => r.name === 'responsesadmin');
    expect(adminResponse).toBeUndefined();
  });

  test('Retourne les réponses triées par date décroissante', async () => {
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

    // Vérifier que les réponses sont triées par created_at DESC
    const dates = responseData.responses.map(r => new Date(r.created_at));
    for (let i = 1; i < dates.length; i++) {
      expect(dates[i - 1].getTime()).toBeGreaterThanOrEqual(dates[i].getTime());
    }
  });

  test('Retourne toutes les propriétés des réponses', async () => {
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

    if (responseData.responses.length > 0) {
      const response = responseData.responses[0];
      expect(response).toHaveProperty('id');
      expect(response).toHaveProperty('owner_id');
      expect(response).toHaveProperty('name');
      expect(response).toHaveProperty('responses');
      expect(response).toHaveProperty('month');
      expect(response).toHaveProperty('is_owner');
      expect(response).toHaveProperty('token');
      expect(response).toHaveProperty('created_at');
    }
  });

  test('Calcule correctement totalPages', async () => {
    verifyJWT.mockReturnValue(testAdminId);

    const req = {
      method: 'GET',
      query: { limit: '3' },
      headers: { authorization: `Bearer ${testToken}` }
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };

    await handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    const responseData = res.json.mock.calls[0][0];

    // Calculer les pages attendues
    expect(responseData.pagination.totalPages).toBe(
      Math.ceil(responseData.pagination.total / 3)
    );
  });
});