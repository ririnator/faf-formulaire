/**
 * Tests pour /api/admin/response/[id]
 * GET/PATCH/DELETE d'une réponse individuelle
 */

const handler = require('../../api/admin/response/[id]');
const { createClient } = require('../../config/supabase');
const { generateToken } = require('../../utils/jwt');
const bcrypt = require('bcrypt');
const { createValidResponses, generateUniqueToken } = require('../helpers/testData');

// Mock du middleware auth
jest.mock('../../middleware/auth', () => ({
  verifyJWT: jest.fn()
}));

const { verifyJWT } = require('../../middleware/auth');

describe('GET/PATCH/DELETE /api/admin/response/[id]', () => {
  let testAdminId;
  let otherAdminId;
  let testToken;
  let testResponseId;
  let otherResponseId;
  let supabase;

  beforeAll(async () => {
    supabase = createClient();

    // Créer deux admins de test avec password_hash bcrypt valide
    const passwordHash = await bcrypt.hash('TestPassword123!', 10);

    const { data: admin1 } = await supabase
      .from('admins')
      .insert({
        username: 'responseidadmin',
        email: 'responseid@test.com',
        password_hash: passwordHash
      })
      .select()
      .single();

    const { data: admin2 } = await supabase
      .from('admins')
      .insert({
        username: 'otheradmin',
        email: 'other@test.com',
        password_hash: passwordHash
      })
      .select()
      .single();

    testAdminId = admin1.id;
    otherAdminId = admin2.id;
    testToken = generateToken({ sub: testAdminId, username: 'responseidadmin1' });

    // Créer une réponse pour testAdmin
    const { data: response1, error: error1 } = await supabase
      .from('responses')
      .insert({
        owner_id: testAdminId,
        name: 'TestUser',
        responses: createValidResponses({ q1: 'ça va', q2: 'Test response 1' }),
        month: '2025-10',
        is_owner: false,
        token: generateUniqueToken()
      })
      .select()
      .single();

    if (error1) {
      console.error('❌ Error creating response1:', error1);
      throw new Error(`Failed to create response1: ${error1.message}`);
    }

    testResponseId = response1.id;

    // Créer une réponse pour otherAdmin
    const { data: response2, error: error2 } = await supabase
      .from('responses')
      .insert({
        owner_id: otherAdminId,
        name: 'OtherUser',
        responses: createValidResponses({ q1: "WE'RE BARACK", q2: 'Test response 2' }),
        month: '2025-10',
        is_owner: false,
        token: generateUniqueToken()
      })
      .select()
      .single();

    if (error2) {
      console.error('❌ Error creating response2:', error2);
      throw new Error(`Failed to create response2: ${error2.message}`);
    }

    otherResponseId = response2.id;
  });

  afterAll(async () => {
    // Cleanup
    await supabase.from('responses').delete().eq('owner_id', testAdminId);
    await supabase.from('responses').delete().eq('owner_id', otherAdminId);
    await supabase.from('admins').delete().eq('id', testAdminId);
    await supabase.from('admins').delete().eq('id', otherAdminId);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ===========================
  // Tests GET
  // ===========================

  describe('GET', () => {
    test('Retourne 405 pour méthode PUT', async () => {
      verifyJWT.mockReturnValue(testAdminId); // JWT valide pour passer l'auth

      const req = {
        method: 'PUT',
        query: { id: testResponseId },
        headers: { authorization: `Bearer ${testToken}` }
      };
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
        query: { id: testResponseId },
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

    test('Retourne 400 si ID manquant', async () => {
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

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: 'Invalid response ID' });
    });

    test('Retourne 404 si réponse appartient à un autre admin', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'GET',
        query: { id: otherResponseId },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Response not found or access denied'
      });
    });

    test('Retourne la réponse complète si admin propriétaire', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'GET',
        query: { id: testResponseId },
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
      expect(responseData.response).toHaveProperty('id', testResponseId);
      expect(responseData.response).toHaveProperty('name', 'TestUser');
      expect(responseData.response).toHaveProperty('responses');
      expect(responseData.response.responses).toHaveLength(10); // 10 réponses valides
    });
  });

  // ===========================
  // Tests PATCH
  // ===========================

  describe('PATCH', () => {
    test('Retourne 401 si JWT invalide', async () => {
      verifyJWT.mockReturnValue(null);

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: { name: 'Updated Name' },
        headers: { authorization: 'Bearer invalid_token' }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
    });

    test('Retourne 404 si réponse appartient à un autre admin', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'PATCH',
        query: { id: otherResponseId },
        body: { name: 'Hacked Name' },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Response not found or access denied'
      });
    });

    test('Retourne 400 si nom trop court', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: { name: 'A' },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Name must be between 2 and 100 characters'
      });
    });

    test('Retourne 400 si responses n\'est pas un array', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: { responses: 'not an array' },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Responses must be an array'
      });
    });

    test('Retourne 400 si aucun champ à mettre à jour', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: {},
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'No valid fields to update'
      });
    });

    test('Met à jour le nom correctement', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: { name: 'Updated Name' },
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
      expect(responseData.response.name).toBe('Updated Name');
    });

    test('Met à jour les réponses correctement', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const newResponses = createValidResponses({ q1: 'ITS JOEVER', q2: 'Nouveau détail' });

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: { responses: newResponses },
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
      expect(responseData.response.responses).toHaveLength(10);
      expect(responseData.response.responses[0].answer).toBe('ITS JOEVER');
    });

    test('Échappe les caractères HTML dans les mises à jour', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const maliciousResponses = createValidResponses({ q2: '<b>Bold</b><script>alert("XSS")</script>' });

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: {
          name: 'Test<script>alert("XSS")</script>',
          responses: maliciousResponses
        },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      const responseData = res.json.mock.calls[0][0];

      expect(responseData.response.name).toContain('&lt;script&gt;');
      expect(responseData.response.responses[1].answer).toContain('&lt;b&gt;');
      expect(responseData.response.responses[1].answer).toContain('&lt;script&gt;');
    });

    test('Préserve les URLs Cloudinary', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const cloudinaryUrl = 'https://res.cloudinary.com/test/image/upload/v123/custom_photo.jpg';
      const responsesWithCloudinary = createValidResponses({ q3: cloudinaryUrl });

      const req = {
        method: 'PATCH',
        query: { id: testResponseId },
        body: {
          responses: responsesWithCloudinary
        },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(200);
      const responseData = res.json.mock.calls[0][0];

      // La Q3 (index 2) devrait avoir l'URL Cloudinary non-échappée
      expect(responseData.response.responses[2].answer).toBe(cloudinaryUrl);
    });
  });

  // ===========================
  // Tests DELETE
  // ===========================

  describe('DELETE', () => {
    let deleteResponseId;

    beforeEach(async () => {
      // Créer une nouvelle réponse à supprimer
      const { data } = await supabase
        .from('responses')
        .insert({
          owner_id: testAdminId,
          name: 'ToDelete',
          responses: createValidResponses({ q1: 'a connu meilleur mois' }),
          month: '2025-10',
          is_owner: false,
          token: generateUniqueToken()
        })
        .select()
        .single();

      deleteResponseId = data.id;
    });

    test('Retourne 401 si JWT invalide', async () => {
      verifyJWT.mockReturnValue(null);

      const req = {
        method: 'DELETE',
        query: { id: deleteResponseId },
        headers: { authorization: 'Bearer invalid_token' }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        end: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
    });

    test('Retourne 404 si réponse appartient à un autre admin', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'DELETE',
        query: { id: otherResponseId },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        end: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Response not found or access denied'
      });
    });

    test('Supprime la réponse et retourne 204', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      const req = {
        method: 'DELETE',
        query: { id: deleteResponseId },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        end: jest.fn()
      };

      await handler(req, res);

      expect(res.status).toHaveBeenCalledWith(204);
      expect(res.end).toHaveBeenCalled();

      // Vérifier que la réponse a été supprimée
      const { data } = await supabase
        .from('responses')
        .select('*')
        .eq('id', deleteResponseId)
        .single();

      expect(data).toBeNull();
    });

    test('Ne supprime pas les réponses d\'un autre admin', async () => {
      verifyJWT.mockReturnValue(testAdminId);

      // Compter les réponses de otherAdmin avant
      const { count: beforeCount } = await supabase
        .from('responses')
        .select('*', { count: 'exact', head: true })
        .eq('owner_id', otherAdminId);

      const req = {
        method: 'DELETE',
        query: { id: otherResponseId },
        headers: { authorization: `Bearer ${testToken}` }
      };
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        end: jest.fn()
      };

      await handler(req, res);

      // Vérifier que la réponse n'a PAS été supprimée
      const { count: afterCount } = await supabase
        .from('responses')
        .select('*', { count: 'exact', head: true })
        .eq('owner_id', otherAdminId);

      expect(afterCount).toBe(beforeCount);
    });
  });
});