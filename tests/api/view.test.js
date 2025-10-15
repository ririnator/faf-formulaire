/**
 * Tests pour /api/response/view/[token]
 * Étape 5 : API Consultation privée
 *
 * Scénarios testés :
 * 1. Validation HTTP et format token
 * 2. Récupération comparaison valide
 * 3. Gestion erreurs (token invalide, admin n'a pas répondu)
 * 4. Format des données retournées
 */

const handler = require('../../api/response/view/[token]');
const { createClient } = require('../../config/supabase');
const { generateToken } = require('../../utils/tokens');
const bcrypt = require('bcrypt');

// Mock de req/res
function createMockRequest(method = 'GET', query = {}) {
  return {
    method,
    query,
  };
}

function createMockResponse() {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
  };

  res.status = (code) => {
    res.statusCode = code;
    return res;
  };

  res.json = (data) => {
    res.body = data;
    return res;
  };

  res.setHeader = (key, value) => {
    res.headers[key] = value;
    return res;
  };

  return res;
}

// Helper pour créer des données de test
let testAdminId = null;
let testToken = null;

beforeAll(async () => {
  const supabase = createClient();

  // Créer un hash bcrypt valide pour les tests
  const passwordHash = await bcrypt.hash('testpassword123', 10);

  // Créer un admin de test
  const uniqueId = Date.now().toString().slice(-6); // Prendre les 6 derniers chiffres
  const { data: admin, error: adminError } = await supabase
    .from('admins')
    .insert({
      username: `testview${uniqueId}`,
      email: `view${uniqueId}@test.com`,
      password_hash: passwordHash,
    })
    .select()
    .single();

  if (adminError) {
    throw new Error(`Failed to create test admin: ${adminError.message}`);
  }

  testAdminId = admin.id;

  // Créer des réponses avec 10 questions (minimum requis)
  const adminResponses = [];
  const friendResponses = [];
  for (let i = 1; i <= 10; i++) {
    adminResponses.push({
      question: `Question ${i}`,
      answer: `Admin Answer ${i}`
    });
    friendResponses.push({
      question: `Question ${i}`,
      answer: `Friend Answer ${i}`
    });
  }

  // Créer la réponse de l'admin
  const { error: adminResponseError } = await supabase.from('responses').insert({
    owner_id: testAdminId,
    name: admin.username,
    responses: adminResponses,
    month: new Date().toISOString().slice(0, 7),
    is_owner: true,
    token: null,
  });

  if (adminResponseError) {
    throw new Error(`Failed to create admin response: ${adminResponseError.message}`);
  }

  // Créer une réponse d'ami avec token
  testToken = generateToken();
  const { error: friendResponseError } = await supabase.from('responses').insert({
    owner_id: testAdminId,
    name: 'Friend Tester',
    responses: friendResponses,
    month: new Date().toISOString().slice(0, 7),
    is_owner: false,
    token: testToken,
  });

  if (friendResponseError) {
    throw new Error(`Failed to create friend response: ${friendResponseError.message}`);
  }
});

afterAll(async () => {
  if (!testAdminId) return;

  const supabase = createClient();

  // Supprimer les réponses de test
  await supabase.from('responses').delete().eq('owner_id', testAdminId);

  // Supprimer l'admin de test
  await supabase.from('admins').delete().eq('id', testAdminId);
});

describe('API /api/response/view/[token] - Validation HTTP', () => {
  test('Retourne 405 pour méthode POST', async () => {
    const req = createMockRequest('POST', { token: 'abc123' });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(405);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Method not allowed');
  });

  test('Retourne 405 pour méthode PUT', async () => {
    const req = createMockRequest('PUT', { token: 'abc123' });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(405);
    expect(res.body.success).toBe(false);
  });

  test('Retourne 400 si token manquant', async () => {
    const req = createMockRequest('GET', {});
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Token is required');
  });

  test('Retourne 400 si token invalide (trop court)', async () => {
    const req = createMockRequest('GET', { token: 'abc123' });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Invalid token format');
  });

  test('Retourne 400 si token invalide (caractères invalides)', async () => {
    const req = createMockRequest('GET', {
      token: 'z'.repeat(64), // 64 chars mais pas hexadécimal
    });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Invalid token format');
  });
});

describe('API /api/response/view/[token] - Récupération données', () => {
  test('Retourne 404 pour token inexistant', async () => {
    const fakeToken = generateToken();
    const req = createMockRequest('GET', { token: fakeToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(404);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Token not found');
    expect(res.body.message).toContain('invalide ou a expiré');
  });

  test('Retourne comparaison valide avec token existant', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);
    expect(res.body.success).toBe(true);

    // Vérifier structure de la réponse
    expect(res.body.user).toBeDefined();
    expect(res.body.admin).toBeDefined();
    expect(res.body.adminUsername).toBeDefined();
    expect(res.body.monthName).toBeDefined();

    // Vérifier données utilisateur
    expect(res.body.user.name).toBe('Friend Tester');
    expect(res.body.user.responses).toHaveLength(10);
    expect(res.body.user.responses[0].question).toBe('Question 1');
    expect(res.body.user.responses[0].answer).toBe('Friend Answer 1');

    // Vérifier données admin
    expect(res.body.admin.responses).toHaveLength(10);
    expect(res.body.admin.responses[0].question).toBe('Question 1');
    expect(res.body.admin.responses[0].answer).toBe('Admin Answer 1');

    // Vérifier mois
    expect(res.body.user.month).toBe(res.body.admin.month);
  });

  test('Retourne le nom du mois formaté correctement', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);

    // Vérifier format du mois (ex: "Octobre 2025")
    expect(res.body.monthName).toMatch(/^(Janvier|Février|Mars|Avril|Mai|Juin|Juillet|Août|Septembre|Octobre|Novembre|Décembre) \d{4}$/);
  });

  test('Retourne 404 si admin n\'a pas rempli son formulaire', async () => {
    const supabase = createClient();

    // Créer un hash bcrypt valide
    const passwordHash = await bcrypt.hash('testpassword123', 10);

    // Créer un nouvel admin sans réponse
    const uniqueId = Date.now().toString().slice(-6);
    const { data: newAdmin } = await supabase
      .from('admins')
      .insert({
        username: `noresp${uniqueId}`,
        email: `noresp${uniqueId}@test.com`,
        password_hash: passwordHash,
      })
      .select()
      .single();

    // Créer une réponse d'ami uniquement (10 questions minimum)
    const token = generateToken();
    const responses = [];
    for (let i = 1; i <= 10; i++) {
      responses.push({ question: `Q${i}`, answer: `A${i}` });
    }
    await supabase.from('responses').insert({
      owner_id: newAdmin.id,
      name: 'Lonely Friend',
      responses: responses,
      month: new Date().toISOString().slice(0, 7),
      is_owner: false,
      token: token,
    });

    const req = createMockRequest('GET', { token });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(404);
    expect(res.body.success).toBe(false);
    expect(res.body.error).toBe('Admin response not found');
    expect(res.body.message).toContain('administrateur n\'a pas encore rempli son formulaire');

    // Cleanup
    await supabase.from('responses').delete().eq('owner_id', newAdmin.id);
    await supabase.from('admins').delete().eq('id', newAdmin.id);
  });
});

describe('API /api/response/view/[token] - Format des données', () => {
  test('Retourne tous les champs requis pour l\'utilisateur', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);

    expect(res.body.user).toHaveProperty('name');
    expect(res.body.user).toHaveProperty('responses');
    expect(res.body.user).toHaveProperty('month');
    expect(res.body.user).toHaveProperty('createdAt');
  });

  test('Retourne tous les champs requis pour l\'admin', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);

    expect(res.body.admin).toHaveProperty('name');
    expect(res.body.admin).toHaveProperty('responses');
    expect(res.body.admin).toHaveProperty('month');
  });

  test('Les réponses sont au format JSONB correct', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);

    // Vérifier que responses est un array
    expect(Array.isArray(res.body.user.responses)).toBe(true);
    expect(Array.isArray(res.body.admin.responses)).toBe(true);

    // Vérifier la structure de chaque réponse
    res.body.user.responses.forEach((resp) => {
      expect(resp).toHaveProperty('question');
      expect(resp).toHaveProperty('answer');
      expect(typeof resp.question).toBe('string');
      expect(typeof resp.answer).toBe('string');
    });
  });

  test('Ne retourne pas le token dans les données', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);

    // Vérifier que le token n'est pas exposé
    expect(res.body.user.token).toBeUndefined();
    expect(res.body.admin.token).toBeUndefined();
  });

  test('Ne retourne pas le owner_id dans les données', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    expect(res.statusCode).toBe(200);

    // Vérifier que owner_id n'est pas exposé
    expect(res.body.user.owner_id).toBeUndefined();
    expect(res.body.admin.owner_id).toBeUndefined();
  });
});

describe('API /api/response/view/[token] - Sécurité', () => {
  test('Token de 64 caractères est valide', async () => {
    const req = createMockRequest('GET', { token: testToken });
    const res = createMockResponse();

    await handler(req, res);

    // Ne devrait pas retourner d'erreur de format
    expect(res.statusCode).not.toBe(400);
  });

  test('Gère les erreurs serveur proprement', async () => {
    // Token valide en format mais qui causera une erreur DB (pas dans notre cas, mais on teste le catch)
    const validFormatToken = 'a'.repeat(64);
    const req = createMockRequest('GET', { token: validFormatToken });
    const res = createMockResponse();

    await handler(req, res);

    // Devrait retourner 404 (token non trouvé) et non 500
    expect(res.statusCode).toBe(404);
    expect(res.body.success).toBe(false);
  });
});
