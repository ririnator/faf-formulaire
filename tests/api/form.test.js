/**
 * Tests pour /api/form/[username]
 *
 * Tests couverts :
 * - Récupération du formulaire d'un admin existant
 * - Gestion du 404 pour un admin inexistant
 * - Validation du format de username
 * - Vérification de la structure de la réponse
 * - Vérification des questions retournées
 */

const { createClient } = require('../../config/supabase');
const handler = require('../../api/form/[username]');
const { getQuestions } = require('../../utils/questions');
const bcrypt = require('bcrypt');

// Mock request et response
function createMockReq(method = 'GET', query = {}) {
  return {
    method,
    query
  };
}

function createMockRes() {
  const res = {
    statusCode: 200,
    data: null,
    status: function(code) {
      this.statusCode = code;
      return this;
    },
    json: function(data) {
      this.data = data;
      return this;
    }
  };
  return res;
}

describe('API: /api/form/[username]', () => {
  let supabase;
  let testAdminId;
  // Générer un username unique mais court (max 20 caractères)
  const testUsername = 'test' + Math.random().toString(36).substring(2, 10);

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
    // Nettoyer : supprimer l'admin de test
    if (testAdminId) {
      await supabase
        .from('admins')
        .delete()
        .eq('id', testAdminId);
    }
  });

  describe('GET /api/form/[username]', () => {
    test('should return 405 for non-GET methods', async () => {
      const req = createMockReq('POST');
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(405);
      expect(res.data.success).toBe(false);
      expect(res.data.error).toBe('Method not allowed');
    });

    test('should return 400 if username is missing', async () => {
      const req = createMockReq('GET', {});
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.data.success).toBe(false);
      expect(res.data.error).toBe('Username parameter is required');
    });

    test('should return 400 for invalid username format', async () => {
      const req = createMockReq('GET', { username: 'INVALID USERNAME!' });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(400);
      expect(res.data.success).toBe(false);
      expect(res.data.error).toBe('Invalid username format');
    });

    test('should return 404 if admin does not exist', async () => {
      const req = createMockReq('GET', { username: 'nonexistentuser999' });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(404);
      expect(res.data.success).toBe(false);
      expect(res.data.error).toBe('Admin not found');
      expect(res.data.message).toContain('nonexistentuser999');
    });

    test('should return 200 and form data for existing admin', async () => {
      const req = createMockReq('GET', { username: testUsername });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(200);
      expect(res.data.success).toBe(true);
      expect(res.data.admin).toBeDefined();
      expect(res.data.admin.username).toBe(testUsername);
      expect(res.data.admin.formUrl).toBe(`/form/${testUsername}`);
    });

    test('should return all questions in the response', async () => {
      const req = createMockReq('GET', { username: testUsername });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(200);
      expect(res.data.questions).toBeDefined();
      expect(Array.isArray(res.data.questions)).toBe(true);
      expect(res.data.questions.length).toBeGreaterThan(0);
    });

    test('should return correct metadata', async () => {
      const req = createMockReq('GET', { username: testUsername });
      const res = createMockRes();

      await handler(req, res);

      const questions = getQuestions();
      const requiredCount = questions.filter(q => q.required).length;
      const optionalCount = questions.filter(q => !q.required).length;

      expect(res.statusCode).toBe(200);
      expect(res.data.metadata).toBeDefined();
      expect(res.data.metadata.totalQuestions).toBe(questions.length);
      expect(res.data.metadata.requiredQuestions).toBe(requiredCount);
      expect(res.data.metadata.optionalQuestions).toBe(optionalCount);
    });

    test('should normalize username (case-insensitive)', async () => {
      const req = createMockReq('GET', { username: testUsername.toUpperCase() });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(200);
      expect(res.data.success).toBe(true);
      expect(res.data.admin.username).toBe(testUsername);
    });

    test('should have correct question structure', async () => {
      const req = createMockReq('GET', { username: testUsername });
      const res = createMockRes();

      await handler(req, res);

      expect(res.statusCode).toBe(200);

      // Vérifier la structure de chaque question
      res.data.questions.forEach(question => {
        expect(question).toHaveProperty('id');
        expect(question).toHaveProperty('type');
        expect(question).toHaveProperty('question');
        expect(question).toHaveProperty('required');

        // Vérifier les types valides
        expect(['text', 'textarea', 'radio', 'file']).toContain(question.type);

        // Les questions radio doivent avoir des options
        if (question.type === 'radio') {
          expect(question).toHaveProperty('options');
          expect(Array.isArray(question.options)).toBe(true);
          expect(question.options.length).toBeGreaterThan(0);
        }
      });
    });
  });
});

describe('Utils: questions.js', () => {
  test('getQuestions should return an array', () => {
    const questions = getQuestions();
    expect(Array.isArray(questions)).toBe(true);
    expect(questions.length).toBeGreaterThan(0);
  });

  test('all questions should have required fields', () => {
    const questions = getQuestions();

    questions.forEach(q => {
      expect(q).toHaveProperty('id');
      expect(q).toHaveProperty('type');
      expect(q).toHaveProperty('question');
      expect(q).toHaveProperty('required');
    });
  });

  test('should have at least 10 questions', () => {
    const questions = getQuestions();
    expect(questions.length).toBeGreaterThanOrEqual(10);
  });

  test('should have at least one optional question', () => {
    const questions = getQuestions();
    const optionalQuestions = questions.filter(q => !q.required);
    expect(optionalQuestions.length).toBeGreaterThan(0);
  });

  test('validateRequiredQuestions should detect missing answers', () => {
    const { validateRequiredQuestions } = require('../../utils/questions');

    // Réponses incomplètes
    const responses = [
      { question: 'En rapide, comment ça va ?', answer: 'ça va' }
    ];

    const result = validateRequiredQuestions(responses);

    expect(result.valid).toBe(false);
    expect(result.missing.length).toBeGreaterThan(0);
  });

  test('validateRequiredQuestions should pass with all required answers', () => {
    const { validateRequiredQuestions, getQuestions } = require('../../utils/questions');

    const questions = getQuestions();
    const requiredQuestions = questions.filter(q => q.required);

    // Créer des réponses pour toutes les questions requises
    const responses = requiredQuestions.map(q => ({
      question: q.question,
      answer: 'test answer'
    }));

    const result = validateRequiredQuestions(responses);

    expect(result.valid).toBe(true);
    expect(result.missing.length).toBe(0);
  });
});
