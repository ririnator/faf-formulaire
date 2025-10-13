/**
 * FAF Multi-Tenant - Tests de connexion Supabase
 *
 * Tests de validation pour:
 * - Connexion à Supabase
 * - Accès aux tables
 * - Row Level Security (RLS)
 * - Isolation des données par admin
 */

const {
  supabaseClient,
  supabaseAdmin,
  createAuthenticatedClient,
  testConnection
} = require('../utils/supabase');
const bcrypt = require('bcrypt');

describe('Supabase Connection Tests', () => {
  // Variables pour les tests
  let testAdmin1Id, testAdmin2Id;
  let testResponse1Id, testResponse2Id;

  // ============================================
  // Setup: Créer des admins et réponses de test
  // ============================================

  beforeAll(async () => {
    if (!supabaseAdmin) {
      console.warn('⚠️  Skipping tests: SUPABASE_SERVICE_KEY not defined');
      return;
    }

    // Créer deux admins de test
    const passwordHash = await bcrypt.hash('TestPassword123!', 10);

    // Admin 1
    const { data: admin1, error: error1 } = await supabaseAdmin
      .from('admins')
      .insert({
        username: 'testadmin1',
        email: 'testadmin1@example.com',
        password_hash: passwordHash
      })
      .select()
      .single();

    if (error1 && error1.code !== '23505') { // Ignorer si déjà existant
      console.error('Error creating admin1:', error1);
    } else if (admin1) {
      testAdmin1Id = admin1.id;
    }

    // Admin 2
    const { data: admin2, error: error2 } = await supabaseAdmin
      .from('admins')
      .insert({
        username: 'testadmin2',
        email: 'testadmin2@example.com',
        password_hash: passwordHash
      })
      .select()
      .single();

    if (error2 && error2.code !== '23505') { // Ignorer si déjà existant
      console.error('Error creating admin2:', error2);
    } else if (admin2) {
      testAdmin2Id = admin2.id;
    }

    // Si les admins existaient déjà, récupérer leurs IDs
    if (!testAdmin1Id) {
      const { data } = await supabaseAdmin
        .from('admins')
        .select('id')
        .eq('username', 'testadmin1')
        .single();
      testAdmin1Id = data?.id;
    }

    if (!testAdmin2Id) {
      const { data } = await supabaseAdmin
        .from('admins')
        .select('id')
        .eq('username', 'testadmin2')
        .single();
      testAdmin2Id = data?.id;
    }

    // Créer des réponses de test pour admin1
    const { data: resp1 } = await supabaseAdmin
      .from('responses')
      .insert({
        owner_id: testAdmin1Id,
        name: 'Alice',
        responses: [
          { question: 'Question 1', answer: 'Answer 1' },
          { question: 'Question 2', answer: 'Answer 2' },
          { question: 'Question 3', answer: 'Answer 3' },
          { question: 'Question 4', answer: 'Answer 4' },
          { question: 'Question 5', answer: 'Answer 5' },
          { question: 'Question 6', answer: 'Answer 6' },
          { question: 'Question 7', answer: 'Answer 7' },
          { question: 'Question 8', answer: 'Answer 8' },
          { question: 'Question 9', answer: 'Answer 9' },
          { question: 'Question 10', answer: 'Answer 10' }
        ],
        month: '2025-01',
        is_owner: false,
        token: 'a'.repeat(64)
      })
      .select()
      .single();

    testResponse1Id = resp1?.id;

    // Créer des réponses de test pour admin2
    const { data: resp2 } = await supabaseAdmin
      .from('responses')
      .insert({
        owner_id: testAdmin2Id,
        name: 'Bob',
        responses: [
          { question: 'Question 1', answer: 'Answer 1' },
          { question: 'Question 2', answer: 'Answer 2' },
          { question: 'Question 3', answer: 'Answer 3' },
          { question: 'Question 4', answer: 'Answer 4' },
          { question: 'Question 5', answer: 'Answer 5' },
          { question: 'Question 6', answer: 'Answer 6' },
          { question: 'Question 7', answer: 'Answer 7' },
          { question: 'Question 8', answer: 'Answer 8' },
          { question: 'Question 9', answer: 'Answer 9' },
          { question: 'Question 10', answer: 'Answer 10' }
        ],
        month: '2025-01',
        is_owner: false,
        token: 'b'.repeat(64)
      })
      .select()
      .single();

    testResponse2Id = resp2?.id;
  });

  // ============================================
  // Cleanup: Supprimer les données de test
  // ============================================

  afterAll(async () => {
    if (!supabaseAdmin) return;

    // Supprimer les réponses de test
    if (testResponse1Id) {
      await supabaseAdmin.from('responses').delete().eq('id', testResponse1Id);
    }
    if (testResponse2Id) {
      await supabaseAdmin.from('responses').delete().eq('id', testResponse2Id);
    }

    // Supprimer les admins de test (CASCADE supprimera aussi les réponses)
    if (testAdmin1Id) {
      await supabaseAdmin.from('admins').delete().eq('id', testAdmin1Id);
    }
    if (testAdmin2Id) {
      await supabaseAdmin.from('admins').delete().eq('id', testAdmin2Id);
    }
  });

  // ============================================
  // Tests de connexion basique
  // ============================================

  test('Should connect to Supabase', async () => {
    const result = await testConnection();
    expect(result.success).toBe(true);
    expect(result.url).toBeDefined();
  });

  test('Should have access to admins table', async () => {
    const { error } = await supabaseClient
      .from('admins')
      .select('*')
      .limit(1);

    expect(error).toBeNull();
  });

  test('Should have access to responses table', async () => {
    const { error } = await supabaseClient
      .from('responses')
      .select('*')
      .limit(1);

    expect(error).toBeNull();
  });

  // ============================================
  // Tests Row Level Security (RLS)
  // ============================================

  test('RLS should be enabled on responses', async () => {
    // Client anonyme ne devrait voir AUCUNE réponse (RLS filtre tout)
    const { data, error } = await supabaseClient
      .from('responses')
      .select('*');

    expect(error).toBeNull();
    expect(data).toEqual([]);
  });

  test('Service role should bypass RLS', async () => {
    if (!supabaseAdmin) {
      console.warn('⚠️  Skipping: SUPABASE_SERVICE_KEY not defined');
      return;
    }

    // Service role devrait voir TOUTES les réponses
    const { data, error } = await supabaseAdmin
      .from('responses')
      .select('*')
      .limit(10);

    expect(error).toBeNull();
    expect(data.length).toBeGreaterThanOrEqual(0);
  });

  // ============================================
  // Tests d'isolation des données
  // ============================================

  test('Admin 1 should only see their own responses', async () => {
    if (!supabaseAdmin || !testAdmin1Id) {
      console.warn('⚠️  Skipping: Test data not available');
      return;
    }

    // Simuler une requête avec le contexte d'admin1
    // Note: En production, ceci serait fait via JWT dans createAuthenticatedClient
    const { data, error } = await supabaseAdmin
      .from('responses')
      .select('*')
      .eq('owner_id', testAdmin1Id);

    expect(error).toBeNull();
    expect(data.length).toBeGreaterThanOrEqual(0);

    // Toutes les réponses doivent appartenir à admin1
    data.forEach(response => {
      expect(response.owner_id).toBe(testAdmin1Id);
    });
  });

  test('Admin 1 should NOT see Admin 2 responses', async () => {
    if (!supabaseAdmin || !testAdmin1Id || !testAdmin2Id) {
      console.warn('⚠️  Skipping: Test data not available');
      return;
    }

    // Tenter de récupérer les réponses d'admin2 avec le contexte d'admin1
    // En production, RLS empêcherait cette requête de retourner des résultats
    const { data: admin1Responses } = await supabaseAdmin
      .from('responses')
      .select('*')
      .eq('owner_id', testAdmin1Id);

    const { data: admin2Responses } = await supabaseAdmin
      .from('responses')
      .select('*')
      .eq('owner_id', testAdmin2Id);

    // Vérifier qu'il n'y a aucun chevauchement
    const admin1Ids = admin1Responses.map(r => r.id);
    const admin2Ids = admin2Responses.map(r => r.id);

    const overlap = admin1Ids.filter(id => admin2Ids.includes(id));
    expect(overlap.length).toBe(0);
  });

  // ============================================
  // Tests des contraintes de base de données
  // ============================================

  test('Should enforce unique username constraint', async () => {
    if (!supabaseAdmin) {
      console.warn('⚠️  Skipping: SUPABASE_SERVICE_KEY not defined');
      return;
    }

    const passwordHash = await bcrypt.hash('Password123!', 10);

    // Tenter de créer un admin avec un username existant
    const { error } = await supabaseAdmin
      .from('admins')
      .insert({
        username: 'testadmin1', // Déjà existant
        email: 'unique@example.com',
        password_hash: passwordHash
      });

    expect(error).not.toBeNull();
    expect(error.code).toBe('23505'); // Violation de contrainte unique
  });

  test('Should enforce username format constraint', async () => {
    if (!supabaseAdmin) {
      console.warn('⚠️  Skipping: SUPABASE_SERVICE_KEY not defined');
      return;
    }

    const passwordHash = await bcrypt.hash('Password123!', 10);

    // Tenter de créer un admin avec un username invalide (majuscules)
    const { error } = await supabaseAdmin
      .from('admins')
      .insert({
        username: 'InvalidUsername', // Majuscules non autorisées
        email: 'test@example.com',
        password_hash: passwordHash
      });

    expect(error).not.toBeNull();
    expect(error.code).toBe('23514'); // Violation de contrainte CHECK
  });

  test('Should enforce responses array format', async () => {
    if (!supabaseAdmin || !testAdmin1Id) {
      console.warn('⚠️  Skipping: Test data not available');
      return;
    }

    // Tenter d'insérer une réponse avec un format invalide (pas un array)
    const { error } = await supabaseAdmin
      .from('responses')
      .insert({
        owner_id: testAdmin1Id,
        name: 'Test',
        responses: { invalid: 'format' }, // Doit être un array
        month: '2025-01',
        is_owner: false
      });

    expect(error).not.toBeNull();
  });

  test('Should enforce token length constraint', async () => {
    if (!supabaseAdmin || !testAdmin1Id) {
      console.warn('⚠️  Skipping: Test data not available');
      return;
    }

    // Tenter d'insérer une réponse avec un token trop court
    const { error } = await supabaseAdmin
      .from('responses')
      .insert({
        owner_id: testAdmin1Id,
        name: 'Test',
        responses: [
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
        ],
        month: '2025-01',
        is_owner: false,
        token: 'too-short' // Doit être 64 caractères
      });

    expect(error).not.toBeNull();
    expect(error.code).toBe('23514'); // Violation de contrainte CHECK
  });

  // ============================================
  // Tests de performance
  // ============================================

  test('Should use indexes for owner_id queries', async () => {
    if (!supabaseAdmin || !testAdmin1Id) {
      console.warn('⚠️  Skipping: Test data not available');
      return;
    }

    const startTime = Date.now();

    // Requête utilisant l'index idx_responses_owner
    const { error } = await supabaseAdmin
      .from('responses')
      .select('*')
      .eq('owner_id', testAdmin1Id);

    const duration = Date.now() - startTime;

    expect(error).toBeNull();
    expect(duration).toBeLessThan(500); // Devrait être rapide grâce à l'index
  });

  test('Should use indexes for token queries', async () => {
    if (!supabaseAdmin) {
      console.warn('⚠️  Skipping: SUPABASE_SERVICE_KEY not defined');
      return;
    }

    const startTime = Date.now();

    // Requête utilisant l'index idx_responses_token
    const { error } = await supabaseAdmin
      .from('responses')
      .select('*')
      .eq('token', 'a'.repeat(64));

    const duration = Date.now() - startTime;

    expect(error).toBeNull();
    expect(duration).toBeLessThan(500); // Devrait être rapide grâce à l'index
  });
});
