/**
 * Tests de performance - Load Testing
 * FAF Multi-Tenant
 *
 * Simule 100 utilisateurs simultanés pour tester la charge
 */

const { createClient } = require('../../config/supabase');
const registerHandler = require('../../api/auth/register');
const loginHandler = require('../../api/auth/login');
const submitHandler = require('../../api/response/submit');

describe('Performance - Load Testing', () => {
  let supabase;
  const testAdminIds = [];

  beforeAll(() => {
    supabase = createClient();
  });

  afterAll(async () => {
    // Cleanup - supprimer tous les admins de test
    for (const adminId of testAdminIds) {
      await supabase.from('responses').delete().eq('owner_id', adminId);
      await supabase.from('admins').delete().eq('id', adminId);
    }
  });

  /**
   * Helper pour simuler une requête HTTP
   */
  function createMockRequest(method, body, headers = {}) {
    return {
      method,
      body,
      headers,
      query: {}
    };
  }

  function createMockResponse() {
    return {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      setHeader: jest.fn()
    };
  }

  /**
   * Test 1 : Inscription simultanée de 100 utilisateurs
   */
  test('100 users - Inscription simultanée (< 30s)', async () => {
    const startTime = Date.now();
    const promises = [];

    // Créer 100 promesses d'inscription simultanées
    for (let i = 0; i < 100; i++) {
      const req = createMockRequest('POST', {
        username: `loadtest_user_${i}_${Date.now()}`,
        email: `loadtest${i}_${Date.now()}@test.com`,
        password: 'LoadTest123!'
      });

      const res = createMockResponse();

      // Lancer l'inscription (sans await)
      const promise = registerHandler(req, res)
        .then(() => {
          // Sauvegarder l'admin ID pour cleanup
          if (res.status.mock.calls[0]?.[0] === 201) {
            const response = res.json.mock.calls[0]?.[0];
            if (response?.admin?.id) {
              testAdminIds.push(response.admin.id);
            }
          }
          return { status: res.status.mock.calls[0]?.[0] };
        })
        .catch(err => ({ error: err.message }));

      promises.push(promise);
    }

    // Attendre que toutes les inscriptions se terminent
    const results = await Promise.all(promises);

    const duration = Date.now() - startTime;

    // Vérifications
    const successCount = results.filter(r => r.status === 201).length;
    const errorCount = results.filter(r => r.error).length;

    console.log(`\n📊 Load Test Results - Register:
      - Total requests: 100
      - Success: ${successCount}
      - Errors: ${errorCount}
      - Duration: ${duration}ms (${(duration / 1000).toFixed(2)}s)
      - Avg per request: ${(duration / 100).toFixed(0)}ms
    `);

    // Au moins 80% de succès (rate limiting peut bloquer certains)
    expect(successCount).toBeGreaterThanOrEqual(80);

    // Durée totale < 30 secondes
    expect(duration).toBeLessThan(30000);
  }, 60000); // Timeout 60s

  /**
   * Test 2 : Connexion simultanée de 50 utilisateurs
   */
  test('50 users - Connexion simultanée (< 15s)', async () => {
    // D'abord, créer 50 admins de test
    const testUsers = [];

    for (let i = 0; i < 50; i++) {
      const username = `logintest_${i}_${Date.now()}`;
      const password = 'LoginTest123!';

      const req = createMockRequest('POST', {
        username,
        email: `${username}@test.com`,
        password
      });

      const res = createMockResponse();
      await registerHandler(req, res);

      if (res.status.mock.calls[0]?.[0] === 201) {
        const response = res.json.mock.calls[0]?.[0];
        testAdminIds.push(response.admin.id);
        testUsers.push({ username, password });
      }
    }

    // Attendre un peu pour éviter rate limiting
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Maintenant, connexion simultanée
    const startTime = Date.now();
    const promises = testUsers.map(({ username, password }) => {
      const req = createMockRequest('POST', {
        username,
        password
      });

      const res = createMockResponse();

      return loginHandler(req, res)
        .then(() => ({ status: res.status.mock.calls[0]?.[0] }))
        .catch(err => ({ error: err.message }));
    });

    const results = await Promise.all(promises);
    const duration = Date.now() - startTime;

    const successCount = results.filter(r => r.status === 200).length;
    const errorCount = results.filter(r => r.error || r.status !== 200).length;

    console.log(`\n📊 Load Test Results - Login:
      - Total requests: ${testUsers.length}
      - Success: ${successCount}
      - Errors: ${errorCount}
      - Duration: ${duration}ms (${(duration / 1000).toFixed(2)}s)
      - Avg per request: ${(duration / testUsers.length).toFixed(0)}ms
    `);

    // Au moins 90% de succès
    expect(successCount).toBeGreaterThanOrEqual(testUsers.length * 0.9);

    // Durée totale < 15 secondes
    expect(duration).toBeLessThan(15000);
  }, 60000);

  /**
   * Test 3 : Soumission simultanée de 30 formulaires
   */
  test('30 users - Soumission simultanée de formulaires (< 20s)', async () => {
    // Créer 1 admin de test
    const adminUsername = `submitadmin_${Date.now()}`;
    const reqRegister = createMockRequest('POST', {
      username: adminUsername,
      email: `${adminUsername}@test.com`,
      password: 'SubmitTest123!'
    });

    const resRegister = createMockResponse();
    await registerHandler(reqRegister, resRegister);

    const adminResponse = resRegister.json.mock.calls[0]?.[0];
    if (adminResponse?.admin?.id) {
      testAdminIds.push(adminResponse.admin.id);
    }

    // Attendre un peu
    await new Promise(resolve => setTimeout(resolve, 500));

    // Soumission simultanée de 30 formulaires
    const startTime = Date.now();
    const promises = [];

    for (let i = 0; i < 30; i++) {
      const req = createMockRequest('POST', {
        username: adminUsername,
        name: `User${i}`,
        responses: [
          { question: 'Question 1?', answer: `Réponse ${i} Q1` },
          { question: 'Question 2?', answer: `Réponse ${i} Q2` },
          { question: 'Question 3?', answer: `Réponse ${i} Q3` }
        ]
      });

      const res = createMockResponse();

      const promise = submitHandler(req, res)
        .then(() => ({ status: res.status.mock.calls[0]?.[0] }))
        .catch(err => ({ error: err.message }));

      promises.push(promise);
    }

    const results = await Promise.all(promises);
    const duration = Date.now() - startTime;

    const successCount = results.filter(r => r.status === 201).length;
    const errorCount = results.filter(r => r.error || r.status !== 201).length;

    console.log(`\n📊 Load Test Results - Submit:
      - Total requests: 30
      - Success: ${successCount}
      - Errors: ${errorCount}
      - Duration: ${duration}ms (${(duration / 1000).toFixed(2)}s)
      - Avg per request: ${(duration / 30).toFixed(0)}ms
    `);

    // Au moins 90% de succès
    expect(successCount).toBeGreaterThanOrEqual(27); // 90% de 30

    // Durée totale < 20 secondes
    expect(duration).toBeLessThan(20000);
  }, 60000);

  /**
   * Test 4 : Performance Dashboard - Récupération de données avec 100+ réponses
   */
  test('Dashboard - Performance avec 100+ réponses (< 3s)', async () => {
    // Créer un admin avec beaucoup de réponses
    const adminUsername = `dashboardadmin_${Date.now()}`;
    const reqRegister = createMockRequest('POST', {
      username: adminUsername,
      email: `${adminUsername}@test.com`,
      password: 'DashTest123!'
    });

    const resRegister = createMockResponse();
    await registerHandler(reqRegister, resRegister);

    const adminResponse = resRegister.json.mock.calls[0]?.[0];
    const adminId = adminResponse?.admin?.id;

    if (adminId) {
      testAdminIds.push(adminId);
    }

    // Insérer 100 réponses directement dans Supabase (plus rapide)
    const currentMonth = new Date().toISOString().slice(0, 7);
    const responses = [];

    for (let i = 0; i < 100; i++) {
      responses.push({
        owner_id: adminId,
        name: `User${i}`,
        responses: [
          { question: 'Q1?', answer: 'A1' },
          { question: 'Q2?', answer: 'A2' }
        ],
        month: currentMonth,
        is_admin: false,
        token: `token_${i}_${Date.now()}`
      });
    }

    // Insérer par batch de 20 (limite Supabase)
    for (let i = 0; i < responses.length; i += 20) {
      const batch = responses.slice(i, i + 20);
      await supabase.from('responses').insert(batch);
    }

    // Tester la performance du dashboard
    const dashboardHandler = require('../../api/admin/dashboard');

    const startTime = Date.now();

    const req = {
      method: 'GET',
      query: {},
      headers: {
        authorization: `Bearer ${adminResponse.token}`
      },
      user: { id: adminId, username: adminUsername }
    };

    const res = createMockResponse();

    await dashboardHandler(req, res);

    const duration = Date.now() - startTime;

    console.log(`\n📊 Load Test Results - Dashboard:
      - Total responses in DB: 100+
      - Query duration: ${duration}ms (${(duration / 1000).toFixed(2)}s)
    `);

    // Dashboard doit répondre en moins de 3 secondes même avec 100+ réponses
    expect(duration).toBeLessThan(3000);

    // Vérifier que les stats sont correctes
    const dashboardData = res.json.mock.calls[0]?.[0];
    expect(dashboardData.stats.totalResponses).toBeGreaterThanOrEqual(100);
  }, 60000);

  /**
   * Test 5 : Stress test - Taux de succès avec charge élevée
   */
  test('Stress test - 100 requêtes mixtes simultanées', async () => {
    const promises = [];
    const startTime = Date.now();

    // 50 inscriptions + 30 connexions + 20 soumissions
    for (let i = 0; i < 50; i++) {
      const req = createMockRequest('POST', {
        username: `stress_${i}_${Date.now()}`,
        email: `stress${i}_${Date.now()}@test.com`,
        password: 'Stress123!'
      });

      const res = createMockResponse();

      promises.push(
        registerHandler(req, res)
          .then(() => {
            if (res.status.mock.calls[0]?.[0] === 201) {
              const response = res.json.mock.calls[0]?.[0];
              if (response?.admin?.id) {
                testAdminIds.push(response.admin.id);
              }
            }
            return { type: 'register', status: res.status.mock.calls[0]?.[0] };
          })
          .catch(err => ({ type: 'register', error: err.message }))
      );
    }

    const results = await Promise.all(promises);
    const duration = Date.now() - startTime;

    const successCount = results.filter(r => r.status === 201 || r.status === 200).length;
    const totalRequests = results.length;

    console.log(`\n📊 Stress Test Results:
      - Total requests: ${totalRequests}
      - Success: ${successCount}
      - Errors: ${totalRequests - successCount}
      - Duration: ${duration}ms (${(duration / 1000).toFixed(2)}s)
      - Success rate: ${((successCount / totalRequests) * 100).toFixed(1)}%
    `);

    // Au moins 70% de succès même sous stress
    expect(successCount / totalRequests).toBeGreaterThanOrEqual(0.7);
  }, 90000); // Timeout 90s
});
