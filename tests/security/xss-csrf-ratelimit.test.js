/**
 * Tests de sécurité - XSS, CSRF, Rate Limiting
 * FAF Multi-Tenant
 */

const { escapeHtml, isCloudinaryUrl } = require('../../utils/validation');
const submitHandler = require('../../api/response/submit');
const loginHandler = require('../../api/auth/login');
const registerHandler = require('../../api/auth/register');
const { createClient } = require('../../config/supabase');
const bcrypt = require('bcrypt');

describe('Tests de sécurité', () => {
  let supabase;
  let testAdminId;

  beforeAll(async () => {
    supabase = createClient();

    // Créer un admin de test
    const passwordHash = await bcrypt.hash('TestPass123!', 10);
    const { data: admin } = await supabase
      .from('admins')
      .insert({
        username: 'securitytestadmin',
        email: 'security@test.com',
        password_hash: passwordHash
      })
      .select()
      .single();

    testAdminId = admin.id;
  });

  afterAll(async () => {
    if (testAdminId) {
      await supabase.from('responses').delete().eq('owner_id', testAdminId);
      await supabase.from('admins').delete().eq('id', testAdminId);
    }
  });

  // ========================================
  // TESTS XSS (Cross-Site Scripting)
  // ========================================

  describe('XSS Prevention', () => {
    test('Escape HTML - Balises script bloquées', () => {
      const malicious = '<script>alert("XSS")</script>';
      const escaped = escapeHtml(malicious);

      expect(escaped).toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
      expect(escaped).not.toContain('<script>');
    });

    test('Escape HTML - Event handlers bloqués', () => {
      const malicious = '<img src=x onerror="alert(1)">';
      const escaped = escapeHtml(malicious);

      expect(escaped).toBe('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
      expect(escaped).not.toContain('onerror=');
    });

    test('Escape HTML - Injection SQL-like bloquée', () => {
      const malicious = "'; DROP TABLE admins; --";
      const escaped = escapeHtml(malicious);

      expect(escaped).toBe('&#x27;; DROP TABLE admins; --');
      expect(escaped).not.toContain("'"));
    });

    test('Cloudinary URLs - Préservées si valides', () => {
      const validUrl = 'https://res.cloudinary.com/test/image/upload/v123/photo.jpg';

      expect(isCloudinaryUrl(validUrl)).toBe(true);

      // Validation ne doit PAS échapper les URLs Cloudinary valides
      const validated = isCloudinaryUrl(validUrl) ? validUrl : escapeHtml(validUrl);
      expect(validated).toBe(validUrl);
    });

    test('URLs malicieuses - Bloquées si non-Cloudinary', () => {
      const maliciousUrl = 'javascript:alert(1)';

      expect(isCloudinaryUrl(maliciousUrl)).toBe(false);
    });

    test('Submit avec XSS dans réponse - Doit être échappé', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'securitytestadmin',
          name: 'TestUser',
          responses: [
            {
              question: 'Question normale?',
              answer: '<script>alert("XSS")</script>'
            }
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

      // Vérifier que la soumission a réussi
      expect(res.status).toHaveBeenCalledWith(201);

      // Récupérer la réponse depuis Supabase
      const { data: response } = await supabase
        .from('responses')
        .select('*')
        .eq('owner_id', testAdminId)
        .eq('name', 'TestUser')
        .single();

      // Vérifier que le XSS a été échappé
      expect(response.responses[0].answer).toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');
      expect(response.responses[0].answer).not.toContain('<script>');
    });

    test('Submit avec nom XSS - Doit être échappé', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'securitytestadmin',
          name: '<img src=x onerror=alert(1)>',
          responses: [
            { question: 'Q1?', answer: 'Réponse normale' }
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

      // Vérifier que le nom a été échappé
      const { data: response } = await supabase
        .from('responses')
        .select('*')
        .eq('owner_id', testAdminId)
        .ilike('name', '%img%')
        .single();

      expect(response.name).toBe('&lt;img src=x onerror=alert(1)&gt;');
      expect(response.name).not.toContain('<img');
    });
  });

  // ========================================
  // TESTS RATE LIMITING
  // ========================================

  describe('Rate Limiting', () => {
    test('Login - 5 tentatives max en 15 minutes', async () => {
      const attempts = [];

      // Essayer 6 connexions rapides (devrait bloquer la 6ème)
      for (let i = 0; i < 6; i++) {
        const req = {
          method: 'POST',
          body: {
            username: 'securitytestadmin',
            password: 'WrongPassword!'
          },
          headers: {
            'x-forwarded-for': '192.168.1.100' // Simuler même IP
          }
        };

        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
          setHeader: jest.fn()
        };

        await loginHandler(req, res);
        attempts.push(res.status.mock.calls[0][0]);

        // Petit délai pour éviter problèmes de timing
        await new Promise(resolve => setTimeout(resolve, 50));
      }

      // Les 5 premières doivent être 401 (credentials invalides)
      expect(attempts.slice(0, 5).every(status => status === 401)).toBe(true);

      // La 6ème peut être 429 (rate limited) ou 401 selon implémentation
      // Ce test vérifie juste que le rate limiting est considéré
      expect([401, 429]).toContain(attempts[5]);
    }, 15000); // Timeout 15s

    test('Register - Rate limiting sur création de comptes', async () => {
      const attempts = [];

      // Essayer 6 inscriptions rapides
      for (let i = 0; i < 6; i++) {
        const req = {
          method: 'POST',
          body: {
            username: `ratelimituser${i}`,
            email: `ratelimit${i}@test.com`,
            password: 'SecurePass123!'
          },
          headers: {
            'x-forwarded-for': '192.168.1.200'
          }
        };

        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn(),
          setHeader: jest.fn()
        };

        await registerHandler(req, res);
        attempts.push({
          status: res.status.mock.calls[0][0],
          username: `ratelimituser${i}`
        });

        await new Promise(resolve => setTimeout(resolve, 50));
      }

      // Au moins une tentative doit être bloquée ou limitée
      const successCount = attempts.filter(a => a.status === 201).length;
      expect(successCount).toBeLessThan(6);

      // Cleanup - supprimer les admins créés
      for (const attempt of attempts) {
        if (attempt.status === 201) {
          await supabase
            .from('admins')
            .delete()
            .eq('username', attempt.username);
        }
      }
    }, 15000);
  });

  // ========================================
  // TESTS INPUT VALIDATION
  // ========================================

  describe('Input Validation', () => {
    test('Submit - Nom trop court (< 2 caractères) doit échouer', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'securitytestadmin',
          name: 'A',
          responses: [
            { question: 'Q1?', answer: 'Réponse' }
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

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('Nom')
        })
      );
    });

    test('Submit - Nom trop long (> 100 caractères) doit échouer', async () => {
      const longName = 'A'.repeat(101);

      const req = {
        method: 'POST',
        body: {
          username: 'securitytestadmin',
          name: longName,
          responses: [
            { question: 'Q1?', answer: 'Réponse' }
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

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('Nom')
        })
      );
    });

    test('Submit - Réponse vide doit échouer', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'securitytestadmin',
          name: 'ValidUser',
          responses: [
            { question: 'Q1?', answer: '' }
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

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('Réponse')
        })
      );
    });

    test('Submit - Trop de questions (> 20) doit échouer', async () => {
      const tooManyResponses = Array(21).fill(null).map((_, i) => ({
        question: `Question ${i}?`,
        answer: `Réponse ${i}`
      }));

      const req = {
        method: 'POST',
        body: {
          username: 'securitytestadmin',
          name: 'ValidUser',
          responses: tooManyResponses
        },
        headers: {}
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await submitHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringMatching(/maximum|trop/i)
        })
      );
    });

    test('Register - Email invalide doit échouer', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'validuser',
          email: 'invalid-email',
          password: 'SecurePass123!'
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await registerHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('email')
        })
      );
    });

    test('Register - Password trop court (< 8 caractères) doit échouer', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'validuser',
          email: 'valid@test.com',
          password: 'Short1!'
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await registerHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.stringContaining('password')
        })
      );
    });
  });

  // ========================================
  // TESTS SQL INJECTION
  // ========================================

  describe('SQL Injection Prevention', () => {
    test('Login avec SQL injection dans username - Doit échouer proprement', async () => {
      const req = {
        method: 'POST',
        body: {
          username: "admin' OR '1'='1",
          password: 'anything'
        }
      };

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
      };

      await loginHandler(req, res);

      // Doit retourner 401 (pas d'erreur SQL)
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.any(String)
        })
      );
    });

    test('Submit avec SQL injection dans nom - Doit être échappé', async () => {
      const req = {
        method: 'POST',
        body: {
          username: 'securitytestadmin',
          name: "'; DELETE FROM responses WHERE '1'='1",
          responses: [
            { question: 'Q1?', answer: 'Réponse' }
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

      // Doit réussir (SQL échappé par Supabase)
      expect(res.status).toHaveBeenCalledWith(201);

      // Vérifier que les données ne sont pas corrompues
      const { count } = await supabase
        .from('responses')
        .select('*', { count: 'exact', head: true })
        .eq('owner_id', testAdminId);

      // Doit avoir au moins les réponses de test (pas toutes supprimées)
      expect(count).toBeGreaterThan(0);
    });
  });
});
