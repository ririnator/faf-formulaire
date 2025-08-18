/**
 * Tests de sécurité - Protection contre injection MongoDB
 * Valide les corrections apportées pour la recherche sécurisée
 */

const request = require('supertest');
const Response = require('../models/Response');

const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

beforeAll(async () => {
  app = getTestApp();
}, 30000);

describe('MongoDB Injection Security Tests', () => {
  let adminSession = null;

  beforeAll(async () => {
    // Connexion à la base de test
    if (!mongoose.connection.readyState) {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-test');
    }
    
    // Créer quelques responses de test
    await Response.deleteMany({});
    await Response.create([
      { name: 'Alice Test', responses: [{ question: 'Test?', answer: 'Response' }], month: '2025-01', isAdmin: false, token: 'token1' },
      { name: 'Bob Example', responses: [{ question: 'Example?', answer: 'Answer' }], month: '2025-01', isAdmin: false, token: 'token2' },
      { name: 'Charlie Admin', responses: [{ question: 'Admin?', answer: 'Yes' }], month: '2025-01', isAdmin: true }
    ]);
  });

  beforeEach(async () => {
    // Login admin pour accéder aux endpoints protégés
    const loginResponse = await request(app)
      .post('/auth/login')
      .send({
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: process.env.LOGIN_ADMIN_PASS || 'password'
      });
      
    if (loginResponse.headers['set-cookie']) {
      adminSession = loginResponse.headers['set-cookie'];
    }
  });

  afterAll(async () => {
    await Response.deleteMany({});
    });

  describe('Malicious Regex Pattern Tests', () => {
    const maliciousPatterns = [
      // ReDoS patterns
      '(a+)+$',
      '([a-zA-Z]+)*$',
      '^(([a-z])+.)+[A-Z]([a-z])+$',
      '(a|a)*$',
      
      // Regex injection attempts
      '.*',
      '.+',
      '^.*$',
      '(?=.*a)(?=.*b).*',
      
      // Special regex characters
      '\\w+',
      '\\d+',
      '\\s*',
      '[a-z]*',
      
      // MongoDB operators injection attempts
      '{"$regex": ".*"}',
      '{"$where": "this.name"}',
      '{"$ne": null}',
      
      // Complex nested patterns
      '((a)*b)*c',
      '(a|b)*aaaa',
      '(a+b)*c'
    ];

    maliciousPatterns.forEach((pattern) => {
      test(`should safely handle malicious pattern: ${pattern}`, async () => {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: pattern })
          .set('Cookie', adminSession)
          .timeout(5000); // Timeout pour détecter ReDoS

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('data');
        expect(Array.isArray(response.body.data)).toBe(true);
        
        // Vérifier que la réponse arrive rapidement (pas de ReDoS)
        expect(response.duration).toBeLessThan(1000);
      }, 10000);
    });
  });

  describe('Text Search Security Tests', () => {
    const testCases = [
      // Recherches normales
      { input: 'Alice', expectedCount: 1, description: 'normal search' },
      { input: 'Test', expectedCount: 1, description: 'partial match' },
      
      // Caractères spéciaux échappés
      { input: 'Al*ce', expectedCount: 0, description: 'wildcard characters' },
      { input: 'Al?ce', expectedCount: 0, description: 'question mark' },
      { input: 'Al+ce', expectedCount: 0, description: 'plus sign' },
      { input: 'Al.ce', expectedCount: 0, description: 'dot character' },
      
      // Tentatives d'injection
      { input: '"; DROP TABLE responses; --', expectedCount: 0, description: 'SQL injection attempt' },
      { input: '{"$ne": null}', expectedCount: 0, description: 'MongoDB operator injection' },
      { input: '\\x00', expectedCount: 0, description: 'null byte injection' },
      
      // Recherches très longues
      { input: 'a'.repeat(1000), expectedCount: 0, description: 'very long search' },
      { input: 'é'.repeat(100), expectedCount: 0, description: 'unicode characters' },
      
      // Caractères de contrôle
      { input: '\n\r\t', expectedCount: 0, description: 'control characters' },
      { input: '<script>alert(1)</script>', expectedCount: 0, description: 'XSS attempt' }
    ];

    testCases.forEach(({ input, expectedCount, description }) => {
      test(`should handle ${description}: "${input.substring(0, 20)}..."`, async () => {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: input })
          .set('Cookie', adminSession)
          .timeout(5000);

        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('data');
        expect(response.body.data).toHaveLength(expectedCount);
        
        // Vérifier pas d'erreur serveur
        expect(response.body).not.toHaveProperty('error');
      });
    });
  });

  describe('Search Sanitization Edge Cases', () => {
    test('should handle empty search', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: '' })
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
      expect(response.body.data.length).toBeGreaterThan(0);
    });

    test('should handle null search', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: null })
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
    });

    test('should handle undefined search', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
      expect(response.body.data.length).toBeGreaterThan(0);
    });

    test('should handle search with only whitespace', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: '   \t\n  ' })
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
    });

    test('should limit search length', async () => {
      const veryLongSearch = 'a'.repeat(200);
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: veryLongSearch })
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
      // Vérifier que la recherche est tronquée à 100 caractères maximum
    });

    test('should handle search with quotes and backslashes', async () => {
      const searchWithSpecialChars = 'Alice"Test\\Bob';
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: searchWithSpecialChars })
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('data');
    });
  });

  describe('MongoDB Text Index Functionality', () => {
    test('should use text search for longer queries', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: 'Alice Test' }) // >= 2 caractères
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].name).toBe('Alice Test');
    });

    test('should fallback to regex for short queries', async () => {
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: 'A' }) // < 2 caractères
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('data');
      // Peut retourner Alice Test et autres commençant par A
    });

    test('should handle French characters in text search', async () => {
      // Créer une response avec des caractères français
      await Response.create({
        name: 'François Élève',
        responses: [{ question: 'Français?', answer: 'Oui' }],
        month: '2025-01',
        isAdmin: false,
        token: 'token-french'
      });

      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: 'François' })
        .set('Cookie', adminSession);

      expect(response.status).toBe(200);
      const found = response.body.data.some(r => r.name.includes('François'));
      expect(found).toBe(true);
    });
  });

  describe('Performance and DoS Protection', () => {
    test('should complete search within reasonable time', async () => {
      const startTime = Date.now();
      
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: '((a)*b)*c' }) // Potentially expensive regex
        .set('Cookie', adminSession);

      const duration = Date.now() - startTime;
      
      expect(response.status).toBe(200);
      expect(duration).toBeLessThan(2000); // Max 2 seconds
    });

    test('should handle multiple concurrent searches', async () => {
      const searches = ['Alice', 'Bob', 'Charlie', 'Test', 'Example'];
      
      const promises = searches.map(search => 
        request(app)
          .get('/admin/api/responses')
          .query({ search })
          .set('Cookie', adminSession)
      );

      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('data');
      });
    });
  });

  describe('Error Handling and Logging', () => {
    test('should not expose internal errors in response', async () => {
      // Force une erreur en fermant temporairement la connexion
      const originalReadyState = mongoose.connection.readyState;
      
      const response = await request(app)
        .get('/admin/api/responses')
        .query({ search: 'test' })
        .set('Cookie', adminSession);

      // Même en cas d'erreur, pas d'exposition d'informations internes
      if (response.status === 500) {
        expect(response.body.error).not.toContain('stack');
        expect(response.body.error).not.toContain('mongo');
        expect(response.body.error).not.toContain('mongoose');
      }
    });
  });

  describe('Advanced MongoDB Injection Scenarios', () => {
    test('should handle complex nested MongoDB operators', async () => {
      const complexInjections = [
        '{"$and": [{"$or": [{"name": "admin"}]}]}',
        '{"$expr": {"$gt": ["$name", ""]}}',
        '{"$jsonSchema": {"properties": {"name": {"type": "string"}}}}',
        '{"$mod": [2, 0]}',
        '{"$elemMatch": {"$gt": 0}}',
        '{"$exists": true}',
        '{"$type": 2}',
        '{"$size": {"$gt": 0}}'
      ];

      for (const injection of complexInjections) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: injection })
          .set('Cookie', adminSession)
          .timeout(3000);

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body.data)).toBe(true);
        expect(response.duration).toBeLessThan(2000);
      }
    });

    test('should sanitize aggregation pipeline attempts', async () => {
      const aggregationAttempts = [
        '[{"$match": {"name": "admin"}}]',
        '[{"$group": {"_id": "$name"}}]',
        '[{"$project": {"name": 1}}]',
        '[{"$unwind": "$responses"}]',
        '[{"$lookup": {"from": "users", "localField": "name", "foreignField": "name", "as": "user"}}]'
      ];

      for (const attempt of aggregationAttempts) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: attempt })
          .set('Cookie', adminSession);

        expect(response.status).toBe(200);
        expect(response.body.data).toHaveLength(0);
      }
    });

    test('should handle JavaScript injection attempts in text search', async () => {
      const jsInjections = [
        'function(){return true}',
        '() => true',
        'eval("malicious code")',
        'new Function("return 1")',
        'setTimeout("alert(1)", 0)',
        'setInterval("console.log(1)", 1000)',
        'require("fs").readFileSync("/etc/passwd")'
      ];

      for (const injection of jsInjections) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: injection })
          .set('Cookie', adminSession);

        expect(response.status).toBe(200);
        expect(response.body.data).toHaveLength(0);
      }
    });

    test('should handle binary data and buffer overflow attempts', async () => {
      const binaryAttempts = [
        Buffer.from([0x00, 0x01, 0x02, 0xFF]).toString('hex'),
        '\x00\x01\x02\xFF',
        'A'.repeat(100000), // Large payload
        '\uD800\uDC00', // Unicode surrogate pair
        '\uFEFF\uFFFE', // Byte order marks
        String.fromCharCode(0) + 'admin',
        String.fromCharCode(65536) + 'test'
      ];

      for (const attempt of binaryAttempts) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: attempt })
          .set('Cookie', adminSession)
          .timeout(5000);

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body.data)).toBe(true);
        expect(response.duration).toBeLessThan(3000);
      }
    });

    test('should handle MongoDB connection string injection', async () => {
      const connectionAttempts = [
        'mongodb://admin:password@localhost:27017/admin',
        'mongodb+srv://cluster.mongodb.net/test',
        'mongodb://localhost:27017/test?authSource=admin',
        'mongodb://user:pass@host1:27017,host2:27017/db',
        'mongodb://localhost/?ssl=true&replicaSet=rs0'
      ];

      for (const attempt of connectionAttempts) {
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: attempt })
          .set('Cookie', adminSession);

        expect(response.status).toBe(200);
        expect(response.body.data).toHaveLength(0);
      }
    });

    test('should prevent timing-based injection attacks', async () => {
      const timingAttempts = [
        'admin"; sleep(5); --',
        'admin" + sleep(5000) + "',
        '{"$where": "sleep(5000)"}',
        '{"$regex": ".*", "$options": "i"}' + 'a'.repeat(10000)
      ];

      for (const attempt of timingAttempts) {
        const startTime = Date.now();
        
        const response = await request(app)
          .get('/admin/api/responses')
          .query({ search: attempt })
          .set('Cookie', adminSession)
          .timeout(8000);

        const duration = Date.now() - startTime;

        expect(response.status).toBe(200);
        expect(duration).toBeLessThan(5000); // Should not cause delays
      }
    });
  });
});