const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const Response = require('../models/Response');

describe('Dynamic Option Integration Tests', () => {
  
  beforeAll(async () => {
    // Connexion à la base de test
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-test');
    }
  });

  beforeEach(async () => {
    await Response.deleteMany({});
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  /**
   * Génère la même logique que le frontend pour tester la cohérence
   */
  function generateDynamicOption2(customDate = null) {
    const today = customDate || new Date();
    const prev = new Date(today.getFullYear(), today.getMonth() - 1, 1);
    
    const month = prev.toLocaleString('fr-FR', { month: 'long' });
    const vowelsAndH = ['a', 'e', 'i', 'o', 'u', 'h'];
    
    const firstLetter = month[0].toLowerCase();
    const prefix = vowelsAndH.includes(firstLetter)
      ? "a connu meilleur mois d'"
      : 'a connu meilleur mois de ';
    
    return `${prefix}${month}`;
  }

  describe('Form Submission with Dynamic Option', () => {

    test('should successfully submit form with dynamically generated option2', async () => {
      const dynamicOption2 = generateDynamicOption2();
      
      const formData = {
        name: 'Test User',
        responses: [
          {
            question: 'En rapide, comment ça va ?',
            answer: dynamicOption2 // Utilise l'option générée dynamiquement
          },
          {
            question: 'Question test',
            answer: 'Réponse test'
          }
        ]
      };

      const response = await request(app)
        .post('/api/response')
        .send(formData)
        .expect(201);

      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('link');
      
      // Vérifier que la réponse a été sauvegardée avec la bonne valeur
      const savedResponse = await Response.findOne({ name: 'Test User' });
      expect(savedResponse).toBeTruthy();
      expect(savedResponse.responses[0].answer).toBe(dynamicOption2);
    });

    test('should handle all French months correctly in submissions', async () => {
      // Test avec différents mois pour vérifier la cohérence
      const monthTests = [
        { date: '2024-02-01', expected: 'janvier' },
        { date: '2024-05-01', expected: 'avril' },
        { date: '2024-09-01', expected: 'août' },
        { date: '2024-11-01', expected: 'octobre' }
      ];

      for (const { date, expected } of monthTests) {
        const testDate = new Date(date);
        const dynamicOption = generateDynamicOption2(testDate);
        
        const formData = {
          name: `Test User ${expected}`,
          responses: [{
            question: 'En rapide, comment ça va ?',
            answer: dynamicOption
          }]
        };

        const response = await request(app)
          .post('/api/response')
          .send(formData)
          .expect(201);

        expect(response.body.message).toBeTruthy();
        
        // Vérifier en base
        const saved = await Response.findOne({ name: `Test User ${expected}` });
        expect(saved.responses[0].answer).toContain(expected);
      }
    });

    test('should pass validation with vowel and consonant prefixes', async () => {
      // Test préfixe voyelle (d')
      const vowelMonth = generateDynamicOption2(new Date('2024-05-01')); // avril
      expect(vowelMonth).toContain("d'avril");
      
      // Test préfixe consonne (de )
      const consonantMonth = generateDynamicOption2(new Date('2024-02-01')); // janvier
      expect(consonantMonth).toContain('de janvier');

      // Test soumission avec préfixe voyelle
      const response1 = await request(app)
        .post('/api/response')
        .send({
          name: 'User Vowel',
          responses: [{
            question: 'Test question',
            answer: vowelMonth
          }]
        })
        .expect(201);

      // Test soumission avec préfixe consonne  
      const response2 = await request(app)
        .post('/api/response')
        .send({
          name: 'User Consonant', 
          responses: [{
            question: 'Test question',
            answer: consonantMonth
          }]
        })
        .expect(201);

      expect(response1.body.message).toBeTruthy();
      expect(response2.body.message).toBeTruthy();
    });

  });

  describe('Validation Edge Cases', () => {

    test('should reject empty option value (original bug scenario)', async () => {
      const formData = {
        name: 'Test User',
        responses: [{
          question: 'En rapide, comment ça va ?',
          answer: '' // Chaîne vide qui causait l'erreur originale
        }]
      };

      const response = await request(app)
        .post('/api/response')
        .send(formData)
        .expect(400);

      expect(response.body.message).toContain('réponse ne peut pas être vide');
    });

    test('should handle very long dynamic option gracefully', async () => {
      // Simuler un cas où l'option générée serait très longue
      const longOption = 'a connu meilleur mois de ' + 'x'.repeat(500);
      
      const formData = {
        name: 'Test User',
        responses: [{
          question: 'Test question',
          answer: longOption
        }]
      };

      // Devrait passer car la limite backend est 10000 chars
      const response = await request(app)
        .post('/api/response')
        .send(formData)
        .expect(201);

      expect(response.body.message).toBeTruthy();
    });

    test('should handle special characters in month names', async () => {
      // Test avec août (caractère spécial û)
      const aoutOption = generateDynamicOption2(new Date('2024-09-01'));
      expect(aoutOption).toBe("a connu meilleur mois d'août");
      
      const formData = {
        name: 'Test Août',
        responses: [{
          question: 'Test question', 
          answer: aoutOption
        }]
      };

      const response = await request(app)
        .post('/api/response')
        .send(formData)
        .expect(201);

      const saved = await Response.findOne({ name: 'Test Août' });
      expect(saved.responses[0].answer).toBe("a connu meilleur mois d'août");
    });

  });

  describe('XSS and Security Tests', () => {

    test('should escape HTML in dynamic option if somehow injected', async () => {
      // Test de sécurité: même si l'option contenait du HTML malveillant
      const maliciousOption = "a connu meilleur mois de <script>alert('xss')</script>janvier";
      
      const formData = {
        name: 'Test XSS',
        responses: [{
          question: 'Test question',
          answer: maliciousOption
        }]
      };

      const response = await request(app)
        .post('/api/response')
        .send(formData)
        .expect(201);

      // Vérifier que le HTML a été échappé
      const saved = await Response.findOne({ name: 'Test XSS' });
      expect(saved.responses[0].answer).not.toContain('<script>');
      expect(saved.responses[0].answer).toContain('&lt;script&gt;');
    });

  });

  describe('Admin Compatibility Tests', () => {

    test('should handle dynamic option for admin responses', async () => {
      // Set admin name from env
      process.env.FORM_ADMIN_NAME = 'riri';
      
      const dynamicOption = generateDynamicOption2();
      
      const adminData = {
        name: 'riri', // Admin name
        responses: [{
          question: 'En rapide, comment ça va ?',
          answer: dynamicOption
        }]
      };

      const response = await request(app)
        .post('/api/response')
        .send(adminData)
        .expect(201);

      // Admin n'a pas de token/link
      expect(response.body.link).toBeNull();
      
      const saved = await Response.findOne({ name: 'riri' });
      expect(saved.isAdmin).toBe(true);
      expect(saved.token).toBeUndefined();
      expect(saved.responses[0].answer).toBe(dynamicOption);
    });

  });

});