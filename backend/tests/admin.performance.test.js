/**
 * Tests de performance pour l'endpoint /api/admin/summary
 * Vérifie les performances avec de larges datasets
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

describe('🚀 Admin Summary Performance Tests', () => {
  let testResponses = [];

  beforeAll(async () => {
    
    });

  afterAll(async () => {
    });

  beforeEach(async () => {
    await Response.deleteMany({});
    testResponses = [];
  });

  /**
   * Génère un dataset de test avec variations réalistes
   */
  function generateLargeDataset(size) {
    const baseQuestions = [
      "En rapide, comment ça va ?",
      "C'est quoi la réaction pic que tu utilises le plus en ce moment ?",
      "Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci ?",
      "Ta découverte culturelle du moment ?",
      "Le pulse check mensuel... montre une photo de toi ce mois-ci"
    ];

    const questionVariations = [
      "En rapide, comment ça va?", // Sans espace avant ?
      "C'est quoi la RÉACTION pic que tu utilises le plus en ce moment ?", // Majuscules + accent
      "Est-ce que tu veux partager un truc cool que t'as fait ce mois-ci...", // Points de suspension
      "Ta découverte culturelle du moment???", // Multiples ?
      "Le pulse check mensuel, montre une photo de toi ce mois-ci" // Virgule au lieu de ...
    ];

    const responses = [];
    const names = ['Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank', 'Grace', 'Hugo'];
    const answers = [
      'ça va', 'moyen', 'super bien', 'fatigué', 'motivé',
      '😀', '😅', '🤔', '😴', '🔥', '💪', '🌟',
      'Un voyage incroyable', 'Du sport', 'De la lecture', 'Des amis',
      'Un film génial', 'Une série', 'Un restaurant', 'Un concert'
    ];

    for (let i = 0; i < size; i++) {
      const name = names[i % names.length] + (i > names.length ? i : '');
      const responseData = [];

      // Mélange questions de base et variations
      const questionsToUse = i % 2 === 0 ? baseQuestions : questionVariations;
      
      questionsToUse.forEach((question, qIndex) => {
        responseData.push({
          question: question,
          answer: answers[(i + qIndex) % answers.length] + (i % 10 === 0 ? ` détaillé ${i}` : '')
        });
      });

      responses.push({
        name: name,
        responses: responseData,
        month: '2024-01',
        isAdmin: i === 0, // Premier élément = admin
        token: i === 0 ? null : `token-${i}`,
        createdAt: new Date(2024, 0, 1 + (i % 31), 10 + (i % 12), i % 60)
      });
    }

    return responses;
  }

  describe('Small dataset performance (baseline)', () => {
    test('should handle 50 responses quickly', async () => {
      const responses = generateLargeDataset(50);
      await Response.insertMany(responses);

      const startTime = Date.now();
      const res = await request(app)
        .get('/api/admin/summary?month=2024-01')
        .set('Cookie', ['faf-session=valid-session-id']);
      const endTime = Date.now();

      expect(res.status).toBe(200);
      expect(res.body).toBeInstanceOf(Array);
      expect(res.body.length).toBeGreaterThan(0);
      
      const duration = endTime - startTime;
      console.log(`  📊 50 responses: ${duration}ms`);
      expect(duration).toBeLessThan(1000); // < 1 seconde
    }, 10000);
  });

  describe('Medium dataset performance', () => {
    test('should handle 500 responses efficiently', async () => {
      const responses = generateLargeDataset(500);
      await Response.insertMany(responses);

      const startTime = Date.now();
      const res = await request(app)
        .get('/api/admin/summary?month=2024-01')
        .set('Cookie', ['faf-session=valid-session-id']);
      const endTime = Date.now();

      expect(res.status).toBe(200);
      expect(res.body).toBeInstanceOf(Array);
      expect(res.body.length).toBeGreaterThan(0);
      
      const duration = endTime - startTime;
      console.log(`  📊 500 responses: ${duration}ms`);
      expect(duration).toBeLessThan(5000); // < 5 secondes
    }, 15000);
  });

  describe('Large dataset performance', () => {
    test('should handle 1000 responses within reasonable time', async () => {
      const responses = generateLargeDataset(1000);
      await Response.insertMany(responses);

      const startTime = Date.now();
      const res = await request(app)
        .get('/api/admin/summary?month=2024-01')
        .set('Cookie', ['faf-session=valid-session-id']);
      const endTime = Date.now();

      expect(res.status).toBe(200);
      expect(res.body).toBeInstanceOf(Array);
      expect(res.body.length).toBeGreaterThan(0);
      
      const duration = endTime - startTime;
      console.log(`  📊 1000 responses: ${duration}ms`);
      expect(duration).toBeLessThan(10000); // < 10 secondes
    }, 30000);
  });

  describe('Stress test performance', () => {
    test('should handle 2000 responses without timing out', async () => {
      const responses = generateLargeDataset(2000);
      
      // Insert en batches pour éviter les timeouts
      const batchSize = 500;
      for (let i = 0; i < responses.length; i += batchSize) {
        const batch = responses.slice(i, i + batchSize);
        await Response.insertMany(batch);
      }

      const startTime = Date.now();
      const res = await request(app)
        .get('/api/admin/summary?month=2024-01')
        .set('Cookie', ['faf-session=valid-session-id']);
      const endTime = Date.now();

      expect(res.status).toBe(200);
      expect(res.body).toBeInstanceOf(Array);
      expect(res.body.length).toBeGreaterThan(0);
      
      const duration = endTime - startTime;
      console.log(`  📊 2000 responses: ${duration}ms`);
      expect(duration).toBeLessThan(30000); // < 30 secondes
    }, 60000);
  });

  describe('Memory usage tests', () => {
    test('should not cause memory leaks with repeated calls', async () => {
      const responses = generateLargeDataset(200);
      await Response.insertMany(responses);

      const initialMemory = process.memoryUsage().heapUsed;

      // Faire 10 appels consécutifs
      for (let i = 0; i < 10; i++) {
        await request(app)
          .get('/api/admin/summary?month=2024-01')
          .set('Cookie', ['faf-session=valid-session-id']);
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      const memoryIncreaseMB = memoryIncrease / 1024 / 1024;

      console.log(`  🧠 Memory increase: ${memoryIncreaseMB.toFixed(2)} MB`);
      
      // Ne devrait pas augmenter de plus de 50MB
      expect(memoryIncreaseMB).toBeLessThan(50);
    }, 30000);
  });

  describe('Concurrent requests performance', () => {
    test('should handle concurrent summary requests', async () => {
      const responses = generateLargeDataset(300);
      await Response.insertMany(responses);

      const startTime = Date.now();
      
      // Lancer 5 requêtes en parallèle
      const promises = Array(5).fill().map(() => 
        request(app)
          .get('/api/admin/summary?month=2024-01')
          .set('Cookie', ['faf-session=valid-session-id'])
      );

      const results = await Promise.all(promises);
      const endTime = Date.now();

      // Toutes les requêtes doivent réussir
      results.forEach(res => {
        expect(res.status).toBe(200);
        expect(res.body).toBeInstanceOf(Array);
      });

      const duration = endTime - startTime;
      console.log(`  🔄 5 concurrent requests: ${duration}ms`);
      expect(duration).toBeLessThan(15000); // < 15 secondes pour 5 requêtes
    }, 30000);
  });

  describe('Question normalization performance impact', () => {
    test('should measure normalization overhead', async () => {
      // Dataset avec beaucoup de variations pour tester la normalisation
      const responses = [];
      const questionVariations = [
        "Comment ça va ?",
        "COMMENT ÇA VA?",
        "Comment  ça   va...",
        "comment, ça va !",
        "Comment... ça va???",
        "  Comment  ça   va  ?  "
      ];

      for (let i = 0; i < 500; i++) {
        responses.push({
          name: `User${i}`,
          responses: questionVariations.map((q, qIndex) => ({
            question: q,
            answer: `Answer ${i}-${qIndex}`
          })),
          month: '2024-01',
          isAdmin: false,
          token: `token-${i}`,
          createdAt: new Date()
        });
      }

      await Response.insertMany(responses);

      const startTime = Date.now();
      const res = await request(app)
        .get('/api/admin/summary?month=2024-01')
        .set('Cookie', ['faf-session=valid-session-id']);
      const endTime = Date.now();

      expect(res.status).toBe(200);
      expect(res.body).toBeInstanceOf(Array);
      
      // Vérifier que les questions similaires sont bien regroupées
      const questionTitles = res.body.map(item => item.question);
      const uniqueNormalizedQuestions = new Set(questionTitles);
      expect(uniqueNormalizedQuestions.size).toBeLessThan(questionVariations.length);

      const duration = endTime - startTime;
      console.log(`  🔤 Normalization overhead: ${duration}ms`);
      expect(duration).toBeLessThan(8000); // < 8 secondes avec normalisation intensive
    }, 20000);
  });
});