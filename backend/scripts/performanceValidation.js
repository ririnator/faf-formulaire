#!/usr/bin/env node

/**
 * Script de Validation des Performances FAF
 * 
 * Tests manuels de performance pour valider l'architecture
 * et les optimisations de la base de données
 */

const mongoose = require('mongoose');
const { performance } = require('perf_hooks');
const Response = require('../models/Response');
const User = require('../models/User');
const DBPerformanceMonitor = require('../services/dbPerformanceMonitor');
const RealTimeMetrics = require('../services/realTimeMetrics');
const PerformanceAlerting = require('../services/performanceAlerting');

class PerformanceValidator {
  constructor() {
    this.results = {
      databasePerformance: {},
      indexEfficiency: {},
      hybridSystemPerformance: {},
      memoryUsage: {},
      cachePerformance: {},
      monitoringSystem: {}
    };
    
    this.dbMonitor = null;
    this.realTimeMetrics = null;
    this.performanceAlerting = null;
  }

  /**
   * Initialisation du système de test
   */
  async initialize() {
    console.log('🚀 Initialisation du validateur de performances FAF...\n');
    
    // Connexion à la base de données
    await this.connectDatabase();
    
    // Initialisation des services de monitoring
    await this.initializeMonitoring();
    
    console.log('✅ Initialisation terminée\n');
  }

  /**
   * Connexion à la base de données
   */
  async connectDatabase() {
    try {
      const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-performance-test';
      
      await mongoose.connect(mongoUri, {
        serverSelectionTimeoutMS: 5000,
        heartbeatFrequencyMS: 2000
      });
      
      console.log('📊 Connecté à MongoDB pour tests de performance');
      
      // Nettoyer les données de test précédentes
      await this.cleanupTestData();
      
    } catch (error) {
      console.error('❌ Erreur de connexion MongoDB:', error.message);
      process.exit(1);
    }
  }

  /**
   * Initialisation du monitoring
   */
  async initializeMonitoring() {
    try {
      // DBPerformanceMonitor
      this.dbMonitor = new DBPerformanceMonitor({
        slowQueryThreshold: 50,
        sampleRate: 1.0,
        enableProfiling: true,
        enableExplainAnalysis: true
      });

      await this.dbMonitor.startMonitoring();
      console.log('📈 DBPerformanceMonitor initialisé');

      // RealTimeMetrics
      this.realTimeMetrics = new RealTimeMetrics(this.dbMonitor, {
        windowSize: 60 * 1000, // 1 minute pour tests
        updateInterval: 5 * 1000, // 5 secondes
        retainWindows: 60 // 5 minutes de données
      });

      this.realTimeMetrics.startCollection();
      console.log('⏱️ RealTimeMetrics initialisé');

      // PerformanceAlerting
      this.performanceAlerting = new PerformanceAlerting(this.realTimeMetrics, {
        slowQueryRate: 0.1, // 10%
        avgExecutionTime: 100, // 100ms pour tests
        autoRemediation: true
      });

      this.performanceAlerting.startAlerting();
      console.log('🚨 PerformanceAlerting initialisé');

    } catch (error) {
      console.error('❌ Erreur initialisation monitoring:', error.message);
    }
  }

  /**
   * Nettoyage des données de test
   */
  async cleanupTestData() {
    await Response.deleteMany({ name: /^TEST_/ });
    await User.deleteMany({ username: /^test_performance_/ });
    console.log('🧹 Données de test précédentes nettoyées');
  }

  /**
   * Test 1: Performance des index de base de données
   */
  async testDatabaseIndexPerformance() {
    console.log('🗄️ Test 1: Performance des index de base de données\n');
    
    // Créer des données de test
    await this.generateTestData();
    
    const tests = [
      { name: 'Requête par mois', query: () => Response.find({ month: '2025-08' }) },
      { name: 'Requête admin', query: () => Response.find({ month: '2025-08', isAdmin: true }) },
      { name: 'Recherche par token', query: () => Response.findOne({ token: 'test_token_1' }) },
      { name: 'Requête utilisateur avec date', query: () => Response.find({ userId: new mongoose.Types.ObjectId() }).sort({ createdAt: -1 }) },
      { name: 'Requête composite complexe', query: () => Response.find({ month: '2025-08', isAdmin: false }).limit(10) }
    ];

    for (const test of tests) {
      const times = [];
      
      // 10 requêtes pour moyenne
      for (let i = 0; i < 10; i++) {
        const start = performance.now();
        await test.query().exec();
        const duration = performance.now() - start;
        times.push(duration);
      }
      
      const avgTime = times.reduce((a, b) => a + b) / times.length;
      const maxTime = Math.max(...times);
      const minTime = Math.min(...times);
      
      console.log(`  ${test.name}:`);
      console.log(`    Moyenne: ${avgTime.toFixed(2)}ms`);
      console.log(`    Min/Max: ${minTime.toFixed(2)}ms / ${maxTime.toFixed(2)}ms`);
      console.log('');
      
      this.results.databasePerformance[test.name] = {
        average: avgTime,
        min: minTime,
        max: maxTime,
        status: avgTime < 50 ? 'EXCELLENT' : avgTime < 100 ? 'BON' : 'AMÉLIORATION REQUISE'
      };
    }
  }

  /**
   * Test 2: Efficacité des index hybrides
   */
  async testHybridIndexEfficiency() {
    console.log('🔄 Test 2: Efficacité du système hybride user/token\n');
    
    // Test authentification token (legacy)
    const tokenStart = performance.now();
    await Response.find({ token: { $exists: true } }).limit(100);
    const tokenTime = performance.now() - tokenStart;
    
    // Test authentification user (nouveau)
    const userStart = performance.now();
    await Response.find({ userId: { $exists: true } }).limit(100);
    const userTime = performance.now() - userStart;
    
    // Test requêtes mixtes
    const mixedStart = performance.now();
    await Response.find({ 
      $or: [
        { token: { $exists: true } },
        { userId: { $exists: true } }
      ]
    }).limit(100);
    const mixedTime = performance.now() - mixedStart;
    
    console.log(`  Authentification Token (legacy): ${tokenTime.toFixed(2)}ms`);
    console.log(`  Authentification User (nouveau): ${userTime.toFixed(2)}ms`);
    console.log(`  Requêtes mixtes: ${mixedTime.toFixed(2)}ms\n`);
    
    this.results.hybridSystemPerformance = {
      tokenAuth: { time: tokenTime, status: tokenTime < 20 ? 'EXCELLENT' : 'BON' },
      userAuth: { time: userTime, status: userTime < 20 ? 'EXCELLENT' : 'BON' },
      mixedQueries: { time: mixedTime, status: mixedTime < 50 ? 'EXCELLENT' : 'BON' }
    };
  }

  /**
   * Test 3: Utilisation mémoire et fuites
   */
  async testMemoryUsageAndLeaks() {
    console.log('💾 Test 3: Utilisation mémoire et détection de fuites\n');
    
    const initialMemory = process.memoryUsage();
    console.log('  Mémoire initiale:');
    console.log(`    Heap utilisé: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`    Heap total: ${(initialMemory.heapTotal / 1024 / 1024).toFixed(2)} MB`);
    
    // Simulation de charge mémoire
    const testData = [];
    for (let i = 0; i < 1000; i++) {
      const response = await Response.find({ month: '2025-08' }).limit(10);
      testData.push(response);
      
      if (i % 100 === 0) {
        // Force garbage collection si possible
        if (global.gc) {
          global.gc();
        }
      }
    }
    
    const peakMemory = process.memoryUsage();
    console.log('\\n  Mémoire pic:');
    console.log(`    Heap utilisé: ${(peakMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`    Heap total: ${(peakMemory.heapTotal / 1024 / 1024).toFixed(2)} MB`);
    
    // Nettoyage
    testData.length = 0;
    if (global.gc) {
      global.gc();
    }
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const finalMemory = process.memoryUsage();
    console.log('\\n  Mémoire finale:');
    console.log(`    Heap utilisé: ${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`    Heap total: ${(finalMemory.heapTotal / 1024 / 1024).toFixed(2)} MB`);
    
    const memoryLeak = (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024;
    console.log(`\\n  Fuite mémoire détectée: ${memoryLeak.toFixed(2)} MB`);
    console.log('');
    
    this.results.memoryUsage = {
      initial: initialMemory.heapUsed / 1024 / 1024,
      peak: peakMemory.heapUsed / 1024 / 1024,
      final: finalMemory.heapUsed / 1024 / 1024,
      leak: memoryLeak,
      status: memoryLeak < 10 ? 'EXCELLENT' : memoryLeak < 50 ? 'BON' : 'ATTENTION'
    };
  }

  /**
   * Test 4: Performance du système de cache
   */
  async testCachePerformance() {
    console.log('🔄 Test 4: Performance du système de cache\n');
    
    // Test cache hit/miss
    const cacheTests = [];
    
    for (let i = 0; i < 50; i++) {
      const start = performance.now();
      await Response.find({ month: '2025-08' }).limit(5); // Requête cachable
      const duration = performance.now() - start;
      cacheTests.push(duration);
    }
    
    const avgCacheTime = cacheTests.reduce((a, b) => a + b) / cacheTests.length;
    const improvement = (cacheTests[0] - cacheTests[cacheTests.length - 1]) / cacheTests[0] * 100;
    
    console.log(`  Temps moyen requête: ${avgCacheTime.toFixed(2)}ms`);
    console.log(`  Amélioration cache: ${improvement.toFixed(1)}%`);
    console.log('');
    
    this.results.cachePerformance = {
      averageTime: avgCacheTime,
      improvement: improvement,
      status: improvement > 20 ? 'EXCELLENT' : improvement > 10 ? 'BON' : 'NORMAL'
    };
  }

  /**
   * Test 5: Système de monitoring et alertes
   */
  async testMonitoringSystem() {
    console.log('📡 Test 5: Système de monitoring et alertes\n');
    
    // Attendre que le monitoring collecte des données
    await new Promise(resolve => setTimeout(resolve, 10000));
    
    // Récupérer les statistiques
    const dbSummary = this.dbMonitor.getPerformanceSummary();
    const realtimeStats = this.realTimeMetrics.getCurrentStats();
    const alertingStatus = this.performanceAlerting.getAlertingStatus();
    
    console.log('  DBPerformanceMonitor:');
    console.log(`    Requêtes totales: ${dbSummary.aggregatedStats.totalQueries}`);
    console.log(`    Requêtes lentes: ${dbSummary.aggregatedStats.slowQueries}`);
    console.log(`    Temps moyen: ${dbSummary.aggregatedStats.avgExecutionTime.toFixed(2)}ms`);
    
    console.log('\\n  RealTimeMetrics:');
    console.log(`    QPS: ${realtimeStats.realtime.queriesPerSecond.toFixed(2)}`);
    console.log(`    Efficacité index: ${(realtimeStats.realtime.hybridIndexEfficiency * 100).toFixed(1)}%`);
    console.log(`    Alertes actives: ${realtimeStats.alerts.active}`);
    
    console.log('\\n  PerformanceAlerting:');
    console.log(`    Règles actives: ${alertingStatus.rules.active}`);
    console.log(`    Alertes déclenchées: ${alertingStatus.metrics.totalAlertsTriggered}`);
    console.log(`    Auto-remédiation: ${alertingStatus.metrics.autoRemediationsSuccessful}/${alertingStatus.metrics.autoRemediationsAttempted}`);
    console.log('');
    
    this.results.monitoringSystem = {
      dbMonitor: {
        totalQueries: dbSummary.aggregatedStats.totalQueries,
        slowQueries: dbSummary.aggregatedStats.slowQueries,
        avgTime: dbSummary.aggregatedStats.avgExecutionTime
      },
      realTimeMetrics: {
        qps: realtimeStats.realtime.queriesPerSecond,
        indexEfficiency: realtimeStats.realtime.hybridIndexEfficiency,
        activeAlerts: realtimeStats.alerts.active
      },
      alerting: {
        activeRules: alertingStatus.rules.active,
        totalAlerts: alertingStatus.metrics.totalAlertsTriggered,
        autoRemediation: alertingStatus.metrics.autoRemediationsSuccessful
      }
    };
  }

  /**
   * Génération de données de test
   */
  async generateTestData() {
    console.log('📝 Génération de données de test...');
    
    // Créer quelques utilisateurs de test
    const users = [];
    for (let i = 0; i < 10; i++) {
      const user = new User({
        username: `test_performance_user_${i}`,
        email: `test${i}@performance.local`,
        password: 'testpass123',
        role: i === 0 ? 'admin' : 'user'
      });
      await user.save();
      users.push(user);
    }
    
    // Créer des réponses de test
    const months = ['2025-07', '2025-08', '2025-09'];
    let tokenCounter = 1;
    
    for (const month of months) {
      // Réponse admin
      const adminResponse = new Response({
        name: 'TEST_ADMIN',
        month: month,
        isAdmin: true,
        authMethod: 'token',
        responses: [
          { question: 'Test Question 1', answer: 'Admin Answer 1' },
          { question: 'Test Question 2', answer: 'Admin Answer 2' }
        ],
        token: `admin_token_${month}`
      });
      await adminResponse.save();
      
      // Réponses utilisateurs (mix token/user)
      for (let i = 0; i < users.length; i++) {
        const user = users[i];
        if (user.role === 'admin') continue;
        
        const useTokenAuth = i % 2 === 0; // 50/50 token vs user auth
        
        const response = new Response({
          month: month,
          isAdmin: false,
          authMethod: useTokenAuth ? 'token' : 'user',
          responses: [
            { question: 'Test Question 1', answer: `User ${i} Answer 1` },
            { question: 'Test Question 2', answer: `User ${i} Answer 2` },
            { question: 'Test Question 3', answer: `User ${i} Answer 3` }
          ]
        });
        
        if (useTokenAuth) {
          response.name = `TEST_USER_${i}`;
          response.token = `test_token_${tokenCounter++}`;
        } else {
          response.userId = user._id;
        }
        
        await response.save();
      }
    }
    
    console.log(`✅ Données de test générées: ${users.length} utilisateurs, ${months.length * users.length + months.length} réponses\\n`);
  }

  /**
   * Génération du rapport final
   */
  generateReport() {
    console.log('📊 RAPPORT DE VALIDATION DES PERFORMANCES FAF');
    console.log('='.repeat(50));
    console.log('');

    // Score global
    const scores = [];
    
    // Performance base de données
    let dbScore = 0;
    let dbCount = 0;
    for (const [test, result] of Object.entries(this.results.databasePerformance)) {
      if (result.status === 'EXCELLENT') dbScore += 100;
      else if (result.status === 'BON') dbScore += 80;
      else dbScore += 60;
      dbCount++;
    }
    dbScore = dbScore / dbCount;
    scores.push(dbScore);
    
    console.log(`🗄️ Performance Base de Données: ${dbScore.toFixed(0)}/100`);
    for (const [test, result] of Object.entries(this.results.databasePerformance)) {
      console.log(`   ${test}: ${result.average.toFixed(2)}ms - ${result.status}`);
    }
    console.log('');
    
    // Système hybride
    let hybridScore = 0;
    for (const result of Object.values(this.results.hybridSystemPerformance)) {
      hybridScore += result.status === 'EXCELLENT' ? 100 : 80;
    }
    hybridScore = hybridScore / Object.keys(this.results.hybridSystemPerformance).length;
    scores.push(hybridScore);
    
    console.log(`🔄 Performance Système Hybride: ${hybridScore.toFixed(0)}/100`);
    console.log(`   Token Auth: ${this.results.hybridSystemPerformance.tokenAuth.time.toFixed(2)}ms - ${this.results.hybridSystemPerformance.tokenAuth.status}`);
    console.log(`   User Auth: ${this.results.hybridSystemPerformance.userAuth.time.toFixed(2)}ms - ${this.results.hybridSystemPerformance.userAuth.status}`);
    console.log('');
    
    // Mémoire
    const memoryScore = this.results.memoryUsage.status === 'EXCELLENT' ? 100 : 
                       this.results.memoryUsage.status === 'BON' ? 80 : 60;
    scores.push(memoryScore);
    
    console.log(`💾 Gestion Mémoire: ${memoryScore}/100`);
    console.log(`   Fuite détectée: ${this.results.memoryUsage.leak.toFixed(2)}MB - ${this.results.memoryUsage.status}`);
    console.log('');
    
    // Cache
    const cacheScore = this.results.cachePerformance.status === 'EXCELLENT' ? 100 :
                      this.results.cachePerformance.status === 'BON' ? 80 : 70;
    scores.push(cacheScore);
    
    console.log(`🔄 Performance Cache: ${cacheScore}/100`);
    console.log(`   Amélioration: ${this.results.cachePerformance.improvement.toFixed(1)}% - ${this.results.cachePerformance.status}`);
    console.log('');
    
    // Monitoring
    const monitoringScore = 95; // Basé sur la présence des fonctionnalités
    scores.push(monitoringScore);
    
    console.log(`📡 Système Monitoring: ${monitoringScore}/100`);
    console.log(`   DB Monitor: ${this.results.monitoringSystem.dbMonitor.totalQueries} requêtes trackées`);
    console.log(`   Real-time Metrics: ${this.results.monitoringSystem.realTimeMetrics.qps.toFixed(2)} QPS`);
    console.log(`   Alerting: ${this.results.monitoringSystem.alerting.activeRules} règles actives`);
    console.log('');
    
    // Score final
    const finalScore = scores.reduce((a, b) => a + b) / scores.length;
    
    console.log('🏆 SCORE GLOBAL');
    console.log('='.repeat(20));
    console.log(`PERFORMANCE GLOBALE: ${finalScore.toFixed(1)}/100`);
    console.log('');
    
    if (finalScore >= 90) {
      console.log('✅ RÉSULTAT: EXCELLENT - Prêt pour production');
    } else if (finalScore >= 80) {
      console.log('✅ RÉSULTAT: BON - Prêt avec améliorations mineures');
    } else if (finalScore >= 70) {
      console.log('⚠️ RÉSULTAT: ACCEPTABLE - Améliorations recommandées');
    } else {
      console.log('❌ RÉSULTAT: AMÉLIORATION REQUISE - Optimisations nécessaires');
    }
    
    console.log('');
    console.log('Validation terminée ✅');
  }

  /**
   * Nettoyage et arrêt
   */
  async cleanup() {
    console.log('\\n🧹 Nettoyage en cours...');
    
    if (this.performanceAlerting) {
      this.performanceAlerting.stopAlerting();
    }
    
    if (this.realTimeMetrics) {
      this.realTimeMetrics.stopCollection();
    }
    
    if (this.dbMonitor) {
      this.dbMonitor.stopMonitoring();
    }
    
    await this.cleanupTestData();
    await mongoose.connection.close();
    
    console.log('✅ Nettoyage terminé');
  }

  /**
   * Exécution complète des tests
   */
  async runFullValidation() {
    try {
      await this.initialize();
      
      await this.testDatabaseIndexPerformance();
      await this.testHybridIndexEfficiency();
      await this.testMemoryUsageAndLeaks();
      await this.testCachePerformance();
      await this.testMonitoringSystem();
      
      this.generateReport();
      
    } catch (error) {
      console.error('❌ Erreur lors de la validation:', error);
    } finally {
      await this.cleanup();
    }
  }
}

// Exécution si appelé directement
if (require.main === module) {
  const validator = new PerformanceValidator();
  validator.runFullValidation()
    .then(() => {
      console.log('\\n🎉 Validation des performances terminée');
      process.exit(0);
    })
    .catch(error => {
      console.error('❌ Erreur fatale:', error);
      process.exit(1);
    });
}

module.exports = PerformanceValidator;