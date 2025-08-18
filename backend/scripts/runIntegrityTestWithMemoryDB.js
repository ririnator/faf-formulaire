#!/usr/bin/env node

/**
 * EXECUTEUR DE TEST D'INTEGRITE AVEC MONGODB MEMORY SERVER
 * 
 * Ce script lance un serveur MongoDB en mémoire, génère des données de test,
 * puis exécute la vérification complète d'intégrité des données.
 */

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const TestDataGenerator = require('./generateTestData');
const PostMigrationDataIntegrityChecker = require('./postMigrationDataIntegrityCheck');

class IntegrityTestRunner {
  constructor() {
    this.mongod = null;
    this.mongoUri = null;
  }

  async startMongoMemoryServer() {
    console.log('🚀 Démarrage de MongoDB Memory Server...');
    
    try {
      this.mongod = await MongoMemoryServer.create({
        instance: {
          dbName: 'faf-test-integrity'
        }
      });
      
      this.mongoUri = this.mongod.getUri();
      console.log(`✅ MongoDB Memory Server démarré sur: ${this.mongoUri}`);
      return true;
    } catch (error) {
      console.error('❌ Erreur lors du démarrage de MongoDB Memory Server:', error.message);
      return false;
    }
  }

  async stopMongoMemoryServer() {
    if (this.mongod) {
      console.log('🛑 Arrêt de MongoDB Memory Server...');
      await this.mongod.stop();
      console.log('✅ MongoDB Memory Server arrêté');
    }
  }

  async generateTestData() {
    console.log('\n📊 Génération des données de test...');
    
    // Configurer l'URI pour le générateur de données
    process.env.MONGODB_URI = this.mongoUri;
    
    const generator = new TestDataGenerator();
    
    // Override de la méthode de connexion pour utiliser notre URI
    generator.connectToDatabase = async () => {
      try {
        await mongoose.connect(this.mongoUri);
        console.log('✅ Connexion à MongoDB Memory Server établie (générateur)');
        return true;
      } catch (error) {
        console.error('❌ Erreur de connexion:', error.message);
        return false;
      }
    };
    
    const success = await generator.run();
    return success;
  }

  async runIntegrityCheck() {
    console.log('\n🔍 Exécution de la vérification d\'intégrité...');
    
    // Configurer l'URI pour le vérificateur
    process.env.MONGODB_URI = this.mongoUri;
    
    const checker = new PostMigrationDataIntegrityChecker();
    
    // Override de la méthode de connexion pour utiliser notre URI
    checker.connectToDatabase = async () => {
      try {
        await mongoose.connect(this.mongoUri);
        console.log('✅ Connexion à MongoDB Memory Server établie (vérificateur)');
        return true;
      } catch (error) {
        console.error('❌ Erreur de connexion:', error.message);
        checker.report.summary.criticalIssues.push({
          type: 'DATABASE_CONNECTION',
          message: `Impossible de se connecter à la base de données: ${error.message}`,
          timestamp: new Date().toISOString()
        });
        return false;
      }
    };
    
    const report = await checker.run();
    return report;
  }

  async displayDetailedResults(report) {
    console.log('\n📋 ANALYSE DETAILLEE DES RESULTATS');
    console.log('==================================');
    
    // Statut global
    const statusEmoji = {
      'PASSED': '✅',
      'WARNING': '⚠️',
      'FAILED': '❌',
      'ERROR': '💥'
    };
    
    console.log(`${statusEmoji[report.summary.status]} Statut global: ${report.summary.status}`);
    console.log(`📊 Score de réussite: ${report.summary.passedChecks}/${report.summary.totalChecks} (${((report.summary.passedChecks / report.summary.totalChecks) * 100).toFixed(2)}%)`);
    
    // Données de base
    console.log('\n📈 DONNEES DE BASE:');
    console.log(`   Response: ${report.data.responses.total} (Legacy: ${report.data.responses.legacy}, Migrées: ${report.data.responses.migrated})`);
    console.log(`   Submission: ${report.data.submissions.total} (Complètes: ${report.data.submissions.complete})`);
    console.log(`   User: ${report.data.users.total} (Migrés: ${report.data.users.migrated}, Admin: ${report.data.users.admin})`);
    
    // Vérifications d'intégrité
    console.log('\n🔍 VERIFICATIONS D\'INTEGRITE:');
    
    Object.entries(report.integrity).forEach(([key, check]) => {
      const statusIcon = check.status === 'PASSED' ? '✅' : check.status === 'FAILED' ? '❌' : '⚠️';
      console.log(`   ${statusIcon} ${key}: ${check.status}`);
      
      if (check.status === 'FAILED' && check.details) {
        // Afficher les détails des échecs
        if (key === 'responsesToSubmissions') {
          if (check.details.orphanedResponses?.length > 0) {
            console.log(`      → Responses orphelines: ${check.details.orphanedResponses.length}`);
          }
          if (check.details.dataIntegrityIssues?.length > 0) {
            console.log(`      → Problèmes d'intégrité: ${check.details.dataIntegrityIssues.length}`);
          }
        }
        
        if (key === 'userAccountCreation') {
          if (check.details.missingUserAccounts?.length > 0) {
            console.log(`      → Comptes manquants: ${check.details.missingUserAccounts.length}`);
          }
          if (check.details.duplicateUsernames?.length > 0) {
            console.log(`      → Doublons username: ${check.details.duplicateUsernames.length}`);
          }
        }
        
        if (key === 'dataConsistency') {
          const totalCorrupted = (check.details.corruptedResponses?.length || 0) + 
                               (check.details.corruptedSubmissions?.length || 0) + 
                               (check.details.corruptedUsers?.length || 0);
          if (totalCorrupted > 0) {
            console.log(`      → Données corrompues: ${totalCorrupted}`);
          }
          if (check.details.orphanedData?.length > 0) {
            console.log(`      → Données orphelines: ${check.details.orphanedData.length}`);
          }
        }
        
        if (key === 'relationshipValidity') {
          if (check.details.brokenRelationships?.length > 0) {
            console.log(`      → Relations brisées: ${check.details.brokenRelationships.length}`);
          }
          if (check.details.statisticsErrors?.length > 0) {
            console.log(`      → Erreurs statistiques: ${check.details.statisticsErrors.length}`);
          }
        }
        
        if (key === 'backwardCompatibility') {
          if (check.details.brokenTokens?.length > 0) {
            console.log(`      → Tokens cassés: ${check.details.brokenTokens.length}`);
          }
          if (check.details.hybridSystemIssues?.length > 0) {
            console.log(`      → Conflits système hybride: ${check.details.hybridSystemIssues.length}`);
          }
        }
      }
    });
    
    // Problèmes critiques
    if (report.summary.criticalIssues.length > 0) {
      console.log('\n🚨 PROBLEMES CRITIQUES:');
      report.summary.criticalIssues.forEach((issue, index) => {
        console.log(`   ${index + 1}. [${issue.type}] ${issue.message}`);
        if (issue.details) {
          Object.entries(issue.details).forEach(([key, value]) => {
            console.log(`      - ${key}: ${value}`);
          });
        }
      });
    }
    
    // Recommandations prioritaires
    if (report.recommendations && report.recommendations.length > 0) {
      const highPriorityRecs = report.recommendations.filter(r => 
        r.priority === 'CRITICAL' || r.priority === 'HIGH'
      );
      
      if (highPriorityRecs.length > 0) {
        console.log('\n💡 RECOMMANDATIONS PRIORITAIRES:');
        highPriorityRecs.forEach((rec, index) => {
          const priorityEmoji = rec.priority === 'CRITICAL' ? '🔥' : '⚠️';
          console.log(`   ${index + 1}. ${priorityEmoji} [${rec.priority}] ${rec.title}`);
          console.log(`      Description: ${rec.description}`);
          console.log(`      Action: ${rec.action}`);
          console.log(`      Automatisable: ${rec.automatable ? 'Oui' : 'Non'}`);
        });
      }
    }
    
    // Performance
    console.log('\n⚡ PERFORMANCE:');
    console.log(`   Temps d'exécution: ${(report.performance.executionTime / 1000).toFixed(2)}s`);
    console.log(`   Requêtes DB: ${report.performance.queryStats.totalQueries}`);
    console.log(`   Temps moyen/requête: ${report.performance.queryStats.averageQueryTime.toFixed(2)}ms`);
    console.log(`   Mémoire utilisée: ${Math.round(report.performance.memoryUsage.heapUsed / 1024 / 1024)}MB`);
  }

  async run() {
    console.log('🧪 TEST D\'INTEGRITE COMPLET AVEC MONGODB MEMORY SERVER');
    console.log('====================================================');
    console.log(`📅 Démarré le: ${new Date().toLocaleString()}`);
    
    let success = false;
    let report = null;
    
    try {
      // Démarrage du serveur MongoDB en mémoire
      const mongoStarted = await this.startMongoMemoryServer();
      if (!mongoStarted) {
        return false;
      }
      
      // Génération des données de test
      const dataGenerated = await this.generateTestData();
      if (!dataGenerated) {
        console.error('❌ Échec de la génération des données de test');
        return false;
      }
      
      // Exécution de la vérification d'intégrité
      report = await this.runIntegrityCheck();
      if (!report) {
        console.error('❌ Échec de la vérification d\'intégrité');
        return false;
      }
      
      // Affichage des résultats détaillés
      await this.displayDetailedResults(report);
      
      success = report.summary.status === 'PASSED' || report.summary.status === 'WARNING';
      
    } catch (error) {
      console.error('💥 Erreur fatale pendant l\'exécution:', error);
      success = false;
    } finally {
      // Nettoyage
      await this.stopMongoMemoryServer();
    }
    
    console.log('\n🏁 Test d\'intégrité terminé');
    
    if (success) {
      console.log('🎉 Test réussi - Intégrité des données validée!');
    } else {
      console.log('❌ Test échoué - Problèmes d\'intégrité détectés');
    }
    
    return { success, report };
  }
}

// Exécution si appelé directement
if (require.main === module) {
  const runner = new IntegrityTestRunner();
  runner.run().then(({ success, report }) => {
    if (success) {
      console.log('\n✅ CONCLUSION: Migration FAF validée avec succès!');
      process.exit(0);
    } else {
      console.log('\n❌ CONCLUSION: Migration FAF nécessite des corrections');
      process.exit(1);
    }
  }).catch((error) => {
    console.error('💥 Erreur critique:', error);
    process.exit(2);
  });
}

module.exports = IntegrityTestRunner;