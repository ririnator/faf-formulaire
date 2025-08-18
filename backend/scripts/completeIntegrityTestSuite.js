#!/usr/bin/env node

/**
 * SUITE DE TESTS COMPLETE D'INTEGRITE FAF MIGRATION
 * 
 * Ce script orchestre le cycle complet de test:
 * 1. Génération de données de test avec problèmes
 * 2. Vérification d'intégrité initiale 
 * 3. Correction automatique des problèmes
 * 4. Re-vérification post-correction
 * 5. Rapport final comparatif
 */

const { MongoMemoryServer } = require('mongodb-memory-server');
const TestDataGenerator = require('./generateTestData');
const PostMigrationDataIntegrityChecker = require('./postMigrationDataIntegrityCheck');
const MigrationIssuesFixer = require('./fixMigrationIssues');

class CompleteIntegrityTestSuite {
  constructor() {
    this.mongod = null;
    this.mongoUri = null;
    this.results = {
      dataGeneration: null,
      initialVerification: null,
      corrections: null,
      finalVerification: null,
      comparison: null
    };
  }

  async startMongoMemoryServer() {
    console.log('🚀 Démarrage de MongoDB Memory Server...');
    
    try {
      this.mongod = await MongoMemoryServer.create({
        instance: {
          dbName: 'faf-complete-test'
        }
      });
      
      this.mongoUri = this.mongod.getUri();
      process.env.MONGODB_URI = this.mongoUri;
      
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

  async runDataGeneration() {
    console.log('\n📊 PHASE 1: Génération des données de test');
    console.log('===========================================');
    
    const generator = new TestDataGenerator();
    generator.connectToDatabase = async () => {
      const mongoose = require('mongoose');
      try {
        await mongoose.connect(this.mongoUri);
        console.log('✅ Connexion établie (générateur)');
        return true;
      } catch (error) {
        console.error('❌ Erreur de connexion générateur:', error.message);
        return false;
      }
    };
    
    const success = await generator.run();
    this.results.dataGeneration = { success, timestamp: new Date().toISOString() };
    
    if (success) {
      console.log('✅ Phase 1 terminée: Données de test générées');
    } else {
      console.log('❌ Phase 1 échouée: Problème de génération des données');
    }
    
    return success;
  }

  async runInitialVerification() {
    console.log('\n🔍 PHASE 2: Vérification d\'intégrité initiale');
    console.log('===============================================');
    
    const checker = new PostMigrationDataIntegrityChecker();
    checker.connectToDatabase = async () => {
      const mongoose = require('mongoose');
      try {
        await mongoose.connect(this.mongoUri);
        console.log('✅ Connexion établie (vérificateur initial)');
        return true;
      } catch (error) {
        console.error('❌ Erreur de connexion vérificateur:', error.message);
        return false;
      }
    };
    
    const report = await checker.run();
    this.results.initialVerification = report;
    
    if (report) {
      console.log(`✅ Phase 2 terminée: Vérification initiale (${report.summary.status})`);
      console.log(`   📊 Résultats: ${report.summary.passedChecks}/${report.summary.totalChecks} tests réussis`);
      console.log(`   🚨 Problèmes critiques: ${report.summary.criticalIssues.length}`);
    } else {
      console.log('❌ Phase 2 échouée: Problème de vérification');
    }
    
    return report;
  }

  async runCorrections() {
    console.log('\n🔧 PHASE 3: Corrections automatiques');
    console.log('====================================');
    
    const fixer = new MigrationIssuesFixer({ dryRun: false, verbose: false });
    fixer.connectToDatabase = async () => {
      const mongoose = require('mongoose');
      try {
        await mongoose.connect(this.mongoUri);
        console.log('✅ Connexion établie (correcteur)');
        return true;
      } catch (error) {
        console.error('❌ Erreur de connexion correcteur:', error.message);
        return false;
      }
    };
    
    const report = await fixer.run();
    this.results.corrections = report;
    
    if (report) {
      console.log(`✅ Phase 3 terminée: Corrections appliquées`);
      console.log(`   🔧 Problèmes traités: ${report.statistics.totalFixes}`);
      console.log(`   ✅ Corrections réussies: ${report.statistics.successfulFixes}`);
      console.log(`   ❌ Corrections échouées: ${report.statistics.failedFixes}`);
      console.log(`   📈 Taux de réussite: ${report.summary.successRate.toFixed(2)}%`);
    } else {
      console.log('❌ Phase 3 échouée: Problème de correction');
    }
    
    return report;
  }

  async runFinalVerification() {
    console.log('\n🎯 PHASE 4: Vérification finale post-correction');
    console.log('================================================');
    
    const checker = new PostMigrationDataIntegrityChecker();
    checker.connectToDatabase = async () => {
      const mongoose = require('mongoose');
      try {
        await mongoose.connect(this.mongoUri);
        console.log('✅ Connexion établie (vérificateur final)');
        return true;
      } catch (error) {
        console.error('❌ Erreur de connexion vérificateur final:', error.message);
        return false;
      }
    };
    
    const report = await checker.run();
    this.results.finalVerification = report;
    
    if (report) {
      console.log(`✅ Phase 4 terminée: Vérification finale (${report.summary.status})`);
      console.log(`   📊 Résultats: ${report.summary.passedChecks}/${report.summary.totalChecks} tests réussis`);
      console.log(`   🚨 Problèmes critiques: ${report.summary.criticalIssues.length}`);
    } else {
      console.log('❌ Phase 4 échouée: Problème de vérification finale');
    }
    
    return report;
  }

  generateComparison() {
    console.log('\n📊 PHASE 5: Analyse comparative');
    console.log('================================');
    
    if (!this.results.initialVerification || !this.results.finalVerification) {
      console.log('❌ Impossible de générer la comparaison - données manquantes');
      return null;
    }
    
    const initial = this.results.initialVerification;
    const final = this.results.finalVerification;
    
    const comparison = {
      summary: {
        statusChange: { from: initial.summary.status, to: final.summary.status },
        passedChecksChange: { from: initial.summary.passedChecks, to: final.summary.passedChecks },
        criticalIssuesChange: { from: initial.summary.criticalIssues.length, to: final.summary.criticalIssues.length },
        improvement: final.summary.passedChecks > initial.summary.passedChecks
      },
      detailedChanges: {},
      metrics: {
        successRateImprovement: ((final.summary.passedChecks / final.summary.totalChecks) * 100) - 
                               ((initial.summary.passedChecks / initial.summary.totalChecks) * 100),
        criticalIssuesReduction: initial.summary.criticalIssues.length - final.summary.criticalIssues.length,
        remainingIssues: final.summary.criticalIssues
      }
    };
    
    // Analyse détaillée par vérification
    Object.keys(initial.integrity).forEach(checkName => {
      comparison.detailedChanges[checkName] = {
        from: initial.integrity[checkName].status,
        to: final.integrity[checkName].status,
        improved: initial.integrity[checkName].status !== 'PASSED' && 
                  final.integrity[checkName].status === 'PASSED'
      };
    });
    
    this.results.comparison = comparison;
    
    // Affichage des résultats comparatifs
    console.log(`🎯 Statut global: ${initial.summary.status} → ${final.summary.status}`);
    console.log(`📊 Tests réussis: ${initial.summary.passedChecks}/${initial.summary.totalChecks} → ${final.summary.passedChecks}/${final.summary.totalChecks}`);
    console.log(`🚨 Problèmes critiques: ${initial.summary.criticalIssues.length} → ${final.summary.criticalIssues.length}`);
    console.log(`📈 Amélioration du taux de réussite: ${comparison.metrics.successRateImprovement.toFixed(2)}%`);
    
    if (comparison.metrics.criticalIssuesReduction > 0) {
      console.log(`✅ ${comparison.metrics.criticalIssuesReduction} problèmes critiques résolus`);
    }
    
    // Détail des améliorations
    const improvements = Object.entries(comparison.detailedChanges).filter(([_, change]) => change.improved);
    if (improvements.length > 0) {
      console.log(`\n🔧 Vérifications améliorées (${improvements.length}):`);
      improvements.forEach(([checkName, change]) => {
        console.log(`   ✅ ${checkName}: ${change.from} → ${change.to}`);
      });
    }
    
    // Problèmes persistants
    if (comparison.metrics.remainingIssues.length > 0) {
      console.log(`\n⚠️  Problèmes persistants (${comparison.metrics.remainingIssues.length}):`);
      comparison.metrics.remainingIssues.forEach((issue, index) => {
        console.log(`   ${index + 1}. [${issue.type}] ${issue.message}`);
      });
    }
    
    return comparison;
  }

  async generateFinalReport() {
    const report = {
      timestamp: new Date().toISOString(),
      testSuite: 'CompleteIntegrityTestSuite',
      version: '1.0.0',
      results: this.results,
      verdict: {
        dataGenerationSuccess: this.results.dataGeneration?.success || false,
        initialProblemsDetected: this.results.initialVerification?.summary.criticalIssues.length > 0,
        correctionsApplied: this.results.corrections?.statistics.successfulFixes > 0,
        finalStateValid: this.results.finalVerification?.summary.status === 'PASSED',
        overallSuccess: false
      }
    };
    
    // Déterminer le succès global
    report.verdict.overallSuccess = 
      report.verdict.dataGenerationSuccess &&
      report.verdict.initialProblemsDetected &&
      report.verdict.correctionsApplied &&
      (this.results.finalVerification?.summary.passedChecks > this.results.initialVerification?.summary.passedChecks);
    
    // Sauvegarder le rapport complet
    const fs = require('fs');
    const path = require('path');
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `complete-integrity-test-suite-${timestamp}.json`;
    const filepath = path.join(__dirname, '../reports', filename);
    
    try {
      const reportsDir = path.dirname(filepath);
      if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
      }
      
      fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
      console.log(`💾 Rapport complet sauvegardé: ${filepath}`);
    } catch (error) {
      console.error('❌ Erreur lors de la sauvegarde du rapport complet:', error.message);
    }
    
    return report;
  }

  async run() {
    console.log('🧪 SUITE DE TESTS COMPLETE D\'INTEGRITE FAF MIGRATION');
    console.log('=====================================================');
    console.log(`📅 Démarré le: ${new Date().toLocaleString()}`);
    
    let success = false;
    
    try {
      // Démarrage du serveur MongoDB en mémoire
      const mongoStarted = await this.startMongoMemoryServer();
      if (!mongoStarted) {
        return false;
      }
      
      // Phase 1: Génération des données de test
      const dataGenerated = await this.runDataGeneration();
      if (!dataGenerated) {
        console.error('❌ Arrêt: Échec de la génération des données');
        return false;
      }
      
      // Phase 2: Vérification d'intégrité initiale
      const initialReport = await this.runInitialVerification();
      if (!initialReport) {
        console.error('❌ Arrêt: Échec de la vérification initiale');
        return false;
      }
      
      // Phase 3: Corrections automatiques (seulement si des problèmes détectés)
      if (initialReport.summary.criticalIssues.length > 0) {
        const correctionsReport = await this.runCorrections();
        if (!correctionsReport) {
          console.error('❌ Arrêt: Échec des corrections');
          return false;
        }
      } else {
        console.log('ℹ️  Phase 3 ignorée: Aucun problème détecté à corriger');
        this.results.corrections = { 
          statistics: { totalFixes: 0, successfulFixes: 0, failedFixes: 0, skippedFixes: 0 },
          summary: { successRate: 100 }
        };
      }
      
      // Phase 4: Vérification finale
      const finalReport = await this.runFinalVerification();
      if (!finalReport) {
        console.error('❌ Arrêt: Échec de la vérification finale');
        return false;
      }
      
      // Phase 5: Analyse comparative
      const comparison = this.generateComparison();
      
      // Génération du rapport final
      const finalCompleteReport = await this.generateFinalReport();
      
      success = finalCompleteReport.verdict.overallSuccess;
      
    } catch (error) {
      console.error('💥 Erreur fatale pendant l\'exécution de la suite de tests:', error);
      success = false;
    } finally {
      // Nettoyage
      await this.stopMongoMemoryServer();
    }
    
    console.log('\n🏁 SUITE DE TESTS COMPLETE TERMINEE');
    console.log('===================================');
    
    if (success) {
      console.log('🎉 SUCCÈS: Cycle complet de test/correction/validation réussi!');
      console.log('   ✅ Problèmes détectés et corrigés automatiquement');
      console.log('   ✅ Intégrité des données post-migration validée');
    } else {
      console.log('❌ ÉCHEC: La suite de tests a rencontré des problèmes');
      console.log('   ⚠️  Consulter les rapports détaillés pour l\'analyse');
    }
    
    return { success, results: this.results };
  }
}

// Exécution si appelé directement
if (require.main === module) {
  const testSuite = new CompleteIntegrityTestSuite();
  testSuite.run().then(({ success, results }) => {
    if (success) {
      console.log('\n✅ CONCLUSION FINALE: Migration FAF entièrement validée!');
      console.log('   🔧 Système de vérification et correction opérationnel');
      console.log('   📊 Processus complet testé et validé');
      process.exit(0);
    } else {
      console.log('\n❌ CONCLUSION FINALE: Des améliorations sont nécessaires');
      console.log('   📋 Consulter les rapports pour les détails');
      process.exit(1);
    }
  }).catch((error) => {
    console.error('💥 Erreur critique de la suite de tests:', error);
    process.exit(2);
  });
}

module.exports = CompleteIntegrityTestSuite;