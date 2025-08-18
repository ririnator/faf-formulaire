#!/usr/bin/env node

/**
 * SCRIPT DE CORRECTION AUTOMATIQUE DES PROBLÈMES DE MIGRATION FAF
 * 
 * Ce script corrige automatiquement les problèmes identifiés par la vérification
 * d'intégrité post-migration FAF v1 → v2.
 */

const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');

// Configuration
require('dotenv').config({ path: path.resolve(__dirname, '../.env.test') });

// Modèles
const Response = require('../models/Response');
const Submission = require('../models/Submission');
const User = require('../models/User');

class MigrationIssuesFixer {
  constructor(options = {}) {
    this.dryRun = options.dryRun || false;
    this.verbose = options.verbose || false;
    
    this.fixes = {
      orphanedResponses: [],
      missingUserAccounts: [],
      brokenRelationships: [],
      orphanedData: [],
      statisticsErrors: []
    };
    
    this.stats = {
      totalFixes: 0,
      successfulFixes: 0,
      failedFixes: 0,
      skippedFixes: 0
    };
    
    this.startTime = Date.now();
  }

  async connectToDatabase() {
    try {
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/faf-test';
      await mongoose.connect(mongoUri);
      console.log(`✅ Connexion à MongoDB établie${this.dryRun ? ' (MODE DRY-RUN)' : ''}`);
      console.log(`📍 Base de données: ${mongoose.connection.db.databaseName}`);
      return true;
    } catch (error) {
      console.error('❌ Erreur de connexion à MongoDB:', error.message);
      return false;
    }
  }

  log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = this.dryRun ? '[DRY-RUN] ' : '';
    
    if (level === 'verbose' && !this.verbose) return;
    
    const levelEmojis = {
      info: 'ℹ️',
      success: '✅',
      warning: '⚠️',
      error: '❌',
      verbose: '🔍'
    };
    
    console.log(`${levelEmojis[level]} ${prefix}${message}`);
  }

  /**
   * 1. Correction des Response orphelines
   */
  async fixOrphanedResponses() {
    this.log('\n🔧 Correction des Response orphelines...', 'info');
    
    try {
      // Identifier les Response orphelines
      const orphanedResponses = [];
      
      // Méthode 1: Response avec des noms sans User correspondant
      const responsesWithoutUsers = await Response.aggregate([
        { $match: { name: { $exists: true, $ne: null }, authMethod: 'token' } },
        {
          $lookup: {
            from: 'users',
            localField: 'name',
            foreignField: 'migrationData.legacyName',
            as: 'user'
          }
        },
        { $match: { user: { $size: 0 } } }
      ]);
      
      for (const response of responsesWithoutUsers) {
        orphanedResponses.push({
          _id: response._id,
          name: response.name,
          month: response.month,
          type: 'missing_user_account',
          response: response
        });
      }
      
      // Méthode 2: Response avec User mais sans Submission
      const responsesWithoutSubmissions = await Response.aggregate([
        { $match: { name: { $exists: true, $ne: null }, authMethod: 'token' } },
        {
          $lookup: {
            from: 'users',
            localField: 'name',
            foreignField: 'migrationData.legacyName',
            as: 'user'
          }
        },
        { $match: { user: { $size: 1 } } },
        {
          $lookup: {
            from: 'submissions',
            let: { userId: { $arrayElemAt: ['$user._id', 0] }, month: '$month' },
            pipeline: [
              { $match: { $expr: { $and: [{ $eq: ['$userId', '$$userId'] }, { $eq: ['$month', '$$month'] }] } } }
            ],
            as: 'submission'
          }
        },
        { $match: { submission: { $size: 0 } } }
      ]);
      
      for (const response of responsesWithoutSubmissions) {
        orphanedResponses.push({
          _id: response._id,
          name: response.name,
          month: response.month,
          type: 'missing_submission',
          response: response,
          user: response.user[0]
        });
      }
      
      this.log(`🔍 ${orphanedResponses.length} Response orphelines détectées`, 'info');
      
      for (const orphaned of orphanedResponses) {
        this.stats.totalFixes++;
        
        try {
          if (orphaned.type === 'missing_user_account') {
            // Créer le compte User manquant
            await this.createMissingUserAccount(orphaned.name, orphaned.response);
            
            // Récupérer le User nouvellement créé
            const newUser = await User.findOne({ 'migrationData.legacyName': orphaned.name });
            if (newUser) {
              // Créer la Submission correspondante
              await this.createSubmissionFromResponse(orphaned.response, newUser);
              this.log(`✅ Response orpheline corrigée: ${orphaned.name} (${orphaned.month})`, 'success');
            }
          } else if (orphaned.type === 'missing_submission') {
            // Créer seulement la Submission manquante
            const userDoc = await User.findById(orphaned.user._id);
            if (userDoc) {
              await this.createSubmissionFromResponse(orphaned.response, userDoc);
              this.log(`✅ Submission manquante créée: ${orphaned.name} (${orphaned.month})`, 'success');
            }
          }
          
          this.stats.successfulFixes++;
          this.fixes.orphanedResponses.push({
            responseId: orphaned._id,
            name: orphaned.name,
            month: orphaned.month,
            type: orphaned.type,
            status: 'fixed'
          });
          
        } catch (error) {
          this.log(`❌ Erreur lors de la correction de ${orphaned.name}: ${error.message}`, 'error');
          this.stats.failedFixes++;
          this.fixes.orphanedResponses.push({
            responseId: orphaned._id,
            name: orphaned.name,
            month: orphaned.month,
            type: orphaned.type,
            status: 'failed',
            error: error.message
          });
        }
      }
      
    } catch (error) {
      this.log(`❌ Erreur générale lors de la correction des Response orphelines: ${error.message}`, 'error');
    }
  }

  /**
   * 2. Création des comptes User manquants
   */
  async createMissingUserAccount(name, responseExample = null) {
    this.log(`👤 Création du compte User pour: ${name}`, 'verbose');
    
    if (this.dryRun) {
      this.log(`[DRY-RUN] Créerait le compte: ${name}`, 'info');
      return null;
    }
    
    try {
      // Générer un username unique
      let username = name.toLowerCase().replace(/[^a-z0-9]/g, '');
      let counter = 1;
      let originalUsername = username;
      
      while (await User.findOne({ username })) {
        username = `${originalUsername}${counter}`;
        counter++;
      }
      
      // Déterminer si c'est un admin
      const formAdminName = process.env.FORM_ADMIN_NAME;
      const isAdmin = formAdminName && name.toLowerCase() === formAdminName.toLowerCase();
      
      const user = new User({
        username: username,
        email: `${username}@test.com`,
        password: await bcrypt.hash('temp-password-' + Math.random().toString(36), 10),
        role: isAdmin ? 'admin' : 'user',
        profile: {
          firstName: name.charAt(0).toUpperCase() + name.slice(1),
          lastName: 'Migré'
        },
        metadata: {
          isActive: true,
          emailVerified: false, // Nécessitera une vérification
          responseCount: 0,
          registeredAt: new Date()
        },
        migrationData: {
          legacyName: name,
          migratedAt: new Date(),
          source: 'migration'
        },
        statistics: {
          totalSubmissions: 0,
          totalContacts: 0,
          averageResponseRate: 0,
          joinedCycles: 0
        }
      });
      
      await user.save();
      this.log(`✅ Compte User créé: ${name} → ${username} (${isAdmin ? 'ADMIN' : 'USER'})`, 'success');
      return user;
      
    } catch (error) {
      this.log(`❌ Erreur lors de la création du compte ${name}: ${error.message}`, 'error');
      throw error;
    }
  }

  /**
   * 3. Création de Submission à partir de Response
   */
  async createSubmissionFromResponse(response, user) {
    this.log(`📄 Création de Submission: ${user.username} (${response.month})`, 'verbose');
    
    if (this.dryRun) {
      this.log(`[DRY-RUN] Créerait la Submission pour: ${user.username}`, 'info');
      return null;
    }
    
    try {
      // Conversion des réponses
      const submissionResponses = response.responses?.map((resp, index) => ({
        questionId: `q_${index + 1}`,
        type: 'text',
        answer: resp.answer || ''
      })) || [];
      
      // Calcul du taux de completion
      const completionRate = Math.min(100, Math.round((submissionResponses.length / 10) * 100));
      
      const submission = new Submission({
        userId: user._id,
        month: response.month,
        responses: submissionResponses,
        completionRate: completionRate,
        isComplete: completionRate >= 80,
        submittedAt: response.createdAt || new Date(),
        formVersion: 'v1-migrated'
      });
      
      await submission.save();
      
      // Mettre à jour les statistiques utilisateur
      user.statistics.totalSubmissions += 1;
      user.metadata.responseCount += 1;
      await user.save();
      
      this.log(`✅ Submission créée: ${user.username} → ${response.month} (${completionRate}%)`, 'success');
      return submission;
      
    } catch (error) {
      this.log(`❌ Erreur lors de la création de Submission pour ${user.username}: ${error.message}`, 'error');
      throw error;
    }
  }

  /**
   * 4. Correction des relations brisées
   */
  async fixBrokenRelationships() {
    this.log('\n🔗 Correction des relations brisées...', 'info');
    
    try {
      // Identifier les Submission orphelines (sans User)
      const orphanedSubmissions = await Submission.aggregate([
        {
          $lookup: {
            from: 'users',
            localField: 'userId',
            foreignField: '_id',
            as: 'user'
          }
        },
        { $match: { user: { $size: 0 } } }
      ]);
      
      this.log(`🔍 ${orphanedSubmissions.length} Submission orphelines détectées`, 'info');
      
      for (const submission of orphanedSubmissions) {
        this.stats.totalFixes++;
        
        try {
          if (this.dryRun) {
            this.log(`[DRY-RUN] Supprimerait la Submission orpheline: ${submission._id}`, 'info');
            this.stats.skippedFixes++;
          } else {
            // Supprimer la Submission orpheline
            await Submission.deleteOne({ _id: submission._id });
            this.log(`✅ Submission orpheline supprimée: ${submission._id} (${submission.month})`, 'success');
            this.stats.successfulFixes++;
          }
          
          this.fixes.brokenRelationships.push({
            submissionId: submission._id,
            month: submission.month,
            action: 'deleted_orphaned_submission',
            status: this.dryRun ? 'dry_run' : 'fixed'
          });
          
        } catch (error) {
          this.log(`❌ Erreur lors de la suppression de Submission ${submission._id}: ${error.message}`, 'error');
          this.stats.failedFixes++;
        }
      }
      
      // Identifier les Users avec des statistiques incorrectes
      const usersWithWrongStats = await User.find({});
      
      for (const user of usersWithWrongStats) {
        const actualSubmissionCount = await Submission.countDocuments({ userId: user._id });
        
        if (user.statistics.totalSubmissions !== actualSubmissionCount || 
            user.metadata.responseCount !== actualSubmissionCount) {
          
          this.stats.totalFixes++;
          
          try {
            if (this.dryRun) {
              this.log(`[DRY-RUN] Corrigerait les statistiques de: ${user.username}`, 'verbose');
              this.stats.skippedFixes++;
            } else {
              // Corriger les statistiques
              user.statistics.totalSubmissions = actualSubmissionCount;
              user.metadata.responseCount = actualSubmissionCount;
              await user.save();
              
              this.log(`✅ Statistiques corrigées: ${user.username} (${actualSubmissionCount} submissions)`, 'success');
              this.stats.successfulFixes++;
            }
            
            this.fixes.statisticsErrors.push({
              userId: user._id,
              username: user.username,
              oldCount: user.statistics.totalSubmissions,
              newCount: actualSubmissionCount,
              status: this.dryRun ? 'dry_run' : 'fixed'
            });
            
          } catch (error) {
            this.log(`❌ Erreur lors de la correction des statistiques ${user.username}: ${error.message}`, 'error');
            this.stats.failedFixes++;
          }
        }
      }
      
    } catch (error) {
      this.log(`❌ Erreur générale lors de la correction des relations: ${error.message}`, 'error');
    }
  }

  /**
   * 5. Nettoyage des données orphelines générales
   */
  async cleanOrphanedData() {
    this.log('\n🧹 Nettoyage des données orphelines...', 'info');
    
    try {
      // Nettoyer les tokens dupliqués (si existants)
      const duplicateTokens = await Response.aggregate([
        { $match: { token: { $exists: true, $ne: null } } },
        { $group: { _id: '$token', count: { $sum: 1 }, docs: { $push: '$$ROOT' } } },
        { $match: { count: { $gt: 1 } } }
      ]);
      
      for (const duplicate of duplicateTokens) {
        this.stats.totalFixes++;
        
        try {
          // Garder le plus ancien, supprimer les autres
          const docsToDelete = duplicate.docs.slice(1); // Garder le premier
          
          if (this.dryRun) {
            this.log(`[DRY-RUN] Supprimerait ${docsToDelete.length} Response avec token dupliqué: ${duplicate._id}`, 'info');
            this.stats.skippedFixes++;
          } else {
            for (const doc of docsToDelete) {
              await Response.deleteOne({ _id: doc._id });
            }
            this.log(`✅ Tokens dupliqués nettoyés: ${duplicate._id} (${docsToDelete.length} supprimés)`, 'success');
            this.stats.successfulFixes++;
          }
          
        } catch (error) {
          this.log(`❌ Erreur lors du nettoyage du token ${duplicate._id}: ${error.message}`, 'error');
          this.stats.failedFixes++;
        }
      }
      
    } catch (error) {
      this.log(`❌ Erreur générale lors du nettoyage: ${error.message}`, 'error');
    }
  }

  /**
   * Génération du rapport de correction
   */
  generateReport() {
    const endTime = Date.now();
    const executionTime = endTime - this.startTime;
    
    const report = {
      timestamp: new Date().toISOString(),
      dryRun: this.dryRun,
      executionTime: executionTime,
      statistics: this.stats,
      fixes: this.fixes,
      summary: {
        totalIssuesFound: this.stats.totalFixes,
        successfulFixes: this.stats.successfulFixes,
        failedFixes: this.stats.failedFixes,
        skippedFixes: this.stats.skippedFixes,
        successRate: this.stats.totalFixes > 0 ? 
          (this.stats.successfulFixes / this.stats.totalFixes) * 100 : 100
      }
    };
    
    // Sauvegarder le rapport
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `migration-fixes-report-${timestamp}.json`;
    const filepath = path.join(__dirname, '../reports', filename);
    
    try {
      const reportsDir = path.dirname(filepath);
      if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
      }
      
      fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
      this.log(`💾 Rapport de corrections sauvegardé: ${filepath}`, 'success');
    } catch (error) {
      this.log(`❌ Erreur lors de la sauvegarde du rapport: ${error.message}`, 'error');
    }
    
    return report;
  }

  /**
   * Exécution complète des corrections
   */
  async run() {
    this.log(`🔧 CORRECTION AUTOMATIQUE DES PROBLEMES DE MIGRATION FAF${this.dryRun ? ' (DRY-RUN)' : ''}`, 'info');
    this.log('==================================================', 'info');
    this.log(`📅 Démarré le: ${new Date().toLocaleString()}`, 'info');
    
    // Connexion à la base de données
    const connected = await this.connectToDatabase();
    if (!connected) {
      return null;
    }
    
    try {
      // Étapes de correction
      await this.fixOrphanedResponses();
      await this.fixBrokenRelationships();
      await this.cleanOrphanedData();
      
      // Génération du rapport
      const report = this.generateReport();
      
      this.log('\n📊 RÉSUMÉ DES CORRECTIONS:', 'info');
      this.log(`   🎯 Total des problèmes traités: ${this.stats.totalFixes}`, 'info');
      this.log(`   ✅ Corrections réussies: ${this.stats.successfulFixes}`, 'success');
      this.log(`   ❌ Corrections échouées: ${this.stats.failedFixes}`, this.stats.failedFixes > 0 ? 'warning' : 'info');
      this.log(`   ⏭️  Corrections ignorées: ${this.stats.skippedFixes}`, 'info');
      this.log(`   📈 Taux de réussite: ${report.summary.successRate.toFixed(2)}%`, 'info');
      this.log(`   ⏱️  Temps d'exécution: ${(report.executionTime / 1000).toFixed(2)}s`, 'info');
      
      if (this.dryRun) {
        this.log('\n⚠️  MODE DRY-RUN: Aucune modification n\'a été appliquée', 'warning');
        this.log('   Pour exécuter les corrections, relancez sans --dry-run', 'info');
      }
      
      return report;
      
    } catch (error) {
      this.log(`💥 Erreur fatale pendant les corrections: ${error.message}`, 'error');
      return null;
    } finally {
      await mongoose.connection.close();
      this.log('✅ Connexion à MongoDB fermée', 'info');
    }
  }
}

// Analyse des arguments de ligne de commande
const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const verbose = args.includes('--verbose');
const help = args.includes('--help') || args.includes('-h');

if (help) {
  console.log(`
🔧 SCRIPT DE CORRECTION AUTOMATIQUE DES PROBLEMES DE MIGRATION FAF

Usage: node fixMigrationIssues.js [options]

Options:
  --dry-run     Mode simulation - affiche les corrections sans les appliquer
  --verbose     Affichage détaillé des opérations
  --help, -h    Affiche cette aide

Exemples:
  node fixMigrationIssues.js --dry-run          # Simulation des corrections
  node fixMigrationIssues.js --verbose          # Corrections avec détails
  node fixMigrationIssues.js                    # Corrections normales
  
Corrections appliquées:
  - Response orphelines → Création User + Submission
  - Comptes User manquants → Création avec paramètres par défaut  
  - Relations brisées → Nettoyage + correction des statistiques
  - Données orphelines → Suppression des enregistrements invalides
`);
  process.exit(0);
}

// Exécution si appelé directement
if (require.main === module) {
  const fixer = new MigrationIssuesFixer({ dryRun, verbose });
  fixer.run().then((report) => {
    if (report) {
      if (dryRun) {
        console.log('\n✅ Simulation terminée - Aucune modification appliquée');
      } else if (report.summary.successRate >= 95) {
        console.log('\n🎉 Corrections appliquées avec succès!');
      } else {
        console.log('\n⚠️  Corrections partielles - Vérifier les erreurs');
      }
      process.exit(0);
    } else {
      console.log('\n❌ Corrections échouées');
      process.exit(1);
    }
  }).catch((error) => {
    console.error('💥 Erreur critique:', error);
    process.exit(2);
  });
}

module.exports = MigrationIssuesFixer;