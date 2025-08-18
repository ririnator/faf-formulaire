#!/usr/bin/env node

/**
 * POST-MIGRATION DATA INTEGRITY VERIFICATION SCRIPT
 * 
 * Ce script effectue une vérification complète de l'intégrité des données 
 * après la migration FAF v1 (Response-based) vers Form-a-Friend v2 (User-Submission).
 * 
 * Fonctionnalités:
 * 1. Validation de la migration Response → Submission
 * 2. Vérification de la création des comptes User
 * 3. Contrôle de l'intégrité des données
 * 4. Validation des relations User ↔ Submission
 * 5. Tests de régression système
 * 6. Rapport détaillé avec recommandations
 */

const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');

// Modèles de données
const Response = require('../models/Response');
const Submission = require('../models/Submission');
const User = require('../models/User');
const Invitation = require('../models/Invitation');

// Configuration de la base de données - utilise .env.test pour la base locale
require('dotenv').config({ path: path.resolve(__dirname, '../.env.test') });

class PostMigrationDataIntegrityChecker {
  constructor() {
    this.report = {
      timestamp: new Date().toISOString(),
      summary: {
        status: 'PENDING',
        totalChecks: 0,
        passedChecks: 0,
        failedChecks: 0,
        criticalIssues: [],
        warnings: []
      },
      data: {
        responses: { total: 0, legacy: 0, migrated: 0 },
        submissions: { total: 0, complete: 0, incomplete: 0 },
        users: { total: 0, migrated: 0, native: 0, admin: 0 },
        invitations: { total: 0, active: 0, expired: 0 }
      },
      integrity: {
        responsesToSubmissions: { status: 'PENDING', details: {} },
        userAccountCreation: { status: 'PENDING', details: {} },
        dataConsistency: { status: 'PENDING', details: {} },
        relationshipValidity: { status: 'PENDING', details: {} },
        backwardCompatibility: { status: 'PENDING', details: {} }
      },
      performance: {
        executionTime: 0,
        memoryUsage: {},
        queryStats: {}
      },
      recommendations: []
    };
    
    this.startTime = Date.now();
    this.queryCount = 0;
  }

  /**
   * Connexion à la base de données
   */
  async connectToDatabase() {
    try {
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/faf-test';
      await mongoose.connect(mongoUri);
      console.log('✅ Connexion à MongoDB établie');
      console.log(`📍 Base de données: ${mongoose.connection.db.databaseName}`);
      return true;
    } catch (error) {
      console.error('❌ Erreur de connexion à MongoDB:', error.message);
      this.report.summary.criticalIssues.push({
        type: 'DATABASE_CONNECTION',
        message: `Impossible de se connecter à la base de données: ${error.message}`,
        timestamp: new Date().toISOString()
      });
      return false;
    }
  }

  /**
   * Collecte des données de base
   */
  async collectBaseData() {
    console.log('\n📊 Collecte des données de base...');
    
    try {
      // Comptage des Response
      this.queryCount++;
      this.report.data.responses.total = await Response.countDocuments();
      this.report.data.responses.legacy = await Response.countDocuments({ authMethod: 'token' });
      this.report.data.responses.migrated = await Response.countDocuments({ authMethod: 'user' });
      
      // Comptage des Submission
      this.queryCount++;
      this.report.data.submissions.total = await Submission.countDocuments();
      this.report.data.submissions.complete = await Submission.countDocuments({ isComplete: true });
      this.report.data.submissions.incomplete = await Submission.countDocuments({ isComplete: false });
      
      // Comptage des User
      this.queryCount++;
      this.report.data.users.total = await User.countDocuments();
      this.report.data.users.migrated = await User.countDocuments({ 'migrationData.source': 'migration' });
      this.report.data.users.native = await User.countDocuments({ 'migrationData.source': 'registration' });
      this.report.data.users.admin = await User.countDocuments({ role: 'admin' });
      
      // Comptage des Invitation
      this.queryCount++;
      if (mongoose.models.Invitation) {
        this.report.data.invitations.total = await Invitation.countDocuments();
        this.report.data.invitations.active = await Invitation.countDocuments({ status: 'sent' });
        this.report.data.invitations.expired = await Invitation.countDocuments({ status: 'expired' });
      }
      
      console.log(`   📈 Responses: ${this.report.data.responses.total} (Legacy: ${this.report.data.responses.legacy}, Migrated: ${this.report.data.responses.migrated})`);
      console.log(`   📝 Submissions: ${this.report.data.submissions.total} (Complete: ${this.report.data.submissions.complete})`);
      console.log(`   👤 Users: ${this.report.data.users.total} (Migrated: ${this.report.data.users.migrated}, Admins: ${this.report.data.users.admin})`);
      console.log(`   📧 Invitations: ${this.report.data.invitations.total}`);
      
      this.report.summary.passedChecks++;
      
    } catch (error) {
      console.error('❌ Erreur lors de la collecte des données:', error.message);
      this.report.summary.criticalIssues.push({
        type: 'DATA_COLLECTION_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
      this.report.summary.failedChecks++;
    }
    
    this.report.summary.totalChecks++;
  }

  /**
   * Vérification de la migration Response → Submission
   */
  async verifyResponseToSubmissionMigration() {
    console.log('\n🔄 Vérification de la migration Response → Submission...');
    
    const check = {
      status: 'PENDING',
      details: {
        totalResponses: 0,
        migratedToSubmissions: 0,
        orphanedResponses: [],
        duplicatedSubmissions: [],
        dataIntegrityIssues: [],
        monthlyBreakdown: {}
      }
    };

    try {
      // Récupération de tous les Response legacy (avec name)
      this.queryCount++;
      const legacyResponses = await Response.find({ 
        name: { $exists: true, $ne: null },
        authMethod: 'token'
      }).lean();
      
      check.details.totalResponses = legacyResponses.length;
      console.log(`   📋 Responses legacy trouvées: ${legacyResponses.length}`);
      
      // Vérification pour chaque Response
      for (const response of legacyResponses) {
        // Rechercher le User correspondant
        this.queryCount++;
        const user = await User.findOne({ 
          'migrationData.legacyName': response.name 
        }).lean();
        
        if (!user) {
          check.details.orphanedResponses.push({
            responseId: response._id,
            name: response.name,
            month: response.month,
            reason: 'User account not found'
          });
          continue;
        }
        
        // Rechercher la Submission correspondante
        this.queryCount++;
        const submission = await Submission.findOne({
          userId: user._id,
          month: response.month
        }).lean();
        
        if (submission) {
          check.details.migratedToSubmissions++;
          
          // Vérification de l'intégrité des données
          if (response.responses && submission.responses) {
            const responseQuestions = response.responses.length;
            const submissionQuestions = submission.responses.length;
            
            if (responseQuestions !== submissionQuestions) {
              check.details.dataIntegrityIssues.push({
                responseId: response._id,
                submissionId: submission._id,
                userName: response.name,
                month: response.month,
                issue: `Question count mismatch: ${responseQuestions} → ${submissionQuestions}`
              });
            }
          }
          
          // Statistiques par mois
          if (!check.details.monthlyBreakdown[response.month]) {
            check.details.monthlyBreakdown[response.month] = {
              responses: 0,
              submissions: 0,
              migrationRate: 0
            };
          }
          check.details.monthlyBreakdown[response.month].responses++;
          check.details.monthlyBreakdown[response.month].submissions++;
        } else {
          check.details.orphanedResponses.push({
            responseId: response._id,
            name: response.name,
            month: response.month,
            reason: 'Corresponding submission not found',
            userId: user._id
          });
        }
      }
      
      // Calcul des taux de migration par mois
      for (const month in check.details.monthlyBreakdown) {
        const data = check.details.monthlyBreakdown[month];
        data.migrationRate = data.responses > 0 ? (data.submissions / data.responses) * 100 : 0;
      }
      
      // Détection des doublons de Submission
      this.queryCount++;
      const duplicateSubmissions = await Submission.aggregate([
        { $group: { _id: { userId: '$userId', month: '$month' }, count: { $sum: 1 } } },
        { $match: { count: { $gt: 1 } } }
      ]);
      
      check.details.duplicatedSubmissions = duplicateSubmissions;
      
      // Évaluation du statut
      const migrationRate = check.details.totalResponses > 0 ? 
        (check.details.migratedToSubmissions / check.details.totalResponses) * 100 : 0;
      
      if (migrationRate >= 95 && check.details.dataIntegrityIssues.length === 0) {
        check.status = 'PASSED';
        console.log(`   ✅ Migration réussie: ${migrationRate.toFixed(2)}% (${check.details.migratedToSubmissions}/${check.details.totalResponses})`);
        this.report.summary.passedChecks++;
      } else {
        check.status = 'FAILED';
        console.log(`   ❌ Migration incomplète: ${migrationRate.toFixed(2)}% (${check.details.migratedToSubmissions}/${check.details.totalResponses})`);
        console.log(`   ⚠️  Responses orphelines: ${check.details.orphanedResponses.length}`);
        console.log(`   ⚠️  Problèmes d'intégrité: ${check.details.dataIntegrityIssues.length}`);
        this.report.summary.failedChecks++;
        
        this.report.summary.criticalIssues.push({
          type: 'MIGRATION_INCOMPLETE',
          message: `Migration Response → Submission incomplète (${migrationRate.toFixed(2)}%)`,
          details: {
            orphanedResponses: check.details.orphanedResponses.length,
            integrityIssues: check.details.dataIntegrityIssues.length
          }
        });
      }
      
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
      console.error('❌ Erreur lors de la vérification Response → Submission:', error.message);
      this.report.summary.failedChecks++;
      this.report.summary.criticalIssues.push({
        type: 'MIGRATION_CHECK_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
    
    this.report.integrity.responsesToSubmissions = check;
    this.report.summary.totalChecks++;
  }

  /**
   * Validation de la création des comptes User
   */
  async validateUserAccountCreation() {
    console.log('\n👤 Validation de la création des comptes User...');
    
    const check = {
      status: 'PENDING',
      details: {
        uniqueResponseNames: 0,
        createdUserAccounts: 0,
        missingUserAccounts: [],
        duplicateUsernames: [],
        invalidUserData: [],
        adminAccountsCreated: 0,
        nameToUsernameMapping: {}
      }
    };

    try {
      // Récupération des noms uniques des Response legacy
      this.queryCount++;
      const uniqueNames = await Response.distinct('name', { 
        name: { $exists: true, $ne: null },
        authMethod: 'token'
      });
      
      check.details.uniqueResponseNames = uniqueNames.length;
      console.log(`   📋 Noms uniques trouvés dans Response: ${uniqueNames.length}`);
      
      // Vérification pour chaque nom unique
      for (const name of uniqueNames) {
        this.queryCount++;
        const user = await User.findOne({ 
          'migrationData.legacyName': name 
        }).lean();
        
        if (user) {
          check.details.createdUserAccounts++;
          check.details.nameToUsernameMapping[name] = user.username;
          
          // Vérification du rôle admin
          const formAdminName = process.env.FORM_ADMIN_NAME;
          if (formAdminName && name.toLowerCase() === formAdminName.toLowerCase()) {
            if (user.role === 'admin') {
              check.details.adminAccountsCreated++;
            } else {
              check.details.invalidUserData.push({
                name,
                username: user.username,
                issue: `Should be admin but role is: ${user.role}`
              });
            }
          }
          
          // Validation des données utilisateur
          if (!user.email || !user.username) {
            check.details.invalidUserData.push({
              name,
              userId: user._id,
              issue: 'Missing required fields (email or username)'
            });
          }
          
        } else {
          check.details.missingUserAccounts.push({
            name,
            reason: 'User account not created during migration'
          });
        }
      }
      
      // Vérification des doublons d'username
      this.queryCount++;
      const duplicateUsernames = await User.aggregate([
        { $group: { _id: '$username', count: { $sum: 1 } } },
        { $match: { count: { $gt: 1 } } }
      ]);
      
      check.details.duplicateUsernames = duplicateUsernames.map(dup => ({
        username: dup._id,
        count: dup.count
      }));
      
      // Évaluation du statut
      const accountCreationRate = check.details.uniqueResponseNames > 0 ? 
        (check.details.createdUserAccounts / check.details.uniqueResponseNames) * 100 : 0;
      
      if (accountCreationRate >= 100 && 
          check.details.duplicateUsernames.length === 0 && 
          check.details.invalidUserData.length === 0) {
        check.status = 'PASSED';
        console.log(`   ✅ Création des comptes réussie: ${accountCreationRate}% (${check.details.createdUserAccounts}/${check.details.uniqueResponseNames})`);
        console.log(`   👑 Comptes admin créés: ${check.details.adminAccountsCreated}`);
        this.report.summary.passedChecks++;
      } else {
        check.status = 'FAILED';
        console.log(`   ❌ Création des comptes incomplète: ${accountCreationRate.toFixed(2)}%`);
        console.log(`   ⚠️  Comptes manquants: ${check.details.missingUserAccounts.length}`);
        console.log(`   ⚠️  Doublons username: ${check.details.duplicateUsernames.length}`);
        console.log(`   ⚠️  Données invalides: ${check.details.invalidUserData.length}`);
        this.report.summary.failedChecks++;
        
        this.report.summary.criticalIssues.push({
          type: 'USER_CREATION_INCOMPLETE',
          message: `Création des comptes User incomplète (${accountCreationRate.toFixed(2)}%)`,
          details: {
            missingAccounts: check.details.missingUserAccounts.length,
            duplicateUsernames: check.details.duplicateUsernames.length,
            invalidData: check.details.invalidUserData.length
          }
        });
      }
      
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
      console.error('❌ Erreur lors de la validation des comptes User:', error.message);
      this.report.summary.failedChecks++;
      this.report.summary.criticalIssues.push({
        type: 'USER_VALIDATION_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
    
    this.report.integrity.userAccountCreation = check;
    this.report.summary.totalChecks++;
  }

  /**
   * Contrôle de l'intégrité et corruption des données
   */
  async checkDataIntegrityAndCorruption() {
    console.log('\n🔍 Contrôle de l\'intégrité et corruption des données...');
    
    const check = {
      status: 'PENDING',
      details: {
        corruptedResponses: [],
        corruptedSubmissions: [],
        corruptedUsers: [],
        missingFields: [],
        invalidDates: [],
        orphanedData: [],
        schemaViolations: []
      }
    };

    try {
      // Vérification des Response corrompues
      this.queryCount++;
      const responses = await Response.find({}).lean();
      
      for (const response of responses) {
        const issues = [];
        
        // Vérification des champs requis
        if (!response.month) issues.push('Missing month field');
        if (!response.createdAt) issues.push('Missing createdAt field');
        if (!response.responses || !Array.isArray(response.responses)) {
          issues.push('Missing or invalid responses array');
        }
        
        // Vérification du format du mois
        if (response.month && !/^\d{4}-\d{2}$/.test(response.month)) {
          issues.push(`Invalid month format: ${response.month}`);
        }
        
        // Vérification des dates
        if (response.createdAt && isNaN(Date.parse(response.createdAt))) {
          issues.push('Invalid createdAt date');
        }
        
        // Vérification de la cohérence authMethod
        if (response.authMethod === 'user' && !response.userId) {
          issues.push('Missing userId for user authMethod');
        }
        if (response.authMethod === 'token' && !response.name) {
          issues.push('Missing name for token authMethod');
        }
        
        if (issues.length > 0) {
          check.details.corruptedResponses.push({
            id: response._id,
            issues
          });
        }
      }
      
      // Vérification des Submission corrompues
      this.queryCount++;
      const submissions = await Submission.find({}).lean();
      
      for (const submission of submissions) {
        const issues = [];
        
        // Vérification des champs requis
        if (!submission.userId) issues.push('Missing userId field');
        if (!submission.month) issues.push('Missing month field');
        if (!submission.responses || !Array.isArray(submission.responses)) {
          issues.push('Missing or invalid responses array');
        }
        
        // Vérification du format du mois
        if (submission.month && !/^\d{4}-\d{2}$/.test(submission.month)) {
          issues.push(`Invalid month format: ${submission.month}`);
        }
        
        // Vérification des dates
        if (submission.submittedAt && isNaN(Date.parse(submission.submittedAt))) {
          issues.push('Invalid submittedAt date');
        }
        
        // Vérification de la cohérence completionRate
        if (typeof submission.completionRate !== 'number' || 
            submission.completionRate < 0 || 
            submission.completionRate > 100) {
          issues.push(`Invalid completionRate: ${submission.completionRate}`);
        }
        
        if (issues.length > 0) {
          check.details.corruptedSubmissions.push({
            id: submission._id,
            issues
          });
        }
      }
      
      // Vérification des User corrompus
      this.queryCount++;
      const users = await User.find({}).lean();
      
      for (const user of users) {
        const issues = [];
        
        // Vérification des champs requis
        if (!user.username) issues.push('Missing username field');
        if (!user.email) issues.push('Missing email field');
        if (!user.password) issues.push('Missing password field');
        
        // Vérification du format email
        if (user.email && !/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(user.email)) {
          issues.push(`Invalid email format: ${user.email}`);
        }
        
        // Vérification de la longueur username
        if (user.username && (user.username.length < 3 || user.username.length > 30)) {
          issues.push(`Invalid username length: ${user.username.length}`);
        }
        
        // Vérification du rôle
        if (user.role && !['user', 'admin'].includes(user.role)) {
          issues.push(`Invalid role: ${user.role}`);
        }
        
        if (issues.length > 0) {
          check.details.corruptedUsers.push({
            id: user._id,
            username: user.username,
            issues
          });
        }
      }
      
      // Vérification des données orphelines (Submission sans User)
      this.queryCount++;
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
      
      check.details.orphanedData = orphanedSubmissions.map(sub => ({
        type: 'Submission',
        id: sub._id,
        userId: sub.userId,
        month: sub.month
      }));
      
      // Évaluation du statut
      const totalIssues = check.details.corruptedResponses.length + 
                         check.details.corruptedSubmissions.length + 
                         check.details.corruptedUsers.length + 
                         check.details.orphanedData.length;
      
      if (totalIssues === 0) {
        check.status = 'PASSED';
        console.log('   ✅ Aucune corruption de données détectée');
        this.report.summary.passedChecks++;
      } else {
        check.status = 'FAILED';
        console.log(`   ❌ ${totalIssues} problèmes d'intégrité détectés:`);
        console.log(`      - Responses corrompues: ${check.details.corruptedResponses.length}`);
        console.log(`      - Submissions corrompues: ${check.details.corruptedSubmissions.length}`);
        console.log(`      - Users corrompus: ${check.details.corruptedUsers.length}`);
        console.log(`      - Données orphelines: ${check.details.orphanedData.length}`);
        this.report.summary.failedChecks++;
        
        this.report.summary.criticalIssues.push({
          type: 'DATA_CORRUPTION',
          message: `${totalIssues} problèmes d'intégrité de données détectés`,
          details: {
            corruptedResponses: check.details.corruptedResponses.length,
            corruptedSubmissions: check.details.corruptedSubmissions.length,
            corruptedUsers: check.details.corruptedUsers.length,
            orphanedData: check.details.orphanedData.length
          }
        });
      }
      
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
      console.error('❌ Erreur lors du contrôle d\'intégrité:', error.message);
      this.report.summary.failedChecks++;
      this.report.summary.criticalIssues.push({
        type: 'INTEGRITY_CHECK_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
    
    this.report.integrity.dataConsistency = check;
    this.report.summary.totalChecks++;
  }

  /**
   * Validation des relations User ↔ Submission
   */
  async validateUserSubmissionRelationships() {
    console.log('\n🔗 Validation des relations User ↔ Submission...');
    
    const check = {
      status: 'PENDING',
      details: {
        totalSubmissions: 0,
        validRelationships: 0,
        brokenRelationships: [],
        missingUsers: [],
        inconsistentData: [],
        statisticsErrors: []
      }
    };

    try {
      // Récupération de toutes les Submission
      this.queryCount++;
      const submissions = await Submission.find({}).populate('userId').lean();
      check.details.totalSubmissions = submissions.length;
      
      console.log(`   📋 Submissions à vérifier: ${submissions.length}`);
      
      for (const submission of submissions) {
        if (!submission.userId) {
          check.details.missingUsers.push({
            submissionId: submission._id,
            month: submission.month,
            reason: 'userId is null or undefined'
          });
          continue;
        }
        
        // Si populate a échoué, l'utilisateur n'existe pas
        if (!submission.userId.username) {
          check.details.brokenRelationships.push({
            submissionId: submission._id,
            userId: submission.userId._id || submission.userId,
            month: submission.month,
            reason: 'Referenced user does not exist'
          });
          continue;
        }
        
        check.details.validRelationships++;
        
        // Vérification des statistiques utilisateur
        const user = submission.userId;
        
        // Comptage réel des submissions de cet utilisateur
        this.queryCount++;
        const actualSubmissionCount = await Submission.countDocuments({ userId: user._id });
        
        if (user.statistics && user.statistics.totalSubmissions !== actualSubmissionCount) {
          check.details.statisticsErrors.push({
            userId: user._id,
            username: user.username,
            recordedCount: user.statistics.totalSubmissions,
            actualCount: actualSubmissionCount,
            difference: actualSubmissionCount - user.statistics.totalSubmissions
          });
        }
        
        // Vérification de la cohérence responseCount (legacy)
        if (user.metadata && user.metadata.responseCount) {
          const totalResponses = actualSubmissionCount; // Dans le nouveau système
          if (user.metadata.responseCount !== totalResponses) {
            check.details.inconsistentData.push({
              userId: user._id,
              username: user.username,
              field: 'responseCount',
              recorded: user.metadata.responseCount,
              actual: totalResponses
            });
          }
        }
      }
      
      // Vérification inverse: Users sans Submission qui devraient en avoir
      this.queryCount++;
      const migratedUsers = await User.find({ 
        'migrationData.source': 'migration' 
      }).lean();
      
      for (const user of migratedUsers) {
        this.queryCount++;
        const submissionCount = await Submission.countDocuments({ userId: user._id });
        
        if (submissionCount === 0) {
          // Vérifier s'il y avait des Response legacy pour ce nom
          this.queryCount++;
          const legacyResponseCount = await Response.countDocuments({ 
            name: user.migrationData.legacyName,
            authMethod: 'token'
          });
          
          if (legacyResponseCount > 0) {
            check.details.brokenRelationships.push({
              userId: user._id,
              username: user.username,
              legacyName: user.migrationData.legacyName,
              reason: `User has ${legacyResponseCount} legacy Response but no Submission`
            });
          }
        }
      }
      
      // Évaluation du statut
      const relationshipValidityRate = check.details.totalSubmissions > 0 ? 
        (check.details.validRelationships / check.details.totalSubmissions) * 100 : 100;
      
      if (relationshipValidityRate >= 98 && 
          check.details.brokenRelationships.length === 0 &&
          check.details.statisticsErrors.length <= 5) { // Tolérance pour les stats
        check.status = 'PASSED';
        console.log(`   ✅ Relations valides: ${relationshipValidityRate.toFixed(2)}% (${check.details.validRelationships}/${check.details.totalSubmissions})`);
        if (check.details.statisticsErrors.length > 0) {
          console.log(`   ⚠️  Erreurs statistiques mineures: ${check.details.statisticsErrors.length}`);
        }
        this.report.summary.passedChecks++;
      } else {
        check.status = 'FAILED';
        console.log(`   ❌ Relations invalides: ${(100 - relationshipValidityRate).toFixed(2)}%`);
        console.log(`   ⚠️  Relations brisées: ${check.details.brokenRelationships.length}`);
        console.log(`   ⚠️  Utilisateurs manquants: ${check.details.missingUsers.length}`);
        console.log(`   ⚠️  Erreurs statistiques: ${check.details.statisticsErrors.length}`);
        this.report.summary.failedChecks++;
        
        this.report.summary.criticalIssues.push({
          type: 'RELATIONSHIP_VALIDATION_FAILED',
          message: `Relations User ↔ Submission invalides (${(100 - relationshipValidityRate).toFixed(2)}% d'erreur)`,
          details: {
            brokenRelationships: check.details.brokenRelationships.length,
            missingUsers: check.details.missingUsers.length,
            statisticsErrors: check.details.statisticsErrors.length
          }
        });
      }
      
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
      console.error('❌ Erreur lors de la validation des relations:', error.message);
      this.report.summary.failedChecks++;
      this.report.summary.criticalIssues.push({
        type: 'RELATIONSHIP_CHECK_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
    
    this.report.integrity.relationshipValidity = check;
    this.report.summary.totalChecks++;
  }

  /**
   * Tests de régression pour l'ancien système
   */
  async runRegressionTests() {
    console.log('\n🔬 Tests de régression pour l\'ancien système...');
    
    const check = {
      status: 'PENDING',
      details: {
        legacyTokensWorking: 0,
        brokenTokens: [],
        legacyDataAccessible: 0,
        inaccessibleLegacyData: [],
        authMethodConsistency: [],
        hybridSystemIssues: []
      }
    };

    try {
      // Test 1: Vérification des tokens legacy
      this.queryCount++;
      const legacyResponses = await Response.find({ 
        token: { $exists: true, $ne: null },
        authMethod: 'token'
      }).lean();
      
      console.log(`   🔑 Tokens legacy à tester: ${legacyResponses.length}`);
      
      for (const response of legacyResponses) {
        // Vérifier que le token est toujours unique
        this.queryCount++;
        const duplicateTokens = await Response.countDocuments({ token: response.token });
        
        if (duplicateTokens === 1) {
          check.details.legacyTokensWorking++;
        } else {
          check.details.brokenTokens.push({
            responseId: response._id,
            token: response.token,
            duplicateCount: duplicateTokens,
            name: response.name,
            month: response.month
          });
        }
      }
      
      // Test 2: Accessibilité des données legacy
      this.queryCount++;
      const responsesWithData = await Response.find({
        authMethod: 'token',
        responses: { $exists: true, $not: { $size: 0 } }
      }).lean();
      
      for (const response of responsesWithData) {
        // Vérifier que les données sont toujours structurées correctement
        let accessible = true;
        let issues = [];
        
        if (!response.responses || !Array.isArray(response.responses)) {
          accessible = false;
          issues.push('responses field is not an array');
        } else {
          for (const resp of response.responses) {
            if (!resp.question || !resp.answer) {
              accessible = false;
              issues.push('Missing question or answer in response');
              break;
            }
          }
        }
        
        if (accessible) {
          check.details.legacyDataAccessible++;
        } else {
          check.details.inaccessibleLegacyData.push({
            responseId: response._id,
            name: response.name,
            month: response.month,
            issues
          });
        }
      }
      
      // Test 3: Cohérence des authMethod
      this.queryCount++;
      const inconsistentAuthMethods = await Response.find({
        $or: [
          { authMethod: 'token', name: { $exists: false } },
          { authMethod: 'token', token: { $exists: false } },
          { authMethod: 'user', userId: { $exists: false } },
          { authMethod: 'user', name: { $exists: true, $ne: null } }
        ]
      }).lean();
      
      check.details.authMethodConsistency = inconsistentAuthMethods.map(resp => ({
        responseId: resp._id,
        authMethod: resp.authMethod,
        hasName: !!resp.name,
        hasToken: !!resp.token,
        hasUserId: !!resp.userId,
        month: resp.month
      }));
      
      // Test 4: Vérification du système hybride
      // Chercher des conflits potentiels entre ancien et nouveau système
      this.queryCount++;
      const hybridConflicts = await Response.aggregate([
        {
          $group: {
            _id: { month: '$month', name: '$name' },
            authMethods: { $addToSet: '$authMethod' },
            count: { $sum: 1 }
          }
        },
        {
          $match: {
            'authMethods.1': { $exists: true } // Plus d'une méthode d'auth
          }
        }
      ]);
      
      check.details.hybridSystemIssues = hybridConflicts;
      
      // Évaluation du statut
      const tokenSuccessRate = legacyResponses.length > 0 ? 
        (check.details.legacyTokensWorking / legacyResponses.length) * 100 : 100;
      const dataAccessRate = responsesWithData.length > 0 ? 
        (check.details.legacyDataAccessible / responsesWithData.length) * 100 : 100;
      
      if (tokenSuccessRate >= 95 && 
          dataAccessRate >= 95 && 
          check.details.authMethodConsistency.length === 0 &&
          check.details.hybridSystemIssues.length === 0) {
        check.status = 'PASSED';
        console.log(`   ✅ Système legacy fonctionnel:`);
        console.log(`      - Tokens valides: ${tokenSuccessRate.toFixed(2)}% (${check.details.legacyTokensWorking}/${legacyResponses.length})`);
        console.log(`      - Données accessibles: ${dataAccessRate.toFixed(2)}% (${check.details.legacyDataAccessible}/${responsesWithData.length})`);
        this.report.summary.passedChecks++;
      } else {
        check.status = 'FAILED';
        console.log(`   ❌ Problèmes détectés dans le système legacy:`);
        console.log(`      - Tokens cassés: ${check.details.brokenTokens.length}`);
        console.log(`      - Données inaccessibles: ${check.details.inaccessibleLegacyData.length}`);
        console.log(`      - Incohérences authMethod: ${check.details.authMethodConsistency.length}`);
        console.log(`      - Conflits système hybride: ${check.details.hybridSystemIssues.length}`);
        this.report.summary.failedChecks++;
        
        this.report.summary.criticalIssues.push({
          type: 'REGRESSION_TEST_FAILED',
          message: 'Tests de régression échoués pour le système legacy',
          details: {
            brokenTokens: check.details.brokenTokens.length,
            inaccessibleData: check.details.inaccessibleLegacyData.length,
            authMethodIssues: check.details.authMethodConsistency.length,
            hybridIssues: check.details.hybridSystemIssues.length
          }
        });
      }
      
    } catch (error) {
      check.status = 'ERROR';
      check.details.error = error.message;
      console.error('❌ Erreur lors des tests de régression:', error.message);
      this.report.summary.failedChecks++;
      this.report.summary.criticalIssues.push({
        type: 'REGRESSION_TEST_ERROR',
        message: error.message,
        timestamp: new Date().toISOString()
      });
    }
    
    this.report.integrity.backwardCompatibility = check;
    this.report.summary.totalChecks++;
  }

  /**
   * Génération des recommandations
   */
  generateRecommendations() {
    console.log('\n💡 Génération des recommandations...');
    
    const recommendations = [];
    
    // Recommandations basées sur les résultats des vérifications
    if (this.report.integrity.responsesToSubmissions.status === 'FAILED') {
      const details = this.report.integrity.responsesToSubmissions.details;
      
      if (details.orphanedResponses && details.orphanedResponses.length > 0) {
        recommendations.push({
          priority: 'HIGH',
          category: 'MIGRATION',
          title: 'Responses orphelines détectées',
          description: `${details.orphanedResponses.length} Response n'ont pas été migrées vers Submission`,
          action: 'Exécuter un script de migration complémentaire pour traiter les Response orphelines',
          impact: 'CRITICAL',
          automatable: true
        });
      }
      
      if (details.dataIntegrityIssues && details.dataIntegrityIssues.length > 0) {
        recommendations.push({
          priority: 'HIGH',
          category: 'DATA_INTEGRITY',
          title: 'Problèmes d\'intégrité de données',
          description: `${details.dataIntegrityIssues.length} problèmes d'intégrité détectés lors de la migration`,
          action: 'Réviser et corriger les données corrompues ou incomplètes',
          impact: 'HIGH',
          automatable: false
        });
      }
    }
    
    if (this.report.integrity.userAccountCreation.status === 'FAILED') {
      const details = this.report.integrity.userAccountCreation.details;
      
      if (details.missingUserAccounts && details.missingUserAccounts.length > 0) {
        recommendations.push({
          priority: 'HIGH',
          category: 'USER_MANAGEMENT',
          title: 'Comptes utilisateur manquants',
          description: `${details.missingUserAccounts.length} comptes utilisateur n'ont pas été créés`,
          action: 'Créer les comptes utilisateur manquants avec les paramètres par défaut',
          impact: 'HIGH',
          automatable: true
        });
      }
      
      if (details.duplicateUsernames && details.duplicateUsernames.length > 0) {
        recommendations.push({
          priority: 'CRITICAL',
          category: 'DATA_INTEGRITY',
          title: 'Doublons d\'username détectés',
          description: `${details.duplicateUsernames.length} usernames dupliqués violent les contraintes uniques`,
          action: 'Résoudre les conflits d\'username en appliquant une stratégie de nommage cohérente',
          impact: 'CRITICAL',
          automatable: false
        });
      }
    }
    
    if (this.report.integrity.dataConsistency.status === 'FAILED') {
      const details = this.report.integrity.dataConsistency.details;
      
      if (details.orphanedData && details.orphanedData.length > 0) {
        recommendations.push({
          priority: 'MEDIUM',
          category: 'DATA_CLEANUP',
          title: 'Données orphelines détectées',
          description: `${details.orphanedData.length} enregistrements orphelins sans références valides`,
          action: 'Nettoyer les données orphelines ou rétablir les références manquantes',
          impact: 'MEDIUM',
          automatable: true
        });
      }
      
      const totalCorrupted = (details.corruptedResponses?.length || 0) + 
                           (details.corruptedSubmissions?.length || 0) + 
                           (details.corruptedUsers?.length || 0);
      
      if (totalCorrupted > 0) {
        recommendations.push({
          priority: 'HIGH',
          category: 'DATA_INTEGRITY',
          title: 'Données corrompues détectées',
          description: `${totalCorrupted} enregistrements avec des données corrompues ou invalides`,
          action: 'Réparer ou supprimer les enregistrements corrompus selon la criticité',
          impact: 'HIGH',
          automatable: false
        });
      }
    }
    
    if (this.report.integrity.relationshipValidity.status === 'FAILED') {
      const details = this.report.integrity.relationshipValidity.details;
      
      if (details.brokenRelationships && details.brokenRelationships.length > 0) {
        recommendations.push({
          priority: 'HIGH',
          category: 'RELATIONSHIP_INTEGRITY',
          title: 'Relations brisées User ↔ Submission',
          description: `${details.brokenRelationships.length} relations brisées entre User et Submission`,
          action: 'Rétablir les références manquantes ou supprimer les enregistrements orphelins',
          impact: 'HIGH',
          automatable: true
        });
      }
      
      if (details.statisticsErrors && details.statisticsErrors.length > 0) {
        recommendations.push({
          priority: 'LOW',
          category: 'DATA_CONSISTENCY',
          title: 'Statistiques utilisateur incohérentes',
          description: `${details.statisticsErrors.length} utilisateurs avec des statistiques incorrectes`,
          action: 'Recalculer les statistiques utilisateur à partir des données réelles',
          impact: 'LOW',
          automatable: true
        });
      }
    }
    
    if (this.report.integrity.backwardCompatibility.status === 'FAILED') {
      const details = this.report.integrity.backwardCompatibility.details;
      
      if (details.brokenTokens && details.brokenTokens.length > 0) {
        recommendations.push({
          priority: 'HIGH',
          category: 'BACKWARD_COMPATIBILITY',
          title: 'Tokens legacy cassés',
          description: `${details.brokenTokens.length} tokens legacy ne fonctionnent plus correctement`,
          action: 'Régénérer ou corriger les tokens legacy pour maintenir la compatibilité',
          impact: 'HIGH',
          automatable: true
        });
      }
      
      if (details.hybridSystemIssues && details.hybridSystemIssues.length > 0) {
        recommendations.push({
          priority: 'MEDIUM',
          category: 'SYSTEM_ARCHITECTURE',
          title: 'Conflits système hybride',
          description: `${details.hybridSystemIssues.length} conflits détectés dans le système hybride`,
          action: 'Résoudre les conflits entre ancien et nouveau système d\'authentification',
          impact: 'MEDIUM',
          automatable: false
        });
      }
    }
    
    // Recommandations générales basées sur les performances
    if (this.queryCount > 100) {
      recommendations.push({
        priority: 'LOW',
        category: 'PERFORMANCE',
        title: 'Optimisation des requêtes de vérification',
        description: `${this.queryCount} requêtes exécutées pendant la vérification`,
        action: 'Optimiser les index de base de données pour améliorer les performances',
        impact: 'LOW',
        automatable: true
      });
    }
    
    // Recommandations préventives
    recommendations.push({
      priority: 'MEDIUM',
      category: 'MONITORING',
      title: 'Surveillance continue de l\'intégrité',
      description: 'Mettre en place une surveillance régulière de l\'intégrité des données',
      action: 'Programmer des vérifications d\'intégrité automatiques hebdomadaires',
      impact: 'MEDIUM',
      automatable: true
    });
    
    recommendations.push({
      priority: 'LOW',
      category: 'DOCUMENTATION',
      title: 'Documentation des procédures de migration',
      description: 'Documenter les leçons apprises et les bonnes pratiques',
      action: 'Créer un guide de migration et de maintenance pour les futures versions',
      impact: 'LOW',
      automatable: false
    });
    
    this.report.recommendations = recommendations;
    
    console.log(`   📋 ${recommendations.length} recommandations générées`);
    console.log(`      - Priorité CRITICAL: ${recommendations.filter(r => r.priority === 'CRITICAL').length}`);
    console.log(`      - Priorité HIGH: ${recommendations.filter(r => r.priority === 'HIGH').length}`);
    console.log(`      - Priorité MEDIUM: ${recommendations.filter(r => r.priority === 'MEDIUM').length}`);
    console.log(`      - Priorité LOW: ${recommendations.filter(r => r.priority === 'LOW').length}`);
  }

  /**
   * Finalisation du rapport et calcul des métriques
   */
  finalizeReport() {
    const endTime = Date.now();
    this.report.performance.executionTime = endTime - this.startTime;
    this.report.performance.memoryUsage = process.memoryUsage();
    this.report.performance.queryStats = {
      totalQueries: this.queryCount,
      averageQueryTime: this.report.performance.executionTime / this.queryCount
    };
    
    // Détermination du statut global
    const successRate = this.report.summary.totalChecks > 0 ? 
      (this.report.summary.passedChecks / this.report.summary.totalChecks) * 100 : 0;
    
    if (successRate >= 95 && this.report.summary.criticalIssues.length === 0) {
      this.report.summary.status = 'PASSED';
    } else if (successRate >= 80 && this.report.summary.criticalIssues.length <= 2) {
      this.report.summary.status = 'WARNING';
    } else {
      this.report.summary.status = 'FAILED';
    }
    
    console.log('\n📊 RÉSUMÉ DE LA VÉRIFICATION:');
    console.log(`   🎯 Statut global: ${this.report.summary.status}`);
    console.log(`   ✅ Tests réussis: ${this.report.summary.passedChecks}/${this.report.summary.totalChecks} (${successRate.toFixed(2)}%)`);
    console.log(`   ❌ Tests échoués: ${this.report.summary.failedChecks}`);
    console.log(`   🚨 Problèmes critiques: ${this.report.summary.criticalIssues.length}`);
    console.log(`   ⚠️  Avertissements: ${this.report.summary.warnings.length}`);
    console.log(`   ⏱️  Temps d'exécution: ${(this.report.performance.executionTime / 1000).toFixed(2)}s`);
    console.log(`   📊 Requêtes exécutées: ${this.queryCount}`);
  }

  /**
   * Sauvegarde du rapport
   */
  async saveReport() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `post-migration-integrity-report-${timestamp}.json`;
    const filepath = path.join(__dirname, '../reports', filename);
    
    try {
      // Créer le dossier reports s'il n'existe pas
      const reportsDir = path.dirname(filepath);
      if (!fs.existsSync(reportsDir)) {
        fs.mkdirSync(reportsDir, { recursive: true });
      }
      
      fs.writeFileSync(filepath, JSON.stringify(this.report, null, 2));
      console.log(`\n💾 Rapport sauvegardé: ${filepath}`);
      
      // Créer aussi un lien vers le dernier rapport
      const latestPath = path.join(reportsDir, 'latest-integrity-report.json');
      if (fs.existsSync(latestPath)) {
        fs.unlinkSync(latestPath);
      }
      fs.symlinkSync(filename, latestPath);
      
      return filepath;
    } catch (error) {
      console.error('❌ Erreur lors de la sauvegarde du rapport:', error.message);
      return null;
    }
  }

  /**
   * Exécution complète de la vérification
   */
  async run() {
    console.log('🔍 POST-MIGRATION DATA INTEGRITY VERIFICATION');
    console.log('============================================');
    console.log(`📅 Démarré le: ${new Date().toLocaleString()}`);
    console.log(`🗄️  Base de données: ${process.env.MONGODB_URI || 'mongodb://localhost:27017/faf-test'}`);
    
    // Connexion à la base de données
    const connected = await this.connectToDatabase();
    if (!connected) {
      this.finalizeReport();
      await this.saveReport();
      return this.report;
    }
    
    try {
      // Étapes de vérification
      await this.collectBaseData();
      await this.verifyResponseToSubmissionMigration();
      await this.validateUserAccountCreation();
      await this.checkDataIntegrityAndCorruption();
      await this.validateUserSubmissionRelationships();
      await this.runRegressionTests();
      
      // Génération du rapport final
      this.generateRecommendations();
      this.finalizeReport();
      
    } catch (error) {
      console.error('❌ Erreur fatale pendant la vérification:', error);
      this.report.summary.status = 'ERROR';
      this.report.summary.criticalIssues.push({
        type: 'FATAL_ERROR',
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      });
    } finally {
      // Fermeture de la connexion
      await mongoose.connection.close();
      console.log('✅ Connexion à MongoDB fermée');
      
      // Sauvegarde du rapport
      await this.saveReport();
    }
    
    return this.report;
  }
}

// Exécution si appelé directement
if (require.main === module) {
  const checker = new PostMigrationDataIntegrityChecker();
  checker.run().then((report) => {
    console.log('\n🏁 Vérification terminée');
    
    if (report.summary.status === 'PASSED') {
      console.log('🎉 Migration validée avec succès !');
      process.exit(0);
    } else if (report.summary.status === 'WARNING') {
      console.log('⚠️  Migration partiellement validée - Vérifier les avertissements');
      process.exit(1);
    } else {
      console.log('❌ Migration échouée - Action requise');
      process.exit(2);
    }
  }).catch((error) => {
    console.error('💥 Erreur fatale:', error);
    process.exit(3);
  });
}

module.exports = PostMigrationDataIntegrityChecker;