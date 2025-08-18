#!/usr/bin/env node

/**
 * GENERATEUR DE DONNEES DE TEST POUR MIGRATION FAF
 * 
 * Ce script génère des données de test pour simuler un scénario
 * de migration FAF v1 → v2 avec des données Response et User/Submission.
 */

const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcrypt');

// Configuration de test
require('dotenv').config({ path: path.resolve(__dirname, '../.env.test') });

// Modèles
const Response = require('../models/Response');
const Submission = require('../models/Submission');
const User = require('../models/User');

class TestDataGenerator {
  constructor() {
    this.testData = {
      names: ['alice', 'bob', 'charlie', 'david', 'eve', 'riri', 'testadmin'],
      months: ['2024-01', '2024-02', '2024-03', '2024-04', '2024-05'],
      questions: [
        'Quel est ton plat préféré?',
        'Où aimerais-tu voyager?',
        'Quel est ton hobby?',
        'Ton film favori?',
        'Une chose qui te rend heureux?'
      ],
      answers: [
        'Pizza', 'Japon', 'Lecture', 'Inception', 'Les amis',
        'Pasta', 'Italie', 'Football', 'Avatar', 'La musique',
        'Sushi', 'Canada', 'Yoga', 'Titanic', 'La nature',
        'Burger', 'Australie', 'Gaming', 'Matrix', 'Le sport',
        'Tacos', 'Islande', 'Photo', 'Pulp Fiction', 'La famille'
      ]
    };
  }

  async connectToDatabase() {
    try {
      const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/faf-test';
      await mongoose.connect(mongoUri);
      console.log('✅ Connexion à MongoDB établie');
      console.log(`📍 Base de données: ${mongoose.connection.db.databaseName}`);
      return true;
    } catch (error) {
      console.error('❌ Erreur de connexion à MongoDB:', error.message);
      return false;
    }
  }

  async cleanDatabase() {
    console.log('🧹 Nettoyage de la base de données...');
    await Response.deleteMany({});
    await Submission.deleteMany({});
    await User.deleteMany({});
    console.log('   ✅ Base de données nettoyée');
  }

  async generateLegacyResponses() {
    console.log('📝 Génération des Response legacy...');
    
    const responses = [];
    const usedTokens = new Set();
    
    for (const name of this.testData.names) {
      for (const month of this.testData.months) {
        // 80% de chance de créer une response pour ce nom/mois
        if (Math.random() > 0.2) {
          
          // Vérifier la contrainte admin unique par mois
          const isAdmin = name === 'riri' || name === 'testadmin';
          if (isAdmin) {
            const existingAdminResponse = responses.find(r => r.isAdmin && r.month === month);
            if (existingAdminResponse) {
              continue; // Skip pour éviter la violation de contrainte unique
            }
          }
          // Génération d'un token unique
          let token;
          do {
            token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
          } while (usedTokens.has(token));
          usedTokens.add(token);

          const responseData = [];
          for (let i = 0; i < this.testData.questions.length; i++) {
            responseData.push({
              question: this.testData.questions[i],
              answer: this.testData.answers[Math.floor(Math.random() * this.testData.answers.length)]
            });
          }

          const response = new Response({
            name: name,
            responses: responseData,
            month: month,
            isAdmin: name === 'riri' || name === 'testadmin',
            token: token,
            authMethod: 'token',
            createdAt: new Date(month + '-15T10:00:00Z')
          });

          responses.push(response);
        }
      }
    }
    
    await Response.insertMany(responses);
    console.log(`   ✅ ${responses.length} Response legacy créées`);
    return responses.length;
  }

  async generateMigratedUsers() {
    console.log('👤 Génération des User migrés...');
    
    const users = [];
    
    // Récupérer les noms uniques des Response
    const uniqueNames = await Response.distinct('name');
    
    for (const name of uniqueNames) {
      // Générer un username unique à partir du nom
      let username = name.toLowerCase().replace(/[^a-z0-9]/g, '');
      let counter = 1;
      let originalUsername = username;
      
      // Vérifier l'unicité
      while (users.find(u => u.username === username)) {
        username = `${originalUsername}${counter}`;
        counter++;
      }

      // Détermine si c'est un admin
      const isAdmin = name === 'riri' || name === 'testadmin';

      const user = new User({
        username: username,
        email: `${username}@test.com`,
        password: await bcrypt.hash('password123', 10),
        role: isAdmin ? 'admin' : 'user',
        profile: {
          firstName: name.charAt(0).toUpperCase() + name.slice(1),
          lastName: 'Test'
        },
        metadata: {
          isActive: true,
          emailVerified: true,
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

      users.push(user);
    }
    
    await User.insertMany(users);
    console.log(`   ✅ ${users.length} User migrés créés`);
    return users;
  }

  async generateMigratedSubmissions(users) {
    console.log('📄 Génération des Submission migrées...');
    
    const submissions = [];
    
    for (const user of users) {
      // Récupérer les Response correspondantes
      const userResponses = await Response.find({ 
        name: user.migrationData.legacyName 
      });
      
      for (const response of userResponses) {
        // Convertir Response vers Submission
        const submissionResponses = response.responses.map((resp, index) => ({
          questionId: `q_${index + 1}`,
          type: 'text',
          answer: resp.answer
        }));

        const submission = new Submission({
          userId: user._id,
          month: response.month,
          responses: submissionResponses,
          freeText: Math.random() > 0.7 ? 'Commentaire libre additionnel' : undefined,
          completionRate: Math.floor(80 + Math.random() * 20), // 80-100%
          isComplete: true,
          submittedAt: response.createdAt,
          formVersion: 'v1'
        });

        submissions.push(submission);
        
        // Mettre à jour les statistiques utilisateur
        user.statistics.totalSubmissions++;
        user.metadata.responseCount++;
      }
      
      await user.save();
    }
    
    await Submission.insertMany(submissions);
    console.log(`   ✅ ${submissions.length} Submission migrées créées`);
    return submissions.length;
  }

  async generateIncompleteData() {
    console.log('⚠️  Génération de données incomplètes pour les tests...');
    
    // 1. Response orpheline (sans User correspondant)
    const orphanResponse = new Response({
      name: 'orphan_user',
      responses: [{ question: 'Test?', answer: 'Test' }],
      month: '2024-06',
      isAdmin: false,
      token: 'orphan_token_123',
      authMethod: 'token',
      createdAt: new Date()
    });
    await orphanResponse.save();
    
    // 2. User sans Submission (mais avec Response legacy)
    const userWithoutSubmission = new User({
      username: 'no_submission_user',
      email: 'nosubmission@test.com',
      password: await bcrypt.hash('password123', 10),
      role: 'user',
      migrationData: {
        legacyName: 'user_with_no_submission',
        migratedAt: new Date(),
        source: 'migration'
      }
    });
    await userWithoutSubmission.save();
    
    const responseWithoutSubmission = new Response({
      name: 'user_with_no_submission',
      responses: [{ question: 'Test?', answer: 'Test' }],
      month: '2024-07',
      isAdmin: false,
      token: 'no_submission_token',
      authMethod: 'token',
      createdAt: new Date()
    });
    await responseWithoutSubmission.save();
    
    // 3. Submission orpheline (sans User)
    const orphanSubmission = new Submission({
      userId: new mongoose.Types.ObjectId(), // ID inexistant
      month: '2024-08',
      responses: [{ questionId: 'q1', type: 'text', answer: 'Test orphan' }],
      completionRate: 90,
      isComplete: true,
      submittedAt: new Date()
    });
    await orphanSubmission.save();
    
    // 4. Données corrompues
    const corruptedResponse = new Response({
      name: null, // Nom manquant
      responses: 'not_an_array', // Format incorrect
      month: 'invalid-format', // Format mois incorrect
      isAdmin: 'yes', // Booléen incorrect
      token: 'corrupted_token',
      authMethod: 'invalid', // AuthMethod invalide
      createdAt: 'not_a_date' // Date invalide
    });
    
    try {
      await corruptedResponse.save();
    } catch (error) {
      // On s'attend à ce que ça échoue à cause des validations
      console.log('   ⚠️  Données corrompues intentionnellement rejetées par les validations');
    }
    
    console.log('   ✅ Données incomplètes créées pour les tests');
  }

  async generateStatistics() {
    console.log('📊 Génération des statistiques finales...');
    
    const stats = {
      responses: await Response.countDocuments(),
      submissions: await Submission.countDocuments(),
      users: await User.countDocuments(),
      legacyResponses: await Response.countDocuments({ authMethod: 'token' }),
      migratedUsers: await User.countDocuments({ 'migrationData.source': 'migration' }),
      adminUsers: await User.countDocuments({ role: 'admin' }),
      months: await Response.distinct('month'),
      uniqueNames: await Response.distinct('name')
    };
    
    console.log('   📈 Statistiques générées:');
    console.log(`      - Response total: ${stats.responses}`);
    console.log(`      - Response legacy: ${stats.legacyResponses}`);
    console.log(`      - Submission total: ${stats.submissions}`);
    console.log(`      - User total: ${stats.users}`);
    console.log(`      - User migrés: ${stats.migratedUsers}`);
    console.log(`      - User admin: ${stats.adminUsers}`);
    console.log(`      - Mois couverts: ${stats.months.length}`);
    console.log(`      - Noms uniques: ${stats.uniqueNames.length}`);
    
    return stats;
  }

  async run() {
    console.log('🏗️  GENERATEUR DE DONNEES DE TEST FAF MIGRATION');
    console.log('===============================================');
    console.log(`📅 Démarré le: ${new Date().toLocaleString()}`);
    
    // Connexion à la base de données
    const connected = await this.connectToDatabase();
    if (!connected) {
      return false;
    }
    
    try {
      // Nettoyage
      await this.cleanDatabase();
      
      // Génération des données legacy
      await this.generateLegacyResponses();
      
      // Génération des données migrées
      const users = await this.generateMigratedUsers();
      await this.generateMigratedSubmissions(users);
      
      // Génération de cas d'erreur
      await this.generateIncompleteData();
      
      // Statistiques finales
      await this.generateStatistics();
      
      console.log('\n✅ Génération des données de test terminée avec succès!');
      return true;
      
    } catch (error) {
      console.error('❌ Erreur pendant la génération:', error);
      return false;
    } finally {
      await mongoose.connection.close();
      console.log('✅ Connexion à MongoDB fermée');
    }
  }
}

// Exécution si appelé directement
if (require.main === module) {
  const generator = new TestDataGenerator();
  generator.run().then((success) => {
    if (success) {
      console.log('🎉 Données de test prêtes pour la vérification!');
      process.exit(0);
    } else {
      console.log('❌ Échec de la génération des données de test');
      process.exit(1);
    }
  }).catch((error) => {
    console.error('💥 Erreur fatale:', error);
    process.exit(2);
  });
}

module.exports = TestDataGenerator;