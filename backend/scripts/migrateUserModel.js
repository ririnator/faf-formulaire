#!/usr/bin/env node

/**
 * Script de Migration - Enrichissement du modèle User
 * 
 * Ce script ajoute les nouveaux champs preferences, statistics et met à jour
 * migrationData selon les spécifications DATA-MODELS.md pour tous les utilisateurs existants.
 * 
 * Usage: node scripts/migrateUserModel.js
 */

const mongoose = require('mongoose');
const User = require('../models/User');
require('dotenv').config();

// Configuration par défaut selon DATA-MODELS.md
const DEFAULT_PREFERENCES = {
  sendTime: "18:00",
  timezone: "Europe/Paris", 
  sendDay: 5,
  reminderSettings: {
    firstReminder: true,
    secondReminder: true,
    reminderChannel: 'email'
  },
  emailTemplate: 'friendly',
  customMessage: ""
};

const DEFAULT_STATISTICS = {
  totalSubmissions: 0,
  totalContacts: 0,
  averageResponseRate: 0,
  bestResponseMonth: {
    month: null,
    rate: 0
  },
  joinedCycles: 0
};

async function connectDatabase() {
  try {
    const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/faf';
    await mongoose.connect(uri);
    console.log('✅ Connexion à MongoDB établie');
  } catch (error) {
    console.error('❌ Erreur de connexion MongoDB:', error.message);
    process.exit(1);
  }
}

async function migrateUsers() {
  try {
    console.log('🔄 Début de la migration du modèle User...');
    
    // Compter les utilisateurs existants
    const totalUsers = await User.countDocuments();
    console.log(`📊 ${totalUsers} utilisateurs trouvés`);
    
    if (totalUsers === 0) {
      console.log('ℹ️  Aucun utilisateur à migrer');
      return;
    }
    
    // Migration par batch pour éviter les problèmes de mémoire
    const batchSize = 100;
    let processed = 0;
    let migrated = 0;
    
    for (let skip = 0; skip < totalUsers; skip += batchSize) {
      const users = await User.find({})
        .skip(skip)
        .limit(batchSize)
        .exec();
      
      for (const user of users) {
        let needsSave = false;
        
        // Ajouter preferences si manquant
        if (!user.preferences) {
          user.preferences = DEFAULT_PREFERENCES;
          needsSave = true;
        } else {
          // Compléter les préférences manquantes
          Object.keys(DEFAULT_PREFERENCES).forEach(key => {
            if (user.preferences[key] === undefined) {
              user.preferences[key] = DEFAULT_PREFERENCES[key];
              needsSave = true;
            }
          });
        }
        
        // Ajouter statistics si manquant
        if (!user.statistics) {
          user.statistics = DEFAULT_STATISTICS;
          needsSave = true;
        } else {
          // Compléter les statistiques manquantes
          Object.keys(DEFAULT_STATISTICS).forEach(key => {
            if (user.statistics[key] === undefined) {
              user.statistics[key] = DEFAULT_STATISTICS[key];
              needsSave = true;
            }
          });
        }
        
        // Mettre à jour migrationData si nécessaire
        if (!user.migrationData) {
          user.migrationData = {
            source: 'registration'
          };
          needsSave = true;
        }
        
        // Sauvegarder si des changements ont été faits
        if (needsSave) {
          await user.save();
          migrated++;
        }
        
        processed++;
      }
      
      // Afficher le progrès
      const progress = Math.round((processed / totalUsers) * 100);
      console.log(`⏳ Progression: ${processed}/${totalUsers} (${progress}%) - ${migrated} migrés`);
    }
    
    console.log(`✅ Migration terminée: ${migrated}/${totalUsers} utilisateurs migrés`);
    
  } catch (error) {
    console.error('❌ Erreur lors de la migration:', error.message);
    throw error;
  }
}

async function validateMigration() {
  try {
    console.log('🔍 Validation de la migration...');
    
    // Vérifier que tous les users ont les nouveaux champs
    const usersWithoutPreferences = await User.countDocuments({
      preferences: { $exists: false }
    });
    
    const usersWithoutStatistics = await User.countDocuments({
      statistics: { $exists: false }
    });
    
    const usersWithoutMigrationData = await User.countDocuments({
      migrationData: { $exists: false }
    });
    
    console.log(`📊 Validation des résultats:`);
    console.log(`   - Utilisateurs sans preferences: ${usersWithoutPreferences}`);
    console.log(`   - Utilisateurs sans statistics: ${usersWithoutStatistics}`);
    console.log(`   - Utilisateurs sans migrationData: ${usersWithoutMigrationData}`);
    
    if (usersWithoutPreferences === 0 && usersWithoutStatistics === 0 && usersWithoutMigrationData === 0) {
      console.log('✅ Validation réussie - Tous les utilisateurs ont été migrés');
    } else {
      console.log('⚠️  Avertissement - Certains utilisateurs n\'ont pas été complètement migrés');
    }
    
  } catch (error) {
    console.error('❌ Erreur lors de la validation:', error.message);
    throw error;
  }
}

async function createIndexes() {
  try {
    console.log('🔧 Création des nouveaux index...');
    
    // Créer les index en background pour éviter le blocage
    await User.collection.createIndex(
      { 'preferences.sendDay': 1, 'preferences.timezone': 1 }, 
      { background: true, name: 'preferences_sendDay_timezone' }
    );
    
    await User.collection.createIndex(
      { 'statistics.totalSubmissions': -1 }, 
      { background: true, name: 'statistics_totalSubmissions' }
    );
    
    await User.collection.createIndex(
      { 'statistics.averageResponseRate': -1 }, 
      { background: true, name: 'statistics_averageResponseRate' }
    );
    
    await User.collection.createIndex(
      { 'migrationData.source': 1 }, 
      { background: true, name: 'migrationData_source' }
    );
    
    console.log('✅ Index créés avec succès');
    
  } catch (error) {
    console.error('❌ Erreur lors de la création des index:', error.message);
    // Ne pas faire échouer la migration si les index échouent
    console.log('⚠️  Continuant malgré l\'erreur d\'index...');
  }
}

async function main() {
  try {
    console.log('🚀 Démarrage de la migration du modèle User');
    console.log('📋 Ajout des champs: preferences, statistics, migrationData');
    console.log('📚 Selon les spécifications DATA-MODELS.md\n');
    
    await connectDatabase();
    await migrateUsers();
    await validateMigration();
    await createIndexes();
    
    console.log('\n🎉 Migration terminée avec succès!');
    console.log('ℹ️  Les utilisateurs existants ont maintenant:');
    console.log('   - Préférences de notification configurées');
    console.log('   - Statistiques d\'utilisation initialisées');
    console.log('   - Données de migration mises à jour');
    console.log('   - Nouveaux index de performance créés');
    
  } catch (error) {
    console.error('\n💥 Échec de la migration:', error.message);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Connexion MongoDB fermée');
  }
}

// Gestion des signaux pour un arrêt propre
process.on('SIGINT', async () => {
  console.log('\n⏹️  Arrêt demandé...');
  await mongoose.disconnect();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n⏹️  Arrêt forcé...');
  await mongoose.disconnect();
  process.exit(0);
});

// Exécuter la migration
if (require.main === module) {
  main();
}

module.exports = { migrateUsers, validateMigration, createIndexes };