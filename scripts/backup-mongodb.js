#!/usr/bin/env node

/**
 * Script de backup MongoDB
 *
 * Sauvegarde toutes les réponses MongoDB dans un fichier JSON
 * avant la migration vers Supabase
 *
 * Usage:
 *   node scripts/backup-mongodb.js
 *
 * Environnement requis:
 *   - MONGODB_URI: URI de connexion MongoDB
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');
const fs = require('fs');
const path = require('path');

// Configuration
const MONGODB_URI = process.env.MONGODB_URI;
const BACKUP_DIR = path.join(__dirname, '../backups');
const BACKUP_FILE = path.join(BACKUP_DIR, `mongodb-backup-${Date.now()}.json`);

/**
 * Sauvegarde MongoDB dans un fichier JSON
 */
async function backupMongoDB() {
  console.log('🚀 Début du backup MongoDB...\n');

  // Validation des variables d'environnement
  if (!MONGODB_URI) {
    console.error('❌ Erreur: MONGODB_URI non défini');
    console.error('   Définir: export MONGODB_URI="mongodb+srv://..."');
    process.exit(1);
  }

  let client;

  try {
    // 1. Connexion MongoDB
    console.log('📡 Connexion à MongoDB...');
    client = await MongoClient.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('✅ Connexion réussie\n');

    // 2. Récupération des données
    const db = client.db();
    console.log('📥 Récupération des réponses...');

    const responses = await db.collection('responses')
      .find({})
      .sort({ createdAt: 1 }) // Tri par date de création
      .toArray();

    console.log(`✅ ${responses.length} réponses récupérées\n`);

    // 3. Analyse des données
    console.log('📊 Statistiques:');
    const adminResponses = responses.filter(r => r.isAdmin === true);
    const userResponses = responses.filter(r => r.isAdmin !== true);
    const withToken = responses.filter(r => r.token);
    const months = [...new Set(responses.map(r => r.month))];

    console.log(`   - Réponses admin: ${adminResponses.length}`);
    console.log(`   - Réponses utilisateurs: ${userResponses.length}`);
    console.log(`   - Réponses avec token: ${withToken.length}`);
    console.log(`   - Mois uniques: ${months.length} (${months.join(', ')})`);

    // 4. Validation des données
    console.log('\n🔍 Validation des données:');
    let validCount = 0;
    let issues = [];

    for (const response of responses) {
      const errors = [];

      // Validation des champs requis
      if (!response.name) errors.push('name manquant');
      if (!response.responses || !Array.isArray(response.responses)) {
        errors.push('responses invalide');
      }
      if (!response.month) errors.push('month manquant');
      if (!response.createdAt) errors.push('createdAt manquant');

      // Validation du format token
      if (response.token && typeof response.token !== 'string') {
        errors.push('token format invalide');
      }

      if (errors.length > 0) {
        issues.push({
          id: response._id,
          name: response.name,
          errors
        });
      } else {
        validCount++;
      }
    }

    console.log(`   ✅ Réponses valides: ${validCount}/${responses.length}`);
    if (issues.length > 0) {
      console.log(`   ⚠️  Réponses avec problèmes: ${issues.length}`);
      issues.forEach(issue => {
        console.log(`      - ${issue.name} (${issue.id}): ${issue.errors.join(', ')}`);
      });
    }

    // 5. Création du dossier backup
    if (!fs.existsSync(BACKUP_DIR)) {
      fs.mkdirSync(BACKUP_DIR, { recursive: true });
      console.log(`\n📁 Dossier créé: ${BACKUP_DIR}`);
    }

    // 6. Sauvegarde dans un fichier JSON
    const backupData = {
      metadata: {
        date: new Date().toISOString(),
        mongodbUri: MONGODB_URI.replace(/\/\/[^:]+:[^@]+@/, '//***:***@'), // Masquer credentials
        totalResponses: responses.length,
        adminResponses: adminResponses.length,
        userResponses: userResponses.length,
        withToken: withToken.length,
        months: months,
        validCount: validCount,
        issues: issues.length
      },
      responses: responses
    };

    fs.writeFileSync(BACKUP_FILE, JSON.stringify(backupData, null, 2));
    console.log(`\n💾 Backup sauvegardé: ${BACKUP_FILE}`);

    // Afficher la taille du fichier
    const stats = fs.statSync(BACKUP_FILE);
    const fileSizeInMB = (stats.size / (1024 * 1024)).toFixed(2);
    console.log(`   Taille: ${fileSizeInMB} MB`);

    // 7. Résumé
    console.log('\n✅ Backup terminé avec succès!');
    console.log('\n📋 Résumé:');
    console.log(`   - Fichier: ${path.basename(BACKUP_FILE)}`);
    console.log(`   - Total réponses: ${responses.length}`);
    console.log(`   - Format: JSON avec metadata`);
    console.log(`   - Statut: Prêt pour migration\n`);

    return {
      success: true,
      file: BACKUP_FILE,
      count: responses.length
    };

  } catch (error) {
    console.error('\n❌ Erreur lors du backup:');
    console.error(error.message);

    if (error.name === 'MongoNetworkError') {
      console.error('\n💡 Vérifier:');
      console.error('   - La connexion Internet');
      console.error('   - L\'URI MongoDB dans .env');
      console.error('   - Les credentials MongoDB');
    }

    throw error;

  } finally {
    // Fermeture de la connexion
    if (client) {
      await client.close();
      console.log('🔌 Connexion MongoDB fermée');
    }
  }
}

// Exécution du script
if (require.main === module) {
  backupMongoDB()
    .then(() => {
      console.log('\n✨ Backup réussi!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Backup échoué:', error.message);
      process.exit(1);
    });
}

module.exports = { backupMongoDB };
