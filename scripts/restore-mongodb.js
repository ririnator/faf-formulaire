#!/usr/bin/env node

const { MongoClient } = require('mongodb');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const uri = process.env.MONGODB_URI;

if (!uri) {
  console.log('❌ MONGODB_URI non défini dans .env');
  process.exit(1);
}

const client = new MongoClient(uri);

async function restoreMongoDB() {
  try {
    console.log('🔄 Restauration MongoDB depuis le backup JSON');
    console.log('='.repeat(50), '\n');

    // 1. Trouver le backup le plus récent
    const backupDir = path.join(__dirname, '../backups');
    const files = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('mongodb-backup-') && f.endsWith('.json'))
      .sort()
      .reverse();

    if (files.length === 0) {
      console.log('❌ Aucun backup trouvé dans /backups/');
      process.exit(1);
    }

    const backupFile = path.join(backupDir, files[0]);
    console.log('📁 Utilisation du backup:', files[0]);

    // 2. Charger le backup
    const backupData = JSON.parse(fs.readFileSync(backupFile, 'utf8'));
    const responses = backupData.responses || [];

    console.log('📦 Backup chargé:');
    console.log('   - Date:', backupData.metadata?.date || 'N/A');
    console.log('   - Total réponses:', responses.length);
    console.log('   - Admin:', backupData.metadata?.adminResponses || 0);
    console.log('   - Users:', backupData.metadata?.userResponses || 0);
    console.log('');

    // 3. Connexion MongoDB
    await client.connect();
    const db = client.db();
    console.log('✅ Connecté à MongoDB:', db.databaseName, '\n');

    // 4. Vérifier les données existantes
    const existingCount = await db.collection('responses').countDocuments();
    console.log('📊 État actuel de MongoDB:');
    console.log('   - Réponses existantes:', existingCount);

    if (existingCount > 0) {
      console.log('\n⚠️  MongoDB contient déjà des données !');
      console.log('   Options:');
      console.log('   1. Fusionner (ajouter le backup aux données existantes)');
      console.log('   2. Remplacer (supprimer l\'existant et restaurer le backup)');
      console.log('   3. Annuler\n');

      // Pour l'instant, on va fusionner par défaut (safe)
      console.log('🔧 Mode: FUSION (ajout sans suppression)');
      console.log('   Les données existantes seront CONSERVÉES\n');
    }

    // 5. Restauration
    console.log('📤 Restauration des réponses...\n');

    let inserted = 0;
    let skipped = 0;
    let errors = 0;

    for (const response of responses) {
      try {
        // Préparer le document pour MongoDB
        const doc = {
          name: response.name,
          responses: response.responses,
          month: response.month,
          isAdmin: response.isAdmin || false,
          token: response.token || null,
          createdAt: new Date(response.createdAt)
        };

        // Vérifier si le document existe déjà (par _id MongoDB si présent, sinon par token unique)
        let exists = null;

        if (response._id) {
          // Vérifier par _id original
          exists = await db.collection('responses').findOne({ _id: response._id });
        } else if (doc.token) {
          // Vérifier par token unique
          exists = await db.collection('responses').findOne({ token: doc.token });
        }

        if (exists) {
          skipped++;
          continue;
        }

        // Insérer
        await db.collection('responses').insertOne(doc);
        inserted++;

        if (inserted % 10 === 0) {
          console.log(`   ✅ ${inserted} réponses restaurées...`);
        }

      } catch (error) {
        errors++;
        console.log(`   ❌ Erreur pour ${response.name}:`, error.message);
      }
    }

    // 6. Rapport final
    console.log('\n' + '='.repeat(50));
    console.log('📊 RAPPORT DE RESTAURATION');
    console.log('='.repeat(50), '\n');

    console.log('✅ Insérées:', inserted);
    console.log('⏭️  Ignorées (doublons):', skipped);
    console.log('❌ Erreurs:', errors);
    console.log('📦 Total traité:', responses.length);

    const finalCount = await db.collection('responses').countDocuments();
    console.log('\n📊 Total dans MongoDB maintenant:', finalCount);

    console.log('\n💡 Notes importantes:');
    console.log('   - Supabase n\'a PAS été modifié');
    console.log('   - Les données existantes ont été conservées');
    console.log('   - Le backup JSON reste intact');

    console.log('\n✨ Restauration terminée!\n');

    await client.close();
    process.exit(0);

  } catch (err) {
    console.log('\n❌ Erreur:', err.message);
    console.log(err.stack);
    await client.close();
    process.exit(1);
  }
}

restoreMongoDB();
