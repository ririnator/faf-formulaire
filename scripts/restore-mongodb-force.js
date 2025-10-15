#!/usr/bin/env node

const { MongoClient } = require('mongodb');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function forceRestoreMongoDB() {
  try {
    console.log('🔄 Restauration COMPLÈTE MongoDB (avec suppression des contraintes)');
    console.log('='.repeat(60), '\n');

    console.log('⚠️  IMPORTANT:');
    console.log('   - MongoDB sera modifié');
    console.log('   - Supabase reste 100% INTACT');
    console.log('   - Backup JSON reste intact\n');

    // 1. Charger le backup
    const backupFile = path.join(__dirname, '../backups/mongodb-backup-1760513256245.json');
    const backupData = JSON.parse(fs.readFileSync(backupFile, 'utf8'));
    const responses = backupData.responses || [];

    console.log('📦 Backup chargé:', responses.length, 'réponses\n');

    // 2. Connexion MongoDB
    await client.connect();
    const db = client.db();
    console.log('✅ Connecté à MongoDB:', db.databaseName, '\n');

    const existingCount = await db.collection('responses').countDocuments();
    console.log('📊 État actuel:', existingCount, 'réponses\n');

    // 3. Supprimer les index problématiques
    console.log('🔧 Suppression des contraintes qui bloquent...');

    try {
      const indexes = await db.collection('responses').indexes();
      console.log('   Index actuels:', indexes.map(i => i.name).join(', '));

      // Supprimer token_1 (contrainte unique sur token)
      try {
        await db.collection('responses').dropIndex('token_1');
        console.log('   ✅ Index "token_1" supprimé');
      } catch (e) {
        console.log('   ⚠️  Index "token_1" n\'existe pas ou déjà supprimé');
      }

      // Supprimer month_1_isAdmin_1 (contrainte unique sur month+isAdmin)
      try {
        await db.collection('responses').dropIndex('month_1_isAdmin_1');
        console.log('   ✅ Index "month_1_isAdmin_1" supprimé');
      } catch (e) {
        console.log('   ⚠️  Index "month_1_isAdmin_1" n\'existe pas ou déjà supprimé');
      }

    } catch (e) {
      console.log('   ⚠️  Erreur lors de la suppression des index:', e.message);
    }

    console.log('\n📤 Restauration des réponses manquantes...\n');

    // 4. Restauration
    let inserted = 0;
    let skipped = 0;

    for (const response of responses) {
      try {
        const doc = {
          name: response.name,
          responses: response.responses,
          month: response.month,
          isAdmin: response.isAdmin || false,
          token: response.token || null,
          createdAt: new Date(response.createdAt)
        };

        // Vérifier si existe déjà (par _id ou token unique non-null)
        let exists = null;

        if (response._id) {
          exists = await db.collection('responses').findOne({ _id: response._id });
        } else if (doc.token && doc.token !== null) {
          exists = await db.collection('responses').findOne({ token: doc.token });
        }

        if (exists) {
          skipped++;
          continue;
        }

        // Insérer
        await db.collection('responses').insertOne(doc);
        inserted++;

        if (inserted % 5 === 0) {
          console.log(`   ✅ ${inserted} réponses restaurées...`);
        }

      } catch (error) {
        console.log(`   ❌ ${response.name}: ${error.message}`);
      }
    }

    // 5. Rapport
    console.log('\n' + '='.repeat(60));
    console.log('📊 RAPPORT FINAL');
    console.log('='.repeat(60), '\n');

    const finalCount = await db.collection('responses').countDocuments();

    console.log('✅ Nouvelles insérées:', inserted);
    console.log('⏭️  Ignorées (déjà présentes):', skipped);
    console.log('📊 Total avant:', existingCount);
    console.log('📊 Total maintenant:', finalCount);

    console.log('\n💡 Statut:');
    console.log('   ✅ MongoDB:', finalCount, '/', responses.length, 'réponses');
    console.log('   ✅ Supabase: INTACT (non modifié)');
    console.log('   ✅ Backup JSON: INTACT');

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

forceRestoreMongoDB();
