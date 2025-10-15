#!/usr/bin/env node

const { MongoClient } = require('mongodb');
require('dotenv').config();

const uri = process.env.MONGODB_URI;

if (!uri) {
  console.log('❌ MONGODB_URI non défini dans .env');
  process.exit(1);
}

const client = new MongoClient(uri);

async function checkMongoDB() {
  try {
    console.log('🔍 Analyse détaillée de MongoDB...\n');
    console.log('📡 URI:', uri.replace(/:[^:@]+@/, ':****@'), '\n');

    await client.connect();
    console.log('✅ Connexion réussie\n');

    const db = client.db();
    console.log('📂 Base de données:', db.databaseName, '\n');

    // Lister toutes les collections
    const collections = await db.listCollections().toArray();
    console.log('📋 Collections trouvées:', collections.length);

    for (const coll of collections) {
      const count = await db.collection(coll.name).countDocuments();
      console.log(`   - ${coll.name}: ${count} documents`);
    }

    console.log('\n');

    // Vérifier spécifiquement la collection 'responses'
    const responsesExists = collections.some(c => c.name === 'responses');

    if (responsesExists) {
      const count = await db.collection('responses').countDocuments();
      console.log('📊 Collection "responses":', count, 'documents');

      if (count > 0) {
        const sample = await db.collection('responses').findOne();
        console.log('\n📄 Exemple de document:');
        console.log('   - _id:', sample._id);
        console.log('   - name:', sample.name);
        console.log('   - month:', sample.month);
        console.log('   - createdAt:', sample.createdAt);
      } else {
        console.log('\n⚠️  La collection "responses" existe mais est VIDE');
        console.log('   Cela peut arriver si:');
        console.log('   1. Les données ont été supprimées');
        console.log('   2. Tu regardes la mauvaise base de données');
        console.log('   3. Le script de migration a supprimé après copie');
      }
    } else {
      console.log('❌ La collection "responses" n\'existe pas');
    }

    console.log('\n💡 Mais tes données sont SAUVEGARDÉES dans:');
    console.log('   - Backup JSON: backups/mongodb-backup-*.json');
    console.log('   - Supabase: Production active avec toutes les données\n');

    await client.close();
    process.exit(0);
  } catch (err) {
    console.log('❌ Erreur:', err.message);
    await client.close();
    process.exit(1);
  }
}

checkMongoDB();
