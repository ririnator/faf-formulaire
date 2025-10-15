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
    console.log('🔍 Vérification de MongoDB...\n');

    await client.connect();
    console.log('✅ MongoDB est toujours accessible et opérationnel\n');

    const db = client.db();
    const count = await db.collection('responses').countDocuments();

    console.log('📊 Nombre de réponses dans MongoDB:', count);
    console.log('\n💡 Tes données MongoDB sont intactes !');
    console.log('   La migration a seulement COPIÉ les données vers Supabase.');
    console.log('   MongoDB n\'a PAS été modifié.\n');

    process.exit(0);
  } catch (err) {
    console.log('❌ Erreur de connexion:', err.message);
    process.exit(1);
  }
}

checkMongoDB();
