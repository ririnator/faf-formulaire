#!/usr/bin/env node

const { MongoClient } = require('mongodb');
const crypto = require('crypto');
require('dotenv').config();

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function fixNullTokens() {
  try {
    console.log('🔧 Correction des tokens null');
    console.log('='.repeat(50), '\n');

    await client.connect();
    const db = client.db();
    const collection = db.collection('responses');

    // Trouver toutes les réponses avec token: null ET isAdmin: false
    const nullTokenResponses = await collection.find({
      token: null,
      isAdmin: false
    }).toArray();

    console.log('📊 Réponses avec token: null (non-admin):', nullTokenResponses.length);

    if (nullTokenResponses.length === 0) {
      console.log('✅ Aucune correction nécessaire\n');
      await client.close();
      return;
    }

    console.log('\n🔨 Génération de tokens uniques...\n');

    let updated = 0;
    for (const response of nullTokenResponses) {
      // Générer un token unique
      const token = crypto.randomBytes(32).toString('hex');

      await collection.updateOne(
        { _id: response._id },
        { $set: { token: token } }
      );

      updated++;
      if (updated % 10 === 0) {
        console.log(`   ✅ ${updated} tokens générés...`);
      }
    }

    console.log(`\n✅ ${updated} tokens générés au total`);

    // Vérifier qu'il ne reste plus de null (sauf admins)
    const remaining = await collection.countDocuments({ token: null, isAdmin: false });
    console.log('📊 Tokens null restants (non-admin):', remaining);

    console.log('\n💡 Note: Les réponses admin conservent token: null (normal)\n');

    await client.close();
    process.exit(0);

  } catch (err) {
    console.log('\n❌ Erreur:', err.message);
    await client.close();
    process.exit(1);
  }
}

fixNullTokens();
