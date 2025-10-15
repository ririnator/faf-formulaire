#!/usr/bin/env node

const { MongoClient } = require('mongodb');
require('dotenv').config();

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

async function recreateIndexes() {
  try {
    console.log('🔧 Recréation des index MongoDB');
    console.log('='.repeat(50), '\n');

    await client.connect();
    const db = client.db();
    const collection = db.collection('responses');

    console.log('✅ Connecté à MongoDB:', db.databaseName, '\n');

    // 1. Lister les index existants
    console.log('📋 Index actuels:');
    const existingIndexes = await collection.indexes();
    for (const idx of existingIndexes) {
      console.log(`   - ${idx.name}:`, JSON.stringify(idx.key));
    }
    console.log('');

    // 2. Créer les nouveaux index
    console.log('🔨 Création des nouveaux index...\n');

    // Index 1: Token (UNIQUE mais seulement pour les tokens non-null)
    try {
      await collection.createIndex(
        { token: 1 },
        {
          name: 'token_1_unique',
          unique: true,
          sparse: true // Ignore les documents avec token: null
        }
      );
      console.log('   ✅ Index "token_1_unique" créé (unique, sparse)');
    } catch (e) {
      console.log('   ⚠️  Index "token_1_unique":', e.message);
    }

    // Index 2: Month + isAdmin (UNIQUE pour éviter doublons admin par mois)
    try {
      await collection.createIndex(
        { month: 1, isAdmin: 1 },
        {
          name: 'month_1_isAdmin_1_partial',
          unique: true,
          partialFilterExpression: { isAdmin: true } // Unique seulement pour admins
        }
      );
      console.log('   ✅ Index "month_1_isAdmin_1_partial" créé (unique pour admins)');
    } catch (e) {
      console.log('   ⚠️  Index "month_1_isAdmin_1_partial":', e.message);
    }

    // Index 3: CreatedAt (pour trier par date)
    try {
      await collection.createIndex(
        { createdAt: -1 },
        { name: 'createdAt_-1' }
      );
      console.log('   ✅ Index "createdAt_-1" créé');
    } catch (e) {
      console.log('   ⚠️  Index "createdAt_-1":', e.message);
    }

    // Index 4: Month (pour recherche par mois)
    try {
      await collection.createIndex(
        { month: 1 },
        { name: 'month_1' }
      );
      console.log('   ✅ Index "month_1" créé');
    } catch (e) {
      console.log('   ⚠️  Index "month_1":', e.message);
    }

    // Index 5: Name (pour recherche par nom)
    try {
      await collection.createIndex(
        { name: 1 },
        { name: 'name_1' }
      );
      console.log('   ✅ Index "name_1" créé');
    } catch (e) {
      console.log('   ⚠️  Index "name_1":', e.message);
    }

    // 3. Vérifier les index finaux
    console.log('\n📋 Index après recréation:');
    const finalIndexes = await collection.indexes();
    for (const idx of finalIndexes) {
      const details = [];
      if (idx.unique) details.push('unique');
      if (idx.sparse) details.push('sparse');
      if (idx.partialFilterExpression) details.push('partial');

      const detailsStr = details.length > 0 ? ` (${details.join(', ')})` : '';
      console.log(`   - ${idx.name}:`, JSON.stringify(idx.key) + detailsStr);
    }

    console.log('\n💡 Améliorations:');
    console.log('   ✅ Token: unique seulement pour les tokens non-null (sparse)');
    console.log('   ✅ Month+isAdmin: unique seulement pour les admins (partial)');
    console.log('   ✅ Performance: index sur createdAt, month, name');
    console.log('   ✅ Permet plusieurs réponses avec token: null');
    console.log('   ✅ Permet plusieurs utilisateurs par mois');

    console.log('\n✨ Index recréés avec succès!\n');

    await client.close();
    process.exit(0);

  } catch (err) {
    console.log('\n❌ Erreur:', err.message);
    console.log(err.stack);
    await client.close();
    process.exit(1);
  }
}

recreateIndexes();
