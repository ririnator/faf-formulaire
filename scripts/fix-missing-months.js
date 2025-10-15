#!/usr/bin/env node

/**
 * Script de correction des réponses MongoDB sans champ "month"
 *
 * Ajoute le champ month basé sur createdAt - 1 mois
 * Ex: createdAt = 2025-10-15 → month = "2025-09"
 *
 * Usage:
 *   node scripts/fix-missing-months.js
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI;

/**
 * Calculer le mois précédent (n-1) depuis une date
 */
function getPreviousMonth(date) {
  const d = new Date(date);

  // Reculer d'un mois
  d.setMonth(d.getMonth() - 1);

  // Format YYYY-MM
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');

  return `${year}-${month}`;
}

/**
 * Corriger les réponses sans month
 */
async function fixMissingMonths() {
  console.log('🔧 Correction des réponses sans champ "month"');
  console.log('='.repeat(50));
  console.log('');

  // Validation
  if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI non défini dans .env');
    process.exit(1);
  }

  let client;

  try {
    // 1. Connexion MongoDB
    console.log('📡 Connexion à MongoDB...');
    client = await MongoClient.connect(MONGODB_URI);
    console.log('✅ Connexion réussie\n');

    const db = client.db();
    const collection = db.collection('responses');

    // 2. Trouver les réponses sans month
    console.log('🔍 Recherche des réponses sans month...');
    const responsesWithoutMonth = await collection
      .find({
        $or: [
          { month: { $exists: false } },
          { month: null },
          { month: '' }
        ]
      })
      .toArray();

    console.log(`   Trouvées: ${responsesWithoutMonth.length} réponses\n`);

    if (responsesWithoutMonth.length === 0) {
      console.log('✅ Aucune réponse à corriger!');
      return { success: true, fixed: 0 };
    }

    // 3. Afficher les réponses à corriger
    console.log('📋 Réponses à corriger:');
    responsesWithoutMonth.forEach((resp, index) => {
      const createdAt = resp.createdAt ? new Date(resp.createdAt).toISOString().slice(0, 10) : 'N/A';
      const calculatedMonth = resp.createdAt ? getPreviousMonth(resp.createdAt) : 'N/A';
      console.log(`   ${index + 1}. ${resp.name} (créé le ${createdAt} → month: ${calculatedMonth})`);
    });
    console.log('');

    // 4. Demander confirmation
    console.log('⚠️  Ces réponses seront mises à jour avec month = createdAt - 1 mois');
    console.log('');

    // 5. Appliquer les corrections
    console.log('🔧 Application des corrections...\n');

    let fixedCount = 0;
    let errorCount = 0;
    const errors = [];

    for (const resp of responsesWithoutMonth) {
      try {
        // Vérifier que createdAt existe
        if (!resp.createdAt) {
          console.warn(`   ⚠️  ${resp.name}: createdAt manquant, impossible de calculer month`);
          errorCount++;
          errors.push({
            name: resp.name,
            id: resp._id,
            error: 'createdAt manquant'
          });
          continue;
        }

        // Calculer le mois précédent
        const month = getPreviousMonth(resp.createdAt);

        // Mettre à jour dans MongoDB
        const result = await collection.updateOne(
          { _id: resp._id },
          { $set: { month: month } }
        );

        if (result.modifiedCount === 1) {
          console.log(`   ✅ ${resp.name}: month = "${month}"`);
          fixedCount++;
        } else {
          console.warn(`   ⚠️  ${resp.name}: échec de la mise à jour`);
          errorCount++;
        }

      } catch (error) {
        console.error(`   ❌ ${resp.name}: ${error.message}`);
        errorCount++;
        errors.push({
          name: resp.name,
          id: resp._id,
          error: error.message
        });
      }
    }

    // 6. Rapport final
    console.log('\n' + '='.repeat(50));
    console.log('📊 RAPPORT DE CORRECTION');
    console.log('='.repeat(50));
    console.log(`\n✅ Corrigées: ${fixedCount}`);
    console.log(`❌ Erreurs: ${errorCount}`);
    console.log(`📦 Total: ${responsesWithoutMonth.length}`);

    if (errors.length > 0) {
      console.log('\n❌ Détails des erreurs:');
      errors.forEach(err => {
        console.log(`   - ${err.name} (${err.id}): ${err.error}`);
      });
    }

    console.log('\n💡 Prochaine étape:');
    console.log('   Relancer la migration: npm run migrate:run');
    console.log('');

    return {
      success: errorCount === 0,
      fixed: fixedCount,
      errors: errorCount
    };

  } catch (error) {
    console.error('\n❌ Erreur:', error.message);
    throw error;

  } finally {
    if (client) {
      await client.close();
      console.log('🔌 Connexion MongoDB fermée\n');
    }
  }
}

// Exécution
if (require.main === module) {
  fixMissingMonths()
    .then((result) => {
      if (result.success) {
        console.log('✅ Correction réussie!\n');
        process.exit(0);
      } else {
        console.warn('⚠️  Correction avec erreurs\n');
        process.exit(1);
      }
    })
    .catch((error) => {
      console.error('💥 Correction échouée:', error.message);
      process.exit(1);
    });
}

module.exports = { fixMissingMonths, getPreviousMonth };
