#!/usr/bin/env node

/**
 * Script de migration MongoDB → Supabase
 *
 * Transfère toutes les données MongoDB vers Supabase:
 * 1. Backup MongoDB (sauvegarde JSON)
 * 2. Création du compte admin "riri" dans Supabase
 * 3. Migration de toutes les réponses avec owner_id = riri.id
 * 4. Validation des données migrées
 *
 * Usage:
 *   node scripts/migrate-to-supabase.js
 *
 * Environnement requis:
 *   - MONGODB_URI: URI de connexion MongoDB
 *   - SUPABASE_URL: URL du projet Supabase
 *   - SUPABASE_SERVICE_KEY: Clé service_role (bypass RLS)
 *   - RIRI_EMAIL: Email du compte admin riri
 *   - RIRI_PASSWORD: Mot de passe du compte admin riri
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const { backupMongoDB } = require('./backup-mongodb');

// Configuration
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const RIRI_EMAIL = process.env.RIRI_EMAIL;
const RIRI_PASSWORD = process.env.RIRI_PASSWORD;

const BCRYPT_ROUNDS = 10;
const BATCH_SIZE = 50; // Nombre de réponses par batch

/**
 * Validation des variables d'environnement
 */
function validateEnvironment() {
  const required = {
    MONGODB_URI: process.env.MONGODB_URI,
    SUPABASE_URL,
    SUPABASE_SERVICE_KEY,
    RIRI_EMAIL,
    RIRI_PASSWORD
  };

  const missing = Object.entries(required)
    .filter(([_, value]) => !value)
    .map(([key]) => key);

  if (missing.length > 0) {
    console.error('❌ Variables d\'environnement manquantes:');
    missing.forEach(key => console.error(`   - ${key}`));
    console.error('\n💡 Créer un fichier .env avec:');
    console.error('   MONGODB_URI="mongodb+srv://..."');
    console.error('   SUPABASE_URL="https://xxx.supabase.co"');
    console.error('   SUPABASE_SERVICE_KEY="eyJhbGc..."');
    console.error('   RIRI_EMAIL="riri@example.com"');
    console.error('   RIRI_PASSWORD="Password123!"');
    process.exit(1);
  }
}

/**
 * Créer le compte admin "riri" dans Supabase
 */
async function createRiriAdmin(supabase) {
  console.log('\n👤 Création du compte admin "riri"...');

  try {
    // 1. Vérifier si l'admin existe déjà
    const { data: existingAdmin } = await supabase
      .from('admins')
      .select('id, username')
      .eq('username', 'riri')
      .single();

    if (existingAdmin) {
      console.log('⚠️  Admin "riri" existe déjà (ID: ' + existingAdmin.id + ')');
      console.log('   → Utilisation du compte existant');
      return existingAdmin.id;
    }

    // 2. Hasher le password
    console.log('🔐 Hash du mot de passe...');
    const passwordHash = await bcrypt.hash(RIRI_PASSWORD, BCRYPT_ROUNDS);

    // 3. Créer l'admin dans Supabase
    const { data: newAdmin, error } = await supabase
      .from('admins')
      .insert({
        username: 'riri',
        email: RIRI_EMAIL,
        password_hash: passwordHash
      })
      .select()
      .single();

    if (error) {
      console.error('❌ Erreur création admin:', error.message);
      throw error;
    }

    console.log('✅ Admin créé avec succès!');
    console.log(`   - ID: ${newAdmin.id}`);
    console.log(`   - Username: ${newAdmin.username}`);
    console.log(`   - Email: ${newAdmin.email}`);

    return newAdmin.id;

  } catch (error) {
    console.error('❌ Erreur lors de la création de l\'admin:', error.message);
    throw error;
  }
}

/**
 * Migrer les réponses MongoDB vers Supabase
 */
async function migrateResponses(supabase, mongoResponses, ririAdminId) {
  console.log('\n📦 Migration des réponses...');
  console.log(`   Total à migrer: ${mongoResponses.length}`);

  const stats = {
    total: mongoResponses.length,
    success: 0,
    errors: 0,
    skipped: 0,
    errorDetails: []
  };

  // Migration par batch pour éviter les timeouts
  const batches = [];
  for (let i = 0; i < mongoResponses.length; i += BATCH_SIZE) {
    batches.push(mongoResponses.slice(i, i + BATCH_SIZE));
  }

  console.log(`   Batches: ${batches.length} (${BATCH_SIZE} réponses/batch)\n`);

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
    const batch = batches[batchIndex];
    console.log(`📤 Batch ${batchIndex + 1}/${batches.length} (${batch.length} réponses)...`);

    for (const mongoResp of batch) {
      try {
        // Validation des données essentielles
        if (!mongoResp.name || !mongoResp.responses || !mongoResp.month) {
          console.warn(`   ⚠️  Skipped: ${mongoResp.name || 'Unknown'} (données incomplètes)`);
          stats.skipped++;
          continue;
        }

        // Préparation des données Supabase
        const supabaseResp = {
          owner_id: ririAdminId,
          name: mongoResp.name,
          responses: mongoResp.responses, // JSONB (array)
          month: mongoResp.month,
          is_owner: mongoResp.isAdmin === true,
          token: mongoResp.token || null,
          created_at: mongoResp.createdAt ? new Date(mongoResp.createdAt).toISOString() : new Date().toISOString()
        };

        // Insertion dans Supabase
        const { error } = await supabase
          .from('responses')
          .insert(supabaseResp);

        if (error) {
          // Gérer les doublons (contrainte unique token ou owner_id+month)
          if (error.code === '23505') { // Duplicate key
            console.warn(`   ⚠️  Doublon ignoré: ${mongoResp.name}`);
            stats.skipped++;
          } else {
            console.error(`   ❌ Erreur pour ${mongoResp.name}: ${error.message}`);
            stats.errors++;
            stats.errorDetails.push({
              name: mongoResp.name,
              month: mongoResp.month,
              error: error.message
            });
          }
        } else {
          stats.success++;
        }

      } catch (err) {
        console.error(`   ❌ Exception pour ${mongoResp.name}:`, err.message);
        stats.errors++;
        stats.errorDetails.push({
          name: mongoResp.name,
          error: err.message
        });
      }
    }

    // Afficher la progression
    const progress = ((batchIndex + 1) / batches.length * 100).toFixed(1);
    console.log(`   ✅ Batch terminé (${progress}%)\n`);
  }

  return stats;
}

/**
 * Valider la migration
 */
async function validateMigration(supabase, originalCount, ririAdminId) {
  console.log('\n🔍 Validation de la migration...');

  try {
    // 1. Compter les réponses dans Supabase
    const { count: supabaseCount, error } = await supabase
      .from('responses')
      .select('*', { count: 'exact', head: true })
      .eq('owner_id', ririAdminId);

    if (error) {
      throw error;
    }

    console.log(`   MongoDB: ${originalCount} réponses`);
    console.log(`   Supabase: ${supabaseCount} réponses`);

    // 2. Vérifier la correspondance
    if (supabaseCount === originalCount) {
      console.log('   ✅ Nombre de réponses identique!');
      return { success: true, count: supabaseCount };
    } else {
      const diff = originalCount - supabaseCount;
      console.warn(`   ⚠️  Différence: ${diff} réponses manquantes`);
      return { success: false, count: supabaseCount, missing: diff };
    }

  } catch (error) {
    console.error('   ❌ Erreur de validation:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Script principal de migration
 */
async function migrate() {
  console.log('🚀 Migration MongoDB → Supabase');
  console.log('='.repeat(50));

  // 1. Validation environnement
  validateEnvironment();

  // 2. Backup MongoDB
  console.log('\n📋 Étape 1/4: Backup MongoDB');
  const backup = await backupMongoDB();

  if (!backup.success) {
    console.error('❌ Backup échoué, migration annulée');
    process.exit(1);
  }

  // Charger les données du backup
  const backupData = JSON.parse(fs.readFileSync(backup.file, 'utf8'));
  const mongoResponses = backupData.responses;
  console.log(`✅ Backup chargé: ${mongoResponses.length} réponses`);

  // 3. Connexion Supabase
  console.log('\n📋 Étape 2/4: Connexion Supabase');
  console.log(`   URL: ${SUPABASE_URL}`);

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });
  console.log('✅ Client Supabase initialisé');

  // 4. Créer admin Riri
  console.log('\n📋 Étape 3/4: Création admin "riri"');
  const ririAdminId = await createRiriAdmin(supabase);

  // 5. Migrer les réponses
  console.log('\n📋 Étape 4/4: Migration des réponses');
  const migrationStats = await migrateResponses(supabase, mongoResponses, ririAdminId);

  // 6. Validation
  const validation = await validateMigration(supabase, mongoResponses.length, ririAdminId);

  // 7. Rapport final
  console.log('\n' + '='.repeat(50));
  console.log('📊 RAPPORT DE MIGRATION');
  console.log('='.repeat(50));
  console.log('\n✅ Succès:', migrationStats.success);
  console.log('❌ Erreurs:', migrationStats.errors);
  console.log('⚠️  Ignorés:', migrationStats.skipped);
  console.log('📦 Total:', migrationStats.total);

  if (migrationStats.errorDetails.length > 0) {
    console.log('\n❌ Détails des erreurs:');
    migrationStats.errorDetails.slice(0, 10).forEach(err => {
      console.log(`   - ${err.name}: ${err.error}`);
    });
    if (migrationStats.errorDetails.length > 10) {
      console.log(`   ... et ${migrationStats.errorDetails.length - 10} autres`);
    }
  }

  console.log('\n🔍 Validation:');
  if (validation.success) {
    console.log('   ✅ Migration complète et validée!');
    console.log(`   ✅ ${validation.count} réponses dans Supabase`);
  } else {
    console.warn('   ⚠️  Migration partielle');
    if (validation.missing) {
      console.warn(`   ⚠️  ${validation.missing} réponses manquantes`);
    }
  }

  console.log('\n📁 Fichiers générés:');
  console.log(`   - Backup: ${backup.file}`);

  console.log('\n💡 Prochaines étapes:');
  console.log('   1. Vérifier les données dans Supabase dashboard');
  console.log('   2. Tester quelques liens privés (/view/{token})');
  console.log('   3. Se connecter au dashboard admin avec riri');
  console.log('   4. Exécuter: node scripts/validate-migration.js');

  console.log('\n✨ Migration terminée!\n');

  return {
    success: validation.success,
    stats: migrationStats,
    validation
  };
}

// Exécution du script
if (require.main === module) {
  migrate()
    .then((result) => {
      if (result.success) {
        console.log('✅ Migration réussie!');
        process.exit(0);
      } else {
        console.warn('⚠️  Migration avec erreurs');
        process.exit(1);
      }
    })
    .catch((error) => {
      console.error('\n💥 Migration échouée:', error.message);
      console.error(error.stack);
      process.exit(1);
    });
}

module.exports = { migrate };
