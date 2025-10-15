#!/usr/bin/env node

/**
 * Script de validation post-migration
 *
 * Valide que la migration MongoDB → Supabase s'est bien déroulée:
 * 1. Compte le nombre total de réponses dans Supabase
 * 2. Vérifie un échantillon de tokens (liens privés fonctionnent)
 * 3. Vérifie la structure des données (JSONB responses)
 * 4. Génère un rapport détaillé
 *
 * Usage:
 *   node scripts/validate-migration.js [backup-file.json]
 *
 * Environnement requis:
 *   - SUPABASE_URL: URL du projet Supabase
 *   - SUPABASE_SERVICE_KEY: Clé service_role (bypass RLS)
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

// Configuration
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const SAMPLE_SIZE = 10; // Nombre de tokens à vérifier

/**
 * Validation des variables d'environnement
 */
function validateEnvironment() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error('❌ Variables d\'environnement manquantes:');
    if (!SUPABASE_URL) console.error('   - SUPABASE_URL');
    if (!SUPABASE_SERVICE_KEY) console.error('   - SUPABASE_SERVICE_KEY');
    process.exit(1);
  }
}

/**
 * Trouver le fichier de backup le plus récent
 */
function findLatestBackup() {
  const backupDir = path.join(__dirname, '../backups');

  if (!fs.existsSync(backupDir)) {
    console.error('❌ Dossier backups introuvable');
    return null;
  }

  const files = fs.readdirSync(backupDir)
    .filter(f => f.startsWith('mongodb-backup-') && f.endsWith('.json'))
    .map(f => ({
      name: f,
      path: path.join(backupDir, f),
      time: fs.statSync(path.join(backupDir, f)).mtime.getTime()
    }))
    .sort((a, b) => b.time - a.time);

  return files.length > 0 ? files[0].path : null;
}

/**
 * Charger les données du backup
 */
function loadBackup(backupFile) {
  if (!backupFile) {
    const latest = findLatestBackup();
    if (!latest) {
      console.error('❌ Aucun fichier backup trouvé');
      console.error('   Exécuter d\'abord: node scripts/backup-mongodb.js');
      process.exit(1);
    }
    backupFile = latest;
    console.log(`📁 Utilisation du backup le plus récent: ${path.basename(backupFile)}`);
  }

  if (!fs.existsSync(backupFile)) {
    console.error(`❌ Fichier backup introuvable: ${backupFile}`);
    process.exit(1);
  }

  try {
    const data = JSON.parse(fs.readFileSync(backupFile, 'utf8'));
    return data;
  } catch (error) {
    console.error('❌ Erreur de lecture du backup:', error.message);
    process.exit(1);
  }
}

/**
 * Valider le nombre total de réponses
 */
async function validateCount(supabase, expectedCount, ririAdminId) {
  console.log('\n📊 Validation du nombre de réponses...');

  try {
    const { count, error } = await supabase
      .from('responses')
      .select('*', { count: 'exact', head: true })
      .eq('owner_id', ririAdminId);

    if (error) {
      throw error;
    }

    console.log(`   MongoDB (backup): ${expectedCount}`);
    console.log(`   Supabase: ${count}`);

    if (count === expectedCount) {
      console.log('   ✅ Nombre de réponses identique!');
      return { success: true, count };
    } else {
      const diff = expectedCount - count;
      console.warn(`   ⚠️  Différence: ${Math.abs(diff)} réponses ${diff > 0 ? 'manquantes' : 'en trop'}`);
      return { success: false, count, expected: expectedCount, diff };
    }

  } catch (error) {
    console.error('   ❌ Erreur:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Valider un échantillon de tokens
 */
async function validateTokens(supabase, mongoResponses) {
  console.log('\n🔑 Validation des tokens (liens privés)...');

  // Filtrer les réponses avec token
  const responsesWithToken = mongoResponses.filter(r => r.token);

  if (responsesWithToken.length === 0) {
    console.log('   ⚠️  Aucun token à valider');
    return { success: true, validated: 0 };
  }

  // Prendre un échantillon aléatoire
  const sample = responsesWithToken
    .sort(() => Math.random() - 0.5)
    .slice(0, Math.min(SAMPLE_SIZE, responsesWithToken.length));

  console.log(`   Échantillon: ${sample.length} tokens`);

  let validCount = 0;
  let invalidTokens = [];

  for (const mongoResp of sample) {
    try {
      const { data, error } = await supabase
        .from('responses')
        .select('id, name, token, month')
        .eq('token', mongoResp.token)
        .single();

      if (error || !data) {
        console.error(`   ❌ Token introuvable: ${mongoResp.token} (${mongoResp.name})`);
        invalidTokens.push({
          token: mongoResp.token,
          name: mongoResp.name,
          month: mongoResp.month
        });
      } else {
        // Vérifier la correspondance des données
        if (data.name === mongoResp.name && data.month === mongoResp.month) {
          validCount++;
        } else {
          console.warn(`   ⚠️  Token ${mongoResp.token}: données différentes`);
          console.warn(`      MongoDB: ${mongoResp.name} (${mongoResp.month})`);
          console.warn(`      Supabase: ${data.name} (${data.month})`);
        }
      }

    } catch (error) {
      console.error(`   ❌ Erreur pour token ${mongoResp.token}:`, error.message);
      invalidTokens.push({
        token: mongoResp.token,
        name: mongoResp.name,
        error: error.message
      });
    }
  }

  console.log(`   ✅ Tokens valides: ${validCount}/${sample.length}`);

  if (invalidTokens.length > 0) {
    console.warn(`   ⚠️  Tokens invalides: ${invalidTokens.length}`);
    invalidTokens.forEach(t => {
      console.warn(`      - ${t.name} (${t.token.slice(0, 8)}...): ${t.error || 'introuvable'}`);
    });
  }

  return {
    success: invalidTokens.length === 0,
    validated: validCount,
    total: sample.length,
    invalid: invalidTokens
  };
}

/**
 * Valider la structure des données JSONB
 */
async function validateDataStructure(supabase, ririAdminId) {
  console.log('\n🔍 Validation de la structure des données...');

  try {
    // Récupérer un échantillon de réponses
    const { data: responses, error } = await supabase
      .from('responses')
      .select('id, name, responses, month, is_owner, token')
      .eq('owner_id', ririAdminId)
      .limit(10);

    if (error) {
      throw error;
    }

    if (responses.length === 0) {
      console.warn('   ⚠️  Aucune réponse à valider');
      return { success: true, validated: 0 };
    }

    console.log(`   Échantillon: ${responses.length} réponses`);

    let validCount = 0;
    let issues = [];

    for (const resp of responses) {
      const errors = [];

      // Validation des champs requis
      if (!resp.name) errors.push('name manquant');
      if (!resp.month) errors.push('month manquant');

      // Validation JSONB responses
      if (!resp.responses) {
        errors.push('responses manquant');
      } else if (!Array.isArray(resp.responses)) {
        errors.push('responses n\'est pas un array');
      } else {
        // Vérifier le format des réponses
        for (let i = 0; i < resp.responses.length; i++) {
          const r = resp.responses[i];
          if (!r.question) errors.push(`responses[${i}].question manquant`);
          if (!r.answer && r.answer !== '') errors.push(`responses[${i}].answer manquant`);
        }
      }

      // Validation token (si is_owner = false)
      if (!resp.is_owner && !resp.token) {
        errors.push('token manquant pour is_owner=false');
      }

      if (errors.length > 0) {
        issues.push({
          id: resp.id,
          name: resp.name,
          errors
        });
      } else {
        validCount++;
      }
    }

    console.log(`   ✅ Réponses valides: ${validCount}/${responses.length}`);

    if (issues.length > 0) {
      console.warn(`   ⚠️  Problèmes détectés: ${issues.length}`);
      issues.forEach(issue => {
        console.warn(`      - ${issue.name}: ${issue.errors.join(', ')}`);
      });
    }

    return {
      success: issues.length === 0,
      validated: validCount,
      total: responses.length,
      issues
    };

  } catch (error) {
    console.error('   ❌ Erreur:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Vérifier l'admin Riri
 */
async function validateAdmin(supabase) {
  console.log('\n👤 Validation du compte admin...');

  try {
    const { data: admin, error } = await supabase
      .from('admins')
      .select('id, username, email')
      .eq('username', 'riri')
      .single();

    if (error || !admin) {
      console.error('   ❌ Admin "riri" introuvable');
      return { success: false };
    }

    console.log(`   ✅ Admin trouvé:`);
    console.log(`      - ID: ${admin.id}`);
    console.log(`      - Username: ${admin.username}`);
    console.log(`      - Email: ${admin.email}`);

    return { success: true, admin };

  } catch (error) {
    console.error('   ❌ Erreur:', error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Script principal de validation
 */
async function validate() {
  console.log('🔍 Validation de la migration MongoDB → Supabase');
  console.log('='.repeat(50));

  // 1. Validation environnement
  validateEnvironment();

  // 2. Charger le backup
  const backupFile = process.argv[2];
  const backupData = loadBackup(backupFile);

  console.log('\n📋 Informations du backup:');
  console.log(`   Date: ${backupData.metadata.date}`);
  console.log(`   Total réponses: ${backupData.metadata.totalResponses}`);
  console.log(`   Réponses admin: ${backupData.metadata.adminResponses}`);
  console.log(`   Réponses utilisateurs: ${backupData.metadata.userResponses}`);
  console.log(`   Avec token: ${backupData.metadata.withToken}`);

  // 3. Connexion Supabase
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  });

  // 4. Validation admin
  const adminResult = await validateAdmin(supabase);
  if (!adminResult.success) {
    console.error('\n❌ Validation échouée: Admin introuvable');
    process.exit(1);
  }

  const ririAdminId = adminResult.admin.id;

  // 5. Validation nombre de réponses
  const countResult = await validateCount(
    supabase,
    backupData.metadata.totalResponses,
    ririAdminId
  );

  // 6. Validation tokens
  const tokenResult = await validateTokens(supabase, backupData.responses);

  // 7. Validation structure
  const structureResult = await validateDataStructure(supabase, ririAdminId);

  // 8. Rapport final
  console.log('\n' + '='.repeat(50));
  console.log('📊 RAPPORT DE VALIDATION');
  console.log('='.repeat(50));

  const allSuccess = countResult.success && tokenResult.success && structureResult.success;

  console.log('\n✅ Compte admin:');
  console.log(`   ${adminResult.success ? '✅' : '❌'} Admin "riri" existe`);

  console.log('\n📊 Nombre de réponses:');
  console.log(`   ${countResult.success ? '✅' : '⚠️ '} ${countResult.count} réponses dans Supabase`);
  if (!countResult.success && countResult.diff) {
    console.log(`   ⚠️  Différence: ${Math.abs(countResult.diff)} réponses`);
  }

  console.log('\n🔑 Tokens (liens privés):');
  console.log(`   ${tokenResult.success ? '✅' : '⚠️ '} ${tokenResult.validated}/${tokenResult.total} tokens validés`);
  if (tokenResult.invalid && tokenResult.invalid.length > 0) {
    console.log(`   ⚠️  ${tokenResult.invalid.length} tokens invalides`);
  }

  console.log('\n🔍 Structure des données:');
  console.log(`   ${structureResult.success ? '✅' : '⚠️ '} ${structureResult.validated}/${structureResult.total} réponses valides`);
  if (structureResult.issues && structureResult.issues.length > 0) {
    console.log(`   ⚠️  ${structureResult.issues.length} problèmes détectés`);
  }

  console.log('\n' + '='.repeat(50));
  if (allSuccess) {
    console.log('✅ VALIDATION RÉUSSIE!');
    console.log('   Toutes les données ont été correctement migrées.');
  } else {
    console.log('⚠️  VALIDATION AVEC AVERTISSEMENTS');
    console.log('   Certaines données nécessitent une vérification.');
  }
  console.log('='.repeat(50));

  console.log('\n💡 Prochaines étapes:');
  console.log('   1. Tester la connexion au dashboard: /admin/dashboard.html');
  console.log('   2. Vérifier quelques liens privés: /view/{token}');
  console.log('   3. Tester la soumission d\'un nouveau formulaire');
  console.log('   4. Si tout fonctionne, désactiver MongoDB');

  console.log('\n✨ Validation terminée!\n');

  return {
    success: allSuccess,
    admin: adminResult,
    count: countResult,
    tokens: tokenResult,
    structure: structureResult
  };
}

// Exécution du script
if (require.main === module) {
  validate()
    .then((result) => {
      if (result.success) {
        console.log('✅ Validation réussie!');
        process.exit(0);
      } else {
        console.warn('⚠️  Validation avec avertissements');
        process.exit(1);
      }
    })
    .catch((error) => {
      console.error('\n💥 Validation échouée:', error.message);
      console.error(error.stack);
      process.exit(1);
    });
}

module.exports = { validate };
