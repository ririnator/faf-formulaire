/**
 * Script pour créer un admin de test
 *
 * Usage: node create-test-admin.js
 */

require('dotenv').config();
const { createClient } = require('./config/supabase');
const bcrypt = require('bcrypt');

async function createTestAdmin() {
  console.log('🔧 Création d\'un admin de test...\n');

  const supabase = createClient();

  const username = 'testadmin';
  const email = 'test@admin.com';
  const password = 'TestPassword123!';

  // Vérifier si l'admin existe déjà
  const { data: existing } = await supabase
    .from('admins')
    .select('id, username')
    .eq('username', username)
    .single();

  if (existing) {
    console.log(`✅ Admin "${username}" existe déjà`);
    console.log(`   ID: ${existing.id}`);
    console.log(`   Username: ${existing.username}\n`);
    return existing.id;
  }

  // Créer l'admin
  console.log(`📝 Création de l'admin "${username}"...`);

  const passwordHash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from('admins')
    .insert({
      username,
      email,
      password_hash: passwordHash
    })
    .select()
    .single();

  if (error) {
    console.error('❌ Erreur:', error);
    throw error;
  }

  console.log(`✅ Admin créé avec succès !`);
  console.log(`   ID: ${data.id}`);
  console.log(`   Username: ${data.username}`);
  console.log(`   Email: ${data.email}\n`);

  return data.id;
}

createTestAdmin()
  .then(() => {
    console.log('🎉 Tu peux maintenant tester:');
    console.log('   node test-form-api.js');
  })
  .catch(err => {
    console.error('❌ Erreur:', err);
    process.exit(1);
  });
