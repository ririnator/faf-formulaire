const bcrypt = require('bcrypt');

// Remplacez 'VOTRE_MOT_DE_PASSE_ICI' par votre vrai mot de passe admin
const plainPassword = 'VOTRE_MOT_DE_PASSE_ICI';

async function generateHash() {
  try {
    const hash = await bcrypt.hash(plainPassword, 10);
    console.log('🔑 Mot de passe:', plainPassword);
    console.log('🔐 Hash bcrypt:');
    console.log(hash);
    console.log('');
    console.log('📋 Variable d\'environnement à définir:');
    console.log('LOGIN_ADMIN_PASS=' + hash);
    console.log('');
    console.log('⚠️  IMPORTANT: Supprimez ce fichier après utilisation pour la sécurité!');
  } catch (error) {
    console.error('❌ Erreur:', error);
  }
}

generateHash();