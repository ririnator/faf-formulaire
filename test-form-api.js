/**
 * Script de test manuel pour /api/form/[username]
 *
 * Usage: node test-form-api.js
 */

require('dotenv').config();
const handler = require('./api/form/[username]');

// Simuler une requête HTTP
function createMockReq(username) {
  return {
    method: 'GET',
    query: { username }
  };
}

function createMockRes() {
  return {
    statusCode: 200,
    data: null,
    status: function(code) {
      this.statusCode = code;
      return this;
    },
    json: function(data) {
      this.data = data;
      return this;
    }
  };
}

async function testAPI() {
  console.log('🧪 Test manuel de l\'API /api/form/[username]\n');

  // Test 1: Admin qui existe (utilise un admin créé dans l'étape 2)
  console.log('📝 Test 1: Récupérer le formulaire d\'un admin existant');
  console.log('   GET /api/form/testadmin\n');

  const req1 = createMockReq('testadmin');
  const res1 = createMockRes();

  await handler(req1, res1);

  console.log(`   Status: ${res1.statusCode}`);
  console.log(`   Success: ${res1.data?.success}`);

  if (res1.statusCode === 200) {
    console.log(`   ✅ Admin trouvé: ${res1.data.admin.username}`);
    console.log(`   ✅ Nombre de questions: ${res1.data.questions.length}`);
    console.log(`   ✅ Questions requises: ${res1.data.metadata.requiredQuestions}`);
    console.log(`   ✅ Questions optionnelles: ${res1.data.metadata.optionalQuestions}`);
  } else if (res1.statusCode === 404) {
    console.log(`   ⚠️  Admin 'testadmin' n'existe pas encore`);
    console.log(`   💡 Crée d'abord un admin avec POST /api/auth/register`);
  } else {
    console.log(`   ❌ Erreur: ${JSON.stringify(res1.data, null, 2)}`);
  }

  console.log('\n' + '─'.repeat(60) + '\n');

  // Test 2: Admin inexistant
  console.log('📝 Test 2: Admin inexistant');
  console.log('   GET /api/form/userquinexistepas\n');

  const req2 = createMockReq('userquinexistepas');
  const res2 = createMockRes();

  await handler(req2, res2);

  console.log(`   Status: ${res2.statusCode}`);
  console.log(`   Success: ${res2.data?.success}`);

  if (res2.statusCode === 404) {
    console.log(`   ✅ Erreur 404 correcte`);
    console.log(`   ✅ Message: ${res2.data.message}`);
  } else {
    console.log(`   ❌ Attendu 404, reçu ${res2.statusCode}`);
  }

  console.log('\n' + '─'.repeat(60) + '\n');

  // Test 3: Format username invalide
  console.log('📝 Test 3: Format username invalide');
  console.log('   GET /api/form/INVALID USER!\n');

  const req3 = createMockReq('INVALID USER!');
  const res3 = createMockRes();

  await handler(req3, res3);

  console.log(`   Status: ${res3.statusCode}`);
  console.log(`   Success: ${res3.data?.success}`);

  if (res3.statusCode === 400) {
    console.log(`   ✅ Erreur 400 correcte`);
    console.log(`   ✅ Message: ${res3.data.error}`);
  } else {
    console.log(`   ❌ Attendu 400, reçu ${res3.statusCode}`);
  }

  console.log('\n' + '─'.repeat(60) + '\n');

  // Test 4: Afficher les questions
  console.log('📝 Test 4: Structure des questions');
  const { getQuestions } = require('./utils/questions');
  const questions = getQuestions();

  console.log(`   Total questions: ${questions.length}\n`);

  questions.forEach((q, idx) => {
    const required = q.required ? '🔴' : '⚪';
    console.log(`   ${required} Q${idx + 1}: ${q.question}`);
    console.log(`      Type: ${q.type}${q.options ? ` (${q.options.length} options)` : ''}`);
  });

  console.log('\n' + '─'.repeat(60) + '\n');
  console.log('✅ Tests terminés !');
  console.log('\n💡 Pour créer un admin de test, utilise:');
  console.log('   npm test -- tests/api/auth.test.js');
}

testAPI().catch(err => {
  console.error('❌ Erreur:', err);
  process.exit(1);
});
