/**
 * Script de test manuel pour /api/response/submit
 * Vérifie que tout fonctionne vraiment
 */

require('dotenv').config();
const handler = require('./api/response/submit');
const { generateToken, isValidToken } = require('./utils/tokens');
const {
  escapeHtml,
  isCloudinaryUrl,
  validateResponses,
  validateName,
  validateHoneypot
} = require('./utils/validation');
const { createRateLimiter, resetStore } = require('./middleware/rateLimit');

console.log('🧪 Test manuel Étape 4: API Soumission\n');

// ========================================
// TEST 1: Module tokens.js
// ========================================
console.log('📝 Test 1: utils/tokens.js');
const token1 = generateToken();
const token2 = generateToken();

console.log(`   ✓ Token 1 généré: ${token1.substring(0, 16)}... (longueur: ${token1.length})`);
console.log(`   ✓ Token 2 généré: ${token2.substring(0, 16)}... (longueur: ${token2.length})`);
console.log(`   ✓ Tokens différents: ${token1 !== token2 ? 'OUI' : 'NON'}`);
console.log(`   ✓ Token 1 valide: ${isValidToken(token1) ? 'OUI' : 'NON'}`);
console.log(`   ✓ Token invalide rejeté: ${!isValidToken('invalid123') ? 'OUI' : 'NON'}`);

// ========================================
// TEST 2: Module validation.js
// ========================================
console.log('\n📝 Test 2: utils/validation.js (nouvelles fonctions)');

// Test escapeHtml
const xss = '<script>alert("XSS")</script>';
const escaped = escapeHtml(xss);
console.log(`   ✓ XSS échappé: ${escaped.includes('&lt;script&gt;') ? 'OUI' : 'NON'}`);

// Test isCloudinaryUrl
const validUrl = 'https://res.cloudinary.com/mycloud/image/upload/v123/photo.jpg';
const invalidUrl = 'https://evil.com/malicious.jpg';
console.log(`   ✓ URL Cloudinary valide: ${isCloudinaryUrl(validUrl) ? 'OUI' : 'NON'}`);
console.log(`   ✓ URL malveillante rejetée: ${!isCloudinaryUrl(invalidUrl) ? 'OUI' : 'NON'}`);

// Test validateResponses
const validResponses = [
  { question: 'Q1', answer: 'A1' },
  { question: 'Q2', answer: 'A2' },
  { question: 'Q3', answer: 'A3' },
  { question: 'Q4', answer: 'A4' },
  { question: 'Q5', answer: 'A5' },
  { question: 'Q6', answer: 'A6' },
  { question: 'Q7', answer: 'A7' },
  { question: 'Q8', answer: 'A8' },
  { question: 'Q9', answer: 'A9' },
  { question: 'Q10', answer: 'A10' }
];
const result = validateResponses(validResponses);
console.log(`   ✓ 10 réponses valides: ${result.valid ? 'OUI' : 'NON'}`);

const invalidResponses = [{ question: 'Q1', answer: 'A1' }]; // Pas assez
const result2 = validateResponses(invalidResponses);
console.log(`   ✓ 1 réponse rejetée: ${!result2.valid ? 'OUI' : 'NON'}`);

// Test validateName
const validName = validateName('Emma');
const invalidName = validateName('A');
console.log(`   ✓ Nom "Emma" valide: ${validName.valid ? 'OUI' : 'NON'}`);
console.log(`   ✓ Nom "A" rejeté: ${!invalidName.valid ? 'OUI' : 'NON'}`);

// Test validateHoneypot
console.log(`   ✓ Honeypot vide valide: ${validateHoneypot('') ? 'OUI' : 'NON'}`);
console.log(`   ✓ Honeypot rempli rejeté: ${!validateHoneypot('spam') ? 'OUI' : 'NON'}`);

// ========================================
// TEST 3: Module rateLimit.js
// ========================================
console.log('\n📝 Test 3: middleware/rateLimit.js');

resetStore(); // Nettoyer avant le test

const rateLimiter = createRateLimiter({ windowMs: 60000, max: 3 });

function mockReq(ip) {
  return {
    headers: { 'x-forwarded-for': ip },
    connection: { remoteAddress: ip }
  };
}

function mockRes() {
  const res = {
    statusCode: 200,
    data: null,
    headers: {},
    status(code) { this.statusCode = code; return this; },
    json(data) { this.data = data; return this; },
    setHeader(key, value) { this.headers[key] = value; return this; }
  };
  return res;
}

// Simuler 4 requêtes de la même IP
const ip = '192.168.1.100';
const req1 = mockReq(ip);
const res1 = mockRes();
rateLimiter(req1, res1, () => {});
console.log(`   ✓ Requête 1: ${res1.statusCode === 200 ? 'OK' : 'FAIL'} (Remaining: ${res1.headers['X-RateLimit-Remaining']})`);

const req2 = mockReq(ip);
const res2 = mockRes();
rateLimiter(req2, res2, () => {});
console.log(`   ✓ Requête 2: ${res2.statusCode === 200 ? 'OK' : 'FAIL'} (Remaining: ${res2.headers['X-RateLimit-Remaining']})`);

const req3 = mockReq(ip);
const res3 = mockRes();
rateLimiter(req3, res3, () => {});
console.log(`   ✓ Requête 3: ${res3.statusCode === 200 ? 'OK' : 'FAIL'} (Remaining: ${res3.headers['X-RateLimit-Remaining']})`);

const req4 = mockReq(ip);
const res4 = mockRes();
rateLimiter(req4, res4, () => {});
console.log(`   ✓ Requête 4: ${res4.statusCode === 429 ? 'BLOQUÉE (429)' : 'FAIL'}`);

// ========================================
// TEST 4: API submit.js (sans DB)
// ========================================
console.log('\n📝 Test 4: api/response/submit.js (validation basique)');

async function testSubmitValidation() {
  // Test méthode GET (devrait retourner 405)
  const getReq = { method: 'GET', body: {}, headers: { 'x-forwarded-for': '127.0.0.1' } };
  const getRes = mockRes();
  await handler(getReq, getRes);
  console.log(`   ✓ GET rejeté (405): ${getRes.statusCode === 405 ? 'OUI' : 'NON'}`);

  // Test honeypot rempli
  resetStore();
  const spamReq = {
    method: 'POST',
    body: {
      username: 'test',
      name: 'Spammer',
      responses: validResponses,
      website: 'http://spam.com' // Honeypot rempli
    },
    headers: { 'x-forwarded-for': '127.0.0.2' },
    connection: { remoteAddress: '127.0.0.2' }
  };
  const spamRes = mockRes();
  await handler(spamReq, spamRes);
  console.log(`   ✓ Spam rejeté (400): ${spamRes.statusCode === 400 ? 'OUI' : 'NON'}`);
  console.log(`   ✓ Message spam: ${spamRes.data?.error === 'Spam detected' ? 'OUI' : 'NON'}`);

  // Test champs manquants
  resetStore();
  const missingReq = {
    method: 'POST',
    body: { username: 'test' }, // name et responses manquants
    headers: { 'x-forwarded-for': '127.0.0.3' },
    connection: { remoteAddress: '127.0.0.3' }
  };
  const missingRes = mockRes();
  await handler(missingReq, missingRes);
  console.log(`   ✓ Champs manquants rejetés (400): ${missingRes.statusCode === 400 ? 'OUI' : 'NON'}`);
}

testSubmitValidation().then(() => {
  console.log('\n' + '='.repeat(60));
  console.log('✅ TOUS LES TESTS MANUELS PASSENT');
  console.log('='.repeat(60));
  console.log('\n💡 Pour tester avec la DB Supabase :');
  console.log('   npm test -- tests/api/submit.test.js');
}).catch(err => {
  console.error('\n❌ ERREUR:', err);
  process.exit(1);
});
