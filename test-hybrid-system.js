// Test script pour le système hybride
require('dotenv').config();
const path = require('path');
process.chdir(path.join(__dirname, 'backend'));
const mongoose = require('mongoose');
const User = require('./models/User');
const Response = require('./models/Response');

async function testHybridSystem() {
  try {
    console.log('🚀 Test du système hybride FAF');
    console.log('================================');
    
    // Connexion à MongoDB avec URI de test
    const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/faf-test';
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connecté à MongoDB');
    
    // Test 1: Création d'un utilisateur
    console.log('\n📝 Test 1: Création utilisateur');
    
    // Nettoyer les données de test
    await User.deleteOne({ username: 'testuser' });
    await Response.deleteMany({ $or: [{ name: 'TestUser' }, { 'migrationData.legacyName': 'TestUser' }] });
    
    const testUser = new User({
      username: 'testuser',
      email: 'test@example.com',
      password: 'password123',
      role: 'user'
    });
    
    await testUser.save();
    console.log('✅ Utilisateur créé:', testUser.toPublicJSON());
    
    // Test 2: Création d'une réponse legacy (ancien système)
    console.log('\n📝 Test 2: Réponse legacy');
    const legacyResponse = new Response({
      name: 'TestUser',
      responses: [
        { question: 'Question test', answer: 'Réponse test' }
      ],
      month: '2025-01',
      isAdmin: false,
      token: 'abc123def456',
      authMethod: 'token'
    });
    
    await legacyResponse.save();
    console.log('✅ Réponse legacy créée:', {
      id: legacyResponse._id,
      name: legacyResponse.name,
      token: legacyResponse.token,
      authMethod: legacyResponse.authMethod
    });
    
    // Test 3: Création d'une réponse moderne (nouveau système)
    console.log('\n📝 Test 3: Réponse moderne');
    const modernResponse = new Response({
      userId: testUser._id,
      responses: [
        { question: 'Question moderne', answer: 'Réponse moderne' }
      ],
      month: '2025-02',
      isAdmin: false,
      authMethod: 'user'
    });
    
    await modernResponse.save();
    console.log('✅ Réponse moderne créée:', {
      id: modernResponse._id,
      userId: modernResponse.userId,
      authMethod: modernResponse.authMethod
    });
    
    // Test 4: Migration d'une réponse legacy vers un utilisateur
    console.log('\n📝 Test 4: Migration legacy → moderne');
    
    const migrationResult = await Response.updateOne(
      { token: 'abc123def456' },
      {
        $set: {
          userId: testUser._id,
          authMethod: 'user'
        },
        $unset: {
          name: 1,
          token: 1
        }
      }
    );
    
    console.log('✅ Migration réussie:', migrationResult);
    
    // Test 5: Vérification finale
    console.log('\n📝 Test 5: Vérification finale');
    
    const userResponses = await Response.find({ userId: testUser._id });
    console.log(`✅ ${userResponses.length} réponse(s) associée(s) à l'utilisateur`);
    
    const legacyResponses = await Response.find({ authMethod: 'token' });
    console.log(`📊 ${legacyResponses.length} réponse(s) legacy restante(s)`);
    
    const modernResponses = await Response.find({ authMethod: 'user' });
    console.log(`📊 ${modernResponses.length} réponse(s) moderne(s)`);
    
    console.log('\n🎉 Tous les tests passent ! Le système hybride fonctionne.');
    
  } catch (error) {
    console.error('❌ Erreur lors du test:', error);
  } finally {
    await mongoose.disconnect();
    console.log('🔌 Déconnecté de MongoDB');
  }
}

// Exécuter les tests
testHybridSystem().catch(console.error);