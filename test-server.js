/**
 * Serveur de test pour les routes API d'authentification
 * Usage: node test-server.js
 * Ensuite utiliser curl ou Postman pour tester les routes
 */

require('dotenv').config();
const express = require('express');
const { authLimiter } = require('./middleware/rateLimit');

// Import des handlers API
const registerHandler = require('./api/auth/register');
const loginHandler = require('./api/auth/login');
const verifyHandler = require('./api/auth/verify');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Trust proxy pour rate limiting
app.set('trust proxy', 1);

// Routes d'authentification
app.post('/api/auth/register', authLimiter, registerHandler);
app.post('/api/auth/login', authLimiter, loginHandler);
app.get('/api/auth/verify', verifyHandler);

// Route de test
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    env: {
      supabase: !!process.env.SUPABASE_URL,
      jwt: !!process.env.JWT_SECRET
    }
  });
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log('\n🚀 Serveur de test démarré');
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log('\n📝 Routes disponibles:');
  console.log('  POST   /api/auth/register  - Inscription');
  console.log('  POST   /api/auth/login     - Connexion');
  console.log('  GET    /api/auth/verify    - Vérification JWT');
  console.log('  GET    /health             - État du serveur');
  console.log('\n💡 Exemples de commandes curl:');
  console.log('\n  # 1. Inscription');
  console.log('  curl -X POST http://localhost:3000/api/auth/register \\');
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -d \'{"username":"sophie","email":"sophie@test.com","password":"Password123!","website":""}\'');
  console.log('\n  # 2. Connexion');
  console.log('  curl -X POST http://localhost:3000/api/auth/login \\');
  console.log('    -H "Content-Type: application/json" \\');
  console.log('    -d \'{"username":"sophie","password":"Password123!"}\'');
  console.log('\n  # 3. Vérification (remplacer YOUR_TOKEN)');
  console.log('  curl http://localhost:3000/api/auth/verify \\');
  console.log('    -H "Authorization: Bearer YOUR_TOKEN"');
  console.log('\n  # 4. Health check');
  console.log('  curl http://localhost:3000/health');
  console.log('\n');
});

// Gestion des erreurs
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled rejection:', err);
});

process.on('SIGTERM', () => {
  console.log('\n👋 Arrêt du serveur...');
  process.exit(0);
});
