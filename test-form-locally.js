#!/usr/bin/env node

/**
 * Script pour tester la soumission du formulaire localement
 * Lance un serveur de test et simule des interactions
 */

const express = require('express');
const path = require('path');
const multer = require('multer');

const app = express();
const PORT = 3001;

// Middleware pour parser JSON
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Servir les fichiers statiques du frontend
app.use(express.static(path.join(__dirname, 'frontend/public')));
app.use('/admin', express.static(path.join(__dirname, 'frontend/admin')));

// Setup multer pour les uploads de test
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// Mock endpoint pour upload
app.post('/api/upload', upload.single('image'), (req, res) => {
  console.log('📎 Upload reçu:', req.file ? req.file.originalname : 'Pas de fichier');
  
  if (!req.file) {
    return res.status(400).json({ error: 'Pas de fichier fourni' });
  }

  // Simuler réponse Cloudinary
  const mockUrl = `https://mock-cloudinary.com/${Date.now()}-${req.file.originalname}`;
  
  setTimeout(() => {
    res.json({ 
      url: mockUrl,
      message: 'Upload simulé avec succès' 
    });
  }, 500); // Simuler délai upload
});

// Mock endpoint pour soumission formulaire
app.post('/api/response', (req, res) => {
  console.log('📝 Soumission reçue:');
  console.log('- Nom:', req.body.name);
  console.log('- Nombre de réponses:', req.body.responses?.length || 0);
  
  if (req.body.responses) {
    req.body.responses.forEach((resp, index) => {
      console.log(`  ${index + 1}. ${resp.question.substring(0, 50)}...`);
      console.log(`     → ${resp.answer.substring(0, 100)}${resp.answer.length > 100 ? '...' : ''}`);
    });
  }

  // Validation basique
  if (!req.body.name || req.body.name.trim().length < 2) {
    return res.status(400).json({
      message: 'Le nom doit contenir au moins 2 caractères',
      field: 'name'
    });
  }

  if (!req.body.responses || req.body.responses.length === 0) {
    return res.status(400).json({
      message: 'Au moins une réponse est requise',
      field: 'responses'
    });
  }

  // Simuler différents scénarios
  const scenario = Math.random();
  
  if (scenario < 0.1) { // 10% de chance d'erreur rate limiting
    return res.status(429).json({
      message: 'Trop de tentatives. Réessayez dans 15 minutes.'
    });
  }
  
  if (scenario < 0.2) { // 10% de chance d'erreur validation
    return res.status(400).json({
      message: 'Une réponse ne peut pas être vide (max 10000 caractères)',
      field: 'responses'
    });
  }

  // Succès - générer token mock
  const token = Math.random().toString(36).substring(2, 15);
  const isAdmin = req.body.name.toLowerCase() === 'riri';
  
  setTimeout(() => {
    res.status(201).json({
      message: isAdmin 
        ? 'Réponse admin enregistrée avec succès !' 
        : 'Réponse enregistrée avec succès !',
      link: isAdmin ? null : `http://localhost:${PORT}/view/${token}`
    });
  }, 300); // Simuler délai sauvegarde
});

// Mock endpoint pour consultation
app.get('/view/:token', (req, res) => {
  console.log('👀 Consultation du token:', req.params.token);
  res.send(`
    <h1>Consultation des réponses</h1>
    <p>Token: ${req.params.token}</p>
    <p>Ici s'afficheraient les réponses du mois...</p>
    <a href="/">← Retour au formulaire</a>
  `);
});

// Page d'accueil redirige vers le formulaire
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend/public/index.html'));
});

// Démarrage du serveur
const server = app.listen(PORT, () => {
  console.log(`
🚀 Serveur de test démarré sur http://localhost:${PORT}

📋 Instructions de test:
1. Ouvrir http://localhost:${PORT} dans le navigateur
2. Remplir le formulaire complet
3. Observer les logs dans cette console
4. Tester différents scénarios (nom court, champs vides, etc.)

🎯 Scénarios de test automatiques:
- 70% de chance de succès
- 10% de chance d'erreur rate limiting  
- 10% de chance d'erreur validation
- 10% de chance d'autre erreur

💡 Pour arrêter: Ctrl+C
`);
});

// Gestion gracieuse de l'arrêt
process.on('SIGINT', () => {
  console.log('\n🛑 Arrêt du serveur de test...');
  server.close(() => {
    console.log('✅ Serveur arrêté proprement.');
    process.exit(0);
  });
});

// Gestion des erreurs non capturées
process.on('uncaughtException', (error) => {
  console.error('❌ Erreur non capturée:', error);
});

process.on('unhandledRejection', (reason) => {
  console.error('❌ Promesse rejetée:', reason);
});