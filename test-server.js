#!/usr/bin/env node

/**
 * Serveur de test simple pour tester la soumission du formulaire
 * Sans MongoDB - juste pour valider la logique frontend
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = 3002;

// Simulation de données en mémoire
let submissions = [];

// Helper pour parser les données POST
function parsePostData(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(error);
      }
    });
  });
}

// Helper pour CORS
function setCORSHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  console.log(`${new Date().toLocaleTimeString()} - ${req.method} ${pathname}`);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    setCORSHeaders(res);
    res.writeHead(204);
    res.end();
    return;
  }

  setCORSHeaders(res);

  // Servir les fichiers statiques
  if (req.method === 'GET') {
    if (pathname === '/') {
      // Page d'accueil - rediriger vers le formulaire
      try {
        const html = fs.readFileSync(path.join(__dirname, 'frontend/public/index.html'), 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
      } catch (error) {
        console.error('Erreur lecture HTML:', error);
        res.writeHead(404);
        res.end('Fichier HTML non trouvé');
        return;
      }
    }

    if (pathname.startsWith('/css/') || pathname.startsWith('/js/')) {
      // Servir les assets CSS/JS
      const filePath = path.join(__dirname, 'frontend/public', pathname);
      try {
        const content = fs.readFileSync(filePath);
        const ext = path.extname(filePath);
        const contentType = ext === '.css' ? 'text/css' : 'application/javascript';
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
        return;
      } catch (error) {
        res.writeHead(404);
        res.end('Fichier non trouvé');
        return;
      }
    }
  }

  // API Endpoints
  if (pathname === '/api/upload' && req.method === 'POST') {
    // Mock upload endpoint
    console.log('📎 Upload simulé reçu');
    
    setTimeout(() => {
      const mockUrl = `https://mock-cloudinary.com/image-${Date.now()}.jpg`;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        url: mockUrl,
        message: 'Upload simulé avec succès'
      }));
    }, Math.random() * 1000 + 200); // Délai aléatoire 200-1200ms
    return;
  }

  if (pathname === '/api/response' && req.method === 'POST') {
    try {
      const data = await parsePostData(req);
      console.log('📝 Soumission reçue:');
      console.log(`- Nom: ${data.name}`);
      console.log(`- Réponses: ${data.responses?.length || 0}`);
      
      // Validation basique
      if (!data.name || data.name.trim().length < 2) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          message: 'Le nom doit contenir au moins 2 caractères',
          field: 'name'
        }));
        return;
      }

      if (!data.responses || data.responses.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          message: 'Au moins une réponse est requise',
          field: 'responses'
        }));
        return;
      }

      // Simuler différents scénarios aléatoires
      const scenario = Math.random();
      
      if (scenario < 0.15) { // 15% chance d'erreur
        const errors = [
          'Le nom doit contenir entre 2 et 100 caractères',
          'Une réponse ne peut pas être vide (max 10000 caractères)',
          'Il faut entre 1 et 20 réponses'
        ];
        
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          message: errors[Math.floor(Math.random() * errors.length)],
          field: 'validation'
        }));
        return;
      }

      if (scenario < 0.25) { // 10% chance de rate limiting
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          message: 'Trop de tentatives. Réessayez dans 15 minutes.',
          retryAfter: 900
        }));
        return;
      }

      // Succès - sauvegarder en mémoire
      const submission = {
        id: Date.now(),
        name: data.name,
        responses: data.responses,
        timestamp: new Date().toISOString(),
        isAdmin: data.name.toLowerCase() === 'riri'
      };

      submissions.push(submission);

      // Générer token si pas admin
      const token = submission.isAdmin ? null : Math.random().toString(36).substring(2, 15);
      const link = token ? `http://localhost:${PORT}/view/${token}` : null;

      // Délai pour simuler traitement
      setTimeout(() => {
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          message: submission.isAdmin 
            ? 'Réponse admin enregistrée avec succès !' 
            : 'Réponse enregistrée avec succès !',
          link: link,
          submissionId: submission.id
        }));
      }, Math.random() * 500 + 100); // 100-600ms

      return;
    } catch (error) {
      console.error('Erreur parsing JSON:', error);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        message: 'Données JSON invalides'
      }));
      return;
    }
  }

  // Page de consultation des tokens
  if (pathname.startsWith('/view/') && req.method === 'GET') {
    const token = pathname.substring(6);
    console.log(`👀 Consultation token: ${token}`);
    
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`
      <!DOCTYPE html>
      <html>
      <head><title>Consultation - Token ${token}</title></head>
      <body>
        <h1>🎉 Consultation des Réponses</h1>
        <p><strong>Token:</strong> ${token}</p>
        <p>Ici s'afficheraient normalement toutes les réponses du mois...</p>
        <div style="background: #f0f8ff; padding: 15px; margin: 20px 0; border-radius: 5px;">
          <h3>📊 Statistiques de Test</h3>
          <p>Total des soumissions: ${submissions.length}</p>
          <p>Dernière soumission: ${submissions.length > 0 ? submissions[submissions.length - 1].timestamp : 'Aucune'}</p>
        </div>
        <a href="/">← Retour au formulaire</a>
      </body>
      </html>
    `);
    return;
  }

  // API debug - lister toutes les soumissions
  if (pathname === '/api/debug/submissions' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      total: submissions.length,
      submissions: submissions.map(s => ({
        id: s.id,
        name: s.name,
        responseCount: s.responses.length,
        timestamp: s.timestamp,
        isAdmin: s.isAdmin
      }))
    }));
    return;
  }

  // 404 pour tout le reste
  res.writeHead(404, { 'Content-Type': 'text/html' });
  res.end(`
    <h1>404 - Page non trouvée</h1>
    <p>Chemin: ${pathname}</p>
    <a href="/">← Retour à l'accueil</a>
  `);
});

server.listen(PORT, () => {
  console.log(`
🚀 Serveur de test démarré sur http://localhost:${PORT}

📋 Endpoints disponibles:
- GET  /                          → Formulaire principal
- POST /api/response              → Soumission formulaire  
- POST /api/upload                → Upload d'images (mock)
- GET  /view/<token>              → Consultation privée
- GET  /api/debug/submissions     → Debug - toutes les soumissions

🎯 Scénarios aléatoires:
- 75% de succès
- 15% d'erreurs de validation
- 10% de rate limiting

💡 Pour arrêter: Ctrl+C
`);
});

// Gestion gracieuse de l'arrêt
process.on('SIGINT', () => {
  console.log('\n🛑 Arrêt du serveur de test...');
  console.log(`📊 Statistiques finales: ${submissions.length} soumissions reçues`);
  server.close(() => {
    console.log('✅ Serveur arrêté proprement.');
    process.exit(0);
  });
});