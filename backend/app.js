// app.js
require('dotenv').config();
const express       = require('express');
const rateLimit     = require('express-rate-limit');
const mongoose      = require('mongoose');
const path          = require('path');
const session       = require('express-session');
const cors          = require('cors');
const helmet        = require('helmet');

const formRoutes     = require('./routes/formRoutes');
const responseRoutes = require('./routes/responseRoutes');
const adminRoutes    = require('./routes/adminRoutes');
const uploadRoutes   = require('./routes/upload');
const Response       = require('./models/Response');
const { ensureAdmin, authenticateAdmin, destroySession } = require('./middleware/auth');
const { createSecurityMiddleware, createSessionOptions } = require('./middleware/security');
const { createStandardBodyParser, createPayloadErrorHandler } = require('./middleware/bodyParser');
const { csrfTokenMiddleware } = require('./middleware/csrf');

const app  = express();
const port = process.env.PORT || 3000;

// Health check endpoint pour Docker
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: Date.now(),
    uptime: process.uptime()
  });
});

// Endpoints de debug - seulement en développement
if (process.env.NODE_ENV !== 'production') {
  // SIMPLE TEST - aucun middleware, juste du JSON brut
  app.get('/test-simple', (req, res) => {
    res.json({ message: 'Simple test works', timestamp: Date.now() });
  });

  app.get('/test-debug', (req, res) => {
    const info = {
      nodeVersion: process.version,
      platform: process.platform,
      env: process.env.NODE_ENV,
      port: port,
      mongoConnected: mongoose.connection.readyState === 1,
      timestamp: new Date().toISOString()
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(info, null, 2));
  });
}

// 1) Enhanced Security headers with nonce-based CSP
app.use(createSecurityMiddleware());

// 1.5) UTF-8 encoding middleware for all responses
app.use((req, res, next) => {
  // Définir l'encodage UTF-8 par défaut pour toutes les réponses
  const originalSend = res.send;
  const originalJson = res.json;
  
  res.send = function(data) {
    if (!res.get('Content-Type')) {
      if (typeof data === 'string' && data.trim().startsWith('<')) {
        res.set('Content-Type', 'text/html; charset=utf-8');
      } else {
        res.set('Content-Type', 'text/plain; charset=utf-8');
      }
    }
    return originalSend.call(this, data);
  };
  
  res.json = function(data) {
    res.set('Content-Type', 'application/json; charset=utf-8');
    return originalJson.call(this, data);
  };
  
  next();
});

// 2) CORS – n'autorise que votre front
app.use(cors({
  origin: [
    process.env.APP_BASE_URL, 
    process.env.FRONTEND_URL
  ].filter(Boolean), // Removes any undefined values
  credentials: true
}));
app.set('trust proxy', 1);

// 3) Enhanced Sessions with better dev/prod handling
app.use(session(createSessionOptions()));

// 3.5) CSRF Token generation for admin routes
app.use(csrfTokenMiddleware());

// 4) Optimized Body Parsers (512KB standard limit)
app.use(createStandardBodyParser());
app.use(createPayloadErrorHandler());

// 5) Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("Connecté à la base de données");
    
    // Index for performance (chronological sorting)
    await mongoose.connection.collection('responses')
      .createIndex({ createdAt: -1 });
    console.log("Index créé sur responses.createdAt");
    
    // Unique constraint to prevent admin duplicates per month
    await mongoose.connection.collection('responses')
      .createIndex(
        { month: 1, isAdmin: 1 }, 
        { unique: true, partialFilterExpression: { isAdmin: true } }
      );
    console.log("Index unique créé sur responses.{month, isAdmin} avec filtre admin");
  })
  .catch(err => console.error("Erreur de connexion à la DB :", err));

// 6) Front public (index.html, view.html…)
app.use(express.static(path.join(__dirname, '../frontend/public')));

// 7) Pages de login/logout
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/login.html'));
});
app.post('/login', authenticateAdmin);
app.get('/logout', destroySession);

// 8) Back-office Admin (HTML + assets)
app.get('/admin', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/admin.html'));
});
app.get('/admin/gestion', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/admin_gestion.html'));
});

// Assets admin (faf-admin.js module, CSS, images, etc.) - accessible si session admin active
app.use('/admin', ensureAdmin, (req, res, next) => {
  // Set proper MIME type for JavaScript modules
  if (req.path.endsWith('.js')) {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    // Cache pour 1 heure en développement, 24h en production
    const cacheMaxAge = process.env.NODE_ENV === 'production' ? 86400 : 3600;
    res.setHeader('Cache-Control', `public, max-age=${cacheMaxAge}`);
  }
  next();
}, express.static(path.join(__dirname, '../frontend/admin')));

// DEBUG ENDPOINTS - désactivés en production pour la sécurité
if (process.env.NODE_ENV !== 'production') {
  app.get('/api/debug/health', (req, res) => {
    console.log('=== DEBUG HEALTH CHECK ===');
    try {
      res.setHeader('Content-Type', 'application/json');
      const response = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        environment: process.env.NODE_ENV || 'development',
        version: 'debug-1.0'
      };
      console.log('Sending response:', JSON.stringify(response, null, 2));
      res.status(200).json(response);
    } catch (error) {
      console.error('ERROR in debug endpoint:', error);
      res.status(500).json({ error: error.message });
    }
  });

  app.post('/api/debug/echo', (req, res) => {
    console.log('=== DEBUG ECHO ===');
    console.log('Body:', req.body);
    console.log('Headers:', req.headers);
    try {
      res.setHeader('Content-Type', 'application/json');
      res.status(200).json({
        received: req.body,
        method: req.method,
        path: req.path,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('ERROR in debug echo:', error);
      res.status(500).json({ error: error.message });
    }
  });
}

// 9) API Admin
app.use('/api/admin', ensureAdmin, adminRoutes);

// 10) Consultation privée (JSON)
app.get('/api/view/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const userResp  = await Response.findOne({ token, isAdmin: false }).lean();
    if (!userResp) {
      return res.status(404).json({ error: 'Lien invalide ou expiré' });
    }
    const adminResp = await Response.findOne({ month: userResp.month, isAdmin: true }).lean();
    return res.json({ user: userResp, admin: adminResp });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// 11) Limiteur pour les soumissions de formulaire
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 3,
  message: { message: "Trop de soumissions. Réessaie dans 15 minutes." }
});
app.use('/api/response', formLimiter);

// 12) API publiques
app.use('/api/form', formRoutes);
app.use('/api/response', responseRoutes);
app.use('/api/upload', uploadRoutes);

// 13) Servir la page view.html pour /view/:token
app.get('/view/:token', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/view.html'));
});

// 14) 404 générique
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '../frontend/404.html'));
});

// 15) Lancement du serveur
if (require.main === module) {
  app.listen(port, () => {
    console.log(`Serveur lancé sur le port ${port}`);
  });
}

module.exports = app;
