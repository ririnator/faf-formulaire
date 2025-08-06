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

const app  = express();
const port = process.env.PORT || 3000;

// 1) Enhanced Security headers with nonce-based CSP
app.use(createSecurityMiddleware());

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
app.use('/admin/assets', ensureAdmin,
  express.static(path.join(__dirname, '../frontend/admin'))
);

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
