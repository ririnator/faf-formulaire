require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const cors       = require('cors');
const port = process.env.PORT || 3000;
const MongoStore = require('connect-mongo');

const app = express();

// Faire confiance au proxy de Render pour récupérer la vraie IP client
app.set('trust proxy', 1);


// --- 1. SESSION CONFIGURATION ---
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60,    // durée de vie : 14 jours en secondes
    autoRemove: 'native'       // MongoDB supprime automatiquement les sessions expirées
  }),
  cookie: {
    maxAge: 1000 * 60 * 60  // 1 heure
  }
}));

// 2. PARSERS
// Augmente la limite à 50 Mo (par défaut c’est souvent 1 Mo ou 100 ko selon la config)
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
// Middleware pour parser le JSON des requêtes
app.use(express.json());
  
// 3. BASE DE DONNÉES
// Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("Connecté à la base de données");
    // Création de l’index si pas déjà présent
    await mongoose.connection.collection('responses')
      .createIndex({ createdAt: -1 });
    console.log("Index créé sur responses.createdAt");
  })
  .catch(err => console.error("Erreur de connexion à la DB :", err));


//4. SERVIR LE FRONT PUBLIC
app.use(express.static(path.join(__dirname, '../frontend/public')));
app.use(cors());


// 5. Outils d'Authentification
const ADMIN_USER      = process.env.ADMIN_USER;
const ADMIN_PASS_HASH = bcrypt.hashSync(process.env.ADMIN_PASS, 10);

function ensureAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect('/login');
}

// 6. LOGIN / LOGOUT ROUTES
// Affiche le formulaire de connexion
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/login.html'));
});

// Traite le formulaire
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && await bcrypt.compare(password, ADMIN_PASS_HASH)) {
    req.session.isAdmin = true;
    return res.redirect('/admin');  // ou la page de gestion que tu sers
  }
  // échec
  return res.redirect('/login?error=1');
});

// Déconnexion
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    // ignore error
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

// 7. PROTÉGER L'INTERFACE ADMIN ---
// Si tu as une page admin.html dans frontend/
app.get('/admin', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/admin.html'));
});

// Nouvelle route pour la gestion avancée
app.get('/admin/gestion', ensureAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/admin/admin_gestion.html'));
});

app.use('/admin/assets', ensureAdmin,
  express.static(path.join(__dirname, '../frontend/admin'))
);

// Import et utilisation du routeur pour l'admin
const adminRoutes = require('./routes/adminRoutes');
app.use('/api/admin', ensureAdmin,adminRoutes);

// Rate limiter : max 5 requêtes POST sur /api/response toutes les 15 minutes par IP
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                   // limite à 5 requêtes
  message: { 
    message: "Trop de soumissions. Réessaie dans 15 minutes." 
  }
});
app.use('/api/response', formLimiter);

// Import et utilisation du routeur pour les formulaires
const formRoutes = require('./routes/formRoutes');
app.use('/api/form', formRoutes);

// Import et utilisation du routeur pour les réponses
const responseRoutes = require('./routes/responseRoutes');
app.use('/api/response', responseRoutes);

// Sert les JS/CSS/images du back-office UNIQUEMENT si connecté
app.use('/admin/assets', ensureAdmin,
  express.static(path.join(__dirname, '../frontend/admin'))
);

// Route 404 : envoie frontend/404.html
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '../frontend/404.html'));
});


// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur lancé sur le port ${port}`);
});