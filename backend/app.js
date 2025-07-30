// app.js
require('dotenv').config();
const express       = require('express');
const rateLimit     = require('express-rate-limit');
const mongoose      = require('mongoose');
const bodyParser    = require('body-parser');
const bcrypt        = require('bcrypt');
const path          = require('path');
const session       = require('express-session');
const cors          = require('cors');
const MongoStore    = require('connect-mongo');

const formRoutes     = require('./routes/formRoutes');
const responseRoutes = require('./routes/responseRoutes');
const adminRoutes    = require('./routes/adminRoutes');
const uploadRoutes   = require('./routes/upload');
const Response       = require('./models/Response');

const app  = express();
const port = process.env.PORT || 3000;

// 1) CORS – n’autorise que votre front
app.use(cors({
  origin: process.env.APP_BASE_URL, 
  credentials: true
}));
app.set('trust proxy', 1);

// 2) Sessions
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60,    // 14 jours
    autoRemove: 'native'
  }),
  cookie: {
    maxAge: 1000 * 60 * 60, // 1 heure
    sameSite: 'none',
    secure: true            // en prod via HTTPS
  }
}));

// 3) Parsers
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.json());

// 4) Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("Connecté à la base de données");
    await mongoose.connection.collection('responses')
      .createIndex({ createdAt: -1 });
    console.log("Index créé sur responses.createdAt");
  })
  .catch(err => console.error("Erreur de connexion à la DB :", err));

// 5) Front public (index.html, view.html…)
app.use(express.static(path.join(__dirname, '../frontend/public')));

// 6) Authentification Admin
const ADMIN_USER      = process.env.ADMIN_USER;
const ADMIN_PASS_HASH = bcrypt.hashSync(process.env.ADMIN_PASS, 10);
function ensureAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  return res.redirect('/login');
}

// 7) Pages de login/logout
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/login.html'));
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && await bcrypt.compare(password, ADMIN_PASS_HASH)) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }
  return res.redirect('/login?error=1');
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

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
app.listen(port, () => {
  console.log(`Serveur lancé sur le port ${port}`);
});
