require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const app = express();

const path = require('path');
app.use(express.static(path.join(__dirname, '../frontend')));
const port = process.env.PORT || 3000;

const cors = require('cors');
app.use(cors());

// Augmente la limite à 50 Mo (par défaut c’est souvent 1 Mo ou 100 ko selon la config)
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
  
// Connexion à MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("Connecté à la base de données"))
  .catch(err => console.error("Erreur de connexion à la DB :", err));

// Middleware pour parser le JSON des requêtes
app.use(express.json());

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

// Import et utilisation du routeur pour l'admin
const adminRoutes = require('./routes/adminRoutes');
app.use('/api/admin', adminRoutes);

// Route 404 : envoie frontend/404.html
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '../frontend/404.html'));
});


// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur lancé sur le port ${port}`);
});