require('dotenv').config();
const express = require('express');
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
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log("Connecté à la base de données"))
  .catch(err => console.error("Erreur de connexion à la DB :", err));

// Middleware pour parser le JSON des requêtes
app.use(express.json());

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