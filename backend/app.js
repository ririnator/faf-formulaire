require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const app = express();
const port = process.env.PORT || 3000;
  
// Connexion à MongoDB
mongoose.connect('mongodb://localhost:27017/FAF')
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

// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur lancé sur le port ${port}`);
});
