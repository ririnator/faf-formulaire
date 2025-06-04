require('dotenv').config();
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
  
// Middleware pour parser le JSON
app.use(express.json());

// Import du routeur pour les formulaires
const formRoutes = require('./routes/formRoutes');
app.use('/api/form', formRoutes);

// Import du routeur pour les réponses
const responseRoutes = require('./routes/responseRoutes');
app.use('/api/response', responseRoutes);

// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur lancé sur le port ${port}`);
});
