require('dotenv').config();  // Pour charger les variables d'environnement
const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

// Middleware pour parser le JSON des requêtes
app.use(express.json());

// Exemple d'import de routes
// Tu devras créer ces fichiers dans le dossier "routes"
const formRoutes = require('./routes/formRoutes');

// Utiliser les routes (toutes les routes dans formRoutes seront préfixées par /api/form)
app.use('/api/form', formRoutes);

// Démarrer le serveur
app.listen(port, () => {
  console.log(`Serveur lancé sur le port ${port}`);
});
