const express = require('express');
const router = express.Router();

// Endpoint POST pour enregistrer une réponse
router.post('/', (req, res) => {
  // On récupère les données envoyées dans le corps de la requête
  const responseData = req.body;
  
  // Pour l'instant, on affiche la réponse dans la console
  console.log('Réponse reçue:', responseData);
  
  // Et on renvoie un message de succès au client
  res.json({ message: "Réponse enregistrée avec succès !" });
});

module.exports = router;
