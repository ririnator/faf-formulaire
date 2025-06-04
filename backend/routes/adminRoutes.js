const express = require('express');
const router = express.Router();
const Response = require('../models/Response'); // On importe notre modèle de réponse

// Endpoint GET pour récupérer toutes les réponses (pour l'admin)
router.get('/responses', async (req, res) => {
  try {
    // Récupère toutes les réponses depuis la base de données
    const responses = await Response.find();
    res.json(responses);
  } catch (err) {
    console.error("Erreur en récupérant les réponses:", err);
    res.status(500).json({ message: "Erreur lors de la récupération des réponses" });
  }
});

module.exports = router;
