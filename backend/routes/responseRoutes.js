const express = require('express');
const router = express.Router();
const Response = require('../models/Response');

// Endpoint POST pour enregistrer une réponse
router.post('/', async (req, res) => {
  // On récupère les données envoyées dans le corps de la requête
  const responseData = req.body;
  try {
    const newResponse = new Response(responseData);
    await newResponse.save();  // Sauvegarde dans la base de données
    res.json({ message: "Réponse enregistrée avec succès !" });
  } catch (err) {
    console.error("Erreur en sauvegardant la réponse:", err);
    res.status(500).json({ message: "Erreur en sauvegardant la réponse" });
  }
});
module.exports = router;
