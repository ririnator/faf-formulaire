const express = require('express');
const router = express.Router();
const Response = require('../models/Response');

router.post('/response', async (req, res) => {
  try {
    // Ici, req.body.responses doit être déjà un tableau d'objets { question, answer }
    const { name, responses } = req.body;

    // Création du document avec le nouveau format
    const responseDoc = new Response({
      name,
      responses  // Déjà au bon format
    });

    await responseDoc.save();
    res.json({ message: "Réponse enregistrée avec succès" });
  } catch (error) {
    console.error("Erreur lors de l'enregistrement :", error);
    res.status(500).json({ message: "Erreur lors de l'enregistrement de la réponse" });
  }
});

module.exports = router;