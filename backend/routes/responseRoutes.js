const express = require('express');
const router = express.Router();
const Response = require('../models/Response');
const { body, validationResult } = require('express-validator');

// Endpoint POST pour enregistrer une réponse
router.post('/', 
 // 1) règles de validation
 [
  body('name')
    .trim()
    .isLength({ min: 2 })
    .withMessage('Le nom doit contenir au moins 2 caractères'),
  body('responses')
    .isArray({ min: 1 })
    .withMessage('Il faut au moins une réponse'),
  body('responses.*.question')
    .notEmpty()
    .withMessage('Chaque question doit être précisée'),
  body('responses.*.answer')
    .notEmpty()
    .withMessage('Chaque réponse ne peut pas être vide'),
  // honeypot (champ invisible) — facultatif ici
  body('website')
    .optional()
    .isEmpty()
    .withMessage('Spam détecté')
],

  async (req, res) => {
    // 2) gestion des erreurs de validation 
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
  // 3) traitement normal : On récupère les données envoyées dans le corps de la requête
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
