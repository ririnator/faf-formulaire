// backend/routes/responseRoutes.js

const express = require('express');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const Response = require('../models/Response');

// POST /api/response
router.post(
  '/',
  [
    // 1) règles de validation
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

    // 3) normalisation des données
    const { name, responses } = req.body;
    const month = new Date().toISOString().slice(0, 7); // "YYYY-MM"
    const isAdmin = name.trim().toLowerCase() === 'riri';
    // seul l’ami reçoit un token et pourra consulter
    const token = isAdmin 
    ? undefined 
    : crypto.randomBytes(32).toString('hex');

// → **NE PAS CRÉER** si un admin pour ce mois existe déjà
  if (isAdmin) {
      const already = await Response.exists({ month, isAdmin: true });
      if (already) {
        return res.status(409).json({
          message: 'Une réponse admin existe déjà pour ce mois.'
        });
      }
  }

    try {
      // 4) création et sauvegarde
      const newResponse = new Response({
        name,
        responses,
        month,
        isAdmin,
        token
      });
      await newResponse.save();

      // 5) on renvoie le lien privé dans la réponse JSON
      const link = token
        ? `${process.env.APP_BASE_URL}/view/${token}`
        : null;

      return res.status(201).json({
        message: 'Réponse enregistrée avec succès !',
        link
      });
    } catch (err) {
      console.error('Erreur en sauvegardant la réponse :', err);
      return res.status(500).json({ message: 'Erreur en sauvegardant la réponse' });
    }
  }
);

module.exports = router;
