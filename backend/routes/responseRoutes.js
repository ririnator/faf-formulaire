// backend/routes/responseRoutes.js

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const Response = require('../models/Response');
const { validateResponseStrict, handleValidationErrors, sanitizeResponse } = require('../middleware/validation');
const { createFormBodyParser } = require('../middleware/bodyParser');

// POST /api/response with form-specific body parser (2MB limit for text data)
router.post(
  '/',
  createFormBodyParser(),
  validateResponseStrict,
  handleValidationErrors,
  sanitizeResponse,
  async (req, res) => {

    // 3) normalisation des données
    const { name, responses } = req.body;
    const month = new Date().toISOString().slice(0, 7); // "YYYY-MM"
    const isAdmin = name.trim().toLowerCase() === process.env.FORM_ADMIN_NAME?.toLowerCase();
    // seul l’ami reçoit un token et pourra consulter
    const token = isAdmin 
    ? undefined 
    : crypto.randomBytes(32).toString('hex');

  try {
    let saved;
    
    // Pour les admin, utiliser une opération atomique pour éviter les race conditions
    if (isAdmin) {
      const result = await Response.findOneAndUpdate(
        { month, isAdmin: true },
        {
          $setOnInsert: {
            name,
            responses,
            month,
            isAdmin: true,
            token: null,
            createdAt: new Date()
          }
        },
        { 
          upsert: true, 
          new: true,
          runValidators: true,
          setDefaultsOnInsert: true
        }
      );

      // Vérifier si le document a été créé ou s'il existait déjà
      if (result.name !== name) {
        return res.status(409).json({
          message: 'Une réponse admin existe déjà pour ce mois.'
        });
      }

      saved = result;
    } else {
      // Pour les utilisateurs normaux, création standard
      const newResponse = new Response({
        name,
        responses,
        month,
        isAdmin,
        token
      });
      saved = await newResponse.save();
    }

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
