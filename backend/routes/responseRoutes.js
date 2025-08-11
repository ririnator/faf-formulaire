// backend/routes/responseRoutes.js

const express = require('express');
const crypto = require('crypto');
const router = express.Router();

const Response = require('../models/Response');
const User = require('../models/User');
const { validateResponseStrict, validateResponseConditional, handleValidationErrors, sanitizeResponse } = require('../middleware/validation');
const { createFormBodyParser } = require('../middleware/bodyParser');
const { detectAuthMethod, requireAuth } = require('../middleware/hybridAuth');

// POST /api/response with form-specific body parser (2MB limit for text data)
router.post(
  '/',
  createFormBodyParser(),
  detectAuthMethod,
  validateResponseConditional,
  handleValidationErrors,
  sanitizeResponse,
  async (req, res) => {

    const { responses } = req.body;
    const month = new Date().toISOString().slice(0, 7); // "YYYY-MM"
    
    let responseData;

  try {
    let saved;

    if (req.authMethod === 'user') {
      // NOUVEAU système - utilisateur connecté
      const currentUser = await User.findById(req.session.userId);
      if (!currentUser) {
        return res.status(401).json({
          success: false,
          error: 'Utilisateur introuvable'
        });
      }

      responseData = {
        userId: currentUser._id,
        responses,
        month,
        isAdmin: currentUser.role === 'admin',
        authMethod: 'user'
        // Pas de token, pas de name
      };

      // Pour les admins, vérifier qu'il n'y en a pas déjà un
      if (currentUser.role === 'admin') {
        const existingAdmin = await Response.findOne({
          month,
          isAdmin: true,
          $or: [
            { authMethod: 'user' },
            { authMethod: 'token' }
          ]
        });
        
        if (existingAdmin) {
          return res.status(409).json({
            success: false,
            error: 'Une réponse admin existe déjà pour ce mois'
          });
        }
      }

      // Vérifier que l'utilisateur n'a pas déjà répondu ce mois
      const existing = await Response.findOne({
        userId: currentUser._id,
        month
      });

      if (existing) {
        return res.status(409).json({
          success: false,
          error: 'Vous avez déjà répondu ce mois-ci'
        });
      }

      saved = new Response(responseData);
      await saved.save();

      // Incrémenter le compteur de réponses de l'utilisateur
      await currentUser.incrementResponseCount();

    } else {
      // LEGACY système - compatibilité backward (ou aucune auth = mode legacy)
      const { name } = req.body;
      if (!name || name.trim().length === 0) {
        return res.status(400).json({
          success: false,
          error: 'Le nom est requis pour le mode legacy'
        });
      }

      const isAdmin = name.trim().toLowerCase() === process.env.FORM_ADMIN_NAME?.toLowerCase();
      const token = isAdmin ? null : crypto.randomBytes(32).toString('hex');

      responseData = {
        name: name.trim(),
        responses,
        month,
        isAdmin,
        token,
        authMethod: 'token'
      };

      if (isAdmin) {
        // Pour les admin legacy, utiliser opération atomique
        saved = await Response.findOneAndUpdate(
          { month, isAdmin: true },
          {
            $setOnInsert: responseData
          },
          { 
            upsert: true, 
            new: true,
            runValidators: true,
            setDefaultsOnInsert: true
          }
        );

        // Vérifier conflit
        if (saved.name !== name.trim()) {
          return res.status(409).json({
            success: false,
            error: 'Une réponse admin existe déjà pour ce mois'
          });
        }
      } else {
        // Utilisateur normal legacy
        saved = new Response(responseData);
        await saved.save();
      }
    }

    // Réponse adaptée selon le système
    const baseUrl = process.env.APP_BASE_URL || 'http://localhost:3000';
    let response = {
      success: true,
      message: 'Réponse enregistrée avec succès !',
      responseId: saved._id
    };

    if (req.authMethod === 'user') {
      // Mode utilisateur : pas de token, accès via dashboard
      response.dashboardUrl = `${baseUrl}/dashboard`;
    } else {
      // Mode legacy : token pour accès direct
      response.link = saved.token ? `${baseUrl}/view/${saved.token}` : null;
    }

    return res.status(201).json(response);

  } catch (err) {
    console.error('Erreur en sauvegardant la réponse :', err);
    
    // Messages d'erreur plus spécifiques
    if (err.code === 11000) {
      return res.status(409).json({ 
        success: false,
        error: 'Une réponse existe déjà pour cette période'
      });
    }
    
    return res.status(500).json({ 
      success: false,
      error: 'Erreur en sauvegardant la réponse' 
    });
  }
  }
);

module.exports = router;
