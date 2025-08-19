const express = require('express');
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Response = require('../models/Response');
const { HTTP_STATUS, APP_CONSTANTS } = require('../constants');
const { authLimiters } = require('../middleware/authRateLimit');
const { createEmailDomainMiddleware } = require('../middleware/emailDomainValidation');
const SecureLogger = require('../utils/secureLogger');
const router = express.Router();

// Validation rules
const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: APP_CONSTANTS.MIN_USERNAME_LENGTH, max: APP_CONSTANTS.MAX_USERNAME_LENGTH })
    .withMessage('Le nom d\'utilisateur doit contenir entre 3 et 30 caractères')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Le nom d\'utilisateur ne peut contenir que des lettres, chiffres, tirets et underscores'),
  
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Email invalide'),
  
  body('password')
    .isLength({ min: APP_CONSTANTS.MIN_PASSWORD_LENGTH })
    .withMessage('Le mot de passe doit contenir au moins 6 caractères'),
  
  
  body('migrateToken')
    .optional()
    .isLength({ min: 64, max: 64 })
    .withMessage('Token de migration invalide (doit faire 64 caractères)')
];

const loginValidation = [
  body('login')
    .trim()
    .notEmpty()
    .withMessage('Email ou nom d\'utilisateur requis'),
  
  body('password')
    .notEmpty()
    .withMessage('Mot de passe requis')
];

// Email domain validation middleware for registration
const emailDomainValidation = createEmailDomainMiddleware({
  emailField: 'email',
  logBlocked: true
});

// POST /api/auth/register - Inscription avec rate limiting
router.post('/register', authLimiters.register, emailDomainValidation, registerValidation, async (req, res) => {
  try {
    // Vérifier les erreurs de validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: 'Données invalides',
        details: errors.array()
      });
    }

    const { username, email, password, profile, migrateToken } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      const field = existingUser.email === email ? 'email' : 'nom d\'utilisateur';
      return res.status(HTTP_STATUS.CONFLICT).json({ 
        error: `Ce ${field} est déjà utilisé`
      });
    }

    // Gestion de la migration si token fourni
    let migrationData = { source: 'registration' };
    let migratedResponses = 0;
    
    if (migrateToken) {
      const legacyResponse = await Response.findOne({ token: migrateToken });
      if (legacyResponse && legacyResponse.name) {
        migrationData = {
          legacyName: legacyResponse.name,
          migratedAt: new Date(),
          source: 'migration'
        };
      }
    }

    // Créer le nouvel utilisateur
    const user = new User({
      username,
      email,
      password, // Sera hashé automatiquement par le pre-save hook
      profile: profile || {},
      metadata: {
        registeredAt: new Date(),
        lastActive: new Date()
      },
      migrationData
    });

    await user.save();

    // Si migration : associer les anciennes réponses avec transaction
    if (migrateToken && migrationData.legacyName) {
      const session = await mongoose.startSession();
      
      try {
        await session.withTransaction(async () => {
          // Vérifier que l'utilisateur existe toujours
          const userStillExists = await User.exists({ _id: user._id }).session(session);
          if (!userStillExists) {
            throw new Error('User creation failed during migration');
          }

          const migrationResult = await Response.updateMany(
            { 
              name: migrationData.legacyName,
              authMethod: { $ne: 'user' }
            },
            { 
              $set: { 
                userId: user._id,
                authMethod: 'user'
              },
              $unset: { 
                token: 1,
                name: 1
              }
            },
            { session }
          );
          
          migratedResponses = migrationResult.modifiedCount;
          
          // Validation avant mise à jour
          if (migratedResponses > 0) {
            user.metadata.responseCount = migratedResponses;
            await user.save({ session });
          }
        });
      } catch (migrationError) {
        // Log error safely without sensitive data - use specialized migration error logging
        SecureLogger.logMigrationError('registration_migration', 'transaction_failed', 0);
        
        // Migration failed but user created - continue with warning
        // Don't fail the entire registration
        migratedResponses = 0;
        migrationData.error = 'Migration partially failed';
      } finally {
        await session.endSession();
      }
    }

    // Créer la session
    req.session.userId = user._id;
    req.session.user = user.toPublicJSON();

    res.status(201).json({
      message: 'Compte créé avec succès',
      user: user.toPublicJSON(),
      migrated: migratedResponses > 0,
      migratedCount: migratedResponses,
      redirect: '/dashboard'
    });

  } catch (error) {
    SecureLogger.logError('Registration failed', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/login - Connexion avec rate limiting
router.post('/login', authLimiters.login, loginValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: 'Données invalides',
        details: errors.array()
      });
    }

    const { login, password } = req.body;

    // Chercher par email ou username
    const user = await User.findOne({
      $or: [
        { email: login.toLowerCase() },
        { username: login }
      ],
      'metadata.isActive': true
    });

    if (!user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Email/nom d\'utilisateur ou mot de passe incorrect'
      });
    }

    // Vérifier le mot de passe
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        error: 'Email/nom d\'utilisateur ou mot de passe incorrect'
      });
    }

    // Mettre à jour la dernière activité
    await user.updateLastActive();

    // Créer la session
    req.session.userId = user._id;
    req.session.user = user.toPublicJSON();

    res.json({
      message: 'Connexion réussie',
      user: user.toPublicJSON(),
      redirect: '/dashboard'
    });

  } catch (error) {
    SecureLogger.logError('Login failed', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/logout - Déconnexion
router.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        SecureLogger.logError('Logout failed', err);
        return res.status(500).json({ error: 'Erreur lors de la déconnexion' });
      }
      res.json({ message: 'Déconnexion réussie' });
    });
  } else {
    res.json({ message: 'Aucune session active' });
  }
});

// GET /api/auth/me - Profil utilisateur
router.get('/me', async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false,
        error: 'Non authentifié' 
      });
    }

    const user = await User.findById(req.session.userId)
      .select('-password'); // Exclure le mot de passe

    if (!user || !user.metadata.isActive) {
      req.session.destroy();
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ 
        success: false,
        error: 'Utilisateur introuvable' 
      });
    }

    res.json({
      success: true,
      data: {
        user: user.toPublicJSON()
      }
    });

  } catch (error) {
    SecureLogger.logError('Profile retrieval failed', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ 
      success: false,
      error: 'Erreur serveur' 
    });
  }
});

// PUT /api/auth/profile - Mettre à jour le profil avec rate limiting
router.put('/profile', authLimiters.profileUpdate, [
  
  body('profile.firstName')
    .optional()
    .trim()
    .isLength({ max: 30 })
    .withMessage('Le prénom ne peut dépasser 30 caractères'),
  
  body('profile.lastName')
    .optional()
    .trim()
    .isLength({ max: 30 })
    .withMessage('Le nom ne peut dépasser 30 caractères'),
  
  body('profile.profession')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('La profession ne peut dépasser 50 caractères'),
  
  body('profile.location')
    .optional()
    .trim()
    .isLength({ max: 50 })
    .withMessage('La localisation ne peut dépasser 50 caractères')
    
], async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: 'Non authentifié' });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: 'Données invalides',
        details: errors.array()
      });
    }

    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable' });
    }

    // Mettre à jour les champs autorisés
    const { profile } = req.body;
    if (profile) {
      if (profile.firstName !== undefined) user.profile.firstName = profile.firstName;
      if (profile.lastName !== undefined) user.profile.lastName = profile.lastName;
      if (profile.profession !== undefined) user.profile.profession = profile.profession;
      if (profile.location !== undefined) user.profile.location = profile.location;
      if (profile.dateOfBirth !== undefined) user.profile.dateOfBirth = profile.dateOfBirth;
    }

    await user.save();
    
    // Mettre à jour la session
    req.session.user = user.toPublicJSON();

    res.json({
      message: 'Profil mis à jour',
      user: user.toPublicJSON()
    });

  } catch (error) {
    SecureLogger.logError('Profile update failed', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/claim-responses - Récupérer des réponses legacy
router.post('/claim-responses', [
  body('legacyName')
    .trim()
    .notEmpty()
    .withMessage('Nom legacy requis'),
  body('months')
    .optional()
    .isArray()
    .withMessage('Les mois doivent être un tableau')
], async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: 'Authentification requise' });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(HTTP_STATUS.BAD_REQUEST).json({ 
        error: 'Données invalides',
        details: errors.array()
      });
    }

    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(HTTP_STATUS.UNAUTHORIZED).json({ error: 'Utilisateur introuvable' });
    }

    const { legacyName, months } = req.body;

    // Construire la query pour trouver les réponses à récupérer
    let query = {
      name: legacyName.trim(),
      authMethod: { $ne: 'user' },
      userId: { $exists: false }
    };

    if (months && months.length > 0) {
      query.month = { $in: months };
    }

    // Trouver les réponses à récupérer
    const responsesToClaim = await Response.find(query);

    if (responsesToClaim.length === 0) {
      return res.status(404).json({
        error: 'Aucune réponse trouvée pour ce nom',
        searchedName: legacyName.trim()
      });
    }

    // Associer les réponses à l'utilisateur
    const result = await Response.updateMany(
      query,
      {
        $set: {
          userId: user._id,
          authMethod: 'user'
        },
        $unset: {
          name: 1,
          token: 1
        }
      }
    );

    // Mettre à jour le compteur de réponses de l'utilisateur
    user.metadata.responseCount += result.modifiedCount;
    await user.save();

    res.json({
      message: `${result.modifiedCount} réponse(s) récupérée(s) avec succès`,
      claimedCount: result.modifiedCount,
      responsesDetails: responsesToClaim.map(r => ({
        month: r.month,
        responseCount: r.responses.length,
        createdAt: r.createdAt
      }))
    });

  } catch (error) {
    SecureLogger.logError('Response retrieval failed', error);
    res.status(HTTP_STATUS.INTERNAL_SERVER_ERROR).json({ error: 'Erreur serveur' });
  }
});

module.exports = router;