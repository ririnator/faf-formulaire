const { body, validationResult } = require('express-validator');

const validateResponse = [
  body('name')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Le nom est requis et doit faire moins de 100 caractères'),
  
  body('responses')
    .isArray({ min: 1 })
    .withMessage('Les réponses doivent être un tableau non vide'),
  
  body('responses.*.question')
    .trim()
    .isLength({ min: 1 })
    .withMessage('Chaque question est requise'),
  
  body('responses.*.answer')
    .trim()
    .isLength({ min: 1 })
    .withMessage('Chaque réponse est requise'),

  // Protection honeypot
  body('website')
    .isEmpty()
    .withMessage('Champ honeypot détecté')
];

const validateLogin = [
  body('username')
    .trim()
    .isLength({ min: 1 })
    .withMessage('Nom d\'utilisateur requis'),
  
  body('password')
    .isLength({ min: 1 })
    .withMessage('Mot de passe requis')
];

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Erreur de validation',
      details: errors.array()
    });
  }
  next();
}

module.exports = {
  validateResponse,
  validateLogin,
  handleValidationErrors
};