const { body, validationResult } = require('express-validator');

const validateResponseStrict = [
  body('name')
    .trim()
    .escape()
    .isLength({ min: 2, max: 100 })
    .withMessage('Le nom doit contenir entre 2 et 100 caractères'),
  
  body('responses')
    .isArray({ min: 1, max: 20 })
    .withMessage('Il faut entre 1 et 20 réponses'),
  
  body('responses.*.question')
    .trim()
    .escape()
    .notEmpty()
    .isLength({ max: 500 })
    .withMessage('Chaque question doit être précisée (max 500 caractères)'),
  
  body('responses.*.answer')
    .trim()
    .escape()
    .notEmpty()
    .isLength({ max: 10000 })
    .withMessage('Chaque réponse ne peut pas être vide (max 10000 caractères)'),

  body('website')
    .optional()
    .isEmpty()
    .withMessage('Spam détecté')
];

const validateResponse = [
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
  body('website')
    .optional()
    .isEmpty()
    .withMessage('Spam détecté')
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
    const firstError = errors.array()[0];
    return res.status(400).json({
      message: firstError.msg,
      field: firstError.path
    });
  }
  next();
}

function sanitizeResponse(req, res, next) {
  if (req.body.responses && Array.isArray(req.body.responses)) {
    req.body.responses = req.body.responses.map(response => ({
      question: response.question?.toString().substring(0, 500) || '',
      answer: response.answer?.toString().substring(0, 10000) || ''
    }));
  }
  next();
}

module.exports = {
  validateResponse,
  validateResponseStrict,
  validateLogin,
  handleValidationErrors,
  sanitizeResponse
};