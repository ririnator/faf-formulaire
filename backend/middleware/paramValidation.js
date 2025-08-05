const { param, validationResult } = require('express-validator');

// Validation pour les tokens hexadécimaux de 64 caractères
const validateToken = [
  param('token')
    .isLength({ min: 64, max: 64 })
    .withMessage('Le token doit faire exactement 64 caractères')
    .matches(/^[a-f0-9]{64}$/i)
    .withMessage('Le token doit contenir uniquement des caractères hexadécimaux'),
];

// Validation pour les IDs MongoDB
const validateMongoId = [
  param('id')
    .isMongoId()
    .withMessage('ID MongoDB invalide'),
];

// Validation pour les paramètres de pagination
const validatePagination = [
  param('page')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('La page doit être un entier entre 1 et 1000'),
  param('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('La limite doit être un entier entre 1 et 100'),
];

// Validation pour les mois au format YYYY-MM
const validateMonth = [
  param('month')
    .optional()
    .matches(/^\d{4}-\d{2}$/)
    .withMessage('Le mois doit être au format YYYY-MM')
    .custom((value) => {
      const [year, month] = value.split('-').map(Number);
      const currentYear = new Date().getFullYear();
      
      if (year < 2020 || year > currentYear + 1) {
        throw new Error(`L'année doit être entre 2020 et ${currentYear + 1}`);
      }
      
      if (month < 1 || month > 12) {
        throw new Error('Le mois doit être entre 01 et 12');
      }
      
      return true;
    }),
];

// Middleware de gestion des erreurs de validation des paramètres
function handleParamValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstError = errors.array()[0];
    return res.status(400).json({
      error: 'Paramètre invalide',
      field: firstError.param,
      message: firstError.msg,
      value: firstError.value
    });
  }
  next();
}

// Validation personnalisée pour les tokens avec logging de sécurité
function validateTokenSecurity(req, res, next) {
  const { token } = req.params;
  
  // Log des tentatives d'accès avec des tokens suspects
  if (token && (token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token))) {
    console.warn(`🚨 Tentative d'accès avec token suspect: ${token.substring(0, 8)}... depuis ${req.ip}`);
  }
  
  next();
}

// Middleware de rate limiting spécifique aux tokens
const tokenRateLimit = require('express-rate-limit')({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Max 10 tentatives par IP
  message: {
    error: 'Trop de tentatives d\'accès aux tokens',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Rate limit par IP + token pour éviter le brute force
    return `${req.ip}-${req.params.token?.substring(0, 8) || 'no-token'}`;
  }
});

module.exports = {
  validateToken,
  validateMongoId,
  validatePagination,
  validateMonth,
  handleParamValidationErrors,
  validateTokenSecurity,
  tokenRateLimit
};