const { body, validationResult } = require('express-validator');

// Fonction pour détecter si une chaîne est une URL Cloudinary valide ET sûre
function isCloudinaryUrl(str) {
  if (!str || typeof str !== 'string') return false;
  
  // Vérifier le pattern Cloudinary de base
  const cloudinaryPattern = /^https:\/\/res\.cloudinary\.com\/[\w-]+\/image\/upload\/.+$/;
  if (!str.match(cloudinaryPattern)) return false;
  
  // Vérifier qu'il n'y a pas de caractères dangereux dans l'URL
  // Refuser les URLs avec <, >, ", ou code JavaScript (mais autoriser ' dans les noms de fichiers)
  const dangerousChars = /<|>|"|javascript:|data:|vbscript:|onclick|onerror|onload|script/i;
  if (dangerousChars.test(str)) return false;
  
  return true;
}

// Fonction d'escape personnalisée qui préserve les URLs Cloudinary
function smartEscape(str) {
  if (!str || typeof str !== 'string') return str;
  
  // Si c'est une URL Cloudinary valide, ne pas l'encoder
  if (isCloudinaryUrl(str)) {
    return str; // Garder l'URL intacte
  }
  
  // Sinon, appliquer l'escape HTML standard pour la sécurité
  const escapeMap = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  };
  
  return str.replace(/[&<>"'\/]/g, (char) => escapeMap[char]);
}

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
    .exists({ checkNull: true, checkFalsy: true })
    .withMessage('La question ne peut pas être nulle ou vide')
    .trim()
    .escape()
    .notEmpty()
    .isLength({ max: 500 })
    .withMessage('Chaque question doit être précisée (max 500 caractères)'),
  
  body('responses.*.answer')
    .exists({ checkNull: true, checkFalsy: true })
    .withMessage('La réponse ne peut pas être nulle ou vide')
    .trim()
    .custom((value) => {
      // Appliquer smartEscape au lieu de .escape() pour préserver les URLs Cloudinary
      return smartEscape(value);
    })
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
    req.body.responses = req.body.responses
      .filter(response => response !== null && response !== undefined) // Remove null/undefined elements
      .map(response => {
        if (typeof response !== 'object' || response === null) {
          return { question: '', answer: '' };
        }
        
        // Appliquer smartEscape pour préserver les URLs Cloudinary tout en protégeant contre XSS
        const question = response.question != null ? response.question.toString().substring(0, 500) : '';
        const answer = response.answer != null ? response.answer.toString().substring(0, 10000) : '';
        
        return {
          question: smartEscape(question),
          answer: smartEscape(answer)
        };
      });
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