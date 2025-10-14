/**
 * Valide un username
 * @param {string} username
 * @returns {boolean}
 */
function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;

  // 3-20 caractères, lowercase, alphanumériques + tirets/underscores
  const regex = /^[a-z0-9_-]{3,20}$/;
  return regex.test(username);
}

/**
 * Valide un email
 * @param {string} email
 * @returns {boolean}
 */
function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;

  // Format email basique (pas d'espaces, @ et . requis)
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

/**
 * Valide un password
 * @param {string} password
 * @returns {boolean}
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;

  // Min 8 chars, 1 majuscule, 1 chiffre
  const regex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
  return regex.test(password);
}

/**
 * Échappe les caractères HTML dangereux
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  if (!text || typeof text !== 'string') return '';

  const map = {
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
    "'": '&#x27;'
  };

  return text.replace(/[<>&"']/g, (m) => map[m]);
}

/**
 * Normalise un username (lowercase, trim)
 * @param {string} username
 * @returns {string}
 */
function normalizeUsername(username) {
  if (!username || typeof username !== 'string') return '';
  return username.trim().toLowerCase();
}

/**
 * Normalise un email (lowercase, trim)
 * @param {string} email
 * @returns {string}
 */
function normalizeEmail(email) {
  if (!email || typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

/**
 * Vérifie si une URL est une URL Cloudinary valide
 * Whitelist pour permettre les URLs d'images uploadées
 *
 * @param {string} url - URL à vérifier
 * @returns {boolean} True si URL Cloudinary valide
 */
function isCloudinaryUrl(url) {
  if (!url || typeof url !== 'string') {
    return false;
  }

  // Pattern strict pour Cloudinary
  const cloudinaryPattern = /^https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/image\/upload\/.+$/;

  // Vérifier le pattern
  if (!cloudinaryPattern.test(url)) {
    return false;
  }

  // Vérifier qu'il n'y a pas de caractères suspects (XSS attempts)
  const suspiciousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+=/i, // onclick, onerror, etc.
    /<iframe/i,
    /<object/i,
    /<embed/i
  ];

  return !suspiciousPatterns.some(pattern => pattern.test(url));
}

/**
 * Valide et nettoie une réponse
 * Échappe le HTML sauf pour les URLs Cloudinary
 *
 * @param {string} text - Texte à valider
 * @returns {string} Texte validé et sécurisé
 */
function cleanResponse(text) {
  if (!text || typeof text !== 'string') {
    return '';
  }

  // Trim whitespace
  text = text.trim();

  // Si c'est une URL Cloudinary, ne pas échapper
  if (isCloudinaryUrl(text)) {
    return text;
  }

  // Sinon, échapper le HTML
  return escapeHtml(text);
}

/**
 * Valide un tableau de réponses au formulaire
 *
 * @param {Array} responses - Tableau de { question, answer }
 * @returns {Object} { valid: boolean, errors: Array, cleaned: Array }
 */
function validateResponses(responses) {
  const errors = [];
  const cleaned = [];

  // Vérifier que c'est un tableau
  if (!Array.isArray(responses)) {
    return {
      valid: false,
      errors: ['Responses must be an array'],
      cleaned: []
    };
  }

  // Vérifier le nombre de réponses (10-11 questions)
  if (responses.length < 10 || responses.length > 11) {
    errors.push(`Invalid number of responses: ${responses.length} (expected 10-11)`);
  }

  // Valider chaque réponse
  responses.forEach((response, index) => {
    // Vérifier la structure
    if (!response || typeof response !== 'object') {
      errors.push(`Response ${index + 1}: Invalid structure`);
      return;
    }

    if (!response.question || !response.answer) {
      errors.push(`Response ${index + 1}: Missing question or answer`);
      return;
    }

    // Valider les longueurs
    const question = String(response.question).trim();
    const answer = String(response.answer).trim();

    if (question.length === 0) {
      errors.push(`Response ${index + 1}: Question cannot be empty`);
    }

    if (question.length > 500) {
      errors.push(`Response ${index + 1}: Question too long (max 500 chars)`);
    }

    if (answer.length === 0) {
      errors.push(`Response ${index + 1}: Answer cannot be empty`);
    }

    if (answer.length > 10000) {
      errors.push(`Response ${index + 1}: Answer too long (max 10000 chars)`);
    }

    // Nettoyer et ajouter
    cleaned.push({
      question: escapeHtml(question),
      answer: cleanResponse(answer)
    });
  });

  return {
    valid: errors.length === 0,
    errors,
    cleaned
  };
}

/**
 * Valide un nom d'utilisateur (pour les réponses)
 *
 * @param {string} name - Nom à valider
 * @returns {Object} { valid: boolean, error: string|null }
 */
function validateName(name) {
  if (!name || typeof name !== 'string') {
    return { valid: false, error: 'Name is required' };
  }

  const trimmed = name.trim();

  if (trimmed.length < 2) {
    return { valid: false, error: 'Name must be at least 2 characters' };
  }

  if (trimmed.length > 100) {
    return { valid: false, error: 'Name must be at most 100 characters' };
  }

  return { valid: true, error: null };
}

/**
 * Valide le champ honeypot (anti-spam)
 *
 * @param {string} honeypot - Valeur du champ honeypot
 * @returns {boolean} True si valide (vide), False si spam détecté
 */
function validateHoneypot(honeypot) {
  // Le honeypot doit être vide (les bots le remplissent)
  return !honeypot || honeypot.trim() === '';
}

module.exports = {
  validateUsername,
  validateEmail,
  validatePassword,
  escapeHtml,
  normalizeUsername,
  normalizeEmail,
  isCloudinaryUrl,
  cleanResponse,
  validateResponses,
  validateName,
  validateHoneypot
};
