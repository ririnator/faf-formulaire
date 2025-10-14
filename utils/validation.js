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

module.exports = {
  validateUsername,
  validateEmail,
  validatePassword,
  escapeHtml,
  normalizeUsername,
  normalizeEmail
};
