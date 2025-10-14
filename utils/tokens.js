/**
 * Utilitaires de génération de tokens
 *
 * Génère des tokens uniques et sécurisés pour les liens privés
 */

const crypto = require('crypto');

/**
 * Génère un token aléatoire unique de 64 caractères
 * Utilise crypto.randomBytes pour une sécurité cryptographique
 *
 * @returns {string} Token hexadécimal de 64 caractères
 *
 * @example
 * const token = generateToken();
 * // "a3f8c92d..."
 */
function generateToken() {
  // Générer 32 bytes aléatoires → 64 caractères en hexadécimal
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Génère un token court (pour tests ou identifiants courts)
 *
 * @param {number} length - Longueur en bytes (défaut: 16)
 * @returns {string} Token hexadécimal
 *
 * @example
 * const shortToken = generateShortToken(8);
 * // "4f3a2b1c5d6e7f8a"
 */
function generateShortToken(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Vérifie si un token a le bon format
 *
 * @param {string} token - Token à valider
 * @returns {boolean} True si valide
 */
function isValidToken(token) {
  if (!token || typeof token !== 'string') {
    return false;
  }

  // Token doit être de 64 caractères hexadécimaux
  const hexRegex = /^[a-f0-9]{64}$/i;
  return hexRegex.test(token);
}

module.exports = {
  generateToken,
  generateShortToken,
  isValidToken
};
