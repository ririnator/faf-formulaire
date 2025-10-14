const jwt = require('jsonwebtoken');

/**
 * Génère un JWT token
 * @param {Object} payload - Données à encoder (ex: { sub: adminId, username })
 * @param {string} expiresIn - Durée de validité (défaut: 7 jours)
 * @returns {string} Token JWT
 */
function generateToken(payload, expiresIn = '7d') {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  return jwt.sign(payload, secret, {
    expiresIn,
    issuer: 'faf-multitenant',
    audience: 'faf-users'
  });
}

/**
 * Vérifie un JWT token
 * @param {string} token - Token à vérifier
 * @returns {Object|null} Payload décodé ou null si invalide
 */
function verifyToken(token) {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  try {
    return jwt.verify(token, secret, {
      issuer: 'faf-multitenant',
      audience: 'faf-users'
    });
  } catch (error) {
    console.error('JWT verification failed:', error.message);
    return null;
  }
}

/**
 * Décode un JWT sans vérification (pour debug uniquement)
 * @param {string} token - Token à décoder
 * @returns {Object|null} Payload décodé
 */
function decodeToken(token) {
  try {
    return jwt.decode(token);
  } catch (error) {
    return null;
  }
}

module.exports = {
  generateToken,
  verifyToken,
  decodeToken
};
