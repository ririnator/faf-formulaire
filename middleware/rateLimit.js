/**
 * Middleware de rate limiting
 *
 * Limite le nombre de requêtes par IP dans une fenêtre de temps
 * Implémentation en mémoire (pour Vercel serverless)
 */

// Store en mémoire pour tracking des IPs
// Format: { ip: { count: number, resetTime: timestamp } }
const requestStore = new Map();

// Nettoyage automatique toutes les 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of requestStore.entries()) {
    if (now > data.resetTime) {
      requestStore.delete(ip);
    }
  }
}, 5 * 60 * 1000);

/**
 * Crée un middleware de rate limiting
 *
 * @param {Object} options - Options de configuration
 * @param {number} options.windowMs - Fenêtre de temps en ms (défaut: 15 min)
 * @param {number} options.max - Nombre max de requêtes (défaut: 3)
 * @param {string} options.message - Message d'erreur personnalisé
 * @returns {Function} Middleware Express/Vercel
 */
function createRateLimiter(options = {}) {
  const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes par défaut
  const max = options.max || 3; // 3 requêtes max par défaut
  const message = options.message || 'Too many requests, please try again later';

  return function rateLimitMiddleware(req, res, next) {
    // Extraire l'IP (Vercel fournit x-forwarded-for ou x-real-ip)
    const ip =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.headers['x-real-ip'] ||
      req.connection?.remoteAddress ||
      'unknown';

    const now = Date.now();

    // Récupérer ou initialiser les données de l'IP
    let ipData = requestStore.get(ip);

    if (!ipData || now > ipData.resetTime) {
      // Première requête ou fenêtre expirée
      ipData = {
        count: 1,
        resetTime: now + windowMs
      };
      requestStore.set(ip, ipData);

      // Ajouter les headers de rate limiting
      res.setHeader('X-RateLimit-Limit', max);
      res.setHeader('X-RateLimit-Remaining', max - 1);
      res.setHeader('X-RateLimit-Reset', new Date(ipData.resetTime).toISOString());

      return next ? next() : undefined;
    }

    // Incrémenter le compteur
    ipData.count++;

    // Vérifier si la limite est dépassée
    if (ipData.count > max) {
      const retryAfter = Math.ceil((ipData.resetTime - now) / 1000); // en secondes

      res.setHeader('X-RateLimit-Limit', max);
      res.setHeader('X-RateLimit-Remaining', 0);
      res.setHeader('X-RateLimit-Reset', new Date(ipData.resetTime).toISOString());
      res.setHeader('Retry-After', retryAfter);

      return res.status(429).json({
        success: false,
        error: 'Rate limit exceeded',
        message: message,
        retryAfter: retryAfter
      });
    }

    // Requête autorisée
    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', max - ipData.count);
    res.setHeader('X-RateLimit-Reset', new Date(ipData.resetTime).toISOString());

    return next ? next() : undefined;
  };
}

/**
 * Réinitialise le store (utile pour les tests)
 */
function resetStore() {
  requestStore.clear();
}

/**
 * Récupère les stats du store (utile pour debug)
 */
function getStoreStats() {
  return {
    size: requestStore.size,
    entries: Array.from(requestStore.entries()).map(([ip, data]) => ({
      ip,
      count: data.count,
      resetTime: new Date(data.resetTime).toISOString()
    }))
  };
}

module.exports = {
  createRateLimiter,
  resetStore,
  getStoreStats
};
