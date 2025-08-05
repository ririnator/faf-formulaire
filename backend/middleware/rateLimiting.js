const rateLimit = require('express-rate-limit');

const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 3,
  message: { message: "Trop de soumissions. Réessaie dans 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,
  message: { message: "Trop de requêtes admin. Réessaie plus tard." }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,
  message: { message: "Trop de tentatives de connexion. Réessaie dans 15 minutes." }
});

module.exports = {
  formLimiter,
  adminLimiter,
  loginLimiter
};