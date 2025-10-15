/**
 * Test endpoint - Vérifie tous les imports des routes auth
 */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // Imports de login.js
    const { supabaseAdmin } = require('../utils/supabase');
    const { generateToken } = require('../utils/jwt');
    const bcrypt = require('bcrypt');

    // Imports supplémentaires de register.js
    const {
      validateUsername,
      validateEmail,
      validatePassword,
      normalizeUsername,
      normalizeEmail
    } = require('../utils/validation');

    // Test basique
    const normalized = normalizeUsername('TestUser');
    const isValid = validateUsername(normalized);

    return res.status(200).json({
      success: true,
      importsWork: true,
      supabaseAvailable: !!supabaseAdmin,
      generateTokenAvailable: !!generateToken,
      bcryptAvailable: !!bcrypt,
      validationWorks: isValid,
      normalizedUsername: normalized
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message,
      stack: error.stack,
      name: error.name
    });
  }
};
