const { supabaseAdmin } = require('../../utils/supabase');
const { generateToken } = require('../../utils/jwt');
const {
  validateUsername,
  validateEmail,
  validatePassword,
  normalizeUsername,
  normalizeEmail
} = require('../../utils/validation');
const bcrypt = require('bcrypt');

/**
 * API Route: POST /api/auth/register
 * Inscription d'un nouvel admin
 */
module.exports = async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { username, email, password, website } = req.body;

    // 1. Honeypot validation (anti-bot)
    if (website) {
      return res.status(400).json({ error: 'Validation failed' });
    }

    // 2. Validation des champs requis
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Tous les champs sont requis (username, email, password).'
      });
    }

    // 3. Normalisation
    const normalizedUsername = normalizeUsername(username);
    const normalizedEmail = normalizeEmail(email);

    // 4. Validation du username
    if (!validateUsername(normalizedUsername)) {
      return res.status(400).json({
        error: 'Username invalide. 3-20 caractères, lowercase, alphanumériques et tirets uniquement.'
      });
    }

    // 5. Validation de l'email
    if (!validateEmail(normalizedEmail)) {
      return res.status(400).json({
        error: 'Email invalide.'
      });
    }

    // 6. Validation du password
    if (!validatePassword(password)) {
      return res.status(400).json({
        error: 'Mot de passe trop faible. Min 8 caractères, 1 majuscule, 1 chiffre.'
      });
    }

    // 7. Vérifier username unique
    const { data: existingUser, error: userError } = await supabaseAdmin
      .from('admins')
      .select('id')
      .eq('username', normalizedUsername)
      .maybeSingle();

    if (userError && userError.code !== 'PGRST116') {
      console.error('Error checking username:', userError);
      return res.status(500).json({ error: 'Erreur lors de la vérification du username.' });
    }

    if (existingUser) {
      return res.status(409).json({
        error: 'Ce nom d\'utilisateur est déjà pris.'
      });
    }

    // 8. Vérifier email unique
    const { data: existingEmail, error: emailError } = await supabaseAdmin
      .from('admins')
      .select('id')
      .eq('email', normalizedEmail)
      .maybeSingle();

    if (emailError && emailError.code !== 'PGRST116') {
      console.error('Error checking email:', emailError);
      return res.status(500).json({ error: 'Erreur lors de la vérification de l\'email.' });
    }

    if (existingEmail) {
      return res.status(409).json({
        error: 'Cet email est déjà utilisé.'
      });
    }

    // 9. Hash du password (10 rounds)
    const passwordHash = await bcrypt.hash(password, 10);

    // 10. Insertion dans Supabase
    const { data: newAdmin, error: insertError } = await supabaseAdmin
      .from('admins')
      .insert({
        username: normalizedUsername,
        email: normalizedEmail,
        password_hash: passwordHash
      })
      .select('id, username, email')
      .single();

    if (insertError) {
      console.error('Insert error:', insertError);
      return res.status(500).json({
        error: 'Erreur lors de la création du compte.'
      });
    }

    // 11. Génération JWT token
    const token = generateToken({
      sub: newAdmin.id,
      username: newAdmin.username
    });

    // 12. Retour succès
    return res.status(201).json({
      success: true,
      token,
      admin: {
        id: newAdmin.id,
        username: newAdmin.username,
        email: newAdmin.email
      }
    });

  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({
      error: 'Erreur serveur.'
    });
  }
};
