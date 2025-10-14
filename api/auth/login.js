const { supabaseAdmin } = require('../../utils/supabase');
const { generateToken } = require('../../utils/jwt');
const bcrypt = require('bcrypt');

/**
 * Fonction helper pour délai constant (timing attack prevention)
 * @param {number} ms - Millisecondes à attendre
 */
function delay(ms) {
  if (ms <= 0) return Promise.resolve();
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * API Route: POST /api/auth/login
 * Connexion d'un admin existant
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
    const { username, password } = req.body;

    // 1. Validation basique
    if (!username || !password) {
      return res.status(400).json({
        error: 'Username et password requis.'
      });
    }

    // Délai constant pour éviter timing attack (100-200ms aléatoire)
    const startTime = Date.now();
    const minDelay = 100 + Math.random() * 100;

    // 2. Chercher l'admin (case-insensitive)
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, email, password_hash')
      .ilike('username', username)
      .maybeSingle();

    if (error) {
      console.error('Login lookup error:', error);
      // Délai constant avant de répondre
      await delay(minDelay - (Date.now() - startTime));
      return res.status(500).json({ error: 'Erreur serveur.' });
    }

    if (!admin) {
      // Délai constant avant de répondre
      await delay(minDelay - (Date.now() - startTime));
      return res.status(401).json({
        error: 'Identifiants invalides.'
      });
    }

    // 3. Vérifier le password
    const isValid = await bcrypt.compare(password, admin.password_hash);

    if (!isValid) {
      // Délai constant avant de répondre
      await delay(minDelay - (Date.now() - startTime));
      return res.status(401).json({
        error: 'Identifiants invalides.'
      });
    }

    // 4. Génération JWT token
    const token = generateToken({
      sub: admin.id,
      username: admin.username
    });

    // Délai constant avant de répondre (même en cas de succès)
    await delay(minDelay - (Date.now() - startTime));

    // 5. Retour succès
    return res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        email: admin.email
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({
      error: 'Erreur serveur.'
    });
  }
};
