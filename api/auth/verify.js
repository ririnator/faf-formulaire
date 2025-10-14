const { supabaseAdmin } = require('../../utils/supabase');
const { verifyToken } = require('../../utils/jwt');

/**
 * API Route: GET /api/auth/verify
 * Vérification d'un JWT token
 */
module.exports = async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // 1. Extraire le token
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Token manquant.'
      });
    }

    const token = authHeader.split(' ')[1];

    // 2. Vérifier le token
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        error: 'Token invalide ou expiré.'
      });
    }

    // 3. Récupérer l'admin depuis Supabase
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, email, created_at')
      .eq('id', decoded.sub)
      .single();

    if (error || !admin) {
      return res.status(401).json({
        error: 'Admin introuvable.'
      });
    }

    // 4. Retour succès
    return res.status(200).json({
      success: true,
      admin: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        createdAt: admin.created_at
      }
    });

  } catch (error) {
    console.error('Verify error:', error);
    return res.status(401).json({
      error: 'Token invalide.'
    });
  }
};
