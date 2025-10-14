const { verifyToken } = require('../utils/jwt');
const { supabaseAdmin } = require('../utils/supabase');

/**
 * Middleware de vérification JWT
 * Protège les routes admin
 */
async function verifyJWT(req, res, next) {
  try {
    // 1. Extraire le token
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentification requise. Token manquant.'
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

    // 3. Vérifier que l'admin existe toujours
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, email')
      .eq('id', decoded.sub)
      .single();

    if (error || !admin) {
      return res.status(401).json({
        error: 'Admin introuvable.'
      });
    }

    // 4. Attacher les infos admin à la requête
    req.admin = {
      id: admin.id,
      username: admin.username,
      email: admin.email
    };

    // 5. Continuer vers la route suivante
    next();

  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({
      error: 'Erreur d\'authentification.'
    });
  }
}

/**
 * Middleware optionnel : parse le token mais ne bloque pas si absent
 */
async function optionalAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = verifyToken(token);

      if (decoded) {
        const { data: admin } = await supabaseAdmin
          .from('admins')
          .select('id, username, email')
          .eq('id', decoded.sub)
          .single();

        if (admin) {
          req.admin = {
            id: admin.id,
            username: admin.username,
            email: admin.email
          };
        }
      }
    }

    // Continuer même si pas d'auth
    next();

  } catch (error) {
    // Ne pas bloquer en cas d'erreur
    next();
  }
}

module.exports = {
  verifyJWT,
  optionalAuth
};
