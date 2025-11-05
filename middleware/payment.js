const { supabaseAdmin } = require('../utils/supabase');
const { verifyToken } = require('../utils/jwt');

/**
 * Middleware de vérification du paiement
 * Bloque l'accès aux routes protégées si l'admin n'a pas payé
 *
 * Usage dans une API route:
 *   const { requirePayment } = require('../../middleware/payment');
 *   const paymentCheck = await requirePayment(req);
 *   if (!paymentCheck.hasAccess) {
 *     return res.status(402).json({ error: 'Payment required', payment_status: paymentCheck.status });
 *   }
 */

/**
 * Vérifie si un admin a un accès payé valide
 * @param {Object} req - Requête HTTP (avec Authorization header)
 * @returns {Promise<Object>} { hasAccess: boolean, adminId: string, status: string }
 */
async function requirePayment(req) {
  try {
    // 1. Extraire le token JWT
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        hasAccess: false,
        error: 'Token manquant',
        status: 'unauthorized',
      };
    }

    const token = authHeader.substring(7);

    // 2. Vérifier le token
    let decoded;
    try {
      decoded = verifyToken(token);
    } catch (err) {
      return {
        hasAccess: false,
        error: 'Token invalide ou expiré',
        status: 'unauthorized',
      };
    }

    const adminId = decoded.sub;

    // 3. Récupérer le statut de paiement
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, payment_status, subscription_end_date, is_grandfathered')
      .eq('id', adminId)
      .single();

    if (error || !admin) {
      console.error('Payment middleware - Admin lookup error:', error);
      return {
        hasAccess: false,
        error: 'Admin introuvable',
        status: 'not_found',
      };
    }

    // 4. Vérifier si l'accès est actif
    const now = new Date();
    const endDate = admin.subscription_end_date ? new Date(admin.subscription_end_date) : null;

    // Accès actif si:
    // - is_grandfathered = true (accès gratuit permanent) OU
    // - payment_status = 'active' OU
    // - subscription_end_date est dans le futur (période de grâce)
    const hasAccess = admin.is_grandfathered === true ||
                      admin.payment_status === 'active' ||
                      (endDate !== null && endDate > now);

    return {
      hasAccess,
      adminId: admin.id,
      username: admin.username,
      status: admin.payment_status,
      subscriptionEndDate: admin.subscription_end_date,
    };

  } catch (error) {
    console.error('Payment middleware error:', error);
    return {
      hasAccess: false,
      error: 'Erreur serveur',
      status: 'error',
    };
  }
}

/**
 * Middleware wrapper pour Vercel serverless functions
 * Bloque automatiquement la requête si le paiement n'est pas valide
 *
 * Usage:
 *   module.exports = withPaymentRequired(async function handler(req, res) {
 *     // req.adminId est disponible ici
 *     return res.status(200).json({ ... });
 *   });
 */
function withPaymentRequired(handler) {
  return async function (req, res) {
    const paymentCheck = await requirePayment(req);

    if (!paymentCheck.hasAccess) {
      return res.status(402).json({
        error: 'Accès payant requis',
        payment_status: paymentCheck.status,
        message: 'Vous devez avoir un abonnement actif pour accéder à cette ressource',
      });
    }

    // Attacher les infos admin à la requête pour l'utiliser dans le handler
    req.adminId = paymentCheck.adminId;
    req.adminUsername = paymentCheck.username;

    return handler(req, res);
  };
}

module.exports = {
  requirePayment,
  withPaymentRequired,
};
