const { supabaseAdmin } = require('../../utils/supabase');
const { verifyToken } = require('../../utils/jwt');

/**
 * API Route: GET /api/payment/status
 * Vérifie le statut de paiement d'un admin
 * Utilisé par le frontend pour afficher/masquer du contenu
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
    // 1. Extraire le token JWT
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token manquant' });
    }

    const token = authHeader.substring(7);

    // 2. Vérifier le token
    let decoded;
    try {
      decoded = verifyToken(token);
    } catch (err) {
      return res.status(401).json({ error: 'Token invalide ou expiré' });
    }

    const adminId = decoded.sub;

    // 3. Récupérer le statut de paiement
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, payment_status, subscription_end_date, stripe_customer_id, stripe_subscription_id')
      .eq('id', adminId)
      .single();

    if (error || !admin) {
      console.error('Admin lookup error:', error);
      return res.status(404).json({ error: 'Admin introuvable' });
    }

    // 4. Vérifier si l'accès est actif
    const now = new Date();
    const endDate = admin.subscription_end_date ? new Date(admin.subscription_end_date) : null;

    // Accès actif si:
    // - payment_status = 'active' OU
    // - subscription_end_date est dans le futur (période de grâce après annulation)
    const hasAccess = admin.payment_status === 'active' ||
                      (endDate !== null && endDate > now);

    // 5. Retourner le statut
    return res.status(200).json({
      success: true,
      payment_status: admin.payment_status,
      has_access: hasAccess,
      subscription_end_date: admin.subscription_end_date,
      has_stripe_customer: !!admin.stripe_customer_id,
      has_stripe_subscription: !!admin.stripe_subscription_id,
    });

  } catch (error) {
    console.error('Payment status check error:', error);
    return res.status(500).json({
      error: 'Erreur lors de la vérification du statut de paiement'
    });
  }
};
