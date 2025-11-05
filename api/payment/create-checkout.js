const { supabaseAdmin } = require('../../utils/supabase');
const { createCheckoutSession } = require('../../utils/stripe');
const { verifyToken } = require('../../utils/jwt');

/**
 * POST /api/payment/create-checkout
 * Crée une session Stripe Checkout pour un nouvel admin
 */
module.exports = async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
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

    // 3. Récupérer les infos de l'admin
    const { data: admin, error: adminError } = await supabaseAdmin
      .from('admins')
      .select('id, username, email, payment_status')
      .eq('id', adminId)
      .single();

    if (adminError || !admin) {
      console.error('Admin lookup error:', adminError);
      return res.status(404).json({ error: 'Admin introuvable' });
    }

    // 4. Vérifier que l'admin n'a pas déjà payé
    if (admin.payment_status === 'active') {
      return res.status(400).json({
        error: 'Vous avez déjà un abonnement actif',
        already_paid: true
      });
    }

    // 5. Construire les URLs de redirection
    const baseUrl = process.env.VERCEL_URL
      ? `https://${process.env.VERCEL_URL}`
      : process.env.APP_BASE_URL || 'http://localhost:3000';

    const successUrl = `${baseUrl}/auth/payment-success.html?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = `${baseUrl}/auth/payment-required.html?cancelled=true`;

    // 6. Créer la session Stripe
    const session = await createCheckoutSession({
      customerEmail: admin.email,
      adminId: admin.id,
      successUrl,
      cancelUrl,
    });

    // 7. Retourner l'URL de la session
    return res.status(200).json({
      success: true,
      sessionUrl: session.url,
      sessionId: session.id,
    });

  } catch (error) {
    console.error('Create checkout session error:', error);
    return res.status(500).json({
      error: 'Erreur lors de la création de la session de paiement'
    });
  }
};
