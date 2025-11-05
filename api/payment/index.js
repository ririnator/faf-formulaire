const { supabaseAdmin } = require('../../utils/supabase');
const { createCheckoutSession, constructWebhookEvent } = require('../../utils/stripe');
const { verifyToken } = require('../../utils/jwt');

/**
 * API Route: /api/payment/*
 * Unified payment handler routing to create-checkout, status, and webhook
 */
module.exports = async function handler(req, res) {
  const { pathname } = new URL(req.url, `http://${req.headers.host}`);

  // Extract sub-route: /api/payment/create-checkout -> create-checkout
  const subRoute = pathname.replace('/api/payment/', '').replace('/api/payment', '');

  // Route to appropriate handler
  if (subRoute === 'create-checkout' || subRoute === 'create-checkout/') {
    return handleCreateCheckout(req, res);
  } else if (subRoute === 'status' || subRoute === 'status/') {
    return handleStatus(req, res);
  } else if (subRoute === 'webhook' || subRoute === 'webhook/') {
    return handleWebhook(req, res);
  } else if (subRoute === '' || subRoute === '/') {
    return res.status(404).json({ error: 'Sub-route required: /create-checkout, /status, or /webhook' });
  } else {
    return res.status(404).json({ error: 'Unknown payment route' });
  }
};

/**
 * POST /api/payment/create-checkout
 * Crée une session Stripe Checkout pour un nouvel admin
 */
async function handleCreateCheckout(req, res) {
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
}

/**
 * GET /api/payment/status
 * Vérifie le statut de paiement d'un admin
 */
async function handleStatus(req, res) {
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
}

/**
 * POST /api/payment/webhook
 * Gère les webhooks Stripe
 */
async function handleWebhook(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // 1. Lire le raw body depuis le stream
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  const rawBody = Buffer.concat(chunks).toString('utf8');

  // 2. Récupérer la signature
  const signature = req.headers['stripe-signature'];
  if (!signature) {
    console.error('Missing stripe-signature header');
    return res.status(400).json({ error: 'Missing signature' });
  }

  let event;

  try {
    // 3. Construire l'événement avec vérification de signature
    event = constructWebhookEvent(rawBody, signature);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  console.log(`[Webhook] Received event: ${event.type} (${event.id})`);

  try {
    // 3. Traiter l'événement selon son type
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        await handleCheckoutCompleted(session);
        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        await handleSubscriptionUpdated(subscription);
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        await handleSubscriptionDeleted(subscription);
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        await handlePaymentFailed(invoice);
        break;
      }

      default:
        console.log(`[Webhook] Unhandled event type: ${event.type}`);
    }

    // 4. Répondre à Stripe avec succès
    return res.status(200).json({ received: true });

  } catch (error) {
    console.error(`[Webhook] Error processing ${event.type}:`, error);
    // Important: toujours répondre 200 pour éviter les retries infinis
    return res.status(200).json({ received: true, error: error.message });
  }
}

// ===== Webhook Helper Functions =====

async function handleCheckoutCompleted(session) {
  const adminId = session.metadata?.admin_id;
  if (!adminId) {
    console.error('[Webhook] Missing admin_id in session metadata');
    return;
  }

  const customerId = session.customer;
  const subscriptionId = session.subscription;

  console.log(`[Webhook] Checkout completed for admin ${adminId}`);

  const { error } = await supabaseAdmin
    .from('admins')
    .update({
      stripe_customer_id: customerId,
      stripe_subscription_id: subscriptionId,
      payment_status: 'active',
      subscription_end_date: null,
      updated_at: new Date().toISOString(),
    })
    .eq('id', adminId);

  if (error) {
    console.error('[Webhook] Error updating admin after checkout:', error);
    throw error;
  }

  console.log(`[Webhook] Admin ${adminId} activated successfully`);
}

async function handleSubscriptionUpdated(subscription) {
  const adminId = subscription.metadata?.admin_id;
  if (!adminId) {
    console.error('[Webhook] Missing admin_id in subscription metadata');
    return;
  }

  const status = subscription.status;
  const currentPeriodEnd = new Date(subscription.current_period_end * 1000);

  console.log(`[Webhook] Subscription updated for admin ${adminId}: ${status}`);

  let paymentStatus;
  if (status === 'active' || status === 'trialing') {
    paymentStatus = 'active';
  } else if (status === 'past_due') {
    paymentStatus = 'failed';
  } else if (status === 'canceled' || status === 'unpaid') {
    paymentStatus = 'cancelled';
  } else {
    paymentStatus = 'pending';
  }

  const { error } = await supabaseAdmin
    .from('admins')
    .update({
      payment_status: paymentStatus,
      subscription_end_date: paymentStatus === 'cancelled' ? currentPeriodEnd.toISOString() : null,
      updated_at: new Date().toISOString(),
    })
    .eq('id', adminId);

  if (error) {
    console.error('[Webhook] Error updating subscription status:', error);
    throw error;
  }

  console.log(`[Webhook] Admin ${adminId} status updated to ${paymentStatus}`);
}

async function handleSubscriptionDeleted(subscription) {
  const adminId = subscription.metadata?.admin_id;
  if (!adminId) {
    console.error('[Webhook] Missing admin_id in subscription metadata');
    return;
  }

  const currentPeriodEnd = new Date(subscription.current_period_end * 1000);

  console.log(`[Webhook] Subscription deleted for admin ${adminId}`);

  const { error } = await supabaseAdmin
    .from('admins')
    .update({
      payment_status: 'cancelled',
      subscription_end_date: currentPeriodEnd.toISOString(),
      updated_at: new Date().toISOString(),
    })
    .eq('id', adminId);

  if (error) {
    console.error('[Webhook] Error marking subscription as cancelled:', error);
    throw error;
  }

  console.log(`[Webhook] Admin ${adminId} subscription cancelled (access until ${currentPeriodEnd})`);
}

async function handlePaymentFailed(invoice) {
  const subscriptionId = invoice.subscription;
  if (!subscriptionId) {
    console.log('[Webhook] Invoice has no subscription, ignoring');
    return;
  }

  console.log(`[Webhook] Payment failed for subscription ${subscriptionId}`);

  const { data: admin, error: lookupError } = await supabaseAdmin
    .from('admins')
    .select('id, username, email')
    .eq('stripe_subscription_id', subscriptionId)
    .single();

  if (lookupError || !admin) {
    console.error('[Webhook] Could not find admin for subscription:', subscriptionId);
    return;
  }

  const { error } = await supabaseAdmin
    .from('admins')
    .update({
      payment_status: 'failed',
      updated_at: new Date().toISOString(),
    })
    .eq('id', admin.id);

  if (error) {
    console.error('[Webhook] Error marking payment as failed:', error);
    throw error;
  }

  console.log(`[Webhook] Admin ${admin.id} payment marked as failed`);
}

// Désactiver le body parser de Vercel pour le webhook (raw body nécessaire)
module.exports.config = {
  api: {
    bodyParser: false,
  },
};
