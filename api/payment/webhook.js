const { supabaseAdmin } = require('../../utils/supabase');
const { constructWebhookEvent } = require('../../utils/stripe');

/**
 * POST /api/payment/webhook
 * Gère les webhooks Stripe
 */
async function handler(req, res) {
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
    // 4. Traiter l'événement selon son type
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

    // 5. Répondre à Stripe avec succès
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

// Désactiver le body parser de Vercel pour recevoir le raw body
handler.config = {
  api: {
    bodyParser: false,
  },
};

module.exports = handler;
