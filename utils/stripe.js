/**
 * Stripe Client Configuration
 * Initialise le client Stripe pour les paiements
 */

const Stripe = require('stripe');

// Vérifier que la clé secrète Stripe est définie
if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error('STRIPE_SECRET_KEY environment variable is not defined');
}

// Initialiser le client Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: '2024-11-20.acacia', // Version API Stripe la plus récente
  maxNetworkRetries: 3,
  timeout: 30000 // 30 secondes
});

/**
 * Crée une session Checkout Stripe
 * @param {Object} params - Paramètres de la session
 * @param {string} params.customerEmail - Email du client
 * @param {string} params.adminId - UUID de l'admin dans Supabase
 * @param {string} params.successUrl - URL de redirection après succès
 * @param {string} params.cancelUrl - URL de redirection après annulation
 * @returns {Promise<Object>} Session Stripe
 */
async function createCheckoutSession({ customerEmail, adminId, successUrl, cancelUrl }) {
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer_email: customerEmail,
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID, // ID du prix €12/mois
          quantity: 1,
        },
      ],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: {
        admin_id: adminId,
      },
      subscription_data: {
        metadata: {
          admin_id: adminId,
        },
      },
      allow_promotion_codes: true, // Permettre les codes promo
      billing_address_collection: 'auto',
    });

    return session;
  } catch (error) {
    console.error('Stripe checkout session error:', error);
    throw error;
  }
}

/**
 * Récupère une session Checkout
 * @param {string} sessionId - ID de la session
 * @returns {Promise<Object>} Session Stripe
 */
async function retrieveCheckoutSession(sessionId) {
  try {
    return await stripe.checkout.sessions.retrieve(sessionId);
  } catch (error) {
    console.error('Stripe retrieve session error:', error);
    throw error;
  }
}

/**
 * Récupère un abonnement Stripe
 * @param {string} subscriptionId - ID de l'abonnement
 * @returns {Promise<Object>} Abonnement Stripe
 */
async function retrieveSubscription(subscriptionId) {
  try {
    return await stripe.subscriptions.retrieve(subscriptionId);
  } catch (error) {
    console.error('Stripe retrieve subscription error:', error);
    throw error;
  }
}

/**
 * Annule un abonnement Stripe
 * @param {string} subscriptionId - ID de l'abonnement
 * @returns {Promise<Object>} Abonnement annulé
 */
async function cancelSubscription(subscriptionId) {
  try {
    return await stripe.subscriptions.cancel(subscriptionId);
  } catch (error) {
    console.error('Stripe cancel subscription error:', error);
    throw error;
  }
}

/**
 * Récupère un client Stripe par ID
 * @param {string} customerId - ID du client
 * @returns {Promise<Object>} Client Stripe
 */
async function retrieveCustomer(customerId) {
  try {
    return await stripe.customers.retrieve(customerId);
  } catch (error) {
    console.error('Stripe retrieve customer error:', error);
    throw error;
  }
}

/**
 * Construit un événement webhook depuis la signature
 * @param {string} payload - Corps de la requête (raw)
 * @param {string} signature - Signature du webhook (header stripe-signature)
 * @returns {Object} Événement Stripe vérifié
 */
function constructWebhookEvent(payload, signature) {
  if (!process.env.STRIPE_WEBHOOK_SECRET) {
    throw new Error('STRIPE_WEBHOOK_SECRET environment variable is not defined');
  }

  try {
    return stripe.webhooks.constructEvent(
      payload,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (error) {
    console.error('Webhook signature verification failed:', error.message);
    throw error;
  }
}

module.exports = {
  stripe,
  createCheckoutSession,
  retrieveCheckoutSession,
  retrieveSubscription,
  cancelSubscription,
  retrieveCustomer,
  constructWebhookEvent,
};
