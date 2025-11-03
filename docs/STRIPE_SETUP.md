# Guide d'installation Stripe pour Form-a-Friend

Ce guide explique comment configurer Stripe pour le système de paywall (€12/mois par admin).

---

## 📋 Table des matières

1. [Prérequis](#prérequis)
2. [Configuration Stripe Dashboard](#configuration-stripe-dashboard)
3. [Variables d'environnement](#variables-denvironnement)
4. [Migration de la base de données](#migration-de-la-base-de-données)
5. [Configuration des webhooks](#configuration-des-webhooks)
6. [Tests avec Stripe CLI](#tests-avec-stripe-cli)
7. [Protection des routes admin](#protection-des-routes-admin)
8. [Tests de bout en bout](#tests-de-bout-en-bout)
9. [Dépannage](#dépannage)

---

## 🔧 Prérequis

- Compte Stripe (https://dashboard.stripe.com/register)
- Accès au Dashboard Supabase
- Accès aux variables d'environnement Vercel
- Stripe CLI installé (pour tests locaux) : https://stripe.com/docs/stripe-cli

---

## 🎛️ Configuration Stripe Dashboard

### Étape 1 : Créer un produit

1. Allez sur **Stripe Dashboard** → [Products](https://dashboard.stripe.com/products)
2. Cliquez sur **"+ Add product"**
3. Remplissez les champs :
   - **Name** : `Form-a-Friend Admin`
   - **Description** : `Abonnement mensuel pour créer et gérer un formulaire Form-a-Friend`
   - **Pricing model** : `Standard pricing`
   - **Price** : `12.00 EUR`
   - **Billing period** : `Monthly`
   - Cochez **"Recurring"**

4. Cliquez sur **"Save product"**

### Étape 2 : Récupérer l'ID du prix

1. Sur la page du produit, dans la section **"Pricing"**, cliquez sur le prix que vous venez de créer
2. Copiez l'**ID du prix** (format : `price_xxxxxxxxxxxxx`)
3. **Important** : Gardez cet ID, vous en aurez besoin pour les variables d'environnement

### Étape 3 : Récupérer les clés API

1. Allez sur **Stripe Dashboard** → [API Keys](https://dashboard.stripe.com/apikeys)
2. Mode **Test** (pour développement) :
   - Copiez la **Publishable key** (format : `pk_test_xxxxx`)
   - Cliquez sur **"Reveal test key"** pour copier la **Secret key** (format : `sk_test_xxxxx`)
3. Mode **Production** (pour déploiement) :
   - Basculez en mode **"Live"** (toggle en haut à droite)
   - Copiez les clés Live de la même manière

⚠️ **IMPORTANT** : Ne commitez JAMAIS les clés secrètes dans Git !

---

## 🔐 Variables d'environnement

Ajoutez les variables suivantes à votre fichier `.env.local` (développement) et dans **Vercel Dashboard** → Settings → Environment Variables (production).

### Variables Stripe

```bash
# Stripe Secret Key (sk_test_xxx pour test, sk_live_xxx pour production)
STRIPE_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxx

# Stripe Price ID (créé à l'étape précédente)
STRIPE_PRICE_ID=price_xxxxxxxxxxxxx

# Stripe Webhook Secret (voir section "Configuration des webhooks")
STRIPE_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxx
```

### Variables existantes (déjà configurées normalement)

```bash
# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-key
SUPABASE_ANON_KEY=your-anon-key

# App URLs
APP_BASE_URL=https://your-domain.vercel.app
VERCEL_URL=your-domain.vercel.app
```

### Configuration Vercel

1. Allez sur **Vercel Dashboard** → Votre projet → Settings → Environment Variables
2. Ajoutez chaque variable :
   - `STRIPE_SECRET_KEY` : Votre clé secrète Stripe
   - `STRIPE_PRICE_ID` : L'ID du prix créé
   - `STRIPE_WEBHOOK_SECRET` : Le secret du webhook (voir section suivante)
3. Sélectionnez les environnements : **Production**, **Preview**, **Development**
4. Cliquez sur **"Save"**

---

## 💾 Migration de la base de données

### Étape 1 : Exécuter le script SQL

1. Allez sur **Supabase Dashboard** → SQL Editor
2. Ouvrez le fichier `/sql/04_add_payment_fields.sql` du projet
3. Copiez-collez le contenu complet dans le SQL Editor
4. Cliquez sur **"Run"**

### Étape 2 : Vérifier la migration

Exécutez cette requête pour vérifier que les colonnes ont été ajoutées :

```sql
SELECT column_name, data_type, column_default
FROM information_schema.columns
WHERE table_name = 'admins'
  AND column_name IN ('stripe_customer_id', 'stripe_subscription_id', 'payment_status', 'subscription_end_date');
```

Vous devriez voir 4 lignes (une par colonne).

---

## 🔔 Configuration des webhooks

Les webhooks permettent à Stripe de notifier votre application des événements de paiement.

### Production (Vercel)

1. Allez sur **Stripe Dashboard** → [Webhooks](https://dashboard.stripe.com/webhooks)
2. Cliquez sur **"+ Add endpoint"**
3. Remplissez :
   - **Endpoint URL** : `https://your-domain.vercel.app/api/payment/webhook`
   - **Description** : `Form-a-Friend payment webhook`
   - **Events to send** : Sélectionnez ces 4 événements :
     - ✅ `checkout.session.completed`
     - ✅ `customer.subscription.updated`
     - ✅ `customer.subscription.deleted`
     - ✅ `invoice.payment_failed`
4. Cliquez sur **"Add endpoint"**
5. Sur la page du webhook, cliquez sur **"Reveal"** pour copier le **Signing secret** (format : `whsec_xxxxx`)
6. Ajoutez ce secret à vos variables d'environnement Vercel :
   - Variable : `STRIPE_WEBHOOK_SECRET`
   - Valeur : `whsec_xxxxxxxxxxxxx`

### Développement local (avec Stripe CLI)

Pour tester les webhooks en local :

```bash
# 1. Installer Stripe CLI
brew install stripe/stripe-cli/stripe

# 2. Se connecter
stripe login

# 3. Lancer le forwarding (dans un terminal séparé)
stripe listen --forward-to http://localhost:3000/api/payment/webhook

# 4. Copier le webhook secret affiché (whsec_xxx) dans votre .env.local
```

---

## 🧪 Tests avec Stripe CLI

### 1. Tester un paiement réussi

```bash
stripe trigger checkout.session.completed
```

### 2. Tester un échec de paiement

```bash
stripe trigger invoice.payment_failed
```

### 3. Tester une annulation d'abonnement

```bash
stripe trigger customer.subscription.deleted
```

### 4. Cartes de test Stripe

Utilisez ces numéros de carte dans Stripe Checkout (mode test) :

| Scénario | Numéro de carte | CVC | Date d'expiration |
|----------|----------------|-----|-------------------|
| ✅ Succès | `4242 4242 4242 4242` | N'importe quel | Futur |
| ❌ Refusé | `4000 0000 0000 0002` | N'importe quel | Futur |
| 🔄 3D Secure | `4000 0027 6000 3184` | N'importe quel | Futur |

---

## 🛡️ Protection des routes admin

Pour protéger une route API existante avec le paywall :

### Option 1 : Wrapper automatique

```javascript
// Dans votre route API (ex: /api/admin/dashboard.js)
const { withPaymentRequired } = require('../../middleware/payment');

module.exports = withPaymentRequired(async function handler(req, res) {
  // req.adminId est disponible ici
  const adminId = req.adminId;

  // Votre logique existante...
  return res.status(200).json({ success: true });
});
```

### Option 2 : Vérification manuelle

```javascript
// Dans votre route API
const { requirePayment } = require('../../middleware/payment');

module.exports = async function handler(req, res) {
  const paymentCheck = await requirePayment(req);

  if (!paymentCheck.hasAccess) {
    return res.status(402).json({
      error: 'Paiement requis',
      payment_status: paymentCheck.status
    });
  }

  // Votre logique existante...
  const adminId = paymentCheck.adminId;
};
```

### Routes à protéger

Ajoutez le middleware `withPaymentRequired` à ces routes :

- ✅ `/api/admin/dashboard.js`
- ✅ `/api/admin/responses.js`
- ✅ `/api/admin/response/[id].js`
- ❌ `/api/response/submit.js` (public, ne PAS protéger)
- ❌ `/api/form/[username].js` (public, ne PAS protéger)

---

## ✅ Tests de bout en bout

### Scénario 1 : Inscription + Paiement

1. Allez sur `/auth/register.html`
2. Créez un compte avec un email de test
3. Vérifiez la redirection automatique vers Stripe Checkout
4. Utilisez la carte test `4242 4242 4242 4242`
5. Complétez le paiement
6. Vérifiez la redirection vers `/auth/payment-success.html`
7. Vérifiez l'accès au dashboard `/admin/dashboard.html`

### Scénario 2 : Accès bloqué sans paiement

1. Créez un admin directement dans Supabase (SQL Editor) :

```sql
INSERT INTO admins (username, email, password_hash, payment_status)
VALUES ('testuser', 'test@example.com', '$2b$10$dummy_hash', 'pending');
```

2. Essayez d'accéder au dashboard : vous devriez être redirigé vers `/auth/payment-required.html`
3. Cliquez sur "Payer" et complétez le processus

### Scénario 3 : Webhook de paiement échoué

1. Avec Stripe CLI, déclenchez un échec :

```bash
stripe trigger invoice.payment_failed
```

2. Vérifiez dans Supabase que le `payment_status` passe à `failed`

### Scénario 4 : Annulation d'abonnement

1. Allez sur Stripe Dashboard → Customers
2. Trouvez un client de test
3. Annulez son abonnement
4. Vérifiez que le webhook met à jour le statut dans Supabase

---

## 🐛 Dépannage

### Erreur : "STRIPE_SECRET_KEY environment variable is not defined"

**Solution** : Vérifiez que la variable est bien définie dans Vercel et redéployez.

```bash
vercel env pull .env.local
cat .env.local | grep STRIPE_SECRET_KEY
```

### Erreur : "Invalid signature" dans les webhooks

**Solution** : Vérifiez que `STRIPE_WEBHOOK_SECRET` correspond au secret du webhook dans Stripe Dashboard.

### Le paiement ne met pas à jour la base de données

**Causes possibles** :
1. Le webhook n'est pas configuré correctement
2. Le `admin_id` n'est pas dans les metadata de la session
3. Le webhook n'écoute pas les bons événements

**Debug** :
- Vérifiez les logs Vercel : `vercel logs`
- Vérifiez les webhooks dans Stripe Dashboard → Webhooks → Votre endpoint → Recent events

### L'utilisateur est redirigé vers `/auth/payment-required.html` alors qu'il a payé

**Solution** : Vérifiez manuellement dans Supabase :

```sql
SELECT username, payment_status, subscription_end_date
FROM admins
WHERE email = 'email@exemple.com';
```

Si `payment_status` est `pending` alors qu'il devrait être `active`, ré-exécutez manuellement le webhook :

1. Allez sur Stripe Dashboard → Webhooks → Votre endpoint
2. Trouvez l'événement `checkout.session.completed`
3. Cliquez sur **"Resend"**

### La redirection après Stripe Checkout ne fonctionne pas

**Solution** : Vérifiez que `APP_BASE_URL` et `VERCEL_URL` sont bien configurés dans les variables d'environnement.

---

## 📊 Monitoring en production

### Supabase : Vérifier les statuts de paiement

```sql
SELECT
  payment_status,
  COUNT(*) as count
FROM admins
GROUP BY payment_status;
```

### Stripe Dashboard : Suivi des revenus

- **Dashboard** → [Home](https://dashboard.stripe.com/) : Revenus mensuels
- **Dashboard** → [Subscriptions](https://dashboard.stripe.com/subscriptions) : Liste des abonnements actifs
- **Dashboard** → [Webhooks](https://dashboard.stripe.com/webhooks) : Vérifier que les webhooks ne retournent pas d'erreurs

---

## 🚀 Passage en production

### Checklist avant le lancement

- [ ] Stripe est en mode **Live** (pas Test)
- [ ] Les clés API Live sont dans Vercel (`sk_live_xxx`)
- [ ] Le webhook est configuré avec l'URL de production
- [ ] `STRIPE_WEBHOOK_SECRET` correspond au webhook Live
- [ ] La migration SQL `04_add_payment_fields.sql` a été exécutée sur Supabase Production
- [ ] Les routes admin sont protégées par `withPaymentRequired`
- [ ] Test de bout en bout réalisé avec une vraie carte (puis remboursé)

### Activation du mode Live

1. Allez sur **Stripe Dashboard** → Basculez en mode **"Live"** (toggle en haut à droite)
2. Mettez à jour **toutes** les variables d'environnement Vercel avec les clés Live
3. Reconfigurez le webhook avec l'URL de production
4. Redéployez sur Vercel : `vercel --prod`
5. Testez avec une vraie carte, puis remboursez immédiatement dans Stripe Dashboard

---

## 📚 Ressources

- [Documentation Stripe Checkout](https://stripe.com/docs/payments/checkout)
- [Documentation Stripe Webhooks](https://stripe.com/docs/webhooks)
- [Stripe CLI](https://stripe.com/docs/stripe-cli)
- [Cartes de test Stripe](https://stripe.com/docs/testing)

---

**Besoin d'aide ?** Consultez les logs Vercel avec `vercel logs` ou les événements webhook dans Stripe Dashboard.
