# 🚀 Stripe Quickstart - Form-a-Friend

Guide rapide pour activer le système de paywall en 10 minutes.

---

## 📦 Installation

```bash
npm install stripe
```

---

## ⚡ Configuration rapide (4 étapes)

### 1️⃣ Créer le produit Stripe (2 min)

1. Allez sur [Stripe Dashboard → Products](https://dashboard.stripe.com/products)
2. Cliquez sur **"+ Add product"**
3. Remplissez :
   - Name : `Form-a-Friend Admin`
   - Price : `12 EUR / month` (recurring)
4. Copiez l'**ID du prix** (format : `price_xxxxx`)

### 2️⃣ Récupérer les clés API (1 min)

1. Allez sur [Stripe Dashboard → API Keys](https://dashboard.stripe.com/apikeys)
2. Copiez :
   - **Secret key** (sk_test_xxxxx) - Mode Test pour commencer

### 3️⃣ Migration base de données (1 min)

Dans Supabase SQL Editor, exécutez :

```sql
-- Copier-coller le contenu de /sql/04_add_payment_fields.sql
```

### 4️⃣ Variables d'environnement (1 min)

Dans **Vercel Dashboard** → Settings → Environment Variables :

```bash
STRIPE_SECRET_KEY=sk_test_xxxxxxxxxxxxxxxxxxxxx
STRIPE_PRICE_ID=price_xxxxxxxxxxxxx
STRIPE_WEBHOOK_SECRET=whsec_xxxxx  # (voir étape 5)
```

---

## 🔔 Configuration Webhook (5 min)

### Pour production (Vercel)

1. Allez sur [Stripe Dashboard → Webhooks](https://dashboard.stripe.com/webhooks)
2. Cliquez **"+ Add endpoint"**
3. URL : `https://your-domain.vercel.app/api/payment/webhook`
4. Sélectionnez ces événements :
   - ✅ `checkout.session.completed`
   - ✅ `customer.subscription.updated`
   - ✅ `customer.subscription.deleted`
   - ✅ `invoice.payment_failed`
5. Copiez le **Signing secret** (whsec_xxxxx) et ajoutez-le à Vercel

### Pour développement local

```bash
# Installer Stripe CLI
brew install stripe/stripe-cli/stripe

# Lancer le forwarding
stripe listen --forward-to http://localhost:3000/api/payment/webhook

# Copier le whsec_xxx affiché dans votre .env.local
```

---

## ✅ Test rapide

### 1. Tester l'inscription

```bash
# 1. Créer un compte sur /auth/register.html
# 2. Vous serez redirigé vers Stripe Checkout
# 3. Utilisez la carte test : 4242 4242 4242 4242
# 4. Après paiement → dashboard accessible
```

### 2. Tester les webhooks localement

```bash
stripe trigger checkout.session.completed
```

---

## 🛡️ Protéger les routes admin

Ajoutez une ligne à vos routes admin existantes :

```javascript
// Avant (route non protégée)
module.exports = async function handler(req, res) {
  // ...
};

// Après (route protégée par paywall)
const { withPaymentRequired } = require('../../middleware/payment');

module.exports = withPaymentRequired(async function handler(req, res) {
  const adminId = req.adminId; // Disponible automatiquement
  // ...
});
```

### Routes à protéger immédiatement

- ✅ `/api/admin/dashboard.js`
- ✅ `/api/admin/responses.js`
- ✅ `/api/admin/response/[id].js`

### Routes à laisser publiques

- ❌ `/api/response/submit.js` (amis remplissent gratuitement)
- ❌ `/api/form/[username].js` (formulaire public)

---

## 🎨 Pages créées automatiquement

- `/auth/payment-required.html` - Page de paiement (redirection si non payé)
- `/auth/payment-success.html` - Confirmation après paiement

---

## 🧪 Cartes de test Stripe

| Scénario | Numéro |
|----------|--------|
| ✅ Succès | `4242 4242 4242 4242` |
| ❌ Refusé | `4000 0000 0000 0002` |

**CVC** : N'importe quel (123)
**Date** : N'importe quelle date future (12/25)

---

## 🚀 Passage en production

1. Dans Stripe Dashboard, basculez en mode **Live** (toggle en haut à droite)
2. Remplacez `sk_test_xxx` par `sk_live_xxx` dans Vercel
3. Reconfigurez le webhook avec l'URL de production
4. Testez avec une vraie carte (puis remboursez dans Stripe Dashboard)

---

## 📚 Aide

- **Documentation complète** : Voir [STRIPE_SETUP.md](./STRIPE_SETUP.md)
- **Debug webhook** : [Stripe Dashboard → Webhooks](https://dashboard.stripe.com/webhooks)
- **Logs Vercel** : `vercel logs`

---

**C'est tout !** Votre paywall est maintenant opérationnel. 🎉
