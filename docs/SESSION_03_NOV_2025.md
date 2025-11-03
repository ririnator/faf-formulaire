# Session de travail - 3 Novembre 2025

## 🎯 Objectif de la session
Implémenter un système de paywall Stripe complet pour Form-a-Friend (€12/mois par admin).

---

## ✅ Ce qui a été fait

### 1. Architecture et fichiers créés

#### Base de données
- **`sql/04_add_payment_fields.sql`** - Migration SQL ajoutant les champs de paiement à la table `admins` :
  - `stripe_customer_id` (TEXT)
  - `stripe_subscription_id` (TEXT)
  - `payment_status` (ENUM: pending, active, cancelled, failed)
  - `subscription_end_date` (TIMESTAMPTZ)

#### Backend - Utilities
- **`utils/stripe.js`** - Client Stripe avec fonctions helper :
  - `createCheckoutSession()` - Créer une session de paiement
  - `retrieveCheckoutSession()` - Récupérer une session
  - `constructWebhookEvent()` - Vérifier les webhooks
  - Configuration avec `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID`, `STRIPE_WEBHOOK_SECRET`

#### Backend - API Routes
- **`api/payment/create-checkout.js`** - Crée une session Stripe Checkout
  - Vérifie le JWT de l'admin
  - Vérifie que l'admin n'a pas déjà payé
  - Retourne l'URL de redirection Stripe

- **`api/payment/webhook.js`** - Gère les événements Stripe
  - `checkout.session.completed` - Active l'admin après paiement
  - `customer.subscription.updated` - Met à jour le statut
  - `customer.subscription.deleted` - Marque comme annulé
  - `invoice.payment_failed` - Marque comme échoué
  - ⚠️ **PROBLÈME** : Vérification de signature ne fonctionne pas en dev local avec Vercel Dev

- **`api/payment/status.js`** - Vérifie le statut de paiement d'un admin
  - Retourne `has_access`, `payment_status`, `subscription_end_date`

#### Backend - Middleware
- **`middleware/payment.js`** - Protection des routes payantes
  - `requirePayment(req)` - Vérifie si l'admin a payé
  - `withPaymentRequired(handler)` - Wrapper pour protéger une route automatiquement

#### Frontend - Pages
- **`public/auth/payment-required.html`** - Page de souscription
  - Affiche le prix (12€/mois)
  - Liste des fonctionnalités
  - Bouton pour lancer Stripe Checkout
  - Gestion des annulations

- **`public/auth/payment-success.html`** - Confirmation après paiement
  - Message de succès
  - Redirection automatique vers le dashboard

#### Frontend - Modifications
- **`frontend/public/js/auth.js`** - Modifié pour rediriger vers Stripe après inscription
  - Après création du compte → Appel à `/api/payment/create-checkout`
  - Redirection automatique vers Stripe Checkout

#### Configuration
- **`package.json`** - Ajout de la dépendance `stripe@^17.4.0` ✅ Installée
- **`.env.local`** - Créé avec toutes les variables (Supabase + Stripe)
- **`.env.example`** - Mis à jour avec les variables Stripe

#### Documentation
- **`docs/STRIPE_SETUP.md`** - Guide complet (11 pages) :
  - Configuration Stripe Dashboard
  - Migration base de données
  - Configuration webhooks
  - Tests et dépannage

- **`docs/STRIPE_QUICKSTART.md`** - Guide rapide (10 minutes)
- **`docs/SESSION_03_NOV_2025.md`** - Ce fichier

---

## 🔧 Configuration effectuée

### Stripe Dashboard
- ✅ Compte Stripe créé en mode Test
- ✅ Produit créé : "Form-a-Friend Admin" à 12€/mois (récurrent)
- ✅ Prix créé avec ID : `price_xxxxx` (à remplir dans `.env.local`)
- ✅ Clés API récupérées : `STRIPE_SECRET_KEY` (à remplir dans `.env.local`)

### Variables d'environnement (`.env.local`)
```bash
# Supabase (déjà configuré)
SUPABASE_URL=https://hftcsnovixmndwsugfvw.supabase.co
SUPABASE_ANON_KEY=eyJhbG...
SUPABASE_SERVICE_KEY=eyJhbG...

# JWT (déjà configuré)
JWT_SECRET=919bb969...

# Cloudinary (déjà configuré)
CLOUDINARY_CLOUD_NAME=doyupygie
CLOUDINARY_API_KEY=351836535454814
CLOUDINARY_API_SECRET=MccuZGD...

# Stripe (À REMPLIR AVEC VOS VRAIES VALEURS)
STRIPE_SECRET_KEY=sk_test_VOTRE_CLE_ICI
STRIPE_PRICE_ID=price_VOTRE_PRICE_ID_ICI
STRIPE_WEBHOOK_SECRET=whsec_d2e6ff516f6e75444c91ce6018b2c1c9218358648f45341b7365d656d84cf013

# App
APP_BASE_URL=http://localhost:3000
NODE_ENV=development
```

### Stripe CLI
- ✅ Installé via Homebrew : `brew install stripe/stripe-cli/stripe`
- ✅ Authentifié avec succès : `stripe login`
- ✅ Webhook forwarding lancé : `stripe listen --forward-to http://localhost:3000/api/payment/webhook`
- ✅ Webhook secret récupéré et ajouté à `.env.local`

---

## ❌ Problèmes rencontrés

### 1. Problème principal : Vérification de signature webhook en dev local

**Symptôme** :
```
Webhook signature verification failed: No webhook payload was provided.
```

**Cause** :
- Stripe a besoin du **raw body** (non parsé) pour vérifier la signature du webhook
- **Vercel Dev** parse automatiquement `req.body` en JSON
- Le raw body est perdu → impossible de vérifier la signature

**Tentatives de résolution** :
1. ❌ Ajout de `export const config = { api: { bodyParser: false } }` → Erreur "require is not defined in ES module"
2. ❌ Passage à `handler.config = { ... }` en CommonJS → Ignoré par Vercel Dev
3. ❌ Lecture du body via `for await (const chunk of req)` → Body vide

**Impact** :
- Les webhooks sont reçus mais retournent 400 (signature invalide)
- La logique métier (activation admin, mise à jour statut) n'est jamais exécutée

**Solutions possibles** :
- **Option A** : Désactiver la vérification de signature en mode dev (`NODE_ENV !== 'production'`)
- **Option B** : Passer directement en production (recommandé, plus simple)
- **Option C** : Utiliser `micro-dev` au lieu de `vercel dev` (complexe)

---

## 📋 Ce qu'il reste à faire

### Option 1 : Tester en développement local (complexe)
1. Modifier `api/payment/webhook.js` pour skip la vérification en dev
2. Relancer `vercel dev`
3. Tester avec `stripe trigger checkout.session.completed`
4. Vérifier que la base de données est mise à jour

### Option 2 : Déployer en production (recommandé) ✅

#### Étape 1 : Migration SQL Supabase
```sql
-- Aller sur Supabase Dashboard → SQL Editor
-- Copier-coller le contenu de sql/04_add_payment_fields.sql
-- Exécuter
```

#### Étape 2 : Ajouter les variables Stripe dans Vercel
```bash
# Aller sur Vercel Dashboard → Votre projet → Settings → Environment Variables
# Ajouter :
STRIPE_SECRET_KEY=sk_test_votre_cle_secrete
STRIPE_PRICE_ID=price_votre_price_id
STRIPE_WEBHOOK_SECRET=whsec_xxx  # (vide pour l'instant, à remplir après étape 4)
```

#### Étape 3 : Déployer sur Vercel
```bash
cd /Users/ririnator/Desktop/FAF
git add .
git commit -m "feat: Add Stripe payment system"
git push origin multijoueurs
# Vercel déploiera automatiquement
```

#### Étape 4 : Configurer le webhook Stripe (production)
1. Aller sur [Stripe Dashboard → Webhooks](https://dashboard.stripe.com/test/webhooks)
2. Cliquer sur **"+ Add endpoint"**
3. Remplir :
   - **URL** : `https://votre-projet.vercel.app/api/payment/webhook`
   - **Description** : `Form-a-Friend payment webhook`
   - **Events** :
     - ✅ `checkout.session.completed`
     - ✅ `customer.subscription.updated`
     - ✅ `customer.subscription.deleted`
     - ✅ `invoice.payment_failed`
4. Copier le **Signing secret** (whsec_xxx)
5. L'ajouter dans Vercel → Environment Variables → `STRIPE_WEBHOOK_SECRET`
6. Redéployer : `vercel --prod`

#### Étape 5 : Protéger les routes admin
Modifier vos routes admin existantes pour ajouter la protection paywall :

**Exemple pour `/api/admin/dashboard.js`** :
```javascript
const { withPaymentRequired } = require('../../middleware/payment');

module.exports = withPaymentRequired(async function handler(req, res) {
  const adminId = req.adminId; // Disponible automatiquement

  // Votre logique existante...
});
```

Routes à protéger :
- ✅ `/api/admin/dashboard.js`
- ✅ `/api/admin/responses.js`
- ✅ `/api/admin/response/[id].js`

Routes à laisser publiques :
- ❌ `/api/response/submit.js` (amis remplissent gratuitement)
- ❌ `/api/form/[username].js` (formulaire public)

#### Étape 6 : Tester en production
1. Créer un compte sur `/auth/register.html`
2. Vérifier la redirection vers Stripe Checkout
3. Payer avec la carte test : `4242 4242 4242 4242`
4. Vérifier la redirection vers `/auth/payment-success.html`
5. Vérifier l'accès au dashboard
6. Vérifier dans Supabase que `payment_status = 'active'`

---

## 🔍 État des processus en cours

### Processus en arrière-plan (à arrêter avant de partir)
```bash
# Stripe webhook forwarding
# Shell ID: 57cd52
# Commande : stripe listen --forward-to http://localhost:3000/api/payment/webhook

# Vercel dev server
# Shell ID: 64ce26
# Commande : vercel dev --listen 3000

# Pour les arrêter :
# Ctrl+C dans les terminaux ou fermer les shells
```

---

## 📚 Ressources

### Documentation
- [docs/STRIPE_SETUP.md](./STRIPE_SETUP.md) - Guide complet
- [docs/STRIPE_QUICKSTART.md](./STRIPE_QUICKSTART.md) - Guide rapide
- [Stripe Documentation](https://stripe.com/docs/webhooks)
- [Vercel Serverless Functions](https://vercel.com/docs/functions)

### Stripe Dashboard (Mode Test)
- [Products](https://dashboard.stripe.com/test/products)
- [API Keys](https://dashboard.stripe.com/test/apikeys)
- [Webhooks](https://dashboard.stripe.com/test/webhooks)
- [Events Log](https://dashboard.stripe.com/test/events)

### Cartes de test
- ✅ Succès : `4242 4242 4242 4242`
- ❌ Refusée : `4000 0000 0000 0002`
- CVC : N'importe quel (123)
- Date : N'importe quelle date future (12/25)

---

## 💡 Recommandations pour demain

### Approche recommandée
**Passer directement en production** plutôt que de perdre du temps avec le dev local :

**Avantages** :
- ✅ Pas de problème de raw body / signature
- ✅ Test dans les vraies conditions
- ✅ Plus rapide (30 min vs 2-3h de debug)
- ✅ Vous validez directement le flow complet

**Étapes** :
1. Exécuter la migration SQL (2 min)
2. Ajouter variables Stripe dans Vercel (5 min)
3. Déployer (2 min)
4. Configurer webhook production (5 min)
5. Tester avec vraie carte test (5 min)
6. Protéger les routes admin (10 min)

**Total** : ~30 minutes pour un système fonctionnel en production !

---

## 🐛 Debug utile

### Vérifier le statut de paiement d'un admin dans Supabase
```sql
SELECT
  username,
  email,
  payment_status,
  subscription_end_date,
  stripe_customer_id,
  stripe_subscription_id
FROM admins
WHERE email = 'votre@email.com';
```

### Vérifier les webhooks dans Stripe Dashboard
1. Aller sur [Stripe Dashboard → Webhooks](https://dashboard.stripe.com/test/webhooks)
2. Cliquer sur votre endpoint
3. Onglet **"Recent events"** → Voir les succès/échecs

### Logs Vercel
```bash
vercel logs
# Ou via le dashboard : https://vercel.com/your-project/logs
```

---

## 📝 Notes importantes

1. **Mode Test vs Live** : Tout a été configuré en mode **Test** pour l'instant. Passage en Live plus tard.

2. **Sécurité** : Les clés secrètes Stripe ne doivent JAMAIS être commitées dans Git (déjà dans `.gitignore`).

3. **Webhook Secret** : Différent entre dev local (Stripe CLI) et production (Stripe Dashboard).

4. **Migration SQL** : À exécuter **UNE SEULE FOIS** en production.

5. **Variables Vercel** : Penser à les configurer pour **Production**, **Preview** ET **Development**.

---

## ✨ Résumé

**Ce qui fonctionne** :
- ✅ Architecture complète du paywall
- ✅ Toutes les routes API créées
- ✅ Pages frontend créées
- ✅ Migration SQL prête
- ✅ Documentation complète
- ✅ Stripe CLI configuré
- ✅ Dépendance Stripe installée

**Ce qui ne fonctionne pas (dev local uniquement)** :
- ❌ Vérification de signature webhook (problème Vercel Dev)

**Solution recommandée** :
- 🚀 Passer directement en production (30 minutes demain)

---

**Bon courage pour demain ! 💪**
