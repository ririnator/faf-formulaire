# Session de travail - 3 & 5 Novembre 2025

## 🎯 Objectif de la session
Implémenter un système de paywall Stripe complet pour Form-a-Friend (€12/mois par admin).

---

## ✅ STATUT FINAL : PAYWALL OPÉRATIONNEL EN PRODUCTION ✅

Le système de paywall Stripe est **100% fonctionnel** sur https://faf-multijoueur.vercel.app

### Flow de paiement validé
1. ✅ Register → Création compte
2. ✅ Onboarding → Vérification paiement
3. ✅ Redirection automatique → Stripe Checkout
4. ✅ Paiement carte test → Validation
5. ✅ Webhook → Activation automatique dans Supabase
6. ✅ Dashboard → Accès débloqué

### Configuration production
- ✅ 12 fonctions serverless (limite Vercel respectée)
- ✅ Variables Stripe configurées dans Vercel
- ✅ Webhook Stripe pointant vers production
- ✅ Migration SQL exécutée sur Supabase
- ✅ Routes admin protégées par paywall

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

#### Backend - API Routes (3 fichiers séparés pour Vercel)
- **`api/payment/create-checkout.js`** - Crée une session Stripe Checkout ✅
  - Vérifie le JWT de l'admin
  - Vérifie que l'admin n'a pas déjà payé
  - Retourne l'URL de redirection Stripe
  - **TESTÉ EN PRODUCTION** : Fonctionne parfaitement

- **`api/payment/webhook.js`** - Gère les événements Stripe ✅
  - `checkout.session.completed` - Active l'admin après paiement
  - `customer.subscription.updated` - Met à jour le statut
  - `customer.subscription.deleted` - Marque comme annulé
  - `invoice.payment_failed` - Marque comme échoué
  - **TESTÉ EN PRODUCTION** : Webhook activé et fonctionnel

- **`api/payment/status.js`** - Vérifie le statut de paiement d'un admin ✅
  - Retourne `has_access`, `payment_status`, `subscription_end_date`
  - **TESTÉ EN PRODUCTION** : Utilisé par onboarding.html

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
- **`public/auth/onboarding.html`** - Modifié pour gérer le paywall ✅
  - Vérifie le statut de paiement via `/api/payment/status`
  - Redirige vers Stripe Checkout si pas d'abonnement actif
  - Affiche la page d'onboarding après paiement réussi

- **`public/admin/faf-admin.js`** - Ajout gestion 402 Payment Required ✅
  - Détecte réponse 402 et redirige vers `/auth/payment-required.html`
  - Remplacement de `/api/auth/verify` par décodage JWT client-side (économie 1 fonction serverless)
  - JWT toujours vérifié côté serveur sur toutes les routes protégées

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

## ❌ Problèmes rencontrés et résolus

### 1. ✅ RÉSOLU - Limite de 12 fonctions serverless Vercel (Hobby plan)

**Symptôme** :
```
No more than 12 Serverless Functions can be added to a Deployment on the Hobby plan.
```

**Tentative 1** : Fusionner les 3 routes payment en 1 seul fichier `api/payment/index.js` avec routing interne
- ❌ **Échec** : Vercel ne supporte pas le routing interne dans un seul fichier
- Erreur 404 sur `/api/payment/create-checkout`

**Solution finale** ✅ :
- Suppression de `/api/auth/verify` (remplacé par décodage JWT côté client)
- JWT toujours vérifié côté serveur sur toutes les routes protégées
- **Résultat** : 12 fonctions exactement
  - `auth/` (2): login, register
  - `admin/` (3): dashboard, responses, response/[id]
  - `payment/` (3): create-checkout, status, webhook
  - `response/` (2): submit, view/[token]
  - `form/[username]` (1)
  - `upload` (1)

### 2. ✅ RÉSOLU - Erreur 500 création session Stripe

**Symptôme** :
```
Failed to load resource: the server responded with a status of 500 (create-checkout)
```

**Cause** : `STRIPE_PRICE_ID` incorrect dans les variables Vercel

**Solution** ✅ :
- Récupérer le bon Price ID depuis [Stripe Dashboard → Products](https://dashboard.stripe.com/test/products)
- Format : `price_xxxxxxxxxxxxx`
- Mettre à jour dans Vercel → Environment Variables
- Redéployer

### 3. ✅ RÉSOLU - Webhook en production

**Solution** ✅ :
- Passer directement en production (Option 2 recommandée)
- Configurer le webhook dans Stripe Dashboard pointant vers production
- URL : `https://faf-multijoueur.vercel.app/api/payment/webhook`
- **TESTÉ ET FONCTIONNEL** : Admin activé automatiquement après paiement

---

## 📋 Déploiement en production - COMPLÉTÉ ✅

#### Étape 1 : Migration SQL Supabase ✅ FAIT
```sql
-- Exécuté sur Supabase Dashboard → SQL Editor
-- Contenu de sql/04_add_payment_fields.sql
-- Ajout champs : stripe_customer_id, stripe_subscription_id, payment_status, subscription_end_date
```

#### Étape 2 : Ajouter les variables Stripe dans Vercel ✅ FAIT
```bash
# Vercel Dashboard → faf-multijoueur → Settings → Environment Variables
STRIPE_SECRET_KEY=sk_test_... (de Stripe Dashboard → API Keys)
STRIPE_PRICE_ID=price_... (de Stripe Dashboard → Products → Form-a-Friend Admin)
STRIPE_WEBHOOK_SECRET=whsec_... (de Stripe Dashboard → Webhooks → Signing secret)
```

**⚠️ IMPORTANT** : Le STRIPE_PRICE_ID doit être le bon, sinon erreur 500

#### Étape 3 : Déployer sur Vercel ✅ FAIT
```bash
# Commits effectués :
- 37b1dd7 : Fusion routes payment (13→11 fonctions)
- 2cda8e8 : Protection routes admin avec paywall
- 32b987b : Ajout redirection payment flow
- b1b1719 : Restauration fichiers payment séparés
- 6473174 : Suppression /api/auth/verify (12 fonctions exactement)
```

#### Étape 4 : Configurer le webhook Stripe (production) ✅ FAIT
- **URL** : `https://faf-multijoueur.vercel.app/api/payment/webhook`
- **Events** : checkout.session.completed, customer.subscription.updated, customer.subscription.deleted, invoice.payment_failed
- **Signing secret** : Copié dans Vercel Environment Variables
- **TESTÉ** : Webhook fonctionne, admin activé automatiquement

#### Étape 5 : Protéger les routes admin ✅ FAIT
Routes protégées avec `withPaymentRequired()` :
- ✅ `/api/admin/dashboard.js`
- ✅ `/api/admin/responses.js`
- ✅ `/api/admin/response/[id].js`

Routes publiques (non protégées) :
- ✅ `/api/response/submit.js` (amis remplissent gratuitement)
- ✅ `/api/form/[username].js` (formulaire public)

#### Étape 6 : Tester en production ✅ VALIDÉ
1. ✅ Compte créé sur `/auth/register.html`
2. ✅ Redirection automatique vers Stripe Checkout
3. ✅ Paiement avec carte test : `4242 4242 4242 4242`
4. ✅ Redirection vers `/auth/payment-success.html`
5. ✅ Accès au dashboard débloqué
6. ✅ Vérifié dans Supabase : `payment_status = 'active'`

**RÉSULTAT** : Système de paywall 100% opérationnel en production ! 🎉

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

## ✨ Résumé Final

### 🎉 SYSTÈME OPÉRATIONNEL EN PRODUCTION

**Architecture déployée** :
- ✅ 12 fonctions serverless (limite Vercel respectée)
- ✅ 3 routes payment API (create-checkout, status, webhook)
- ✅ 3 routes admin protégées par paywall
- ✅ Middleware de protection paywall
- ✅ Migration SQL Supabase exécutée
- ✅ Variables Stripe configurées dans Vercel
- ✅ Webhook Stripe configuré en production

**Flow validé** :
1. ✅ Register → Création compte + JWT
2. ✅ Onboarding → Vérification paiement
3. ✅ Redirection → Stripe Checkout (12€/mois)
4. ✅ Paiement → Carte test 4242...
5. ✅ Webhook → Activation automatique Supabase
6. ✅ Success page → Redirection dashboard
7. ✅ Dashboard → Accès débloqué

**Tests réussis** :
- ✅ Création compte + paiement
- ✅ Activation automatique via webhook
- ✅ Protection routes admin (402 si pas payé)
- ✅ Redirection vers page paiement si nécessaire
- ✅ Dashboard accessible après paiement

**URL de production** : https://faf-multijoueur.vercel.app

**Prochaines étapes (optionnel)** :
- [ ] Passer en mode Live Stripe (quand prêt à accepter vrais paiements)
- [ ] Ajouter page de gestion abonnement (annulation, facturation)
- [ ] Email de confirmation après paiement
- [ ] Période d'essai gratuit (7 jours)

---

**Mission accomplie ! 🚀**
