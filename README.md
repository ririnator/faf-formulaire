# 🤝 FAF (Form-a-Friend) - Multi-Tenant v2.0

> **Application de formulaires mensuels multi-tenant avec architecture serverless, authentification JWT et isolation par admin**

![Node.js](https://img.shields.io/badge/node.js-v18+-green.svg)
![Vercel](https://img.shields.io/badge/vercel-serverless-black.svg)
![Supabase](https://img.shields.io/badge/supabase-postgresql-green.svg)
![Security](https://img.shields.io/badge/security-JWT+RLS-red.svg)
![Payment](https://img.shields.io/badge/stripe-subscription-blueviolet.svg)

---

## 📋 Vue d'Ensemble

**FAF Multi-Tenant** permet à plusieurs administrateurs indépendants de créer leurs propres formulaires mensuels et de gérer les réponses de leurs amis. Chaque admin a :

- ✅ **Son propre compte** avec authentification JWT
- ✅ **Son formulaire unique** accessible via `/form/{username}`
- ✅ **Ses données isolées** grâce au Row Level Security (Supabase)
- ✅ **Son dashboard privé** avec statistiques et graphiques
- ✅ **Abonnement Stripe** (€12/mois) ou grandfathered (gratuit à vie)

---

## 🚀 Installation Rapide

### Prérequis
- **Node.js** v18+
- **Compte Supabase** (gratuit)
- **Compte Cloudinary** (pour uploads d'images)
- **Compte Stripe** (pour système de paiement)

### Setup Initial

```bash
# 1. Cloner le projet
git clone <repository-url>
cd FAF

# 2. Installer les dépendances
npm install

# 3. Configuration environnement
cp .env.multitenant.example .env
# Éditer .env avec vos variables Supabase

# 4. Créer les tables Supabase
# Exécuter le contenu de sql/schema.sql dans l'éditeur SQL Supabase

# 5. Démarrer en développement (Vercel CLI)
vercel dev
```

### Variables d'Environnement Requises

```bash
# .env
NODE_ENV=development

# Supabase (obligatoire)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJhbGci...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGci...

# JWT (obligatoire)
JWT_SECRET=your-super-secret-key-min-32-chars

# Upload images (optionnel)
CLOUDINARY_CLOUD_NAME=your-cloud
CLOUDINARY_API_KEY=your-key
CLOUDINARY_API_SECRET=your-secret

# Config formulaire
PIE_CHART_QUESTION=En rapide, comment ça va ?
```

---

## 🏗️ Architecture

### Structure Serverless (Vercel)

```
FAF/
├── api/                        # Vercel Serverless Functions (12 max)
│   ├── auth/                   # Authentification JWT
│   │   ├── register.js         # POST - Inscription admin
│   │   └── login.js            # POST - Connexion JWT
│   ├── form/
│   │   └── [username].js       # GET - Formulaire dynamique
│   ├── response/
│   │   ├── submit.js           # POST - Soumission formulaire
│   │   └── view/[token].js     # GET - Consultation privée
│   ├── admin/                  # Dashboard admin (JWT + Payment requis)
│   │   ├── dashboard.js        # GET - Stats et réponses
│   │   ├── responses.js        # GET - Liste paginée
│   │   └── response/[id].js    # GET/PATCH/DELETE - CRUD
│   ├── payment/                # Système Stripe
│   │   ├── create-checkout.js  # POST - Créer checkout Stripe
│   │   ├── status.js           # GET - Vérifier statut paiement
│   │   └── webhook.js          # POST - Webhook Stripe
│   └── upload.js               # POST - Upload images Cloudinary
├── frontend/                   # Pages statiques
│   ├── public/                 # Pages publiques
│   │   ├── auth/               # Landing + Register + Login
│   │   ├── form/index.html     # Formulaire dynamique
│   │   └── view.html           # Comparaison privée
│   └── admin/                  # Dashboard admin
│       ├── admin.html          # Résumé + graphiques
│       ├── admin_gestion.html  # Gestion réponses
│       └── faf-admin.js        # Module ES6 JWT
├── middleware/                 # Middleware serverless
│   ├── auth.js                 # verifyJWT(), optionalAuth()
│   ├── payment.js              # requirePayment() - Stripe check
│   └── rateLimit.js            # Rate limiting (3/15min)
├── utils/                      # Utilitaires
│   ├── supabase.js             # Client Supabase
│   ├── jwt.js                  # Génération/vérification JWT
│   ├── tokens.js               # Tokens de consultation
│   ├── validation.js           # Validation inputs + XSS prevention
│   └── questions.js            # Normalisation questions
├── tests/                      # Tests automatisés
│   ├── auth.test.js            # Tests authentification JWT
│   ├── integration/            # Tests end-to-end
│   ├── performance/            # Tests de charge
│   └── security/               # Tests XSS, CSRF, rate limiting
├── sql/                        # Schema Supabase
│   ├── 001_initial_schema.sql  # Tables de base
│   ├── 002_rls_policies.sql    # Row Level Security
│   ├── 003_payment_columns.sql # Colonnes Stripe
│   ├── 004_grandfathered.sql   # Comptes grandfathered
│   └── 005_cleanup_test_data.sql # Nettoyage production
└── backend_mono_user_legacy/   # ⚠️ ARCHIVE - Ancien Express/MongoDB
```

### Technologies Utilisées

**Backend (Serverless):**
- **Vercel Serverless Functions** - Déploiement edge, auto-scaling
- **Supabase** (PostgreSQL) - Base de données avec Row Level Security
- **JWT** (jsonwebtoken) - Authentification stateless
- **bcrypt** - Hashing mots de passe

**Frontend:**
- **HTML5 + CSS3 + Vanilla JS** - Pas de framework
- **TailwindCSS** (via CDN) - Styling rapide
- **Chart.js** - Graphiques admin
- **ES6 Modules** - Architecture modulaire

---

## 🔐 Authentification & Sécurité

### Flow d'Authentification JWT

```
1. Register (POST /api/auth/register)
   → Créer admin dans Supabase
   → Générer JWT (7 jours)
   → Stocker dans localStorage

2. Login (POST /api/auth/login)
   → Vérifier credentials (bcrypt)
   → Générer JWT
   → Stocker dans localStorage

3. Accès Dashboard
   → checkAuth() vérifie JWT
   → GET /api/auth/verify avec Bearer token
   → Si invalide → Redirection /auth/login.html
```

### Row Level Security (RLS)

Toutes les données sont isolées par `owner_id` :

```sql
-- Policy exemple (responses table)
CREATE POLICY "Admins see only their responses"
ON responses FOR SELECT
USING (owner_id = auth.uid());
```

Chaque admin ne voit **QUE** ses propres données, même s'il manipule les requêtes.

### Protection Multi-Couche

- ✅ **JWT** - Authentification stateless (7 jours)
- ✅ **RLS** - Isolation données au niveau DB
- ✅ **Stripe** - Abonnement €12/mois + webhook validation
- ✅ **Rate Limiting** - 3 soumissions/15min
- ✅ **XSS Prevention** - HTML escaping + validation inputs
- ✅ **Input Validation** - Limites strictes (XSS, SQL injection)

---

## 🧪 Tests

### Tests Backend

```bash
# Tests authentification
npm test tests/auth.test.js

# Tests intégration complète
npm test tests/integration/full-flow.test.js

# Tests sécurité (XSS, CSRF, rate limiting)
npm test tests/security/xss-csrf-ratelimit.test.js

# Tests performance
npm test tests/performance/load.test.js

# Tous les tests
npm test
```

### Architecture de Tests

- **Unit tests**: Fonctions individuelles
- **Integration tests**: Flux complets (inscription → paiement → dashboard)
- **Security tests**: XSS, CSRF, rate limiting, injection SQL
- **Performance tests**: Load testing, temps de réponse

**Note**: Tests legacy dans `backend_mono_user_legacy/backend/tests/` (non utilisés)

---

## 📱 Utilisation

### 1. Créer un Compte Admin

```
1. Aller sur /auth/landing.html
2. Cliquer "Créer mon compte"
3. Remplir username + email + password
4. Compte créé → JWT généré → Redirection onboarding
```

### 2. Partager son Formulaire

```
1. Sur le dashboard admin
2. Cliquer "📋 Mon formulaire"
3. Lien copié : https://faf.app/form/{username}
4. Partager avec amis via WhatsApp/Email
```

### 3. Ami Remplit le Formulaire

```
1. Ouvrir le lien /form/{username}
2. Remplir nom + réponses (10-11 questions)
3. Upload 4 images
4. Soumettre → Recevoir lien privé
5. Lien privé : /view/{token} (comparaison 1vs1)
```

### 4. Admin Consulte les Résultats

```
1. Se connecter sur /auth/login.html
2. Dashboard : Résumé + graphiques
3. Gestion : Liste paginée des réponses
4. Actions : Voir/Modifier/Supprimer
```

---

## 🌍 Déploiement Vercel

### 1. Setup Vercel

```bash
# Installer Vercel CLI
npm i -g vercel

# Login
vercel login

# Déployer
vercel --prod
```

### 2. Variables d'Environnement Vercel

Dans le dashboard Vercel, ajouter :

```bash
NODE_ENV=production
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=eyJhbGci...
SUPABASE_SERVICE_ROLE_KEY=eyJhbGci...
JWT_SECRET=your-super-secret-key-min-32-chars
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_ID=price_...
CLOUDINARY_CLOUD_NAME=your-cloud
CLOUDINARY_API_KEY=your-key
CLOUDINARY_API_SECRET=your-secret
```

### 3. Configuration Supabase

1. **Créer les tables** : Exécuter `sql/schema.sql`
2. **Activer RLS** : Policies déjà dans le schema
3. **Auth Settings** : JWT secret doit correspondre à `.env`

---

## 📚 Documentation Complète

### Guides par Étape

- ✅ **[Steps 1-9](docs/steps/)** - Développement initial multi-tenant (2025-10)
- ✅ **[STEP_10_COMPLETED.md](docs/steps/STEP_10_COMPLETED.md)** - Migration MongoDB → Supabase
- ✅ **[STEP_11_COMPLETED.md](docs/steps/STEP_11_COMPLETED.md)** - Configuration Vercel
- ✅ **[STEP_12_COMPLETED.md](docs/steps/STEP_12_COMPLETED.md)** - Tests & Déploiement (130+ tests)

### Spécifications

- 📐 **[MULTITENANT_SPEC.md](docs/architecture/MULTITENANT_SPEC.md)** - Spécifications complètes
- 💳 **[STRIPE_SETUP.md](docs/STRIPE_SETUP.md)** - Configuration paiement Stripe
- 🤖 **[CLAUDE.md](CLAUDE.md)** - Guide pour Claude Code
- 📝 **[SESSION_03_NOV_2025.md](docs/SESSION_03_NOV_2025.md)** - Notes session (déploiement production)

---

## 🔄 Migration depuis Mono-User

L'ancienne version mono-utilisateur (Express + MongoDB + Sessions) a été archivée dans `backend_mono_user_legacy/`.

**⚠️ IMPORTANT**: Cette archive est conservée **uniquement pour référence historique**. Ne pas l'utiliser pour le développement.

### Différences Clés

| Aspect | Mono-User (legacy) | Multi-Tenant (actuel) |
|--------|-------------------|----------------------|
| **Architecture** | Express monolithe | Vercel Serverless |
| **Base de données** | MongoDB | Supabase (PostgreSQL) |
| **Authentification** | Sessions (cookies) | JWT (localStorage) |
| **Admins** | 1 seul (hardcodé) | Illimité (table admins) |
| **Isolation données** | N/A | RLS par owner_id |
| **Formulaires** | 1 seul (`/`) | 1 par admin (`/form/{username}`) |
| **Déploiement** | Serveur Node.js | Edge Functions |

---

## 🎯 Roadmap

### ✅ Version 2.0 (Actuelle - Production)

- [x] Architecture serverless (Vercel) - **12 fonctions max**
- [x] Multi-tenancy avec RLS (Supabase PostgreSQL)
- [x] Authentification JWT (7 jours expiry)
- [x] **Système de paiement Stripe** (€12/mois + grandfathered)
- [x] Dashboard admin avec graphiques (Chart.js)
- [x] Formulaires dynamiques par username
- [x] Upload images (Cloudinary)
- [x] Tests sécurité (XSS, CSRF, rate limiting)
- [x] **Déploiement production**: https://faf-multijoueur.vercel.app

### 🔮 Version 2.1 (Futur)

- [ ] Refresh tokens (auto-renewal JWT)
- [ ] Notifications email (réponses reçues via Resend)
- [ ] Export CSV/PDF des réponses
- [ ] Thèmes personnalisés par admin
- [ ] Statistiques avancées (tendances mensuelles)
- [ ] Gestion factures Stripe dans l'interface

---

## 📞 Support

**Questions ?**
- 📖 Consulter [MULTITENANT_SPEC.md](MULTITENANT_SPEC.md)
- 🐛 Reporter un Bug (GitHub Issues)
- 💡 Proposer une Feature

---

## 📄 License

MIT License - Voir LICENSE.md pour détails.

---

<div align="center">

**🔒 Multi-tenant sécurisé • 🚀 Serverless scalable • 💳 Stripe payment • 🌐 Production live**

**Version actuelle** : Multi-Tenant v2.0 (Production)
**URL Production** : https://faf-multijoueur.vercel.app
**Architecture** : 12 Vercel Functions + Supabase PostgreSQL + Stripe
**Last Updated** : November 7, 2025

</div>
