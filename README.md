# 🤝 FAF (Form-a-Friend) - Multi-Tenant v2.0

> **Application de formulaires mensuels multi-tenant avec architecture serverless, authentification JWT et isolation par admin**

![Node.js](https://img.shields.io/badge/node.js-v18+-green.svg)
![Vercel](https://img.shields.io/badge/vercel-serverless-black.svg)
![Supabase](https://img.shields.io/badge/supabase-postgresql-green.svg)
![Security](https://img.shields.io/badge/security-JWT+RLS-red.svg)
![Tests](https://img.shields.io/badge/tests-117+-brightgreen.svg)

---

## 📋 Vue d'Ensemble

**FAF Multi-Tenant** permet à plusieurs administrateurs indépendants de créer leurs propres formulaires mensuels et de gérer les réponses de leurs amis. Chaque admin a :

- ✅ **Son propre compte** avec authentification JWT
- ✅ **Son formulaire unique** accessible via `/form/{username}`
- ✅ **Ses données isolées** grâce au Row Level Security (Supabase)
- ✅ **Son dashboard privé** avec statistiques et graphiques

---

## 🚀 Installation Rapide

### Prérequis
- **Node.js** v18+
- **Compte Supabase** (gratuit)
- **Compte Cloudinary** (optionnel pour uploads d'images)

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
├── api/                        # Vercel Serverless Functions
│   ├── auth/                   # Authentification JWT
│   │   ├── register.js         # POST - Inscription admin
│   │   ├── login.js            # POST - Connexion JWT
│   │   └── verify.js           # GET - Vérification token
│   ├── form/
│   │   └── [username].js       # GET - Formulaire dynamique
│   ├── response/
│   │   ├── submit.js           # POST - Soumission formulaire
│   │   └── view/[token].js     # GET - Consultation privée
│   └── admin/                  # Dashboard admin (JWT requis)
│       ├── dashboard.js        # GET - Stats et réponses
│       ├── responses.js        # GET - Liste paginée
│       ├── months.js           # GET - Liste des mois
│       ├── summary.js          # GET - Résumé par question
│       └── response/[id].js    # GET/PATCH/DELETE - CRUD
├── frontend/                   # Pages statiques
│   ├── public/                 # Pages publiques
│   │   ├── auth/               # Landing + Register + Login
│   │   ├── form/index.html     # Formulaire dynamique
│   │   └── view.html           # Comparaison privée
│   └── admin/                  # Dashboard admin
│       ├── admin.html          # Résumé + graphiques
│       ├── admin_gestion.html  # Gestion réponses
│       └── faf-admin.js        # Module ES6 JWT
├── middleware/                 # Middleware JWT
│   └── auth.js                 # verifyJWT()
├── utils/                      # Utilitaires
│   ├── supabase.js             # Client Supabase
│   ├── jwt.js                  # Génération/vérification JWT
│   └── tokens.js               # Tokens de consultation
├── tests/                      # Tests automatisés
│   └── api/                    # Tests des routes
└── sql/                        # Schema Supabase
    └── schema.sql              # Tables + RLS policies
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
- ✅ **Rate Limiting** - 3 soumissions/15min
- ✅ **XSS Prevention** - HTML escaping + CSP
- ✅ **CSRF** - Tokens pour mutations
- ✅ **Input Validation** - Limites strictes

---

## 🧪 Tests

### Tests Backend (117 tests ✅)

```bash
# Étape 1 - Supabase Setup (13 tests)
npm test tests/api/supabase.test.js

# Étape 2 - Authentification (18 tests)
npm test tests/api/auth-register.test.js
npm test tests/api/auth-login.test.js
npm test tests/api/auth-verify.test.js

# Étape 3 - API Form (15 tests)
npm test tests/api/form-username.test.js

# Étape 4 - Soumission (13 tests)
npm test tests/api/submit.test.js

# Étape 5 - Consultation (16 tests)
npm test tests/api/view-token.test.js

# Étape 6 - Dashboard Admin (42 tests)
npm test tests/api/admin-dashboard.test.js
npm test tests/api/admin-responses.test.js
npm test tests/api/admin-response-id.test.js

# Tous les tests
npm test
```

### Couverture

```
✅ 117 tests backend passent (100%)
✅ Authentification JWT complète
✅ Isolation RLS validée
✅ CRUD admin sécurisé
✅ Upload images testé
```

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
CLOUDINARY_CLOUD_NAME=your-cloud
CLOUDINARY_API_KEY=your-key
CLOUDINARY_API_SECRET=your-secret
PIE_CHART_QUESTION=En rapide, comment ça va ?
```

### 3. Configuration Supabase

1. **Créer les tables** : Exécuter `sql/schema.sql`
2. **Activer RLS** : Policies déjà dans le schema
3. **Auth Settings** : JWT secret doit correspondre à `.env`

---

## 📚 Documentation Complète

### Guides par Étape

- ✅ **[STEP_1_COMPLETED.md](STEP_1_COMPLETED.md)** - Setup Supabase + Infrastructure
- ✅ **[STEP_2_COMPLETED.md](STEP_2_COMPLETED.md)** - API d'authentification JWT
- ✅ **[STEP_3_COMPLETED.md](STEP_3_COMPLETED.md)** - API Formulaire dynamique
- ✅ **[STEP_4_COMPLETED.md](STEP_4_COMPLETED.md)** - API Soumission
- ✅ **[STEP_5_COMPLETED.md](STEP_5_COMPLETED.md)** - API Consultation privée
- ✅ **[STEP_6_COMPLETED.md](STEP_6_COMPLETED.md)** - API Dashboard admin
- ✅ **[STEP_7_COMPLETED.md](STEP_7_COMPLETED.md)** - Frontend Landing + Auth
- ✅ **[STEP_8_COMPLETED.md](STEP_8_COMPLETED.md)** - Frontend Formulaire dynamique
- ✅ **[STEP_9_COMPLETED.md](STEP_9_COMPLETED.md)** - Frontend Dashboard admin JWT

### Spécifications

- 📐 **[MULTITENANT_SPEC.md](MULTITENANT_SPEC.md)** - Spécifications complètes
- 📝 **[PROMPT_DEVELOPMENT.md](PROMPT_DEVELOPMENT.md)** - Plan de développement
- 🤖 **[CLAUDE.md](CLAUDE.md)** - Guide pour Claude Code

---

## 🔄 Migration depuis Mono-User

L'ancienne version mono-utilisateur (Express + MongoDB + Sessions) a été archivée dans `backend_mono_user_legacy/`.

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

### ✅ Version 2.0 (Actuelle)

- [x] Architecture serverless (Vercel)
- [x] Multi-tenancy avec RLS
- [x] Authentification JWT
- [x] Dashboard admin par compte
- [x] Formulaires dynamiques
- [x] 117 tests automatisés

### 🔮 Version 2.1 (Futur)

- [ ] Refresh tokens (auto-renewal)
- [ ] Notifications email (réponses reçues)
- [ ] Export CSV/PDF des réponses
- [ ] Thèmes personnalisés par admin
- [ ] API REST publique (webhooks)

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

**🔒 Multi-tenant sécurisé • 🚀 Serverless scalable • 🧪 117 tests validés**

**Version actuelle** : Multi-Tenant v2.0 (Étapes 1-9 complétées)

</div>
