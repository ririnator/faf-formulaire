# Structure du Projet FAF Multi-Tenant

**Date** : 14 octobre 2025
**Version** : Multi-Tenant v2.0 (Étapes 1-9)

---

## 📁 Structure Complète

```
FAF/
├── 📄 README.md                      # Documentation principale (multi-tenant)
├── 📄 CLAUDE.md                      # Guide Claude Code
├── 📄 MULTITENANT_SPEC.md            # Spécifications complètes
├── 📄 PROMPT_DEVELOPMENT.md          # Plan de développement
│
├── 📁 api/                           # ⭐ Routes Serverless Vercel
│   ├── auth/                         # Authentification JWT
│   │   ├── register.js               # POST - Inscription
│   │   ├── login.js                  # POST - Connexion
│   │   └── verify.js                 # GET - Vérification JWT
│   ├── form/
│   │   └── [username].js             # GET - Formulaire dynamique
│   ├── response/
│   │   ├── submit.js                 # POST - Soumission
│   │   └── view/[token].js           # GET - Consultation privée
│   └── admin/                        # Dashboard (JWT requis)
│       ├── dashboard.js              # GET - Stats et réponses
│       ├── responses.js              # GET - Liste paginée
│       ├── months.js                 # GET - Liste des mois
│       ├── summary.js                # GET - Résumé par question
│       └── response/[id].js          # CRUD réponse individuelle
│
├── 📁 frontend/                      # ⭐ Pages Statiques
│   ├── public/
│   │   ├── auth/                     # Pages d'authentification
│   │   │   ├── landing.html          # Page d'accueil
│   │   │   ├── register.html         # Inscription
│   │   │   ├── login.html            # Connexion
│   │   │   └── onboarding.html       # Guide post-inscription
│   │   ├── form/
│   │   │   └── index.html            # Formulaire dynamique
│   │   ├── view/
│   │   │   └── index.html            # Comparaison privée
│   │   ├── js/
│   │   │   ├── auth.js               # Module authentification
│   │   │   └── form.js               # Module formulaire
│   │   └── css/
│   │       └── main.css              # Styles globaux
│   └── admin/
│       ├── admin.html                # Dashboard résumé + graphiques
│       ├── admin_gestion.html        # Gestion réponses paginée
│       └── faf-admin.js              # Module ES6 JWT + API
│
├── 📁 middleware/                    # ⭐ Middleware Serverless
│   ├── auth.js                       # verifyJWT() + optionalAuth()
│   └── rateLimit.js                  # Rate limiting par IP
│
├── 📁 utils/                         # ⭐ Utilitaires
│   ├── supabase.js                   # Client Supabase
│   ├── jwt.js                        # Génération/vérification JWT
│   ├── tokens.js                     # Tokens consultation
│   ├── validation.js                 # Validation inputs
│   └── questions.js                  # Normalisation questions
│
├── 📁 tests/                         # ⭐ Tests Automatisés (117)
│   ├── api/
│   │   ├── auth-register.test.js     # 6 tests
│   │   ├── auth-login.test.js        # 6 tests
│   │   ├── auth-verify.test.js       # 6 tests
│   │   ├── form-username.test.js     # 15 tests
│   │   ├── submit.test.js            # 13 tests
│   │   ├── view-token.test.js        # 16 tests
│   │   ├── admin-dashboard.test.js   # 11 tests
│   │   ├── admin-responses.test.js   # 13 tests
│   │   └── admin-response-id.test.js # 18 tests
│   └── helpers/
│       └── testData.js               # Données de test
│
├── 📁 sql/                           # ⭐ Schema Supabase
│   └── schema.sql                    # Tables + RLS policies
│
├── 📁 docs/                          # Documentation étapes
│   ├── STEP_1_COMPLETED.md           # Setup Supabase (13 tests)
│   ├── STEP_2_COMPLETED.md           # API Auth (18 tests)
│   ├── STEP_3_COMPLETED.md           # API Form (15 tests)
│   ├── STEP_4_COMPLETED.md           # API Submit (13 tests)
│   ├── STEP_5_COMPLETED.md           # API View (16 tests)
│   ├── STEP_6_COMPLETED.md           # API Dashboard (42 tests)
│   ├── STEP_7_COMPLETED.md           # Frontend Auth (4 pages)
│   ├── STEP_8_COMPLETED.md           # Frontend Form (1 page)
│   └── STEP_9_COMPLETED.md           # Frontend Dashboard JWT
│
├── 📁 backend_mono_user_legacy/      # ⚠️ ARCHIVE (ne pas utiliser)
│   ├── README.md                     # Explication archive
│   ├── backend/                      # Ancien code Express/MongoDB
│   ├── test_scripts/                 # Scripts de test manuels
│   └── archives/                     # Docs de travail anciennes
│
├── 📄 package.json                   # Dependencies npm
├── 📄 vercel.json                    # Configuration Vercel
└── 📄 .env.multitenant.example       # Template variables d'env
```

---

## 🎯 Fichiers Clés par Rôle

### 🔐 Backend Serverless

| Fichier | Description | Tests |
|---------|-------------|-------|
| `api/auth/register.js` | Inscription + JWT | 6 ✅ |
| `api/auth/login.js` | Connexion + JWT | 6 ✅ |
| `api/auth/verify.js` | Vérification JWT | 6 ✅ |
| `api/form/[username].js` | Formulaire dynamique | 15 ✅ |
| `api/response/submit.js` | Soumission sécurisée | 13 ✅ |
| `api/response/view/[token].js` | Consultation privée | 16 ✅ |
| `api/admin/dashboard.js` | Dashboard stats | 11 ✅ |
| `api/admin/responses.js` | Liste paginée | 13 ✅ |
| `api/admin/response/[id].js` | CRUD réponse | 18 ✅ |
| `api/admin/months.js` | Liste mois | - |
| `api/admin/summary.js` | Résumé questions | - |

**Total Backend** : 117 tests ✅

---

### 🎨 Frontend Pages

| Page | Route | Description | Auth |
|------|-------|-------------|------|
| Landing | `/auth/landing.html` | Page d'accueil | Public |
| Register | `/auth/register.html` | Inscription | Public |
| Login | `/auth/login.html` | Connexion | Public |
| Onboarding | `/auth/onboarding.html` | Guide démarrage | JWT |
| Formulaire | `/form/{username}` | Formulaire dynamique | Public |
| Comparaison | `/view/{token}` | Consultation 1vs1 | Token |
| Dashboard | `/admin` | Résumé + graphiques | JWT |
| Gestion | `/admin/gestion` | Liste réponses | JWT |

---

### 🛠️ Middleware & Utils

| Fichier | Exports | Usage |
|---------|---------|-------|
| `middleware/auth.js` | `verifyJWT()`, `optionalAuth()` | Protection routes admin |
| `middleware/rateLimit.js` | `createRateLimiter()` | Anti-spam |
| `utils/supabase.js` | `createClient()`, `supabaseAdmin` | DB Supabase |
| `utils/jwt.js` | `generateToken()`, `verifyToken()` | JWT auth |
| `utils/tokens.js` | `generateViewToken()` | Tokens consultation |
| `utils/validation.js` | Validators | Input validation |
| `utils/questions.js` | `normalizeQuestion()` | Normalisation |

---

## 🗄️ Base de Données Supabase

### Tables Principales

```sql
-- Admins (propriétaires de formulaires)
admins (
  id UUID PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT,
  created_at TIMESTAMP
)

-- Réponses (isolées par owner_id via RLS)
responses (
  id UUID PRIMARY KEY,
  owner_id UUID REFERENCES admins(id),
  name TEXT,
  responses JSONB,
  month TEXT,
  is_owner BOOLEAN,
  token TEXT UNIQUE,
  created_at TIMESTAMP
)
```

### RLS Policies

- **Admins voient uniquement leurs réponses** (`owner_id = auth.uid()`)
- **Insertion limitée à l'admin connecté**
- **Modification/suppression uniquement par owner**

---

## 🚀 Commandes Utiles

```bash
# Développement
vercel dev                    # Serveur local Vercel

# Tests
npm test                      # Tous les tests backend
npm test tests/api/auth*      # Tests authentification
npm test tests/api/admin*     # Tests dashboard admin

# Déploiement
vercel --prod                 # Déploiement production
```

---

## 📦 Dépendances Principales

```json
{
  "dependencies": {
    "@supabase/supabase-js": "^2.39.0",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "@supabase/supabase-js": "^2.39.0"
  }
}
```

---

## ⚠️ Ancien Code (Archive)

Le dossier `backend_mono_user_legacy/` contient l'ancienne version mono-utilisateur :

```
backend_mono_user_legacy/
├── README.md                 # ⚠️ Explication archive
├── README_MONO_USER.md       # Documentation ancienne version
├── backend/                  # Express + MongoDB (OBSOLÈTE)
├── test_scripts/             # Scripts de test manuels
└── archives/                 # Docs de travail anciennes
```

**⚠️ NE PAS UTILISER EN PRODUCTION**

Cette archive est conservée uniquement pour :
- 📖 Référence historique
- 🔍 Comparer avec la nouvelle architecture
- 📚 Comprendre les décisions de migration

---

## 🎯 Prochaines Étapes

- [ ] **Étape 10** : Migration données MongoDB → Supabase
- [ ] **Étape 11** : Frontend - Page de comparaison
- [ ] **Étape 12** : Tests End-to-End
- [ ] **Étape 13** : Optimisations & Monitoring

---

**Version actuelle** : Multi-Tenant v2.0 (Étapes 1-9 complétées)
**Total tests backend** : 117 ✅
**Architecture** : Vercel Serverless + Supabase + JWT + RLS
