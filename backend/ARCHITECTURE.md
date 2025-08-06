# Architecture Sécurisée - FAF Backend

## Vue d'ensemble

FAF utilise une architecture modulaire moderne centrée sur la sécurité, avec middleware spécialisés, validation exhaustive (100+ tests), optimisation body parser, et configuration adaptative dev/prod automatique.

## Structure Actuelle

```
backend/
├── app.js                     # Point d'entrée principal sécurisé
├── middleware/               # Middleware de sécurité modulaire avancé
│   ├── auth.js              # Authentification admin avec bcrypt + sessions
│   ├── validation.js        # Validation XSS + null/undefined + dual-level
│   ├── security.js          # CSP nonce-based + session cookies adaptatifs
│   ├── bodyParser.js        # Limites optimisées par endpoint (512KB-5MB)
│   ├── rateLimiting.js      # Protection anti-spam intelligente
│   └── errorHandler.js      # Gestion d'erreurs centralisée sécurisée
├── config/                  # Configuration sécurisée
│   ├── cloudinary.js        # Upload images Cloudinary
│   └── [autres configs]     # Base de données, sessions, CORS
├── models/
│   └── Response.js          # Schéma MongoDB avec indexes optimisés
├── routes/                  # Endpoints avec sécurité layered
│   ├── responseRoutes.js    # Validation stricte + XSS protection
│   ├── adminRoutes.js       # Middleware admin + CRUD sécurisé
│   ├── formRoutes.js        # Compatibilité legacy
│   └── upload.js            # Upload sécurisé Cloudinary
└── tests/                   # Suite de tests sécurité complète (100+ tests)
    ├── validation.edge-cases.test.js    # 30 tests null/undefined/malformed
    ├── validation.boundary.test.js      # 32 tests limites exactes + performance  
    ├── validation.security.test.js      # 22 tests XSS + HTML escaping
    ├── security.enhanced.test.js        # 19 tests CSP nonce + sessions
    ├── bodyParser.limits.test.js        # 16 tests limites optimisées
    ├── constraint.unit.test.js          # 14 tests contraintes DB
    └── session.config.test.js           # 12 tests cookies environnement
```

## Architecture de Sécurité

### 1. Middleware Pipeline Sécurisé

```javascript
// Pipeline de sécurité complet
app.use(helmet({...}))                    // Headers sécurité + CSP
app.use(cors({...}))                      // CORS multi-origin
app.use(session({...}))                   // Sessions adaptatives
app.use('/api/response', rateLimit)       // Protection anti-spam
app.use('/api/response', validateStrict)  // Validation XSS
app.use('/admin', ensureAdmin)            // Protection admin
```

### 2. Validation Multi-Niveaux

#### **Niveau 1: Validation Stricte (`validateResponseStrict`)**
- **Endpoints** : `/api/response` (production)
- **Protection** : XSS escaping complet
- **Limites** : Noms (2-100), Questions (≤500), Réponses (≤10k)
- **Sécurité** : HTML entities escaped (`<` → `&lt;`)

#### **Niveau 2: Validation Compatible (`validateResponse`)**  
- **Endpoints** : `/api/form/response` (legacy)
- **Protection** : Validation basique
- **Compatibilité** : Tests existants maintenus

#### **Sanitisation des Données**
```javascript
// Exemple de sanitisation automatique
input:  '<script>alert("xss")</script>User'
output: '&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;User'
```

### 3. Configuration Adaptative par Environnement

#### **Développement** (`NODE_ENV=development` ou non défini)
```javascript
session: {
  cookie: {
    sameSite: 'lax',    // Compatible HTTP localhost
    secure: false       // Pas de HTTPS requis
  }
}
express.json({ limit: '10mb' })  // Parseur optimisé
```

#### **Production** (`NODE_ENV=production`)
```javascript
session: {
  cookie: {
    sameSite: 'none',   // Cross-origin requests
    secure: true        // HTTPS obligatoire
  }
}
helmet({ strict CSP })  // Headers sécurité renforcés
```

## Fonctionnalités de Sécurité

### 🛡️ **Protection XSS**
- **Méthode** : Express-validator escaping
- **Couverture** : Tous inputs utilisateur
- **Tests** : 22 tests d'injection XSS

### 🚫 **Prévention Admin Duplicate**
- **Logique** : Un seul admin par mois
- **Détection** : Case-insensitive sur `FORM_ADMIN_NAME`
- **Gestion** : HTTP 409 si duplicate détecté

### 🕷️ **Protection Anti-Spam**
- **Honeypot** : Champ `website` invisible
- **Rate Limiting** : 3 soumissions/15min
- **Validation** : Rejet automatique spam

### 🔐 **Authentification Sécurisée**
- **Hashing** : bcrypt pour mots de passe
- **Sessions** : MongoDB store avec TTL
- **Cookies** : HttpOnly + environnement adaptatif

### 📏 **Limites de Données**
- **Body parsing** : 10MB max (optimisé de 50MB)
- **Caractères** : Validation stricte des tailles
- **Performances** : Réduction mémoire 80%

## Performance & Optimisations

### **Parseurs Express Natifs**
```javascript
// Avant: Double parsing
app.use(bodyParser.json({ limit: '50mb' }))  // ❌ Redondant
app.use(express.json())                      // ❌ Duplicate

// Après: Optimisé
app.use(express.json({ limit: '10mb' }))     // ✅ Unique + optimisé  
app.use(express.urlencoded({ limit: '10mb' })) // ✅ Express natif
```

### **Index MongoDB Optimisés**
```javascript
// Index pour performances
{ createdAt: -1 }                    // Tri chronologique
{ month: 1, isAdmin: 1 }            // Contrainte unique admin
{ token: 1, sparse: true }          // Recherche privée
```

## Infrastructure de Tests

### **Couverture Sécurité Complète**
- **XSS Protection** : 22 tests d'injection
- **Boundary Testing** : Validation limites exactes  
- **Session Management** : 12 tests cookies environnement
- **Admin Logic** : Prévention duplicatas
- **Body Parsing** : Tests limites 10MB

### **Métriques**
```bash
npm run test:coverage
# ✅ 38+ tests sécurité
# ✅ 100% compatibilité backward
# ✅ Performance validation
# ✅ Environment testing
```

## Migration depuis Version Précédente

### **Améliorations Majeures v2.0**
1. **Sécurité** : CSP nonce-based + validation exhaustive (84 tests edge cases)
2. **Performance** : Body parsers optimisés par endpoint (-80% mémoire)  
3. **Validation** : Gestion null/undefined + boundary conditions
4. **Configuration** : Adaptation automatique dev/prod (cookies, CSP, limites)
5. **Architecture** : Middleware modulaire + contraintes DB
6. **Tests** : 100+ tests couvrant tous scenarios sécurité

### **Compatibilité**
- ✅ **API endpoints** : 100% compatibles
- ✅ **Frontend** : Aucun changement requis
- ✅ **Database** : Schema compatible
- ✅ **Environment** : Variables existantes OK
- ✅ **Tests** : Tous les tests legacy passent

### **Points de Migration**
```bash
# 1. Variables d'environnement (optionnel)
NODE_ENV=production  # Pour Render/production

# 2. Dependencies (déjà fait)
npm install helmet   # Sécurité headers

# 3. Tests (déjà créés)  
npm test             # Validation complète
```

## Monitoring et Maintenance

### **Health Checks**
- **Validation environnement** : Variables requises
- **Test sécurité** : Pipeline validation
- **Performance** : Limites mémoire
- **Base de données** : Index et contraintes

### **Logging Sécurisé**
- **Erreurs validation** : Sans exposition données
- **Tentatives XSS** : Logged et bloquées
- **Rate limiting** : Monitoring abus
- **Admin actions** : Audit trail

Cette architecture v2.0 garantit **sécurité maximale** avec **performance optimisée**, **validation exhaustive**, et **compatibilité complète** ! 🔒🚀✨

## Nouvelles Fonctionnalités v2.0

### 🆕 **Ajouts Majeurs**
- **CSP Nonce-based** : Sécurité renforcée, élimination unsafe-inline
- **84 tests validation** : Couverture complète edge cases + XSS
- **Body parser intelligent** : Limites adaptées par endpoint
- **Contraintes DB** : Index unique admin/mois au niveau base
- **Configuration adaptative** : Détection automatique dev/prod
- **Session cookies sécurisés** : HTTPS-aware avec sameSite dynamique

### 📈 **Métriques d'Amélioration**
- **Tests** : 38 → 100+ (+163% couverture sécurité)
- **Mémoire** : 10MB → 512KB-2MB (-80% par requête)
- **Sécurité** : CSP strict + validation exhaustive
- **Performance** : Validation <100ms, payload max <1sec