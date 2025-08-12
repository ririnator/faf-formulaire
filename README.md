# 🤝 FAF (Form-a-Friend) - Application Mensuelle Sécurisée

> **Application de formulaires mensuels entre amis avec architecture sécurisée, validation XSS, et protection anti-spam**

![Node.js](https://img.shields.io/badge/node.js-v18+-green.svg)
![Express](https://img.shields.io/badge/express-v5+-blue.svg) 
![Security](https://img.shields.io/badge/security-helmet+XSS-red.svg)
![Tests](https://img.shields.io/badge/tests-100+-brightgreen.svg)

## 📋 Table des Matières

- [🚀 Installation Rapide](#-installation-rapide)
- [🏗️ Architecture](#️-architecture)
- [🛡️ Sécurité](#️-sécurité)
- [🧪 Tests](#-tests)
- [🌍 Déploiement](#-déploiement)
- [📚 Documentation](#-documentation)

---

## 🚀 Installation Rapide

### Prérequis
- **Node.js** v18+ 
- **MongoDB** (local ou cloud)
- **npm** ou **yarn**

### Setup Initial

```bash
# 1. Cloner le projet
git clone <repository-url>
cd FAF

# 2. Installer les dépendances backend
cd backend
npm install

# 3. Configuration environnement
cp .env.example .env
# Éditer .env avec vos variables

# 4. Démarrer en développement  
npm run dev
```

### Variables d'Environnement Requises

```bash
# .env
NODE_ENV=development                    # ou production
MONGODB_URI=mongodb://localhost:27017/faf
SESSION_SECRET=your-super-secret-key
LOGIN_ADMIN_USER=admin
LOGIN_ADMIN_PASS=$2b$10$hashed_password
FORM_ADMIN_NAME=riri
APP_BASE_URL=http://localhost:3000
FRONTEND_URL=http://localhost:3000
CLOUDINARY_CLOUD_NAME=your-cloud
CLOUDINARY_API_KEY=your-key
CLOUDINARY_API_SECRET=your-secret
```

### Commandes Disponibles

```bash
# Développement
npm run dev              # Serveur avec hot-reload
npm start               # Serveur production

# Tests
npm test                # Tests backend complets
npm run test:watch      # Tests backend en mode watch
npm run test:coverage   # Couverture de tests backend
npm run test:dynamic    # Tests d'intégration options dynamiques
npm run test:frontend   # Tests frontend
npm run test:frontend:watch # Tests frontend en mode watch
npm run test:frontend:coverage # Couverture tests frontend
npm run test:form       # Test formulaire local
npm run test:all        # Tous les tests (backend + frontend)
npm run test:all:coverage # Couverture complète

# Utilitaires
npm run validate-env    # Vérifier les variables d'env
```

---

## 🏗️ Architecture

### Structure du Projet

```
FAF/
├── 📁 backend/                 # Serveur Express sécurisé
│   ├── 📄 app.js              # Point d'entrée principal
│   ├── 📁 config/             # Configuration modulaire
│   │   ├── cloudinary.js      # Configuration upload Cloudinary
│   │   ├── cors.js           # Configuration CORS
│   │   ├── database.js       # Configuration MongoDB
│   │   ├── environment.js    # Validation variables d'environnement
│   │   └── session.js        # Configuration sessions et cookies
│   ├── 📁 services/          # Couche logique métier
│   │   ├── authService.js          # Logique authentification
│   │   ├── responseService.js      # CRUD réponses et validation
│   │   ├── uploadService.js        # Traitement uploads Cloudinary
│   │   ├── serviceFactory.js       # Factory pattern et injection dépendances
│   │   ├── sessionCleanupService.js    # Nettoyage automatique des sessions expirées
│   │   ├── sessionMonitoringService.js # Surveillance temps réel des sessions
│   │   ├── hybridIndexMonitor.js       # Monitoring performance index dual-auth
│   │   ├── dbPerformanceMonitor.js     # Monitoring performance base de données
│   │   ├── realTimeMetrics.js          # Métriques temps réel
│   │   └── performanceAlerting.js      # Système d'alertes performance
│   ├── 📁 middleware/         # Middleware de sécurité modulaire
│   │   ├── auth.js           # Authentification admin bcrypt
│   │   ├── validation.js     # Validation XSS + null/undefined
│   │   ├── security.js       # CSP nonce-based + sessions
│   │   ├── bodyParser.js     # Limites optimisées par endpoint
│   │   ├── rateLimiting.js   # Protection anti-spam intelligente
│   │   ├── csrf.js           # Protection CSRF
│   │   ├── errorHandler.js   # Gestion centralisée des erreurs
│   │   ├── paramValidation.js # Validation paramètres URL
│   │   └── sessionMonitoring.js # Surveillance sécurisée des sessions
│   ├── 📁 routes/            # Endpoints API
│   │   ├── responseRoutes.js # Soumission sécurisée
│   │   ├── adminRoutes.js    # Interface admin
│   │   ├── formRoutes.js     # Utilitaires formulaires
│   │   └── upload.js         # Upload Cloudinary
│   ├── 📁 models/            # Schémas MongoDB
│   ├── 📁 tests/             # Suite de tests sécurité (100+)
│   │   ├── validation.*.test.js           # Tests validation (84+ tests)
│   │   ├── security.*.test.js             # Tests sécurité XSS/CSP
│   │   ├── bodyParser.*.test.js           # Tests limites optimisées
│   │   ├── constraint.*.test.js           # Tests contraintes DB
│   │   ├── dynamic.*.test.js              # Tests options dynamiques
│   │   ├── integration.*.test.js          # Tests d'intégration complète
│   │   ├── sessionMonitoring.test.js      # Tests surveillance sessions (25+ tests)
│   │   ├── sessionManagement.integration.test.js # Tests intégration sessions
│   │   └── dbPerformanceMonitor.test.js   # Tests monitoring performance DB
│   └── 📁 utils/             # Utilitaires partagés
├── 📁 frontend/              # Interface utilisateur
│   ├── 📁 public/            # Pages publiques
│   │   ├── index.html        # Formulaire principal
│   │   ├── view.html         # Affichage sécurisé des réponses
│   │   └── login.html        # Connexion admin
│   ├── 📁 admin/             # Interface admin
│   │   ├── core-utils.js     # Utilitaires essentiels (chargés sync)
│   │   ├── admin-utils.js    # Fonctionnalités étendues (async)
│   │   ├── admin.html        # Dashboard principal
│   │   └── admin_gestion.html # Gestion des réponses
│   └── 📁 tests/             # Tests frontend
│       ├── dynamic-option.test.js    # Tests options dynamiques
│       ├── form-integration.test.js  # Tests intégration formulaires
│       ├── form-submission.test.js   # Tests soumission
│       └── real-form-submission.test.js # Tests réalistes
├── 📁 docs/                  # Documentation technique
│   ├── ARCHITECTURE.md              # Architecture sécurisée
│   ├── SERVICE_PATTERNS.md          # Patterns de services
│   ├── SESSION_CONFIG.md            # Configuration sessions
│   ├── ERROR_HANDLING.md            # Gestion d'erreurs
│   ├── MIGRATION_ROLLBACK_PROCEDURES.md  # Procédures rollback migration
│   └── enhanced-rate-limiting.md    # Rate limiting avancé
└── 📚 Documentation/
```

### Technologies Utilisées

**Backend:**
- **Express.js** v5+ - Framework web moderne avec optimisations
- **MongoDB** + Mongoose v8+ - Base de données avec indexes optimisés
- **Helmet.js** v8+ - Headers de sécurité et CSP nonce-based
- **bcrypt** v6+ - Hashing mots de passe sécurisé
- **express-validator** v7+ - Validation stricte + protection XSS
- **express-rate-limit** v7+ - Rate limiting intelligent par endpoint  
- **express-session** v1.18+ - Gestion sessions avec MongoDB store
- **Cloudinary** v1.41+ - Upload d'images sécurisé avec validation MIME
- **Multer** v2+ - Gestion multipart/form-data pour uploads
- **CORS** v2.8+ - Configuration CORS multi-origins

**Frontend:**
- **HTML5** + **CSS3** + **Vanilla JS** - Architecture moderne sans framework
- **TailwindCSS** (admin interface) - Styling utilitaire responsive
- **Chart.js** (graphiques admin) - Visualisations données interactives
- **Modular Architecture** - Pattern DRY avec utilitaires partagés
- **XSS-Safe Rendering** - Manipulation DOM sécurisée sans innerHTML
- **Frontend Testing** - Suite de tests Jest dédiée

**DevOps & Testing:**
- **Jest** v30+ - Framework de tests avec couverture complète
- **Supertest** v7+ - Tests d'intégration API
- **mongodb-memory-server** v10+ - Tests avec MongoDB en mémoire  
- **Nodemon** v3+ - Hot-reload développement

---

## 🛡️ Sécurité

### Protection Multi-Couche

#### 🔒 **Headers de Sécurité Avancés (Helmet.js + CSP Nonce)**
```javascript
// CSP avec nonces dynamiques (élimine unsafe-inline)
Content-Security-Policy: default-src 'self'; 
  script-src 'self' 'nonce-Ac8dW2x9...' cdn.jsdelivr.net;
  style-src 'self' 'nonce-Ac8dW2x9...' cdn.tailwindcss.com;
  frame-ancestors 'none'
X-Content-Type-Options: nosniff  
X-Frame-Options: SAMEORIGIN
```

#### 🧹 **Validation & Sanitisation Avancée**
```javascript
// Exemple: Input malveillant automatiquement sécurisé
Input:  '<script>alert("hack")</script>John'
Output: '&lt;script&gt;alert(&quot;hack&quot;)&lt;&#x2F;script&gt;John'

// Décodage sécurisé avec whitelist (nouvellement ajouté)
const SAFE_HTML_ENTITIES = {
  '&#x27;': "'", '&quot;': '"', '&eacute;': 'é', // Liste contrôlée
};
// Rejette automatiquement: <script>, <iframe>, javascript:, etc.
```

#### 🌍 **Support UTF-8 Complet**
```javascript
// Middleware global pour l'encodage des caractères
app.use((req, res, next) => {
  res.json = function(data) {
    res.set('Content-Type', 'application/json; charset=utf-8');
    return originalJson.call(this, data);
  };
});
// Supporte parfaitement: éàçùûîôêâ, etc.
```

#### 🛡️ **Architecture XSS-Proof** 
```javascript
// ❌ Dangereux (ancien code)
block.innerHTML = `<h2>${userQuestion}</h2>`;

// ✅ Sécurisé (nouveau code)
const h2 = document.createElement('h2');
h2.textContent = unescapeHTML(userQuestion); // Décodage whitelist
block.appendChild(h2);
```

**Protections implémentées:**
- ✅ **XSS Prevention** - HTML escaping + CSP nonce-based + Secure DOM rendering
- ✅ **HTML Entity Security** - Whitelist-based decoding with SAFE_HTML_ENTITIES
- ✅ **UTF-8 Encoding** - Global charset middleware for French characters
- ✅ **Input Validation** - Null/undefined + 84 tests edge cases
- ✅ **SQL Injection** - MongoDB paramétrisé + Mongoose
- ✅ **Rate Limiting** - 3 soumissions/15min par IP
- ✅ **Honeypot** - Champ invisible anti-spam
- ✅ **CORS** - Origins configurés explicitement
- ✅ **Session Security** - Cookies adaptatifs HTTPS dev/prod + surveillance temps réel
- ✅ **Session Management** - Nettoyage automatique + détection activité suspecte
- ✅ **Performance Monitoring** - Surveillance hybrid index + métriques temps réel
- ✅ **Body Parser Limits** - 512KB-5MB selon endpoint
- ✅ **Database Constraints** - Index unique admin/mois
- ✅ **Modular Architecture** - DRY principle, shared constants
- ✅ **Error Handling Hierarchy** - Multi-level fallback system
- ✅ **IP Blocking** - Détection automatique activité malveillante
- ✅ **Database Performance** - Monitoring requêtes + alertes intelligentes

#### 🚫 **Prévention Admin Duplicate**
```javascript
// Un seul admin par mois - détection automatique
if (isAdmin && adminAlreadyExists) {
  return res.status(409).json({
    message: 'Une réponse admin existe déjà pour ce mois.'
  });
}
```

#### 📏 **Limites Optimisées par Endpoint**
| Endpoint | Body Limit | Usage | Protection |
|----------|------------|-------|------------|
| **Standard** | 512KB | Login, consultation | DoS prevention |
| **Formulaires** | 2MB | Réponses texte | Optimisé contenu long |
| **Admin** | 1MB | Operations admin | Payloads appropriés |
| **Upload Images** | 5MB | Images via Multer | Type validation |
| **Questions/Réponses** | 500-10k chars | Texte utilisateur | Troncature auto |
| **Réponses array** | 1-20 éléments | Limitation usage | Validation stricte |

---

## 🧪 Tests

### Suite de Tests Sécurité Complète (100+ tests)

```bash
# Tests backend (validation et sécurité)
npm test tests/validation.edge-cases.test.js    # 30 tests null/undefined/edge cases
npm test tests/validation.boundary.test.js      # 32 tests limites exactes
npm test tests/validation.security.test.js      # 22 tests XSS + HTML escaping
npm test tests/security.enhanced.test.js        # 19 tests CSP nonce + sessions
npm test tests/bodyParser.limits.test.js        # 16 tests limites optimisées
npm test tests/constraint.unit.test.js          # 14 tests contraintes DB

# Tests intégration et options dynamiques
npm test tests/dynamic.option.integration.test.js # Tests options formulaires dynamiques
npm test tests/integration.full.test.js           # Tests intégration complète
npm test tests/middleware.integration.test.js     # Tests intégration middleware
npm test tests/sessionMonitoring.test.js          # Tests surveillance sessions (25+ tests)
npm test tests/sessionManagement.integration.test.js # Tests intégration sessions
npm test tests/dbPerformanceMonitor.test.js       # Tests monitoring performance

# Tests frontend
npm run test:frontend                              # Tous les tests frontend
npm test frontend/tests/dynamic-option.test.js    # Tests options dynamiques frontend
npm test frontend/tests/form-integration.test.js  # Tests intégration formulaires
npm test frontend/tests/real-form-submission.test.js # Tests soumission réalistes

# Tests complets
npm test                                        # Tous les tests backend
npm run test:all                               # Backend + Frontend
npm run test:all:coverage                     # Couverture complète
```

### Couverture de Tests Exhaustive

**🛡️ Sécurité Backend (100+ tests validation):**
- **Null/Undefined Edge Cases** - 30 tests tous champs/scenarios
- **Boundary Conditions** - 32 tests limites exactes (1-2 chars, 500 chars, 10k chars)
- **XSS Protection** - 22 tests injection HTML/JS + échappement
- **Performance** - Tests charge max + rejet rapide payload invalide
- **Unicode Support** - Emojis, CJK, caractères spéciaux accents français

**🔧 Infrastructure Backend (40+ tests):**
- **CSP Nonce-based** - 19 tests génération unique, headers sécurisés
- **Body Parser Optimisé** - 16 tests limites 512KB/2MB/5MB par endpoint
- **Session Cookies** - 12 tests adaptatifs dev/prod HTTPS
- **Database Constraints** - 14 tests index unique admin/mois
- **Environment Detection** - Tests configuration automatique
- **Middleware Integration** - Tests intégration couches middleware
- **Dynamic Options** - Tests options formulaires dynamiques

**🎯 Frontend Testing (15+ tests):**
- **Form Integration** - Tests intégration formulaires complets
- **Dynamic Options** - Tests options dynamiques côté client
- **Form Submission** - Tests soumission avec validation
- **Real-World Scenarios** - Tests scénarios utilisateur réalistes
- **XSS Prevention** - Tests prévention côté frontend

### Résultats Tests

```bash
✅ 100+ tests backend + 15+ tests frontend passent (100% succès)
✅ 100+ tests validation edge cases + XSS protection
✅ Couverture complète null/undefined/boundary conditions
✅ Performance validée (payload max <1sec, rejet rapide)
✅ Compatibilité backward 100% maintenue
✅ CSP nonce-based sans unsafe-inline (sécurité maximale)
✅ Body parser optimisé par endpoint (80% réduction mémoire)
✅ Database constraints admin duplicate (prévention race conditions)
✅ Frontend testing infrastructure complète
✅ Integration testing backend/frontend/middleware
✅ Dynamic options validation (formulaires adaptatifs)
✅ Service layer architecture testée (patterns métier)
```

---

## 🏗️ Architecture Frontend Moderne

### 🔄 Pattern de Chargement Optimisé

```javascript
// core-utils.js - Chargé SYNCHRONIQUEMENT (critique)
<script src="/admin/assets/core-utils.js"></script>
- unescapeHTML() avec SAFE_HTML_ENTITIES
- coreAlert() pour gestion d'erreur
- Constantes partagées DRY

// admin-utils.js - Chargé ASYNCHRONIQUEMENT (étendu)  
- Fonctions CSRF, API calls
- Composants UI (lightbox, charts)
- Fonctionnalités avancées
```

### 🛡️ Architecture XSS-Proof

**Avant (vulnérable):**
```javascript
// ❌ Injection possible
element.innerHTML = `<div>${userContent}</div>`;
```

**Après (sécurisé):**
```javascript
// ✅ Sécurité totale
const div = document.createElement('div');
div.textContent = unescapeHTML(userContent); // Whitelist only
element.appendChild(div);
```

### 🎯 Gestion d'Erreur Hiérarchique

```javascript
function safeAlert(message, type) {
  // Priorité 1: showAlert (admin-utils.js)
  if (typeof showAlert === 'function') return showAlert(message, type);
  
  // Priorité 2: coreAlert (core-utils.js)  
  if (typeof coreAlert === 'function') return coreAlert(message, type);
  
  // Priorité 3: alert natif
  alert(`${type === 'error' ? '❌' : '✅'} ${message}`);
}
```

### 📁 Structure Modulaire

```
frontend/admin/
├── core-utils.js          # 🔥 ESSENTIEL (synchrone)
│   ├── unescapeHTML()     # Décodage sécurisé HTML
│   ├── SAFE_HTML_ENTITIES # Constante partagée
│   └── coreAlert()        # Gestion erreur basique
└── admin-utils.js         # 🚀 ÉTENDU (asynchrone)
    ├── showAlert()        # Alertes avancées avec auto-hide
    ├── fetchWithErrorHandling() # API calls + CSRF
    ├── createLightbox()   # Composants UI
    └── createPieChart()   # Visualisations données
```

---

## 🌍 Déploiement

### Déploiement Render (Recommandé)

#### **1. Variables d'Environnement Render**
```bash
# Configuration principale
NODE_ENV=production                              # Cookies sécurisés + CSP strict
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/faf
SESSION_SECRET=super-long-secret-key-production  # 32+ caractères entropy

# Authentification admin
LOGIN_ADMIN_USER=admin  
LOGIN_ADMIN_PASS=$2b$10$hashed_bcrypt_password  # Généré avec bcrypt
FORM_ADMIN_NAME=riri                            # Détection admin automatique

# URLs et CORS
APP_BASE_URL=https://your-app.render.com
FRONTEND_URL=https://your-app.render.com        # CORS origin autorisé

# Configuration avancée (optionnel)
HTTPS=true                                      # Force cookies secure en dev
COOKIE_DOMAIN=.your-domain.com                 # Multi-subdomaines

# Upload images
CLOUDINARY_CLOUD_NAME=your-cloud
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
```

#### **2. Configuration Build**
```json
{
  "scripts": {
    "build": "echo 'No build step required'",
    "start": "cd backend && node app.js"
  }
}
```

#### **3. Comportement Production vs Développement**

| Aspect | Développement | Production |
|--------|---------------|------------|
| **Session Cookies** | `sameSite: 'lax'`, `secure: false` | `sameSite: 'none'`, `secure: true` |
| **Body Parser** | 512KB standard, 2MB forms | Idem + surveillance usage |
| **CSP Headers** | Nonce-based + permissif dev | Nonce-based + strict prod |
| **Database Index** | Auto-créés au démarrage | Index unique admin contrainte |
| **Error Messages** | Messages détaillés | Messages sanitisés |
| **HTTPS** | HTTP compatible | HTTPS obligatoire |

### Autres Plateformes

**Heroku:**
```bash
heroku config:set NODE_ENV=production
heroku config:set MONGODB_URI=mongodb+srv://...
# ... autres variables
```

**Railway/Vercel/Netlify:**
- Configurer les variables d'environnement dans le dashboard
- S'assurer que `NODE_ENV=production` est défini

---

## 📚 Documentation

### Documentation Technique Complète

#### **Guides Principaux**
- 📋 **[CLAUDE.md](CLAUDE.md)** - Guide complet pour Claude Code + nouvelles features
- 🏗️ **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture sécurisée + middleware modulaire
- ❌ **[ERROR_HANDLING.md](docs/ERROR_HANDLING.md)** - Gestion d'erreurs + validation XSS
- 🔧 **[SERVICE_PATTERNS.md](docs/SERVICE_PATTERNS.md)** - Patterns de services

#### **Configuration & Sécurité**  
- 🍪 **[SESSION_CONFIG.md](docs/SESSION_CONFIG.md)** - Configuration cookies dev/prod
- 📝 **[BODY_PARSER_OPTIMIZATION.md](docs/BODY_PARSER_OPTIMIZATION.md)** - Limites optimisées par endpoint
- 🧪 **[INPUT_VALIDATION_TESTING.md](docs/INPUT_VALIDATION_TESTING.md)** - Tests validation 84+ edge cases

### API Endpoints

#### **Public Endpoints**

```javascript
// Soumission formulaire (avec validation stricte XSS + null/undefined)
POST /api/response
Content-Type: application/json
Body-Limit: 2MB (optimisé pour formulaires texte)
{
  "name": "John Doe",                    // 2-100 chars, HTML escaped
  "responses": [                         // 1-20 éléments max
    { 
      "question": "Comment ça va ?",     // ≤500 chars, XSS escaped
      "answer": "Très bien ! 😊"        // ≤10k chars, Unicode support
    }
  ],
  "website": ""                         // Honeypot (doit rester vide)
}

// Réponse: 201 + lien privé ou 400 + erreur validation détaillée

// Consultation privée 
GET /api/view/{token}
// Retourne les réponses user + admin pour le mois (sécurisé)
```

#### **Admin Endpoints** (Auth requise + Body-Limit: 1MB)

```javascript
// Dashboard admin (sessions sécurisées)
GET /admin                    # Interface HTML avec CSP nonce
GET /admin/gestion           # Gestion des réponses + contraintes

// API Admin (limites optimisées)
GET /api/admin/responses     # Liste paginée (validation pagination)
GET /api/admin/summary       # Résumé par question (sécurisé)
GET /api/admin/months        # Liste des mois disponibles
DELETE /api/admin/responses/{id}  # Suppression (vérification admin)

// Session Management & Monitoring (nouveaux endpoints)
GET /api/admin/session-stats      # Statistiques surveillance sessions temps réel
POST /api/admin/reset-suspicious-ip # Reset IP bloquées (action admin)
GET /api/admin/hybrid-index-stats # Métriques performance index dual-auth
POST /api/admin/hybrid-index-reset # Reset métriques monitoring

// Upload Images (endpoint séparé)
POST /api/upload             # Body-Limit: 5MB, validation MIME types
Content-Type: multipart/form-data
Form-Data: image (JPG/PNG seulement)
```

### Utilisation

#### **1. Soumission Utilisateur**
1. Remplir le formulaire sur `/`
2. Données validées et sécurisées automatiquement
3. Recevoir lien privé de consultation
4. Partager le lien avec les amis

#### **2. Interface Admin**  
1. Se connecter sur `/login`
2. Accéder au dashboard `/admin`
3. Voir résumés et graphiques
4. Gérer les réponses `/admin/gestion`

---

## 🔧 Maintenance & Monitoring

### Health Checks
```bash
# Vérification environnement
npm run validate-env

# Tests complets
npm run test:coverage

# Vérification sécurité
npm test tests/validation.security.test.js
```

### Logs de Sécurité
- **Tentatives XSS** - Détectées et loggées
- **Rate limiting** - IPs bloquées trackées  
- **Admin actions** - Audit trail complet
- **Erreurs système** - Loggées sans exposition de données

---

## 🤝 Contribution

### Standards de Code
- **Sécurité first** - Toute nouvelle fonctionnalité doit être testée contre XSS
- **Tests obligatoires** - Couverture minimale 80%
- **Validation stricte** - express-validator sur tous inputs
- **Documentation** - Mise à jour des .md files

### Workflow
1. **Fork** le projet
2. **Branch** feature (`git checkout -b feature/amazing-feature`)
3. **Commit** avec messages explicites
4. **Tests** complets (`npm test`)
5. **Pull Request** avec description détaillée

---

## 📄 License

MIT License - Voir [LICENSE.md](LICENSE.md) pour détails.

---

## 🎯 Roadmap

### 🚀 **Version 2.0 (En cours)**
- [x] **Architecture sécurisée** - Middleware modulaire
- [x] **Protection XSS** - Validation stricte
- [x] **Tests de sécurité** - 38+ tests
- [x] **Configuration adaptative** - Dev/Prod

### 🔮 **Version 2.1 (Futur)**
- [ ] **API Rate Limiting** granulaire par endpoint
- [ ] **Cache Redis** pour performances
- [ ] **Monitoring** avec métriques Prometheus
- [ ] **PWA** - Service Worker + offline

---

## 🆕 Dernières Améliorations (Janvier 2025)

### **🔐 Session Management & Monitoring (Août 2025)**
- **🔍 Surveillance Temps Réel**: SessionMonitoringService pour détection activité suspecte
- **🧹 Nettoyage Automatique**: Sessions expirées + utilisateurs inactifs (90j)
- **🚫 Blocage IP Intelligent**: 5 tentatives échouées = IP bloquée automatiquement
- **📊 Métriques Détaillées**: Dashboard admin avec statistiques sécurité temps réel
- **⚡ Performance Monitoring**: HybridIndexMonitor pour surveillance dual-auth
- **🔄 Rollback Procedures**: Documentation complète procédures migration rollback

### **🔧 Corrections d'Affichage & UI/UX**
- **✨ Affichage Naturel Français**: Correction du problème d'affichage des apostrophes (`&#x27;` → `'`) dans admin.html
- **🎯 Stratégie d'Échappement Intelligente**: Suppression de `.escape()` express-validator trop agressif, conservation de `escapeQuestion()` qui préserve le français
- **🛡️ Sécurité Préservée**: Toutes les protections XSS maintenues (60/60 tests passent)
- **🧪 Décodage HTML Amélioré**: Fonction `Utils.unescapeHTML()` optimisée avec création DOM sécurisée

### **🛡️ Sécurité & XSS**
- **🚨 Fix XSS Critique**: Remplacement complet de `innerHTML` par `textContent` sécurisé
- **🔧 Correction Cookies**: Nom de cookie corrigé de `connect.sid` à `faf-session`
- **🔒 Debug Production**: Endpoints de debug désactivés en production
- **📐 Limites Corpo**: Optimisation body parser par endpoint (80% réduction mémoire)

### **🏗️ Architecture & Code**
- **🧹 Refactoring Module**: Remplacement admin-utils.js + core-utils.js par faf-admin.js ES6 unifié
- **✅ Tests Robustes**: 25+ nouveaux tests session monitoring + intégration
- **🚀 Cache Intelligent**: Système de cache 10min avec prévention memory leaks
- **📊 Logging Structuré**: Debug contextuel avec métriques performance
- **🏭 Service Layer**: Architecture modulaire services avec monitoring intégré

---

## 📞 Support

**Questions ?** 
- 📖 Consulter la [Documentation](docs/ARCHITECTURE.md)
- 🐛 Reporter un [Bug](issues/new?template=bug_report.md)
- 💡 Proposer une [Feature](issues/new?template=feature_request.md)

---

<div align="center">

**🔒 Sécurisé par design • 🚀 Optimisé pour la performance • 🧪 Testé rigoureusement**

</div>