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
npm test                # Tests complets
npm run test:watch      # Tests en mode watch
npm run test:coverage   # Couverture de tests

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
│   ├── 📁 middleware/         # Middleware de sécurité modulaire
│   │   ├── auth.js           # Authentification admin bcrypt
│   │   ├── validation.js     # Validation XSS + null/undefined
│   │   ├── security.js       # CSP nonce-based + sessions
│   │   ├── bodyParser.js     # Limites optimisées par endpoint
│   │   └── rateLimiting.js   # Protection anti-spam intelligente
│   ├── 📁 routes/            # Endpoints API
│   │   ├── responseRoutes.js # Soumission sécurisée
│   │   ├── adminRoutes.js    # Interface admin
│   │   └── upload.js         # Upload Cloudinary
│   ├── 📁 models/            # Schémas MongoDB
│   ├── 📁 tests/             # Suite de tests sécurité (100+)
│   │   ├── validation.*.test.js    # Tests validation (84 tests)
│   │   ├── security.*.test.js      # Tests sécurité XSS/CSP
│   │   ├── bodyParser.*.test.js    # Tests limites optimisées
│   │   └── constraint.*.test.js    # Tests contraintes DB
│   └── 📁 config/            # Configuration
├── 📁 frontend/              # Interface utilisateur
│   ├── 📁 public/            # Pages publiques
│   └── 📁 admin/             # Interface admin
└── 📚 Documentation/
```

### Technologies Utilisées

**Backend:**
- **Express.js** v5 - Framework web moderne
- **MongoDB** + Mongoose - Base de données 
- **Helmet.js** - Headers de sécurité
- **bcrypt** - Hashing mots de passe
- **express-validator** - Validation + XSS protection
- **Cloudinary** - Upload d'images sécurisé

**Frontend:**
- **HTML5** + **CSS3** + **Vanilla JS**
- **TailwindCSS** (admin interface)
- **Chart.js** (graphiques admin)

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

#### 🧹 **Validation & Sanitisation**
```javascript
// Exemple: Input malveillant automatiquement sécurisé
Input:  '<script>alert("hack")</script>John'
Output: '&lt;script&gt;alert(&quot;hack&quot;)&lt;&#x2F;script&gt;John'
```

**Protections implémentées:**
- ✅ **XSS Prevention** - HTML escaping + CSP nonce-based
- ✅ **Input Validation** - Null/undefined + 84 tests edge cases
- ✅ **SQL Injection** - MongoDB paramétrisé + Mongoose
- ✅ **Rate Limiting** - 3 soumissions/15min par IP
- ✅ **Honeypot** - Champ invisible anti-spam
- ✅ **CORS** - Origins configurés explicitement
- ✅ **Session Security** - Cookies adaptatifs HTTPS dev/prod
- ✅ **Body Parser Limits** - 512KB-5MB selon endpoint
- ✅ **Database Constraints** - Index unique admin/mois

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
# Tests validation complets (84 tests)
npm test tests/validation.edge-cases.test.js    # 30 tests null/undefined/edge cases
npm test tests/validation.boundary.test.js      # 32 tests limites exactes
npm test tests/validation.security.test.js      # 22 tests XSS + HTML escaping

# Tests infrastructure sécurisée
npm test tests/security.enhanced.test.js        # 19 tests CSP nonce + sessions
npm test tests/bodyParser.limits.test.js        # 16 tests limites optimisées
npm test tests/constraint.unit.test.js          # 14 tests contraintes DB

# Tests complets
npm test                                        # Tous les tests
npm run test:coverage                           # Couverture complète
```

### Couverture de Tests Exhaustive

**🛡️ Sécurité (84 tests validation):**
- **Null/Undefined Edge Cases** - 30 tests tous champs/scenarios
- **Boundary Conditions** - 32 tests limites exactes (1-2 chars, 500 chars, 10k chars)
- **XSS Protection** - 22 tests injection HTML/JS + échappement
- **Performance** - Tests charge max + rejet rapide payload invalide
- **Unicode Support** - Emojis, CJK, caractères spéciaux

**🔧 Infrastructure (35+ tests):**
- **CSP Nonce-based** - 19 tests génération unique, headers sécurisés
- **Body Parser Optimisé** - 16 tests limites 512KB/2MB/5MB par endpoint
- **Session Cookies** - 12 tests adaptatifs dev/prod HTTPS
- **Database Constraints** - 14 tests index unique admin/mois
- **Environment Detection** - Tests configuration automatique

### Résultats Tests

```bash
✅ 100+ tests sécurité passent (100% succès)
✅ 84 tests validation edge cases + XSS
✅ Couverture complète null/undefined/boundary
✅ Performance validée (payload max <1sec)
✅ Compatibilité backward 100%
✅ CSP nonce-based sans unsafe-inline
✅ Body parser optimisé par endpoint
✅ Database constraints admin duplicate
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

## 📞 Support

**Questions ?** 
- 📖 Consulter la [Documentation](docs/ARCHITECTURE.md)
- 🐛 Reporter un [Bug](issues/new?template=bug_report.md)
- 💡 Proposer une [Feature](issues/new?template=feature_request.md)

---

<div align="center">

**🔒 Sécurisé par design • 🚀 Optimisé pour la performance • 🧪 Testé rigoureusement**

</div>