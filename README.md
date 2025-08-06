# 🤝 FAF (Form-a-Friend) - Application Mensuelle Sécurisée

> **Application de formulaires mensuels entre amis avec architecture sécurisée, validation XSS, et protection anti-spam**

![Node.js](https://img.shields.io/badge/node.js-v18+-green.svg)
![Express](https://img.shields.io/badge/express-v5+-blue.svg) 
![Security](https://img.shields.io/badge/security-helmet+XSS-red.svg)
![Tests](https://img.shields.io/badge/tests-38+-brightgreen.svg)

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
│   ├── 📁 middleware/         # Middleware de sécurité
│   │   ├── auth.js           # Authentification admin
│   │   ├── validation.js     # Validation XSS + sanitisation
│   │   └── rateLimiting.js   # Protection anti-spam
│   ├── 📁 routes/            # Endpoints API
│   │   ├── responseRoutes.js # Soumission sécurisée
│   │   ├── adminRoutes.js    # Interface admin
│   │   └── upload.js         # Upload Cloudinary
│   ├── 📁 models/            # Schémas MongoDB
│   ├── 📁 tests/             # Suite de tests (38+)
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

#### 🔒 **Headers de Sécurité (Helmet.js)**
```javascript
// CSP Protection contre XSS
Content-Security-Policy: default-src 'self'; script-src 'self' cdn.jsdelivr.net...
X-XSS-Protection: 0
X-Content-Type-Options: nosniff  
X-Frame-Options: DENY
```

#### 🧹 **Validation & Sanitisation**
```javascript
// Exemple: Input malveillant automatiquement sécurisé
Input:  '<script>alert("hack")</script>John'
Output: '&lt;script&gt;alert(&quot;hack&quot;)&lt;&#x2F;script&gt;John'
```

**Protections implémentées:**
- ✅ **XSS Prevention** - Tous inputs échappés automatiquement
- ✅ **SQL Injection** - MongoDB paramétrisé + Mongoose
- ✅ **Rate Limiting** - 3 soumissions/15min
- ✅ **Honeypot** - Champ invisible anti-spam
- ✅ **CORS** - Origins configurés explicitement
- ✅ **Session Security** - Cookies adaptatifs dev/prod

#### 🚫 **Prévention Admin Duplicate**
```javascript
// Un seul admin par mois - détection automatique
if (isAdmin && adminAlreadyExists) {
  return res.status(409).json({
    message: 'Une réponse admin existe déjà pour ce mois.'
  });
}
```

#### 📏 **Limites de Données**
| Type | Limite | Protection |
|------|--------|------------|
| **Nom** | 2-100 chars | Validation stricte |
| **Questions** | ≤500 chars | Troncature auto |
| **Réponses** | ≤10k chars | Sanitisation |
| **Body total** | ≤10MB | Parser Express |
| **Réponses max** | 20 | Validation array |

---

## 🧪 Tests

### Suite de Tests Sécurisée (38+ tests)

```bash
# Lancer tous les tests
npm test

# Tests spécifiques
npm test validation.security.test.js    # XSS + boundary (22 tests)
npm test session.config.test.js         # Cookies environnement (12 tests) 
npm test admin.duplicate.test.js        # Prévention duplicata
npm test body.limit.test.js             # Limites de taille (4 tests)
```

### Couverture de Tests

**🛡️ Sécurité:**
- **XSS Injection** - Script tags, HTML entities, événements JS
- **Boundary Testing** - Limites exactes de caractères
- **Spam Protection** - Honeypot + rate limiting
- **Admin Logic** - Prévention duplicata, détection case-insensitive

**🔧 Configuration:**
- **Environment Variables** - Dev vs prod
- **Session Cookies** - sameSite/secure adaptatifs  
- **Body Parsing** - Limites 10MB
- **Error Handling** - Messages sécurisés

### Résultats Tests

```bash
✅ 38+ tests de sécurité passent
✅ 100% compatibilité backward
✅ Couverture validation complète
✅ Performance validée
```

---

## 🌍 Déploiement

### Déploiement Render (Recommandé)

#### **1. Variables d'Environnement Render**
```bash
NODE_ENV=production
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/faf
SESSION_SECRET=super-long-secret-key-production
LOGIN_ADMIN_USER=admin  
LOGIN_ADMIN_PASS=$2b$10$hashed_bcrypt_password
FORM_ADMIN_NAME=riri
APP_BASE_URL=https://your-app.render.com
FRONTEND_URL=https://your-app.render.com
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
| **Cookies** | `sameSite: 'lax'`, `secure: false` | `sameSite: 'none'`, `secure: true` |
| **HTTPS** | Optionnel | Obligatoire |
| **CSP** | Permissif | Strict |
| **Logging** | Verbose | Optimisé |

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

### Documentation Technique

- 📋 **[CLAUDE.md](CLAUDE.md)** - Guide complet pour Claude Code
- 🏗️ **[ARCHITECTURE.md](backend/ARCHITECTURE.md)** - Architecture détaillée
- ❌ **[ERROR_HANDLING.md](backend/ERROR_HANDLING.md)** - Gestion d'erreurs sécurisée

### API Endpoints

#### **Public Endpoints**

```javascript
// Soumission formulaire (avec validation stricte)
POST /api/response
Content-Type: application/json
{
  "name": "John Doe",
  "responses": [
    { "question": "Comment ça va ?", "answer": "Très bien !" }
  ]
}

// Consultation privée 
GET /api/view/{token}
// Retourne les réponses user + admin pour le mois
```

#### **Admin Endpoints** (Auth requise)

```javascript
// Dashboard admin
GET /admin                    # Interface HTML
GET /admin/gestion           # Gestion des réponses

// API Admin
GET /api/admin/responses     # Liste paginée
GET /api/admin/summary       # Résumé par question
GET /api/admin/months        # Liste des mois
DELETE /api/admin/responses/{id}  # Suppression
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
- 📖 Consulter la [Documentation](backend/ARCHITECTURE.md)
- 🐛 Reporter un [Bug](issues/new?template=bug_report.md)
- 💡 Proposer une [Feature](issues/new?template=feature_request.md)

---

<div align="center">

**🔒 Sécurisé par design • 🚀 Optimisé pour la performance • 🧪 Testé rigoureusement**

</div>