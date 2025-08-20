# Guide de Déploiement FAF sur Render.com

Ce guide complet couvre le déploiement sécurisé de l'application Form-a-Friend (FAF) sur Render.com en production.

## Sommaire
1. [Préparation du Code](#1-préparation-du-code)
2. [Configuration Render.com](#2-configuration-rendercom)
3. [Variables d'Environnement Production](#3-variables-denvironnement-production)
4. [Configuration MongoDB Atlas](#4-configuration-mongodb-atlas)
5. [Optimisations Production](#5-optimisations-production)
6. [Tests Post-Déploiement](#6-tests-post-déploiement)
7. [Procédures de Rollback](#7-procédures-de-rollback)
8. [Monitoring et Maintenance](#8-monitoring-et-maintenance)

## 1. Préparation du Code

### 1.1 Vérification des Scripts package.json

Le `package.json` est déjà optimisé pour la production :

```json
{
  "scripts": {
    "start": "node app.js",
    "dev": "nodemon app.js",
    "test:post-deployment": "node tests/post-deployment/run-post-deployment-tests.js"
  }
}
```

### 1.2 Configuration des Fichiers Statiques

L'application sert déjà les fichiers statiques correctement :
- Frontend public : `/frontend/public/`
- Admin dashboard : `/frontend/admin/`
- Pas de build process requis (fichiers servis directement)

### 1.3 Optimisations pour Production

Le code inclut déjà :
- ✅ Helmet.js pour les headers de sécurité
- ✅ CORS configuré pour production
- ✅ Session cookies adaptatives (sameSite='none', secure=true en production)
- ✅ Body parser limits optimisées (512KB/2MB/5MB)
- ✅ Rate limiting intelligent
- ✅ Monitoring de performance intégré

## 2. Configuration Render.com

### 2.1 Création du Service Web

1. **Connectez votre repo GitHub à Render**
2. **Créez un nouveau Web Service** avec ces paramètres :

```yaml
# Configuration Render
Name: faf-production
Environment: Node
Region: Frankfurt (Europe) ou Oregon (US)
Branch: main ou master
Root Directory: backend
Build Command: npm install
Start Command: npm start
```

### 2.2 Configuration du Runtime

```yaml
# render.yaml (optionnel - peut être fait via interface)
services:
  - type: web
    name: faf-production
    env: node
    plan: starter # ou standard selon vos besoins
    buildCommand: cd backend && npm install
    startCommand: cd backend && npm start
    healthCheckPath: /health
    envVars:
      - key: NODE_ENV
        value: production
```

### 2.3 Configuration du Health Check

L'application inclut déjà un endpoint `/health` :

```javascript
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: Date.now(),
    uptime: process.uptime()
  });
});
```

## 3. Variables d'Environnement Production

### 3.1 Variables Requises

**Configuration dans Render Dashboard > Environment Variables :**

```bash
# ========== VARIABLES OBLIGATOIRES ==========

# Base de données MongoDB
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/faf-production?retryWrites=true&w=majority

# Sécurité des sessions
SESSION_SECRET=votre-clé-secrète-très-longue-et-complexe-64-caractères

# Authentification admin
LOGIN_ADMIN_USER=admin
LOGIN_ADMIN_PASS=mot-de-passe-admin-sécurisé
FORM_ADMIN_NAME=riri

# URLs et CORS
APP_BASE_URL=https://votre-app.onrender.com
FRONTEND_URL=https://votre-frontend-domain.com

# Upload d'images Cloudinary
CLOUDINARY_CLOUD_NAME=votre-cloud-name
CLOUDINARY_API_KEY=votre-api-key
CLOUDINARY_API_SECRET=votre-api-secret

# Configuration production
NODE_ENV=production
PORT=10000
HTTPS=true
```

### 3.2 Variables Optionnelles Recommandées

```bash
# ========== OPTIMISATIONS PERFORMANCE ==========

# Domaine des cookies (pour sous-domaines)
COOKIE_DOMAIN=.votre-domaine.com

# Configuration rate limiting
DISABLE_RATE_LIMITING=false

# Configuration debug
DEBUG_VERBOSE=false

# ========== SERVICES AVANCÉS ==========

# Email service (si utilisé)
RESEND_API_KEY=votre-resend-api-key
EMAIL_FROM_ADDRESS=noreply@votre-domaine.com
EMAIL_FROM_NAME=Form-a-Friend

# Monitoring email
ENABLE_EMAIL_MONITORING=true
EMAIL_BOUNCE_RATE_THRESHOLD=0.05
EMAIL_COMPLAINT_RATE_THRESHOLD=0.01

# Configuration scheduler
SCHEDULER_TIMEZONE=Europe/Paris
SCHEDULER_MONTHLY_JOB_DAY=5
SCHEDULER_MONTHLY_JOB_HOUR=18

# Limites service
CONTACT_MAX_CSV_SIZE=5242880
CONTACT_MAX_BATCH_SIZE=100
INVITATION_EXPIRATION_DAYS=60
```

### 3.3 Sécurisation des Secrets

**Génération de SESSION_SECRET sécurisé :**

```bash
# Générez une clé de 64 caractères
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Mot de passe admin bcrypt :**

```javascript
// Utilisez bcrypt pour hasher votre mot de passe admin
const bcrypt = require('bcrypt');
const hashedPassword = await bcrypt.hash('votre-mot-de-passe', 12);
console.log(hashedPassword);
```

## 4. Configuration MongoDB Atlas

### 4.1 Setup Base de Données

1. **Créez un cluster MongoDB Atlas :**
   - Région : Même que Render (Frankfurt/Oregon)
   - Tier : M0 (gratuit) ou M2+ selon besoins
   - Nom : `faf-production`

2. **Configuration réseau :**
   ```
   IP Whitelist: 0.0.0.0/0 (Render utilise des IPs dynamiques)
   ```

3. **Utilisateur de base :**
   ```
   Username: fafuser
   Password: [générer mot de passe fort]
   Rôles: readWrite sur faf-production
   ```

### 4.2 Index de Performance

L'application créée automatiquement les index nécessaires :

```javascript
// Index automatiquement créés au démarrage
await mongoose.connection.collection('responses')
  .createIndex({ createdAt: -1 });

await mongoose.connection.collection('responses')
  .createIndex(
    { month: 1, isAdmin: 1 }, 
    { unique: true, partialFilterExpression: { isAdmin: true } }
  );
```

### 4.3 String de Connexion

```
mongodb+srv://fafuser:PASSWORD@cluster.mongodb.net/faf-production?retryWrites=true&w=majority&maxPoolSize=20&minPoolSize=5
```

## 5. Optimisations Production

### 5.1 Performance Node.js

L'application est déjà optimisée avec :

```javascript
// Trust proxy (important pour Render)
app.set('trust proxy', 1);

// Optimisations body parser par endpoint
createStandardBodyParser(); // 512KB standard
// 2MB pour formulaires, 5MB pour uploads

// Cache middleware
const cacheMiddleware = (req, res, next) => {
  if (req.method === 'GET') {
    res.set('Cache-Control', 'public, max-age=300'); // 5 minutes
  }
};
```

### 5.2 Sécurité Production

```javascript
// Headers de sécurité Helmet.js
createSecurityMiddleware();

// Session cookies sécurisées
sameSite: 'none',
secure: true,
httpOnly: true,
signed: true

// CORS configuré pour production
cors({
  origin: [process.env.APP_BASE_URL, process.env.FRONTEND_URL],
  credentials: true
});
```

### 5.3 Monitoring Intégré

L'application inclut déjà :
- ✅ Performance monitoring en temps réel
- ✅ Session security monitoring
- ✅ Database performance tracking
- ✅ Automatic session cleanup
- ✅ Real-time metrics collection

## 6. Tests Post-Déploiement

### 6.1 Suite de Tests Automatisés

L'application inclut une suite complète de tests post-déploiement :

```bash
# Tests post-déploiement complets
npm run test:post-deployment

# Tests par catégorie
npm run test:post-deployment:functionality
npm run test:post-deployment:security
npm run test:post-deployment:performance
```

### 6.2 Tests Manuels Critiques

**1. Test de Health Check :**
```bash
curl https://votre-app.onrender.com/health
# Attendu: {"status":"healthy","timestamp":...,"uptime":...}
```

**2. Test d'authentification admin :**
```bash
# Connexion admin
curl -X POST https://votre-app.onrender.com/admin-login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"votre-mot-de-passe"}'
```

**3. Test de soumission de formulaire :**
```bash
# Test endpoint public
curl https://votre-app.onrender.com/form
# Vérifier que la page se charge correctement
```

**4. Test des uploads Cloudinary :**
- Accédez au dashboard admin
- Testez l'upload d'une image
- Vérifiez l'affichage dans Cloudinary

**5. Test de session et cookies :**
- Vérifiez que les cookies sont `Secure` et `SameSite=None`
- Testez la persistence des sessions
- Vérifiez l'auto-logout après inactivité

### 6.3 Validation de la Sécurité

**Tests de sécurité automatiques :**
```bash
# Suite de tests sécurité
npm run test:post-deployment:security

# Tests spécifiques
npm run test:security:comprehensive
npm run test:security:upload-rate-limiting
npm run test:security:mongodb-injection
```

## 7. Procédures de Rollback

### 7.1 Rollback Automatique Render

**Configuration Render pour rollback automatique :**

1. **Health Check Configuration :**
   ```yaml
   healthCheckPath: /health
   healthCheckTimeout: 30s
   healthCheckInterval: 10s
   healthCheckGracePeriod: 300s
   ```

2. **Deploy Settings :**
   - ✅ Auto-deploy on git push
   - ✅ Auto-rollback on health check failure

### 7.2 Rollback Manuel

**Via Render Dashboard :**
1. Allez dans votre service > Deploys
2. Sélectionnez un déploiement précédent
3. Cliquez "Rollback to this Deploy"

**Via Git (recommandé) :**
```bash
# Identifiez le commit précédent
git log --oneline

# Créez une branche de rollback
git checkout -b rollback-to-working-version
git revert <commit-hash-problématique>
git push origin rollback-to-working-version

# Mergez dans main après validation
```

### 7.3 Rollback Base de Données

**L'application inclut des outils de rollback automatiques :**

```javascript
// Utilisation du système de rollback intégré
const RollbackSystem = require('./scripts/backup-restore/AutomaticRollbackSystem');

// Rollback via CLI
node scripts/backup-restore/BackupRestoreCLI.js --rollback --dry-run
node scripts/backup-restore/BackupRestoreCLI.js --rollback --confirm
```

### 7.4 Validation Post-Rollback

```bash
# Suite de tests post-rollback
npm run test:post-deployment:critical
npm run test:post-deployment:functionality
```

## 8. Monitoring et Maintenance

### 8.1 Monitoring Intégré

L'application offre plusieurs endpoints de monitoring :

```bash
# Health check général
GET /health

# Monitoring admin (authentification requise)
GET /api/admin/session-stats
GET /api/admin/hybrid-index-stats
GET /api/v2/health

# Debug (développement uniquement)
GET /api/debug/health
```

### 8.2 Logs de Production

**Configuration logging sécurisée :**

```javascript
// L'application utilise Winston pour les logs
const SecureLogger = require('./utils/secureLogger');

// Types de logs disponibles :
SecureLogger.logInfo('Application started');
SecureLogger.logWarning('Performance degradation detected');
SecureLogger.logError('Database connection failed');
```

**Accès aux logs Render :**
- Dashboard Render > Votre service > Logs
- Filtrage par niveau (INFO, WARNING, ERROR)
- Download des logs pour analyse

### 8.3 Alertes et Notifications

**Configuration recommandée :**

1. **Render Notifications :**
   - ✅ Deploy success/failure
   - ✅ Health check failures
   - ✅ Service down alerts

2. **Monitoring Custom :**
   ```javascript
   // L'application inclut un système d'alertes
   const PerformanceAlerting = require('./services/performanceAlerting');
   
   // Seuils d'alerte configurables
   alertThresholds: {
     slowQueryRate: 0.15, // 15%
     avgExecutionTime: 150, // ms
     queryVolume: 500, // queries per minute
     indexEfficiency: 0.75 // 75%
   }
   ```

### 8.4 Maintenance Planifiée

**Tâches automatiques :**
- ✅ Nettoyage sessions expirées (90 jours)
- ✅ Optimisation index base de données
- ✅ Rotation des logs sécurisée
- ✅ Health checks performance

**Maintenance mensuelle recommandée :**
```bash
# Validation santé système
npm run test:post-deployment

# Vérification performance
curl https://votre-app.onrender.com/api/v2/health

# Backup base de données
# (MongoDB Atlas fait des backups automatiques)
```

## 9. Checklist de Déploiement

### Pré-Déploiement
- [ ] Variables d'environnement configurées
- [ ] MongoDB Atlas configuré et accessible
- [ ] Cloudinary configuré pour uploads
- [ ] Tests locaux passent (`npm test`)
- [ ] Configuration HTTPS/SSL vérifiée

### Déploiement
- [ ] Service Render créé et configuré
- [ ] Build et déploiement réussis
- [ ] Health check endpoint répond
- [ ] Variables d'environnement chargées
- [ ] Connexion base de données établie

### Post-Déploiement
- [ ] Suite de tests post-déploiement passée
- [ ] Authentification admin fonctionnelle
- [ ] Upload d'images opérationnel
- [ ] Sessions et cookies sécurisés
- [ ] Monitoring actif et fonctionnel
- [ ] Performance dans les seuils acceptables

### Validation Utilisateur
- [ ] Formulaire public accessible
- [ ] Soumission de réponses fonctionnelle
- [ ] Dashboard admin accessible
- [ ] Gestion des réponses opérationnelle
- [ ] Génération des statistiques correcte

## Contacts et Support

- **Documentation technique :** `/docs/ARCHITECTURE.md`
- **Tests de validation :** `/tests/post-deployment/`
- **Scripts de maintenance :** `/scripts/`
- **Monitoring intégré :** Endpoints `/health` et `/api/v2/health`

---

*Ce guide couvre tous les aspects du déploiement sécurisé de FAF sur Render.com. L'application inclut déjà toutes les optimisations et sécurisations nécessaires pour un environnement de production robuste.*