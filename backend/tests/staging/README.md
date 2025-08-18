# 🧪 Suite de Tests Staging - Migration FAF

Cette suite de tests complète valide la migration du système FAF (Form-a-Friend) en environnement staging avec isolation totale des données de production.

## 📋 Vue d'ensemble

La suite comprend **6 composants principaux** :

### 1. **Configuration Environnement Staging** (`staging-config.js`)
- Setup automatique MongoDB Memory Server
- Configuration variables d'environnement isolées  
- Génération de données de test réalistes
- Cleanup automatique après tests
- Health check de l'environnement

### 2. **Tests de Validation des Données** (`data-validation.test.js`)
- ✅ Vérification intégrité avant migration
- ✅ Validation transformation Response→Submission  
- ✅ Contrôle génération automatique des Users
- ✅ Test préservation des tokens legacy
- ✅ Validation des relations et contraintes

### 3. **Tests des Fonctionnalités** (`functionality.test.js`)
- ✅ Workflow d'authentification complet
- ✅ Validation des APIs après migration
- ✅ Compatibilité avec URLs existantes
- ✅ Vérification des dashboards et interfaces
- ✅ Tests des fonctionnalités admin et user

### 4. **Tests de Performance** (`performance.test.js`)
- ⚡ Load testing avec volumes réalistes (100+ utilisateurs)
- ⚡ Stress testing des opérations critiques
- ⚡ Memory leak detection et optimisation
- ⚡ Database performance validation
- ⚡ Response time benchmarking

### 5. **Tests de Régression** (`regression.test.js`)
- 🔄 Test de tous les endpoints API
- 🔄 Validation des workflows existants  
- 🔄 Test de la sécurité et authentification
- 🔄 Vérification des rate limits
- 🔄 Test des middlewares de sécurité

### 6. **Rapports et Monitoring** (`monitoring.test.js`)
- 📊 Génération de rapports détaillés
- 📊 Métriques de performance en temps réel
- 📊 Logs structurés pour debug
- 📊 Dashboard de monitoring live
- 📊 Alertes automatiques

## 🚀 Utilisation

### Lancement Rapide

```bash
# Tous les tests en séquentiel
cd backend
node tests/staging/run-staging-tests.js

# Avec rapports détaillés
node tests/staging/run-staging-tests.js --report --coverage

# Mode parallèle (plus rapide)
node tests/staging/run-staging-tests.js --parallel --verbose

# Suite spécifique
node tests/staging/run-staging-tests.js --suite performance
```

### Options Disponibles

| Option | Description | Exemple |
|--------|-------------|---------|
| `--verbose` | Affichage détaillé | `--verbose` |
| `--coverage` | Rapports de coverage | `--coverage` |
| `--parallel` | Exécution parallèle | `--parallel` |
| `--suite <name>` | Suite spécifique | `--suite data-validation` |
| `--report` | Rapport HTML+JSON | `--report` |
| `--help` | Aide complète | `--help` |

### Suites Disponibles

| Nom | Fichier | Description | Durée |
|-----|---------|-------------|-------|
| **Data Validation** | `data-validation.test.js` | Validation migration données | ~30s |
| **Functionality** | `functionality.test.js` | Tests fonctionnalités post-migration | ~45s |
| **Performance** | `performance.test.js` | Load testing et optimisations | ~60s |
| **Regression** | `regression.test.js` | Tests de régression complète | ~45s |
| **Monitoring** | `monitoring.test.js` | Rapports et monitoring | ~30s |

## 📊 Rapports Générés

### Rapports Automatiques
```
backend/reports/
├── staging-tests-2024-12-XX.html     # Rapport HTML interactif
├── staging-tests-2024-12-XX.json     # Rapport JSON détaillé  
├── staging-migration-report-XXX.json # Rapport de migration
└── coverage/staging/                  # Coverage par suite
```

### Métriques Collectées
- **Performance** : Temps de réponse, mémoire, CPU
- **Base de données** : Requêtes, index, optimisations
- **Sécurité** : XSS, CSRF, authentification, validation
- **Fonctionnalités** : Endpoints, workflows, compatibilité
- **Migration** : Intégrité, relations, tokens legacy

## 🔧 Configuration

### Variables d'Environnement Staging

```env
NODE_ENV=staging
STAGING_MODE=true
MIGRATION_TEST_MODE=true
LOG_LEVEL=debug

# MongoDB (remplacé par Memory Server)
MONGODB_URI=auto-generated-memory-server

# Session de test
SESSION_SECRET=staging-secret-key-for-testing-only

# Admin de test
LOGIN_ADMIN_USER=staging-admin
LOGIN_ADMIN_PASS=staging-password-123
FORM_ADMIN_NAME=staging-admin

# URLs de test
APP_BASE_URL=http://localhost:3000
FRONTEND_URL=http://localhost:3000

# Cloudinary mock
CLOUDINARY_CLOUD_NAME=staging-cloud
CLOUDINARY_API_KEY=staging-api-key
CLOUDINARY_API_SECRET=staging-api-secret
```

### Configuration Jest

Fichier `jest.config.staging.js` optimisé pour :
- **Isolation** : MongoDB Memory Server par test
- **Performance** : Workers séquentiels, cache désactivé
- **Rapports** : HTML, JSON, JUnit, Coverage
- **Timeout** : 30s par test (migrations complexes)

## 🏗️ Architecture des Tests

### Isolation Complète
- **Base de données** : MongoDB Memory Server unique par run
- **Variables d'env** : Scope isolé avec restauration
- **Données** : Génération automatique + cleanup
- **Sessions** : Cookies et auth isolés

### Données de Test
```javascript
// Génération automatique
await stagingEnv.generateTestData();      // Données de base
await stagingEnv.generateVolumeData(100, 50); // Données de volume

// Types de données créées
- Users (legacy + nouveaux) 
- Responses (format legacy)
- Submissions (format post-migration)
- Relations et contraintes
- Tokens legacy préservés
```

### Validation Multi-niveaux
1. **Structurelle** : Schémas, contraintes, relations
2. **Fonctionnelle** : Workflows, APIs, interfaces  
3. **Performance** : Temps de réponse, mémoire, DB
4. **Sécurité** : XSS, CSRF, auth, validation
5. **Compatibilité** : URLs legacy, tokens, données

## 📈 Critères de Validation

### Seuils de Performance
- **Response Time** : < 500ms (moyenne)
- **Memory Usage** : < 100MB augmentation
- **DB Queries** : < 100ms (optimisées)
- **Load Testing** : 100 utilisateurs simultanés
- **Success Rate** : > 95% pour validation

### Seuils de Sécurité  
- **XSS Protection** : 100% tests passés
- **Authentication** : Aucune escalade privilège
- **Input Validation** : Résistance injection
- **Rate Limiting** : Protection brute force
- **Session Security** : Gestion appropriée

### Seuils de Coverage
- **Branches** : > 70%
- **Functions** : > 75%  
- **Lines** : > 80%
- **Statements** : > 80%

## 🛠️ Maintenance

### Ajout de Nouveaux Tests

1. **Créer le fichier test** dans `/tests/staging/`
2. **Suivre la convention** : `nom.test.js`
3. **Ajouter à la suite** dans `run-staging-tests.js`
4. **Configurer timeout** approprié
5. **Documenter** dans ce README

### Debugging

```bash
# Tests avec logs détaillés
node tests/staging/run-staging-tests.js --verbose

# Test spécifique en debug
NODE_ENV=staging DEBUG=faf:staging:* npm test tests/staging/data-validation.test.js

# Analyse mémoire
node --inspect tests/staging/run-staging-tests.js --suite performance
```

### Optimisation Performance

- **Workers séquentiels** : Évite conflits MongoDB Memory Server
- **Cleanup automatique** : Prévient fuites mémoire
- **Cache désactivé** : Évite problèmes entre runs
- **Timeout adaptatif** : Selon complexité des tests

## 🔍 Résolution de Problèmes

### Problèmes Courants

| Problème | Cause | Solution |
|----------|-------|---------|
| **Timeout tests** | MongoDB lent | Augmenter `testTimeout` |
| **Memory leaks** | Cleanup incomplet | Vérifier `afterAll` hooks |
| **Port conflicts** | Autre instance | Utiliser MongoDB Memory Server |
| **Coverage faible** | Fichiers exclus | Ajuster `collectCoverageFrom` |

### Logs de Debug

```bash
# Logs environnement
DEBUG=faf:staging:env node tests/staging/run-staging-tests.js

# Logs base de données  
DEBUG=faf:staging:db node tests/staging/run-staging-tests.js

# Logs performance
DEBUG=faf:staging:perf node tests/staging/run-staging-tests.js
```

## 📋 Checklist de Validation

Avant déploiement en production, vérifier :

### ✅ Tests de Base
- [ ] Tous les tests staging passent (100%)
- [ ] Coverage > seuils définis (70-80%)
- [ ] Aucune fuite mémoire détectée
- [ ] Performance dans les seuils acceptables

### ✅ Migration
- [ ] Intégrité des données validée
- [ ] Relations User ↔ Submission correctes  
- [ ] Tokens legacy accessibles
- [ ] Contraintes base de données respectées

### ✅ Fonctionnalités
- [ ] Authentification hybride fonctionne
- [ ] APIs nouvelles et legacy opérationnelles
- [ ] Dashboards admin et user fonctionnels
- [ ] Compatibilité URLs existantes

### ✅ Sécurité
- [ ] Protection XSS active
- [ ] CSRF et rate limiting opérationnels
- [ ] Validation input robuste
- [ ] Session security appropriée

### ✅ Performance
- [ ] Load testing 100+ utilisateurs OK
- [ ] Temps de réponse < 500ms moyenne
- [ ] Optimisations DB validées
- [ ] Monitoring en place

## 🎯 Prochaines Étapes

Après validation staging :

1. **Production Deployment** 
   - Backup complet base de données
   - Migration progressive par batch
   - Monitoring temps réel actif

2. **Post-Migration**
   - Tests de validation en production
   - Performance monitoring continu  
   - Rollback procedures prêtes

3. **Optimisations**
   - Analyse des métriques collectées
   - Optimisations identifiées appliquées
   - Tests de régression actualisés

---

**📞 Support** : Pour questions ou problèmes, consulter les logs détaillés ou les rapports HTML générés.