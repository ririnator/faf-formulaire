# 🚀 Quick Start - Tests de Migration Staging

## Installation

```bash
# Installer les dépendances pour les rapports
cd backend
npm install jest-html-reporters jest-junit --save-dev

# Vérifier la configuration
node tests/staging/run-staging-tests.js --help
```

## Utilisation Rapide

### 🧪 Tests Complets (Recommandé)
```bash
npm run test:staging:full
```
**✅ Lance tous les tests en parallèle avec coverage et rapports HTML**

### 🎯 Tests par Composant
```bash
npm run test:staging:data           # Tests de validation des données
npm run test:staging:functionality  # Tests des fonctionnalités
npm run test:staging:performance    # Tests de performance  
npm run test:staging:regression     # Tests de régression
npm run test:staging:monitoring     # Tests de monitoring
```

### 📊 Tests avec Rapports
```bash
npm run test:staging:coverage      # Tests + coverage + rapports
npm run test:staging:verbose       # Tests avec logs détaillés
npm run test:staging:parallel      # Tests en parallèle (plus rapide)
```

## Résultats

### Rapports Générés
```
backend/reports/staging/
├── staging-tests-[timestamp].html      # 📊 Rapport HTML interactif
├── staging-tests-[timestamp].json      # 📋 Rapport JSON détaillé
├── staging-migration-report-[xxx].json # 🔄 Rapport de migration
└── coverage/                           # 📈 Coverage par suite
```

### Métriques Clés
- **🎯 Taux de succès** : Doit être > 95%
- **⚡ Performance** : Temps de réponse < 500ms
- **🧠 Mémoire** : Pas de fuites détectées  
- **🔒 Sécurité** : Protection XSS/CSRF validée
- **📊 Coverage** : Branches > 70%, Lines > 80%

## Validation Rapide

```bash
# Test minimal pour vérifier que tout fonctionne
npm run test:staging:data

# Si ça passe, lancer les tests complets
npm run test:staging:full
```

## 🆘 Résolution Problèmes

| Problème | Solution |
|----------|----------|
| **Tests timeout** | `npm run test:staging:verbose` pour voir les détails |
| **Memory errors** | Relancer individuellement : `npm run test:staging:performance` |
| **Dependencies** | `npm install` puis `npm run test:staging:data` |

## 📋 Checklist de Validation

- [ ] `npm run test:staging:full` passe à 100%
- [ ] Rapports HTML générés dans `/reports/staging/`
- [ ] Coverage > 70% branches, 80% lines
- [ ] Aucune alerte de sécurité critique
- [ ] Performance < 500ms moyenne

**✅ Si tout est vert → Migration prête pour production !**