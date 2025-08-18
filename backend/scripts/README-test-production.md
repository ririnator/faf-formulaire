# Script de Test de Déploiement Production

## Utilisation

### Méthode 1: Avec npm script (recommandé)
```bash
npm run test:production
# ou
npm run test:prod
```

### Méthode 2: Directement avec Node
```bash
node scripts/test-production-deployment.js [URL_PRODUCTION]
```

### Méthode 3: Avec variables d'environnement
```bash
PRODUCTION_URL=https://votre-app.onrender.com \
LOGIN_ADMIN_USER=admin \
LOGIN_ADMIN_PASS=votre_password \
npm run test:production
```

## Configuration

1. **Copiez le fichier de configuration:**
   ```bash
   cp .env.test-production .env.local
   ```

2. **Remplissez vos valeurs dans `.env.local`:**
   ```env
   PRODUCTION_URL=https://votre-app.onrender.com
   LOGIN_ADMIN_USER=admin
   LOGIN_ADMIN_PASS=votre_mot_de_passe
   ```

## Tests Effectués

### ✅ Tests Fonctionnels
- **Accès application**: Vérification que l'URL charge
- **HTTPS forcé**: Redirection HTTP → HTTPS  
- **Formulaire**: Test de soumission basique
- **Interface admin**: Accès aux pages d'administration

### 🔒 Tests Sécurité
- **Connexion admin**: Authentification avec identifiants
- **Protection CSRF**: Obtention et validation des tokens
- **En-têtes sécurité**: CSP, X-Frame-Options, etc.
- **Sessions sécurisées**: Gestion des cookies

### ⚡ Tests Performance  
- **Temps de réponse**: Pages < 3 secondes
- **Disponibilité**: Status codes et erreurs
- **Base de données**: Connexion MongoDB

### 🛠️ Tests Infrastructure
- **Variables d'environnement**: Configuration Render
- **Services externes**: Cloudinary, MongoDB Atlas
- **Logs**: Détection d'erreurs de déploiement

## Rapport de Tests

Les résultats sont sauvegardés dans:
```
test-reports/production-test-[timestamp].json
```

### Format du rapport:
```json
{
  "url": "https://votre-app.onrender.com",
  "timestamp": "2025-01-XX...",
  "duration": 1234,
  "summary": {
    "PASS": 15,
    "FAIL": 0, 
    "WARN": 2,
    "INFO": 5
  },
  "results": [...]
}
```

## Interprétation des Résultats

### ✅ PASS (Vert)
Test réussi, fonctionnalité opérationnelle

### ❌ FAIL (Rouge)  
Test échoué, nécessite une action immédiate

### ⚠️ WARN (Orange)
Fonctionnalité OK mais peut être améliorée

### ℹ️ INFO (Bleu)
Information, pas d'action requise

## Dépannage

### Erreur "Impossible d'accéder à l'application"
- Vérifiez que l'URL est correcte
- Attendez quelques minutes si Render redémarre
- Consultez les logs Render

### Erreur "Connexion admin échouée"  
- Vérifiez LOGIN_ADMIN_USER et LOGIN_ADMIN_PASS
- Confirmez que ces valeurs correspondent à Render

### Erreur "Base de données"
- Vérifiez MONGODB_URI dans Render  
- Confirmez que MongoDB Atlas accepte les connexions

### Erreur "Token CSRF"
- Vérifiez que les sessions fonctionnent
- Contrôlez la configuration des cookies sécurisés

## Automatisation

Pour intégrer dans CI/CD:
```bash
# Dans votre pipeline
npm run test:production
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Tests de production échoués"
  exit 1
fi
```