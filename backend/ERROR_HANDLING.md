# Gestion d'Erreurs Améliorée - FAF Backend

## Vue d'ensemble

La gestion d'erreurs a été complètement refactorisée pour offrir une meilleure sécurité, des messages d'erreur plus précis et une expérience utilisateur améliorée.

## Améliorations Implémentées

### 🛡️ **Validation des Paramètres**

#### Token Validation (`/api/view/:token` et `/view/:token`)
```javascript
// Validation automatique via middleware
validateToken,           // Format hexadécimal 64 caractères
validateTokenSecurity,   // Logging des tentatives suspectes
tokenRateLimit          // Rate limiting anti-brute force
```

**Contrôles effectués** :
- ✅ Longueur exacte de 64 caractères  
- ✅ Format hexadécimal uniquement (`/^[a-f0-9]{64}$/i`)
- ✅ Rate limiting : 10 tentatives/15min par IP+token
- ✅ Logging des tentatives suspectes

#### MongoDB ID Validation
```javascript
validateMongoId  // IDs MongoDB valides uniquement
```

#### Pagination Validation
```javascript
validatePagination  // page: 1-1000, limit: 1-100
```

### 🎯 **Gestion d'Erreurs Spécifique**

#### Erreurs de Base de Données
```javascript
// MongoDB CastError
if (err.name === 'CastError') {
  return res.status(400).json({ 
    error: 'Token malformé',
    details: 'Format invalide pour la base de données'
  });
}

// Erreurs de réseau MongoDB
if (err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
  return res.status(503).json({ 
    error: 'Service temporairement indisponible',
    details: 'Problème de connexion à la base de données'
  });
}

// Contraintes d'unicité
if (err.code === 11000) {
  return res.status(409).json({ 
    message: 'Réponse déjà enregistrée pour ce mois' 
  });
}
```

#### Erreurs de Validation
```javascript
// Erreurs Mongoose
if (err.name === 'ValidationError') {
  return res.status(400).json({ 
    message: 'Données invalides',
    details: err.message 
  });
}
```

#### Erreurs de Service
```javascript
// Services indisponibles
if (!responseService) {
  return res.status(503).json({ 
    message: 'Service de réponses indisponible' 
  });
}
```

### 🔒 **Sécurité Renforcée**

#### Rate Limiting Intelligent
```javascript
// Rate limiting par IP + token
keyGenerator: (req) => {
  return `${req.ip}-${req.params.token?.substring(0, 8) || 'no-token'}`;
}
```

#### Logging de Sécurité
```javascript
// Log des tentatives suspectes
if (token && (token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token))) {
  console.warn(`🚨 Tentative d'accès avec token suspect: ${token.substring(0, 8)}... depuis ${req.ip}`);
}
```

## Structure des Réponses d'Erreur

### ✅ **Format Standardisé**

```json
// Erreur de validation
{
  "error": "Paramètre invalide",
  "field": "token",
  "message": "Le token doit faire exactement 64 caractères",
  "value": "abc123"
}

// Erreur de service
{
  "error": "Service temporairement indisponible",
  "details": "Problème de connexion à la base de données"
}

// Erreur métier
{
  "message": "Une réponse admin existe déjà pour ce mois."
}
```

### 📊 **Codes de Status HTTP**

| Code | Signification | Cas d'usage |
|------|---------------|-------------|
| `400` | Bad Request | Paramètres invalides, données malformées |
| `404` | Not Found | Token inexistant, ressource introuvable |
| `409` | Conflict | Réponse admin déjà existante, duplicata |
| `429` | Too Many Requests | Rate limiting dépassé |
| `500` | Internal Server Error | Erreur serveur générique |
| `503` | Service Unavailable | DB indisponible, services down |

## Middleware Chain

### 🔄 **Ordre d'Exécution pour `/api/view/:token`**

1. **tokenRateLimit** - Rate limiting anti-brute force
2. **validateTokenSecurity** - Logging des tentatives suspectes  
3. **validateToken** - Validation format hexadécimal
4. **handleParamValidationErrors** - Gestion erreurs de validation
5. **Route Handler** - Logique métier avec try/catch
6. **Error Handler** - Gestionnaire global d'erreurs

### 🛠️ **Avantages**

**Sécurité** :
- ✅ Protection contre le brute force
- ✅ Validation stricte des entrées
- ✅ Logging des activités suspectes

**Expérience Utilisateur** :
- ✅ Messages d'erreur clairs et précis
- ✅ Codes de status appropriés
- ✅ Détails contextuels quand nécessaire

**Maintenance** :
- ✅ Middleware réutilisable
- ✅ Gestion d'erreurs centralisée
- ✅ Logs structurés pour le debugging

**Performance** :
- ✅ Validation précoce (early return)
- ✅ Rate limiting intelligent
- ✅ Réponses rapides pour les erreurs

## Migration des Erreurs Legacy

### ❌ **Avant (Legacy)**
```javascript
// Validation manuelle répétitive
if (!token || typeof token !== 'string' || token.length !== 64) {
  return res.status(400).json({ error: 'Token invalide' });
}

// Gestion d'erreurs basique
catch (err) {
  console.error(err);
  res.status(500).json({ error: 'Erreur serveur' });
}
```

### ✅ **Après (Refactorisé)**
```javascript
// Validation middleware réutilisable
app.get('/api/view/:token', 
  tokenRateLimit,
  validateTokenSecurity,
  validateToken,
  handleParamValidationErrors,
  async (req, res) => {
    // Logique métier avec gestion d'erreurs spécifique
  }
);
```

Cette architecture garantit une gestion d'erreurs robuste, sécurisée et maintenable ! 🚀