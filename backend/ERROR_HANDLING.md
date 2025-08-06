# Gestion d'Erreurs Sécurisée - FAF Backend

## Vue d'ensemble

La gestion d'erreurs de FAF implémente une approche multicouche avec validation stricte, sanitisation XSS, et réponses sécurisées adaptées à chaque type d'erreur.

## Architecture de Validation

### 🛡️ **Pipeline de Validation Multi-Niveaux**

#### **Niveau 1: Validation Express-Validator**
```javascript
// Validation stricte avec XSS protection
const validateResponseStrict = [
  body('name')
    .trim()
    .escape()                    // ✅ XSS escaping automatique
    .isLength({ min: 2, max: 100 })
    .withMessage('Le nom doit contenir entre 2 et 100 caractères'),
    
  body('responses.*.question')
    .trim()
    .escape()                    // ✅ Sanitisation HTML entities
    .isLength({ max: 500 })
    .withMessage('Question trop longue (max 500 caractères)'),
    
  body('website')
    .optional()
    .isEmpty()                   // ✅ Honeypot anti-spam
    .withMessage('Spam détecté')
];
```

#### **Niveau 2: Validation Métier**
```javascript
// Prévention des doublons admin
if (isAdmin) {
  const already = await Response.exists({ month, isAdmin: true });
  if (already) {
    return res.status(409).json({
      message: 'Une réponse admin existe déjà pour ce mois.'
    });
  }
}
```

#### **Niveau 3: Gestion d'Erreurs Spécialisées**
```javascript
// Rate limiting intelligent
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { message: "Trop de soumissions. Réessaie dans 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false
});
```

## Types d'Erreurs et Réponses

### 🚫 **Erreurs de Validation (400)**

#### **Validation XSS Détectée**
```json
{
  "message": "Le nom doit contenir entre 2 et 100 caractères",
  "field": "name"
}
```

#### **Données Sanitisées Automatiquement**
```javascript
// Input malveillant
input: '<script>alert("hack")</script>John'

// Après sanitisation automatique  
output: '&lt;script&gt;alert(&quot;hack&quot;)&lt;&#x2F;script&gt;John'

// Sauvegardé de façon sécurisée
database: { name: '&lt;script&gt;alert(&quot;hack&quot;)&lt;&#x2F;script&gt;John' }
```

#### **Honeypot Spam Détecté**
```json
{
  "message": "Spam détecté",
  "field": "website"
}
```

### ❌ **Erreurs de Conflit (409)**

#### **Admin Duplicate Prevention**
```json
{
  "message": "Une réponse admin existe déjà pour ce mois."
}
```

### 🚦 **Rate Limiting (429)**
```json
{
  "message": "Trop de soumissions. Réessaie dans 15 minutes."
}
```

### 🔍 **Token Invalide (404)**
```json
{
  "error": "Lien invalide ou expiré"
}
```

### 🔧 **Erreurs Serveur (500)**

#### **Erreur Base de Données**
```javascript
// MongoDB connection errors
if (err.name === 'MongoNetworkError') {
  console.error('❌ Erreur MongoDB:', err.message);
  return res.status(503).json({ 
    error: 'Service temporairement indisponible' 
  });
}

// Contraintes d'unicité
if (err.code === 11000) {
  return res.status(409).json({ 
    message: 'Données déjà existantes' 
  });
}
```

#### **Validation Mongoose**
```javascript
if (err.name === 'ValidationError') {
  console.error('❌ Erreur validation Mongoose:', err.message);
  return res.status(400).json({ 
    message: 'Données invalides',
    details: 'Vérifiez le format des données soumises'
  });
}
```

## Middleware de Sécurité

### 🔐 **Authentication Error Handling**
```javascript
// middleware/auth.js
async function authenticateAdmin(req, res, next) {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.redirect('/login?error=1');
    }
    
    if (username === LOGIN_ADMIN_USER && 
        await bcrypt.compare(password, LOGIN_ADMIN_PASS)) {
      req.session.isAdmin = true;
      return res.redirect('/admin');
    }
    
    return res.redirect('/login?error=1');
  } catch (error) {
    console.error('❌ Erreur authentification:', error);
    return res.redirect('/login?error=1');
  }
}
```

### 📏 **Body Size Error Handling**
```javascript
// Limite 10MB avec message d'erreur approprié
app.use(express.json({ 
  limit: '10mb',
  extended: true
}));

// Error handler pour payload trop large
app.use((error, req, res, next) => {
  if (error.type === 'entity.too.large') {
    return res.status(413).json({
      message: 'Fichier trop volumineux (limite: 10MB)'
    });
  }
  next(error);
});
```

## Format des Erreurs Standardisées

### 📋 **Structure de Réponse Cohérente**

#### **Validation Errors**
```json
{
  "message": "Description claire de l'erreur",
  "field": "nom_du_champ_concerné"
}
```

#### **Business Logic Errors**
```json
{
  "message": "Description de l'erreur métier",
  "code": "ADMIN_DUPLICATE" // Code d'erreur optionnel
}
```

#### **System Errors (Sanitized)**
```json
{
  "error": "Erreur système générique",
  "details": "Information safe pour l'utilisateur"
}
```

### 🔒 **Sécurité dans les Messages d'Erreur**

#### **❌ À éviter (Information Leakage)**
```javascript
// NE PAS exposer les détails internes
res.json({ 
  error: err.stack,           // ❌ Stack trace exposé
  query: err.query,          // ❌ Requête DB exposée
  password: err.password     // ❌ Données sensibles exposées
});
```

#### **✅ Approche Sécurisée**
```javascript
// Messages d'erreur sanitisés
console.error('❌ Erreur détaillée pour logs:', err);  // ✅ Logging interne
res.status(500).json({ 
  message: 'Erreur en sauvegardant la réponse'        // ✅ Message générique
});
```

## Logging Sécurisé

### 📝 **Stratégie de Logging**

#### **Erreurs de Validation**
```javascript
// Log sans exposer les données utilisateur
console.warn(`🚨 Tentative XSS détectée depuis ${req.ip}`);
// Ne PAS logger: req.body (peut contenir XSS)
```

#### **Erreurs Admin**
```javascript
console.error('❌ Erreur admin duplicate:', {
  month: month,
  isAdmin: isAdmin,
  ip: req.ip,
  timestamp: new Date().toISOString()
});
```

#### **Erreurs Système**
```javascript
console.error('❌ Erreur MongoDB:', {
  error: err.name,
  message: err.message,
  operation: 'findOne',
  collection: 'responses'
  // Ne PAS logger: données utilisateur sensibles
});
```

## Tests d'Erreurs

### 🧪 **Couverture de Tests Complète**

#### **Validation XSS Tests**
```javascript
// tests/validation.security.test.js
test('should escape XSS in user input', async () => {
  const xssData = {
    name: '<script>alert("xss")</script>User',
    responses: [{ question: 'Safe?', answer: 'Safe!' }]
  };
  
  const response = await request(app)
    .post('/api/response')
    .send(xssData)
    .expect(201);
    
  // Vérifier que les données sont échappées
  const saved = await Response.findOne({ name: /User/ });
  expect(saved.name).toContain('&lt;script&gt;');
  expect(saved.name).not.toContain('<script>');
});
```

#### **Error Boundary Tests**
```javascript
test('should handle character limits properly', async () => {
  const oversizedData = {
    name: 'A'.repeat(101), // Dépasse la limite de 100
    responses: [{ question: 'Q', answer: 'A' }]
  };
  
  const response = await request(app)
    .post('/api/response')
    .send(oversizedData)
    .expect(400);
    
  expect(response.body.message).toContain('100 caractères');
});
```

## Codes de Status HTTP

### 📊 **Mapping Erreur → Status Code**

| Status | Type | Utilisation FAF |
|--------|------|----------------|
| `400` | Bad Request | Validation échouée, XSS détecté, données malformées |
| `401` | Unauthorized | Session expirée, auth requise |
| `403` | Forbidden | Admin requis, permissions insuffisantes |
| `404` | Not Found | Token invalide, ressource inexistante |
| `409` | Conflict | Admin duplicate, contrainte unique violée |
| `413` | Payload Too Large | Body > 10MB |
| `429` | Too Many Requests | Rate limiting (3/15min) |
| `500` | Internal Server Error | Erreur système générique |
| `503` | Service Unavailable | MongoDB indisponible |

## Migration vers Gestion Sécurisée

### **Améliorations Apportées**

#### **✅ Avant → Après**
```javascript
// ❌ Avant: Validation manuelle
if (!req.body.name || req.body.name.length < 2) {
  return res.status(400).json({ error: 'Nom invalide' });
}

// ✅ Après: Middleware de validation avec XSS protection
router.post('/', 
  validateResponseStrict,    // Validation + XSS escaping
  handleValidationErrors,    // Gestion erreurs standardisée
  sanitizeResponse,          // Sanitisation supplémentaire
  controllerFunction         // Logique métier propre
);
```

#### **Protection Multicouche**
1. **Express-validator** : Validation + XSS escaping
2. **Honeypot** : Détection spam automatique  
3. **Rate limiting** : Protection brute force
4. **Sanitisation** : Nettoyage données supplémentaire
5. **Logging sécurisé** : Audit trail sans exposition

Cette architecture garantit **sécurité maximale** avec **expérience utilisateur optimale** ! 🔒✨