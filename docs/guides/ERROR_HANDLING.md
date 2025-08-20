# Gestion d'Erreurs Sécurisée - FAF Backend

## Vue d'ensemble

La gestion d'erreurs de FAF v2.0 implémente une approche multicouche avec validation exhaustive (84 tests edge cases), sanitisation XSS renforcée, gestion null/undefined, et réponses sécurisées adaptées à chaque type d'erreur.

## Architecture de Validation

### 🛡️ **Pipeline de Validation Multi-Niveaux**

#### **Niveau 1: Validation Express-Validator Renforcée**
```javascript
// Validation stricte avec XSS protection + null/undefined handling
const validateResponseStrict = [
  body('name')
    .trim()
    .escape()                    // ✅ XSS escaping automatique
    .isLength({ min: 2, max: 100 })
    .withMessage('Le nom doit contenir entre 2 et 100 caractères'),
    
  body('responses.*.question')
    .exists({ checkNull: true, checkFalsy: true })  // ✅ Null/undefined check
    .withMessage('La question ne peut pas être nulle ou vide')
    .trim()
    .escape()                    // ✅ Sanitisation HTML entities
    .isLength({ max: 500 })
    .withMessage('Question trop longue (max 500 caractères)'),
    
  body('responses.*.answer')
    .exists({ checkNull: true, checkFalsy: true })  // ✅ Null/undefined check
    .withMessage('La réponse ne peut pas être nulle ou vide')
    .trim()
    .escape()
    .isLength({ max: 10000 })
    .withMessage('Réponse trop longue (max 10000 caractères)'),
    
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

#### **Niveau 3: Body Parser Optimisé + Gestion Erreurs**
```javascript
// Body parser avec limites adaptées par endpoint
router.post('/api/response', 
  createFormBodyParser(),    // ✅ 2MB pour formulaires texte
  validateResponseStrict,
  handleValidationErrors
);

router.use('/api/admin', 
  createAdminBodyParser(),   // ✅ 1MB pour admin
  ensureAdmin
);

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

#### **Validation Null/Undefined Détectée**
```json
{
  "message": "La question ne peut pas être nulle ou vide",
  "field": "responses[0].question"
}
```

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

### 📏 **Body Parser Optimisé + Error Handling**
```javascript
// Limites optimisées par endpoint
app.use(createStandardBodyParser());              // 512KB par défaut
app.use('/api/response', createFormBodyParser()); // 2MB pour formulaires
app.use('/api/admin', createAdminBodyParser());   // 1MB pour admin

// Error handler amélioré pour payload trop large
function createPayloadErrorHandler() {
  return (error, req, res, next) => {
    if (error.type === 'entity.too.large') {
      const limit = error.limit ? Math.round(error.limit / 1024 / 1024) : 'inconnue';
      return res.status(413).json({
        message: `Données trop volumineuses (limite: ${limit}MB)`,
        error: 'PAYLOAD_TOO_LARGE'
      });
    }
    
    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({
        message: 'Format de données invalide',
        error: 'INVALID_JSON'
      });
    }
    
    next(error);
  };
}
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

### 🧪 **Couverture de Tests Exhaustive (84+ tests)**

#### **Tests Null/Undefined Edge Cases (30 tests)**
```javascript
// tests/validation.edge-cases.test.js
test('should reject null name', async () => {
  const nullData = {
    name: null,
    responses: [{ question: 'Test', answer: 'Test' }]
  };

  const response = await request(app)
    .post('/test-strict')
    .send(nullData)
    .expect(400);

  expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
  expect(response.body.field).toBe('name');
});

test('should handle sanitization of null array elements', async () => {
  const nullElementsData = {
    name: 'Test',
    responses: [
      null,
      { question: 'Valid', answer: 'Valid' },
      undefined,
      { question: 'Another', answer: 'Valid' }
    ]
  };

  const response = await request(app)
    .post('/test-sanitize')
    .send(nullElementsData)
    .expect(200);
        
  // Null elements should be filtered out, leaving valid responses
  expect(response.body.sanitized.responses).toHaveLength(2);
});
```

#### **Boundary Condition Tests (32 tests)**
```javascript
// tests/validation.boundary.test.js
test('should accept exactly 100 characters (max boundary)', async () => {
  const data = {
    name: 'A'.repeat(100),
    responses: [{ question: 'Q', answer: 'A' }]
  };

  await request(app)
    .post('/test-boundary')
    .send(data)
    .expect(200);
});

test('should handle maximum valid payload efficiently', async () => {
  const maxPayload = {
    name: 'A'.repeat(100), // Max name length
    responses: Array(20).fill().map((_, i) => ({ // Max responses count
      question: 'Q'.repeat(500), // Max question length
      answer: 'A'.repeat(10000)  // Max answer length
    }))
  };

  const startTime = Date.now();
  await request(app).post('/test-performance').send(maxPayload).expect(200);
  const processingTime = Date.now() - startTime;
  
  // Should process large valid payload in reasonable time (under 1 second)
  expect(processingTime).toBeLessThan(1000);
});
```

#### **XSS Protection Tests (22 tests)**
```javascript
// tests/validation.security.test.js
test('should escape script tags in name field', async () => {
  const maliciousData = {
    name: '<script>alert("xss")</script>John',
    responses: [{ question: 'Safe question', answer: 'Safe answer' }]
  };

  const response = await request(app)
    .post('/test-strict')
    .send(maliciousData)
    .expect(200);

  expect(response.body.sanitized.name).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;John');
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

Cette architecture de gestion d'erreurs v2.0 garantit **sécurité maximale**, **validation exhaustive**, et **expérience utilisateur optimale** ! 🔒✨

## Nouveautés v2.0 - Gestion d'Erreurs

### 🆕 **Améliorations Majeures**
- **84 tests validation** : Couverture complète null/undefined + edge cases
- **Body parser intelligent** : Erreurs appropriées selon endpoint (512KB/2MB/5MB)  
- **Validation null explicite** : Messages d'erreur spécifiques pour null/undefined
- **Sanitisation robuste** : Filtrage éléments null dans tableaux
- **Performance** : Validation <100ms, rejet rapide payload invalide
- **Messages localisés** : Erreurs en français avec champs précis