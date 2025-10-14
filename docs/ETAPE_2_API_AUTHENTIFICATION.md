# Étape 2 : API d'authentification (Register + Login)

## Vue d'ensemble

Cette étape implémente le système d'authentification complet avec :
- Inscription de nouveaux admins (Register)
- Connexion sécurisée (Login)
- Vérification des tokens JWT
- Middleware de protection des routes
- Rate limiting et sécurité anti-spam

## Objectifs

- Permettre à n'importe qui de créer un compte admin
- Générer des JWT tokens sécurisés pour l'authentification
- Protéger les routes admin avec un middleware
- Implémenter des protections contre les attaques (rate limiting, honeypot)

## Livrables

### API Routes
- [ ] `/api/auth/register.js` - Inscription d'un nouvel admin
- [ ] `/api/auth/login.js` - Connexion d'un admin existant
- [ ] `/api/auth/verify.js` - Vérification d'un JWT token
- [ ] `/api/auth/logout.js` - Déconnexion (optionnel, JWT stateless)

### Utilitaires
- [ ] `/utils/jwt.js` - Génération et vérification de JWT
- [ ] `/utils/validation.js` - Validation des inputs (username, email, password)

### Middleware
- [ ] `/middleware/auth.js` - Middleware de vérification JWT
- [ ] `/middleware/rateLimit.js` - Rate limiting par IP

### Tests
- [ ] `/tests/auth.test.js` - Tests unitaires d'authentification (15+ tests)
- [ ] `/tests/jwt.test.js` - Tests de génération/vérification JWT
- [ ] `/tests/validation.test.js` - Tests de validation des inputs

### Documentation
- [ ] `/docs/ETAPE_2_API_AUTHENTIFICATION.md` - Cette documentation

---

## Installation des dépendances

```bash
# Installer les dépendances nécessaires
npm install jsonwebtoken bcrypt express-rate-limit

# Dépendances de développement (si pas déjà installées)
npm install --save-dev jest supertest
```

---

## Architecture de l'authentification

### Flux d'inscription (Register)

```
1. Utilisateur envoie: { username, email, password }
   └─> POST /api/auth/register

2. Backend valide:
   ├─> Username: 3-20 chars, lowercase, alphanumériques + tirets
   ├─> Email: format valide
   ├─> Password: min 8 chars, 1 majuscule, 1 chiffre
   └─> Honeypot: champ "website" doit être vide

3. Backend vérifie:
   ├─> Username unique dans Supabase
   └─> Email unique dans Supabase

4. Backend hash le password:
   └─> bcrypt.hash(password, 10) → password_hash

5. Backend insère dans Supabase:
   └─> INSERT INTO admins (username, email, password_hash)

6. Backend génère JWT token:
   ├─> Payload: { sub: admin.id, username: admin.username }
   ├─> Secret: process.env.JWT_SECRET
   └─> Expiration: 7 jours

7. Backend retourne:
   └─> { success: true, token: "...", admin: { id, username, email } }
```

### Flux de connexion (Login)

```
1. Utilisateur envoie: { username, password }
   └─> POST /api/auth/login

2. Backend cherche l'admin:
   └─> SELECT * FROM admins WHERE LOWER(username) = LOWER(...)

3. Backend vérifie le password:
   └─> bcrypt.compare(password, admin.password_hash)

4. Si correct:
   ├─> Génère JWT token (même format que register)
   └─> Retourne { success: true, token: "...", admin: { ... } }

5. Si incorrect:
   └─> Retourne 401 { error: "Identifiants invalides" }
      (pas de distinction username/password pour éviter l'énumération)
```

### Flux de vérification (Verify)

```
1. Client envoie:
   └─> GET /api/auth/verify
       Headers: { Authorization: "Bearer <token>" }

2. Backend extrait le token:
   └─> const token = req.headers.authorization?.split(' ')[1]

3. Backend vérifie le token:
   └─> jwt.verify(token, process.env.JWT_SECRET)

4. Si valide:
   ├─> Récupère admin depuis Supabase (avec admin.id du token)
   └─> Retourne { success: true, admin: { id, username, email } }

5. Si invalide/expiré:
   └─> Retourne 401 { error: "Token invalide" }
```

### Middleware de protection

```javascript
// Utilisation dans les routes protégées
const { verifyJWT } = require('../middleware/auth');

app.get('/api/admin/dashboard', verifyJWT, async (req, res) => {
  // req.admin contient { id, username } depuis le JWT
  const adminId = req.admin.id;

  // Filtrer les données par owner_id
  const { data } = await supabase
    .from('responses')
    .select('*')
    .eq('owner_id', adminId);

  res.json({ responses: data });
});
```

---

## Spécifications détaillées

### 1. `/api/auth/register.js`

**Méthode** : `POST`

**Body** :
```json
{
  "username": "sophie",
  "email": "sophie@example.com",
  "password": "Password123!",
  "website": ""
}
```

**Validation** :
- `username` :
  - Requis
  - 3-20 caractères
  - Lowercase uniquement
  - Alphanumériques + tirets/underscores
  - Regex : `^[a-z0-9_-]{3,20}$`
- `email` :
  - Requis
  - Format email valide
  - Regex : `^[^@]+@[^@]+\.[^@]+$`
- `password` :
  - Requis
  - Minimum 8 caractères
  - Au moins 1 majuscule
  - Au moins 1 chiffre
  - Regex : `^(?=.*[A-Z])(?=.*\d).{8,}$`
- `website` :
  - Honeypot (champ caché anti-bot)
  - Doit être vide
  - Si rempli → rejeter avec 400

**Logique** :
```javascript
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { username, email, password, website } = req.body;

    // 1. Honeypot validation
    if (website) {
      return res.status(400).json({ error: 'Validation failed' });
    }

    // 2. Validation des inputs
    if (!validateUsername(username)) {
      return res.status(400).json({
        error: 'Username invalide. 3-20 caractères, lowercase, alphanumériques et tirets uniquement.'
      });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Email invalide.' });
    }

    if (!validatePassword(password)) {
      return res.status(400).json({
        error: 'Mot de passe trop faible. Min 8 caractères, 1 majuscule, 1 chiffre.'
      });
    }

    // 3. Vérifier username unique
    const { data: existingUser } = await supabaseAdmin
      .from('admins')
      .select('id')
      .eq('username', username.toLowerCase())
      .single();

    if (existingUser) {
      return res.status(409).json({ error: 'Ce nom d\'utilisateur est déjà pris.' });
    }

    // 4. Vérifier email unique
    const { data: existingEmail } = await supabaseAdmin
      .from('admins')
      .select('id')
      .eq('email', email.toLowerCase())
      .single();

    if (existingEmail) {
      return res.status(409).json({ error: 'Cet email est déjà utilisé.' });
    }

    // 5. Hash du password
    const passwordHash = await bcrypt.hash(password, 10);

    // 6. Insertion dans Supabase
    const { data: newAdmin, error: insertError } = await supabaseAdmin
      .from('admins')
      .insert({
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        password_hash: passwordHash
      })
      .select('id, username, email')
      .single();

    if (insertError) {
      console.error('Insert error:', insertError);
      return res.status(500).json({ error: 'Erreur lors de la création du compte.' });
    }

    // 7. Génération JWT
    const token = generateToken({
      sub: newAdmin.id,
      username: newAdmin.username
    });

    // 8. Retour succès
    return res.status(201).json({
      success: true,
      token,
      admin: {
        id: newAdmin.id,
        username: newAdmin.username,
        email: newAdmin.email
      }
    });

  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
}
```

**Réponses** :
- **201 Created** : Inscription réussie
  ```json
  {
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "admin": {
      "id": "uuid-xxx",
      "username": "sophie",
      "email": "sophie@example.com"
    }
  }
  ```

- **400 Bad Request** : Validation échouée
  ```json
  { "error": "Username invalide. 3-20 caractères, lowercase..." }
  ```

- **409 Conflict** : Username ou email déjà pris
  ```json
  { "error": "Ce nom d'utilisateur est déjà pris." }
  ```

- **500 Internal Server Error** : Erreur serveur
  ```json
  { "error": "Erreur serveur." }
  ```

**Sécurité** :
- Rate limiting : 5 tentatives / 15 minutes par IP
- Honeypot field : rejeter si `website` non vide
- Password hashing : bcrypt avec 10 rounds
- Lowercase normalization : username et email en minuscules
- Pas de leak d'info : messages d'erreur génériques

---

### 2. `/api/auth/login.js`

**Méthode** : `POST`

**Body** :
```json
{
  "username": "sophie",
  "password": "Password123!"
}
```

**Logique** :
```javascript
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { username, password } = req.body;

    // 1. Validation basique
    if (!username || !password) {
      return res.status(400).json({ error: 'Username et password requis.' });
    }

    // Délai constant pour éviter timing attack (100-200ms aléatoire)
    const startTime = Date.now();
    const minDelay = 100 + Math.random() * 100;

    // 2. Chercher l'admin (case-insensitive)
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, email, password_hash')
      .ilike('username', username)
      .single();

    if (error || !admin) {
      // Délai constant avant de répondre
      await delay(minDelay - (Date.now() - startTime));
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    // 3. Vérifier le password
    const isValid = await bcrypt.compare(password, admin.password_hash);

    if (!isValid) {
      // Délai constant avant de répondre
      await delay(minDelay - (Date.now() - startTime));
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    // 4. Génération JWT
    const token = generateToken({
      sub: admin.id,
      username: admin.username
    });

    // Délai constant avant de répondre (même en cas de succès)
    await delay(minDelay - (Date.now() - startTime));

    // 5. Retour succès
    return res.status(200).json({
      success: true,
      token,
      admin: {
        id: admin.id,
        username: admin.username,
        email: admin.email
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
}

// Fonction helper pour délai constant
function delay(ms) {
  if (ms <= 0) return Promise.resolve();
  return new Promise(resolve => setTimeout(resolve, ms));
}
```

**Réponses** :
- **200 OK** : Connexion réussie
  ```json
  {
    "success": true,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "admin": {
      "id": "uuid-xxx",
      "username": "sophie",
      "email": "sophie@example.com"
    }
  }
  ```

- **400 Bad Request** : Champs manquants
  ```json
  { "error": "Username et password requis." }
  ```

- **401 Unauthorized** : Identifiants incorrects
  ```json
  { "error": "Identifiants invalides." }
  ```

- **429 Too Many Requests** : Rate limit dépassé
  ```json
  { "error": "Trop de tentatives. Réessayez dans 15 minutes." }
  ```

**Sécurité** :
- Rate limiting : 5 tentatives / 15 minutes par IP
- Pas de distinction entre "username inconnu" et "password incorrect"
- Délai constant de réponse (timing attack prevention)
- Case-insensitive username lookup
- Messages d'erreur génériques

---

### 3. `/api/auth/verify.js`

**Méthode** : `GET`

**Headers** :
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Logique** :
```javascript
export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // 1. Extraire le token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token manquant.' });
    }

    const token = authHeader.split(' ')[1];

    // 2. Vérifier le token
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(401).json({ error: 'Token invalide ou expiré.' });
    }

    // 3. Récupérer l'admin depuis Supabase
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, email, created_at')
      .eq('id', decoded.sub)
      .single();

    if (error || !admin) {
      return res.status(401).json({ error: 'Admin introuvable.' });
    }

    // 4. Retour succès
    return res.status(200).json({
      success: true,
      admin: {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        createdAt: admin.created_at
      }
    });

  } catch (error) {
    console.error('Verify error:', error);
    return res.status(401).json({ error: 'Token invalide.' });
  }
}
```

**Réponses** :
- **200 OK** : Token valide
  ```json
  {
    "success": true,
    "admin": {
      "id": "uuid-xxx",
      "username": "sophie",
      "email": "sophie@example.com",
      "createdAt": "2025-01-13T10:30:00Z"
    }
  }
  ```

- **401 Unauthorized** : Token invalide/expiré
  ```json
  { "error": "Token invalide ou expiré." }
  ```

---

### 4. `/utils/jwt.js`

```javascript
const jwt = require('jsonwebtoken');

/**
 * Génère un JWT token
 * @param {Object} payload - Données à encoder (ex: { sub: adminId, username })
 * @param {string} expiresIn - Durée de validité (défaut: 7 jours)
 * @returns {string} Token JWT
 */
function generateToken(payload, expiresIn = '7d') {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  return jwt.sign(payload, secret, {
    expiresIn,
    issuer: 'faf-multitenant',
    audience: 'faf-users'
  });
}

/**
 * Vérifie un JWT token
 * @param {string} token - Token à vérifier
 * @returns {Object|null} Payload décodé ou null si invalide
 */
function verifyToken(token) {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET is not defined');
  }

  try {
    return jwt.verify(token, secret, {
      issuer: 'faf-multitenant',
      audience: 'faf-users'
    });
  } catch (error) {
    console.error('JWT verification failed:', error.message);
    return null;
  }
}

/**
 * Décode un JWT sans vérification (pour debug uniquement)
 * @param {string} token - Token à décoder
 * @returns {Object|null} Payload décodé
 */
function decodeToken(token) {
  try {
    return jwt.decode(token);
  } catch (error) {
    return null;
  }
}

module.exports = {
  generateToken,
  verifyToken,
  decodeToken
};
```

---

### 5. `/utils/validation.js`

```javascript
/**
 * Valide un username
 * @param {string} username
 * @returns {boolean}
 */
function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;

  // 3-20 caractères, lowercase, alphanumériques + tirets/underscores
  const regex = /^[a-z0-9_-]{3,20}$/;
  return regex.test(username);
}

/**
 * Valide un email
 * @param {string} email
 * @returns {boolean}
 */
function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;

  // Format email basique
  const regex = /^[^@]+@[^@]+\.[^@]+$/;
  return regex.test(email);
}

/**
 * Valide un password
 * @param {string} password
 * @returns {boolean}
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;

  // Min 8 chars, 1 majuscule, 1 chiffre
  const regex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
  return regex.test(password);
}

/**
 * Échappe les caractères HTML dangereux
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  if (!text || typeof text !== 'string') return '';

  const map = {
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    '"': '&quot;',
    "'": '&#x27;'
  };

  return text.replace(/[<>&"']/g, (m) => map[m]);
}

/**
 * Normalise un username (lowercase, trim)
 * @param {string} username
 * @returns {string}
 */
function normalizeUsername(username) {
  if (!username || typeof username !== 'string') return '';
  return username.trim().toLowerCase();
}

/**
 * Normalise un email (lowercase, trim)
 * @param {string} email
 * @returns {string}
 */
function normalizeEmail(email) {
  if (!email || typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

module.exports = {
  validateUsername,
  validateEmail,
  validatePassword,
  escapeHtml,
  normalizeUsername,
  normalizeEmail
};
```

---

### 6. `/middleware/auth.js`

```javascript
const { verifyToken } = require('../utils/jwt');
const { supabaseAdmin } = require('../utils/supabase');

/**
 * Middleware de vérification JWT
 * Protège les routes admin
 */
async function verifyJWT(req, res, next) {
  try {
    // 1. Extraire le token
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentification requise. Token manquant.'
      });
    }

    const token = authHeader.split(' ')[1];

    // 2. Vérifier le token
    const decoded = verifyToken(token);

    if (!decoded) {
      return res.status(401).json({
        error: 'Token invalide ou expiré.'
      });
    }

    // 3. Vérifier que l'admin existe toujours
    const { data: admin, error } = await supabaseAdmin
      .from('admins')
      .select('id, username, email')
      .eq('id', decoded.sub)
      .single();

    if (error || !admin) {
      return res.status(401).json({
        error: 'Admin introuvable.'
      });
    }

    // 4. Attacher les infos admin à la requête
    req.admin = {
      id: admin.id,
      username: admin.username,
      email: admin.email
    };

    // 5. Continuer vers la route suivante
    next();

  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(401).json({
      error: 'Erreur d\'authentification.'
    });
  }
}

/**
 * Middleware optionnel : parse le token mais ne bloque pas si absent
 */
async function optionalAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const decoded = verifyToken(token);

      if (decoded) {
        const { data: admin } = await supabaseAdmin
          .from('admins')
          .select('id, username, email')
          .eq('id', decoded.sub)
          .single();

        if (admin) {
          req.admin = {
            id: admin.id,
            username: admin.username,
            email: admin.email
          };
        }
      }
    }

    // Continuer même si pas d'auth
    next();

  } catch (error) {
    // Ne pas bloquer en cas d'erreur
    next();
  }
}

module.exports = {
  verifyJWT,
  optionalAuth
};
```

---

### 7. `/middleware/rateLimit.js`

```javascript
const rateLimit = require('express-rate-limit');

/**
 * Rate limiter pour les tentatives de login/register
 * 5 tentatives par 15 minutes par IP
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requêtes max
  message: {
    error: 'Trop de tentatives. Réessayez dans 15 minutes.'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  // Clé basée sur l'IP
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  },
  // Handler personnalisé
  handler: (req, res) => {
    res.status(429).json({
      error: 'Trop de tentatives. Réessayez dans 15 minutes.',
      retryAfter: Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000)
    });
  }
});

/**
 * Rate limiter pour les requêtes publiques
 * 100 requêtes par 15 minutes par IP
 */
const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Trop de requêtes. Réessayez plus tard.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  }
});

/**
 * Rate limiter strict pour les opérations sensibles
 * 3 tentatives par 15 minutes par IP
 */
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: {
    error: 'Limite dépassée. Réessayez dans 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.headers['x-forwarded-for'] || 'unknown';
  }
});

module.exports = {
  authLimiter,
  publicLimiter,
  strictLimiter
};
```

---

## Tests

### 1. `/tests/auth.test.js`

```javascript
const request = require('supertest');
const { supabaseAdmin } = require('../utils/supabase');
const bcrypt = require('bcrypt');

// Mock de l'app Express (à adapter selon votre structure)
const app = require('../app'); // ou créer un serveur de test

describe('Authentication API', () => {

  // Nettoyer la base de test avant chaque test
  beforeEach(async () => {
    await supabaseAdmin
      .from('admins')
      .delete()
      .neq('id', '00000000-0000-0000-0000-000000000000'); // Delete all test data
  });

  describe('POST /api/auth/register', () => {

    test('Should register a new admin successfully', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
          website: ''
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      expect(res.body.admin.username).toBe('testuser');
      expect(res.body.admin.email).toBe('test@example.com');
    });

    test('Should reject invalid username (too short)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'ab',
          email: 'test@example.com',
          password: 'Password123!',
          website: ''
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Username invalide');
    });

    test('Should reject invalid username (uppercase)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'TestUser',
          email: 'test@example.com',
          password: 'Password123!',
          website: ''
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Username invalide');
    });

    test('Should reject weak password', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'password', // no uppercase, no digit
          website: ''
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toContain('Mot de passe trop faible');
    });

    test('Should reject duplicate username', async () => {
      // Créer un admin
      await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
          website: ''
        });

      // Tenter de créer un autre avec le même username
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'other@example.com',
          password: 'Password123!',
          website: ''
        });

      expect(res.status).toBe(409);
      expect(res.body.error).toContain('déjà pris');
    });

    test('Should reject honeypot (bot detection)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
          website: 'http://spam.com' // Bot rempli ce champ
        });

      expect(res.status).toBe(400);
    });

  });

  describe('POST /api/auth/login', () => {

    beforeEach(async () => {
      // Créer un admin de test
      await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
          website: ''
        });
    });

    test('Should login successfully with correct credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'Password123!'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.token).toBeDefined();
      expect(res.body.admin.username).toBe('testuser');
    });

    test('Should reject incorrect password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'testuser',
          password: 'WrongPassword123!'
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Identifiants invalides.');
    });

    test('Should reject non-existent username', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'nonexistent',
          password: 'Password123!'
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Identifiants invalides.');
    });

    test('Should be case-insensitive for username', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'TESTUSER', // Uppercase
          password: 'Password123!'
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

  });

  describe('GET /api/auth/verify', () => {

    let token;
    let adminId;

    beforeEach(async () => {
      // Créer un admin et récupérer son token
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser',
          email: 'test@example.com',
          password: 'Password123!',
          website: ''
        });

      token = res.body.token;
      adminId = res.body.admin.id;
    });

    test('Should verify valid token', async () => {
      const res = await request(app)
        .get('/api/auth/verify')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.admin.id).toBe(adminId);
      expect(res.body.admin.username).toBe('testuser');
    });

    test('Should reject missing token', async () => {
      const res = await request(app)
        .get('/api/auth/verify');

      expect(res.status).toBe(401);
      expect(res.body.error).toContain('Token manquant');
    });

    test('Should reject invalid token', async () => {
      const res = await request(app)
        .get('/api/auth/verify')
        .set('Authorization', 'Bearer invalid-token-123');

      expect(res.status).toBe(401);
      expect(res.body.error).toContain('Token invalide');
    });

  });

});
```

### 2. `/tests/jwt.test.js`

```javascript
const { generateToken, verifyToken, decodeToken } = require('../utils/jwt');

describe('JWT Utils', () => {

  test('Should generate a valid token', () => {
    const payload = { sub: 'user-123', username: 'testuser' };
    const token = generateToken(payload);

    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    expect(token.split('.').length).toBe(3); // JWT format: header.payload.signature
  });

  test('Should verify a valid token', () => {
    const payload = { sub: 'user-123', username: 'testuser' };
    const token = generateToken(payload);

    const decoded = verifyToken(token);

    expect(decoded).toBeDefined();
    expect(decoded.sub).toBe('user-123');
    expect(decoded.username).toBe('testuser');
  });

  test('Should reject an invalid token', () => {
    const decoded = verifyToken('invalid-token');

    expect(decoded).toBeNull();
  });

  test('Should decode token without verification', () => {
    const payload = { sub: 'user-123', username: 'testuser' };
    const token = generateToken(payload);

    const decoded = decodeToken(token);

    expect(decoded).toBeDefined();
    expect(decoded.sub).toBe('user-123');
  });

  test('Should expire after specified duration', async () => {
    const payload = { sub: 'user-123' };
    const token = generateToken(payload, '1ms'); // Expire immédiatement

    // Attendre 10ms
    await new Promise(resolve => setTimeout(resolve, 10));

    const decoded = verifyToken(token);
    expect(decoded).toBeNull(); // Token expiré
  });

});
```

### 3. `/tests/validation.test.js`

```javascript
const {
  validateUsername,
  validateEmail,
  validatePassword,
  escapeHtml,
  normalizeUsername,
  normalizeEmail
} = require('../utils/validation');

describe('Validation Utils', () => {

  describe('validateUsername', () => {
    test('Should accept valid usernames', () => {
      expect(validateUsername('alice')).toBe(true);
      expect(validateUsername('bob123')).toBe(true);
      expect(validateUsername('user_name')).toBe(true);
      expect(validateUsername('user-name')).toBe(true);
      expect(validateUsername('a1b2c3')).toBe(true);
    });

    test('Should reject invalid usernames', () => {
      expect(validateUsername('ab')).toBe(false); // too short
      expect(validateUsername('a'.repeat(21))).toBe(false); // too long
      expect(validateUsername('User')).toBe(false); // uppercase
      expect(validateUsername('user@name')).toBe(false); // special char
      expect(validateUsername('user name')).toBe(false); // space
      expect(validateUsername('')).toBe(false); // empty
      expect(validateUsername(null)).toBe(false); // null
    });
  });

  describe('validateEmail', () => {
    test('Should accept valid emails', () => {
      expect(validateEmail('test@example.com')).toBe(true);
      expect(validateEmail('user+tag@domain.co.uk')).toBe(true);
      expect(validateEmail('a@b.c')).toBe(true);
    });

    test('Should reject invalid emails', () => {
      expect(validateEmail('notanemail')).toBe(false);
      expect(validateEmail('@example.com')).toBe(false);
      expect(validateEmail('user@')).toBe(false);
      expect(validateEmail('user@domain')).toBe(false);
      expect(validateEmail('')).toBe(false);
      expect(validateEmail(null)).toBe(false);
    });
  });

  describe('validatePassword', () => {
    test('Should accept strong passwords', () => {
      expect(validatePassword('Password1')).toBe(true);
      expect(validatePassword('MyPass123')).toBe(true);
      expect(validatePassword('Abcdefg1')).toBe(true);
    });

    test('Should reject weak passwords', () => {
      expect(validatePassword('pass')).toBe(false); // too short
      expect(validatePassword('password')).toBe(false); // no uppercase
      expect(validatePassword('PASSWORD')).toBe(false); // no digit
      expect(validatePassword('Pass')).toBe(false); // too short
      expect(validatePassword('')).toBe(false); // empty
      expect(validatePassword(null)).toBe(false); // null
    });
  });

  describe('escapeHtml', () => {
    test('Should escape HTML characters', () => {
      expect(escapeHtml('<script>alert("XSS")</script>'))
        .toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');

      expect(escapeHtml("It's mine & yours"))
        .toBe('It&#x27;s mine &amp; yours');
    });

    test('Should handle empty/null input', () => {
      expect(escapeHtml('')).toBe('');
      expect(escapeHtml(null)).toBe('');
    });
  });

  describe('normalizeUsername', () => {
    test('Should normalize usernames', () => {
      expect(normalizeUsername('Alice')).toBe('alice');
      expect(normalizeUsername('  bob  ')).toBe('bob');
      expect(normalizeUsername('USER')).toBe('user');
    });
  });

  describe('normalizeEmail', () => {
    test('Should normalize emails', () => {
      expect(normalizeEmail('Test@Example.COM')).toBe('test@example.com');
      expect(normalizeEmail('  user@domain.com  ')).toBe('user@domain.com');
    });
  });

});
```

---

## Configuration pour Vercel

### Structure des fichiers API

```
/api/
  auth/
    register.js       # export default async function handler(req, res)
    login.js
    verify.js
```

### Format Vercel Serverless Function

```javascript
// api/auth/register.js
const { supabaseAdmin } = require('../../utils/supabase');
const { generateToken } = require('../../utils/jwt');
const { validateUsername, validateEmail, validatePassword } = require('../../utils/validation');
const bcrypt = require('bcrypt');

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ... reste de la logique
}
```

---

## Variables d'environnement

Ajouter dans `.env` :

```bash
# JWT Secret (générer avec crypto.randomBytes(32).toString('hex'))
JWT_SECRET=votre-secret-jwt-ultra-securise-192837465abcdef

# Durée de validité des tokens (optionnel, défaut: 7d)
JWT_EXPIRATION=7d

# Supabase (déjà configuré à l'étape 1)
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGc...
SUPABASE_SERVICE_KEY=eyJhbGc...
```

### Générer JWT_SECRET

```bash
# Via Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Via OpenSSL
openssl rand -hex 32
```

---

## Checklist de validation

### Développement
- [ ] `/api/auth/register.js` implémenté
- [ ] `/api/auth/login.js` implémenté
- [ ] `/api/auth/verify.js` implémenté
- [ ] `/utils/jwt.js` créé avec generateToken/verifyToken
- [ ] `/utils/validation.js` créé avec toutes les fonctions
- [ ] `/middleware/auth.js` créé avec verifyJWT
- [ ] `/middleware/rateLimit.js` créé avec authLimiter

### Tests
- [ ] 15+ tests d'authentification passent
- [ ] Tests JWT passent (génération, vérification, expiration)
- [ ] Tests de validation passent (username, email, password)
- [ ] Rate limiting testé (5 tentatives max)
- [ ] Honeypot testé (rejette les bots)

### Sécurité
- [ ] JWT_SECRET généré et stocké dans `.env`
- [ ] Passwords hashés avec bcrypt (10 rounds)
- [ ] Rate limiting activé (5 tentatives / 15 min)
- [ ] Honeypot field implémenté
- [ ] Timing attack prevention (délai constant)
- [ ] Messages d'erreur génériques (pas de leak d'info)
- [ ] Username/email normalisés (lowercase)

### API
- [ ] POST `/api/auth/register` retourne 201 + token + admin
- [ ] POST `/api/auth/login` retourne 200 + token + admin
- [ ] GET `/api/auth/verify` retourne 200 + admin
- [ ] Erreurs retournent les bons codes (400, 401, 409, 429, 500)
- [ ] CORS headers configurés

---

## Utilisation

### Inscription (Frontend)

```javascript
async function register(username, email, password) {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password,
      website: '' // Honeypot
    })
  });

  const data = await res.json();

  if (res.ok) {
    // Stocker le token
    localStorage.setItem('faf_token', data.token);
    localStorage.setItem('faf_username', data.admin.username);

    // Redirection
    window.location.href = '/onboarding.html';
  } else {
    alert(data.error);
  }
}
```

### Connexion (Frontend)

```javascript
async function login(username, password) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();

  if (res.ok) {
    localStorage.setItem('faf_token', data.token);
    localStorage.setItem('faf_username', data.admin.username);
    window.location.href = '/admin/dashboard.html';
  } else {
    alert(data.error);
  }
}
```

### Vérification (Frontend)

```javascript
async function checkAuth() {
  const token = localStorage.getItem('faf_token');

  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  const res = await fetch('/api/auth/verify', {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!res.ok) {
    localStorage.removeItem('faf_token');
    localStorage.removeItem('faf_username');
    window.location.href = '/login.html';
  }
}

// Appeler au chargement des pages admin
checkAuth();
```

### Requêtes authentifiées (Frontend)

```javascript
async function loadDashboard() {
  const token = localStorage.getItem('faf_token');

  const res = await fetch('/api/admin/dashboard', {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  });

  const data = await res.json();
  // Afficher les données...
}
```

---

## Troubleshooting

### Erreur : "JWT_SECRET is not defined"

**Solution** : Ajouter `JWT_SECRET` dans `.env` et redémarrer le serveur

```bash
echo "JWT_SECRET=$(openssl rand -hex 32)" >> .env
```

### Erreur : "Token invalide" immédiatement après login

**Cause** : Horloge système désynchronisée ou JWT_SECRET différent entre register et verify

**Solution** : Vérifier que JWT_SECRET est le même partout, synchroniser l'heure système

### Rate limiting bloque en développement

**Solution** : Désactiver temporairement en dev ou augmenter la limite

```javascript
// middleware/rateLimit.js
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'development' ? 1000 : 5 // Plus permissif en dev
});
```

### Tests échouent : "Admin introuvable" après register

**Cause** : Délai entre insertion et lecture (problème de cohérence Supabase)

**Solution** : Ajouter un court délai ou utiliser `.single()` avec retry

---

## Prochaines étapes

✅ **Étape 1 complétée** : Setup Supabase & Base de données
✅ **Étape 2 complétée** : API d'authentification (Register + Login)

➡️ **Étape 3** : API Formulaire dynamique (`/api/form/[username]`)

Fichiers à créer :
- `/api/form/[username].js`
- `/utils/questions.js`
- `/tests/form.test.js`

Voir `PROMPT_DEVELOPMENT.md` pour les instructions détaillées.

---

## Ressources

- [JWT.io](https://jwt.io/) - Debugger JWT tokens
- [bcrypt](https://github.com/kelektiv/node.bcrypt.js) - Password hashing
- [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit) - Rate limiting
- [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
