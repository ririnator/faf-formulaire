# Guide de test manuel - API d'authentification

## ✅ Tests validés automatiquement

Les 48 tests automatiques passent avec succès :
```bash
npm test -- tests/jwt.test.js tests/validation.test.js tests/auth.test.js
```

**Résultat** : 48 tests ✅ (13 JWT + 17 validation + 18 auth)

## 🧪 Tests manuels (optionnels)

Si vous souhaitez tester manuellement les API routes, voici les options :

### Option 1 : Via les tests Jest (recommandé)

Les tests Jest testent déjà toutes les fonctionnalités de manière isolée :

```bash
# Tester JWT
npm test -- tests/jwt.test.js

# Tester validation
npm test -- tests/validation.test.js

# Tester authentification complète
npm test -- tests/auth.test.js --verbose
```

### Option 2 : Tester les fonctions directement dans Node REPL

```bash
node
```

Puis dans le REPL Node :

```javascript
// Charger les modules
require('dotenv').config();
const { generateToken, verifyToken } = require('./utils/jwt');
const { validateUsername, validateEmail, validatePassword } = require('./utils/validation');

// 1. Tester JWT
const token = generateToken({ sub: 'test-123', username: 'alice' });
console.log('Token généré:', token);

const decoded = verifyToken(token);
console.log('Token décodé:', decoded);

// 2. Tester validation
console.log('Username valide:', validateUsername('alice')); // true
console.log('Username invalide:', validateUsername('Alice')); // false (uppercase)
console.log('Email valide:', validateEmail('test@example.com')); // true
console.log('Password fort:', validatePassword('Password123!')); // true
console.log('Password faible:', validatePassword('password')); // false
```

### Option 3 : Tester l'inscription directement

```bash
node
```

```javascript
require('dotenv').config();
const registerHandler = require('./api/auth/register');

// Mock request/response
const req = {
  method: 'POST',
  body: {
    username: 'alice',
    email: 'alice@test.com',
    password: 'Password123!',
    website: ''
  }
};

const res = {
  statusCode: null,
  body: null,
  status(code) { this.statusCode = code; return this; },
  json(data) { this.body = data; return this; },
  setHeader() { return this; },
  end() { return this; }
};

// Exécuter l'inscription
registerHandler(req, res).then(() => {
  console.log('Status:', res.statusCode);
  console.log('Body:', JSON.stringify(res.body, null, 2));
});
```

### Option 4 : Vérifier Supabase directement

1. Aller sur [https://supabase.com/dashboard](https://supabase.com/dashboard)
2. Ouvrir votre projet FAF-MultiTenant
3. Aller dans **Table Editor** > **admins**
4. Vérifier que la table est vide (ou contient vos tests)
5. Exécuter un test d'inscription via Jest
6. Actualiser la table et voir le nouvel admin apparaître

```bash
# Exécuter un test qui crée un admin
npm test -- tests/auth.test.js -t "Should register a new admin successfully"
```

7. Vérifier dans Supabase que l'admin "testuser" apparaît avec :
   - Un UUID dans `id`
   - Username "testuser"
   - Email "test@example.com"
   - Password hashé dans `password_hash`

## 🔍 Vérifications clés

### 1. JWT_SECRET configuré
```bash
grep JWT_SECRET .env
```
✅ Doit afficher une clé de 64 caractères

### 2. Supabase connecté
```bash
node -e "require('dotenv').config(); const { supabaseAdmin } = require('./utils/supabase'); supabaseAdmin.from('admins').select('count').then(({data, error}) => console.log('Connexion:', error ? 'ERREUR' : 'OK', data));"
```

### 3. Tests unitaires passent
```bash
npm test -- tests/jwt.test.js tests/validation.test.js
```
✅ 30 tests doivent passer (13 JWT + 17 validation)

### 4. Tests d'authentification passent
```bash
npm test -- tests/auth.test.js
```
✅ 18 tests doivent passer

### 5. Vérifier un admin dans Supabase

Après avoir exécuté les tests, vérifier manuellement dans Supabase :

```sql
-- Dans SQL Editor de Supabase
SELECT id, username, email, created_at
FROM admins
ORDER BY created_at DESC
LIMIT 5;
```

Vous devriez voir les admins de test créés.

### 6. Nettoyer les données de test (optionnel)

```sql
-- Dans SQL Editor de Supabase
DELETE FROM admins WHERE username LIKE 'testuser%';
```

Ou via Node :

```bash
node -e "require('dotenv').config(); const { supabaseAdmin } = require('./utils/supabase'); supabaseAdmin.from('admins').delete().ilike('username', 'testuser%').then(({error}) => console.log(error ? 'Erreur' : 'Nettoyé'));"
```

## 📊 Résumé des fonctionnalités testées

### ✅ JWT (utils/jwt.js)
- [x] Génération de tokens avec payload
- [x] Vérification de tokens valides
- [x] Rejet de tokens invalides
- [x] Expiration après durée configurée
- [x] Gestion des erreurs

### ✅ Validation (utils/validation.js)
- [x] Username: 3-20 chars, lowercase, alphanumériques
- [x] Email: format valide sans espaces
- [x] Password: min 8 chars, 1 majuscule, 1 chiffre
- [x] HTML escaping pour XSS
- [x] Normalisation username/email en lowercase

### ✅ Authentification (api/auth/*.js)
- [x] POST /api/auth/register - Inscription
  - Validation stricte
  - Hash bcrypt
  - Génération JWT
  - Vérification unicité
  - Honeypot anti-spam
- [x] POST /api/auth/login - Connexion
  - Recherche case-insensitive
  - Vérification bcrypt
  - Timing attack prevention
  - Messages génériques
- [x] GET /api/auth/verify - Vérification
  - Extraction token JWT
  - Validation expiration
  - Récupération admin

## 🚀 Prochaines étapes

Étape 2 validée ✅

**Prochaine étape** : Étape 3 - API Formulaire dynamique

Fichiers à créer :
- `/api/form/[username].js` - Récupération formulaire par username
- `/utils/questions.js` - Liste des 11 questions
- `/tests/form.test.js` - Tests de l'API formulaire

---

**Note** : Si vous souhaitez vraiment tester avec un serveur HTTP live, vous pouvez déployer sur Vercel (Étape 11) ou utiliser Postman/Insomnia avec des mocks.
