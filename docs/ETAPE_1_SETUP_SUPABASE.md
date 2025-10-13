# Étape 1 : Setup Supabase & Base de données

## Vue d'ensemble

Cette étape configure l'infrastructure de base de données Supabase avec :
- Tables `admins` et `responses` avec contraintes et indexes
- Row Level Security (RLS) pour isolation complète des données
- Client Node.js pour connexion API
- Tests de validation

## Livrables

✅ `/sql/01_create_tables.sql` - Script de création des tables
✅ `/sql/02_create_rls.sql` - Script Row Level Security
✅ `/sql/03_fix_rls_policy.sql` - Script de correction de la policy RLS
✅ `/utils/supabase.js` - Client Supabase configuré
✅ `/tests/supabase-connection.test.js` - Tests de connexion (13 tests)
✅ `/tests/setup.js` - Configuration Jest pour chargement des variables d'environnement
✅ `/.env.multitenant.example` - Template de configuration
✅ `/.env` - Configuration locale (créée)
✅ `/package.json` - Scripts npm configurés
✅ `/docs/ETAPE_1_SETUP_SUPABASE.md` - Cette documentation

---

## Instructions d'installation

### 1. Créer un projet Supabase

1. Aller sur [https://supabase.com/dashboard](https://supabase.com/dashboard)
2. Cliquer sur "New Project"
3. Remplir les informations :
   - **Name**: FAF-MultiTenant (ou nom de votre choix)
   - **Database Password**: Générer un mot de passe fort (le sauvegarder !)
   - **Region**: Choisir la région la plus proche (ex: West EU (Ireland))
   - **Pricing Plan**: Free tier (suffisant pour démarrer)
4. Cliquer sur "Create new project"
5. Attendre 2-3 minutes que le projet soit provisionné

### 2. Récupérer les clés API

Une fois le projet créé :

1. Aller dans **Settings** (icône engrenage dans la sidebar)
2. Aller dans **API**
3. Copier les valeurs suivantes :

**URL du projet** :
```
https://xxxxxxxxxxxxx.supabase.co
```

**anon (public) key** :
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**service_role key** (⚠️ secret, ne jamais exposer côté client) :
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 3. Configurer les variables d'environnement

1. Copier le fichier d'exemple :
```bash
cp .env.multitenant.example .env
```

2. Éditer `.env` et remplir les valeurs Supabase :
```bash
# Supabase
SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGc...
SUPABASE_SERVICE_KEY=eyJhbGc...

# JWT (générer un secret fort)
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")

# Cloudinary (réutiliser configuration existante)
CLOUDINARY_CLOUD_NAME=votre-cloud-name
CLOUDINARY_API_KEY=123456789
CLOUDINARY_API_SECRET=abc...

# Application
APP_BASE_URL=http://localhost:3000
NODE_ENV=development
```

### 4. Installer les dépendances

```bash
npm install @supabase/supabase-js
```

### 5. Exécuter les scripts SQL

#### Option A : Via l'interface Supabase (recommandé)

1. Aller dans **SQL Editor** (icône dans la sidebar)
2. Cliquer sur **New query**
3. Copier-coller le contenu de `sql/01_create_tables.sql`
4. Cliquer sur **Run** (ou Ctrl+Enter)
5. Vérifier que le script s'exécute sans erreur
6. Répéter avec `sql/02_create_rls.sql`

#### Option B : Via psql (ligne de commande)

```bash
# Récupérer l'URI de connexion dans Settings > Database > Connection string
psql "postgresql://postgres:[PASSWORD]@db.xxxxx.supabase.co:5432/postgres"

# Exécuter les scripts
\i sql/01_create_tables.sql
\i sql/02_create_rls.sql
```

### 6. Vérifier l'installation

#### Vérifier les tables créées

Dans SQL Editor, exécuter :
```sql
SELECT table_name, table_type
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('admins', 'responses');
```

Résultat attendu :
```
table_name | table_type
-----------+-----------
admins     | BASE TABLE
responses  | BASE TABLE
```

#### Vérifier RLS activé

```sql
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN ('admins', 'responses');
```

Résultat attendu :
```
tablename  | rowsecurity
-----------+------------
admins     | t
responses  | t
```

#### Vérifier les policies

```sql
SELECT tablename, policyname
FROM pg_policies
WHERE tablename IN ('admins', 'responses')
ORDER BY tablename, policyname;
```

Résultat attendu (9 policies, mais `select_by_token_public` sera supprimée) :
```
tablename  | policyname
-----------+----------------------------
admins     | delete_own_admin
admins     | insert_new_admin
admins     | select_own_admin
admins     | update_own_admin
responses  | delete_own_responses
responses  | insert_own_responses
responses  | insert_public_responses
responses  | select_own_responses
responses  | update_own_responses
```

**Note importante** : Si vous voyez `select_by_token_public` dans la liste, supprimez-la car elle est trop permissive :
```sql
DROP POLICY IF EXISTS "select_by_token_public" ON responses;
```

### 7. Corriger la policy RLS (important)

La policy `select_by_token_public` créée par le script est trop permissive. Elle doit être supprimée.

**Option A : Via script SQL (recommandé)**

Exécuter le script `sql/03_fix_rls_policy.sql` dans SQL Editor :
1. Copier-coller le contenu de `sql/03_fix_rls_policy.sql`
2. Cliquer sur **Run**
3. Vérifier que la policy a été supprimée

**Option B : Commande manuelle**

```sql
-- Exécuter dans SQL Editor
DROP POLICY IF EXISTS "select_by_token_public" ON responses;
```

**Explication** : Cette policy permettait à tous les utilisateurs anonymes de voir toutes les réponses ayant un token. L'accès public via token se fera via `service_role` côté backend API.

### 8. Exécuter les tests

```bash
# Installer les dépendances
npm install @supabase/supabase-js dotenv
npm install --save-dev jest bcrypt

# Lancer les tests
npm test -- tests/supabase-connection.test.js
```

Résultat attendu :
```
PASS  tests/supabase-connection.test.js
  Supabase Connection Tests
    ✓ Should connect to Supabase (123ms)
    ✓ Should have access to admins table (45ms)
    ✓ Should have access to responses table (38ms)
    ✓ RLS should be enabled on responses (52ms)
    ✓ Service role should bypass RLS (67ms)
    ✓ Admin 1 should only see their own responses (89ms)
    ✓ Admin 1 should NOT see Admin 2 responses (102ms)
    ✓ Should enforce unique username constraint (56ms)
    ✓ Should enforce username format constraint (48ms)
    ✓ Should enforce responses array format (61ms)
    ✓ Should enforce token length constraint (55ms)
    ✓ Should use indexes for owner_id queries (34ms)
    ✓ Should use indexes for token queries (41ms)

Test Suites: 1 passed, 1 total
Tests:       13 passed, 13 total
```

---

## Architecture de la base de données

### Table `admins`

**Colonnes** :
- `id` (UUID) : Identifiant unique
- `username` (TEXT) : Nom d'utilisateur unique (3-20 caractères, lowercase)
- `email` (TEXT) : Email unique
- `password_hash` (TEXT) : Hash bcrypt du mot de passe
- `created_at` (TIMESTAMPTZ) : Date de création
- `updated_at` (TIMESTAMPTZ) : Date de modification

**Contraintes** :
- Username : regex `^[a-z0-9_-]{3,20}$`
- Email : format valide
- Password hash : min 50 caractères

**Indexes** :
- `idx_admins_username` sur `username`
- `idx_admins_email` sur `email`

### Table `responses`

**Colonnes** :
- `id` (UUID) : Identifiant unique
- `owner_id` (UUID) : Référence vers `admins.id` (CASCADE DELETE)
- `name` (TEXT) : Nom du répondant (2-100 caractères)
- `responses` (JSONB) : Array de `{question, answer}`
- `month` (TEXT) : Format YYYY-MM
- `is_owner` (BOOLEAN) : true si admin, false si ami
- `token` (TEXT) : Token unique de 64 caractères (null si admin)
- `created_at` (TIMESTAMPTZ) : Date de création

**Contraintes** :
- `owner_id` doit exister dans `admins`
- Un admin = 1 seule réponse par mois (contrainte unique)
- Responses : array de 10-11 éléments
- Token : null ou 64 caractères

**Indexes** :
- `idx_responses_owner` sur `owner_id`
- `idx_responses_token` sur `token` (WHERE token IS NOT NULL)
- `idx_responses_month` sur `month`
- `idx_responses_owner_month` sur `(owner_id, month)`
- `idx_responses_created` sur `created_at DESC`
- `idx_owner_month_unique` unique sur `(owner_id, month)` WHERE is_owner = true

---

## Row Level Security (RLS)

### Principe

RLS filtre automatiquement les données en fonction du contexte d'authentification :
- `auth.uid()` : UUID de l'admin connecté (via JWT)
- `auth.role()` : Rôle ('anon', 'authenticated', 'service_role')

### Policies sur `admins`

| Policy | Action | Condition |
|--------|--------|-----------|
| `select_own_admin` | SELECT | `id = auth.uid()` ou service_role |
| `insert_new_admin` | INSERT | `auth.role() = 'anon'` (inscription publique) |
| `update_own_admin` | UPDATE | `id = auth.uid()` |
| `delete_own_admin` | DELETE | `id = auth.uid()` |

### Policies sur `responses`

| Policy | Action | Condition |
|--------|--------|-----------|
| `select_own_responses` | SELECT | `owner_id = auth.uid()` ou service_role |
| `insert_own_responses` | INSERT | `owner_id = auth.uid()` ou service_role |
| `insert_public_responses` | INSERT | `auth.role() = 'anon'` (soumissions publiques) |
| `update_own_responses` | UPDATE | `owner_id = auth.uid()` |
| `delete_own_responses` | DELETE | `owner_id = auth.uid()` |

**Note** : La policy `select_by_token_public` a été supprimée car trop permissive. L'accès public via token utilisera `service_role` côté backend.

### Exemples d'isolation

**Scénario 1 : Admin consulte son dashboard**
```javascript
// JWT contient: { sub: 'uuid-admin-1' }
const { data } = await supabase
  .from('responses')
  .select('*');

// RLS filtre automatiquement: WHERE owner_id = 'uuid-admin-1'
// Résultat: uniquement les réponses de admin-1
```

**Scénario 2 : Utilisateur consulte un lien privé**
```javascript
// Utiliser service_role pour bypass RLS de manière sécurisée
const { data } = await supabaseAdmin
  .from('responses')
  .select('*')
  .eq('token', 'abc123...');

// Service role bypass RLS
// Résultat: réponse correspondant au token
```

**Scénario 3 : Migration (service_role)**
```javascript
// Clé service_role bypass RLS
const { data } = await supabaseAdmin
  .from('responses')
  .select('*');

// RLS bypass
// Résultat: TOUTES les réponses de tous les admins
```

---

## Utilisation du client Supabase

### Client anonyme (public)

```javascript
const { supabaseClient } = require('./utils/supabase');

// Soumission publique de formulaire
const { data, error } = await supabaseClient
  .from('responses')
  .insert({
    owner_id: adminId,
    name: 'Emma',
    responses: [...],
    month: '2025-01',
    is_owner: false,
    token: generatedToken
  });
```

### Client admin (service_role)

```javascript
const { supabaseAdmin } = require('./utils/supabase');

// Migration de données (bypass RLS)
const { data, error } = await supabaseAdmin
  .from('responses')
  .select('*');
```

### Client authentifié (JWT)

```javascript
const { createAuthenticatedClient } = require('./utils/supabase');

// Dashboard admin (avec JWT)
const adminClient = createAuthenticatedClient(req.headers.authorization);

const { data, error } = await adminClient
  .from('responses')
  .select('*');
// RLS filtre automatiquement par owner_id
```

---

## Tests de validation

### Checklist de validation

- [x] Tables créées dans Supabase
- [x] RLS activé sur `admins` et `responses`
- [x] 9 policies créées (4 sur admins, 5+ sur responses)
- [x] Contraintes validées (username format, email, token length)
- [x] Indexes créés pour performance
- [x] Connexion Node.js fonctionnelle
- [x] Tests d'isolation passent (admin A ≠ admin B)
- [x] Service role bypass RLS
- [x] Client anonyme filtré par RLS

### Commandes de test

```bash
# Test connexion
npm test -- tests/supabase-connection.test.js

# Test isolation (manuel)
node -e "require('./utils/supabase').testConnection().then(console.log)"

# Vérifier RLS dans Supabase
# SQL Editor:
SELECT * FROM test_rls_isolation('uuid-quelconque');
```

---

## Troubleshooting

### Erreur : "SUPABASE_URL is not defined"

**Solution** : Vérifier que le fichier `.env` existe et contient `SUPABASE_URL`

```bash
cat .env | grep SUPABASE_URL
```

### Erreur : "relation 'admins' does not exist"

**Solution** : Exécuter le script `sql/01_create_tables.sql` dans SQL Editor

### Erreur : "new row violates row-level security policy"

**Cause** : RLS bloque l'insertion car le contexte auth n'est pas correct

**Solution** : Utiliser `supabaseAdmin` (service_role) pour les opérations sans JWT

### Tests échouent : "Test data not available"

**Cause** : `SUPABASE_SERVICE_KEY` n'est pas définie dans `.env`

**Solution** : Ajouter la clé service_role dans `.env`

### Test "RLS should be enabled" échoue

**Cause** : La policy `select_by_token_public` est trop permissive

**Solution** : Supprimer la policy dans SQL Editor
```sql
DROP POLICY IF EXISTS "select_by_token_public" ON responses;
```

Puis relancer les tests :
```bash
npm test -- tests/supabase-connection.test.js
```

### Performance lente sur les requêtes

**Cause** : Indexes manquants

**Vérification** :
```sql
SELECT tablename, indexname
FROM pg_indexes
WHERE tablename IN ('admins', 'responses');
```

**Solution** : Réexécuter `sql/01_create_tables.sql`

---

## Prochaines étapes

✅ **Étape 1 complétée** : Setup Supabase & Base de données

➡️ **Étape 2** : API d'authentification (Register + Login)

Fichiers à créer :
- `/api/auth/register.js`
- `/api/auth/login.js`
- `/api/auth/verify.js`
- `/utils/jwt.js`
- `/middleware/auth.js`

Voir `PROMPT_DEVELOPMENT.md` pour les instructions détaillées.

---

## Ressources

- [Documentation Supabase](https://supabase.com/docs)
- [Row Level Security](https://supabase.com/docs/guides/auth/row-level-security)
- [JavaScript Client](https://supabase.com/docs/reference/javascript)
- [Policies Examples](https://supabase.com/docs/guides/auth/row-level-security#policies)
