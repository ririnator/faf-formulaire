# Étape 10 : Architecture de Migration

## Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│                    MIGRATION MONGODB → SUPABASE                  │
└─────────────────────────────────────────────────────────────────┘

   ┌────────────┐         ┌──────────────┐         ┌────────────┐
   │  MONGODB   │  =====> │   SCRIPTS    │  =====> │  SUPABASE  │
   │  (Source)  │         │  (Migration) │         │  (Cible)   │
   └────────────┘         └──────────────┘         └────────────┘
        │                        │                        │
   Collection              1. backup-mongodb.js     Table: admins
   "responses"            2. migrate-to-supabase    Table: responses
   156 réponses           3. validate-migration          │
        │                        │                   RLS activé
        │                        │                   owner_id = riri
        ▼                        ▼                        ▼
   ┌─────────┐            ┌─────────┐             ┌─────────┐
   │ Backup  │            │  Logs   │             │ Données │
   │  JSON   │            │ Console │             │ Migrées │
   └─────────┘            └─────────┘             └─────────┘
```

---

## Flow de migration

```
┌────────────────────────────────────────────────────────────────────┐
│                         ÉTAPE 1 : BACKUP                           │
└────────────────────────────────────────────────────────────────────┘

   [MongoDB]
      │
      ├─ Connexion (MONGODB_URI)
      │
      ├─ db.collection('responses').find({})
      │
      ├─ Validation des données
      │  ├─ Champs requis (name, responses, month)
      │  ├─ Format JSONB responses
      │  └─ Statistiques (admin/users, tokens, mois)
      │
      └─ Sauvegarde JSON
         └─ backups/mongodb-backup-{timestamp}.json
            {
              metadata: { ... },
              responses: [ ... ]
            }

┌────────────────────────────────────────────────────────────────────┐
│                       ÉTAPE 2 : MIGRATION                          │
└────────────────────────────────────────────────────────────────────┘

   [Backup JSON]
      │
      ├─ Chargement backup le plus récent
      │
      ├─ Connexion Supabase (service_role)
      │
      ├─ Création Admin "riri"
      │  ├─ Hash bcrypt (10 rounds)
      │  └─ INSERT INTO admins (username, email, password_hash)
      │     → Retourne: riri.id (UUID)
      │
      ├─ Migration par batch (50 réponses)
      │  │
      │  └─ Pour chaque réponse MongoDB:
      │     ├─ Transformation
      │     │  {
      │     │    owner_id: riri.id,        ← NOUVEAU
      │     │    name: mongo.name,
      │     │    responses: mongo.responses, (JSONB)
      │     │    month: mongo.month,
      │     │    is_owner: mongo.isAdmin,  ← RENOMMÉ
      │     │    token: mongo.token,       ← CONSERVÉ
      │     │    created_at: mongo.createdAt
      │     │  }
      │     │
      │     ├─ INSERT INTO responses (...)
      │     │
      │     └─ Gestion erreurs
      │        ├─ Duplicate key → Ignoré
      │        └─ Autres → Log + Continue
      │
      └─ Validation comptage
         ├─ MongoDB count: X
         └─ Supabase count: Y
            └─ X === Y ? ✅ : ⚠️

┌────────────────────────────────────────────────────────────────────┐
│                      ÉTAPE 3 : VALIDATION                          │
└────────────────────────────────────────────────────────────────────┘

   [Supabase]
      │
      ├─ Validation Admin
      │  └─ SELECT * FROM admins WHERE username = 'riri'
      │     → Vérifie existence et ID
      │
      ├─ Validation Nombre
      │  └─ SELECT COUNT(*) FROM responses WHERE owner_id = riri.id
      │     → Compare avec backup MongoDB
      │
      ├─ Validation Tokens (échantillon 10)
      │  └─ SELECT * FROM responses WHERE token = '{token}'
      │     ├─ Token existe ?
      │     ├─ name correspond ?
      │     └─ month correspond ?
      │
      ├─ Validation Structure (échantillon 10)
      │  └─ SELECT responses FROM responses LIMIT 10
      │     ├─ Format JSONB valide ?
      │     ├─ Champs {question, answer} présents ?
      │     └─ Cohérence is_owner + token ?
      │
      └─ Rapport Final
         ├─ ✅ Succès : Tout validé
         └─ ⚠️  Avertissements : Détails des problèmes
```

---

## Transformation des données

### MongoDB (Source)

```javascript
{
  "_id": ObjectId("507f1f77bcf86cd799439011"),
  "name": "Alice",
  "responses": [
    {
      "question": "En rapide, comment ça va ?",
      "answer": "ça va"
    },
    {
      "question": "Photo de toi ce mois-ci",
      "answer": "https://res.cloudinary.com/xxx/image.jpg"
    }
  ],
  "month": "2025-10",
  "isAdmin": false,
  "token": "abc123def456...",
  "createdAt": ISODate("2025-10-14T10:30:00.000Z")
}
```

### Supabase (Cible)

```javascript
{
  "id": "12345678-1234-1234-1234-123456789abc",  // Nouveau UUID
  "owner_id": "riri-uuid",                       // Ajouté
  "name": "Alice",
  "responses": [                                 // JSONB
    {
      "question": "En rapide, comment ça va ?",
      "answer": "ça va"
    },
    {
      "question": "Photo de toi ce mois-ci",
      "answer": "https://res.cloudinary.com/xxx/image.jpg"
    }
  ],
  "month": "2025-10",
  "is_owner": false,                             // Renommé
  "token": "abc123def456...",                    // Conservé
  "created_at": "2025-10-14T10:30:00.000Z"       // Renommé
}
```

### Mapping des champs

| MongoDB | Supabase | Type | Transformation |
|---------|----------|------|----------------|
| `_id` | `id` | ObjectId → UUID | Nouveau UUID généré |
| N/A | `owner_id` | N/A → UUID | `riri.id` (créé) |
| `name` | `name` | String → Text | Conservation |
| `responses` | `responses` | Array → JSONB | Conservation |
| `month` | `month` | String → Text | Conservation |
| `isAdmin` | `is_owner` | Boolean → Boolean | Renommage |
| `token` | `token` | String → Text | Conservation |
| `createdAt` | `created_at` | Date → Timestamptz | ISO 8601 |

---

## Architecture Supabase

### Table `admins`

```sql
CREATE TABLE admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Migration crée:
INSERT INTO admins (username, email, password_hash)
VALUES ('riri', 'riri@example.com', '$2b$10$...');
```

### Table `responses`

```sql
CREATE TABLE responses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  responses JSONB NOT NULL,
  month TEXT NOT NULL,
  is_owner BOOLEAN DEFAULT false,
  token TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes pour performance
CREATE INDEX idx_responses_owner ON responses(owner_id);
CREATE INDEX idx_responses_token ON responses(token) WHERE token IS NOT NULL;
CREATE INDEX idx_responses_month ON responses(month);
CREATE INDEX idx_responses_owner_month ON responses(owner_id, month);

-- Contrainte unique: un admin ne peut avoir qu'une réponse par mois
CREATE UNIQUE INDEX idx_owner_month_unique
ON responses(owner_id, month)
WHERE is_owner = true;
```

### Row Level Security (RLS)

```sql
-- Activer RLS
ALTER TABLE responses ENABLE ROW LEVEL SECURITY;

-- Policy: Les admins voient uniquement leurs réponses
CREATE POLICY "select_own_responses"
ON responses FOR SELECT
USING (
  owner_id = auth.uid() OR
  auth.role() = 'service_role'
);

-- Policy: Consultation publique via token
CREATE POLICY "select_by_token"
ON responses FOR SELECT
USING (
  token IS NOT NULL AND
  EXISTS (
    SELECT 1 FROM responses r2
    WHERE r2.token = responses.token
  )
);
```

---

## Variables d'environnement

### Fichier `.env`

```bash
# MongoDB (Source)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database

# Supabase (Cible)
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
# ⚠️ Utiliser SERVICE_KEY (pas ANON_KEY) pour bypass RLS

# Admin Riri (Compte à créer)
RIRI_EMAIL=riri@example.com
RIRI_PASSWORD=Password123!
# ⚠️ Mot de passe doit respecter la politique de sécurité
```

### Sécurité des variables

| Variable | Sensibilité | Usage | Exposition |
|----------|-------------|-------|------------|
| `MONGODB_URI` | 🔴 Haute | Migration uniquement | Serveur uniquement |
| `SUPABASE_URL` | 🟢 Publique | Frontend + Backend | Peut être exposée |
| `SUPABASE_SERVICE_KEY` | 🔴 Haute | Backend uniquement | **JAMAIS** exposée |
| `SUPABASE_ANON_KEY` | 🟡 Moyenne | Frontend | Peut être exposée |
| `RIRI_EMAIL` | 🟡 Moyenne | Migration uniquement | Serveur uniquement |
| `RIRI_PASSWORD` | 🔴 Haute | Migration uniquement | Serveur uniquement |

---

## Fichiers générés

### Backup JSON

**Chemin** : `/backups/mongodb-backup-{timestamp}.json`

**Structure** :
```json
{
  "metadata": {
    "date": "2025-10-14T12:00:00.000Z",
    "mongodbUri": "mongodb+srv://***:***@cluster/db",
    "totalResponses": 156,
    "adminResponses": 12,
    "userResponses": 144,
    "withToken": 144,
    "months": ["2025-10", "2025-09", "2025-08", ...],
    "validCount": 156,
    "issues": 0
  },
  "responses": [
    {
      "_id": "507f1f77bcf86cd799439011",
      "name": "Alice",
      "responses": [...],
      "month": "2025-10",
      "isAdmin": false,
      "token": "abc123...",
      "createdAt": "2025-10-14T10:30:00.000Z"
    },
    ...
  ]
}
```

**Utilisation** :
- ✅ Sauvegarde de sécurité
- ✅ Source pour la migration
- ✅ Validation post-migration
- ✅ Rollback si nécessaire

---

## Scripts

### 1. `backup-mongodb.js`

```javascript
const { MongoClient } = require('mongodb');

async function backupMongoDB() {
  // 1. Connexion
  const client = await MongoClient.connect(MONGODB_URI);

  // 2. Récupération
  const responses = await db.collection('responses').find({}).toArray();

  // 3. Validation
  validateResponses(responses);

  // 4. Sauvegarde
  fs.writeFileSync(backupFile, JSON.stringify(data));

  return { success: true, file: backupFile, count: responses.length };
}
```

### 2. `migrate-to-supabase.js`

```javascript
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');

async function migrate() {
  // 1. Backup
  const backup = await backupMongoDB();

  // 2. Connexion Supabase
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  // 3. Créer admin
  const ririId = await createRiriAdmin(supabase);

  // 4. Migrer par batch
  await migrateResponses(supabase, mongoResponses, ririId);

  // 5. Validation
  await validateMigration(supabase, originalCount, ririId);
}
```

### 3. `validate-migration.js`

```javascript
async function validate() {
  // 1. Charger backup
  const backup = loadBackup();

  // 2. Validation admin
  const admin = await validateAdmin(supabase);

  // 3. Validation nombre
  await validateCount(supabase, backup.metadata.totalResponses, admin.id);

  // 4. Validation tokens
  await validateTokens(supabase, backup.responses);

  // 5. Validation structure
  await validateDataStructure(supabase, admin.id);

  // 6. Rapport
  generateReport();
}
```

---

## Tests de validation

### Test 1 : Backup MongoDB
```bash
node scripts/backup-mongodb.js

# Vérifier:
# ✅ Fichier créé: backups/mongodb-backup-*.json
# ✅ Statistiques affichées: X réponses, Y admin, Z users
# ✅ Validation: X/X réponses valides
```

### Test 2 : Migration complète
```bash
node scripts/migrate-to-supabase.js

# Vérifier:
# ✅ Admin créé: riri (UUID affiché)
# ✅ Migration: 156 succès, 0 erreurs
# ✅ Validation: MongoDB count === Supabase count
```

### Test 3 : Validation post-migration
```bash
node scripts/validate-migration.js

# Vérifier:
# ✅ Admin "riri" existe
# ✅ Nombre de réponses identique
# ✅ 10/10 tokens valides
# ✅ 10/10 structures valides
```

### Test 4 : Vérification Supabase Dashboard
```sql
-- Compter les réponses
SELECT COUNT(*) FROM responses;

-- Vérifier un échantillon
SELECT * FROM responses LIMIT 5;

-- Vérifier les tokens
SELECT COUNT(*) FROM responses WHERE token IS NOT NULL;
```

### Test 5 : Tests manuels application
```bash
# 1. Connexion admin
# /admin/dashboard.html
# Username: riri
# Password: [RIRI_PASSWORD]

# 2. Liens privés
# /view/{token}
# → Prendre un token du backup

# 3. Nouvelle soumission
# /form/riri
# → Vérifier génération token
```

---

## Gestion des erreurs

### Erreurs MongoDB

| Erreur | Cause | Solution |
|--------|-------|----------|
| `MongoNetworkError` | Connexion Internet | Vérifier le réseau |
| `Authentication failed` | Credentials invalides | Vérifier `MONGODB_URI` |
| `Connection timeout` | MongoDB inaccessible | Vérifier la whitelist IP |

### Erreurs Supabase

| Erreur | Cause | Solution |
|--------|-------|----------|
| `Invalid JWT` | Mauvaise clé | Utiliser `SERVICE_KEY` |
| `Foreign key violation` | Table `admins` manquante | Exécuter scripts SQL |
| `Duplicate key (23505)` | Token/contrainte unique | Normal, ignoré automatiquement |
| `Row Level Security` | RLS bloque | Utiliser `SERVICE_KEY` |

### Erreurs de validation

| Erreur | Cause | Solution |
|--------|-------|----------|
| `Différence de count` | Erreurs durant migration | Vérifier logs, relancer |
| `Token introuvable` | Migration partielle | Vérifier token dans backup |
| `Structure invalide` | Données corrompues | Vérifier backup MongoDB |

---

## Rollback

### Supprimer les données migrées

```sql
-- 1. Supprimer toutes les réponses de riri
DELETE FROM responses
WHERE owner_id = (SELECT id FROM admins WHERE username = 'riri');

-- 2. Supprimer l'admin riri
DELETE FROM admins WHERE username = 'riri';

-- 3. Vérifier
SELECT COUNT(*) FROM responses;
SELECT COUNT(*) FROM admins;
```

### Relancer la migration

```bash
# Le backup MongoDB est intact
# Les scripts gèrent les doublons
node scripts/migrate-to-supabase.js
```

---

## Checklist de migration

- [ ] ✅ Variables d'environnement configurées (`.env`)
- [ ] ✅ Dépendances npm installées
- [ ] ✅ Tables Supabase créées (admins + responses)
- [ ] ✅ RLS activé sur `responses`
- [ ] ✅ Backup MongoDB créé (JSON)
- [ ] ✅ Migration exécutée sans erreurs
- [ ] ✅ Validation réussie (script)
- [ ] ✅ Admin "riri" peut se connecter
- [ ] ✅ Liens privés testés et fonctionnels
- [ ] ✅ Nouvelle soumission fonctionne
- [ ] ✅ Backup archivé en lieu sûr

---

## Conclusion

L'architecture de migration garantit :

✅ **Aucune perte de données** - Backup + validation
✅ **Conservation des tokens** - Liens privés fonctionnels
✅ **Isolation par RLS** - owner_id = riri.id
✅ **Traçabilité** - Logs détaillés + rapport
✅ **Réversibilité** - Rollback possible
✅ **Sécurité** - Backup gitignore + hash bcrypt
