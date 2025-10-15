# Scripts de Migration MongoDB → Supabase

Ce dossier contient les scripts nécessaires pour migrer les données de MongoDB vers Supabase.

---

## Vue d'ensemble

3 scripts principaux :

1. **`backup-mongodb.js`** - Sauvegarde MongoDB → JSON
2. **`migrate-to-supabase.js`** - Migration complète vers Supabase
3. **`validate-migration.js`** - Validation post-migration

---

## Installation

```bash
# Installer les dépendances
npm install @supabase/supabase-js mongodb bcrypt dotenv

# Ou via package.json
npm install
```

---

## Configuration

### Créer le fichier `.env`

```bash
# MongoDB (Source)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database

# Supabase (Cible)
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Admin Riri
RIRI_EMAIL=riri@example.com
RIRI_PASSWORD=Password123!
```

⚠️ **Important** : Utiliser `SUPABASE_SERVICE_KEY` (pas `ANON_KEY`)

---

## Usage

### Option 1 : Scripts npm (recommandé)

```bash
# Backup MongoDB uniquement
npm run migrate:backup

# Migration complète
npm run migrate:run

# Validation post-migration
npm run migrate:validate

# Interface interactive
npm run migrate:interactive
```

### Option 2 : Node.js direct

```bash
# Backup
node scripts/backup-mongodb.js

# Migration
node scripts/migrate-to-supabase.js

# Validation
node scripts/validate-migration.js
```

### Option 3 : Script bash interactif

```bash
./scripts/test-migration.sh
```

---

## Scripts détaillés

### 1. `backup-mongodb.js`

**Fonction** : Sauvegarde MongoDB vers fichier JSON

**Sortie** :
- Fichier : `/backups/mongodb-backup-{timestamp}.json`
- Format : JSON avec métadonnées + array de réponses

**Exemple** :
```bash
$ npm run migrate:backup

🚀 Début du backup MongoDB...
📡 Connexion à MongoDB...
✅ Connexion réussie

📥 Récupération des réponses...
✅ 156 réponses récupérées

📊 Statistiques:
   - Réponses admin: 12
   - Réponses utilisateurs: 144
   - Réponses avec token: 144
   - Mois uniques: 12

💾 Backup sauvegardé: backups/mongodb-backup-1697234567890.json
   Taille: 2.34 MB

✅ Backup terminé avec succès!
```

---

### 2. `migrate-to-supabase.js`

**Fonction** : Migration complète MongoDB → Supabase

**Étapes** :
1. Backup automatique MongoDB
2. Connexion Supabase
3. Création admin "riri" (avec hash bcrypt)
4. Migration par batch (50 réponses)
5. Validation comptage

**Exemple** :
```bash
$ npm run migrate:run

🚀 Migration MongoDB → Supabase
==================================================

📋 Étape 1/4: Backup MongoDB
✅ Backup chargé: 156 réponses

📋 Étape 2/4: Connexion Supabase
✅ Client Supabase initialisé

📋 Étape 3/4: Création admin "riri"
✅ Admin créé avec succès!
   - ID: 12345678-1234-1234-1234-123456789abc
   - Username: riri
   - Email: riri@example.com

📋 Étape 4/4: Migration des réponses
   Total à migrer: 156
   Batches: 4 (50 réponses/batch)

📤 Batch 1/4 (50 réponses)...
   ✅ Batch terminé (25.0%)

[...]

==================================================
📊 RAPPORT DE MIGRATION
==================================================

✅ Succès: 156
❌ Erreurs: 0
⚠️  Ignorés: 0
📦 Total: 156

🔍 Validation:
   ✅ Migration complète et validée!
   ✅ 156 réponses dans Supabase

✨ Migration terminée!
```

---

### 3. `validate-migration.js`

**Fonction** : Validation post-migration avec rapport détaillé

**Validations** :
- ✅ Compte admin "riri" existe
- ✅ Nombre de réponses (MongoDB vs Supabase)
- ✅ Échantillon de 10 tokens (liens privés)
- ✅ Structure JSONB des données

**Exemple** :
```bash
$ npm run migrate:validate

🔍 Validation de la migration MongoDB → Supabase
==================================================

📁 Utilisation du backup le plus récent: mongodb-backup-1697234567890.json

👤 Validation du compte admin...
   ✅ Admin trouvé:
      - ID: 12345678-1234-1234-1234-123456789abc
      - Username: riri
      - Email: riri@example.com

📊 Validation du nombre de réponses...
   MongoDB (backup): 156
   Supabase: 156
   ✅ Nombre de réponses identique!

🔑 Validation des tokens (liens privés)...
   Échantillon: 10 tokens
   ✅ Tokens valides: 10/10

🔍 Validation de la structure des données...
   Échantillon: 10 réponses
   ✅ Réponses valides: 10/10

==================================================
✅ VALIDATION RÉUSSIE!
   Toutes les données ont été correctement migrées.
==================================================

💡 Prochaines étapes:
   1. Tester la connexion au dashboard: /admin/dashboard.html
   2. Vérifier quelques liens privés: /view/{token}
   3. Tester la soumission d'un nouveau formulaire
   4. Si tout fonctionne, désactiver MongoDB
```

---

### 4. `test-migration.sh`

**Fonction** : Interface interactive pour tester la migration

**Menu** :
1. Backup MongoDB uniquement
2. Migration complète (backup + migration + validation)
3. Validation uniquement (post-migration)
4. Quitter

**Exemple** :
```bash
$ npm run migrate:interactive

🧪 Test de la migration MongoDB → Supabase
===========================================

✅ Node.js version: v20.10.0
✅ Fichier .env trouvé
✅ Dépendances npm installées

🔍 Vérification des variables d'environnement:

   ✅ MONGODB_URI
   ✅ SUPABASE_URL
   ✅ SUPABASE_SERVICE_KEY
   ✅ RIRI_EMAIL
   ✅ RIRI_PASSWORD

✅ Toutes les variables d'environnement sont configurées

Choisir une action:
  1) Backup MongoDB uniquement
  2) Migration complète (backup + migration + validation)
  3) Validation uniquement (post-migration)
  4) Quitter

Choix [1-4]: _
```

---

## Gestion des erreurs

### Erreur : "MONGODB_URI non défini"

**Solution** : Créer le fichier `.env` avec les bonnes variables

```bash
cp .env.example .env
# Éditer .env avec vos credentials
```

---

### Erreur : "Admin 'riri' existe déjà"

**Comportement** : Normal si vous relancez le script

Le script détecte l'admin existant et réutilise son ID :
```
⚠️  Admin "riri" existe déjà (ID: xxx)
   → Utilisation du compte existant
```

---

### Erreur : "Duplicate key (23505)"

**Cause** : Token ou contrainte unique déjà présent

**Action** : Doublon ignoré automatiquement (safe)

```
⚠️  Doublon ignoré: Alice
```

---

### Erreur : "Foreign key violation"

**Cause** : Table `admins` n'existe pas ou admin non créé

**Solution** : Exécuter les scripts SQL de création
```bash
# Dans Supabase SQL Editor
# Exécuter: sql/01_create_tables.sql
```

---

### Erreur : "Invalid JWT"

**Cause** : Utilisation de `SUPABASE_ANON_KEY` au lieu de `SUPABASE_SERVICE_KEY`

**Solution** : Vérifier le fichier `.env`
```bash
# Mauvais
SUPABASE_SERVICE_KEY=eyJhbG... (anon key)

# Correct
SUPABASE_SERVICE_KEY=eyJhbG... (service_role key)
```

---

## Fichiers générés

### Dossier `/backups/`

**Structure** :
```
backups/
├── README.md
├── mongodb-backup-1697234567890.json
├── mongodb-backup-1697234598765.json
└── ...
```

**Format du nom** : `mongodb-backup-{timestamp}.json`

**Contenu** :
```json
{
  "metadata": {
    "date": "2025-10-14T12:00:00.000Z",
    "totalResponses": 156,
    "adminResponses": 12,
    "userResponses": 144,
    "withToken": 144,
    "months": ["2025-10", ...],
    "validCount": 156
  },
  "responses": [ ... ]
}
```

⚠️ **Sécurité** : Ces fichiers contiennent des données sensibles et sont exclus du git (`.gitignore`)

---

## Rollback

### Supprimer les données migrées

```sql
-- Dans Supabase SQL Editor

-- 1. Supprimer les réponses
DELETE FROM responses
WHERE owner_id = (SELECT id FROM admins WHERE username = 'riri');

-- 2. Supprimer l'admin
DELETE FROM admins WHERE username = 'riri';
```

### Relancer la migration

```bash
# Le backup MongoDB est intact
# Les scripts gèrent les doublons
npm run migrate:run
```

---

## Tests manuels recommandés

### Test 1 : Connexion admin
```bash
# URL: /admin/dashboard.html
# Username: riri
# Password: [RIRI_PASSWORD depuis .env]

# Vérifier:
# ✅ Dashboard s'affiche
# ✅ Statistiques correctes
# ✅ Réponses listées
```

### Test 2 : Liens privés
```bash
# Prendre un token du backup
cat backups/mongodb-backup-*.json | jq '.responses[0].token'

# URL: /view/{token}

# Vérifier:
# ✅ Comparaison s'affiche
# ✅ Données correctes (nom, réponses, date)
```

### Test 3 : Nouvelle soumission
```bash
# URL: /form/riri

# Remplir et soumettre

# Vérifier:
# ✅ Token généré
# ✅ Lien privé fonctionne
# ✅ Apparaît dans le dashboard
```

---

## Checklist de migration

Avant de désactiver MongoDB :

- [ ] ✅ Backup MongoDB créé et archivé
- [ ] ✅ Migration terminée sans erreurs
- [ ] ✅ Validation post-migration réussie
- [ ] ✅ Admin "riri" peut se connecter
- [ ] ✅ Dashboard affiche les bonnes données
- [ ] ✅ Au moins 5 liens privés testés
- [ ] ✅ Nouvelle soumission fonctionne
- [ ] ✅ Données vérifiées dans Supabase Dashboard

---

## Support

En cas de problème :

1. Vérifier les logs du script
2. Exécuter le script de validation
3. Consulter `/docs/MIGRATION.md` (guide complet)
4. Vérifier les logs Supabase (Dashboard > Logs)

---

## Documentation complète

📖 **Guide détaillé** : [`/docs/MIGRATION.md`](../docs/MIGRATION.md)

📐 **Architecture** : [`/STEP_10_ARCHITECTURE.md`](../STEP_10_ARCHITECTURE.md)

✅ **Rapport d'étape** : [`/STEP_10_COMPLETED.md`](../STEP_10_COMPLETED.md)

---

**Migration réussie ! 🎉**
