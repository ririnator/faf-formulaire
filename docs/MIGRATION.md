# Guide de Migration MongoDB → Supabase

Ce guide détaille la procédure complète de migration des données FAF de MongoDB vers Supabase.

---

## Vue d'ensemble

**Objectif** : Transférer toutes les réponses existantes de MongoDB vers Supabase sans perte de données.

**Durée estimée** : 15-30 minutes (selon le volume de données)

**Prérequis** :
- ✅ Base de données Supabase créée avec tables `admins` et `responses`
- ✅ RLS (Row Level Security) configuré
- ✅ Variables d'environnement configurées
- ✅ Accès à MongoDB en lecture
- ✅ Node.js et npm installés

---

## Étapes de migration

### Étape 1 : Préparation

#### 1.1. Vérifier les variables d'environnement

Créer un fichier `.env` à la racine du projet :

```bash
# MongoDB (source)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database

# Supabase (destination)
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Admin Riri (compte à créer)
RIRI_EMAIL=riri@example.com
RIRI_PASSWORD=Password123!
```

**⚠️ Important** :
- Utiliser `SUPABASE_SERVICE_KEY` (pas `ANON_KEY`) pour bypass le RLS
- Le mot de passe doit respecter la politique (8+ chars, 1 majuscule, 1 chiffre)

#### 1.2. Installer les dépendances

```bash
npm install @supabase/supabase-js mongodb bcrypt dotenv
```

#### 1.3. Vérifier la structure Supabase

Se connecter au [Supabase Dashboard](https://app.supabase.com) et vérifier que les tables suivantes existent :

**Table `admins`** :
```sql
CREATE TABLE admins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
```

**Table `responses`** :
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
```

Si les tables n'existent pas, exécuter les scripts SQL fournis dans `/sql/01_create_tables.sql` et `/sql/02_create_rls.sql`.

---

### Étape 2 : Backup MongoDB

#### 2.1. Exécuter le script de backup

```bash
node scripts/backup-mongodb.js
```

**Ce que fait le script** :
1. Se connecte à MongoDB
2. Récupère toutes les réponses de la collection `responses`
3. Effectue des validations (champs requis, format, etc.)
4. Sauvegarde les données dans `/backups/mongodb-backup-{timestamp}.json`
5. Génère un rapport avec statistiques

**Sortie attendue** :
```
🚀 Début du backup MongoDB...

📡 Connexion à MongoDB...
✅ Connexion réussie

📥 Récupération des réponses...
✅ 156 réponses récupérées

📊 Statistiques:
   - Réponses admin: 12
   - Réponses utilisateurs: 144
   - Réponses avec token: 144
   - Mois uniques: 12 (2024-01, 2024-02, ...)

🔍 Validation des données:
   ✅ Réponses valides: 156/156

💾 Backup sauvegardé: /backups/mongodb-backup-1697234567890.json
   Taille: 2.34 MB

✅ Backup terminé avec succès!
```

#### 2.2. Vérifier le fichier de backup

```bash
# Afficher les métadonnées
cat backups/mongodb-backup-*.json | jq '.metadata'

# Compter les réponses
cat backups/mongodb-backup-*.json | jq '.responses | length'
```

**⚠️ Important** : Garder ce fichier de backup comme sauvegarde de sécurité !

---

### Étape 3 : Migration vers Supabase

#### 3.1. Exécuter le script de migration

```bash
node scripts/migrate-to-supabase.js
```

**Ce que fait le script** :
1. Charge le backup MongoDB le plus récent
2. Se connecte à Supabase avec la clé `service_role`
3. Crée le compte admin "riri" dans la table `admins`
4. Migre toutes les réponses par batch de 50
5. Associe chaque réponse à `owner_id = riri.id`
6. Valide le nombre total de réponses migrées

**Sortie attendue** :
```
🚀 Migration MongoDB → Supabase
==================================================

📋 Étape 1/4: Backup MongoDB
✅ Backup chargé: 156 réponses

📋 Étape 2/4: Connexion Supabase
   URL: https://xxxxx.supabase.co
✅ Client Supabase initialisé

📋 Étape 3/4: Création admin "riri"
🔐 Hash du mot de passe...
✅ Admin créé avec succès!
   - ID: 12345678-1234-1234-1234-123456789abc
   - Username: riri
   - Email: riri@example.com

📋 Étape 4/4: Migration des réponses
   Total à migrer: 156
   Batches: 4 (50 réponses/batch)

📤 Batch 1/4 (50 réponses)...
   ✅ Batch terminé (25.0%)

📤 Batch 2/4 (50 réponses)...
   ✅ Batch terminé (50.0%)

📤 Batch 3/4 (50 réponses)...
   ✅ Batch terminé (75.0%)

📤 Batch 4/4 (6 réponses)...
   ✅ Batch terminé (100.0%)

🔍 Validation de la migration...
   MongoDB: 156 réponses
   Supabase: 156 réponses
   ✅ Nombre de réponses identique!

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

📁 Fichiers générés:
   - Backup: /backups/mongodb-backup-1697234567890.json

💡 Prochaines étapes:
   1. Vérifier les données dans Supabase dashboard
   2. Tester quelques liens privés (/view/{token})
   3. Se connecter au dashboard admin avec riri
   4. Exécuter: node scripts/validate-migration.js

✨ Migration terminée!
```

#### 3.2. Gestion des erreurs courantes

**Erreur : "Username ou email déjà utilisé"**
```
⚠️  Admin "riri" existe déjà (ID: xxx)
   → Utilisation du compte existant
```
→ C'est normal si vous relancez le script. L'admin existant sera réutilisé.

**Erreur : "Duplicate key (23505)"**
```
⚠️  Doublon ignoré: Alice
```
→ Réponse déjà présente dans Supabase (safe, ignorée automatiquement)

**Erreur : "Invalid JWT"**
→ Vérifier que vous utilisez `SUPABASE_SERVICE_KEY` (pas `ANON_KEY`)

**Erreur : "Foreign key violation"**
→ Vérifier que la table `admins` existe et que l'admin "riri" a été créé

---

### Étape 4 : Validation post-migration

#### 4.1. Exécuter le script de validation

```bash
node scripts/validate-migration.js
```

**Ce que fait le script** :
1. Charge le backup MongoDB le plus récent
2. Vérifie que l'admin "riri" existe dans Supabase
3. Compare le nombre de réponses (MongoDB backup vs Supabase)
4. Valide un échantillon de 10 tokens aléatoires
5. Vérifie la structure JSONB des réponses
6. Génère un rapport détaillé

**Sortie attendue** :
```
🔍 Validation de la migration MongoDB → Supabase
==================================================

📁 Utilisation du backup le plus récent: mongodb-backup-1697234567890.json

📋 Informations du backup:
   Date: 2025-10-14T12:00:00.000Z
   Total réponses: 156
   Réponses admin: 12
   Réponses utilisateurs: 144
   Avec token: 144

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
📊 RAPPORT DE VALIDATION
==================================================

✅ Compte admin:
   ✅ Admin "riri" existe

📊 Nombre de réponses:
   ✅ 156 réponses dans Supabase

🔑 Tokens (liens privés):
   ✅ 10/10 tokens validés

🔍 Structure des données:
   ✅ 10/10 réponses valides

==================================================
✅ VALIDATION RÉUSSIE!
   Toutes les données ont été correctement migrées.
==================================================

💡 Prochaines étapes:
   1. Tester la connexion au dashboard: /admin/dashboard.html
   2. Vérifier quelques liens privés: /view/{token}
   3. Tester la soumission d'un nouveau formulaire
   4. Si tout fonctionne, désactiver MongoDB

✨ Validation terminée!
```

#### 4.2. Tests manuels recommandés

**Test 1 : Connexion admin**
```bash
# Se connecter au dashboard admin
# URL: https://faf.vercel.app/admin/dashboard.html
# Username: riri
# Password: [RIRI_PASSWORD défini dans .env]
```
→ Vérifier que le dashboard affiche les bonnes statistiques

**Test 2 : Liens privés**
```bash
# Prendre un token du backup
cat backups/mongodb-backup-*.json | jq '.responses[0].token'

# Tester l'URL
# https://faf.vercel.app/view/{token}
```
→ Vérifier que la comparaison s'affiche correctement

**Test 3 : Nouvelle soumission**
```bash
# Remplir le formulaire de riri
# https://faf.vercel.app/form/riri
```
→ Vérifier que la soumission fonctionne et génère un token

---

### Étape 5 : Vérification dans Supabase Dashboard

#### 5.1. Accéder au dashboard Supabase

1. Se connecter à [https://app.supabase.com](https://app.supabase.com)
2. Sélectionner votre projet FAF
3. Aller dans "Table Editor"

#### 5.2. Vérifier la table `admins`

```sql
SELECT id, username, email, created_at
FROM admins
WHERE username = 'riri';
```

**Résultat attendu** :
```
| id                                   | username | email              | created_at          |
|--------------------------------------|----------|--------------------|---------------------|
| 12345678-1234-1234-1234-123456789abc | riri     | riri@example.com   | 2025-10-14 12:00:00 |
```

#### 5.3. Vérifier la table `responses`

```sql
-- Compter le total de réponses
SELECT COUNT(*) FROM responses WHERE owner_id = '12345678-1234-1234-1234-123456789abc';

-- Compter les réponses admin vs utilisateurs
SELECT is_owner, COUNT(*) FROM responses
WHERE owner_id = '12345678-1234-1234-1234-123456789abc'
GROUP BY is_owner;

-- Vérifier la distribution par mois
SELECT month, COUNT(*) FROM responses
WHERE owner_id = '12345678-1234-1234-1234-123456789abc'
GROUP BY month
ORDER BY month DESC;
```

#### 5.4. Vérifier le format JSONB

```sql
-- Exemple de réponse
SELECT id, name, responses, month, token
FROM responses
WHERE owner_id = '12345678-1234-1234-1234-123456789abc'
LIMIT 1;
```

**Résultat attendu** :
```json
{
  "id": "uuid-xxx",
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
  "token": "abc123..."
}
```

---

## Rollback (en cas de problème)

Si la migration échoue ou si vous devez revenir en arrière :

### Option 1 : Supprimer les données migrées

```sql
-- Supprimer toutes les réponses de riri
DELETE FROM responses WHERE owner_id = (SELECT id FROM admins WHERE username = 'riri');

-- Supprimer l'admin riri
DELETE FROM admins WHERE username = 'riri';
```

### Option 2 : Restaurer depuis le backup

```bash
# Le backup MongoDB original est intact
# Relancer la migration si nécessaire
node scripts/migrate-to-supabase.js
```

---

## FAQ

### Q1 : Puis-je migrer plusieurs fois ?
**R** : Oui, le script détecte les doublons et les ignore. Vous pouvez relancer la migration sans risque.

### Q2 : Que se passe-t-il si j'ajoute des réponses pendant la migration ?
**R** : Le backup MongoDB est fait au début du script. Les réponses ajoutées après ne seront pas migrées. Exécuter un nouveau backup + migration.

### Q3 : Les tokens privés restent-ils valides ?
**R** : Oui ! Les tokens sont conservés tels quels. Tous les liens `/view/{token}` continueront à fonctionner.

### Q4 : Combien de temps garder MongoDB actif ?
**R** : Recommandé : 1-2 semaines après la migration, le temps de valider que tout fonctionne en production.

### Q5 : Que faire si le nombre de réponses ne correspond pas ?
**R** :
1. Vérifier les logs du script de migration (chercher "❌ Erreur")
2. Exécuter `node scripts/validate-migration.js` pour plus de détails
3. Vérifier manuellement dans Supabase Dashboard
4. Si nécessaire, supprimer les données et relancer la migration

### Q6 : La migration peut-elle être interrompue ?
**R** : Oui, vous pouvez Ctrl+C à tout moment. Les données déjà migrées resteront dans Supabase. Relancer le script continuera là où il s'est arrêté (grâce à la détection des doublons).

---

## Checklist finale

Avant de désactiver MongoDB, vérifier que :

- [ ] ✅ Backup MongoDB créé et sauvegardé
- [ ] ✅ Migration terminée sans erreurs
- [ ] ✅ Validation post-migration réussie (script)
- [ ] ✅ Admin "riri" peut se connecter au dashboard
- [ ] ✅ Statistiques du dashboard correctes
- [ ] ✅ Au moins 5 liens privés testés et fonctionnels
- [ ] ✅ Nouvelle soumission de formulaire fonctionne
- [ ] ✅ Données vérifiées dans Supabase Dashboard
- [ ] ✅ Tests manuels en production réussis
- [ ] ✅ Backup MongoDB archivé en lieu sûr

---

## Support

En cas de problème :

1. Vérifier les logs du script (`node scripts/migrate-to-supabase.js`)
2. Exécuter le script de validation (`node scripts/validate-migration.js`)
3. Consulter les issues GitHub du projet
4. Vérifier les logs Supabase (Dashboard > Logs)

---

**Migration réussie ! 🎉**
