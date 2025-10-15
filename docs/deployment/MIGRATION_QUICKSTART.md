# Migration MongoDB → Supabase - Guide Rapide

Guide rapide en 5 minutes pour migrer les données FAF de MongoDB vers Supabase.

---

## 1. Prérequis (2 min)

### Installer les dépendances

```bash
npm install
```

### Configurer les variables d'environnement

```bash
# Copier le template
cp .env.example .env

# Éditer .env avec vos credentials
nano .env
```

**Variables requises** :
```bash
MONGODB_URI=mongodb+srv://...            # Source
SUPABASE_URL=https://xxx.supabase.co     # Cible
SUPABASE_SERVICE_KEY=eyJhbGc...          # Service role (pas anon!)
RIRI_EMAIL=riri@example.com              # Email admin
RIRI_PASSWORD=Password123!                # Password (8+ chars, 1 maj, 1 chiffre)
```

### Vérifier Supabase

Se connecter à [app.supabase.com](https://app.supabase.com) et vérifier que les tables `admins` et `responses` existent.

Si pas encore créées :
```sql
-- Dans Supabase SQL Editor
-- Exécuter : sql/01_create_tables.sql
-- Puis : sql/02_create_rls.sql
```

---

## 2. Migration (3 min)

### Option A : Commande unique (recommandé)

```bash
npm run migrate:run
```

Cette commande exécute automatiquement :
1. ✅ Backup MongoDB
2. ✅ Connexion Supabase
3. ✅ Création admin "riri"
4. ✅ Migration des réponses
5. ✅ Validation

### Option B : Étape par étape

```bash
# 1. Backup
npm run migrate:backup

# 2. Migration
npm run migrate:run

# 3. Validation
npm run migrate:validate
```

### Option C : Interface interactive

```bash
npm run migrate:interactive
```

---

## 3. Validation (1 min)

```bash
npm run migrate:validate
```

**Vérifier la sortie** :
- ✅ Admin "riri" existe
- ✅ Nombre de réponses identique (MongoDB vs Supabase)
- ✅ 10/10 tokens validés
- ✅ 10/10 structures valides

---

## 4. Tests manuels (2 min)

### Test 1 : Connexion admin
```bash
# URL: https://faf.vercel.app/admin/dashboard.html
# Username: riri
# Password: [RIRI_PASSWORD]
```

### Test 2 : Lien privé
```bash
# Prendre un token
cat backups/mongodb-backup-*.json | jq -r '.responses[0].token'

# URL: https://faf.vercel.app/view/{token}
```

### Test 3 : Nouvelle soumission
```bash
# URL: https://faf.vercel.app/form/riri
```

---

## 5. Finalisation

### Si tout fonctionne ✅

```bash
# Archiver le backup
mkdir -p ~/faf-backups
cp backups/mongodb-backup-*.json ~/faf-backups/

# MongoDB peut être désactivé
```

### Si problèmes ⚠️

```bash
# Rollback (Supabase SQL Editor)
DELETE FROM responses WHERE owner_id = (SELECT id FROM admins WHERE username = 'riri');
DELETE FROM admins WHERE username = 'riri';

# Relancer la migration
npm run migrate:run
```

---

## Commandes utiles

```bash
# Backup uniquement
npm run migrate:backup

# Migration complète
npm run migrate:run

# Validation post-migration
npm run migrate:validate

# Interface interactive
npm run migrate:interactive

# Vérifier les backups
ls -lh backups/

# Voir les logs du dernier backup
cat backups/mongodb-backup-*.json | jq '.metadata'

# Compter les réponses dans un backup
cat backups/mongodb-backup-*.json | jq '.responses | length'
```

---

## Résolution de problèmes

### Erreur : "MONGODB_URI non défini"
```bash
# Solution
echo "MONGODB_URI=mongodb+srv://..." >> .env
```

### Erreur : "Invalid JWT"
```bash
# Vérifier que vous utilisez SERVICE_KEY (pas ANON_KEY)
grep SUPABASE_SERVICE_KEY .env
```

### Erreur : "Admin existe déjà"
```bash
# Normal si vous relancez le script
# L'admin existant sera réutilisé
```

### Erreur : "Foreign key violation"
```bash
# Tables Supabase non créées
# Solution : Exécuter sql/01_create_tables.sql
```

---

## Documentation complète

- **Guide détaillé** : [docs/MIGRATION.md](docs/MIGRATION.md)
- **Architecture** : [STEP_10_ARCHITECTURE.md](STEP_10_ARCHITECTURE.md)
- **Scripts** : [scripts/README.md](scripts/README.md)

---

## Checklist rapide

- [ ] Variables `.env` configurées
- [ ] Dépendances npm installées
- [ ] Tables Supabase créées
- [ ] Backup MongoDB réussi
- [ ] Migration terminée sans erreurs
- [ ] Validation réussie
- [ ] Tests manuels passés
- [ ] Backup archivé

---

**Migration en 5 minutes ! 🚀**

```bash
# Commande tout-en-un
npm install && \
npm run migrate:run && \
npm run migrate:validate
```
