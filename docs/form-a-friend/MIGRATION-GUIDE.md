# Form-a-Friend - Guide de Migration

## 📋 Table des matières
1. [Vue d'ensemble](#vue-densemble)
2. [Comparaison FAF vs Form-a-Friend](#comparaison-faf-vs-form-a-friend)
3. [Stratégie de Migration](#stratégie-de-migration)
4. [Scripts de Migration](#scripts-de-migration)
5. [Plan de Rollback](#plan-de-rollback)
6. [Tests & Validation](#tests--validation)
7. [Timeline & Checkpoints](#timeline--checkpoints)

---

## 🔄 Vue d'ensemble

Cette migration transforme le système FAF existant (Form-a-Friend v1) en Form-a-Friend v2 avec architecture complète pour relations bidirectionnelles et soumissions uniques.

### Objectifs de Migration
- **Préserver** : 100% des données existantes
- **Transformer** : Architecture vers système symétrique
- **Ajouter** : Fonctionnalités sociales (contacts, handshakes)
- **Optimiser** : Performance et expérience utilisateur
- **Sécuriser** : Rollback complet possible

### Impact Utilisateurs
- **Users existants** : Comptes créés automatiquement
- **Données historiques** : Converties et conservées
- **Tokens existants** : Maintenus en mode compatibilité
- **URLs** : Fonctionnent encore (redirections automatiques)

---

## 📊 Comparaison FAF vs Form-a-Friend

### Architecture Actuelle (FAF v1)
```
Response {
  name: String,           // Nom en texte libre
  responses: Array,       // Réponses au formulaire
  month: String,          // Mois YYYY-MM
  token: String,          // Token unique pour accès privé
  isAdmin: Boolean        // Flag admin
}
```

### Architecture Cible (Form-a-Friend v2)
```
User {
  username, email, password, role,
  preferences: { sendTime, timezone, ... }
}

Contact {
  ownerId: User._id,      // Propriétaire du contact
  email: String,          // Email du contact
  contactUserId?: User._id // Si le contact a un compte
}

Submission {
  userId: User._id,       // UNE soumission par user/mois
  month: String,
  responses: Array,
  freeText: String        // Nouveau champ libre
}

Invitation {
  fromUserId: User._id,   // Qui invite
  toEmail: String,        // Destinataire
  token: String,          // Token d'accès
  tracking: Object        // Suivi ouverture/soumission
}

Handshake {
  requesterId: User._id,  // Demandeur
  targetId: User._id,     // Cible
  status: Enum            // pending/accepted/declined
}
```

### Changements Majeurs

| Aspect | FAF v1 | Form-a-Friend v2 |
|--------|--------|------------------|
| **Utilisateurs** | Noms libres | Comptes authentifiés |
| **Soumissions** | Multiples par nom | Une par user/mois |
| **Relations** | Unidirectionnelles | Bidirectionnelles avec handshake |
| **Contacts** | Pas de gestion | Gestion complète avec import |
| **Invitations** | Pas de suivi | Tracking complet + relances |
| **Dashboard** | Admin seulement | Tous les utilisateurs |
| **Vie privée** | Token = accès total | Permissions granulaires |

---

## 🗺️ Stratégie de Migration

### Phase 1 : Préparation (Réversible)
1. **Backup complet** de la base de données
2. **Déploiement des nouveaux modèles** (coexistence)
3. **Tests de l'infrastructure** (sans migration données)

### Phase 2 : Migration des Données (Point de non-retour)
1. **Création des Users** depuis noms uniques
2. **Conversion Response → Submission**
3. **Génération des tokens compatibilité**

### Phase 3 : Activation (Progressif)
1. **Activation des nouvelles fonctionnalités**
2. **Redirection des anciennes URLs**
3. **Monitoring intensif**

### Phase 4 : Nettoyage (Optionnel)
1. **Suppression des données legacy** (après validation)
2. **Optimisation des index**
3. **Documentation finale**

---

## 🔧 Scripts de Migration

### Script Principal : `migrate-to-form-a-friend.js`

```javascript
#!/usr/bin/env node
/**
 * Migration FAF → Form-a-Friend
 * 
 * Usage:
 *   node migrate-to-form-a-friend.js --dry-run    # Preview
 *   node migrate-to-form-a-friend.js --execute    # Exécution
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const fs = require('fs').promises;

// Models
const Response = require('../models/Response');
const User = require('../models/User');
const Submission = require('../models/Submission');
const Contact = require('../models/Contact');
const Invitation = require('../models/Invitation');

class MigrationService {
  constructor() {
    this.isDryRun = process.argv.includes('--dry-run');
    this.backupDir = `./backups/migration-${Date.now()}`;
    this.stats = {
      users: { created: 0, errors: 0 },
      submissions: { migrated: 0, errors: 0 },
      invitations: { created: 0, errors: 0 },
      total: { start: new Date() }
    };
  }

  async run() {
    try {
      console.log('🚀 Démarrage migration FAF → Form-a-Friend');
      console.log(`Mode: ${this.isDryRun ? 'DRY RUN' : 'EXECUTION'}`);
      
      // Étape 1: Préparation
      await this.prepareMigration();
      
      // Étape 2: Migration des données
      await this.migrateUsers();
      await this.migrateSubmissions();
      await this.createCompatibilityTokens();
      
      // Étape 3: Vérification
      await this.verifyMigration();
      
      // Étape 4: Rapport final
      await this.generateReport();
      
      console.log('✅ Migration terminée avec succès!');
      
    } catch (error) {
      console.error('❌ Erreur migration:', error);
      if (!this.isDryRun) {
        console.log('🔄 Rollback automatique...');
        await this.rollback();
      }
      process.exit(1);
    }
  }

  /**
   * Phase 1: Préparation de la migration
   */
  async prepareMigration() {
    console.log('📋 Phase 1: Préparation...');
    
    if (!this.isDryRun) {
      // Créer backup
      await fs.mkdir(this.backupDir, { recursive: true });
      await this.createBackup();
    }
    
    // Vérifier prérequis
    await this.checkPrerequisites();
    
    console.log('✅ Préparation terminée');
  }

  /**
   * Créer sauvegarde complète
   */
  async createBackup() {
    console.log('💾 Création backup...');
    
    const collections = ['responses', 'users', 'sessions'];
    
    for (const collection of collections) {
      const data = await mongoose.connection.db
        .collection(collection)
        .find({})
        .toArray();
      
      await fs.writeFile(
        `${this.backupDir}/${collection}.json`,
        JSON.stringify(data, null, 2)
      );
      
      console.log(`  ✓ ${collection}: ${data.length} documents`);
    }
  }

  /**
   * Phase 2: Migration des utilisateurs
   */
  async migrateUsers() {
    console.log('👤 Phase 2: Migration des utilisateurs...');
    
    // Obtenir tous les noms uniques
    const uniqueNames = await Response.distinct('name');
    console.log(`  Noms uniques trouvés: ${uniqueNames.length}`);
    
    const userMap = new Map();
    
    for (const name of uniqueNames) {
      try {
        const username = this.sanitizeUsername(name);
        const email = `${username}@legacy.form-a-friend.com`;
        
        // Vérifier si user existe déjà
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          userMap.set(name, existingUser._id);
          continue;
        }
        
        if (!this.isDryRun) {
          const user = await User.create({
            username,
            email,
            password: await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10),
            role: name.toLowerCase() === process.env.FORM_ADMIN_NAME?.toLowerCase() ? 'admin' : 'user',
            migrationData: {
              legacyName: name,
              migratedAt: new Date(),
              source: 'migration'
            },
            preferences: {
              sendTime: '18:00',
              timezone: 'Europe/Paris',
              sendDay: 5
            }
          });
          
          userMap.set(name, user._id);
        }
        
        this.stats.users.created++;
        
      } catch (error) {
        console.error(`  ❌ Erreur user ${name}:`, error.message);
        this.stats.users.errors++;
      }
    }
    
    console.log(`✅ Users: ${this.stats.users.created} créés, ${this.stats.users.errors} erreurs`);
    return userMap;
  }

  /**
   * Phase 3: Migration des soumissions
   */
  async migrateSubmissions() {
    console.log('📝 Phase 3: Migration des soumissions...');
    
    const responses = await Response.find().sort({ createdAt: 1 });
    console.log(`  Réponses à migrer: ${responses.length}`);
    
    const userMap = await this.buildUserMap();
    
    for (const response of responses) {
      try {
        const userId = userMap.get(response.name);
        if (!userId) {
          throw new Error(`User non trouvé pour: ${response.name}`);
        }
        
        // Vérifier si submission existe déjà
        const existing = await Submission.findOne({ 
          userId, 
          month: response.month 
        });
        
        if (existing) {
          console.log(`  ⚠️  Submission existe déjà: ${response.name} - ${response.month}`);
          continue;
        }
        
        if (!this.isDryRun) {
          await Submission.create({
            userId,
            month: response.month,
            responses: response.responses || [],
            freeText: '', // Nouveau champ vide
            completionRate: this.calculateCompletionRate(response.responses),
            submittedAt: response.createdAt,
            lastModifiedAt: response.createdAt,
            formVersion: 'v1-migrated'
          });
        }
        
        this.stats.submissions.migrated++;
        
      } catch (error) {
        console.error(`  ❌ Erreur submission ${response._id}:`, error.message);
        this.stats.submissions.errors++;
      }
    }
    
    console.log(`✅ Submissions: ${this.stats.submissions.migrated} migrées, ${this.stats.submissions.errors} erreurs`);
  }

  /**
   * Phase 4: Tokens de compatibilité
   */
  async createCompatibilityTokens() {
    console.log('🔗 Phase 4: Tokens de compatibilité...');
    
    const responses = await Response.find({ token: { $exists: true } });
    console.log(`  Tokens legacy à préserver: ${responses.length}`);
    
    const userMap = await this.buildUserMap();
    
    for (const response of responses) {
      try {
        const userId = userMap.get(response.name);
        if (!userId) continue;
        
        if (!this.isDryRun) {
          await Invitation.create({
            fromUserId: userId,
            toEmail: 'legacy@form-a-friend.com',
            month: response.month,
            token: response.token,
            type: 'legacy',
            status: 'submitted',
            tracking: {
              sentAt: response.createdAt,
              submittedAt: response.createdAt
            },
            expiresAt: new Date('2026-12-31'), // Long expiry pour compatibilité
            metadata: {
              isLegacyToken: true,
              originalResponseId: response._id
            }
          });
        }
        
        this.stats.invitations.created++;
        
      } catch (error) {
        console.error(`  ❌ Erreur token ${response.token}:`, error.message);
      }
    }
    
    console.log(`✅ Tokens: ${this.stats.invitations.created} préservés`);
  }

  /**
   * Vérification post-migration
   */
  async verifyMigration() {
    console.log('🔍 Phase 5: Vérification...');
    
    // Compter les données
    const counts = {
      originalResponses: await Response.countDocuments(),
      newUsers: await User.countDocuments({ 'migrationData.source': 'migration' }),
      newSubmissions: await Submission.countDocuments(),
      legacyInvitations: await Invitation.countDocuments({ type: 'legacy' })
    };
    
    console.log('📊 Comptages:');
    Object.entries(counts).forEach(([key, value]) => {
      console.log(`  ${key}: ${value}`);
    });
    
    // Vérifications d'intégrité
    const uniqueNames = await Response.distinct('name');
    const migratedUsers = await User.countDocuments({ 'migrationData.source': 'migration' });
    
    if (uniqueNames.length !== migratedUsers) {
      throw new Error(`Mismatch users: ${uniqueNames.length} noms vs ${migratedUsers} users`);
    }
    
    console.log('✅ Vérification terminée - Intégrité OK');
  }

  /**
   * Utilitaires
   */
  sanitizeUsername(name) {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '')
      .substring(0, 30);
  }

  calculateCompletionRate(responses) {
    if (!responses || responses.length === 0) return 0;
    
    const answered = responses.filter(r => r.answer && r.answer.trim()).length;
    return Math.round((answered / responses.length) * 100);
  }

  async buildUserMap() {
    const users = await User.find({ 'migrationData.source': 'migration' });
    const map = new Map();
    
    users.forEach(user => {
      if (user.migrationData?.legacyName) {
        map.set(user.migrationData.legacyName, user._id);
      }
    });
    
    return map;
  }

  /**
   * Génerer rapport final
   */
  async generateReport() {
    const duration = Date.now() - this.stats.total.start;
    const report = {
      migration: {
        date: new Date().toISOString(),
        duration: `${Math.round(duration / 1000)}s`,
        mode: this.isDryRun ? 'DRY_RUN' : 'EXECUTED'
      },
      stats: this.stats,
      verification: {
        totalOriginalResponses: await Response.countDocuments(),
        totalNewUsers: await User.countDocuments({ 'migrationData.source': 'migration' }),
        totalSubmissions: await Submission.countDocuments(),
        totalLegacyTokens: await Invitation.countDocuments({ type: 'legacy' })
      }
    };
    
    if (!this.isDryRun) {
      await fs.writeFile(
        `${this.backupDir}/migration-report.json`,
        JSON.stringify(report, null, 2)
      );
    }
    
    console.log('\n📋 RAPPORT FINAL:');
    console.log(JSON.stringify(report, null, 2));
  }

  /**
   * Rollback en cas d'erreur
   */
  async rollback() {
    console.log('🔄 Rollback en cours...');
    
    try {
      // Supprimer les nouvelles données
      await User.deleteMany({ 'migrationData.source': 'migration' });
      await Submission.deleteMany({});
      await Invitation.deleteMany({ type: 'legacy' });
      
      console.log('✅ Rollback terminé');
    } catch (error) {
      console.error('❌ Erreur rollback:', error);
      console.log('💾 Restaurer depuis backup:', this.backupDir);
    }
  }
}

// Exécution
if (require.main === module) {
  const migration = new MigrationService();
  migration.run();
}

module.exports = MigrationService;
```

### Script de Rollback : `rollback-migration.js`

```javascript
#!/usr/bin/env node
/**
 * Rollback Migration Form-a-Friend
 * 
 * Usage:
 *   node rollback-migration.js ./backups/migration-1234567890
 */

const mongoose = require('mongoose');
const fs = require('fs').promises;
const path = require('path');

class RollbackService {
  constructor(backupPath) {
    this.backupPath = backupPath;
    this.isDryRun = process.argv.includes('--dry-run');
  }

  async run() {
    try {
      console.log('🔄 Démarrage rollback migration...');
      console.log(`Backup: ${this.backupPath}`);
      
      // Vérifier backup
      await this.verifyBackup();
      
      // Phase 1: Supprimer nouvelles données
      await this.cleanupMigrationData();
      
      // Phase 2: Restaurer données originales
      await this.restoreBackup();
      
      // Phase 3: Vérification
      await this.verifyRollback();
      
      console.log('✅ Rollback terminé avec succès!');
      
    } catch (error) {
      console.error('❌ Erreur rollback:', error);
      process.exit(1);
    }
  }

  async verifyBackup() {
    console.log('🔍 Vérification backup...');
    
    const requiredFiles = ['responses.json', 'users.json', 'sessions.json'];
    
    for (const file of requiredFiles) {
      const filePath = path.join(this.backupPath, file);
      try {
        await fs.access(filePath);
        console.log(`  ✓ ${file} trouvé`);
      } catch {
        throw new Error(`Fichier backup manquant: ${file}`);
      }
    }
  }

  async cleanupMigrationData() {
    console.log('🧹 Suppression données migration...');
    
    if (!this.isDryRun) {
      const deleted = {
        users: await User.deleteMany({ 'migrationData.source': 'migration' }),
        submissions: await Submission.deleteMany({}),
        invitations: await Invitation.deleteMany({ type: 'legacy' }),
        contacts: await Contact.deleteMany({}),
        handshakes: await Handshake.deleteMany({})
      };
      
      console.log('📊 Supprimé:');
      Object.entries(deleted).forEach(([key, result]) => {
        console.log(`  ${key}: ${result.deletedCount} documents`);
      });
    }
  }

  async restoreBackup() {
    console.log('📁 Restauration backup...');
    
    // Restaurer responses (si supprimées accidentellement)
    const responsesData = JSON.parse(
      await fs.readFile(path.join(this.backupPath, 'responses.json'))
    );
    
    if (!this.isDryRun) {
      for (const doc of responsesData) {
        await mongoose.connection.db.collection('responses').insertOne(doc);
      }
    }
    
    console.log(`  ✓ ${responsesData.length} responses restaurées`);
  }

  async verifyRollback() {
    console.log('✅ Vérification rollback...');
    
    const counts = {
      responses: await Response.countDocuments(),
      migratedUsers: await User.countDocuments({ 'migrationData.source': 'migration' }),
      submissions: await Submission.countDocuments(),
      legacyInvitations: await Invitation.countDocuments({ type: 'legacy' })
    };
    
    console.log('📊 État final:');
    Object.entries(counts).forEach(([key, value]) => {
      console.log(`  ${key}: ${value}`);
    });
    
    // Vérifications
    if (counts.migratedUsers > 0) {
      throw new Error('Des utilisateurs migrés subsistent');
    }
    
    if (counts.responses === 0) {
      throw new Error('Aucune response trouvée - échec rollback');
    }
  }
}

// Exécution
if (require.main === module) {
  const backupPath = process.argv[2];
  if (!backupPath) {
    console.error('Usage: node rollback-migration.js <backup-path>');
    process.exit(1);
  }
  
  const rollback = new RollbackService(backupPath);
  rollback.run();
}
```

---

## ✅ Tests & Validation

### Tests Pré-Migration
```bash
# Vérifier l'état actuel
npm test
npm run test:integration

# Compter les données
node -e "
  require('./backend/config/database');
  const Response = require('./backend/models/Response');
  Response.countDocuments().then(count => {
    console.log('Responses actuelles:', count);
    process.exit(0);
  });
"

# Test dry-run migration
node scripts/migrate-to-form-a-friend.js --dry-run
```

### Tests Post-Migration
```bash
# Vérifier intégrité
node scripts/verify-migration.js

# Tests fonctionnels
npm run test:migration

# Test connexions utilisateurs
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@legacy.form-a-friend.com","password":"temp123"}'
```

### Script de Vérification : `verify-migration.js`
```javascript
#!/usr/bin/env node

const mongoose = require('mongoose');
const { Response, User, Submission, Invitation } = require('../backend/models');

async function verify() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    
    console.log('🔍 Vérification migration...\n');
    
    // Comptages
    const counts = {
      originalResponses: await Response.countDocuments(),
      uniqueNames: (await Response.distinct('name')).length,
      migratedUsers: await User.countDocuments({ 'migrationData.source': 'migration' }),
      submissions: await Submission.countDocuments(),
      legacyTokens: await Invitation.countDocuments({ type: 'legacy' })
    };
    
    console.log('📊 COMPTAGES:');
    Object.entries(counts).forEach(([key, value]) => {
      console.log(`  ${key.padEnd(20)}: ${value}`);
    });
    
    // Vérifications d'intégrité
    const checks = [];
    
    // Check 1: Chaque nom unique = 1 user
    if (counts.uniqueNames === counts.migratedUsers) {
      checks.push('✅ Names → Users: OK');
    } else {
      checks.push(`❌ Names → Users: ${counts.uniqueNames} vs ${counts.migratedUsers}`);
    }
    
    // Check 2: Responses migrées
    if (counts.originalResponses === counts.submissions) {
      checks.push('✅ Responses → Submissions: OK');
    } else {
      checks.push(`⚠️  Responses → Submissions: ${counts.originalResponses} vs ${counts.submissions}`);
    }
    
    // Check 3: Tokens préservés
    const originalTokens = await Response.countDocuments({ token: { $exists: true } });
    if (originalTokens === counts.legacyTokens) {
      checks.push('✅ Tokens préservés: OK');
    } else {
      checks.push(`❌ Tokens: ${originalTokens} vs ${counts.legacyTokens}`);
    }
    
    console.log('\n🔍 VÉRIFICATIONS:');
    checks.forEach(check => console.log(`  ${check}`));
    
    // Test fonctionnel
    console.log('\n🧪 TEST FONCTIONNEL:');
    
    // Test connexion admin
    const adminUser = await User.findOne({ role: 'admin', 'migrationData.source': 'migration' });
    if (adminUser) {
      console.log(`  ✅ Admin user: ${adminUser.username}`);
    } else {
      console.log('  ❌ Aucun admin user trouvé');
    }
    
    // Test submission récente
    const recentSubmission = await Submission.findOne().sort({ submittedAt: -1 });
    if (recentSubmission) {
      const user = await User.findById(recentSubmission.userId);
      console.log(`  ✅ Submission récente: ${user.username} (${recentSubmission.month})`);
    }
    
    console.log('\n✅ Vérification terminée');
    
  } catch (error) {
    console.error('❌ Erreur vérification:', error);
    process.exit(1);
  } finally {
    await mongoose.disconnect();
  }
}

verify();
```

---

## 📅 Timeline & Checkpoints

### Planning Recommandé

#### Semaine -1 : Préparation
- **Lundi** : Backup complet production
- **Mardi** : Tests migration en staging
- **Mercredi** : Validation scripts rollback
- **Jeudi** : Communication aux utilisateurs
- **Vendredi** : Formation équipe support

#### Jour J : Migration
- **09:00** : Maintenance mode activé
- **09:15** : Backup final production
- **09:30** : Démarrage migration (--dry-run)
- **10:00** : Migration réelle (--execute)
- **11:00** : Vérifications & tests
- **12:00** : Activation nouvelles fonctionnalités
- **13:00** : Monitoring intensif
- **14:00** : Communication "migration réussie"

#### Semaine +1 : Stabilisation
- **J+1** : Monitoring H24, support utilisateurs
- **J+2** : Collecte feedback, ajustements
- **J+3** : Optimisations performance
- **J+7** : Bilan migration, planning cleanup

#### Mois +1 : Nettoyage
- **Validation** : Toutes les fonctionnalités stables
- **Nettoyage** : Suppression données legacy (optionnel)
- **Documentation** : Mise à jour guides utilisateur

### Checkpoints de Validation

#### Checkpoint 1 : Backup OK
- [ ] Backup complet créé
- [ ] Backup restaurable testé
- [ ] Espace disque suffisant

#### Checkpoint 2 : Migration OK
- [ ] Tous les noms → users
- [ ] Toutes les responses → submissions  
- [ ] Tous les tokens préservés
- [ ] Tests d'intégrité passés

#### Checkpoint 3 : Fonctionnel OK
- [ ] Connexions utilisateurs OK
- [ ] Affichage historique OK
- [ ] Nouveaux formulaires OK
- [ ] APIs répondent correctement

#### Checkpoint 4 : Performance OK
- [ ] Temps de réponse < 200ms
- [ ] Pas d'erreurs 5xx
- [ ] Monitoring vert
- [ ] Charge normale

### Plan de Communication

#### Avant Migration (J-7)
**Email aux utilisateurs :**
```
Sujet: 🚀 Form-a-Friend évolue - Nouvelles fonctionnalités le [DATE]

Bonjour,

Form-a-Friend va recevoir une mise à jour majeure le [DATE] qui apportera :
- Dashboard personnel pour tous
- Gestion de vos contacts
- Invitations automatiques
- Vue comparative 1-vs-1

🔒 Vos données seront préservées intégralement.
⏰ Interruption prévue : 3h maximum le matin.

Merci de votre confiance !
L'équipe Form-a-Friend
```

#### Pendant Migration
**Page maintenance :**
```html
<div class="maintenance">
  <h1>🔧 Maintenance en cours</h1>
  <p>Form-a-Friend évolue ! Nouvelles fonctionnalités en cours d'installation.</p>
  <p>Retour estimé : 12h00</p>
  <div class="progress-bar">...</div>
</div>
```

#### Après Migration (J+0)
**Email de confirmation :**
```
Sujet: ✅ Form-a-Friend est de retour - Découvrez vos nouvelles fonctionnalités

La migration est terminée ! Découvrez :
- Votre nouveau dashboard : [LIEN]
- Vos anciens formulaires préservés
- Guide des nouvelles fonctionnalités : [LIEN]

En cas de problème : support@form-a-friend.com
```

---

## 🔧 Utilitaires de Migration

### Script de Monitoring : `migration-monitor.js`
```javascript
// Surveiller la migration en temps réel
const monitor = setInterval(async () => {
  const stats = {
    responses: await Response.countDocuments(),
    users: await User.countDocuments({ 'migrationData.source': 'migration' }),
    submissions: await Submission.countDocuments()
  };
  
  console.log(`${new Date().toISOString()} - Progress:`, stats);
}, 5000);
```

### Vérification des URLs Legacy
```bash
#!/bin/bash
# Test des redirections anciennes URLs

echo "🔗 Test redirections..."

# URLs à tester
urls=(
  "/view/abc123def456"
  "/admin"
  "/form"
)

for url in "${urls[@]}"; do
  echo "Testing $url..."
  curl -I "http://localhost:3000$url" | head -1
done
```

### Nettoyage Post-Migration (Optionnel)
```javascript
// Après validation complète (1 mois+)
async function cleanupLegacyData() {
  console.log('🧹 Nettoyage données legacy...');
  
  // Sauvegarder avant suppression
  const backup = {
    responses: await Response.find().lean(),
    date: new Date()
  };
  
  await fs.writeFile(
    `./archives/responses-legacy-${Date.now()}.json`,
    JSON.stringify(backup, null, 2)
  );
  
  // Supprimer (IRREVERSIBLE)
  if (process.env.CONFIRM_CLEANUP === 'yes') {
    await Response.deleteMany({});
    console.log('✅ Données legacy supprimées');
  }
}
```

---

## 🚨 Procédures d'Urgence

### En Cas d'Échec Migration
1. **STOP immédiat** : Annuler la migration
2. **Rollback automatique** : `node rollback-migration.js`
3. **Vérifier état** : Tests fonctionnels basiques
4. **Communication** : Informer utilisateurs du report
5. **Analyse post-mortem** : Identifier cause, corriger, re-planifier

### En Cas de Performance Dégradée
1. **Monitoring renforcé** : Métriques temps réel
2. **Index manquants** : Créer indexes critiques
3. **Cache invalidation** : Vider caches applicatifs
4. **Scale horizontal** : Ajouter serveurs si nécessaire

### En Cas de Bugs Utilisateur
1. **Hotfix prioritaire** : Corrections rapides
2. **Support réactif** : Réponse < 1h
3. **Rollback partiel** : Si nécessaire pour features spécifiques
4. **Communication transparente** : Status page à jour

---

*Guide de Migration Form-a-Friend v1.0 - Procédures complètes et sécurisées*