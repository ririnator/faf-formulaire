# Form-a-Friend - Plan d'Implémentation Détaillé

## 📋 Table des matières
1. [Résumé Exécutif](#résumé-exécutif)
2. [Phase 1 : Modèles & Services](#phase-1--modèles--services-jours-1-3)
3. [Phase 2 : APIs REST](#phase-2--apis-rest-jours-4-5)
4. [Phase 3 : Service Email](#phase-3--service-email-jours-6-7)
5. [Phase 4 : Frontend](#phase-4--frontend-jours-8-10)
6. [Phase 5 : Automatisation](#phase-5--automatisation-jours-11-12)
7. [Phase 6 : Migration & Tests](#phase-6--migration--tests-jours-13-15)
8. [Checklist de Lancement](#checklist-de-lancement)

---

## 📊 Résumé Exécutif

### Timeline Globale
- **Durée totale** : 15 jours ouvrables (3 semaines)
- **MVP fonctionnel** : Jour 10
- **Production-ready** : Jour 15

### Milestones Clés
- **Jour 5** : Backend API complète
- **Jour 10** : Interface utilisateur fonctionnelle
- **Jour 15** : Système automatisé complet

### Ressources Requises
- 1 développeur full-stack
- Compte Resend/Postmark (email)
- MongoDB Atlas (existant)
- Cloudinary (existant)

---

## 🔨 Phase 1 : Modèles & Services (Jours 1-3)

### Jour 1 : Création des Modèles

#### Matin (4h)
```bash
# Créer les nouveaux modèles
backend/models/Contact.js
backend/models/Submission.js
backend/models/Invitation.js
backend/models/Handshake.js
```

**Contact.js**
```javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ContactSchema = new Schema({
  ownerId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  email: { 
    type: String, 
    required: true, 
    lowercase: true,
    trim: true
  },
  firstName: { 
    type: String, 
    trim: true 
  },
  contactUserId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User',
    sparse: true
  },
  status: {
    type: String,
    enum: ['pending', 'active', 'opted_out', 'bounced', 'blocked'],
    default: 'pending'
  },
  handshakeId: {
    type: Schema.Types.ObjectId,
    ref: 'Handshake'
  },
  tags: [String],
  tracking: {
    addedAt: { type: Date, default: Date.now },
    lastSentAt: Date,
    lastOpenedAt: Date,
    lastSubmittedAt: Date,
    responseCount: { type: Number, default: 0 },
    responseRate: { type: Number, default: 0, min: 0, max: 100 }
  },
  source: {
    type: String,
    enum: ['manual', 'csv', 'invitation'],
    default: 'manual'
  }
}, {
  timestamps: true
});

// Index composé unique
ContactSchema.index({ ownerId: 1, email: 1 }, { unique: true });

// Méthodes
ContactSchema.methods.updateTracking = function(event) {
  switch(event) {
    case 'sent':
      this.tracking.lastSentAt = new Date();
      break;
    case 'opened':
      this.tracking.lastOpenedAt = new Date();
      break;
    case 'submitted':
      this.tracking.lastSubmittedAt = new Date();
      this.tracking.responseCount++;
      break;
  }
  return this.save();
};

module.exports = mongoose.model('Contact', ContactSchema);
```

#### Après-midi (4h)
- Créer Submission.js (remplace Response)
- Créer Invitation.js avec tokens
- Créer Handshake.js pour relations
- Tests unitaires des modèles

### Jour 2 : Services Métier

#### Matin (4h)
```bash
# Créer les services
backend/services/contactService.js
backend/services/submissionService.js
backend/services/invitationService.js
backend/services/handshakeService.js
```

**ContactService.js**
```javascript
const Contact = require('../models/Contact');
const User = require('../models/User');
const HandshakeService = require('./handshakeService');

class ContactService {
  /**
   * Ajouter un contact avec détection automatique
   */
  async addContact(ownerId, { email, firstName, tags = [] }) {
    // Vérifier doublon
    const existing = await Contact.findOne({ ownerId, email });
    if (existing) {
      return { 
        contact: existing, 
        isNew: false,
        message: 'Contact déjà existant'
      };
    }

    // Vérifier si user existe
    const existingUser = await User.findOne({ email });
    
    // Créer le contact
    const contact = await Contact.create({
      ownerId,
      email,
      firstName,
      contactUserId: existingUser?._id,
      status: existingUser ? 'pending' : 'active',
      tags
    });

    // Si user existe, proposer handshake
    if (existingUser) {
      const handshake = await HandshakeService.request(
        ownerId, 
        existingUser._id
      );
      contact.handshakeId = handshake._id;
      await contact.save();
    }

    return { 
      contact, 
      isNew: true,
      handshakeSent: !!existingUser
    };
  }

  /**
   * Import CSV en batch
   */
  async importCSV(ownerId, csvData) {
    const results = {
      imported: [],
      duplicates: [],
      errors: []
    };

    for (const row of csvData) {
      try {
        const result = await this.addContact(ownerId, {
          email: row.email,
          firstName: row.firstName || row.name,
          tags: row.tags?.split(',') || []
        });
        
        if (result.isNew) {
          results.imported.push(result.contact);
        } else {
          results.duplicates.push(result.contact);
        }
      } catch (error) {
        results.errors.push({ row, error: error.message });
      }
    }

    return results;
  }

  /**
   * Obtenir contacts avec statistiques
   */
  async getContactsWithStats(ownerId) {
    const contacts = await Contact.find({ ownerId })
      .populate('contactUserId', 'username email')
      .populate('handshakeId', 'status')
      .sort('-tracking.lastSubmittedAt');

    // Calculer taux de réponse global
    const totalSent = contacts.reduce((sum, c) => 
      sum + (c.tracking.lastSentAt ? 1 : 0), 0
    );
    const totalResponded = contacts.reduce((sum, c) => 
      sum + c.tracking.responseCount, 0
    );
    
    return {
      contacts,
      stats: {
        total: contacts.length,
        active: contacts.filter(c => c.status === 'active').length,
        responseRate: totalSent ? (totalResponded / totalSent * 100) : 0
      }
    };
  }
}

module.exports = new ContactService();
```

#### Après-midi (4h)
- Implémenter SubmissionService
- Implémenter InvitationService
- Implémenter HandshakeService
- Tests d'intégration services

### Jour 3 : Adaptation Services Existants

#### Matin (4h)
- Adapter AuthService pour Users
- Transformer ResponseService en base pour SubmissionService
- Enrichir User model avec preferences

#### Après-midi (4h)
- Tests complets modèles + services
- Documentation des services
- Validation de la phase 1

---

## 🌐 Phase 2 : APIs REST (Jours 4-5)

### Jour 4 : Routes Principales

#### Matin (4h)
```bash
# Créer les routes
backend/routes/contactRoutes.js
backend/routes/submissionRoutes.js
backend/routes/invitationRoutes.js
backend/routes/handshakeRoutes.js
```

**contactRoutes.js**
```javascript
const express = require('express');
const router = express.Router();
const ContactService = require('../services/contactService');
const { requireUserAuth } = require('../middleware/hybridAuth');
const { body, validationResult } = require('express-validator');

// GET /api/contacts - Liste des contacts
router.get('/', requireUserAuth, async (req, res) => {
  try {
    const result = await ContactService.getContactsWithStats(
      req.session.userId
    );
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/contacts - Ajouter un contact
router.post('/', 
  requireUserAuth,
  [
    body('email').isEmail().normalizeEmail(),
    body('firstName').optional().trim().isLength({ max: 100 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const result = await ContactService.addContact(
        req.session.userId,
        req.body
      );
      res.status(result.isNew ? 201 : 200).json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// POST /api/contacts/import - Import CSV
router.post('/import',
  requireUserAuth,
  upload.single('csv'),
  async (req, res) => {
    try {
      // Parser CSV (utiliser csv-parse)
      const csvData = await parseCSV(req.file.buffer);
      const results = await ContactService.importCSV(
        req.session.userId,
        csvData
      );
      res.json(results);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// PUT /api/contacts/:id - Modifier un contact
router.put('/:id',
  requireUserAuth,
  async (req, res) => {
    try {
      const contact = await Contact.findOneAndUpdate(
        { _id: req.params.id, ownerId: req.session.userId },
        req.body,
        { new: true }
      );
      if (!contact) {
        return res.status(404).json({ error: 'Contact non trouvé' });
      }
      res.json(contact);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// DELETE /api/contacts/:id - Supprimer un contact
router.delete('/:id',
  requireUserAuth,
  async (req, res) => {
    try {
      const contact = await Contact.findOneAndDelete({
        _id: req.params.id,
        ownerId: req.session.userId
      });
      if (!contact) {
        return res.status(404).json({ error: 'Contact non trouvé' });
      }
      res.json({ message: 'Contact supprimé' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

module.exports = router;
```

#### Après-midi (4h)
- Implémenter submissionRoutes.js
- Implémenter invitationRoutes.js
- Implémenter handshakeRoutes.js

### Jour 5 : Intégration & Tests API

#### Matin (4h)
- Intégrer routes dans app.js
- Configurer middleware pipeline
- Tests Postman/Insomnia

#### Après-midi (4h)
- Tests d'intégration API
- Documentation Swagger/OpenAPI
- **MILESTONE : Backend API complète**

---

## 📧 Phase 3 : Service Email (Jours 6-7)

### Jour 6 : Configuration Email

#### Matin (4h)
```bash
npm install resend
# ou
npm install @sendgrid/mail
```

**emailService.js**
```javascript
const { Resend } = require('resend');
const path = require('path');
const fs = require('fs').promises;

class EmailService {
  constructor() {
    this.client = new Resend(process.env.RESEND_API_KEY);
    this.from = process.env.EMAIL_FROM || 'notifications@form-a-friend.com';
  }

  /**
   * Envoyer invitation mensuelle
   */
  async sendInvitation(invitation, fromUser, toContact) {
    const link = `${process.env.APP_BASE_URL}/invite/${invitation.token}`;
    
    const html = await this.renderTemplate('invitation', {
      fromName: fromUser.firstName || fromUser.username,
      toName: toContact.firstName || 'là',
      month: this.formatMonth(invitation.month),
      link,
      shortCode: invitation.shortCode
    });

    const result = await this.client.emails.send({
      from: `${fromUser.firstName} via Form-a-Friend <${this.from}>`,
      reply_to: fromUser.email,
      to: toContact.email,
      subject: `${fromUser.firstName} t'invite à partager ce mois-ci 🌟`,
      html
    });

    // Mettre à jour tracking
    invitation.tracking.sentAt = new Date();
    invitation.status = 'sent';
    await invitation.save();

    return result;
  }

  /**
   * Envoyer rappel
   */
  async sendReminder(invitation, type = 'first') {
    const templates = {
      first: {
        subject: 'Petit rappel 🔔 - Ton ami attend ta réponse',
        template: 'reminder-first'
      },
      second: {
        subject: 'Dernière chance! ⏰ Le formulaire expire bientôt',
        template: 'reminder-second'
      }
    };

    const config = templates[type];
    const fromUser = await User.findById(invitation.fromUserId);
    
    const html = await this.renderTemplate(config.template, {
      fromName: fromUser.firstName,
      link: `${process.env.APP_BASE_URL}/invite/${invitation.token}`,
      daysLeft: Math.ceil((invitation.expiresAt - Date.now()) / (1000 * 60 * 60 * 24))
    });

    return this.client.emails.send({
      from: this.from,
      to: invitation.toEmail,
      subject: config.subject,
      html
    });
  }

  /**
   * Template renderer
   */
  async renderTemplate(templateName, data) {
    const templatePath = path.join(
      __dirname, 
      '../templates/emails', 
      `${templateName}.html`
    );
    
    let html = await fs.readFile(templatePath, 'utf-8');
    
    // Remplacer variables
    Object.keys(data).forEach(key => {
      html = html.replace(new RegExp(`{{${key}}}`, 'g'), data[key]);
    });
    
    return html;
  }

  /**
   * Formatter le mois
   */
  formatMonth(monthStr) {
    const [year, month] = monthStr.split('-');
    const months = [
      'janvier', 'février', 'mars', 'avril', 'mai', 'juin',
      'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'
    ];
    return `${months[parseInt(month) - 1]} ${year}`;
  }
}

module.exports = new EmailService();
```

#### Après-midi (4h)
- Créer templates HTML emails
- Configurer webhooks (bounce, unsubscribe)
- Tests envoi réel

### Jour 7 : Templates & Tests

#### Matin (4h)
- Designer templates responsive
- Template invitation
- Template reminder 1 & 2
- Template handshake

#### Après-midi (4h)
- Tests envoi batch
- Gestion erreurs/retry
- Documentation service email

---

## 🎨 Phase 4 : Frontend (Jours 8-10)

### Jour 8 : Dashboard Universel

#### Matin (4h)
- Transformer admin.html → dashboard.html
- Adapter pour tous les users
- Ajouter navigation par rôle

#### Après-midi (4h)
- Créer composant ContactList
- Créer composant HandshakeNotifications
- Intégration avec APIs

### Jour 9 : Gestion Contacts & Soumissions

#### Matin (4h)
```html
<!-- contacts.html -->
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Mes Contacts - Form-a-Friend</title>
  <link rel="stylesheet" href="/css/faf-base.css">
</head>
<body>
  <div class="container">
    <h1>Mes Contacts</h1>
    
    <!-- Statistiques -->
    <div class="stats-bar">
      <div class="stat">
        <span class="stat-value" id="totalContacts">0</span>
        <span class="stat-label">Contacts</span>
      </div>
      <div class="stat">
        <span class="stat-value" id="responseRate">0%</span>
        <span class="stat-label">Taux de réponse</span>
      </div>
    </div>

    <!-- Actions -->
    <div class="actions">
      <button id="addContact" class="btn btn-primary">
        + Ajouter un contact
      </button>
      <button id="importCSV" class="btn btn-secondary">
        📥 Importer CSV
      </button>
    </div>

    <!-- Liste contacts -->
    <div id="contactsList" class="contacts-grid">
      <!-- Généré dynamiquement -->
    </div>

    <!-- Handshakes en attente -->
    <div id="pendingHandshakes" class="notifications">
      <!-- Généré dynamiquement -->
    </div>
  </div>

  <script type="module">
    import { ContactManager } from '/js/modules/contacts.js';
    const manager = new ContactManager();
    manager.initialize();
  </script>
</body>
</html>
```

#### Après-midi (4h)
- Adapter form.html avec champ libre
- Créer logique soumission unique
- Auto-save et validation

### Jour 10 : Vue 1-vs-1 & Intégration

#### Matin (4h)
```html
<!-- compare.html -->
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Comparaison - Form-a-Friend</title>
  <link rel="stylesheet" href="/css/compare.css">
</head>
<body>
  <div class="comparison-container">
    <!-- Header avec navigation mois -->
    <header class="compare-header">
      <button id="prevMonth">← Mois précédent</button>
      <h1 id="currentMonth">Janvier 2025</h1>
      <button id="nextMonth">Mois suivant →</button>
    </header>

    <!-- Vue 2 colonnes -->
    <div class="comparison-view">
      <!-- Colonne contact -->
      <div class="column left">
        <h2 id="contactName">Alice</h2>
        <div id="contactResponses" class="responses">
          <!-- Réponses du contact -->
        </div>
      </div>

      <!-- Séparateur visuel -->
      <div class="divider"></div>

      <!-- Colonne user -->
      <div class="column right">
        <h2>Mes réponses</h2>
        <div id="myResponses" class="responses">
          <!-- Mes réponses -->
        </div>
      </div>
    </div>
  </div>

  <script type="module">
    import { ComparisonView } from '/js/modules/comparison.js';
    const view = new ComparisonView();
    view.initialize();
  </script>
</body>
</html>
```

#### Après-midi (4h)
- Tests intégration complète
- Responsive mobile
- **MILESTONE : Interface fonctionnelle**

---

## 🤖 Phase 5 : Automatisation (Jours 11-12)

### Jour 11 : Scheduler

#### Matin (4h)
```bash
npm install node-cron
```

**schedulerService.js**
```javascript
const cron = require('node-cron');
const InvitationService = require('./invitationService');
const EmailService = require('./emailService');

class SchedulerService {
  constructor() {
    this.jobs = new Map();
  }

  /**
   * Initialiser tous les jobs
   */
  initialize() {
    // Envoi mensuel
    this.scheduleMonthlyInvitations();
    
    // Relances quotidiennes
    this.scheduleReminders();
    
    // Nettoyage hebdomadaire
    this.scheduleCleanup();
    
    console.log('📅 Scheduler initialisé avec succès');
  }

  /**
   * Envoi mensuel le 5 à 18h
   */
  scheduleMonthlyInvitations() {
    const job = cron.schedule('0 18 5 * *', async () => {
      console.log('🚀 Démarrage envoi mensuel...');
      
      try {
        const stats = await this.sendMonthlyInvitations();
        console.log('✅ Envoi terminé:', stats);
      } catch (error) {
        console.error('❌ Erreur envoi mensuel:', error);
      }
    }, {
      timezone: "Europe/Paris",
      scheduled: true
    });
    
    this.jobs.set('monthly', job);
  }

  /**
   * Process envoi pour tous les users
   */
  async sendMonthlyInvitations() {
    const users = await User.find({ 
      'metadata.isActive': true 
    });
    
    const stats = {
      totalUsers: users.length,
      totalInvitations: 0,
      errors: []
    };

    for (const user of users) {
      try {
        const contacts = await Contact.find({
          ownerId: user._id,
          status: 'active'
        });

        for (const contact of contacts) {
          const invitation = await InvitationService.create({
            fromUserId: user._id,
            toEmail: contact.email,
            toUserId: contact.contactUserId,
            month: this.getCurrentMonth()
          });

          await EmailService.sendInvitation(
            invitation,
            user,
            contact
          );

          stats.totalInvitations++;
        }
      } catch (error) {
        stats.errors.push({ user: user._id, error: error.message });
      }
    }

    return stats;
  }

  /**
   * Relances J+3 et J+7
   */
  scheduleReminders() {
    const job = cron.schedule('0 10,18 * * *', async () => {
      console.log('🔔 Vérification des relances...');
      
      const now = new Date();
      const threeDaysAgo = new Date(now - 3 * 24 * 60 * 60 * 1000);
      const sevenDaysAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);

      // Premier rappel (J+3)
      const firstReminders = await Invitation.find({
        'tracking.sentAt': { 
          $gte: new Date(threeDaysAgo.setHours(0,0,0,0)),
          $lt: new Date(threeDaysAgo.setHours(23,59,59,999))
        },
        status: { $in: ['sent', 'opened'] },
        'reminders.0': { $exists: false }
      });

      for (const invitation of firstReminders) {
        await EmailService.sendReminder(invitation, 'first');
        invitation.reminders.push({
          type: 'first',
          sentAt: now
        });
        await invitation.save();
      }

      // Deuxième rappel (J+7)
      const secondReminders = await Invitation.find({
        'tracking.sentAt': {
          $gte: new Date(sevenDaysAgo.setHours(0,0,0,0)),
          $lt: new Date(sevenDaysAgo.setHours(23,59,59,999))
        },
        status: { $in: ['sent', 'opened'] },
        'reminders.0': { $exists: true },
        'reminders.1': { $exists: false }
      });

      for (const invitation of secondReminders) {
        await EmailService.sendReminder(invitation, 'second');
        invitation.reminders.push({
          type: 'second',
          sentAt: now
        });
        await invitation.save();
      }

      console.log(`✅ Relances: ${firstReminders.length} J+3, ${secondReminders.length} J+7`);
    });

    this.jobs.set('reminders', job);
  }

  /**
   * Nettoyage des données expirées
   */
  scheduleCleanup() {
    const job = cron.schedule('0 3 * * 0', async () => {
      console.log('🧹 Nettoyage hebdomadaire...');
      
      // Supprimer invitations expirées
      const result = await Invitation.deleteMany({
        expiresAt: { $lt: new Date() },
        status: { $ne: 'submitted' }
      });
      
      console.log(`✅ ${result.deletedCount} invitations expirées supprimées`);
    });

    this.jobs.set('cleanup', job);
  }

  /**
   * Obtenir le mois actuel
   */
  getCurrentMonth() {
    return new Date().toISOString().slice(0, 7);
  }

  /**
   * Arrêter tous les jobs
   */
  shutdown() {
    for (const [name, job] of this.jobs) {
      job.stop();
      console.log(`⏹️ Job ${name} arrêté`);
    }
  }
}

module.exports = new SchedulerService();
```

#### Après-midi (4h)
- Intégrer scheduler dans app.js
- Tests cron expressions
- Logs et monitoring

### Jour 12 : Tests Automatisation

#### Matin (4h)
- Simuler cycle mensuel complet
- Tester relances
- Vérifier emails

#### Après-midi (4h)
- Optimisations performance
- Gestion erreurs
- Documentation

---

## 🔄 Phase 6 : Migration & Tests (Jours 13-15)

### Jour 13 : Migration des Données

#### Matin (4h)
**migrate.js**
```javascript
const mongoose = require('mongoose');
const Response = require('./models/Response');
const User = require('./models/User');
const Submission = require('./models/Submission');

async function migrate() {
  console.log('🔄 Démarrage migration...');
  
  // 1. Créer Users pour chaque name unique
  const names = await Response.distinct('name');
  const userMap = new Map();
  
  for (const name of names) {
    const username = name.toLowerCase().replace(/\s+/g, '_');
    const email = `${username}@legacy.form-a-friend.com`;
    
    const user = await User.create({
      username,
      email,
      password: crypto.randomBytes(32).toString('hex'),
      migrationData: {
        legacyName: name,
        migratedAt: new Date(),
        source: 'migration'
      }
    });
    
    userMap.set(name, user._id);
    console.log(`✅ User créé: ${username}`);
  }
  
  // 2. Convertir Responses en Submissions
  const responses = await Response.find();
  
  for (const response of responses) {
    const userId = userMap.get(response.name);
    
    await Submission.create({
      userId,
      month: response.month,
      responses: response.responses,
      submittedAt: response.createdAt,
      completionRate: 100
    });
  }
  
  console.log(`✅ Migration terminée: ${responses.length} réponses converties`);
}

// Exécuter
migrate()
  .then(() => process.exit(0))
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
```

#### Après-midi (4h)
- Exécuter migration en test
- Vérifier intégrité données
- Rollback plan

### Jour 14 : Tests Complets

#### Matin (4h)
- Tests end-to-end
- Tests de charge
- Tests sécurité

#### Après-midi (4h)
- Bug fixes
- Optimisations
- Documentation utilisateur

### Jour 15 : Préparation Production

#### Matin (4h)
- Configuration production
- Variables environnement
- Monitoring setup

#### Après-midi (4h)
- Déploiement staging
- Tests finaux
- **MILESTONE : Production ready**

---

## ✅ Checklist de Lancement

### Avant le lancement
- [ ] Tous les tests passent (backend + frontend)
- [ ] Migration des données validée
- [ ] Service email configuré et testé
- [ ] Scheduler vérifié
- [ ] SSL/HTTPS activé
- [ ] Backup base de données
- [ ] Monitoring configuré
- [ ] Documentation complète

### Jour du lancement
- [ ] Backup final
- [ ] Déployer en production
- [ ] Vérifier tous les services
- [ ] Envoyer emails test
- [ ] Monitorer les logs
- [ ] Préparer rollback si nécessaire

### Post-lancement (J+1)
- [ ] Vérifier métriques
- [ ] Analyser logs erreurs
- [ ] Collecter feedback users
- [ ] Planifier itérations

---

## 📊 Métriques de Succès

### Techniques
- Temps de réponse < 200ms
- Uptime > 99%
- 0 erreurs critiques

### Business
- 50% users créent compte (vs token)
- 60% taux de réponse moyen
- 30% handshakes acceptés

### Utilisateur
- Temps remplissage < 5 min
- NPS > 8
- 0 plainte confidentialité

---

*Plan d'implémentation Form-a-Friend v1.0*