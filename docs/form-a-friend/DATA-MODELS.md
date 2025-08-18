# Form-a-Friend - Modèles de Données

## 📋 Table des matières
1. [Vue d'ensemble](#vue-densemble)
2. [Modèles Existants](#modèles-existants)
3. [Nouveaux Modèles](#nouveaux-modèles)
4. [Relations & Index](#relations--index)
5. [Validation & Contraintes](#validation--contraintes)
6. [Migration des Données](#migration-des-données)

---

## 🗺️ Vue d'ensemble

### Schéma Relationnel
```
Users (1) ──────────< (N) Contacts
  │                         │
  │                         │ (handshake optionnel)
  │                         ▼
  │                    Handshakes
  │                         │
  ▼                         │
Submissions (1/mois)        │
  │                         │
  └─────> (N) Invitations <─┘
              │
              └─> Tokens uniques
```

### Flux de Données
1. **User** ajoute **Contacts** (email)
2. Si contact a un compte → Proposition **Handshake**
3. Chaque mois → Génération **Invitations** vers contacts actifs
4. **Users** remplissent leur **Submission** unique
5. Vues 1-vs-1 basées sur permissions **Handshake**

---

## 📊 Modèles Existants (À Adapter)

### User.js ✅ Existant - Enrichir

#### Schema Actuel
```javascript
const UserSchema = new Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    minlength: 3,
    maxlength: 30,
    trim: true
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true
  },
  password: { 
    type: String, 
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  profile: {
    firstName: String,
    lastName: String,
    dateOfBirth: Date,
    profession: String,
    location: String
  },
  metadata: {
    isActive: { type: Boolean, default: true },
    emailVerified: { type: Boolean, default: false },
    lastActive: { type: Date, default: Date.now },
    responseCount: { type: Number, default: 0 },
    registeredAt: { type: Date, default: Date.now }
  }
});
```

#### Enrichissements À Ajouter
```javascript
// Ajouter au schema User existant :
preferences: {
  // Paramètres d'envoi
  sendTime: { 
    type: String, 
    default: "18:00",
    validate: {
      validator: (v) => /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(v),
      message: 'Format heure invalide (HH:MM)'
    }
  },
  timezone: { 
    type: String, 
    default: "Europe/Paris" 
  },
  sendDay: { 
    type: Number, 
    default: 5, 
    min: 1, 
    max: 28 
  },
  
  // Paramètres de notification
  reminderSettings: {
    firstReminder: { type: Boolean, default: true },
    secondReminder: { type: Boolean, default: true },
    reminderChannel: { 
      type: String, 
      enum: ['email', 'sms', 'push'], 
      default: 'email' 
    }
  },
  
  // Paramètres d'email
  emailTemplate: {
    type: String,
    enum: ['friendly', 'professional', 'fun'],
    default: 'friendly'
  },
  customMessage: { 
    type: String, 
    maxlength: 500 
  }
},

// Statistiques utilisateur
statistics: {
  totalSubmissions: { type: Number, default: 0 },
  totalContacts: { type: Number, default: 0 },
  averageResponseRate: { type: Number, default: 0 },
  bestResponseMonth: {
    month: String,
    rate: Number
  },
  joinedCycles: { type: Number, default: 0 }
}
```

#### Index Existants (À Conserver)
```javascript
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ username: 1 }, { unique: true });
UserSchema.index({ 'metadata.lastActive': -1 });
```

### Response.js ❌ Existant - Remplacer par Submission

#### Schema Actuel (Legacy)
```javascript
const ResponseSchema = new Schema({
  name: String,                    // → userId
  responses: [{ question, answer }], // → conserver
  month: String,                   // → conserver
  isAdmin: Boolean,                // → déduire du role User
  token: String,                   // → migrer vers Invitation
  createdAt: Date                  // → submittedAt
});
```

#### Migration Strategy
1. **Phase 1** : Coexistence (garder Response pour compatibilité)
2. **Phase 2** : Créer Submission en parallèle
3. **Phase 3** : Migrer données Response → Submission
4. **Phase 4** : Supprimer Response

---

## 🆕 Nouveaux Modèles

### Contact.js 🆕 Principal

```javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ContactSchema = new Schema({
  // Propriétaire du contact
  ownerId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  
  // Informations de contact
  email: { 
    type: String, 
    required: true, 
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Email invalide']
  },
  firstName: { 
    type: String, 
    trim: true,
    maxlength: 100
  },
  lastName: { 
    type: String, 
    trim: true,
    maxlength: 100
  },
  
  // Relation avec User (si compte existe)
  contactUserId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User',
    sparse: true
  },
  
  // Statut du contact
  status: {
    type: String,
    enum: ['pending', 'active', 'opted_out', 'bounced', 'blocked'],
    default: 'pending'
  },
  
  // Handshake (pour contacts avec compte)
  handshakeId: {
    type: Schema.Types.ObjectId,
    ref: 'Handshake',
    sparse: true
  },
  
  // Organisation
  tags: [{ 
    type: String, 
    trim: true,
    maxlength: 50
  }],
  notes: { 
    type: String, 
    maxlength: 1000 
  },
  
  // Tracking des interactions
  tracking: {
    addedAt: { type: Date, default: Date.now },
    lastSentAt: Date,
    lastOpenedAt: Date,
    lastSubmittedAt: Date,
    
    // Statistiques
    invitationsSent: { type: Number, default: 0 },
    responsesReceived: { type: Number, default: 0 },
    responseRate: { 
      type: Number, 
      default: 0, 
      min: 0, 
      max: 100 
    },
    averageResponseTime: Number, // en heures
    
    // Dates importantes
    firstResponseAt: Date,
    lastInteractionAt: Date
  },
  
  // Métadonnées
  source: {
    type: String,
    enum: ['manual', 'csv', 'invitation', 'handshake'],
    default: 'manual'
  },
  customFields: {
    type: Map,
    of: String
  }
}, {
  timestamps: true
});

// Index composé unique (un email par owner)
ContactSchema.index({ ownerId: 1, email: 1 }, { unique: true });

// Index pour recherches
ContactSchema.index({ firstName: 'text', lastName: 'text' });
ContactSchema.index({ tags: 1 });
ContactSchema.index({ status: 1, 'tracking.lastSentAt': -1 });

// Méthodes d'instance
ContactSchema.methods.updateTracking = function(event, metadata = {}) {
  const now = new Date();
  
  switch(event) {
    case 'sent':
      this.tracking.lastSentAt = now;
      this.tracking.invitationsSent++;
      break;
    case 'opened':
      this.tracking.lastOpenedAt = now;
      break;
    case 'submitted':
      this.tracking.lastSubmittedAt = now;
      this.tracking.responsesReceived++;
      this.tracking.lastInteractionAt = now;
      
      if (!this.tracking.firstResponseAt) {
        this.tracking.firstResponseAt = now;
      }
      
      // Calculer temps de réponse
      if (this.tracking.lastSentAt && metadata.responseTime) {
        this.tracking.averageResponseTime = metadata.responseTime;
      }
      break;
  }
  
  // Recalculer taux de réponse
  if (this.tracking.invitationsSent > 0) {
    this.tracking.responseRate = Math.round(
      (this.tracking.responsesReceived / this.tracking.invitationsSent) * 100
    );
  }
  
  return this.save();
};

ContactSchema.methods.canReceiveInvitation = function() {
  return this.status === 'active' && 
         this.status !== 'opted_out' && 
         this.status !== 'bounced';
};

module.exports = mongoose.model('Contact', ContactSchema);
```

### Submission.js 🆕 Central

```javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SubmissionSchema = new Schema({
  // User qui a soumis
  userId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  
  // Période
  month: { 
    type: String, 
    required: true,
    match: [/^\d{4}-\d{2}$/, 'Format mois invalide (YYYY-MM)']
  },
  
  // Réponses au formulaire
  responses: [{
    questionId: { 
      type: String, 
      required: true 
    },
    type: { 
      type: String, 
      enum: ['text', 'photo', 'radio'],
      required: true
    },
    answer: { 
      type: String,
      maxlength: 10000
    },
    photoUrl: String,
    photoCaption: { 
      type: String,
      maxlength: 500
    },
    _id: false
  }],
  
  // Champ libre
  freeText: { 
    type: String,
    maxlength: 5000
  },
  
  // Métadonnées de soumission
  completionRate: { 
    type: Number, 
    default: 0,
    min: 0,
    max: 100
  },
  isComplete: { 
    type: Boolean, 
    default: false 
  },
  
  // Timestamps
  submittedAt: { 
    type: Date, 
    default: Date.now 
  },
  lastModifiedAt: Date,
  
  // Version du formulaire
  formVersion: { 
    type: String, 
    default: 'v1' 
  }
}, {
  timestamps: true
});

// Index unique : une soumission par user par mois
SubmissionSchema.index({ userId: 1, month: 1 }, { unique: true });

// Index pour performances
SubmissionSchema.index({ month: 1, submittedAt: -1 });
SubmissionSchema.index({ 'userId': 1, 'submittedAt': -1 });

// Méthodes d'instance
SubmissionSchema.methods.calculateCompletion = function() {
  const totalQuestions = 10; // 5 text + 5 photo
  let completed = 0;
  
  this.responses.forEach(response => {
    if (response.answer || response.photoUrl) {
      completed++;
    }
  });
  
  if (this.freeText && this.freeText.trim()) {
    completed += 0.5; // Bonus pour champ libre
  }
  
  this.completionRate = Math.min(100, Math.round((completed / totalQuestions) * 100));
  this.isComplete = this.completionRate >= 80;
  
  return this.completionRate;
};

SubmissionSchema.methods.getPublicData = function() {
  return {
    month: this.month,
    responses: this.responses,
    freeText: this.freeText,
    completionRate: this.completionRate,
    submittedAt: this.submittedAt
  };
};

// Pre-save hook
SubmissionSchema.pre('save', function(next) {
  this.lastModifiedAt = new Date();
  this.calculateCompletion();
  next();
});

module.exports = mongoose.model('Submission', SubmissionSchema);
```

### Invitation.js 🆕 Orchestration

```javascript
const mongoose = require('mongoose');
const crypto = require('crypto');
const Schema = mongoose.Schema;

const InvitationSchema = new Schema({
  // Expéditeur
  fromUserId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  
  // Destinataire
  toEmail: { 
    type: String, 
    required: true,
    lowercase: true
  },
  toUserId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User'
  },
  
  // Période
  month: { 
    type: String, 
    required: true,
    match: [/^\d{4}-\d{2}$/, 'Format mois invalide']
  },
  
  // Token d'accès unique
  token: { 
    type: String, 
    required: true,
    unique: true,
    default: () => crypto.randomBytes(32).toString('hex')
  },
  shortCode: { 
    type: String,
    default: () => Math.random().toString(36).substring(2, 8).toUpperCase()
  },
  
  // Type d'invitation
  type: {
    type: String,
    enum: ['user', 'external'],
    default: 'external'
  },
  
  // Statut
  status: {
    type: String,
    enum: [
      'queued',     // Créée, pas encore envoyée
      'sent',       // Envoyée
      'opened',     // Lien ouvert
      'started',    // Formulaire commencé
      'submitted',  // Soumission complète
      'expired',    // Expirée
      'bounced',    // Email bounced
      'cancelled'   // Annulée
    ],
    default: 'queued'
  },
  
  // Tracking des interactions
  tracking: {
    createdAt: { type: Date, default: Date.now },
    sentAt: Date,
    openedAt: Date,
    startedAt: Date,
    submittedAt: Date,
    
    // Détails techniques
    ipAddress: String,
    userAgent: String,
    referrer: String,
    
    // Email tracking
    emailProvider: String,
    bounceReason: String,
    unsubscribeReason: String
  },
  
  // Relances
  reminders: [{
    type: { 
      type: String, 
      enum: ['first', 'second', 'final'],
      required: true
    },
    sentAt: { 
      type: Date, 
      required: true 
    },
    opened: { type: Boolean, default: false },
    _id: false
  }],
  
  // Expiration
  expiresAt: { 
    type: Date,
    default: () => new Date(Date.now() + 60 * 24 * 60 * 60 * 1000) // 60 jours
  },
  
  // Réponse liée (une fois soumise)
  submissionId: { 
    type: Schema.Types.ObjectId, 
    ref: 'Submission' 
  },
  
  // Métadonnées
  metadata: {
    template: String,
    customMessage: String,
    priority: { 
      type: String, 
      enum: ['low', 'normal', 'high'],
      default: 'normal'
    }
  }
}, {
  timestamps: true
});

// Index
InvitationSchema.index({ token: 1 }, { unique: true });
InvitationSchema.index({ month: 1, status: 1 });
InvitationSchema.index({ expiresAt: 1 });
InvitationSchema.index({ fromUserId: 1, toEmail: 1, month: 1 }, { unique: true });

// Méthodes d'instance
InvitationSchema.methods.isExpired = function() {
  return new Date() > this.expiresAt;
};

InvitationSchema.methods.canSendReminder = function(type) {
  const existing = this.reminders.find(r => r.type === type);
  return !existing && !this.isExpired() && this.status !== 'submitted';
};

InvitationSchema.methods.markAction = function(action, metadata = {}) {
  const now = new Date();
  
  switch(action) {
    case 'sent':
      this.tracking.sentAt = now;
      this.status = 'sent';
      break;
    case 'opened':
      if (!this.tracking.openedAt) {
        this.tracking.openedAt = now;
        this.status = 'opened';
      }
      break;
    case 'started':
      if (!this.tracking.startedAt) {
        this.tracking.startedAt = now;
        this.status = 'started';
      }
      break;
    case 'submitted':
      this.tracking.submittedAt = now;
      this.status = 'submitted';
      this.submissionId = metadata.submissionId;
      break;
  }
  
  // Metadata tracking
  if (metadata.ipAddress) this.tracking.ipAddress = metadata.ipAddress;
  if (metadata.userAgent) this.tracking.userAgent = metadata.userAgent;
  
  return this.save();
};

// Static methods
InvitationSchema.statics.findPendingReminders = function(type, daysAgo) {
  const cutoffDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
  
  return this.find({
    'tracking.sentAt': { $lte: cutoffDate },
    status: { $in: ['sent', 'opened', 'started'] },
    [`reminders.type`]: { $ne: type }
  });
};

module.exports = mongoose.model('Invitation', InvitationSchema);
```

### Handshake.js 🆕 Relations

```javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const HandshakeSchema = new Schema({
  // Demandeur
  requesterId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true
  },
  
  // Cible
  targetId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User', 
    required: true
  },
  
  // Statut
  status: {
    type: String,
    enum: ['pending', 'accepted', 'declined', 'blocked', 'expired'],
    default: 'pending'
  },
  
  // Dates
  requestedAt: { 
    type: Date, 
    default: Date.now 
  },
  respondedAt: Date,
  expiresAt: { 
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 jours
  },
  
  // Message optionnel
  message: { 
    type: String,
    maxlength: 500
  },
  responseMessage: { 
    type: String,
    maxlength: 500
  },
  
  // Métadonnées
  metadata: {
    initiatedBy: { 
      type: String, 
      enum: ['manual', 'contact_add', 'invitation_response'],
      default: 'manual'
    },
    mutualContacts: [{ 
      type: Schema.Types.ObjectId, 
      ref: 'User' 
    }]
  }
}, {
  timestamps: true
});

// Index unique : une demande par paire d'utilisateurs
HandshakeSchema.index({ requesterId: 1, targetId: 1 }, { unique: true });

// Index pour recherches
HandshakeSchema.index({ targetId: 1, status: 1 });
HandshakeSchema.index({ requesterId: 1, status: 1 });
HandshakeSchema.index({ expiresAt: 1 });

// Méthodes d'instance
HandshakeSchema.methods.accept = function(responseMessage) {
  this.status = 'accepted';
  this.respondedAt = new Date();
  this.responseMessage = responseMessage;
  
  return this.save();
};

HandshakeSchema.methods.decline = function(responseMessage) {
  this.status = 'declined';
  this.respondedAt = new Date();
  this.responseMessage = responseMessage;
  
  return this.save();
};

HandshakeSchema.methods.isExpired = function() {
  return new Date() > this.expiresAt;
};

// Static methods
HandshakeSchema.statics.createMutual = async function(userId1, userId2, initiator) {
  // Vérifier pas déjà existant
  const existing = await this.findOne({
    $or: [
      { requesterId: userId1, targetId: userId2 },
      { requesterId: userId2, targetId: userId1 }
    ]
  });
  
  if (existing) {
    throw new Error('Handshake déjà existant');
  }
  
  return this.create({
    requesterId: initiator === 1 ? userId1 : userId2,
    targetId: initiator === 1 ? userId2 : userId1,
    metadata: { initiatedBy: 'manual' }
  });
};

HandshakeSchema.statics.checkPermission = async function(userId1, userId2) {
  const handshake = await this.findOne({
    $or: [
      { requesterId: userId1, targetId: userId2, status: 'accepted' },
      { requesterId: userId2, targetId: userId1, status: 'accepted' }
    ]
  });
  
  return !!handshake;
};

module.exports = mongoose.model('Handshake', HandshakeSchema);
```

---

## 🔗 Relations & Index

### Relations Principales

#### 1. User ↔ Contact (1:N)
```javascript
// Un User peut avoir plusieurs Contacts
User.hasMany(Contact, { foreignKey: 'ownerId' })

// Un Contact appartient à un User
Contact.belongsTo(User, { foreignKey: 'ownerId' })
```

#### 2. Contact ↔ User (optionnel)
```javascript
// Un Contact peut référencer un User (si compte)
Contact.belongsTo(User, { 
  foreignKey: 'contactUserId',
  optional: true
})
```

#### 3. User ↔ Handshake (M:N via junction)
```javascript
// Handshake relie deux Users
Handshake.belongsTo(User, { foreignKey: 'requesterId' })
Handshake.belongsTo(User, { foreignKey: 'targetId' })
```

#### 4. User → Submission (1:1 par mois)
```javascript
// Une Submission par User par mois
User.hasMany(Submission, { foreignKey: 'userId' })
Submission.belongsTo(User, { foreignKey: 'userId' })
```

#### 5. User → Invitation (1:N)
```javascript
// Un User peut créer plusieurs Invitations
User.hasMany(Invitation, { foreignKey: 'fromUserId' })
Invitation.belongsTo(User, { foreignKey: 'fromUserId' })
```

### Index de Performance

#### Collections avec forte charge
```javascript
// Contacts - recherches fréquentes
{ ownerId: 1, status: 1 }           // Liste contacts actifs
{ ownerId: 1, email: 1 }            // Unique constraint
{ firstName: 'text' }               // Recherche nom
{ tags: 1 }                         // Filtre par tag

// Submissions - affichage vues
{ userId: 1, month: 1 }             // Unique + lookup
{ month: 1, submittedAt: -1 }       // Tri chronologique
{ userId: 1, submittedAt: -1 }      // Timeline user

// Invitations - relances & tracking
{ month: 1, status: 1 }             // Batch relances
{ token: 1 }                        // Accès public
{ expiresAt: 1 }                    // Cleanup
{ fromUserId: 1, toEmail: 1, month: 1 } // Unique

// Handshakes - permissions
{ targetId: 1, status: 1 }          // Notifications
{ requesterId: 1, targetId: 1 }     // Unique paire
```

---

## ✅ Validation & Contraintes

### Contraintes d'Unicité
```javascript
// Éviter duplicatas
Contact: { ownerId + email }        // Un email par propriétaire
Submission: { userId + month }      // Une soumission par mois
Invitation: { token }               // Token unique global
Invitation: { fromUserId + toEmail + month } // Une invitation par destinataire/mois
Handshake: { requesterId + targetId } // Une demande par paire
```

### Validation Métier
```javascript
// Contraintes business
- User ne peut pas s'ajouter comme Contact
- Handshake seulement entre Users avec compte
- Invitation expire si non utilisée (60j)
- Submission modifiable jusqu'à fin du mois
- Contact opted_out ne reçoit plus d'invitations
```

### Validation des Données
```javascript
// Formats requis
Email: RFC 5322 compliant
Month: YYYY-MM (ex: "2025-01")
Token: 64 chars hex
Time: HH:MM (24h format)
Status: Enum strict
Percentage: 0-100
Text fields: HTML escaped
```

---

## 🔄 Migration des Données

### Phase 1 : Préparation
```javascript
// 1. Créer collections vides
await db.createCollection('contacts');
await db.createCollection('submissions'); 
await db.createCollection('invitations');
await db.createCollection('handshakes');

// 2. Créer index en background
await db.contacts.createIndex({ ownerId: 1, email: 1 });
await db.submissions.createIndex({ userId: 1, month: 1 });
```

### Phase 2 : Migration Users
```javascript
// Enrichir Users existants
await User.updateMany({}, {
  $set: {
    preferences: {
      sendTime: "18:00",
      timezone: "Europe/Paris",
      sendDay: 5
    },
    statistics: {
      totalSubmissions: 0,
      totalContacts: 0,
      averageResponseRate: 0
    }
  }
});
```

### Phase 3 : Conversion Response → Submission
```javascript
// Créer Users pour noms uniques
const uniqueNames = await Response.distinct('name');
const userMap = new Map();

for (const name of uniqueNames) {
  const user = await User.create({
    username: name.replace(/\s/g, '_'),
    email: `${name.replace(/\s/g, '_')}@legacy.faf.com`,
    password: await bcrypt.hash(randomBytes(32), 10),
    migrationData: { legacyName: name }
  });
  userMap.set(name, user._id);
}

// Convertir réponses
const responses = await Response.find();
for (const response of responses) {
  await Submission.create({
    userId: userMap.get(response.name),
    month: response.month,
    responses: response.responses,
    submittedAt: response.createdAt,
    completionRate: 100
  });
}
```

### Phase 4 : Cleanup
```javascript
// Archiver anciennes données
await db.responses.renameCollection('responses_legacy_' + Date.now());

// Mettre à jour statistiques
await User.updateMany({}, {
  $inc: { 'statistics.totalSubmissions': 1 }
});
```

---

## 📊 Statistiques & Métriques

### Métriques par Collection

#### Users
- Actifs vs inactifs
- Taux de remplissage mensuel
- Préférences communes

#### Contacts
- Répartition par statut
- Taux de réponse moyen
- Source d'acquisition

#### Submissions
- Taux de complétion
- Temps de remplissage moyen
- Questions populaires

#### Invitations
- Taux d'ouverture
- Efficacité des relances
- Temps de réponse moyen

#### Handshakes
- Taux d'acceptation
- Temps de réponse moyen
- Motifs de refus

### Requêtes d'Analytics
```javascript
// Dashboard admin
db.submissions.aggregate([
  { $match: { month: "2025-01" } },
  { $group: { 
    _id: null,
    total: { $sum: 1 },
    avgCompletion: { $avg: "$completionRate" }
  }}
]);

// Taux de réponse par user
db.contacts.aggregate([
  { $match: { ownerId: userId } },
  { $group: {
    _id: "$ownerId",
    totalContacts: { $sum: 1 },
    avgResponseRate: { $avg: "$tracking.responseRate" }
  }}
]);
```

---

*Documentation complète des modèles de données Form-a-Friend*