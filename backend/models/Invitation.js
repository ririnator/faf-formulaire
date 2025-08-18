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
    },
    // Sécurité anti-transfert
    antiTransferCode: String,
    originalIp: String,
    originalUserAgent: String,
    securityLevel: {
      type: String,
      enum: ['low', 'medium', 'high'],
      default: 'medium'
    },
    // Gestion des modifications
    cancelledAt: Date,
    cancelReason: String,
    cancelledBy: { type: Schema.Types.ObjectId, ref: 'User' },
    extendedAt: Date,
    extendedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    additionalDays: Number
  }
}, {
  timestamps: true
});

// Index
InvitationSchema.index({ token: 1 }, { unique: true });
InvitationSchema.index({ month: 1, status: 1 });
InvitationSchema.index({ expiresAt: 1 });
InvitationSchema.index({ fromUserId: 1, toEmail: 1, month: 1 }, { unique: true });

// Optimized indexes for automated reminder processing
InvitationSchema.index({ 
  'tracking.sentAt': 1, 
  status: 1, 
  expiresAt: 1,
  'tracking.bounceCount': 1
}); // For efficient reminder candidate queries

InvitationSchema.index({ 
  status: 1, 
  'tracking.sentAt': -1 
}); // For status-based queries with recency

InvitationSchema.index({ 
  toEmail: 1, 
  month: 1, 
  status: 1 
}); // For contact response rate calculations

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