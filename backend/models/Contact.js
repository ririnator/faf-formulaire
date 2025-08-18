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
  
  // Statut de l'email (pour le webhook handling)
  emailStatus: {
    type: String,
    enum: ['active', 'sent', 'delivered', 'bounced_temporary', 'bounced_permanent', 'complained', 'unsubscribed'],
    default: 'active'
  },
  
  // Informations de bounce
  bounceCount: {
    type: Number,
    default: 0
  },
  lastBounceAt: Date,
  bounceReason: String,
  
  // Informations de complaint
  lastComplaintAt: Date,
  complaintReason: String,
  
  // Informations de delivery
  deliveryCount: {
    type: Number,
    default: 0
  },
  lastDeliveredAt: Date,
  
  // Opt-out management
  optedOut: {
    type: Boolean,
    default: false
  },
  optedOutAt: Date,
  optOutReason: {
    type: String,
    enum: ['manual_unsubscribe', 'spam_complaint', 'bounce_limit', 'admin_action'],
    sparse: true
  },
  
  // Email activity flags
  isActive: {
    type: Boolean,
    default: true
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

// Index pour email deliverability
ContactSchema.index({ emailStatus: 1 });
ContactSchema.index({ isActive: 1, optedOut: 1 });
ContactSchema.index({ bounceCount: 1, lastBounceAt: -1 });
ContactSchema.index({ email: 1, emailStatus: 1 }); // For webhook lookups

// Optimized indexes for automated monthly cycles
ContactSchema.index({ 
  ownerId: 1, 
  isActive: 1, 
  status: 1,
  'tracking.responseRate': -1 
}); // For efficient user contact retrieval with performance sorting

ContactSchema.index({ 
  ownerId: 1, 
  bounceCount: 1, 
  optedOut: 1 
}); // For filtering problematic contacts during automation

ContactSchema.index({ 
  'tracking.lastSentAt': -1, 
  status: 1 
}); // For cleanup operations and recency filtering

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
      if (this.tracking.lastSentAt) {
        if (metadata.responseTime) {
          this.tracking.averageResponseTime = metadata.responseTime;
        } else {
          // Calculer automatiquement si pas fourni
          const responseTimeHours = (now - this.tracking.lastSentAt.getTime()) / (1000 * 60 * 60);
          this.tracking.averageResponseTime = Math.round(responseTimeHours * 100) / 100;
        }
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
  return (this.status === 'active' || this.status === 'pending') && 
         this.status !== 'opted_out' && 
         this.status !== 'bounced' &&
         this.status !== 'blocked' &&
         !this.optedOut &&
         this.isActive &&
         this.emailStatus !== 'bounced_permanent' &&
         this.emailStatus !== 'complained' &&
         this.emailStatus !== 'unsubscribed';
};

// Méthode pour vérifier la délivrabilité email
ContactSchema.methods.isEmailDeliverable = function() {
  return this.isActive && 
         !this.optedOut &&
         this.emailStatus !== 'bounced_permanent' &&
         this.emailStatus !== 'complained' &&
         this.emailStatus !== 'unsubscribed' &&
         this.bounceCount < 5; // Maximum 5 bounces before blocking
};

// Méthode pour marquer comme bounced
ContactSchema.methods.markAsBounced = function(reason, isPermanent = false, timestamp = new Date()) {
  this.emailStatus = isPermanent ? 'bounced_permanent' : 'bounced_temporary';
  this.lastBounceAt = timestamp;
  this.bounceReason = reason;
  this.bounceCount = (this.bounceCount || 0) + 1;
  
  if (isPermanent || this.bounceCount >= 5) {
    this.isActive = false;
    this.status = 'bounced';
  }
  
  return this.save();
};

// Méthode pour marquer comme complained
ContactSchema.methods.markAsComplained = function(reason, timestamp = new Date()) {
  this.emailStatus = 'complained';
  this.lastComplaintAt = timestamp;
  this.complaintReason = reason;
  this.isActive = false;
  this.optedOut = true;
  this.optedOutAt = timestamp;
  this.optOutReason = 'spam_complaint';
  this.status = 'opted_out';
  
  return this.save();
};

// Méthode pour marquer comme delivered
ContactSchema.methods.markAsDelivered = function(timestamp = new Date()) {
  this.emailStatus = 'delivered';
  this.lastDeliveredAt = timestamp;
  this.deliveryCount = (this.deliveryCount || 0) + 1;
  
  // Reset bounce count on successful delivery
  if (this.bounceCount > 0 && this.emailStatus.startsWith('bounced_temporary')) {
    this.bounceCount = 0;
  }
  
  return this.save();
};

// Méthode pour opt-out
ContactSchema.methods.optOut = function(reason = 'manual_unsubscribe', timestamp = new Date()) {
  this.optedOut = true;
  this.optedOutAt = timestamp;
  this.optOutReason = reason;
  this.isActive = false;
  this.status = 'opted_out';
  this.emailStatus = 'unsubscribed';
  
  return this.save();
};

// Méthode pour réactiver un contact
ContactSchema.methods.reactivate = function(adminNote = null) {
  if (this.emailStatus === 'bounced_permanent' || this.emailStatus === 'complained') {
    throw new Error('Cannot reactivate permanently bounced or complained contacts');
  }
  
  this.isActive = true;
  this.optedOut = false;
  this.status = 'active';
  this.emailStatus = 'active';
  
  if (adminNote) {
    this.notes = (this.notes || '') + `\n[${new Date().toISOString()}] Réactivé par admin: ${adminNote}`;
  }
  
  return this.save();
};

module.exports = mongoose.model('Contact', ContactSchema);