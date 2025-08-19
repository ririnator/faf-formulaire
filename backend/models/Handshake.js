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

module.exports = mongoose.models.Handshake || mongoose.model('Handshake', HandshakeSchema);