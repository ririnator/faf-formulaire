const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ResponseSchema = new Schema({
  // PHASE 1 : Support dual - garder les deux systèmes
  name: { type: String },                         // LEGACY - sera déprécié
  userId: { 
    type: Schema.Types.ObjectId, 
    ref: 'User'                                   // NOUVEAU système
  },
  
  responses: [
    {
      question: String,
      answer: String
    }
  ],
  month: { type: String, required: true },        // ex. "2025-08"
  isAdmin: { type: Boolean, default: false },     // flag pour la réponse admin
  
  // PHASE 1 : Support dual
  token: { type: String }, // LEGACY - index unique créé explicitement plus bas
  authMethod: { 
    type: String, 
    enum: ['token', 'user'], 
    default: 'token' 
  },
  
  createdAt: { type: Date, default: Date.now }
});

// Index hybride pour la transition
ResponseSchema.index({ month: 1, userId: 1 }, { 
  unique: true, 
  sparse: true,
  partialFilterExpression: { authMethod: 'user' }
});

// Unique constraint for admin responses (one admin per month)
ResponseSchema.index(
  { month: 1, isAdmin: 1 },
  {
    unique: true,
    partialFilterExpression: { 
      isAdmin: true
    }
  }
);

// Additional index for name lookups  
ResponseSchema.index(
  { month: 1, isAdmin: 1, name: 1 },
  {
    partialFilterExpression: { 
      isAdmin: true, 
      authMethod: 'token'
    }
  }
);

// Index pour les queries courantes
ResponseSchema.index({ createdAt: -1 });
ResponseSchema.index({ token: 1 }, { unique: true, sparse: true }); // Index unique pour tokens
ResponseSchema.index({ userId: 1, createdAt: -1 }, { sparse: true });

// Index texte pour recherche sécurisée
ResponseSchema.index({ name: 'text' }, { 
  default_language: 'french',
  name: 'name_text_search'
});

module.exports = mongoose.models.Response || mongoose.model('Response', ResponseSchema);