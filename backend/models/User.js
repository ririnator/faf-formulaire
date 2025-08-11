const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { APP_CONSTANTS } = require('../constants');
const Schema = mongoose.Schema;

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
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Email invalide']
  },
  password: { 
    type: String, 
    required: true,
    minlength: 6
  },
  displayName: { 
    type: String, 
    required: true,
    maxlength: 50,
    trim: true
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  profile: {
    firstName: { type: String, trim: true },
    lastName: { type: String, trim: true },
    dateOfBirth: { type: Date },
    profession: { type: String, trim: true },
    location: { type: String, trim: true }
  },
  metadata: {
    isActive: { type: Boolean, default: true },
    emailVerified: { type: Boolean, default: false },
    lastActive: { type: Date, default: Date.now },
    responseCount: { type: Number, default: 0 },
    registeredAt: { type: Date, default: Date.now }
  },
  
  // Champs de migration pour compatibilité
  migrationData: {
    legacyName: String, // Nom original si migré depuis l'ancien système
    migratedAt: Date,
    source: { type: String, enum: ['registration', 'migration'], default: 'registration' }
  }
});

// Index pour les performances (email et username ont déjà unique: true)
UserSchema.index({ 'metadata.lastActive': -1 });

// Hash password avant sauvegarde
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(APP_CONSTANTS.BCRYPT_SALT_ROUNDS);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Méthode pour vérifier le mot de passe
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Méthode pour mettre à jour la dernière activité
UserSchema.methods.updateLastActive = function() {
  this.metadata.lastActive = new Date();
  return this.save();
};

// Méthode pour incrémenter le compteur de réponses
UserSchema.methods.incrementResponseCount = function() {
  this.metadata.responseCount += 1;
  return this.save();
};

// Méthode pour retourner les données publiques (sans password)
UserSchema.methods.toPublicJSON = function() {
  return {
    id: this._id,
    username: this.username,
    email: this.email,
    displayName: this.displayName,
    role: this.role,
    profile: this.profile,
    metadata: {
      isActive: this.metadata.isActive,
      emailVerified: this.metadata.emailVerified,
      lastActive: this.metadata.lastActive,
      responseCount: this.metadata.responseCount,
      registeredAt: this.metadata.registeredAt
    }
  };
};

module.exports = mongoose.model('User', UserSchema);