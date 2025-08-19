
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
    lastLoginAt: { type: Date }, // For session cleanup service
    responseCount: { type: Number, default: 0 },
    registeredAt: { type: Date, default: Date.now }
  },
  
  // Préférences utilisateur selon DATA-MODELS.md
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
  
  // Statistiques utilisateur selon DATA-MODELS.md
  statistics: {
    totalSubmissions: { type: Number, default: 0 },
    totalContacts: { type: Number, default: 0 },
    averageResponseRate: { type: Number, default: 0 },
    bestResponseMonth: {
      month: String,
      rate: Number
    },
    joinedCycles: { type: Number, default: 0 }
  },
  
  // Champs de migration pour compatibilité selon DATA-MODELS.md
  migrationData: {
    legacyName: String, // Nom original si migré depuis l'ancien système
    migratedAt: Date,
    source: { type: String, enum: ['registration', 'migration'], default: 'registration' }
  }
});

// Index pour les performances (email et username ont déjà unique: true)
UserSchema.index({ 'metadata.lastActive': -1 });
UserSchema.index({ 'metadata.lastLoginAt': -1 }); // For cleanup service queries

// Index pour les nouveaux champs selon DATA-MODELS.md
UserSchema.index({ 'preferences.sendDay': 1, 'preferences.timezone': 1 }); // Pour l'envoi d'invitations
UserSchema.index({ 'statistics.totalSubmissions': -1 }); // Pour le classement des utilisateurs
UserSchema.index({ 'statistics.averageResponseRate': -1 }); // Pour l'analyse des performances
UserSchema.index({ 'migrationData.source': 1 }); // Pour distinguer les utilisateurs migrés

// Optimized indexes for automated monthly cycles
UserSchema.index({ 
  'metadata.isActive': 1, 
  'preferences.optedOut': 1,
  'preferences.sendDay': 1 
}); // For efficient active user discovery during monthly processing

UserSchema.index({ 
  'metadata.isActive': 1,
  'statistics.totalContacts': -1 
}); // For user prioritization by contact count

UserSchema.index({ 
  'metadata.lastMonthlyJobRun': -1,
  'metadata.isActive': 1 
}); // For tracking job completion and retry logic

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

// Méthode pour mettre à jour le dernier login
UserSchema.methods.updateLastLogin = function() {
  this.metadata.lastLoginAt = new Date();
  this.metadata.lastActive = new Date();
  return this.save();
};

// Méthode pour incrémenter le compteur de réponses
UserSchema.methods.incrementResponseCount = function() {
  this.metadata.responseCount += 1;
  return this.save();
};

// Méthodes pour gérer les statistiques selon DATA-MODELS.md
UserSchema.methods.updateStatistics = function(updates) {
  Object.assign(this.statistics, updates);
  return this.save();
};

UserSchema.methods.incrementSubmissions = function() {
  this.statistics.totalSubmissions += 1;
  return this.save();
};

UserSchema.methods.incrementContacts = function() {
  this.statistics.totalContacts += 1;
  return this.save();
};

UserSchema.methods.updateResponseRate = function(newRate, month) {
  this.statistics.averageResponseRate = newRate;
  
  // Mettre à jour le meilleur mois si nécessaire
  if (!this.statistics.bestResponseMonth || !this.statistics.bestResponseMonth.rate || newRate > this.statistics.bestResponseMonth.rate) {
    this.statistics.bestResponseMonth = {
      month: month,
      rate: newRate
    };
  }
  
  return this.save();
};

UserSchema.methods.incrementJoinedCycles = function() {
  this.statistics.joinedCycles += 1;
  return this.save();
};

// Méthodes pour gérer les préférences selon DATA-MODELS.md
UserSchema.methods.updatePreferences = function(preferences) {
  Object.assign(this.preferences, preferences);
  return this.save();
};

UserSchema.methods.getNotificationSettings = function() {
  return {
    sendTime: this.preferences.sendTime,
    timezone: this.preferences.timezone,
    sendDay: this.preferences.sendDay,
    reminderSettings: this.preferences.reminderSettings,
    emailTemplate: this.preferences.emailTemplate,
    customMessage: this.preferences.customMessage
  };
};

// Méthode pour retourner les données publiques (sans password)
UserSchema.methods.toPublicJSON = function() {
  return {
    id: this._id,
    username: this.username,
    email: this.email,
    displayName: this.username, // Retourné pour compatibilité backward
    role: this.role,
    profile: this.profile,
    preferences: this.preferences,
    statistics: this.statistics,
    metadata: {
      isActive: this.metadata.isActive,
      emailVerified: this.metadata.emailVerified,
      lastActive: this.metadata.lastActive,
      responseCount: this.metadata.responseCount,
      registeredAt: this.metadata.registeredAt
    },
    migrationData: this.migrationData
  };
};

module.exports = mongoose.models.User || mongoose.model('User', UserSchema);