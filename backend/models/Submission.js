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