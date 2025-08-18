const mongoose = require('mongoose');
const Submission = require('../models/Submission');
const User = require('../models/User');
const Invitation = require('../models/Invitation');
const { validatePhotoUrl, logSecurityEvent } = require('../middleware/validation');

class SubmissionService {
  constructor(config = {}) {
    this.config = {
      maxTextResponses: config.maxTextResponses || 8,
      maxPhotoResponses: config.maxPhotoResponses || 5,
      minCompletionRate: config.minCompletionRate || 50,
      maxQuestionTextLength: config.maxQuestionTextLength || 500,
      maxAnswerTextLength: config.maxAnswerTextLength || 10000,
      maxPhotoCaptionLength: config.maxPhotoCaptionLength || 500,
      maxFreeTextLength: config.maxFreeTextLength || 5000
    };
  }

  /**
   * Crée une nouvelle soumission pour un utilisateur
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {Object} submissionData - Données de la soumission
   * @param {Object} metadata - Métadonnées de contexte
   * @returns {Promise<Object>} Soumission créée
   */
  async createSubmission(userId, submissionData, metadata = {}) {
    try {
      const { responses, freeText, month = this.getCurrentMonth(), invitationToken } = submissionData;
      const { ipAddress, userAgent } = metadata;

      // Validation de l'utilisateur
      const user = await User.findById(userId);
      if (!user) {
        throw new Error('Utilisateur non trouvé');
      }

      // Vérifier contrainte unique : 1 soumission par user par mois
      const existingSubmission = await Submission.findOne({ userId, month });
      if (existingSubmission) {
        throw new Error(`Vous avez déjà soumis une réponse pour ${month}. Une seule soumission par mois est autorisée.`);
      }

      // Valider les données de soumission
      this.validateSubmissionData({ responses, freeText });

      // Vérifier l'invitation si fournie
      let invitation = null;
      if (invitationToken) {
        invitation = await Invitation.findOne({ token: invitationToken, month });
        if (!invitation) {
          throw new Error('Token d\'invitation invalide ou expiré');
        }
        if (invitation.status === 'submitted') {
          throw new Error('Cette invitation a déjà été utilisée');
        }
      }

      // Créer la soumission
      const submission = new Submission({
        userId,
        month,
        responses: this.sanitizeResponses(responses),
        freeText: freeText?.trim() || '',
        formVersion: 'v2' // Nouvelle version avec User-based auth
      });

      await submission.save();

      // Marquer l'invitation comme soumise si applicable
      if (invitation) {
        await invitation.markAction('submitted', {
          submissionId: submission._id,
          ipAddress,
          userAgent
        });
      }

      // Mettre à jour les métadonnées utilisateur
      await this.updateUserSubmissionStats(userId);

      return await Submission.findById(submission._id)
        .populate('userId', 'username email')
        .lean();

    } catch (error) {
      if (error.code === 11000) {
        throw new Error('Vous avez déjà soumis une réponse pour ce mois');
      }
      throw error;
    }
  }

  /**
   * Met à jour une soumission existante (si autorisé)
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {String} month - Mois de la soumission
   * @param {Object} updateData - Données à mettre à jour
   * @returns {Promise<Object>} Soumission mise à jour
   */
  async updateSubmission(userId, month, updateData) {
    try {
      const { responses, freeText } = updateData;

      const submission = await Submission.findOne({ userId, month });
      if (!submission) {
        throw new Error('Soumission non trouvée');
      }

      // Vérifier si modification autorisée (par exemple, dans les 24h)
      const daysSinceSubmission = (Date.now() - submission.submittedAt) / (1000 * 60 * 60 * 24);
      if (daysSinceSubmission > 1) {
        throw new Error('Modification non autorisée après 24h');
      }

      // Valider les nouvelles données
      this.validateSubmissionData({ responses, freeText });

      // Mettre à jour
      if (responses) {
        submission.responses = this.sanitizeResponses(responses);
      }
      if (freeText !== undefined) {
        submission.freeText = freeText.trim();
      }

      await submission.save();

      return await Submission.findById(submission._id)
        .populate('userId', 'username email')
        .lean();

    } catch (error) {
      throw new Error(`Erreur mise à jour soumission: ${error.message}`);
    }
  }

  /**
   * Récupère une soumission par utilisateur et mois
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {String} month - Mois (YYYY-MM)
   * @returns {Promise<Object|null>} Soumission trouvée
   */
  async getSubmissionByUser(userId, month) {
    try {
      return await Submission.findOne({ userId, month })
        .populate('userId', 'username email')
        .lean();
    } catch (error) {
      throw new Error(`Erreur récupération soumission: ${error.message}`);
    }
  }

  /**
   * Compare deux soumissions (1-vs-1)
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur  
   * @param {String} month - Mois de comparaison
   * @param {Object} options - Options de comparaison
   * @returns {Promise<Object>} Résultat de comparaison détaillé
   */
  async compareSubmissions(userId1, userId2, month, options = {}) {
    try {
      const { includePrivateData = false, anonymize = false } = options;

      // Récupérer les deux soumissions
      const [submission1, submission2] = await Promise.all([
        Submission.findOne({ userId: userId1, month }).populate('userId', 'username email'),
        Submission.findOne({ userId: userId2, month }).populate('userId', 'username email')
      ]);

      if (!submission1 || !submission2) {
        const missing = !submission1 ? 'première' : 'deuxième';
        throw new Error(`${missing} soumission non trouvée pour ${month}`);
      }

      // Préparer les données de comparaison
      const comparison = {
        month,
        metadata: {
          comparedAt: new Date(),
          comparisonType: '1vs1',
          anonymized: anonymize
        },
        user1: this.formatUserForComparison(submission1, { includePrivateData, anonymize }),
        user2: this.formatUserForComparison(submission2, { includePrivateData, anonymize }),
        analysis: this.analyzeResponseAlignment(submission1.responses, submission2.responses),
        compatibility: this.calculateCompatibility(submission1, submission2)
      };

      return comparison;

    } catch (error) {
      throw new Error(`Erreur comparaison soumissions: ${error.message}`);
    }
  }

  /**
   * Analyse l'alignement des réponses entre deux utilisateurs
   * @param {Array} responses1 - Réponses du premier utilisateur
   * @param {Array} responses2 - Réponses du deuxième utilisateur
   * @returns {Object} Analyse détaillée de l'alignement
   */
  analyzeResponseAlignment(responses1, responses2) {
    const alignment = {
      score: 0,
      totalQuestions: 0,
      matchingResponses: 0,
      similarResponses: 0,
      conflictingResponses: 0,
      matches: [],
      differences: [],
      details: []
    };

    // Créer une map des réponses pour faciliter la comparaison
    const response1Map = new Map();
    const response2Map = new Map();

    responses1.forEach(r => response1Map.set(r.question, r.answer));
    responses2.forEach(r => response2Map.set(r.question, r.answer));

    // Analyser chaque question commune
    const commonQuestions = [...response1Map.keys()].filter(q => response2Map.has(q));
    
    commonQuestions.forEach(question => {
      const answer1 = response1Map.get(question);
      const answer2 = response2Map.get(question);
      
      alignment.totalQuestions++;
      
      // Analyse de correspondance
      const similarity = this.calculateResponseSimilarity(answer1, answer2);
      
      let alignmentType;
      if (similarity >= 0.8) {
        alignmentType = 'matching';
        alignment.matchingResponses++;
        alignment.matches.push({
          question,
          answer1: answer1.substring(0, 100),
          answer2: answer2.substring(0, 100),
          similarity
        });
      } else if (similarity >= 0.4) {
        alignmentType = 'similar';
        alignment.similarResponses++;
      } else {
        alignmentType = 'conflicting';
        alignment.conflictingResponses++;
        alignment.differences.push({
          question,
          answer1: answer1.substring(0, 100),
          answer2: answer2.substring(0, 100),
          similarity
        });
      }
      
      alignment.details.push({
        question,
        answer1: answer1.substring(0, 100), // Limiter pour éviter trop de données
        answer2: answer2.substring(0, 100),
        similarity,
        alignmentType
      });
    });

    // Calculer les pourcentages et score
    if (alignment.totalQuestions > 0) {
      alignment.matchingPercentage = Math.round((alignment.matchingResponses / alignment.totalQuestions) * 100);
      alignment.similarPercentage = Math.round((alignment.similarResponses / alignment.totalQuestions) * 100);
      alignment.conflictingPercentage = Math.round((alignment.conflictingResponses / alignment.totalQuestions) * 100);
      alignment.score = alignment.matchingPercentage;
    } else {
      alignment.matchingPercentage = 0;
      alignment.similarPercentage = 0;
      alignment.conflictingPercentage = 0;
      alignment.score = 0;
    }

    return alignment;
  }

  /**
   * Analyse le style de communication entre deux textes
   * @param {String} text1 - Premier texte
   * @param {String} text2 - Deuxième texte  
   * @returns {Object} Analyse du style de communication
   */
  analyzeCommunicationStyle(text1, text2) {
    const analysis = {
      score: 0,
      details: {
        lengthSimilarity: 0,
        formalitySimilarity: 0,
        emotionalTone: 0,
        vocabularyOverlap: 0
      }
    };

    if (!text1 || !text2) {
      return analysis;
    }

    // Analyse de la longueur
    const len1 = text1.length;
    const len2 = text2.length;
    const maxLen = Math.max(len1, len2);
    const minLen = Math.min(len1, len2);
    analysis.details.lengthSimilarity = maxLen > 0 ? minLen / maxLen : 0;

    // Analyse de formalité (basée sur la ponctuation et structure)
    const formal1 = (text1.match(/[.!?]/g) || []).length / Math.max(1, text1.split(' ').length);
    const formal2 = (text2.match(/[.!?]/g) || []).length / Math.max(1, text2.split(' ').length);
    analysis.details.formalitySimilarity = 1 - Math.abs(formal1 - formal2);

    // Analyse émotionnelle simple (exclamations, mots positifs/négatifs)
    const exclaim1 = (text1.match(/!/g) || []).length;
    const exclaim2 = (text2.match(/!/g) || []).length;
    const emotionalSimilarity = 1 - Math.abs(exclaim1 - exclaim2) / Math.max(1, exclaim1 + exclaim2);
    analysis.details.emotionalTone = emotionalSimilarity;

    // Overlap vocabulaire
    const words1 = new Set(text1.toLowerCase().split(/\s+/).filter(w => w.length > 3));
    const words2 = new Set(text2.toLowerCase().split(/\s+/).filter(w => w.length > 3));
    const intersection = new Set([...words1].filter(x => words2.has(x)));
    const union = new Set([...words1, ...words2]);
    analysis.details.vocabularyOverlap = union.size > 0 ? intersection.size / union.size : 0;

    // Score final (moyenne pondérée)
    analysis.score = (
      analysis.details.lengthSimilarity * 0.2 +
      analysis.details.formalitySimilarity * 0.3 +
      analysis.details.emotionalTone * 0.2 +
      analysis.details.vocabularyOverlap * 0.3
    );

    return analysis;
  }

  /**
   * Calcule la compatibilité entre deux soumissions
   * @param {Object} submission1 - Première soumission
   * @param {Object} submission2 - Deuxième soumission
   * @returns {Object} Score de compatibilité et détails
   */
  calculateCompatibility(submission1, submission2) {
    const compatibility = {
      overallScore: 0,
      details: {
        responseAlignment: 0,
        interestOverlap: 0,
        valuesSimilarity: 0,
        communicationStyle: 0
      },
      matches: [],
      differences: [],
      recommendations: []
    };

    // Analyser l'alignement des réponses
    const responseAnalysis = this.analyzeResponseAlignment(submission1.responses, submission2.responses);
    compatibility.details.responseAlignment = responseAnalysis.score;
    compatibility.matches.push(...responseAnalysis.matches);
    compatibility.differences.push(...responseAnalysis.differences);

    // Analyser le style de communication via freeText
    const styleAnalysis = this.analyzeCommunicationStyle(submission1.freeText, submission2.freeText);
    compatibility.details.communicationStyle = styleAnalysis.score;

    // Pour l'instant, utiliser des valeurs par défaut pour les autres métriques
    compatibility.details.interestOverlap = 50; // Valeur neutre par défaut
    compatibility.details.valuesSimilarity = 50; // Valeur neutre par défaut

    // Calcul du score global (moyenne pondérée)
    compatibility.overallScore = Math.round(
      (compatibility.details.responseAlignment * 0.4) +
      (compatibility.details.interestOverlap * 0.2) +
      (compatibility.details.valuesSimilarity * 0.2) +
      (compatibility.details.communicationStyle * 0.2)
    );

    // Générer des recommandations
    compatibility.recommendations = this.generateCompatibilityRecommendations(compatibility);

    return compatibility;
  }

  /**
   * Récupère toutes les soumissions avec filtres et pagination
   * @param {Object} filters - Filtres de recherche
   * @param {Object} pagination - Options de pagination
   * @returns {Promise<Object>} Soumissions paginées avec statistiques
   */
  async getSubmissions(filters = {}, pagination = {}) {
    try {
      const {
        month = '',
        userId = '',
        isComplete = null,
        minCompletionRate = 0,
        dateFrom = null,
        dateTo = null
      } = filters;

      const {
        page = 1,
        limit = 20,
        sortBy = 'submittedAt',
        sortOrder = 'desc'
      } = pagination;

      // Construction de la query
      const query = {};

      if (month) query.month = month;
      if (userId) query.userId = userId;
      if (isComplete !== null) query.isComplete = isComplete;
      if (minCompletionRate > 0) query.completionRate = { $gte: minCompletionRate };

      if (dateFrom || dateTo) {
        query.submittedAt = {};
        if (dateFrom) query.submittedAt.$gte = new Date(dateFrom);
        if (dateTo) query.submittedAt.$lte = new Date(dateTo);
      }

      // Options de tri
      const sortOptions = {};
      sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

      // Pagination
      const skip = (page - 1) * limit;

      // Exécution des requêtes en parallèle
      const [submissions, totalCount, stats] = await Promise.all([
        Submission.find(query)
          .populate('userId', 'username email')
          .sort(sortOptions)
          .skip(skip)
          .limit(limit)
          .lean(),
        
        Submission.countDocuments(query),
        
        this.getSubmissionStats(filters)
      ]);

      return {
        submissions,
        pagination: {
          page,
          limit,
          totalCount,
          totalPages: Math.ceil(totalCount / limit),
          hasNext: page < Math.ceil(totalCount / limit),
          hasPrev: page > 1
        },
        stats
      };

    } catch (error) {
      throw new Error(`Erreur récupération soumissions: ${error.message}`);
    }
  }

  /**
   * Calcule les statistiques des soumissions
   * @param {Object} filters - Filtres appliqués
   * @returns {Promise<Object>} Statistiques complètes
   */
  async getSubmissionStats(filters = {}) {
    try {
      // Pour les stats, on veut toutes les soumissions si aucun filtre spécifique
      const query = Object.keys(filters).length > 0 ? this.buildStatsQuery(filters) : {};

      const [basicStats, monthlyStats, completionStats, userStats] = await Promise.all([
        // Statistiques de base
        Submission.aggregate([
          { $match: query },
          {
            $group: {
              _id: null,
              totalSubmissions: { $sum: 1 },
              completeSubmissions: { $sum: { $cond: ['$isComplete', 1, 0] } },
              avgCompletionRate: { $avg: '$completionRate' },
              uniqueUsers: { $addToSet: '$userId' }
            }
          },
          {
            $project: {
              totalSubmissions: 1,
              completeSubmissions: 1,
              avgCompletionRate: { $round: ['$avgCompletionRate', 1] },
              uniqueUsersCount: { $size: '$uniqueUsers' },
              completionPercentage: {
                $round: [
                  { $multiply: [{ $divide: ['$completeSubmissions', '$totalSubmissions'] }, 100] },
                  1
                ]
              }
            }
          }
        ]),

        // Statistiques mensuelles
        Submission.aggregate([
          { $match: query },
          {
            $group: {
              _id: '$month',
              count: { $sum: 1 },
              avgCompletion: { $avg: '$completionRate' },
              completeCount: { $sum: { $cond: ['$isComplete', 1, 0] } }
            }
          },
          { $sort: { '_id': -1 } },
          { $limit: 12 }
        ]),

        // Distribution des taux de complétion
        Submission.aggregate([
          { $match: query },
          {
            $bucket: {
              groupBy: '$completionRate',
              boundaries: [0, 25, 50, 75, 90, 100],
              default: 'other',
              output: {
                count: { $sum: 1 },
                avgRate: { $avg: '$completionRate' }
              }
            }
          }
        ]),

        // Top utilisateurs actifs
        Submission.aggregate([
          { $match: query },
          {
            $group: {
              _id: '$userId',
              submissionCount: { $sum: 1 },
              avgCompletion: { $avg: '$completionRate' },
              months: { $addToSet: '$month' }
            }
          },
          {
            $lookup: {
              from: 'users',
              localField: '_id',
              foreignField: '_id',
              as: 'user'
            }
          },
          {
            $project: {
              submissionCount: 1,
              avgCompletion: { $round: ['$avgCompletion', 1] },
              monthsActive: { $size: '$months' },
              username: { $arrayElemAt: ['$user.username', 0] }
            }
          },
          { $sort: { submissionCount: -1 } },
          { $limit: 10 }
        ])
      ]);

      return {
        basic: basicStats[0] || {
          totalSubmissions: 0,
          completeSubmissions: 0,
          avgCompletionRate: 0,
          uniqueUsersCount: 0,
          completionPercentage: 0
        },
        monthly: monthlyStats,
        completionDistribution: completionStats,
        topUsers: userStats
      };

    } catch (error) {
      throw new Error(`Erreur calcul statistiques: ${error.message}`);
    }
  }

  /**
   * Trouve des correspondances potentielles pour un utilisateur
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {String} month - Mois de référence
   * @param {Object} options - Options de matching
   * @returns {Promise<Array>} Liste des correspondances triées par compatibilité
   */
  async findMatches(userId, month, options = {}) {
    try {
      const { limit = 10, minCompatibility = 60, excludeUserIds = [] } = options;

      // Récupérer la soumission de référence
      const userSubmission = await Submission.findOne({ userId, month })
        .populate('userId', 'username email');

      if (!userSubmission) {
        throw new Error('Soumission utilisateur non trouvée pour ce mois');
      }

      // Récupérer toutes les autres soumissions du même mois
      const otherSubmissions = await Submission.find({
        month,
        userId: { 
          $ne: userId,
          $nin: excludeUserIds
        }
      }).populate('userId', 'username email').lean();

      // Calculer la compatibilité avec chaque soumission
      const matches = [];
      for (const otherSubmission of otherSubmissions) {
        const compatibility = this.calculateCompatibility(userSubmission, otherSubmission);
        
        if (compatibility.overallScore >= minCompatibility) {
          matches.push({
            user: otherSubmission.userId,
            submission: otherSubmission,
            compatibility,
            matchedAt: new Date()
          });
        }
      }

      // Trier par score de compatibilité décroissant
      matches.sort((a, b) => b.compatibility.overallScore - a.compatibility.overallScore);

      return matches.slice(0, limit);

    } catch (error) {
      throw new Error(`Erreur recherche correspondances: ${error.message}`);
    }
  }

  // ===== MÉTHODES UTILITAIRES =====

  /**
   * Obtient le mois courant au format YYYY-MM
   * @returns {String} Mois courant
   */
  getCurrentMonth() {
    return new Date().toISOString().slice(0, 7);
  }

  /**
   * Valide les données d'une soumission
   * @param {Object} submissionData - Données à valider
   * @throws {Error} Si validation échoue
   */
  validateSubmissionData(submissionData) {
    const { responses, freeText } = submissionData;

    if (!responses || !Array.isArray(responses)) {
      throw new Error('Réponses requises sous forme de tableau');
    }

    if (responses.length === 0) {
      throw new Error('Au moins une réponse est requise');
    }

    // Valider chaque réponse
    responses.forEach((response, index) => {
      if (!response.questionId) {
        throw new Error(`ID de question manquant pour la réponse ${index + 1}`);
      }
      
      if (!response.type || !['text', 'photo', 'radio'].includes(response.type)) {
        throw new Error(`Type de réponse invalide pour la question ${response.questionId}`);
      }

      if (response.type === 'text' || response.type === 'radio') {
        if (!response.answer || response.answer.trim().length === 0) {
          throw new Error(`Réponse textuelle requise pour la question ${response.questionId}`);
        }
        if (response.answer.length > this.config.maxAnswerTextLength) {
          throw new Error(`Réponse trop longue pour la question ${response.questionId}`);
        }
      }

      if (response.type === 'photo') {
        if (!response.photoUrl) {
          throw new Error(`URL photo requise pour la question ${response.questionId}`);
        }
        if (response.photoCaption && response.photoCaption.length > this.config.maxPhotoCaptionLength) {
          throw new Error(`Légende photo trop longue pour la question ${response.questionId}`);
        }
      }
    });

    // Valider freeText si présent
    if (freeText && freeText.length > this.config.maxFreeTextLength) {
      throw new Error('Texte libre trop long');
    }

    // Vérifier les limites de types de réponses
    const textResponses = responses.filter(r => r.type === 'text' || r.type === 'radio');
    const photoResponses = responses.filter(r => r.type === 'photo');

    if (textResponses.length > this.config.maxTextResponses) {
      throw new Error(`Maximum ${this.config.maxTextResponses} réponses textuelles autorisées`);
    }

    if (photoResponses.length > this.config.maxPhotoResponses) {
      throw new Error(`Maximum ${this.config.maxPhotoResponses} réponses photos autorisées`);
    }
  }

  /**
   * Nettoie et sanitise les réponses
   * @param {Array} responses - Réponses brutes
   * @returns {Array} Réponses nettoyées
   */
  sanitizeResponses(responses) {
    return responses.map(response => {
      const sanitized = {
        questionId: response.questionId.trim(),
        type: response.type,
      };

      if (response.answer) {
        sanitized.answer = response.answer.trim();
      }
      
      if (response.photoUrl) {
        const photoValidation = validatePhotoUrl(response.photoUrl);
        if (photoValidation.isValid) {
          sanitized.photoUrl = photoValidation.sanitized;
        } else {
          // Log security event and remove invalid photo URL
          logSecurityEvent('INVALID_PHOTO_URL_REJECTED', {
            reason: photoValidation.reason,
            originalUrl: response.photoUrl.substring(0, 100),
            service: 'submissionService'
          });
          // Don't include photoUrl in sanitized response
        }
      }
      
      if (response.photoCaption) {
        sanitized.photoCaption = response.photoCaption.trim();
      }

      return sanitized;
    });
  }

  /**
   * Formate les données utilisateur pour la comparaison
   * @param {Object} submission - Soumission à formater
   * @param {Object} options - Options de formatage
   * @returns {Object} Données formatées
   */
  formatUserForComparison(submission, options) {
    const { includePrivateData, anonymize } = options;
    
    const formatted = {
      id: anonymize ? `user_${Math.random().toString(36).substr(2, 9)}` : submission.userId._id,
      username: anonymize ? `Utilisateur anonyme` : submission.userId.username,
      responses: submission.responses,
      freeText: submission.freeText,
      completionRate: submission.completionRate,
      submittedAt: submission.submittedAt
    };

    if (includePrivateData && !anonymize) {
      formatted.email = submission.userId.email;
    }

    return formatted;
  }

  /**
   * Analyse l'alignement entre deux ensembles de réponses
   * @param {Array} responses1 - Premières réponses
   * @param {Array} responses2 - Deuxièmes réponses
   * @returns {Object} Analyse d'alignement
   */
  static analyzeResponseAlignment(responses1, responses2) {
    const analysis = {
      score: 0,
      matches: [],
      differences: [],
      commonQuestions: 0,
      totalQuestions: 0
    };

    // Créer des maps pour faciliter la comparaison
    const map1 = new Map();
    const map2 = new Map();
    
    responses1.forEach(r => map1.set(r.questionId, r));
    responses2.forEach(r => map2.set(r.questionId, r));

    // Analyser les questions communes
    const allQuestionIds = new Set([...map1.keys(), ...map2.keys()]);
    analysis.totalQuestions = allQuestionIds.size;

    let totalMatches = 0;
    allQuestionIds.forEach(questionId => {
      const response1 = map1.get(questionId);
      const response2 = map2.get(questionId);

      if (response1 && response2) {
        analysis.commonQuestions++;
        
        const similarity = this.calculateResponseSimilarity(response1, response2);
        if (similarity > 0.7) {
          totalMatches++;
          analysis.matches.push({
            questionId,
            similarity,
            response1: response1.answer || response1.photoUrl,
            response2: response2.answer || response2.photoUrl
          });
        } else if (similarity < 0.3) {
          analysis.differences.push({
            questionId,
            similarity,
            response1: response1.answer || response1.photoUrl,
            response2: response2.answer || response2.photoUrl
          });
        }
      }
    });

    analysis.score = analysis.commonQuestions > 0 ? 
      Math.round((totalMatches / analysis.commonQuestions) * 100) : 0;

    return analysis;
  }

  /**
   * Calcule la similarité entre deux réponses
   * @param {Object} response1 - Première réponse
   * @param {Object} response2 - Deuxième réponse
   * @returns {Number} Score de similarité (0-1)
   */
  calculateResponseSimilarity(response1, response2) {
    // Si les types sont différents, similarité faible
    if (response1.type !== response2.type) {
      return 0.1;
    }

    if (response1.type === 'radio') {
      // Pour les réponses radio, comparaison exacte
      return response1.answer === response2.answer ? 1.0 : 0.0;
    }

    if (response1.type === 'text') {
      // Pour le texte, utiliser une mesure de similarité simple
      const text1 = response1.answer.toLowerCase().trim();
      const text2 = response2.answer.toLowerCase().trim();
      
      if (text1 === text2) return 1.0;
      
      // Similarité basée sur les mots communs
      const words1 = new Set(text1.split(/\s+/));
      const words2 = new Set(text2.split(/\s+/));
      const intersection = new Set([...words1].filter(x => words2.has(x)));
      const union = new Set([...words1, ...words2]);
      
      return union.size > 0 ? intersection.size / union.size : 0;
    }

    if (response1.type === 'photo') {
      // Pour les photos, comparer les légendes si disponibles
      if (response1.photoCaption && response2.photoCaption) {
        return this.calculateResponseSimilarity(
          { type: 'text', answer: response1.photoCaption },
          { type: 'text', answer: response2.photoCaption }
        );
      }
      // Si pas de légendes, similarité neutre
      return 0.5;
    }

    return 0;
  }

  /**
   * Analyse le style de communication basé sur freeText
   * @param {String} text1 - Premier texte
   * @param {String} text2 - Deuxième texte
   * @returns {Object} Analyse du style
   */
  static analyzeCommunicationStyle(text1, text2) {
    const analysis = {
      score: 50, // Score par défaut
      details: {
        lengthSimilarity: 0,
        toneSimilarity: 0,
        vocabularySimilarity: 0
      }
    };

    if (!text1 || !text2) {
      return analysis;
    }

    // Analyser la similarité de longueur
    const len1 = text1.length;
    const len2 = text2.length;
    const lengthRatio = Math.min(len1, len2) / Math.max(len1, len2);
    analysis.details.lengthSimilarity = Math.round(lengthRatio * 100);

    // Analyser le vocabulaire (mots communs)
    const words1 = new Set(text1.toLowerCase().split(/\s+/).filter(w => w.length > 3));
    const words2 = new Set(text2.toLowerCase().split(/\s+/).filter(w => w.length > 3));
    const commonWords = new Set([...words1].filter(x => words2.has(x)));
    const allWords = new Set([...words1, ...words2]);
    
    analysis.details.vocabularySimilarity = allWords.size > 0 ? 
      Math.round((commonWords.size / allWords.size) * 100) : 0;

    // Score global basé sur les métriques
    analysis.score = Math.round(
      (analysis.details.lengthSimilarity * 0.3) +
      (analysis.details.vocabularySimilarity * 0.7)
    );

    return analysis;
  }

  /**
   * Génère des recommandations basées sur la compatibilité
   * @param {Object} compatibility - Données de compatibilité
   * @returns {Array} Liste de recommandations
   */
  generateCompatibilityRecommendations(compatibility) {
    const recommendations = [];
    const score = compatibility.overallScore;

    if (score >= 80) {
      recommendations.push({
        type: 'high_match',
        message: 'Excellente compatibilité ! Vous partagez de nombreux points communs.',
        priority: 'high'
      });
    } else if (score >= 60) {
      recommendations.push({
        type: 'good_match',
        message: 'Bonne compatibilité avec quelques différences intéressantes à explorer.',
        priority: 'medium'
      });
    } else {
      recommendations.push({
        type: 'explore_differences',
        message: 'Vos différences pourraient créer des conversations enrichissantes.',
        priority: 'medium'
      });
    }

    // Recommandations spécifiques basées sur les détails
    if (compatibility.details.communicationStyle > 70) {
      recommendations.push({
        type: 'communication',
        message: 'Vos styles de communication sont très alignés.',
        priority: 'low'
      });
    }

    if (compatibility.matches.length > 3) {
      recommendations.push({
        type: 'common_interests',
        message: `Vous avez ${compatibility.matches.length} réponses très similaires.`,
        priority: 'low'
      });
    }

    return recommendations;
  }

  /**
   * Met à jour les statistiques de l'utilisateur après soumission
   * @param {ObjectId} userId - ID de l'utilisateur
   */
  async updateUserSubmissionStats(userId) {
    try {
      const user = await User.findById(userId);
      if (!user) return;

      // Compter le nombre total de soumissions
      const submissionCount = await Submission.countDocuments({ userId });
      
      // Mettre à jour les métadonnées utilisateur
      await User.findByIdAndUpdate(userId, {
        'metadata.responseCount': submissionCount,
        'metadata.lastActive': new Date()
      });

    } catch (error) {
      console.warn('Erreur mise à jour stats utilisateur:', error.message);
    }
  }

  /**
   * Construit la query pour les statistiques
   * @param {Object} filters - Filtres appliqués
   * @returns {Object} Query MongoDB
   */
  buildStatsQuery(filters) {
    const query = {};
    
    if (filters.month) query.month = filters.month;
    if (filters.userId) query.userId = filters.userId;
    if (filters.isComplete !== null) query.isComplete = filters.isComplete;
    if (filters.minCompletionRate > 0) query.completionRate = { $gte: filters.minCompletionRate };
    
    if (filters.dateFrom || filters.dateTo) {
      query.submittedAt = {};
      if (filters.dateFrom) query.submittedAt.$gte = new Date(filters.dateFrom);
      if (filters.dateTo) query.submittedAt.$lte = new Date(filters.dateTo);
    }
    
    return query;
  }

  /**
   * Supprime une soumission (admin seulement)
   * @param {ObjectId} submissionId - ID de la soumission
   * @param {ObjectId} adminUserId - ID de l'admin
   * @returns {Promise<Boolean>} Succès de la suppression
   */
  async deleteSubmission(submissionId, adminUserId) {
    try {
      // Vérifier que l'utilisateur est admin
      const admin = await User.findById(adminUserId);
      if (!admin || admin.role !== 'admin') {
        throw new Error('Seuls les administrateurs peuvent supprimer des soumissions');
      }

      const submission = await Submission.findById(submissionId);
      if (!submission) {
        throw new Error('Soumission non trouvée');
      }

      await Submission.findByIdAndDelete(submissionId);
      
      // Mettre à jour les stats de l'utilisateur
      await this.updateUserSubmissionStats(submission.userId);

      return true;

    } catch (error) {
      throw new Error(`Erreur suppression soumission: ${error.message}`);
    }
  }

  /**
   * Obtient les mois disponibles pour les soumissions
   * @returns {Promise<Array>} Liste des mois avec labels
   */
  async getAvailableMonths() {
    try {
      const pipeline = [
        {
          $group: {
            _id: '$month',
            count: { $sum: 1 },
            avgCompletion: { $avg: '$completionRate' }
          }
        },
        {
          $sort: { _id: -1 }
        },
        {
          $project: {
            key: '$_id',
            label: {
              $concat: [
                {
                  $arrayElemAt: [
                    ['janvier', 'février', 'mars', 'avril', 'mai', 'juin',
                     'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'],
                    { $subtract: [{ $toInt: { $substr: ['$_id', 5, 2] } }, 1] }
                  ]
                },
                ' ',
                { $substr: ['$_id', 0, 4] }
              ]
            },
            count: 1,
            avgCompletion: { $round: ['$avgCompletion', 1] }
          }
        }
      ];

      return await Submission.aggregate(pipeline);

    } catch (error) {
      throw new Error(`Erreur récupération mois disponibles: ${error.message}`);
    }
  }
}

module.exports = SubmissionService;