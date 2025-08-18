const mongoose = require('mongoose');
const Handshake = require('../models/Handshake');
const User = require('../models/User');
const Contact = require('../models/Contact');
const { sanitizeMongoInput, sanitizeObjectId, logSecurityEvent } = require('../middleware/querySanitization');

// Import notification service for automatic notification creation
let notificationService = null;
try {
  notificationService = require('./notificationServiceInstance');
} catch (error) {
  console.warn('⚠️ NotificationService not available, handshake notifications will be disabled');
}

class HandshakeService {
  constructor(config = {}) {
    this.config = {
      expirationDays: config.expirationDays || 30,
      maxMessageLength: config.maxMessageLength || 500,
      maxPending: config.maxPending || 50,
      cleanupIntervalHours: config.cleanupIntervalHours || 6,
      notificationBeforeExpiryDays: config.notificationBeforeExpiryDays || 3
    };
  }

  /**
   * Crée un handshake mutuel entre deux utilisateurs
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   * @param {Object} options - Options de création
   * @returns {Promise<Object>} Handshake créé avec détails
   */
  async createMutual(userId1, userId2, options = {}) {
    try {
      // Sanitize all input parameters
      const sanitizedUserId1 = sanitizeObjectId(userId1);
      const sanitizedUserId2 = sanitizeObjectId(userId2);
      const sanitizedOptions = sanitizeMongoInput(options);
      
      if (!sanitizedUserId1 || !sanitizedUserId2) {
        logSecurityEvent('INVALID_HANDSHAKE_USER_IDS', {
          userId1: typeof userId1,
          userId2: typeof userId2
        });
        throw new Error('Invalid user IDs provided');
      }
      
      const {
        initiator = sanitizedUserId1,
        message = '',
        source = 'manual',
        metadata = {}
      } = sanitizedOptions;

      // Validations préliminaires
      await this.validateUsers(sanitizedUserId1, sanitizedUserId2);
      
      // Vérifier qu'il ne s'agit pas du même utilisateur
      if (new mongoose.Types.ObjectId(sanitizedUserId1).equals(new mongoose.Types.ObjectId(sanitizedUserId2))) {
        throw new Error('Impossible de créer un handshake avec soi-même');
      }

      // Vérifier limites de spam avant toute opération de base de données
      const sanitizedInitiator = sanitizeObjectId(initiator);
      if (!sanitizedInitiator) {
        throw new Error('Invalid initiator ID');
      }
      await this.checkSpamLimits(sanitizedInitiator);

      // Déterminer le sens du handshake (initiator -> target)
      const initiatorObjectId = new mongoose.Types.ObjectId(sanitizedInitiator);
      const userId1ObjectId = new mongoose.Types.ObjectId(sanitizedUserId1);
      const userId2ObjectId = new mongoose.Types.ObjectId(sanitizedUserId2);
      const requesterId = initiatorObjectId.equals(userId1ObjectId) ? sanitizedUserId1 : sanitizedUserId2;
      const targetId = new mongoose.Types.ObjectId(requesterId).equals(userId1ObjectId) ? sanitizedUserId2 : sanitizedUserId1;

      // Normaliser l'ordre des IDs pour éviter les doublons (userId1 toujours le plus petit)
      const normalizedQuery = this.createNormalizedHandshakeQuery(sanitizedUserId1, sanitizedUserId2);

      // Utiliser findOneAndUpdate avec upsert pour une opération atomique
      // Cela évite les race conditions lors de la création
      const handshakeData = {
        requesterId,
        targetId,
        message: message.trim().substring(0, this.config.maxMessageLength),
        expiresAt: new Date(Date.now() + this.config.expirationDays * 24 * 60 * 60 * 1000),
        status: 'pending',
        requestedAt: new Date(),
        metadata: {
          initiatedBy: source,
          mutualContacts: [],
          ...metadata
        }
      };

      try {
        // Vérifier d'abord si un handshake existe déjà
        const existingHandshake = await this.findExistingHandshake(sanitizedUserId1, sanitizedUserId2);
        if (existingHandshake) {
          return this.handleExistingHandshake(existingHandshake, options);
        }

        // Tentative de création atomique avec upsert
        const result = await Handshake.findOneAndUpdate(
          normalizedQuery, // Query pour trouver handshake existant
          { $setOnInsert: handshakeData }, // Données à insérer si pas trouvé
          { 
            upsert: true, // Créer si n'existe pas
            new: true, // Retourner le document après modification
            runValidators: true // Exécuter les validations
          }
        );

        let handshake = result;

        // Mettre à jour les contacts si ils existent
        await this.updateRelatedContacts(sanitizedUserId1, sanitizedUserId2, handshake._id);

        // Récupérer handshake avec relations
        const populatedHandshake = await Handshake.findById(handshake._id)
          .populate('requesterId', 'username email')
          .populate('targetId', 'username email');

        // Create notification for the target user
        if (notificationService) {
          try {
            await notificationService.createHandshakeNotification(
              'handshake_request',
              populatedHandshake.targetId._id,
              populatedHandshake,
              { priority: 'high' }
            );
          } catch (notifError) {
            console.warn('⚠️ Failed to create handshake notification:', notifError.message);
          }
        }

        return {
          handshake: populatedHandshake,
          created: true,
          message: 'Handshake créé avec succès'
        };

      } catch (atomicError) {
        // En cas d'erreur lors de l'opération atomique, essayer la méthode traditionnelle
        console.warn('Atomic handshake creation failed, falling back to traditional method', {
          error: atomicError.message,
          userId1: userId1.toString(),
          userId2: userId2.toString()
        });

        // Vérifier handshake existant avec une nouvelle requête
        const existingHandshake = await this.findExistingHandshake(sanitizedUserId1, sanitizedUserId2);
        if (existingHandshake) {
          return this.handleExistingHandshake(existingHandshake, options);
        }

        // Si vraiment aucun handshake existant, re-throw l'erreur originale
        throw atomicError;
      }

    } catch (error) {
      if (error.code === 11000) {
        // Gérer erreur de contrainte unique MongoDB
        const existing = await this.findExistingHandshake(sanitizedUserId1, sanitizedUserId2);
        if (existing) {
          return this.handleExistingHandshake(existing, options);
        }
      }
      throw error;
    }
  }

  /**
   * Accepte un handshake
   * @param {ObjectId} handshakeId - ID du handshake
   * @param {ObjectId} userId - ID de l'utilisateur qui accepte
   * @param {String} responseMessage - Message de réponse optionnel
   * @returns {Promise<Object>} Handshake accepté
   */
  async accept(handshakeId, userId, responseMessage = '') {
    try {
      const handshake = await Handshake.findById(handshakeId)
        .populate('requesterId', 'username email')
        .populate('targetId', 'username email');

      if (!handshake) {
        throw new Error('Handshake non trouvé');
      }

      // Vérifier permissions
      if (!handshake.targetId._id.equals(new mongoose.Types.ObjectId(userId))) {
        throw new Error('Seul le destinataire peut accepter ce handshake');
      }

      // Vérifier statut
      if (handshake.status !== 'pending') {
        throw new Error(`Handshake déjà ${handshake.status}, impossible d'accepter`);
      }

      // Vérifier expiration
      if (handshake.isExpired()) {
        await this.markExpired(handshake);
        throw new Error('Ce handshake a expiré');
      }

      // Accepter le handshake
      handshake.status = 'accepted';
      handshake.respondedAt = new Date();
      handshake.responseMessage = responseMessage.trim().substring(0, this.config.maxMessageLength);

      await handshake.save();

      // Créer/mettre à jour les contacts mutuels
      await this.createMutualContacts(handshake.requesterId._id, handshake.targetId._id, handshake._id);

      // Mettre à jour les statistiques utilisateur
      await this.updateUserHandshakeStats(handshake.requesterId._id);
      await this.updateUserHandshakeStats(handshake.targetId._id);

      // Create notification for the requester
      if (notificationService) {
        try {
          await notificationService.createHandshakeNotification(
            'handshake_accepted',
            handshake.requesterId._id,
            handshake,
            { priority: 'normal' }
          );
        } catch (notifError) {
          console.warn('⚠️ Failed to create handshake accepted notification:', notifError.message);
        }
      }

      return {
        handshake,
        success: true,
        message: 'Handshake accepté avec succès'
      };

    } catch (error) {
      throw new Error(`Erreur acceptation handshake: ${error.message}`);
    }
  }

  /**
   * Refuse un handshake
   * @param {ObjectId} handshakeId - ID du handshake
   * @param {ObjectId} userId - ID de l'utilisateur qui refuse
   * @param {String} responseMessage - Message de refus optionnel
   * @returns {Promise<Object>} Handshake refusé
   */
  async decline(handshakeId, userId, responseMessage = '') {
    try {
      const handshake = await Handshake.findById(handshakeId)
        .populate('requesterId', 'username email')
        .populate('targetId', 'username email');

      if (!handshake) {
        throw new Error('Handshake non trouvé');
      }

      // Vérifier permissions
      if (!handshake.targetId._id.equals(new mongoose.Types.ObjectId(userId))) {
        throw new Error('Seul le destinataire peut refuser ce handshake');
      }

      // Vérifier statut
      if (handshake.status !== 'pending') {
        throw new Error(`Handshake déjà ${handshake.status}, impossible de refuser`);
      }

      // Refuser le handshake
      handshake.status = 'declined';
      handshake.respondedAt = new Date();
      handshake.responseMessage = responseMessage.trim().substring(0, this.config.maxMessageLength);

      await handshake.save();

      // Nettoyer les contacts associés si nécessaire
      await this.cleanupDeclinedContacts(handshake.requesterId._id, handshake.targetId._id);

      // Create notification for the requester
      if (notificationService) {
        try {
          await notificationService.createHandshakeNotification(
            'handshake_declined',
            handshake.requesterId._id,
            handshake,
            { priority: 'normal' }
          );
        } catch (notifError) {
          console.warn('⚠️ Failed to create handshake declined notification:', notifError.message);
        }
      }

      return {
        handshake,
        success: true,
        message: 'Handshake refusé'
      };

    } catch (error) {
      throw new Error(`Erreur refus handshake: ${error.message}`);
    }
  }

  /**
   * Vérifie les permissions entre deux utilisateurs
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   * @param {Object} options - Options de vérification
   * @returns {Promise<Object>} Résultat de vérification des permissions
   */
  async checkPermission(userId1, userId2, options = {}) {
    try {
      const { includeDetails = false, checkBidirectional = true } = options;

      const result = {
        hasPermission: false,
        handshakeStatus: null,
        handshakeId: null,
        details: null
      };

      // Chercher handshake accepté
      const query = {
        $or: [
          { requesterId: userId1, targetId: userId2, status: 'accepted' }
        ]
      };

      if (checkBidirectional) {
        query.$or.push({ requesterId: userId2, targetId: userId1, status: 'accepted' });
      }

      const handshake = await Handshake.findOne(query);

      if (handshake) {
        result.hasPermission = true;
        result.handshakeStatus = handshake.status;
        result.handshakeId = handshake._id;
        
        if (includeDetails) {
          const populatedHandshake = await Handshake.findById(handshake._id)
            .populate('requesterId', 'username email')
            .populate('targetId', 'username email');
          result.details = populatedHandshake;
        }
      } else {
        // Vérifier s'il y a un handshake pending
        const pendingHandshake = await Handshake.findOne({
          $or: [
            { requesterId: userId1, targetId: userId2, status: 'pending' },
            { requesterId: userId2, targetId: userId1, status: 'pending' }
          ]
        });

        if (pendingHandshake) {
          result.handshakeStatus = 'pending';
          result.handshakeId = pendingHandshake._id;
        }
      }

      return result;

    } catch (error) {
      throw new Error(`Erreur vérification permissions: ${error.message}`);
    }
  }

  /**
   * Récupère un handshake par son ID avec population des utilisateurs
   * @param {ObjectId} handshakeId - ID du handshake
   * @returns {Promise<Object|null>} Handshake avec utilisateurs populés ou null
   */
  async getHandshakeById(handshakeId) {
    try {
      const handshake = await Handshake.findById(handshakeId)
        .populate('requesterId', 'username email')
        .populate('targetId', 'username email');
      
      return handshake;
    } catch (error) {
      throw new Error(`Erreur récupération handshake: ${error.message}`);
    }
  }

  /**
   * Récupère les handshakes d'un utilisateur avec filtres
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {Object} filters - Filtres de recherche
   * @param {Object} pagination - Options de pagination
   * @returns {Promise<Object>} Handshakes avec métadonnées
   */
  async getUserHandshakes(userId, filters = {}, pagination = {}) {
    try {
      const {
        status = '',
        direction = 'all', // 'sent', 'received', 'all'
        includeExpired = false,
        dateFrom = null,
        dateTo = null
      } = filters;

      const {
        page = 1,
        limit = 20,
        sortBy = 'requestedAt',
        sortOrder = 'desc'
      } = pagination;

      // Construction de la query
      let query = {};

      // Direction des handshakes
      if (direction === 'sent') {
        query.requesterId = userId;
      } else if (direction === 'received') {
        query.targetId = userId;
      } else {
        query.$or = [
          { requesterId: userId },
          { targetId: userId }
        ];
      }

      // Statut
      if (status) {
        query.status = status;
      }

      // Expiration
      if (!includeExpired) {
        query.$and = [
          ...(query.$and || []),
          {
            $or: [
              { status: { $ne: 'pending' } },
              { expiresAt: { $gt: new Date() } }
            ]
          }
        ];
      }

      // Dates
      if (dateFrom || dateTo) {
        query.requestedAt = {};
        if (dateFrom) query.requestedAt.$gte = new Date(dateFrom);
        if (dateTo) query.requestedAt.$lte = new Date(dateTo);
      }

      // Options de tri
      const sortOptions = {};
      sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

      // Pagination
      const skip = (page - 1) * limit;

      // Exécution des requêtes en parallèle
      const [handshakes, totalCount, stats] = await Promise.all([
        Handshake.find(query)
          .populate('requesterId', 'username email')
          .populate('targetId', 'username email')
          .sort(sortOptions)
          .skip(skip)
          .limit(limit)
          .lean(),
        
        Handshake.countDocuments(query),
        
        this.getUserHandshakeStats(userId, filters)
      ]);

      return {
        handshakes,
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
      throw new Error(`Erreur récupération handshakes: ${error.message}`);
    }
  }

  /**
   * Annule un handshake (par le demandeur seulement)
   * @param {ObjectId} handshakeId - ID du handshake
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {String} reason - Raison de l'annulation
   * @returns {Promise<Object>} Handshake annulé
   */
  async cancel(handshakeId, userId, reason = 'user_cancelled') {
    try {
      const handshake = await Handshake.findById(handshakeId);

      if (!handshake) {
        throw new Error('Handshake non trouvé');
      }

      // Seul le demandeur peut annuler
      if (!handshake.requesterId.equals(new mongoose.Types.ObjectId(userId))) {
        throw new Error('Seul le demandeur peut annuler ce handshake');
      }

      // On ne peut annuler que les handshakes pending
      if (handshake.status !== 'pending') {
        throw new Error(`Impossible d'annuler un handshake ${handshake.status}`);
      }

      // Marquer comme annulé (utiliser expired pour simplifier)
      handshake.status = 'expired';
      handshake.respondedAt = new Date();
      handshake.responseMessage = `Annulé: ${reason}`;

      await handshake.save();

      return {
        handshake: await Handshake.findById(handshakeId)
          .populate('requesterId', 'username email')
          .populate('targetId', 'username email'),
        success: true,
        message: 'Handshake annulé'
      };

    } catch (error) {
      throw new Error(`Erreur annulation handshake: ${error.message}`);
    }
  }

  /**
   * Bloque un utilisateur (empêche futurs handshakes)
   * @param {ObjectId} handshakeId - ID du handshake
   * @param {ObjectId} userId - ID de l'utilisateur qui bloque
   * @returns {Promise<Object>} Handshake bloqué
   */
  async block(handshakeId, userId) {
    try {
      const handshake = await Handshake.findById(handshakeId);

      if (!handshake) {
        throw new Error('Handshake non trouvé');
      }

      // Seul le destinataire peut bloquer
      if (!handshake.targetId.equals(new mongoose.Types.ObjectId(userId))) {
        throw new Error('Seul le destinataire peut bloquer');
      }

      handshake.status = 'blocked';
      handshake.respondedAt = new Date();
      handshake.responseMessage = 'Utilisateur bloqué';

      await handshake.save();

      return {
        handshake: await Handshake.findById(handshakeId)
          .populate('requesterId', 'username email')
          .populate('targetId', 'username email'),
        success: true,
        message: 'Utilisateur bloqué'
      };

    } catch (error) {
      throw new Error(`Erreur blocage: ${error.message}`);
    }
  }

  /**
   * Nettoie automatiquement les handshakes expirés
   * @param {Number} batchSize - Taille des lots à traiter
   * @returns {Promise<Object>} Résultat du nettoyage
   */
  async cleanupExpiredHandshakes(batchSize = 100) {
    try {
      const now = new Date();
      
      // Marquer les handshakes expirés
      const expiredResult = await Handshake.updateMany(
        {
          status: 'pending',
          expiresAt: { $lt: now }
        },
        {
          $set: { 
            status: 'expired',
            respondedAt: now,
            responseMessage: 'Expiré automatiquement'
          }
        }
      );

      // Supprimer les très anciens handshakes déclinés/expirés (optionnel)
      const veryOld = new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000); // 6 mois
      const deletedResult = await Handshake.deleteMany({
        status: { $in: ['declined', 'expired'] },
        respondedAt: { $lt: veryOld }
      });

      return {
        expired: expiredResult.modifiedCount,
        deleted: deletedResult.deletedCount,
        processedAt: now
      };

    } catch (error) {
      throw new Error(`Erreur nettoyage handshakes: ${error.message}`);
    }
  }

  /**
   * Trouve les suggestions de handshakes pour un utilisateur
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {Object} options - Options de suggestions
   * @returns {Promise<Array>} Suggestions d'utilisateurs
   */
  async getSuggestions(userId, options = {}) {
    try {
      const { limit = 10, excludeExisting = true } = options;

      // Récupérer les utilisateurs avec qui il n'y a pas déjà de handshake
      let excludeIds = [userId];

      if (excludeExisting) {
        const existingHandshakes = await Handshake.find({
          $or: [
            { requesterId: userId },
            { targetId: userId }
          ]
        }).lean();

        const userObjectId = new mongoose.Types.ObjectId(userId);
        const existingUserIds = existingHandshakes.map(h => 
          h.requesterId.equals(userObjectId) ? h.targetId : h.requesterId
        );
        excludeIds = [...excludeIds, ...existingUserIds];
      }

      // Chercher des utilisateurs potentiels
      const suggestions = await User.find({
        _id: { $nin: excludeIds },
        'metadata.isActive': { $ne: false }
      })
      .select('username email metadata.responseCount metadata.lastActive')
      .limit(limit)
      .lean();

      return suggestions.map(user => ({
        userId: user._id,
        username: user.username,
        email: user.email,
        responseCount: user.metadata?.responseCount || 0,
        lastActive: user.metadata?.lastActive,
        suggested: true
      }));

    } catch (error) {
      throw new Error(`Erreur suggestions handshakes: ${error.message}`);
    }
  }

  // ===== MÉTHODES UTILITAIRES PRIVÉES =====

  /**
   * Valide que les utilisateurs existent
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   * @throws {Error} Si validation échoue
   */
  async validateUsers(userId1, userId2) {
    const [user1, user2] = await Promise.all([
      User.findById(userId1),
      User.findById(userId2)
    ]);

    if (!user1) {
      throw new Error('Premier utilisateur non trouvé');
    }
    if (!user2) {
      throw new Error('Deuxième utilisateur non trouvé');
    }
  }

  /**
   * Trouve un handshake existant entre deux utilisateurs
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   * @returns {Promise<Object|null>} Handshake existant ou null
   */
  async findExistingHandshake(userId1, userId2) {
    return await Handshake.findOne({
      $or: [
        { requesterId: userId1, targetId: userId2 },
        { requesterId: userId2, targetId: userId1 }
      ]
    }).populate('requesterId', 'username email')
      .populate('targetId', 'username email');
  }

  /**
   * Crée une requête normalisée pour les handshakes pour éviter les doublons
   * Utilise l'ordre déterministe des IDs pour la cohérence des requêtes
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   * @returns {Object} Query MongoDB normalisée
   */
  createNormalizedHandshakeQuery(userId1, userId2) {
    return {
      $or: [
        { requesterId: userId1, targetId: userId2 },
        { requesterId: userId2, targetId: userId1 }
      ]
    };
  }

  /**
   * Gère un handshake existant lors d'une tentative de création
   * @param {Object} existing - Handshake existant
   * @param {Object} options - Options de la requête
   * @returns {Object} Résultat avec détails
   */
  handleExistingHandshake(existing, options) {
    if (existing.status === 'pending') {
      if (existing.isExpired()) {
        return {
          handshake: existing,
          created: false,
          message: 'Handshake existant mais expiré'
        };
      }
      return {
        handshake: existing,
        created: false,
        message: 'Handshake déjà en attente de réponse'
      };
    }

    if (existing.status === 'accepted') {
      return {
        handshake: existing,
        created: false,
        message: 'Handshake déjà accepté'
      };
    }

    if (existing.status === 'declined') {
      return {
        handshake: existing,
        created: false,
        message: 'Handshake précédemment refusé'
      };
    }

    if (existing.status === 'blocked') {
      throw new Error('Impossible de créer un handshake, utilisateur bloqué');
    }

    return {
      handshake: existing,
      created: false,
      message: `Handshake existant avec statut: ${existing.status}`
    };
  }

  /**
   * Vérifie les limites anti-spam
   * @param {ObjectId} userId - ID de l'utilisateur
   * @throws {Error} Si limites dépassées
   */
  async checkSpamLimits(userId) {
    const recentCount = await Handshake.countDocuments({
      requesterId: userId,
      requestedAt: { 
        $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // 24h
      }
    });

    if (recentCount >= 10) {
      throw new Error('Limite de handshakes atteinte (10/jour)');
    }

    const pendingCount = await Handshake.countDocuments({
      requesterId: userId,
      status: 'pending'
    });

    if (pendingCount >= this.config.maxPending) {
      throw new Error(`Trop de handshakes en attente (${pendingCount}/${this.config.maxPending})`);
    }
  }

  /**
   * Met à jour les contacts associés après création d'un handshake
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   * @param {ObjectId} handshakeId - ID du handshake
   */
  async updateRelatedContacts(userId1, userId2, handshakeId) {
    try {
      // Mettre à jour les contacts existants avec le handshake
      await Promise.all([
        Contact.updateOne(
          { ownerId: userId1, contactUserId: userId2 },
          { $set: { handshakeId, status: 'active' } }
        ),
        Contact.updateOne(
          { ownerId: userId2, contactUserId: userId1 },
          { $set: { handshakeId, status: 'active' } }
        )
      ]);
    } catch (error) {
      // Ne pas faire échouer la création si les contacts ne peuvent pas être mis à jour
      console.warn('Erreur mise à jour contacts:', error.message);
    }
  }

  /**
   * Crée des contacts mutuels après acceptation
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   * @param {ObjectId} handshakeId - ID du handshake
   */
  async createMutualContacts(userId1, userId2, handshakeId) {
    try {
      const [user1, user2] = await Promise.all([
        User.findById(userId1),
        User.findById(userId2)
      ]);

      // Créer ou mettre à jour contact de user1 vers user2
      await Contact.findOneAndUpdate(
        { ownerId: userId1, contactUserId: userId2 },
        {
          ownerId: userId1,
          contactUserId: userId2,
          email: user2.email,
          firstName: user2.username,
          status: 'active',
          handshakeId,
          source: 'handshake'
        },
        { upsert: true }
      );

      // Créer ou mettre à jour contact de user2 vers user1
      await Contact.findOneAndUpdate(
        { ownerId: userId2, contactUserId: userId1 },
        {
          ownerId: userId2,
          contactUserId: userId1,
          email: user1.email,
          firstName: user1.username,
          status: 'active',
          handshakeId,
          source: 'handshake'
        },
        { upsert: true }
      );

    } catch (error) {
      console.warn('Erreur création contacts mutuels:', error.message);
    }
  }

  /**
   * Nettoie les contacts après refus
   * @param {ObjectId} userId1 - Premier utilisateur
   * @param {ObjectId} userId2 - Deuxième utilisateur
   */
  async cleanupDeclinedContacts(userId1, userId2) {
    try {
      // Optionnel: supprimer ou marquer comme inactifs les contacts
      await Promise.all([
        Contact.updateOne(
          { ownerId: userId1, contactUserId: userId2 },
          { $set: { status: 'declined', handshakeId: null } }
        ),
        Contact.updateOne(
          { ownerId: userId2, contactUserId: userId1 },
          { $set: { status: 'declined', handshakeId: null } }
        )
      ]);
    } catch (error) {
      console.warn('Erreur nettoyage contacts:', error.message);
    }
  }

  /**
   * Met à jour les statistiques d'un utilisateur
   * @param {ObjectId} userId - ID de l'utilisateur
   */
  async updateUserHandshakeStats(userId) {
    try {
      const stats = await Handshake.aggregate([
        { $match: { $or: [{ requesterId: userId }, { targetId: userId }] } },
        {
          $group: {
            _id: null,
            totalSent: { $sum: { $cond: [{ $eq: ['$requesterId', userId] }, 1, 0] } },
            totalReceived: { $sum: { $cond: [{ $eq: ['$targetId', userId] }, 1, 0] } },
            totalAccepted: { 
              $sum: { 
                $cond: [
                  { 
                    $and: [
                      { $eq: ['$status', 'accepted'] },
                      { $or: [{ $eq: ['$requesterId', userId] }, { $eq: ['$targetId', userId] }] }
                    ]
                  }, 
                  1, 
                  0
                ] 
              } 
            }
          }
        }
      ]);

      if (stats.length > 0) {
        const { totalSent, totalReceived, totalAccepted } = stats[0];
        
        await User.findByIdAndUpdate(userId, {
          $set: {
            'metadata.handshakesSent': totalSent,
            'metadata.handshakesReceived': totalReceived,
            'metadata.handshakesAccepted': totalAccepted,
            'metadata.lastActive': new Date()
          }
        });
      }

    } catch (error) {
      console.warn('Erreur mise à jour stats handshakes:', error.message);
    }
  }

  /**
   * Calcule les statistiques des handshakes d'un utilisateur
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {Object} filters - Filtres appliqués
   * @returns {Promise<Object>} Statistiques
   */
  async getUserHandshakeStats(userId, filters = {}) {
    try {
      const stats = await Handshake.aggregate([
        {
          $match: {
            $or: [{ requesterId: userId }, { targetId: userId }]
          }
        },
        {
          $group: {
            _id: null,
            totalSent: { $sum: { $cond: [{ $eq: ['$requesterId', userId] }, 1, 0] } },
            totalReceived: { $sum: { $cond: [{ $eq: ['$targetId', userId] }, 1, 0] } },
            totalAccepted: { 
              $sum: { $cond: [{ $eq: ['$status', 'accepted'] }, 1, 0] } 
            },
            totalDeclined: { 
              $sum: { $cond: [{ $eq: ['$status', 'declined'] }, 1, 0] } 
            },
            totalPending: { 
              $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] } 
            }
          }
        }
      ]);

      const result = stats[0] || {
        totalSent: 0,
        totalReceived: 0,
        totalAccepted: 0,
        totalDeclined: 0,
        totalPending: 0
      };

      // Calculer des métriques dérivées
      result.totalHandshakes = result.totalSent + result.totalReceived;
      result.acceptanceRate = result.totalSent > 0 ? 
        Math.round((result.totalAccepted / result.totalSent) * 100) : 0;
      result.responseRate = result.totalReceived > 0 ? 
        Math.round(((result.totalAccepted + result.totalDeclined) / result.totalReceived) * 100) : 0;

      return result;

    } catch (error) {
      throw new Error(`Erreur calcul statistiques: ${error.message}`);
    }
  }

  /**
   * Marque un handshake comme expiré
   * @param {Object} handshake - Handshake à marquer
   * @returns {Promise<Object>} Handshake mis à jour
   */
  async markExpired(handshake) {
    handshake.status = 'expired';
    handshake.respondedAt = new Date();
    handshake.responseMessage = 'Expiré automatiquement';
    return await handshake.save();
  }
}

module.exports = HandshakeService;