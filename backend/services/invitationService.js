const crypto = require('crypto');
const Invitation = require('../models/Invitation');
const User = require('../models/User');
const Submission = require('../models/Submission');
const mongoose = require('mongoose');

class InvitationService {
  constructor(config = {}) {
    this.config = {
      tokenLength: config.tokenLength || 32,
      shortCodeLength: config.shortCodeLength || 8,
      expirationDays: config.expirationDays || 60,
      antiTransferWindowHours: config.antiTransferWindowHours || 24,
      maxIpChanges: config.maxIpChanges || 3,
      rateLimitAttempts: config.rateLimitAttempts || 5
    };
  }

  /**
   * Crée une nouvelle invitation avec tokens sécurisés
   * @param {Object} invitationData - Données de l'invitation
   * @param {Object} securityContext - Contexte de sécurité (IP, User-Agent)
   * @returns {Promise<Object>} Invitation créée avec tokens
   */
  async createInvitation(invitationData, securityContext = {}) {
    try {
      const {
        fromUserId,
        toEmail,
        month,
        type = 'external',
        metadata = {},
        customExpiration = null
      } = invitationData;

      const { ipAddress, userAgent, referrer } = securityContext;

      // Validation des données requises
      if (!fromUserId || !toEmail || !month) {
        throw new Error('fromUserId, toEmail et month sont requis');
      }

      // Vérifier que l'expéditeur existe
      const fromUser = await User.findById(fromUserId);
      if (!fromUser) {
        throw new Error('Utilisateur expéditeur non trouvé');
      }

      // Vérifier les doublons pour ce mois
      const existingInvitation = await Invitation.findOne({
        fromUserId,
        toEmail: toEmail.toLowerCase(),
        month
      });

      if (existingInvitation && existingInvitation.status !== 'cancelled') {
        throw new Error(`Invitation déjà envoyée à ${toEmail} pour ${month}`);
      }

      // Chercher si le destinataire est un utilisateur existant
      const toUser = await User.findOne({ email: toEmail.toLowerCase() });
      
      // Générer tokens sécurisés
      const tokens = this.generateSecureTokens();
      
      // Calculer expiration
      const expiresAt = customExpiration || 
        new Date(Date.now() + this.config.expirationDays * 24 * 60 * 60 * 1000);

      // Créer code anti-transfert
      const antiTransferCode = this.generateAntiTransferCode(tokens.token, ipAddress, userAgent);

      const invitationToCreate = {
        fromUserId,
        toEmail: toEmail.toLowerCase(),
        toUserId: toUser?._id,
        month,
        type: toUser ? 'user' : 'external',
        token: tokens.token,
        shortCode: tokens.shortCode,
        expiresAt,
        tracking: {
          createdAt: new Date(),
          ipAddress,
          userAgent,
          referrer
        },
        metadata: {
          ...metadata,
          antiTransferCode,
          originalIp: ipAddress,
          originalUserAgent: userAgent,
          securityLevel: this.calculateSecurityLevel(securityContext)
        }
      };

      const invitation = new Invitation(invitationToCreate);
      await invitation.save();

      // Mettre à jour le contact si il existe
      if (fromUser) {
        try {
          await this.updateContactTracking(fromUserId, toEmail, 'invitation_created');
        } catch (error) {
          // Ne pas échouer la création d'invitation si le tracking contact échoue
          console.warn('Erreur mise à jour tracking contact:', error.message);
        }
      }

      // Retourner l'invitation avec relations populées
      return await Invitation.findById(invitation._id)
        .populate('fromUserId', 'username email')
        .populate('toUserId', 'username email');

    } catch (error) {
      if (error.code === 11000) {
        throw new Error('Une invitation existe déjà pour cette combinaison');
      }
      throw error;
    }
  }

  /**
   * Génère des tokens cryptographiquement sécurisés
   * @returns {Object} Tokens générés
   */
  generateSecureTokens() {
    // Token principal : 256 bits de sécurité
    const token = crypto.randomBytes(this.config.tokenLength).toString('hex');
    
    // Code court pour UX (évite les caractères ambigus)
    const shortCodeChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let shortCode = '';
    for (let i = 0; i < this.config.shortCodeLength; i++) {
      shortCode += shortCodeChars.charAt(Math.floor(Math.random() * shortCodeChars.length));
    }

    // Vérifier unicité (très improbable mais sécurité)
    return {
      token,
      shortCode,
      entropy: this.calculateEntropy(token),
      createdAt: new Date()
    };
  }

  /**
   * Génère un code anti-transfert lié au contexte
   * @param {String} token - Token principal
   * @param {String} ipAddress - Adresse IP
   * @param {String} userAgent - User Agent
   * @returns {String} Code anti-transfert
   */
  generateAntiTransferCode(token, ipAddress = '', userAgent = '') {
    const data = `${token}:${ipAddress}:${userAgent}:${Date.now()}`;
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
  }

  /**
   * Valide un token d'invitation avec vérifications de sécurité
   * @param {String} token - Token à valider
   * @param {Object} securityContext - Contexte de sécurité actuel
   * @returns {Promise<Object>} Résultat de validation
   */
  async validateInvitationToken(token, securityContext = {}) {
    try {
      if (!token) {
        throw new Error('Token requis');
      }

      // Chercher l'invitation
      const invitation = await Invitation.findOne({ token })
        .populate('fromUserId', 'username email')
        .populate('toUserId', 'username email')
        .populate('submissionId');

      if (!invitation) {
        return {
          valid: false,
          reason: 'TOKEN_NOT_FOUND',
          message: 'Token d\'invitation invalide'
        };
      }

      // Vérifier expiration
      if (invitation.isExpired()) {
        return {
          valid: false,
          reason: 'TOKEN_EXPIRED',
          message: 'L\'invitation a expiré',
          invitation
        };
      }

      // Vérifier statut
      if (invitation.status === 'submitted') {
        return {
          valid: false,
          reason: 'ALREADY_SUBMITTED',
          message: 'Cette invitation a déjà été utilisée',
          invitation
        };
      }

      if (invitation.status === 'cancelled') {
        return {
          valid: false,
          reason: 'CANCELLED',
          message: 'Cette invitation a été annulée',
          invitation
        };
      }

      // Vérifications de sécurité anti-transfert
      const securityCheck = await this.performSecurityChecks(invitation, securityContext);
      
      if (!securityCheck.passed) {
        return {
          valid: false,
          reason: 'SECURITY_VIOLATION',
          message: securityCheck.message,
          securityRisk: securityCheck.riskLevel,
          invitation
        };
      }

      // Marquer comme ouvert si première validation
      if (invitation.status === 'sent' || invitation.status === 'queued') {
        await invitation.markAction('opened', {
          ipAddress: securityContext.ipAddress,
          userAgent: securityContext.userAgent
        });
      }

      return {
        valid: true,
        invitation,
        securityLevel: securityCheck.securityLevel,
        remaining: {
          days: Math.ceil((invitation.expiresAt - new Date()) / (24 * 60 * 60 * 1000)),
          hours: Math.ceil((invitation.expiresAt - new Date()) / (60 * 60 * 1000))
        }
      };

    } catch (error) {
      throw new Error(`Erreur validation token: ${error.message}`);
    }
  }

  /**
   * Effectue les vérifications de sécurité anti-transfert
   * @param {Object} invitation - Invitation à vérifier
   * @param {Object} securityContext - Contexte de sécurité actuel
   * @returns {Promise<Object>} Résultat des vérifications
   */
  async performSecurityChecks(invitation, securityContext) {
    const { ipAddress, userAgent } = securityContext;
    const checks = {
      passed: true,
      securityLevel: 'normal',
      riskLevel: 'low',
      message: '',
      details: []
    };

    // Vérifier le code anti-transfert
    if (invitation.metadata?.antiTransferCode) {
      const expectedCode = this.generateAntiTransferCode(
        invitation.token,
        invitation.metadata.originalIp,
        invitation.metadata.originalUserAgent
      );

      if (invitation.metadata.antiTransferCode !== expectedCode) {
        checks.details.push('Code anti-transfert invalide');
        checks.riskLevel = 'medium';
      }
    }

    // Vérifier changement d'IP
    if (invitation.metadata?.originalIp && ipAddress) {
      if (invitation.metadata.originalIp !== ipAddress) {
        // Vérifier l'historique des IPs
        const ipChanges = await this.countIpChanges(invitation._id);
        if (ipChanges >= this.config.maxIpChanges) {
          checks.passed = false;
          checks.riskLevel = 'high';
          checks.message = 'Trop de changements d\'adresse IP détectés';
          return checks;
        }
        
        checks.details.push(`Changement d'IP détecté (${ipChanges + 1}/${this.config.maxIpChanges})`);
        checks.securityLevel = 'elevated';
      }
    }

    // Vérifier User-Agent
    if (invitation.metadata?.originalUserAgent && userAgent) {
      const similarity = this.calculateUserAgentSimilarity(
        invitation.metadata.originalUserAgent,
        userAgent
      );
      
      if (similarity < 0.7) {
        checks.details.push('User-Agent très différent détecté');
        checks.riskLevel = checks.riskLevel === 'low' ? 'medium' : checks.riskLevel;
      }
    }

    // Vérifier rate limiting
    const recentAttempts = await this.countRecentAttempts(invitation.token, ipAddress);
    if (recentAttempts >= this.config.rateLimitAttempts) {
      checks.passed = false;
      checks.riskLevel = 'high';
      checks.message = 'Trop de tentatives d\'accès récentes';
      return checks;
    }

    // Loguer l'accès pour tracking
    await this.logAccess(invitation._id, securityContext, checks);

    return checks;
  }

  /**
   * Valide un code court d'invitation
   * @param {String} shortCode - Code court à valider
   * @param {String} month - Mois de l'invitation (optionnel pour performance)
   * @returns {Promise<Object>} Résultat de validation
   */
  async validateShortCode(shortCode, month = null) {
    try {
      if (!shortCode || shortCode.length !== this.config.shortCodeLength) {
        return {
          valid: false,
          reason: 'INVALID_FORMAT',
          message: 'Format de code invalide'
        };
      }

      const query = { shortCode: shortCode.toUpperCase() };
      if (month) {
        query.month = month;
      }

      const invitation = await Invitation.findOne(query)
        .populate('fromUserId', 'username email');

      if (!invitation) {
        return {
          valid: false,
          reason: 'CODE_NOT_FOUND',
          message: 'Code d\'invitation non trouvé'
        };
      }

      // Utiliser la validation complète avec le token
      return await this.validateInvitationToken(invitation.token);

    } catch (error) {
      throw new Error(`Erreur validation code court: ${error.message}`);
    }
  }

  /**
   * Marque une invitation comme commencée
   * @param {String} token - Token de l'invitation
   * @param {Object} securityContext - Contexte de sécurité
   * @returns {Promise<Object>} Invitation mise à jour
   */
  async markInvitationStarted(token, securityContext = {}) {
    try {
      const validation = await this.validateInvitationToken(token, securityContext);
      
      if (!validation.valid) {
        throw new Error(validation.message);
      }

      const invitation = validation.invitation;

      await invitation.markAction('started', {
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent
      });

      return await Invitation.findById(invitation._id)
        .populate('fromUserId', 'username email')
        .populate('toUserId', 'username email');

    } catch (error) {
      throw new Error(`Erreur marquage démarrage: ${error.message}`);
    }
  }

  /**
   * Marque une invitation comme soumise et lie la submission
   * @param {String} token - Token de l'invitation
   * @param {ObjectId} submissionId - ID de la submission créée
   * @param {Object} securityContext - Contexte de sécurité
   * @returns {Promise<Object>} Invitation mise à jour
   */
  async markInvitationSubmitted(token, submissionId, securityContext = {}) {
    try {
      const validation = await this.validateInvitationToken(token, securityContext);
      
      if (!validation.valid) {
        throw new Error(validation.message);
      }

      const invitation = validation.invitation;

      // Vérifier que la submission existe
      const submission = await Submission.findById(submissionId);
      if (!submission) {
        throw new Error('Submission non trouvée');
      }

      await invitation.markAction('submitted', {
        ipAddress: securityContext.ipAddress,
        userAgent: securityContext.userAgent,
        submissionId
      });

      // Mettre à jour le tracking du contact
      try {
        await this.updateContactTracking(
          invitation.fromUserId,
          invitation.toEmail,
          'submitted'
        );
      } catch (error) {
        console.warn('Erreur mise à jour tracking contact:', error.message);
      }

      return await Invitation.findById(invitation._id)
        .populate('fromUserId', 'username email')
        .populate('toUserId', 'username email')
        .populate('submissionId');

    } catch (error) {
      throw new Error(`Erreur marquage soumission: ${error.message}`);
    }
  }

  /**
   * Annule une invitation
   * @param {ObjectId} invitationId - ID de l'invitation
   * @param {ObjectId} userId - ID de l'utilisateur (pour autorisation)
   * @param {String} reason - Raison de l'annulation
   * @returns {Promise<Object>} Invitation annulée
   */
  async cancelInvitation(invitationId, userId, reason = 'user_cancelled') {
    try {
      const invitation = await Invitation.findById(invitationId);
      
      if (!invitation) {
        throw new Error('Invitation non trouvée');
      }

      // Vérifier autorisation
      if (!invitation.fromUserId.equals(new mongoose.Types.ObjectId(userId))) {
        throw new Error('Non autorisé à annuler cette invitation');
      }

      if (invitation.status === 'submitted') {
        throw new Error('Impossible d\'annuler une invitation déjà soumise');
      }

      invitation.status = 'cancelled';
      invitation.metadata = {
        ...invitation.metadata,
        cancelledAt: new Date(),
        cancelReason: reason,
        cancelledBy: userId
      };

      await invitation.save();

      return await Invitation.findById(invitationId)
        .populate('fromUserId', 'username email')
        .populate('toUserId', 'username email');

    } catch (error) {
      throw new Error(`Erreur annulation invitation: ${error.message}`);
    }
  }

  /**
   * Prolonge l'expiration d'une invitation
   * @param {ObjectId} invitationId - ID de l'invitation
   * @param {ObjectId} userId - ID de l'utilisateur (pour autorisation)
   * @param {Number} additionalDays - Jours à ajouter
   * @returns {Promise<Object>} Invitation mise à jour
   */
  async extendInvitation(invitationId, userId, additionalDays = 30) {
    try {
      const invitation = await Invitation.findById(invitationId);
      
      if (!invitation) {
        throw new Error('Invitation non trouvée');
      }

      // Vérifier autorisation
      if (!invitation.fromUserId.equals(new mongoose.Types.ObjectId(userId))) {
        throw new Error('Non autorisé à prolonger cette invitation');
      }

      if (invitation.status === 'submitted' || invitation.status === 'cancelled') {
        throw new Error('Impossible de prolonger cette invitation');
      }

      const newExpiration = new Date(invitation.expiresAt.getTime() + additionalDays * 24 * 60 * 60 * 1000);
      
      invitation.expiresAt = newExpiration;
      invitation.metadata = {
        ...invitation.metadata,
        extendedAt: new Date(),
        extendedBy: userId,
        additionalDays
      };

      await invitation.save();

      return await Invitation.findById(invitationId)
        .populate('fromUserId', 'username email')
        .populate('toUserId', 'username email');

    } catch (error) {
      throw new Error(`Erreur prolongation invitation: ${error.message}`);
    }
  }

  /**
   * Récupère une invitation spécifique par ID avec validation d'autorisation
   * @param {ObjectId} invitationId - ID de l'invitation
   * @param {ObjectId} userId - ID de l'utilisateur (pour autorisation)
   * @returns {Promise<Object|null>} Invitation trouvée avec données liées ou null
   */
  async getInvitationById(invitationId, userId) {
    try {
      const invitation = await Invitation.findById(invitationId)
        .populate('fromUserId', 'username email')
        .populate('toUserId', 'username email')
        .populate('submissionId');
      
      if (!invitation) {
        return null;
      }

      // CRITICAL AUTHORIZATION CHECK: Ensure user owns this invitation
      const userObjectId = new mongoose.Types.ObjectId(userId);
      if (!invitation.fromUserId._id.equals(userObjectId)) {
        // Also check if user is the recipient (for some use cases)
        const isRecipient = invitation.toUserId && invitation.toUserId._id.equals(userObjectId);
        if (!isRecipient) {
          throw new Error('Non autorisé à accéder à cette invitation');
        }
      }

      return invitation;

    } catch (error) {
      throw new Error(`Erreur récupération invitation: ${error.message}`);
    }
  }

  /**
   * Récupère les invitations avec filtres et pagination
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {Object} filters - Filtres de recherche
   * @param {Object} pagination - Options de pagination
   * @returns {Promise<Object>} Invitations avec statistiques
   */
  async getInvitations(userId, filters = {}, pagination = {}) {
    try {
      const {
        status = '',
        month = '',
        type = '',
        search = '',
        dateFrom = null,
        dateTo = null,
        includeExpired = false
      } = filters;

      const {
        page = 1,
        limit = 20,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = pagination;

      // Construction de la query
      const query = { fromUserId: userId };

      // Filtres
      if (status) query.status = status;
      if (month) query.month = month;
      if (type) query.type = type;
      
      if (search) {
        query.toEmail = { $regex: search, $options: 'i' };
      }

      if (!includeExpired) {
        query.expiresAt = { $gt: new Date() };
      }

      if (dateFrom || dateTo) {
        query.createdAt = {};
        if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
        if (dateTo) query.createdAt.$lte = new Date(dateTo);
      }

      // Options de tri
      const sortOptions = {};
      sortOptions[sortBy] = sortOrder === 'desc' ? -1 : 1;

      // Pagination
      const skip = (page - 1) * limit;

      // Exécution des requêtes en parallèle
      const [invitations, totalCount, stats] = await Promise.all([
        Invitation.find(query)
          .populate('fromUserId', 'username email')
          .populate('toUserId', 'username email')
          .populate('submissionId')
          .sort(sortOptions)
          .skip(skip)
          .limit(limit),
        
        Invitation.countDocuments(query),
        
        this.getInvitationStats(userId)
      ]);

      return {
        invitations,
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
      throw new Error(`Erreur récupération invitations: ${error.message}`);
    }
  }

  /**
   * Calcule les statistiques des invitations
   * @param {ObjectId} userId - ID de l'utilisateur
   * @returns {Promise<Object>} Statistiques complètes
   */
  async getInvitationStats(userId) {
    try {
      const [basicStats, statusStats, monthlyStats, responseStats] = await Promise.all([
        // Statistiques de base
        Invitation.aggregate([
          { $match: { fromUserId: userId } },
          {
            $group: {
              _id: null,
              total: { $sum: 1 },
              sent: { $sum: { $cond: [{ $ne: ['$status', 'queued'] }, 1, 0] } },
              opened: { $sum: { $cond: [{ $in: ['$status', ['opened', 'started', 'submitted']] }, 1, 0] } },
              submitted: { $sum: { $cond: [{ $eq: ['$status', 'submitted'] }, 1, 0] } },
              expired: { $sum: { $cond: [{ $eq: ['$status', 'expired'] }, 1, 0] } }
            }
          }
        ]),

        // Statistiques par statut
        Invitation.aggregate([
          { $match: { fromUserId: userId } },
          { $group: { _id: '$status', count: { $sum: 1 } } }
        ]),

        // Statistiques mensuelles (6 derniers mois)
        Invitation.aggregate([
          { $match: { fromUserId: userId } },
          {
            $group: {
              _id: '$month',
              count: { $sum: 1 },
              submitted: { $sum: { $cond: [{ $eq: ['$status', 'submitted'] }, 1, 0] } }
            }
          },
          { $sort: { '_id': -1 } },
          { $limit: 6 }
        ]),

        // Taux de réponse
        Invitation.aggregate([
          { $match: { fromUserId: userId, status: { $ne: 'queued' } } },
          {
            $group: {
              _id: null,
              totalSent: { $sum: 1 },
              totalSubmitted: { $sum: { $cond: [{ $eq: ['$status', 'submitted'] }, 1, 0] } },
              avgResponseTime: {
                $avg: {
                  $cond: [
                    { $and: ['$tracking.sentAt', '$tracking.submittedAt'] },
                    { $subtract: ['$tracking.submittedAt', '$tracking.sentAt'] },
                    null
                  ]
                }
              }
            }
          }
        ])
      ]);

      const basic = basicStats[0] || { total: 0, sent: 0, opened: 0, submitted: 0, expired: 0 };
      const response = responseStats[0] || { totalSent: 0, totalSubmitted: 0, avgResponseTime: 0 };

      return {
        basic,
        byStatus: statusStats,
        monthly: monthlyStats,
        responseRate: response.totalSent > 0 ? 
          Math.round((response.totalSubmitted / response.totalSent) * 100) : 0,
        avgResponseTimeHours: response.avgResponseTime ? 
          Math.round(response.avgResponseTime / (1000 * 60 * 60)) : 0
      };

    } catch (error) {
      throw new Error(`Erreur calcul statistiques: ${error.message}`);
    }
  }

  // ===== MÉTHODES UTILITAIRES PRIVÉES =====

  /**
   * Calcule le niveau de sécurité du contexte
   * @param {Object} securityContext - Contexte de sécurité
   * @returns {String} Niveau de sécurité
   */
  calculateSecurityLevel(securityContext) {
    const { ipAddress, userAgent, referrer } = securityContext;
    let score = 0;

    if (ipAddress) score += 25;
    if (userAgent) score += 25;
    if (referrer) score += 25;
    if (ipAddress && this.isPublicIP(ipAddress)) score += 25;

    if (score >= 75) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
  }

  /**
   * Calcule l'entropie d'un token
   * @param {String} token - Token à analyser
   * @returns {Number} Entropie en bits
   */
  calculateEntropy(token) {
    const charset = new Set(token);
    const charsetSize = charset.size;
    return Math.log2(Math.pow(charsetSize, token.length));
  }

  /**
   * Calcule la similarité entre deux User-Agents
   * @param {String} ua1 - Premier User-Agent
   * @param {String} ua2 - Deuxième User-Agent
   * @returns {Number} Score de similarité (0-1)
   */
  calculateUserAgentSimilarity(ua1, ua2) {
    if (!ua1 || !ua2) return 0;
    
    // Extraire les informations clés
    const extract = (ua) => {
      const info = {
        browser: '',
        version: '',
        os: '',
        device: ''
      };
      
      // Patterns simplifiés pour extraction
      if (ua.includes('Chrome/')) info.browser = 'Chrome';
      else if (ua.includes('Firefox/')) info.browser = 'Firefox';
      else if (ua.includes('Safari/')) info.browser = 'Safari';
      
      if (ua.includes('Windows')) info.os = 'Windows';
      else if (ua.includes('Mac OS')) info.os = 'Mac';
      else if (ua.includes('Linux')) info.os = 'Linux';
      
      return info;
    };

    const info1 = extract(ua1);
    const info2 = extract(ua2);
    
    let matches = 0;
    let total = 0;
    
    for (const key in info1) {
      total++;
      if (info1[key] === info2[key] && info1[key] !== '') {
        matches++;
      }
    }
    
    return total > 0 ? matches / total : 0;
  }

  /**
   * Compte les changements d'IP pour une invitation
   * @param {ObjectId} invitationId - ID de l'invitation
   * @returns {Promise<Number>} Nombre de changements d'IP
   */
  async countIpChanges(invitationId) {
    // Implémentation simple - pourrait être étendue avec une collection d'audit
    return 0; // Pour l'instant, retourner 0
  }

  /**
   * Compte les tentatives récentes d'accès
   * @param {String} token - Token de l'invitation
   * @param {String} ipAddress - Adresse IP
   * @returns {Promise<Number>} Nombre de tentatives récentes
   */
  async countRecentAttempts(token, ipAddress) {
    // Implémentation simple - pourrait utiliser Redis pour le cache
    return 0; // Pour l'instant, retourner 0
  }

  /**
   * Logue un accès pour audit
   * @param {ObjectId} invitationId - ID de l'invitation
   * @param {Object} securityContext - Contexte de sécurité
   * @param {Object} checks - Résultats des vérifications
   */
  async logAccess(invitationId, securityContext, checks) {
    // Implémentation d'audit - pourrait écrire dans une collection séparée
    console.log(`Access logged for invitation ${invitationId}:`, {
      ip: securityContext.ipAddress,
      userAgent: securityContext.userAgent,
      securityLevel: checks.securityLevel,
      riskLevel: checks.riskLevel
    });
  }

  /**
   * Vérifie si une IP est publique
   * @param {String} ip - Adresse IP
   * @returns {Boolean} IP publique
   */
  isPublicIP(ip) {
    // Vérifications basiques pour IP privées
    if (!ip) return false;
    
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^localhost$/i
    ];
    
    return !privateRanges.some(range => range.test(ip));
  }

  /**
   * Met à jour le tracking de contact si disponible
   * @param {ObjectId} userId - ID de l'utilisateur
   * @param {String} email - Email du contact
   * @param {String} event - Événement de tracking
   */
  async updateContactTracking(userId, email, event) {
    try {
      // Chercher le contact correspondant
      const Contact = require('../models/Contact');
      const contact = await Contact.findOne({
        ownerId: userId,
        email: email.toLowerCase()
      });

      if (contact) {
        const eventMap = {
          'invitation_created': 'sent',
          'submitted': 'submitted'
        };

        const trackingEvent = eventMap[event];
        if (trackingEvent) {
          await contact.updateTracking(trackingEvent);
        }
      }
    } catch (error) {
      // Erreur silencieuse pour ne pas affecter l'invitation
      console.warn('Erreur tracking contact:', error.message);
    }
  }

  /**
   * Nettoie les invitations expirées
   * @param {Number} batchSize - Taille du lot à traiter
   * @returns {Promise<Object>} Résultat du nettoyage
   */
  async cleanupExpiredInvitations(batchSize = 100) {
    try {
      const now = new Date();
      
      // Marquer les invitations expirées
      const expiredResult = await Invitation.updateMany(
        {
          expiresAt: { $lt: now },
          status: { $nin: ['expired', 'submitted', 'cancelled'] }
        },
        {
          $set: { status: 'expired' }
        }
      );

      // Supprimer les très anciennes invitations (optionnel)
      const veryOld = new Date(now.getTime() - 365 * 24 * 60 * 60 * 1000); // 1 an
      const deletedResult = await Invitation.deleteMany({
        expiresAt: { $lt: veryOld },
        status: 'expired'
      });

      return {
        expired: expiredResult.modifiedCount,
        deleted: deletedResult.deletedCount,
        processedAt: now
      };

    } catch (error) {
      throw new Error(`Erreur nettoyage invitations: ${error.message}`);
    }
  }
}

module.exports = InvitationService;