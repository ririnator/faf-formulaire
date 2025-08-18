const Contact = require('../models/Contact');
const User = require('../models/User');
const Handshake = require('../models/Handshake');
const { validateEmailDomain, isDisposableEmail } = require('../middleware/emailDomainValidation');
const { sanitizeMongoInput, sanitizeObjectId, logSecurityEvent } = require('../middleware/querySanitization');
const mongoose = require('mongoose');
const csv = require('csv-parser');
const { Readable } = require('stream');

// Legacy sanitization functions removed - now using centralized querySanitization middleware
// which provides comprehensive protection against NoSQL injection and advanced query attacks

class ContactService {
  constructor(config = {}) {
    this.config = {
      maxCsvSize: config.maxCsvSize || (5 * 1024 * 1024), // 5MB
      maxBatchSize: config.maxBatchSize || 100,
      maxTags: config.maxTags || 10,
      maxNameLength: config.maxNameLength || 100,
      maxEmailLength: config.maxEmailLength || 320,
      maxNotesLength: config.maxNotesLength || 1000,
      maxTagLength: config.maxTagLength || 50
    };
  }
  
  /**
   * Ajoute un nouveau contact avec validation et gestion des doublons
   * @param {Object} contactData - Données du contact
   * @param {ObjectId} ownerId - ID du propriétaire
   * @returns {Promise<Object>} Contact créé avec informations sur les handshakes
   */
  async addContact(contactData, ownerId) {
    try {
      // Sanitize inputs to prevent NoSQL injection
      const sanitizedContactData = sanitizeMongoInput(contactData);
      const sanitizedOwnerId = sanitizeObjectId(ownerId);
      
      const { email, firstName, lastName, tags = [], notes = '', source = 'manual' } = sanitizedContactData;

      // Validation des données requises
      if (!email || !sanitizedOwnerId) {
        throw new Error('Email et ownerId sont requis');
      }

      const sanitizedEmail = email.toLowerCase().trim();

      // Validate email domain for security
      const domainValidation = await validateEmailDomain(sanitizedEmail);
      if (!domainValidation.isValid) {
        throw new Error(`Email non autorisé: ${domainValidation.message}`);
      }

      // Vérifier si le contact existe déjà
      const existingContact = await Contact.findOne({ 
        ownerId: new mongoose.Types.ObjectId(sanitizedOwnerId), 
        email: sanitizedEmail 
      });
      if (existingContact) {
        throw new Error(`Contact avec l'email ${email} existe déjà`);
      }

      // Chercher si un utilisateur avec cet email existe
      const existingUser = await User.findOne({ email: sanitizedEmail });
      
      // Créer le contact
      const contactToCreate = {
        ownerId: new mongoose.Types.ObjectId(sanitizedOwnerId),
        email: sanitizedEmail,
        firstName: firstName?.trim(),
        lastName: lastName?.trim(),
        tags: Array.isArray(tags) ? tags.map(tag => tag.trim()).filter(Boolean).slice(0, this.config.maxTags) : [],
        notes: notes?.trim(),
        source,
        status: 'pending'
      };

      // Si l'utilisateur existe, lier le contact et créer un handshake automatique
      if (existingUser) {
        contactToCreate.contactUserId = existingUser._id;
        contactToCreate.status = 'active';
      }

      const contact = new Contact(contactToCreate);
      await contact.save();

      let handshakeCreated = false;
      let handshakeError = null;

      // Créer un handshake automatique si l'utilisateur existe
      if (existingUser && !new mongoose.Types.ObjectId(ownerId).equals(new mongoose.Types.ObjectId(existingUser._id))) {
        try {
          const handshake = await this.createAutomaticHandshake(ownerId, existingUser._id, 'contact_add');
          handshakeCreated = true;
          contact.handshakeId = handshake._id;
          await contact.save();
        } catch (error) {
          handshakeError = error.message;
        }
      }

      // Populer les références
      const populatedContact = await Contact.findById(contact._id)
        .populate('ownerId', 'username email')
        .populate('contactUserId', 'username email')
        .populate('handshakeId');

      return {
        contact: populatedContact,
        handshakeCreated,
        handshakeError,
        userExists: !!existingUser
      };

    } catch (error) {
      if (error.code === 11000) {
        throw new Error('Contact avec cet email existe déjà pour ce propriétaire');
      }
      throw error;
    }
  }

  /**
   * Importe des contacts depuis un fichier CSV
   * @param {Buffer|String} csvData - Données CSV
   * @param {ObjectId} ownerId - ID du propriétaire
   * @param {Object} options - Options d'import
   * @returns {Promise<Object>} Résultat de l'import
   */
  async importCSV(csvData, ownerId, options = {}) {
    const {
      skipDuplicates = true,
      createHandshakes = true,
      defaultSource = 'csv',
      batchSize = this.config.maxBatchSize
    } = options;

    const results = {
      total: 0,
      imported: [], // Array of imported contacts
      duplicates: [], // Array of duplicate entries
      skipped: 0,
      errors: [],
      handshakesCreated: 0,
      handshakeErrors: []
    };

    try {
      const contacts = await this.parseCSV(csvData);
      results.total = contacts.length;

      // Traitement par lots pour éviter la surcharge
      for (let i = 0; i < contacts.length; i += batchSize) {
        const batch = contacts.slice(i, i + batchSize);
        await this.processBatch(batch, ownerId, {
          skipDuplicates,
          createHandshakes,
          defaultSource
        }, results);
      }

      return results;

    } catch (error) {
      throw new Error(`Erreur lors de l'import CSV: ${error.message}`);
    }
  }

  /**
   * Sanitize CSV cell value to prevent formula injection
   * @param {string} value - Cell value to sanitize
   * @returns {string} Sanitized value
   */
  sanitizeCSVCell(value) {
    if (!value || typeof value !== 'string') return value;
    
    const trimmedValue = value.trim();
    
    // Enhanced formula injection protection - comprehensive indicators
    const formulaIndicators = ['=', '@', '+', '-', '|', '\t', '\r'];
    const dangerousFunctions = [
      'WEBSERVICE(', 'IMPORTDATA(', 'IMPORTXML(', 'IMPORTHTML(',
      'HYPERLINK(', 'DDE(', 'EXEC(', 'CALL(', 'MDETERM(', 'MMULT(',
      'cmd', 'powershell', 'bash', 'sh', 'eval(', 'exec('
    ];
    
    // Advanced formula detection patterns
    const advancedPatterns = [
      /^[=@+\-\t\r]/,           // Formula indicators at start
      /\$\{.*\}/,               // Variable substitution
      /\beval\s*\(/i,           // Eval function calls
      /\bexec\s*\(/i,           // Exec function calls
      /\bcmd\b/i,               // Command execution
      /\bpowershell\b/i,        // PowerShell execution
      /\bbash\b/i,              // Bash execution
      /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/ // Control characters
    ];
    
    // Check for formula indicators at start
    if (formulaIndicators.some(char => trimmedValue.startsWith(char))) {
      return "'" + value; // Prefix with single quote to make it literal
    }
    
    // Check for dangerous function calls
    const upperValue = trimmedValue.toUpperCase();
    if (dangerousFunctions.some(func => upperValue.includes(func))) {
      return "'" + value; // Neutralize dangerous functions
    }
    
    // Check advanced patterns
    if (advancedPatterns.some(pattern => pattern.test(trimmedValue))) {
      return "'" + value; // Neutralize advanced threats
    }
    
    // Remove any embedded null bytes or control characters
    return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  }
  
  /**
   * Sanitize data for CSV export to prevent formula injection
   * @param {Object} contact - Contact object to sanitize
   * @returns {Object} Sanitized contact object
   */
  sanitizeForCSVExport(contact) {
    const sanitized = { ...contact };
    
    // Sanitize string fields that will be exported to CSV
    const fieldsToSanitize = ['firstName', 'lastName', 'email', 'notes'];
    fieldsToSanitize.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = this.sanitizeCSVCell(sanitized[field]);
      }
    });
    
    // Sanitize tags array
    if (Array.isArray(sanitized.tags)) {
      sanitized.tags = sanitized.tags.map(tag => this.sanitizeCSVCell(tag));
    }
    
    return sanitized;
  }

  /**
   * Parse un fichier CSV et retourne un tableau de contacts
   * @param {Buffer|String} csvData - Données CSV
   * @returns {Promise<Array>} Array de contacts parsés
   */
  async parseCSV(csvData) {
    return new Promise((resolve, reject) => {
      const contacts = [];
      const csvStream = typeof csvData === 'string' 
        ? Readable.from(csvData) 
        : Readable.from(csvData.toString());

      csvStream
        .pipe(csv({
          mapHeaders: ({ header }) => header.toLowerCase().trim(),
          skipEmptyLines: true
        }))
        .on('data', (row) => {
          // Sanitize all row values to prevent formula injection
          for (const key in row) {
            row[key] = this.sanitizeCSVCell(row[key]);
          }
          
          // Mapping flexible des colonnes
          const contact = {
            email: row.email || row['e-mail'] || row.mail,
            firstName: row.firstname || row['first_name'] || row.prenom || row['prénom'] || row.nom,
            lastName: row.lastname || row['last_name'] || row.nom_famille || row.famille,
            tags: this.parseTags(row.tags || row.tag || row.categories),
            notes: row.notes || row.note || row.commentaire || row.description || ''
          };

          // Validation basique et vérification du domaine
          if (contact.email && this.isValidEmail(contact.email) && !isDisposableEmail(contact.email)) {
            contacts.push(contact);
          }
        })
        .on('end', () => resolve(contacts))
        .on('error', reject);
    });
  }

  /**
   * Traite un lot de contacts pour l'import
   * @param {Array} batch - Lot de contacts
   * @param {ObjectId} ownerId - ID du propriétaire
   * @param {Object} options - Options de traitement
   * @param {Object} results - Objet de résultats à mettre à jour
   */
  async processBatch(batch, ownerId, options, results) {
    const { skipDuplicates, createHandshakes, defaultSource } = options;

    for (const contactData of batch) {
      try {
        contactData.source = defaultSource;

        // Vérifier les doublons si demandé
        if (skipDuplicates) {
          const existingContact = await Contact.findOne({ 
            ownerId, 
            email: contactData.email.toLowerCase() 
          });
          
          if (existingContact) {
            results.skipped++;
            results.duplicates.push({
              email: contactData.email,
              reason: 'Email already exists for this owner'
            });
            continue;
          }
        }

        const result = await this.addContact(contactData, ownerId);
        results.imported.push(result.contact);

        if (result.handshakeCreated) {
          results.handshakesCreated++;
        }

        if (result.handshakeError) {
          results.handshakeErrors.push({
            email: contactData.email,
            error: result.handshakeError
          });
        }

      } catch (error) {
        results.errors.push({
          email: contactData.email || 'email_invalide',
          error: error.message
        });
      }
    }
  }

  /**
   * Récupère les contacts avec statistiques complètes
   * @param {ObjectId} ownerId - ID du propriétaire
   * @param {Object} filters - Filtres de recherche
   * @param {Object} pagination - Options de pagination
   * @returns {Promise<Object>} Contacts avec statistiques
   */
  async getContactsWithStats(ownerId, filters = {}, pagination = {}) {
    try {
      // Sanitize inputs to prevent NoSQL injection
      const sanitizedOwnerId = sanitizeObjectId(ownerId);
      const sanitizedFilters = sanitizeMongoInput(filters);
      const sanitizedPagination = sanitizeMongoInput(pagination);
      
      if (!sanitizedOwnerId) {
        throw new Error('Invalid ownerId provided');
      }
      
      const {
        search = '',
        status = '',
        tags = [],
        source = '',
        hasHandshake = null,
        dateFrom = null,
        dateTo = null
      } = sanitizedFilters;

      const {
        page = 1,
        limit = 20,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = pagination;

      // Construction de la query
      const query = { ownerId: new mongoose.Types.ObjectId(sanitizedOwnerId) };

      // Filtres de recherche
      if (search) {
        query.$or = [
          { firstName: { $regex: search, $options: 'i' } },
          { lastName: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } }
        ];
      }

      if (status) {
        query.status = status;
      }

      if (tags.length > 0) {
        query.tags = { $in: tags };
      }

      if (source) {
        query.source = source;
      }

      if (hasHandshake !== null) {
        if (hasHandshake) {
          query.handshakeId = { $exists: true };
        } else {
          query.handshakeId = { $exists: false };
        }
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
      const [contacts, totalCount, stats] = await Promise.all([
        Contact.find(query)
          .populate('ownerId', 'username email')
          .populate('contactUserId', 'username email')
          .populate('handshakeId')
          .sort(sortOptions)
          .skip(skip)
          .limit(limit),
        
        Contact.countDocuments(query),
        
        this.getContactStats(ownerId)
      ]);

      return {
        contacts,
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
      throw new Error(`Erreur lors de la récupération des contacts: ${error.message}`);
    }
  }

  /**
   * Calcule les statistiques des contacts
   * @param {ObjectId} ownerId - ID du propriétaire
   * @returns {Promise<Object>} Statistiques complètes
   */
  async getContactStats(ownerId) {
    try {
      const [basicStats, sourceStats, statusStats, monthlyStats, responseStats] = await Promise.all([
        // Statistiques de base
        Contact.aggregate([
          { $match: { ownerId } },
          {
            $group: {
              _id: null,
              total: { $sum: 1 },
              withHandshake: { 
                $sum: { $cond: [{ $ifNull: ['$handshakeId', false] }, 1, 0] } 
              },
              withUser: { 
                $sum: { $cond: [{ $ifNull: ['$contactUserId', false] }, 1, 0] } 
              },
              avgResponseRate: { $avg: '$tracking.responseRate' },
              totalInvitationsSent: { $sum: '$tracking.invitationsSent' },
              totalResponsesReceived: { $sum: '$tracking.responsesReceived' }
            }
          }
        ]),

        // Statistiques par source
        Contact.aggregate([
          { $match: { ownerId } },
          { $group: { _id: '$source', count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ]),

        // Statistiques par statut
        Contact.aggregate([
          { $match: { ownerId } },
          { $group: { _id: '$status', count: { $sum: 1 } } }
        ]),

        // Statistiques mensuelles (6 derniers mois)
        Contact.aggregate([
          { $match: { ownerId } },
          {
            $group: {
              _id: {
                year: { $year: '$createdAt' },
                month: { $month: '$createdAt' }
              },
              count: { $sum: 1 }
            }
          },
          { $sort: { '_id.year': -1, '_id.month': -1 } },
          { $limit: 6 }
        ]),

        // Statistiques de réponse
        Contact.aggregate([
          { $match: { ownerId } },
          {
            $group: {
              _id: null,
              topPerformers: {
                $push: {
                  $cond: [
                    { $gte: ['$tracking.responseRate', 80] },
                    {
                      email: '$email',
                      responseRate: '$tracking.responseRate',
                      responsesReceived: '$tracking.responsesReceived'
                    },
                    '$$REMOVE'
                  ]
                }
              }
            }
          }
        ])
      ]);

      return {
        basic: basicStats[0] || {
          total: 0,
          withHandshake: 0,
          withUser: 0,
          avgResponseRate: 0,
          totalInvitationsSent: 0,
          totalResponsesReceived: 0
        },
        bySource: sourceStats,
        byStatus: statusStats,
        monthly: monthlyStats,
        topPerformers: responseStats[0]?.topPerformers || []
      };

    } catch (error) {
      throw new Error(`Erreur lors du calcul des statistiques: ${error.message}`);
    }
  }

  /**
   * Met à jour le tracking d'un contact
   * @param {ObjectId} contactId - ID du contact
   * @param {String} event - Type d'événement (sent, opened, submitted)
   * @param {Object} metadata - Métadonnées de l'événement
   * @returns {Promise<Object>} Contact mis à jour
   */
  async updateTracking(contactId, event, metadata = {}) {
    try {
      const contact = await Contact.findById(contactId);
      if (!contact) {
        throw new Error('Contact non trouvé');
      }

      // Calculer le temps de réponse si applicable
      if (event === 'submitted' && contact.tracking.lastSentAt) {
        const responseTimeHours = (Date.now() - contact.tracking.lastSentAt.getTime()) / (1000 * 60 * 60);
        metadata = { ...metadata, responseTime: Math.round(responseTimeHours * 100) / 100 };
      }

      await contact.updateTracking(event, metadata);

      // Retourner le contact mis à jour avec les relations populées
      return await Contact.findById(contactId)
        .populate('ownerId', 'username email')
        .populate('contactUserId', 'username email')
        .populate('handshakeId');

    } catch (error) {
      throw new Error(`Erreur lors de la mise à jour du tracking: ${error.message}`);
    }
  }

  /**
   * Crée un handshake automatique entre deux utilisateurs
   * @param {ObjectId} requesterId - ID du demandeur
   * @param {ObjectId} targetId - ID de la cible
   * @param {String} source - Source de la création
   * @returns {Promise<Object>} Handshake créé
   */
  async createAutomaticHandshake(requesterId, targetId, source = 'contact_add') {
    try {
      // Vérifier qu'un handshake n'existe pas déjà
      const existingHandshake = await Handshake.findOne({
        $or: [
          { requesterId, targetId },
          { requesterId: targetId, targetId: requesterId }
        ]
      });

      if (existingHandshake) {
        if (existingHandshake.status === 'pending') {
          throw new Error('Une demande de handshake est déjà en cours');
        } else if (existingHandshake.status === 'accepted') {
          throw new Error('Handshake déjà accepté');
        } else {
          throw new Error('Handshake existe déjà avec un autre statut');
        }
      }

      const handshake = new Handshake({
        requesterId,
        targetId,
        metadata: {
          initiatedBy: source
        }
      });

      await handshake.save();

      return await Handshake.findById(handshake._id)
        .populate('requesterId', 'username email')
        .populate('targetId', 'username email');

    } catch (error) {
      throw error;
    }
  }

  /**
   * Recherche des contacts avec correspondance fuzzy
   * @param {ObjectId} ownerId - ID du propriétaire
   * @param {String} searchTerm - Terme de recherche
   * @param {Object} options - Options de recherche
   * @returns {Promise<Array>} Contacts trouvés
   */
  async searchContacts(ownerId, searchTerm, options = {}) {
    const { limit = 10, includeInactive = false } = options;

    try {
      const query = {
        ownerId,
        $or: [
          { firstName: { $regex: searchTerm, $options: 'i' } },
          { lastName: { $regex: searchTerm, $options: 'i' } },
          { email: { $regex: searchTerm, $options: 'i' } },
          { tags: { $regex: searchTerm, $options: 'i' } }
        ]
      };

      if (!includeInactive) {
        query.status = { $in: ['active', 'pending'] };
      }

      const contacts = await Contact.find(query)
        .populate('contactUserId', 'username email')
        .limit(limit)
        .sort({ 'tracking.responseRate': -1, createdAt: -1 });

      return contacts;

    } catch (error) {
      throw new Error(`Erreur lors de la recherche: ${error.message}`);
    }
  }

  /**
   * Supprime un contact et nettoie les références
   * @param {ObjectId} contactId - ID du contact
   * @param {ObjectId} ownerId - ID du propriétaire (pour vérification)
   * @returns {Promise<Boolean>} Succès de la suppression
   */
  async deleteContact(contactId, ownerId) {
    try {
      // Sanitize inputs to prevent NoSQL injection
      const sanitizedContactId = sanitizeObjectId(contactId);
      const sanitizedOwnerId = sanitizeObjectId(ownerId);
      
      if (!sanitizedContactId || !sanitizedOwnerId) {
        throw new Error('Invalid contactId or ownerId provided');
      }
      
      const contact = await Contact.findOne({ 
        _id: new mongoose.Types.ObjectId(sanitizedContactId), 
        ownerId: new mongoose.Types.ObjectId(sanitizedOwnerId) 
      });
      if (!contact) {
        throw new Error('Contact non trouvé ou non autorisé');
      }

      // Supprimer le handshake associé si il existe
      if (contact.handshakeId) {
        await Handshake.findByIdAndDelete(contact.handshakeId);
      }

      await Contact.findByIdAndDelete(contactId);
      return true;

    } catch (error) {
      throw new Error(`Erreur lors de la suppression: ${error.message}`);
    }
  }

  /**
   * Récupère un contact spécifique par son ID
   * @param {ObjectId} contactId - ID du contact
   * @param {ObjectId} ownerId - ID du propriétaire
   * @returns {Promise<Object>} Contact trouvé
   */
  async getContactById(contactId, ownerId) {
    try {
      // Sanitize inputs to prevent NoSQL injection
      const sanitizedContactId = sanitizeObjectId(contactId);
      const sanitizedOwnerId = sanitizeObjectId(ownerId);
      
      if (!sanitizedContactId || !sanitizedOwnerId) {
        throw new Error('Invalid contactId or ownerId provided');
      }
      
      const contact = await Contact.findOne({ 
        _id: new mongoose.Types.ObjectId(sanitizedContactId), 
        ownerId: new mongoose.Types.ObjectId(sanitizedOwnerId) 
      })
        .populate('contactUserId', 'username email')
        .populate('handshakeId')
        .lean();
      
      if (!contact) {
        return null;
      }

      return contact;
    } catch (error) {
      throw new Error(`Erreur lors de la récupération du contact: ${error.message}`);
    }
  }

  /**
   * Met à jour un contact existant
   * @param {ObjectId} contactId - ID du contact
   * @param {ObjectId} ownerId - ID du propriétaire
   * @param {Object} updateData - Données de mise à jour
   * @returns {Promise<Object>} Contact mis à jour
   */
  async updateContact(contactId, ownerId, updateData) {
    try {
      // Sanitize inputs to prevent NoSQL injection
      const sanitizedContactId = sanitizeObjectId(contactId);
      const sanitizedOwnerId = sanitizeObjectId(ownerId);
      const sanitizedUpdateData = sanitizeMongoInput(updateData);
      
      if (!sanitizedContactId || !sanitizedOwnerId) {
        throw new Error('Invalid contactId or ownerId provided');
      }
      
      const contact = await Contact.findOne({ 
        _id: new mongoose.Types.ObjectId(sanitizedContactId), 
        ownerId: new mongoose.Types.ObjectId(sanitizedOwnerId) 
      });
      if (!contact) {
        throw new Error('Contact non trouvé ou non autorisé');
      }

      // Mettre à jour les champs autorisés
      if (sanitizedUpdateData.firstName !== undefined) contact.firstName = sanitizedUpdateData.firstName;
      if (sanitizedUpdateData.lastName !== undefined) contact.lastName = sanitizedUpdateData.lastName;
      if (sanitizedUpdateData.tags !== undefined) contact.tags = sanitizedUpdateData.tags;
      if (sanitizedUpdateData.notes !== undefined) contact.notes = sanitizedUpdateData.notes;
      if (sanitizedUpdateData.status !== undefined) contact.status = sanitizedUpdateData.status;

      contact.updatedAt = new Date();
      await contact.save();

      return contact;
    } catch (error) {
      throw new Error(`Erreur lors de la mise à jour: ${error.message}`);
    }
  }

  /**
   * Récupère les statistiques globales des contacts pour un utilisateur
   * @param {ObjectId} ownerId - ID du propriétaire
   * @param {Object} options - Options de filtrage
   * @returns {Promise<Object>} Statistiques globales
   */
  async getGlobalContactStats(ownerId, options = {}) {
    try {
      const pipeline = [
        { $match: { ownerId: new mongoose.Types.ObjectId(ownerId) } },
        {
          $group: {
            _id: null,
            totalContacts: { $sum: 1 },
            activeContacts: {
              $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
            },
            contactsWithHandshake: {
              $sum: { $cond: [{ $ne: ['$handshakeId', null] }, 1, 0] }
            },
            averageResponseRate: { $avg: '$metadata.responseRate' },
            lastInteractionDate: { $max: '$metadata.lastInteraction' }
          }
        }
      ];

      const result = await Contact.aggregate(pipeline);
      return result[0] || {
        totalContacts: 0,
        activeContacts: 0,
        contactsWithHandshake: 0,
        averageResponseRate: 0,
        lastInteractionDate: null
      };
    } catch (error) {
      throw new Error(`Erreur lors du calcul des statistiques: ${error.message}`);
    }
  }

  /**
   * Importe des contacts depuis CSV (alias pour importCSV)
   * @param {string} csvData - Données CSV
   * @param {ObjectId} ownerId - ID du propriétaire
   * @param {Object} options - Options d'importation
   * @returns {Promise<Object>} Résultats de l'importation
   */
  async importContactsFromCSV(csvData, ownerId, options = {}) {
    return this.importCSV(csvData, ownerId, options);
  }

  /**
   * Met à jour le tracking d'un contact (alias pour updateTracking)
   * @param {ObjectId} contactId - ID du contact
   * @param {ObjectId} ownerId - ID du propriétaire (pour sécurité)
   * @param {string} event - Type d'événement
   * @param {Object} metadata - Métadonnées de l'événement
   * @returns {Promise<Object>} Résultat de la mise à jour
   */
  async updateContactTracking(contactId, ownerId, event, metadata = {}) {
    try {
      // Vérifier que le contact appartient bien au propriétaire
      const contact = await Contact.findOne({ _id: contactId, ownerId });
      if (!contact) {
        throw new Error('Contact non trouvé ou non autorisé');
      }

      return this.updateTracking(contactId, event, metadata);
    } catch (error) {
      throw new Error(`Erreur lors de la mise à jour du tracking: ${error.message}`);
    }
  }

  /**
   * Export contacts to CSV format with comprehensive security sanitization
   * @param {Array} contacts - Array of contact objects to export
   * @returns {Promise<string>} CSV formatted string
   */
  async exportContactsToCSV(contacts) {
    try {
      if (!contacts || contacts.length === 0) {
        throw new Error('No contacts to export');
      }

      // CSV headers with comprehensive fields
      const headers = [
        'Email',
        'First Name',
        'Last Name', 
        'Status',
        'Tags',
        'Notes',
        'Source',
        'Created At',
        'Updated At',
        'Response Rate',
        'Last Interaction'
      ];

      // Start with BOM for UTF-8 support in Excel
      let csvContent = '\uFEFF';
      
      // Add headers
      csvContent += headers.join(',') + '\n';

      // Process each contact with security sanitization
      for (const contact of contacts) {
        const sanitizedContact = this.sanitizeForCSVExport(contact);
        
        const row = [
          this.escapeCSVField(sanitizedContact.email || ''),
          this.escapeCSVField(sanitizedContact.firstName || ''),
          this.escapeCSVField(sanitizedContact.lastName || ''),
          this.escapeCSVField(sanitizedContact.status || ''),
          this.escapeCSVField(Array.isArray(sanitizedContact.tags) ? sanitizedContact.tags.join('; ') : ''),
          this.escapeCSVField(sanitizedContact.notes || ''),
          this.escapeCSVField(sanitizedContact.source || ''),
          this.escapeCSVField(sanitizedContact.createdAt ? new Date(sanitizedContact.createdAt).toISOString() : ''),
          this.escapeCSVField(sanitizedContact.updatedAt ? new Date(sanitizedContact.updatedAt).toISOString() : ''),
          this.escapeCSVField(sanitizedContact.tracking?.responseRate?.toString() || '0'),
          this.escapeCSVField(sanitizedContact.tracking?.lastInteraction ? new Date(sanitizedContact.tracking.lastInteraction).toISOString() : '')
        ];

        csvContent += row.join(',') + '\n';
      }

      return csvContent;

    } catch (error) {
      throw new Error(`Erreur lors de l'export CSV: ${error.message}`);
    }
  }

  /**
   * Escape and sanitize CSV field value according to RFC 4180 and security best practices
   * @param {string} field - Field value to escape
   * @returns {string} Properly escaped CSV field
   */
  escapeCSVField(field) {
    if (!field || typeof field !== 'string') {
      return '""'; // Empty quoted field
    }

    // First, sanitize for CSV injection
    let sanitized = this.sanitizeCSVCell(field);
    
    // Remove line breaks that could break CSV structure
    sanitized = sanitized.replace(/[\r\n]/g, ' ');
    
    // Check if field needs to be quoted (contains comma, quote, or whitespace)
    const needsQuoting = /[,"\s]/.test(sanitized);
    
    if (needsQuoting) {
      // Escape internal quotes by doubling them
      sanitized = sanitized.replace(/"/g, '""');
      return `"${sanitized}"`;
    }
    
    return sanitized;
  }

  // ===== MÉTHODES UTILITAIRES =====

  /**
   * Valide le format d'un email
   * @param {String} email - Email à valider
   * @returns {Boolean} Email valide
   */
  isValidEmail(email) {
    if (!email) return false;
    const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
    return emailRegex.test(email) && !email.includes('..') && !email.startsWith('.') && !email.endsWith('.');
  }

  /**
   * Parse les tags depuis une string CSV
   * @param {String} tagsString - String de tags séparés par des virgules
   * @returns {Array} Array de tags nettoyés
   */
  parseTags(tagsString) {
    if (!tagsString) return [];
    
    return tagsString
      .split(',')
      .map(tag => tag.trim())
      .filter(Boolean)
      .slice(0, this.config.maxTags);
  }

  /**
   * Valide les données d'un contact
   * @param {Object} contactData - Données à valider
   * @returns {Object} Données validées
   */
  validateContactData(contactData) {
    const { email, firstName, lastName, tags, notes } = contactData;

    if (!email) {
      throw new Error('Email est requis');
    }

    if (!this.isValidEmail(email)) {
      throw new Error('Format d\'email invalide');
    }

    if (firstName && firstName.length > this.config.maxNameLength) {
      throw new Error(`Prénom trop long (max ${this.config.maxNameLength} caractères)`);
    }

    if (lastName && lastName.length > this.config.maxNameLength) {
      throw new Error(`Nom trop long (max ${this.config.maxNameLength} caractères)`);
    }

    if (notes && notes.length > this.config.maxNotesLength) {
      throw new Error(`Notes trop longues (max ${this.config.maxNotesLength} caractères)`);
    }

    if (tags && Array.isArray(tags)) {
      tags.forEach(tag => {
        if (tag.length > this.config.maxTagLength) {
          throw new Error(`Tag trop long (max ${this.config.maxTagLength} caractères)`);
        }
      });
    }

    return {
      email: email.toLowerCase().trim(),
      firstName: firstName?.trim(),
      lastName: lastName?.trim(),
      tags: Array.isArray(tags) ? tags.map(t => t.trim()).filter(Boolean) : [],
      notes: notes?.trim() || ''
    };
  }
}

module.exports = ContactService;