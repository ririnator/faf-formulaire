/**
 * Validateur de Tokens Legacy - Migration FAF
 * 
 * Vérifie la préservation et le mapping des tokens legacy :
 * - Préservation de tous les tokens existants
 * - Mapping correct Response.token → Invitation.token
 * - Test des URLs legacy (doivent fonctionner)
 * - Vérification des statuts Invitation
 * - Validation des métadonnées de migration
 * 
 * @author FAF Migration Team
 */

const BaseValidator = require('./BaseValidator');
const crypto = require('crypto');

class TokenValidator extends BaseValidator {
    constructor(db, logger) {
        super('Validation des Tokens Legacy', db, logger);
        this.results = {
            tokenPreservation: {},
            tokenMapping: {},
            urlValidation: {},
            statusValidation: {},
            migrationMetadata: {},
            tokenStats: {}
        };
    }

    /**
     * Validation principale des tokens
     */
    async validate() {
        this.logger.info('🎫 Début de la validation des tokens legacy...');
        
        try {
            await this.validateTokenPreservation();
            await this.validateTokenMapping();
            await this.validateTokenStatuses();
            await this.validateTokenFormats();
            await this.validateMigrationMetadata();
            await this.calculateTokenStats();
            
            const score = this.calculateScore();
            
            return {
                category: 'tokens',
                success: score >= 95,
                score,
                errors: this.errors,
                details: this.results,
                metadata: {
                    totalTokens: this.results.tokenStats.totalTokens,
                    preservationRate: this.results.tokenPreservation.preservationRate
                }
            };
            
        } catch (error) {
            this.addError('VALIDATION_FAILED', `Échec de la validation des tokens: ${error.message}`);
            throw error;
        }
    }

    /**
     * Validation de la préservation des tokens
     */
    async validateTokenPreservation() {
        this.logger.info('🔍 Validation de la préservation des tokens...');
        
        // Récupération des tokens originaux depuis les responses
        const originalTokens = await this.getOriginalTokens();
        
        // Récupération des tokens migrés depuis les invitations
        const migratedTokens = await this.getMigratedTokens();
        
        // Analyse de la préservation
        const preservationAnalysis = this.analyzeTokenPreservation(originalTokens, migratedTokens);
        
        this.results.tokenPreservation = preservationAnalysis;
        
        // Vérification des tokens manquants
        if (preservationAnalysis.missingTokens.length > 0) {
            for (const missingToken of preservationAnalysis.missingTokens) {
                this.addError(
                    'MISSING_TOKEN',
                    `Token legacy non préservé: ${missingToken.token} (Response: ${missingToken.responseId})`,
                    { token: missingToken.token, responseId: missingToken.responseId }
                );
            }
        }
        
        // Vérification des tokens en surplus
        if (preservationAnalysis.extraTokens.length > 0) {
            for (const extraToken of preservationAnalysis.extraTokens) {
                this.addWarning(
                    'EXTRA_TOKEN',
                    `Token en surplus dans les invitations: ${extraToken}`,
                    { token: extraToken }
                );
            }
        }
    }

    /**
     * Récupération des tokens originaux
     */
    async getOriginalTokens() {
        const responses = await this.db.collection('responses')
            .find({ 
                token: { $exists: true, $ne: null },
                isAdmin: { $ne: true } 
            })
            .project({ _id: 1, token: 1, name: 1, month: 1, createdAt: 1 })
            .toArray();
        
        return responses.map(r => ({
            token: r.token,
            responseId: r._id,
            name: r.name,
            month: r.month,
            createdAt: r.createdAt
        }));
    }

    /**
     * Récupération des tokens migrés
     */
    async getMigratedTokens() {
        const invitations = await this.db.collection('invitations')
            .find({ token: { $exists: true, $ne: null } })
            .project({ _id: 1, token: 1, userId: 1, status: 1, createdAt: 1, migrationData: 1 })
            .toArray();
        
        return invitations.map(i => ({
            token: i.token,
            invitationId: i._id,
            userId: i.userId,
            status: i.status,
            createdAt: i.createdAt,
            migrationData: i.migrationData
        }));
    }

    /**
     * Analyse de la préservation des tokens
     */
    analyzeTokenPreservation(originalTokens, migratedTokens) {
        const originalTokenSet = new Set(originalTokens.map(t => t.token));
        const migratedTokenSet = new Set(migratedTokens.map(t => t.token));
        
        const preservedTokens = originalTokens.filter(t => migratedTokenSet.has(t.token));
        const missingTokens = originalTokens.filter(t => !migratedTokenSet.has(t.token));
        const extraTokens = [...migratedTokenSet].filter(t => !originalTokenSet.has(t));
        
        const preservationRate = originalTokens.length > 0 
            ? (preservedTokens.length / originalTokens.length) * 100 
            : 100;
        
        return {
            totalOriginal: originalTokens.length,
            totalMigrated: migratedTokens.length,
            preserved: preservedTokens.length,
            missing: missingTokens.length,
            extra: extraTokens.length,
            preservationRate,
            preservedTokens,
            missingTokens,
            extraTokens
        };
    }

    /**
     * Validation du mapping des tokens
     */
    async validateTokenMapping() {
        this.logger.info('🗺️ Validation du mapping des tokens...');
        
        const mappingResults = {
            validMappings: [],
            invalidMappings: [],
            orphanedInvitations: [],
            mappingAccuracy: 0
        };
        
        // Récupération des correspondances Response → Invitation par token
        const tokenCorrespondences = await this.getTokenCorrespondences();
        
        for (const correspondence of tokenCorrespondences) {
            const isValidMapping = await this.validateTokenCorrespondence(correspondence);
            
            if (isValidMapping) {
                mappingResults.validMappings.push(correspondence);
            } else {
                mappingResults.invalidMappings.push(correspondence);
            }
        }
        
        // Recherche d'invitations orphelines
        const orphanedInvitations = await this.findOrphanedInvitations();
        mappingResults.orphanedInvitations = orphanedInvitations;
        
        // Calcul de la précision du mapping
        const totalMappings = mappingResults.validMappings.length + mappingResults.invalidMappings.length;
        mappingResults.mappingAccuracy = totalMappings > 0 
            ? (mappingResults.validMappings.length / totalMappings) * 100 
            : 0;
        
        this.results.tokenMapping = mappingResults;
        
        // Erreurs pour les mappings invalides
        for (const invalidMapping of mappingResults.invalidMappings) {
            this.addError(
                'INVALID_TOKEN_MAPPING',
                `Mapping invalide pour token ${invalidMapping.token}`,
                invalidMapping
            );
        }
        
        // Erreurs pour les invitations orphelines
        for (const orphaned of orphanedInvitations) {
            this.addError(
                'ORPHANED_INVITATION',
                `Invitation orpheline avec token ${orphaned.token}`,
                { invitationId: orphaned._id, token: orphaned.token }
            );
        }
    }

    /**
     * Récupération des correspondances token
     */
    async getTokenCorrespondences() {
        const pipeline = [
            {
                $match: {
                    token: { $exists: true, $ne: null },
                    isAdmin: { $ne: true }
                }
            },
            {
                $lookup: {
                    from: 'invitations',
                    localField: 'token',
                    foreignField: 'token',
                    as: 'invitation'
                }
            },
            {
                $project: {
                    token: 1,
                    name: 1,
                    month: 1,
                    createdAt: 1,
                    invitation: { $arrayElemAt: ['$invitation', 0] }
                }
            }
        ];
        
        return await this.db.collection('responses').aggregate(pipeline).toArray();
    }

    /**
     * Validation d'une correspondance token
     */
    async validateTokenCorrespondence(correspondence) {
        if (!correspondence.invitation) {
            this.addError(
                'MISSING_INVITATION_FOR_TOKEN',
                `Aucune invitation trouvée pour le token ${correspondence.token}`,
                { responseId: correspondence._id, token: correspondence.token }
            );
            return false;
        }
        
        const response = correspondence;
        const invitation = correspondence.invitation;
        
        // Vérification de la cohérence des données
        let isValid = true;
        
        // Vérification du nom utilisateur
        if (invitation.migrationData && invitation.migrationData.legacyName) {
            if (invitation.migrationData.legacyName !== response.name) {
                this.addError(
                    'NAME_MISMATCH_IN_MAPPING',
                    `Nom incohérent pour token ${response.token}: Response(${response.name}) vs Invitation(${invitation.migrationData.legacyName})`,
                    { token: response.token, responseName: response.name, invitationName: invitation.migrationData.legacyName }
                );
                isValid = false;
            }
        }
        
        // Vérification des timestamps (tolérance de 5 minutes)
        if (response.createdAt && invitation.createdAt) {
            const timeDiff = Math.abs(
                new Date(response.createdAt) - new Date(invitation.createdAt)
            );
            
            if (timeDiff > 300000) { // 5 minutes
                this.addWarning(
                    'TIMESTAMP_MISMATCH_IN_MAPPING',
                    `Horodatage incohérent pour token ${response.token} (diff: ${this.formatDuration(timeDiff)})`,
                    { token: response.token, timeDiff }
                );
            }
        }
        
        return isValid;
    }

    /**
     * Recherche d'invitations orphelines
     */
    async findOrphanedInvitations() {
        const pipeline = [
            {
                $lookup: {
                    from: 'responses',
                    localField: 'token',
                    foreignField: 'token',
                    as: 'response'
                }
            },
            {
                $match: {
                    response: { $size: 0 },
                    token: { $exists: true, $ne: null }
                }
            },
            {
                $project: {
                    token: 1,
                    userId: 1,
                    status: 1,
                    createdAt: 1
                }
            }
        ];
        
        return await this.db.collection('invitations').aggregate(pipeline).toArray();
    }

    /**
     * Validation des statuts des invitations
     */
    async validateTokenStatuses() {
        this.logger.info('📊 Validation des statuts des invitations...');
        
        const invitations = await this.db.collection('invitations')
            .find({ token: { $exists: true, $ne: null } })
            .project({ _id: 1, token: 1, status: 1, createdAt: 1, expiresAt: 1 })
            .toArray();
        
        const statusValidation = {
            validStatuses: [],
            invalidStatuses: [],
            expiredTokens: [],
            statusDistribution: {}
        };
        
        const validStatuses = ['active', 'used', 'expired'];
        const now = new Date();
        
        for (const invitation of invitations) {
            // Validation du statut
            if (!validStatuses.includes(invitation.status)) {
                statusValidation.invalidStatuses.push(invitation);
                this.addError(
                    'INVALID_INVITATION_STATUS',
                    `Statut invalide pour l'invitation ${invitation._id}: ${invitation.status}`,
                    { invitationId: invitation._id, status: invitation.status }
                );
            } else {
                statusValidation.validStatuses.push(invitation);
            }
            
            // Comptage des statuts
            statusValidation.statusDistribution[invitation.status] = 
                (statusValidation.statusDistribution[invitation.status] || 0) + 1;
            
            // Vérification de l'expiration
            if (invitation.expiresAt && new Date(invitation.expiresAt) < now) {
                if (invitation.status !== 'expired') {
                    statusValidation.expiredTokens.push(invitation);
                    this.addError(
                        'EXPIRED_TOKEN_WRONG_STATUS',
                        `Token expiré avec statut incorrect: ${invitation.token} (statut: ${invitation.status})`,
                        { invitationId: invitation._id, token: invitation.token, status: invitation.status }
                    );
                }
            }
        }
        
        this.results.statusValidation = statusValidation;
    }

    /**
     * Validation des formats de tokens
     */
    async validateTokenFormats() {
        this.logger.info('🔤 Validation des formats de tokens...');
        
        const formatValidation = {
            validTokens: [],
            invalidTokens: [],
            duplicateTokens: [],
            formatIssues: []
        };
        
        // Vérification des tokens dans responses
        const responseTokens = await this.db.collection('responses')
            .find({ token: { $exists: true, $ne: null } })
            .project({ _id: 1, token: 1 })
            .toArray();
        
        // Vérification des tokens dans invitations
        const invitationTokens = await this.db.collection('invitations')
            .find({ token: { $exists: true, $ne: null } })
            .project({ _id: 1, token: 1 })
            .toArray();
        
        const allTokens = [
            ...responseTokens.map(r => ({ ...r, source: 'response' })),
            ...invitationTokens.map(i => ({ ...i, source: 'invitation' }))
        ];
        
        const tokenCounts = new Map();
        
        for (const tokenDoc of allTokens) {
            const token = tokenDoc.token;
            
            // Validation du format
            if (!this.isValidTokenFormat(token)) {
                formatValidation.invalidTokens.push(tokenDoc);
                this.addError(
                    'INVALID_TOKEN_FORMAT',
                    `Format de token invalide: ${token} (${tokenDoc.source})`,
                    { documentId: tokenDoc._id, token, source: tokenDoc.source }
                );
            } else {
                formatValidation.validTokens.push(tokenDoc);
            }
            
            // Comptage pour détecter les doublons
            const key = `${token}-${tokenDoc.source}`;
            tokenCounts.set(key, (tokenCounts.get(key) || 0) + 1);
        }
        
        // Détection des doublons
        for (const [key, count] of tokenCounts) {
            if (count > 1) {
                const [token, source] = key.split('-');
                formatValidation.duplicateTokens.push({ token, source, count });
                this.addError(
                    'DUPLICATE_TOKEN',
                    `Token en doublon dans ${source}: ${token} (${count} occurrences)`,
                    { token, source, count }
                );
            }
        }
        
        this.results.tokenFormats = formatValidation;
    }

    /**
     * Validation du format d'un token
     */
    isValidTokenFormat(token) {
        if (!token || typeof token !== 'string') {
            return false;
        }
        
        // Les tokens doivent être non vides et avoir une longueur raisonnable
        if (token.length === 0 || token.length > 255) {
            return false;
        }
        
        // Pas de caractères dangereux
        const dangerousChars = /[<>\"'&]/;
        if (dangerousChars.test(token)) {
            return false;
        }
        
        return true;
    }

    /**
     * Validation des métadonnées de migration
     */
    async validateMigrationMetadata() {
        this.logger.info('📋 Validation des métadonnées de migration...');
        
        const invitations = await this.db.collection('invitations')
            .find({ token: { $exists: true, $ne: null } })
            .project({ _id: 1, token: 1, migrationData: 1, createdAt: 1 })
            .toArray();
        
        const metadataValidation = {
            withMetadata: [],
            withoutMetadata: [],
            invalidMetadata: [],
            metadataCompleteness: 0
        };
        
        for (const invitation of invitations) {
            if (!invitation.migrationData) {
                metadataValidation.withoutMetadata.push(invitation);
                this.addWarning(
                    'MISSING_MIGRATION_METADATA',
                    `Métadonnées de migration manquantes pour l'invitation ${invitation._id}`,
                    { invitationId: invitation._id, token: invitation.token }
                );
                continue;
            }
            
            // Validation de la structure des métadonnées
            const metadata = invitation.migrationData;
            const requiredFields = ['legacyName', 'migratedAt', 'source'];
            const missingFields = requiredFields.filter(field => !metadata[field]);
            
            if (missingFields.length > 0) {
                metadataValidation.invalidMetadata.push(invitation);
                this.addError(
                    'INVALID_MIGRATION_METADATA',
                    `Métadonnées de migration incomplètes pour l'invitation ${invitation._id}: ${missingFields.join(', ')} manquant(s)`,
                    { invitationId: invitation._id, missingFields }
                );
            } else {
                metadataValidation.withMetadata.push(invitation);
                
                // Validation de la cohérence temporelle
                if (metadata.migratedAt && invitation.createdAt) {
                    const migrationTime = new Date(metadata.migratedAt);
                    const creationTime = new Date(invitation.createdAt);
                    
                    if (migrationTime > creationTime) {
                        this.addWarning(
                            'MIGRATION_TIME_INCONSISTENCY',
                            `Heure de migration postérieure à la création pour l'invitation ${invitation._id}`,
                            { invitationId: invitation._id }
                        );
                    }
                }
            }
        }
        
        metadataValidation.metadataCompleteness = invitations.length > 0
            ? (metadataValidation.withMetadata.length / invitations.length) * 100
            : 100;
        
        this.results.migrationMetadata = metadataValidation;
    }

    /**
     * Calcul des statistiques des tokens
     */
    async calculateTokenStats() {
        this.logger.info('📈 Calcul des statistiques des tokens...');
        
        const [responsesWithTokens, invitationsWithTokens] = await Promise.all([
            this.db.collection('responses').countDocuments({ 
                token: { $exists: true, $ne: null },
                isAdmin: { $ne: true }
            }),
            this.db.collection('invitations').countDocuments({ 
                token: { $exists: true, $ne: null } 
            })
        ]);
        
        const tokenStats = {
            totalTokens: responsesWithTokens,
            migratedTokens: invitationsWithTokens,
            migrationRate: responsesWithTokens > 0 
                ? (invitationsWithTokens / responsesWithTokens) * 100 
                : 100,
            preservationRate: this.results.tokenPreservation.preservationRate || 0
        };
        
        this.results.tokenStats = tokenStats;
    }

    /**
     * Formatage de durée
     */
    formatDuration(ms) {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes % 60}m`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        } else {
            return `${seconds}s`;
        }
    }

    /**
     * Calcul du score final
     */
    calculateScore() {
        let score = 100;
        
        // Pénalités par type d'erreur
        const penalties = {
            'MISSING_TOKEN': 15,
            'INVALID_TOKEN_MAPPING': 12,
            'ORPHANED_INVITATION': 8,
            'MISSING_INVITATION_FOR_TOKEN': 10,
            'NAME_MISMATCH_IN_MAPPING': 6,
            'INVALID_INVITATION_STATUS': 5,
            'EXPIRED_TOKEN_WRONG_STATUS': 4,
            'INVALID_TOKEN_FORMAT': 8,
            'DUPLICATE_TOKEN': 10,
            'INVALID_MIGRATION_METADATA': 3
        };
        
        // Application des pénalités
        for (const error of this.errors) {
            const penalty = penalties[error.code] || 5;
            score -= penalty;
        }
        
        // Bonus pour taux de préservation élevé
        const preservationRate = this.results.tokenPreservation.preservationRate || 0;
        if (preservationRate === 100) {
            score += 10;
        } else if (preservationRate >= 95) {
            score += 5;
        }
        
        // Bonus pour mapping accuracy élevé
        const mappingAccuracy = this.results.tokenMapping.mappingAccuracy || 0;
        if (mappingAccuracy === 100) {
            score += 5;
        }
        
        return Math.max(0, Math.min(100, score));
    }
}

module.exports = TokenValidator;