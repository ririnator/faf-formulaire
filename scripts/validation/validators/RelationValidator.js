/**
 * Validateur de Relations - Migration FAF
 * 
 * Vérifie l'intégrité référentielle pour tous les aspects de la migration :
 * - Intégrité référentielle Users↔Submissions
 * - Relations User↔Invitations  
 * - Validation des ObjectId et foreign keys
 * - Vérification des relations bidirectionnelles
 * - Détection des références orphelines
 * 
 * @author FAF Migration Team
 */

const BaseValidator = require('./BaseValidator');
const { ObjectId } = require('mongodb');

class RelationValidator extends BaseValidator {
    constructor(db, logger) {
        super('Validation des Relations', db, logger);
        this.results = {
            referentialIntegrity: {},
            orphanedReferences: {},
            bidirectionalChecks: {},
            constraintViolations: [],
            relationshipStats: {}
        };
    }

    /**
     * Validation principale des relations
     */
    async validate() {
        this.logger.info('🔗 Début de la validation des relations...');
        
        try {
            await this.validateCollectionExistence();
            await this.validateReferentialIntegrity();
            await this.validateBidirectionalRelations();
            await this.validateConstraints();
            await this.calculateRelationshipStats();
            
            const score = this.calculateScore();
            
            return {
                category: 'relations',
                success: score >= 95,
                score,
                errors: this.errors,
                details: this.results,
                metadata: {
                    totalViolations: this.results.constraintViolations.length,
                    orphanedCount: this.getTotalOrphaned()
                }
            };
            
        } catch (error) {
            this.addError('VALIDATION_FAILED', `Échec de la validation des relations: ${error.message}`);
            throw error;
        }
    }

    /**
     * Validation de l'existence des collections
     */
    async validateCollectionExistence() {
        const requiredCollections = ['users', 'submissions', 'invitations', 'responses'];
        
        for (const collection of requiredCollections) {
            const exists = await this.validateCollectionExists(collection);
            if (!exists) {
                throw new Error(`Collection manquante: ${collection}`);
            }
        }
    }

    /**
     * Validation de l'intégrité référentielle
     */
    async validateReferentialIntegrity() {
        this.logger.info('🔍 Validation de l\'intégrité référentielle...');
        
        // User → Submission
        await this.validateUserSubmissionReferences();
        
        // User → Invitation  
        await this.validateUserInvitationReferences();
        
        // Submission → User (référence inverse)
        await this.validateSubmissionUserReferences();
        
        // Invitation → User (référence inverse)
        await this.validateInvitationUserReferences();
    }

    /**
     * Validation User → Submission
     */
    async validateUserSubmissionReferences() {
        this.logger.info('  🔗 Vérification User → Submission...');
        
        const pipeline = [
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'user'
                }
            },
            {
                $match: {
                    userId: { $ne: null },
                    user: { $size: 0 }
                }
            },
            {
                $project: {
                    userId: 1,
                    month: 1,
                    legacyName: 1
                }
            }
        ];
        
        const orphanedSubmissions = await this.db.collection('submissions').aggregate(pipeline).toArray();
        
        if (orphanedSubmissions.length > 0) {
            this.results.orphanedReferences.submissions = orphanedSubmissions;
            
            for (const submission of orphanedSubmissions) {
                this.addError(
                    'ORPHANED_SUBMISSION',
                    `Submission ${submission._id} référence un userId inexistant: ${submission.userId}`,
                    { submissionId: submission._id, userId: submission.userId }
                );
            }
        }
        
        this.results.referentialIntegrity.userSubmission = {
            checked: true,
            orphaned: orphanedSubmissions.length,
            valid: orphanedSubmissions.length === 0
        };
    }

    /**
     * Validation User → Invitation
     */
    async validateUserInvitationReferences() {
        this.logger.info('  🔗 Vérification User → Invitation...');
        
        const pipeline = [
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'user'
                }
            },
            {
                $match: {
                    userId: { $ne: null },
                    user: { $size: 0 }
                }
            },
            {
                $project: {
                    userId: 1,
                    token: 1,
                    status: 1
                }
            }
        ];
        
        const orphanedInvitations = await this.db.collection('invitations').aggregate(pipeline).toArray();
        
        if (orphanedInvitations.length > 0) {
            this.results.orphanedReferences.invitations = orphanedInvitations;
            
            for (const invitation of orphanedInvitations) {
                this.addError(
                    'ORPHANED_INVITATION',
                    `Invitation ${invitation._id} référence un userId inexistant: ${invitation.userId}`,
                    { invitationId: invitation._id, userId: invitation.userId }
                );
            }
        }
        
        this.results.referentialIntegrity.userInvitation = {
            checked: true,
            orphaned: orphanedInvitations.length,
            valid: orphanedInvitations.length === 0
        };
    }

    /**
     * Validation Submission → User (référence inverse)
     */
    async validateSubmissionUserReferences() {
        this.logger.info('  🔗 Vérification Submission → User (inverse)...');
        
        const submissions = await this.db.collection('submissions')
            .find({ userId: { $ne: null } })
            .project({ userId: 1, month: 1 })
            .toArray();
        
        const userIds = new Set(
            (await this.db.collection('users').find({}).project({ _id: 1 }).toArray())
                .map(u => u._id.toString())
        );
        
        const invalidReferences = [];
        
        for (const submission of submissions) {
            if (!userIds.has(submission.userId.toString())) {
                invalidReferences.push(submission);
                this.addError(
                    'INVALID_USER_REFERENCE',
                    `Submission ${submission._id} référence un user inexistant: ${submission.userId}`
                );
            }
        }
        
        this.results.referentialIntegrity.submissionUser = {
            checked: submissions.length,
            invalid: invalidReferences.length,
            valid: invalidReferences.length === 0
        };
    }

    /**
     * Validation Invitation → User (référence inverse)
     */
    async validateInvitationUserReferences() {
        this.logger.info('  🔗 Vérification Invitation → User (inverse)...');
        
        const invitations = await this.db.collection('invitations')
            .find({ userId: { $ne: null } })
            .project({ userId: 1, token: 1 })
            .toArray();
        
        const userIds = new Set(
            (await this.db.collection('users').find({}).project({ _id: 1 }).toArray())
                .map(u => u._id.toString())
        );
        
        const invalidReferences = [];
        
        for (const invitation of invitations) {
            if (!userIds.has(invitation.userId.toString())) {
                invalidReferences.push(invitation);
                this.addError(
                    'INVALID_USER_REFERENCE_INV',
                    `Invitation ${invitation._id} référence un user inexistant: ${invitation.userId}`
                );
            }
        }
        
        this.results.referentialIntegrity.invitationUser = {
            checked: invitations.length,
            invalid: invalidReferences.length,
            valid: invalidReferences.length === 0
        };
    }

    /**
     * Validation des relations bidirectionnelles
     */
    async validateBidirectionalRelations() {
        this.logger.info('🔄 Validation des relations bidirectionnelles...');
        
        await this.validateUserSubmissionBidirectional();
        await this.validateUserInvitationBidirectional();
    }

    /**
     * Validation bidirectionnelle User ↔ Submission
     */
    async validateUserSubmissionBidirectional() {
        this.logger.info('  ↔️ Vérification User ↔ Submission...');
        
        // Utilisateurs avec submissions
        const usersWithSubmissions = await this.db.collection('submissions').aggregate([
            { $group: { _id: '$userId', submissionCount: { $sum: 1 } } },
            { $match: { _id: { $ne: null } } }
        ]).toArray();
        
        // Vérification que les utilisateurs existent
        const userIds = usersWithSubmissions.map(u => u._id);
        const existingUsers = await this.db.collection('users')
            .find({ _id: { $in: userIds } })
            .project({ _id: 1 })
            .toArray();
        
        const existingUserIds = new Set(existingUsers.map(u => u._id.toString()));
        const missingUsers = usersWithSubmissions.filter(
            u => !existingUserIds.has(u._id.toString())
        );
        
        if (missingUsers.length > 0) {
            for (const missingUser of missingUsers) {
                this.addError(
                    'BIDIRECTIONAL_MISMATCH_USER',
                    `User ${missingUser._id} a des submissions mais n'existe pas`,
                    { userId: missingUser._id, submissionCount: missingUser.submissionCount }
                );
            }
        }
        
        // Vérification inverse : utilisateurs sans submissions mais avec des métadonnées
        const usersWithResponseCount = await this.db.collection('users')
            .find({ 'metadata.responseCount': { $gt: 0 } })
            .project({ _id: 1, 'metadata.responseCount': 1 })
            .toArray();
        
        const userSubmissionMap = new Map(
            usersWithSubmissions.map(u => [u._id.toString(), u.submissionCount])
        );
        
        for (const user of usersWithResponseCount) {
            const actualSubmissions = userSubmissionMap.get(user._id.toString()) || 0;
            const expectedSubmissions = user.metadata.responseCount;
            
            if (actualSubmissions !== expectedSubmissions) {
                this.addError(
                    'SUBMISSION_COUNT_MISMATCH',
                    `User ${user._id}: responseCount=${expectedSubmissions} mais ${actualSubmissions} submissions trouvées`,
                    { userId: user._id, expected: expectedSubmissions, actual: actualSubmissions }
                );
            }
        }
        
        this.results.bidirectionalChecks.userSubmission = {
            usersWithSubmissions: usersWithSubmissions.length,
            missingUsers: missingUsers.length,
            usersWithResponseCount: usersWithResponseCount.length,
            valid: missingUsers.length === 0
        };
    }

    /**
     * Validation bidirectionnelle User ↔ Invitation
     */
    async validateUserInvitationBidirectional() {
        this.logger.info('  ↔️ Vérification User ↔ Invitation...');
        
        // Utilisateurs avec invitations
        const usersWithInvitations = await this.db.collection('invitations').aggregate([
            { $group: { _id: '$userId', invitationCount: { $sum: 1 } } },
            { $match: { _id: { $ne: null } } }
        ]).toArray();
        
        // Vérification que les utilisateurs existent
        const userIds = usersWithInvitations.map(u => u._id);
        const existingUsers = await this.db.collection('users')
            .find({ _id: { $in: userIds } })
            .project({ _id: 1, role: 1 })
            .toArray();
        
        const existingUserIds = new Set(existingUsers.map(u => u._id.toString()));
        const missingUsers = usersWithInvitations.filter(
            u => !existingUserIds.has(u._id.toString())
        );
        
        if (missingUsers.length > 0) {
            for (const missingUser of missingUsers) {
                this.addError(
                    'BIDIRECTIONAL_MISMATCH_USER_INV',
                    `User ${missingUser._id} a des invitations mais n'existe pas`,
                    { userId: missingUser._id, invitationCount: missingUser.invitationCount }
                );
            }
        }
        
        // Vérification que seuls les utilisateurs non-admin ont des invitations
        const adminUsers = existingUsers.filter(u => u.role === 'admin');
        const adminUserIds = new Set(adminUsers.map(u => u._id.toString()));
        
        const adminsWithInvitations = usersWithInvitations.filter(
            u => adminUserIds.has(u._id.toString())
        );
        
        if (adminsWithInvitations.length > 0) {
            for (const adminWithInv of adminsWithInvitations) {
                this.addError(
                    'ADMIN_WITH_INVITATION',
                    `Admin user ${adminWithInv._id} ne devrait pas avoir d'invitations`,
                    { userId: adminWithInv._id, invitationCount: adminWithInv.invitationCount }
                );
            }
        }
        
        this.results.bidirectionalChecks.userInvitation = {
            usersWithInvitations: usersWithInvitations.length,
            missingUsers: missingUsers.length,
            adminsWithInvitations: adminsWithInvitations.length,
            valid: missingUsers.length === 0 && adminsWithInvitations.length === 0
        };
    }

    /**
     * Validation des contraintes
     */
    async validateConstraints() {
        this.logger.info('📋 Validation des contraintes...');
        
        await this.validateUniqueConstraints();
        await this.validateBusinessRules();
        await this.validateObjectIdFormats();
    }

    /**
     * Validation des contraintes d'unicité
     */
    async validateUniqueConstraints() {
        this.logger.info('  🔑 Vérification des contraintes d\'unicité...');
        
        // Unicité des usernames
        await this.checkUniqueConstraint('users', 'username', 'USERNAME_DUPLICATE');
        
        // Unicité des emails
        await this.checkUniqueConstraint('users', 'email', 'EMAIL_DUPLICATE');
        
        // Unicité des tokens d'invitation
        await this.checkUniqueConstraint('invitations', 'token', 'TOKEN_DUPLICATE');
        
        // Unicité des submissions par utilisateur et mois
        await this.checkCompositeUniqueConstraint(
            'submissions',
            ['userId', 'month'],
            'SUBMISSION_DUPLICATE'
        );
    }

    /**
     * Vérification d'une contrainte d'unicité simple
     */
    async checkUniqueConstraint(collection, field, errorCode) {
        const pipeline = [
            { $group: { _id: `$${field}`, count: { $sum: 1 }, docs: { $push: '$_id' } } },
            { $match: { count: { $gt: 1 } } }
        ];
        
        const duplicates = await this.db.collection(collection).aggregate(pipeline).toArray();
        
        if (duplicates.length > 0) {
            for (const duplicate of duplicates) {
                this.addError(
                    errorCode,
                    `Valeur en doublon pour ${field}: ${duplicate._id} (${duplicate.count} occurrences)`,
                    { field, value: duplicate._id, count: duplicate.count, docs: duplicate.docs }
                );
                
                this.results.constraintViolations.push({
                    type: 'UNIQUE_CONSTRAINT',
                    collection,
                    field,
                    value: duplicate._id,
                    count: duplicate.count
                });
            }
        }
    }

    /**
     * Vérification d'une contrainte d'unicité composite
     */
    async checkCompositeUniqueConstraint(collection, fields, errorCode) {
        const groupId = {};
        fields.forEach(field => {
            groupId[field] = `$${field}`;
        });
        
        const pipeline = [
            { $group: { _id: groupId, count: { $sum: 1 }, docs: { $push: '$_id' } } },
            { $match: { count: { $gt: 1 } } }
        ];
        
        const duplicates = await this.db.collection(collection).aggregate(pipeline).toArray();
        
        if (duplicates.length > 0) {
            for (const duplicate of duplicates) {
                const fieldValues = fields.map(f => `${f}=${duplicate._id[f]}`).join(', ');
                this.addError(
                    errorCode,
                    `Valeur composite en doublon: ${fieldValues} (${duplicate.count} occurrences)`,
                    { fields, values: duplicate._id, count: duplicate.count, docs: duplicate.docs }
                );
                
                this.results.constraintViolations.push({
                    type: 'COMPOSITE_UNIQUE_CONSTRAINT',
                    collection,
                    fields,
                    values: duplicate._id,
                    count: duplicate.count
                });
            }
        }
    }

    /**
     * Validation des règles métier
     */
    async validateBusinessRules() {
        this.logger.info('  📜 Vérification des règles métier...');
        
        // Règle : Un admin ne devrait pas avoir d'invitations
        const adminsWithInvitations = await this.db.collection('users').aggregate([
            { $match: { role: 'admin' } },
            {
                $lookup: {
                    from: 'invitations',
                    localField: '_id',
                    foreignField: 'userId',
                    as: 'invitations'
                }
            },
            { $match: { invitations: { $ne: [] } } },
            { $project: { username: 1, invitationCount: { $size: '$invitations' } } }
        ]).toArray();
        
        for (const admin of adminsWithInvitations) {
            this.addError(
                'ADMIN_BUSINESS_RULE_VIOLATION',
                `Admin ${admin.username} ne devrait pas avoir d'invitations (${admin.invitationCount} trouvées)`,
                { userId: admin._id, username: admin.username }
            );
        }
        
        // Règle : Les submissions d'admin doivent avoir userRole='admin'
        const adminSubmissionsWithWrongRole = await this.db.collection('submissions').aggregate([
            {
                $lookup: {
                    from: 'users',
                    localField: 'userId',
                    foreignField: '_id',
                    as: 'user'
                }
            },
            { $unwind: '$user' },
            {
                $match: {
                    'user.role': 'admin',
                    userRole: { $ne: 'admin' }
                }
            },
            { $project: { userId: 1, userRole: 1, month: 1 } }
        ]).toArray();
        
        for (const submission of adminSubmissionsWithWrongRole) {
            this.addError(
                'ADMIN_ROLE_MISMATCH',
                `Submission ${submission._id} d'un admin a userRole='${submission.userRole}' au lieu de 'admin'`,
                { submissionId: submission._id, userId: submission.userId }
            );
        }
        
        // Règle : Les invitations doivent avoir un statut valide
        const invalidInvitationStatuses = await this.db.collection('invitations')
            .find({ status: { $nin: ['active', 'used', 'expired'] } })
            .project({ token: 1, status: 1 })
            .toArray();
        
        for (const invitation of invalidInvitationStatuses) {
            this.addError(
                'INVALID_INVITATION_STATUS',
                `Invitation ${invitation._id} a un statut invalide: ${invitation.status}`,
                { invitationId: invitation._id, token: invitation.token }
            );
        }
    }

    /**
     * Validation des formats ObjectId
     */
    async validateObjectIdFormats() {
        this.logger.info('  🆔 Vérification des formats ObjectId...');
        
        const collections = ['users', 'submissions', 'invitations'];
        
        for (const collection of collections) {
            const documents = await this.db.collection(collection)
                .find({})
                .project({ _id: 1, userId: 1 })
                .toArray();
            
            for (const doc of documents) {
                // Vérification de l'_id
                if (!this.isValidObjectId(doc._id)) {
                    this.addError(
                        'INVALID_OBJECTID_FORMAT',
                        `Format ObjectId invalide pour _id dans ${collection}: ${doc._id}`,
                        { collection, documentId: doc._id }
                    );
                }
                
                // Vérification du userId si présent
                if (doc.userId && !this.isValidObjectId(doc.userId)) {
                    this.addError(
                        'INVALID_USERID_FORMAT',
                        `Format ObjectId invalide pour userId dans ${collection}: ${doc.userId}`,
                        { collection, documentId: doc._id, userId: doc.userId }
                    );
                }
            }
        }
    }

    /**
     * Calcul des statistiques relationnelles
     */
    async calculateRelationshipStats() {
        this.logger.info('📊 Calcul des statistiques relationnelles...');
        
        // Statistiques User → Submission
        const userSubmissionStats = await this.db.collection('submissions').aggregate([
            { $group: { _id: '$userId', submissionCount: { $sum: 1 } } },
            {
                $group: {
                    _id: null,
                    totalUsers: { $sum: 1 },
                    avgSubmissions: { $avg: '$submissionCount' },
                    maxSubmissions: { $max: '$submissionCount' },
                    minSubmissions: { $min: '$submissionCount' }
                }
            }
        ]).toArray();
        
        // Statistiques User → Invitation
        const userInvitationStats = await this.db.collection('invitations').aggregate([
            { $group: { _id: '$userId', invitationCount: { $sum: 1 } } },
            {
                $group: {
                    _id: null,
                    totalUsers: { $sum: 1 },
                    avgInvitations: { $avg: '$invitationCount' },
                    maxInvitations: { $max: '$invitationCount' },
                    minInvitations: { $min: '$invitationCount' }
                }
            }
        ]).toArray();
        
        // Répartition par rôle
        const roleDistribution = await this.db.collection('users').aggregate([
            { $group: { _id: '$role', count: { $sum: 1 } } }
        ]).toArray();
        
        this.results.relationshipStats = {
            userSubmission: userSubmissionStats[0] || {},
            userInvitation: userInvitationStats[0] || {},
            roleDistribution: roleDistribution.reduce((acc, role) => {
                acc[role._id] = role.count;
                return acc;
            }, {})
        };
    }

    /**
     * Calcul du nombre total d'orphelins
     */
    getTotalOrphaned() {
        let total = 0;
        
        if (this.results.orphanedReferences.submissions) {
            total += this.results.orphanedReferences.submissions.length;
        }
        
        if (this.results.orphanedReferences.invitations) {
            total += this.results.orphanedReferences.invitations.length;
        }
        
        return total;
    }

    /**
     * Calcul du score final
     */
    calculateScore() {
        let score = 100;
        
        // Pénalités par type d'erreur
        const penalties = {
            'ORPHANED_SUBMISSION': 15,
            'ORPHANED_INVITATION': 12,
            'INVALID_USER_REFERENCE': 10,
            'INVALID_USER_REFERENCE_INV': 10,
            'BIDIRECTIONAL_MISMATCH_USER': 8,
            'BIDIRECTIONAL_MISMATCH_USER_INV': 8,
            'SUBMISSION_COUNT_MISMATCH': 5,
            'ADMIN_WITH_INVITATION': 7,
            'USERNAME_DUPLICATE': 20,
            'EMAIL_DUPLICATE': 20,
            'TOKEN_DUPLICATE': 15,
            'SUBMISSION_DUPLICATE': 12,
            'ADMIN_BUSINESS_RULE_VIOLATION': 8,
            'ADMIN_ROLE_MISMATCH': 6,
            'INVALID_INVITATION_STATUS': 4,
            'INVALID_OBJECTID_FORMAT': 3,
            'INVALID_USERID_FORMAT': 3
        };
        
        // Application des pénalités
        for (const error of this.errors) {
            const penalty = penalties[error.code] || 5;
            score -= penalty;
        }
        
        // Bonus pour l'intégrité parfaite
        const hasOrphans = this.getTotalOrphaned() > 0;
        const hasConstraintViolations = this.results.constraintViolations.length > 0;
        
        if (!hasOrphans && !hasConstraintViolations) {
            score += 10;
        }
        
        return Math.max(0, Math.min(100, score));
    }
}

module.exports = RelationValidator;