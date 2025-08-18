/**
 * Validateur de Comptages - Migration FAF
 * 
 * Vérifie l'intégrité des comptages pour tous les aspects de la migration :
 * - Nombre total de documents migrés
 * - Comptage par collection (Users, Submissions, Invitations)
 * - Validation des agrégations par mois/période
 * - Détection des doublons ou documents manquants
 * - Rapport de correspondance 1:1 entre Response et Submission
 * 
 * @author FAF Migration Team
 */

const BaseValidator = require('./BaseValidator');

class CountValidator extends BaseValidator {
    constructor(db, logger) {
        super('Validation des Comptages', db, logger);
        this.results = {
            totalCounts: {},
            monthlyBreakdown: {},
            correspondences: {},
            duplicates: {},
            discrepancies: []
        };
    }

    /**
     * Validation principale des comptages
     */
    async validate() {
        this.logger.info('📊 Début de la validation des comptages...');
        
        try {
            await this.validateTotalCounts();
            await this.validateMonthlyBreakdown();
            await this.validateCorrespondences();
            await this.detectDuplicates();
            await this.calculateDiscrepancies();
            
            const score = this.calculateScore();
            
            return {
                category: 'counts',
                success: score >= 95,
                score,
                errors: this.errors,
                details: this.results,
                metadata: {
                    totalDocuments: this.results.totalCounts,
                    criticalIssues: this.results.discrepancies.length
                }
            };
            
        } catch (error) {
            this.addError('VALIDATION_FAILED', `Échec de la validation des comptages: ${error.message}`);
            throw error;
        }
    }

    /**
     * Validation des comptages totaux
     */
    async validateTotalCounts() {
        this.logger.info('🔢 Validation des comptages totaux...');
        
        const collections = ['responses', 'users', 'submissions', 'invitations'];
        
        for (const collection of collections) {
            try {
                const count = await this.db.collection(collection).countDocuments({});
                this.results.totalCounts[collection] = count;
                this.logger.info(`  ${collection}: ${count} documents`);
            } catch (error) {
                this.addError('COUNT_ERROR', `Erreur de comptage pour ${collection}: ${error.message}`);
            }
        }
        
        // Validation des comptages minimum attendus
        await this.validateMinimumCounts();
    }

    /**
     * Validation des comptages minimum
     */
    async validateMinimumCounts() {
        const expectations = {
            responses: 0, // Peut être 0 après migration
            users: 1, // Au moins l'admin
            submissions: 0, // Doit correspondre aux responses
            invitations: 0 // Doit correspondre aux responses non-admin
        };
        
        for (const [collection, minCount] of Object.entries(expectations)) {
            const actualCount = this.results.totalCounts[collection] || 0;
            
            if (actualCount < minCount) {
                this.addError(
                    'INSUFFICIENT_COUNT',
                    `Collection ${collection}: ${actualCount} documents (minimum attendu: ${minCount})`
                );
            }
        }
    }

    /**
     * Validation par mois/période
     */
    async validateMonthlyBreakdown() {
        this.logger.info('📅 Validation par période mensuelle...');
        
        // Agrégation des responses par mois
        const responsesByMonth = await this.aggregateByMonth('responses');
        const submissionsByMonth = await this.aggregateByMonth('submissions');
        
        this.results.monthlyBreakdown = {
            responses: responsesByMonth,
            submissions: submissionsByMonth
        };
        
        // Validation de la correspondance mensuelle
        await this.validateMonthlyCorrespondence(responsesByMonth, submissionsByMonth);
    }

    /**
     * Agrégation par mois
     */
    async aggregateByMonth(collection) {
        try {
            const pipeline = [
                {
                    $group: {
                        _id: {
                            $substr: ['$month', 0, 7] // YYYY-MM
                        },
                        count: { $sum: 1 },
                        adminCount: {
                            $sum: { $cond: ['$isAdmin', 1, 0] }
                        },
                        userCount: {
                            $sum: { $cond: ['$isAdmin', 0, 1] }
                        }
                    }
                },
                { $sort: { _id: 1 } }
            ];
            
            if (collection === 'submissions') {
                // Pour les submissions, utiliser userId et role
                pipeline[0].$group.adminCount = {
                    $sum: { $cond: [{ $eq: ['$userRole', 'admin'] }, 1, 0] }
                };
                pipeline[0].$group.userCount = {
                    $sum: { $cond: [{ $ne: ['$userRole', 'admin'] }, 1, 0] }
                };
            }
            
            const result = await this.db.collection(collection).aggregate(pipeline).toArray();
            
            return result.reduce((acc, item) => {
                acc[item._id] = {
                    total: item.count,
                    admin: item.adminCount,
                    user: item.userCount
                };
                return acc;
            }, {});
            
        } catch (error) {
            this.addError('AGGREGATION_ERROR', `Erreur d'agrégation pour ${collection}: ${error.message}`);
            return {};
        }
    }

    /**
     * Validation de la correspondance mensuelle
     */
    async validateMonthlyCorrespondence(responsesByMonth, submissionsByMonth) {
        const allMonths = new Set([
            ...Object.keys(responsesByMonth),
            ...Object.keys(submissionsByMonth)
        ]);
        
        for (const month of allMonths) {
            const responsesData = responsesByMonth[month] || { total: 0, admin: 0, user: 0 };
            const submissionsData = submissionsByMonth[month] || { total: 0, admin: 0, user: 0 };
            
            // Correspondance totale
            if (responsesData.total !== submissionsData.total) {
                this.addError(
                    'MONTHLY_MISMATCH',
                    `Mois ${month}: ${responsesData.total} responses vs ${submissionsData.total} submissions`
                );
            }
            
            // Correspondance admin
            if (responsesData.admin !== submissionsData.admin) {
                this.addError(
                    'ADMIN_COUNT_MISMATCH',
                    `Mois ${month}: ${responsesData.admin} admin responses vs ${submissionsData.admin} admin submissions`
                );
            }
            
            // Correspondance utilisateurs
            if (responsesData.user !== submissionsData.user) {
                this.addError(
                    'USER_COUNT_MISMATCH',
                    `Mois ${month}: ${responsesData.user} user responses vs ${submissionsData.user} user submissions`
                );
            }
        }
    }

    /**
     * Validation des correspondances 1:1
     */
    async validateCorrespondences() {
        this.logger.info('🔗 Validation des correspondances 1:1...');
        
        // Correspondance Response → Submission
        await this.validateResponseSubmissionCorrespondence();
        
        // Correspondance Response → Invitation (pour les non-admin)
        await this.validateResponseInvitationCorrespondence();
        
        // Correspondance User → Submission
        await this.validateUserSubmissionCorrespondence();
    }

    /**
     * Correspondance Response → Submission
     */
    async validateResponseSubmissionCorrespondence() {
        const responses = await this.db.collection('responses').find({}).toArray();
        const submissions = await this.db.collection('submissions').find({}).toArray();
        
        // Mapping par identifiant unique
        const responseMap = new Map();
        const submissionMap = new Map();
        
        responses.forEach(r => {
            const key = `${r.name}-${r.month}`;
            if (responseMap.has(key)) {
                this.addError('DUPLICATE_RESPONSE', `Response en doublon: ${key}`);
            }
            responseMap.set(key, r);
        });
        
        submissions.forEach(s => {
            const key = `${s.legacyName || s.userName}-${s.month}`;
            if (submissionMap.has(key)) {
                this.addError('DUPLICATE_SUBMISSION', `Submission en doublon: ${key}`);
            }
            submissionMap.set(key, s);
        });
        
        // Vérification des correspondances
        let matchedCount = 0;
        let unmatchedResponses = 0;
        let unmatchedSubmissions = 0;
        
        for (const [key, response] of responseMap) {
            if (submissionMap.has(key)) {
                matchedCount++;
                // Validation des données correspondantes
                const submission = submissionMap.get(key);
                await this.validateDataCorrespondence(response, submission);
            } else {
                unmatchedResponses++;
                this.addError('UNMATCHED_RESPONSE', `Response sans submission correspondante: ${key}`);
            }
        }
        
        for (const key of submissionMap.keys()) {
            if (!responseMap.has(key)) {
                unmatchedSubmissions++;
                this.addError('UNMATCHED_SUBMISSION', `Submission sans response correspondante: ${key}`);
            }
        }
        
        this.results.correspondences = {
            totalResponses: responses.length,
            totalSubmissions: submissions.length,
            matched: matchedCount,
            unmatchedResponses,
            unmatchedSubmissions,
            correspondenceRate: (matchedCount / Math.max(responses.length, 1)) * 100
        };
    }

    /**
     * Validation de la correspondance des données
     */
    async validateDataCorrespondence(response, submission) {
        // Vérification des champs critiques
        if (response.isAdmin !== (submission.userRole === 'admin')) {
            this.addError(
                'ROLE_MISMATCH',
                `Rôle incohérent pour ${response.name}-${response.month}`
            );
        }
        
        if (response.responses.length !== submission.responses.length) {
            this.addError(
                'RESPONSE_COUNT_MISMATCH',
                `Nombre de réponses différent pour ${response.name}-${response.month}`
            );
        }
        
        // Vérification des métadonnées
        if (response.createdAt && submission.submittedAt) {
            const timeDiff = Math.abs(
                new Date(response.createdAt) - new Date(submission.submittedAt)
            );
            if (timeDiff > 60000) { // Plus d'1 minute de différence
                this.addError(
                    'TIMESTAMP_MISMATCH',
                    `Horodatage incohérent pour ${response.name}-${response.month} (diff: ${timeDiff}ms)`
                );
            }
        }
    }

    /**
     * Correspondance Response → Invitation
     */
    async validateResponseInvitationCorrespondence() {
        const nonAdminResponses = await this.db.collection('responses')
            .find({ isAdmin: { $ne: true }, token: { $exists: true, $ne: null } })
            .toArray();
        
        const invitations = await this.db.collection('invitations').find({}).toArray();
        
        const invitationTokens = new Set(invitations.map(i => i.token));
        
        let matchedTokens = 0;
        let unmatchedTokens = 0;
        
        for (const response of nonAdminResponses) {
            if (invitationTokens.has(response.token)) {
                matchedTokens++;
            } else {
                unmatchedTokens++;
                this.addError(
                    'MISSING_INVITATION',
                    `Token ${response.token} non trouvé dans les invitations`
                );
            }
        }
        
        this.results.correspondences.tokenCorrespondence = {
            totalTokens: nonAdminResponses.length,
            matched: matchedTokens,
            unmatched: unmatchedTokens,
            correspondenceRate: (matchedTokens / Math.max(nonAdminResponses.length, 1)) * 100
        };
    }

    /**
     * Correspondance User → Submission
     */
    async validateUserSubmissionCorrespondence() {
        const users = await this.db.collection('users').find({}).toArray();
        const submissions = await this.db.collection('submissions').find({}).toArray();
        
        const userIds = new Set(users.map(u => u._id.toString()));
        const submissionUserIds = new Set(submissions.map(s => s.userId?.toString()).filter(Boolean));
        
        let orphanedSubmissions = 0;
        let usersWithoutSubmissions = 0;
        
        // Vérification des submissions orphelines
        for (const submission of submissions) {
            if (submission.userId && !userIds.has(submission.userId.toString())) {
                orphanedSubmissions++;
                this.addError(
                    'ORPHANED_SUBMISSION',
                    `Submission avec userId inexistant: ${submission.userId}`
                );
            }
        }
        
        // Vérification des utilisateurs sans submissions
        for (const user of users) {
            if (!submissionUserIds.has(user._id.toString())) {
                usersWithoutSubmissions++;
                // Note: Ce n'est pas forcément une erreur si l'utilisateur n'a jamais soumis
            }
        }
        
        this.results.correspondences.userSubmissionCorrespondence = {
            totalUsers: users.length,
            totalSubmissions: submissions.length,
            orphanedSubmissions,
            usersWithoutSubmissions
        };
    }

    /**
     * Détection des doublons
     */
    async detectDuplicates() {
        this.logger.info('🔍 Détection des doublons...');
        
        await this.detectResponseDuplicates();
        await this.detectUserDuplicates();
        await this.detectSubmissionDuplicates();
        await this.detectInvitationDuplicates();
    }

    /**
     * Détection des doublons de responses
     */
    async detectResponseDuplicates() {
        const pipeline = [
            {
                $group: {
                    _id: { name: '$name', month: '$month' },
                    count: { $sum: 1 },
                    docs: { $push: '$_id' }
                }
            },
            { $match: { count: { $gt: 1 } } }
        ];
        
        const duplicates = await this.db.collection('responses').aggregate(pipeline).toArray();
        
        if (duplicates.length > 0) {
            this.results.duplicates.responses = duplicates;
            duplicates.forEach(dup => {
                this.addError(
                    'RESPONSE_DUPLICATE',
                    `Response en doublon: ${dup._id.name}-${dup._id.month} (${dup.count} occurrences)`
                );
            });
        }
    }

    /**
     * Détection des doublons d'utilisateurs
     */
    async detectUserDuplicates() {
        // Doublons par username
        const usernameDuplicates = await this.db.collection('users').aggregate([
            { $group: { _id: '$username', count: { $sum: 1 }, docs: { $push: '$_id' } } },
            { $match: { count: { $gt: 1 } } }
        ]).toArray();
        
        // Doublons par email
        const emailDuplicates = await this.db.collection('users').aggregate([
            { $group: { _id: '$email', count: { $sum: 1 }, docs: { $push: '$_id' } } },
            { $match: { count: { $gt: 1 } } }
        ]).toArray();
        
        if (usernameDuplicates.length > 0 || emailDuplicates.length > 0) {
            this.results.duplicates.users = { usernameDuplicates, emailDuplicates };
            
            usernameDuplicates.forEach(dup => {
                this.addError(
                    'USERNAME_DUPLICATE',
                    `Username en doublon: ${dup._id} (${dup.count} occurrences)`
                );
            });
            
            emailDuplicates.forEach(dup => {
                this.addError(
                    'EMAIL_DUPLICATE',
                    `Email en doublon: ${dup._id} (${dup.count} occurrences)`
                );
            });
        }
    }

    /**
     * Détection des doublons de submissions
     */
    async detectSubmissionDuplicates() {
        const pipeline = [
            {
                $group: {
                    _id: { userId: '$userId', month: '$month' },
                    count: { $sum: 1 },
                    docs: { $push: '$_id' }
                }
            },
            { $match: { count: { $gt: 1 } } }
        ];
        
        const duplicates = await this.db.collection('submissions').aggregate(pipeline).toArray();
        
        if (duplicates.length > 0) {
            this.results.duplicates.submissions = duplicates;
            duplicates.forEach(dup => {
                this.addError(
                    'SUBMISSION_DUPLICATE',
                    `Submission en doublon: ${dup._id.userId}-${dup._id.month} (${dup.count} occurrences)`
                );
            });
        }
    }

    /**
     * Détection des doublons d'invitations
     */
    async detectInvitationDuplicates() {
        const pipeline = [
            {
                $group: {
                    _id: '$token',
                    count: { $sum: 1 },
                    docs: { $push: '$_id' }
                }
            },
            { $match: { count: { $gt: 1 } } }
        ];
        
        const duplicates = await this.db.collection('invitations').aggregate(pipeline).toArray();
        
        if (duplicates.length > 0) {
            this.results.duplicates.invitations = duplicates;
            duplicates.forEach(dup => {
                this.addError(
                    'INVITATION_DUPLICATE',
                    `Token d'invitation en doublon: ${dup._id} (${dup.count} occurrences)`
                );
            });
        }
    }

    /**
     * Calcul des divergences
     */
    async calculateDiscrepancies() {
        this.logger.info('📋 Calcul des divergences...');
        
        const discrepancies = [];
        
        // Divergence Response vs Submission
        const responseCount = this.results.totalCounts.responses || 0;
        const submissionCount = this.results.totalCounts.submissions || 0;
        
        if (responseCount !== submissionCount) {
            discrepancies.push({
                type: 'COUNT_DISCREPANCY',
                description: `Comptage différent: ${responseCount} responses vs ${submissionCount} submissions`,
                severity: 'HIGH',
                impact: 'MIGRATION_INTEGRITY'
            });
        }
        
        // Divergence de correspondance des tokens
        const tokenCorrespondence = this.results.correspondences.tokenCorrespondence;
        if (tokenCorrespondence && tokenCorrespondence.correspondenceRate < 100) {
            discrepancies.push({
                type: 'TOKEN_CORRESPONDENCE',
                description: `Correspondance des tokens: ${tokenCorrespondence.correspondenceRate.toFixed(2)}%`,
                severity: tokenCorrespondence.correspondenceRate < 95 ? 'HIGH' : 'MEDIUM',
                impact: 'LEGACY_ACCESS'
            });
        }
        
        // Divergence dans les doublons
        const duplicateCategories = Object.keys(this.results.duplicates);
        if (duplicateCategories.length > 0) {
            discrepancies.push({
                type: 'DUPLICATE_DATA',
                description: `Doublons détectés dans: ${duplicateCategories.join(', ')}`,
                severity: 'HIGH',
                impact: 'DATA_INTEGRITY'
            });
        }
        
        this.results.discrepancies = discrepancies;
    }

    /**
     * Calcul du score final
     */
    calculateScore() {
        let score = 100;
        
        // Pénalités par type d'erreur
        const penalties = {
            'COUNT_ERROR': 15,
            'INSUFFICIENT_COUNT': 10,
            'MONTHLY_MISMATCH': 8,
            'ADMIN_COUNT_MISMATCH': 5,
            'USER_COUNT_MISMATCH': 5,
            'DUPLICATE_RESPONSE': 10,
            'DUPLICATE_SUBMISSION': 10,
            'UNMATCHED_RESPONSE': 12,
            'UNMATCHED_SUBMISSION': 12,
            'ROLE_MISMATCH': 8,
            'RESPONSE_COUNT_MISMATCH': 6,
            'TIMESTAMP_MISMATCH': 3,
            'MISSING_INVITATION': 7,
            'ORPHANED_SUBMISSION': 10,
            'USERNAME_DUPLICATE': 15,
            'EMAIL_DUPLICATE': 15,
            'INVITATION_DUPLICATE': 8
        };
        
        // Application des pénalités
        for (const error of this.errors) {
            const penalty = penalties[error.code] || 5;
            score -= penalty;
        }
        
        // Bonus pour les correspondances parfaites
        const correspondence = this.results.correspondences.correspondenceRate;
        if (correspondence === 100) {
            score += 5;
        }
        
        return Math.max(0, Math.min(100, score));
    }
}

module.exports = CountValidator;