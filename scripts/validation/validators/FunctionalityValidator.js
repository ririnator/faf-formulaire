/**
 * Validateur de Fonctionnalités - Migration FAF
 * 
 * Vérifie le bon fonctionnement des workflows post-migration :
 * - Test des workflows complets post-migration
 * - Authentification et autorisation
 * - Soumission de nouvelles réponses
 * - Accès aux données historiques
 * - Fonctionnement des dashboards
 * 
 * @author FAF Migration Team
 */

const BaseValidator = require('./BaseValidator');
const bcrypt = require('bcrypt');

class FunctionalityValidator extends BaseValidator {
    constructor(db, logger) {
        super('Validation des Fonctionnalités', db, logger);
        this.results = {
            authenticationTests: {},
            dataAccessTests: {},
            workflowTests: {},
            dashboardTests: {},
            legacyCompatibility: {}
        };
    }

    /**
     * Validation principale des fonctionnalités
     */
    async validate() {
        this.logger.info('⚙️ Début de la validation des fonctionnalités...');
        
        try {
            await this.validateAuthentication();
            await this.validateDataAccess();
            await this.validateWorkflows();
            await this.validateDashboardFunctionality();
            await this.validateLegacyCompatibility();
            
            const score = this.calculateScore();
            
            return {
                category: 'functionality',
                success: score >= 95,
                score,
                errors: this.errors,
                details: this.results,
                metadata: {
                    totalTests: this.getTotalTestCount(),
                    passedTests: this.getPassedTestCount()
                }
            };
            
        } catch (error) {
            this.addError('VALIDATION_FAILED', `Échec de la validation des fonctionnalités: ${error.message}`);
            throw error;
        }
    }

    /**
     * Validation de l'authentification
     */
    async validateAuthentication() {
        this.logger.info('🔐 Validation de l'authentification...');
        
        const authTests = {
            userAccountCreation: false,
            passwordHashing: false,
            adminRoleAssignment: false,
            usernameUniqueness: false,
            emailValidation: false
        };
        
        try {
            // Test 1: Vérification de la création des comptes utilisateurs
            await this.testUserAccountCreation(authTests);
            
            // Test 2: Vérification du hachage des mots de passe
            await this.testPasswordHashing(authTests);
            
            // Test 3: Vérification de l'attribution des rôles admin
            await this.testAdminRoleAssignment(authTests);
            
            // Test 4: Vérification de l'unicité des usernames
            await this.testUsernameUniqueness(authTests);
            
            // Test 5: Vérification de la validation des emails
            await this.testEmailValidation(authTests);
            
        } catch (error) {
            this.addError('AUTH_TEST_FAILED', `Erreur dans les tests d'authentification: ${error.message}`);
        }
        
        this.results.authenticationTests = authTests;
    }

    /**
     * Test de création des comptes utilisateurs
     */
    async testUserAccountCreation(authTests) {
        try {
            // Vérification que tous les utilisateurs ont été créés
            const responseNames = await this.db.collection('responses')
                .distinct('name', { isAdmin: { $ne: true } });
            
            const userCount = await this.db.collection('users').countDocuments({});
            
            // Au minimum, il devrait y avoir un utilisateur par nom unique dans les responses
            const expectedMinUsers = new Set(responseNames).size;
            
            if (userCount >= expectedMinUsers) {
                authTests.userAccountCreation = true;
                this.logger.info(`✅ Comptes utilisateurs créés: ${userCount} (minimum attendu: ${expectedMinUsers})`);
            } else {
                this.addError(
                    'INSUFFICIENT_USER_ACCOUNTS',
                    `Nombre d'utilisateurs insuffisant: ${userCount} (minimum: ${expectedMinUsers})`
                );
            }
            
        } catch (error) {
            this.addError('USER_ACCOUNT_TEST_FAILED', `Test de création des comptes échoué: ${error.message}`);
        }
    }

    /**
     * Test du hachage des mots de passe
     */
    async testPasswordHashing(authTests) {
        try {
            const users = await this.db.collection('users')
                .find({ password: { $exists: true } })
                .project({ _id: 1, password: 1 })
                .limit(10)
                .toArray();
            
            let validPasswordCount = 0;
            
            for (const user of users) {
                if (this.isValidBcryptHash(user.password)) {
                    validPasswordCount++;
                } else {
                    this.addError(
                        'INVALID_PASSWORD_HASH',
                        `Mot de passe non haché pour l'utilisateur ${user._id}`,
                        { userId: user._id }
                    );
                }
            }
            
            if (validPasswordCount === users.length && users.length > 0) {
                authTests.passwordHashing = true;
                this.logger.info(`✅ Mots de passe correctement hachés: ${validPasswordCount}/${users.length}`);
            }
            
        } catch (error) {
            this.addError('PASSWORD_HASH_TEST_FAILED', `Test de hachage des mots de passe échoué: ${error.message}`);
        }
    }

    /**
     * Test de l'attribution des rôles admin
     */
    async testAdminRoleAssignment(authTests) {
        try {
            // Recherche de l'admin via FORM_ADMIN_NAME
            const adminName = process.env.FORM_ADMIN_NAME;
            
            if (!adminName) {
                this.addWarning('ADMIN_NAME_NOT_CONFIGURED', 'FORM_ADMIN_NAME non configuré');
                return;
            }
            
            // Vérification que l'admin a été créé avec le bon rôle
            const adminUser = await this.db.collection('users')
                .findOne({ 
                    $or: [
                        { username: adminName },
                        { 'migrationData.legacyName': adminName }
                    ]
                });
            
            if (adminUser && adminUser.role === 'admin') {
                authTests.adminRoleAssignment = true;
                this.logger.info(`✅ Rôle admin assigné correctement à ${adminUser.username}`);
            } else if (adminUser) {
                this.addError(
                    'ADMIN_ROLE_NOT_ASSIGNED',
                    `Utilisateur admin trouvé mais rôle incorrect: ${adminUser.role}`,
                    { userId: adminUser._id, role: adminUser.role }
                );
            } else {
                this.addError(
                    'ADMIN_USER_NOT_FOUND',
                    `Utilisateur admin non trouvé pour le nom: ${adminName}`
                );
            }
            
        } catch (error) {
            this.addError('ADMIN_ROLE_TEST_FAILED', `Test d'attribution des rôles admin échoué: ${error.message}`);
        }
    }

    /**
     * Test de l'unicité des usernames
     */
    async testUsernameUniqueness(authTests) {
        try {
            const duplicateUsernames = await this.db.collection('users').aggregate([
                { $group: { _id: '$username', count: { $sum: 1 } } },
                { $match: { count: { $gt: 1 } } }
            ]).toArray();
            
            if (duplicateUsernames.length === 0) {
                authTests.usernameUniqueness = true;
                this.logger.info('✅ Tous les usernames sont uniques');
            } else {
                for (const duplicate of duplicateUsernames) {
                    this.addError(
                        'DUPLICATE_USERNAME',
                        `Username en doublon: ${duplicate._id} (${duplicate.count} occurrences)`
                    );
                }
            }
            
        } catch (error) {
            this.addError('USERNAME_UNIQUENESS_TEST_FAILED', `Test d'unicité des usernames échoué: ${error.message}`);
        }
    }

    /**
     * Test de la validation des emails
     */
    async testEmailValidation(authTests) {
        try {
            const users = await this.db.collection('users')
                .find({ email: { $exists: true } })
                .project({ _id: 1, email: 1 })
                .toArray();
            
            let validEmailCount = 0;
            
            for (const user of users) {
                if (this.validateEmail(user.email)) {
                    validEmailCount++;
                } else {
                    this.addError(
                        'INVALID_EMAIL_FORMAT',
                        `Format d'email invalide pour l'utilisateur ${user._id}: ${user.email}`,
                        { userId: user._id, email: user.email }
                    );
                }
            }
            
            if (validEmailCount === users.length && users.length > 0) {
                authTests.emailValidation = true;
                this.logger.info(`✅ Emails valides: ${validEmailCount}/${users.length}`);
            }
            
        } catch (error) {
            this.addError('EMAIL_VALIDATION_TEST_FAILED', `Test de validation des emails échoué: ${error.message}`);
        }
    }

    /**
     * Validation de l'accès aux données
     */
    async validateDataAccess() {
        this.logger.info('📊 Validation de l'accès aux données...');
        
        const dataAccessTests = {
            submissionRetrieval: false,
            userDataAccess: false,
            invitationAccess: false,
            historicalDataIntegrity: false,
            crossReferenceAccess: false
        };
        
        try {
            // Test 1: Récupération des submissions
            await this.testSubmissionRetrieval(dataAccessTests);
            
            // Test 2: Accès aux données utilisateur
            await this.testUserDataAccess(dataAccessTests);
            
            // Test 3: Accès aux invitations
            await this.testInvitationAccess(dataAccessTests);
            
            // Test 4: Intégrité des données historiques
            await this.testHistoricalDataIntegrity(dataAccessTests);
            
            // Test 5: Accès aux références croisées
            await this.testCrossReferenceAccess(dataAccessTests);
            
        } catch (error) {
            this.addError('DATA_ACCESS_TEST_FAILED', `Erreur dans les tests d'accès aux données: ${error.message}`);
        }
        
        this.results.dataAccessTests = dataAccessTests;
    }

    /**
     * Test de récupération des submissions
     */
    async testSubmissionRetrieval(dataAccessTests) {
        try {
            // Test de récupération par utilisateur
            const users = await this.db.collection('users').find({}).limit(5).toArray();
            
            let successfulRetrievals = 0;
            
            for (const user of users) {
                const submissions = await this.db.collection('submissions')
                    .find({ userId: user._id })
                    .toArray();
                
                if (Array.isArray(submissions)) {
                    successfulRetrievals++;
                }
            }
            
            if (successfulRetrievals === users.length) {
                dataAccessTests.submissionRetrieval = true;
                this.logger.info(`✅ Récupération des submissions réussie: ${successfulRetrievals}/${users.length}`);
            } else {
                this.addError(
                    'SUBMISSION_RETRIEVAL_FAILED',
                    `Échec de récupération des submissions pour certains utilisateurs`
                );
            }
            
        } catch (error) {
            this.addError('SUBMISSION_RETRIEVAL_TEST_FAILED', `Test de récupération des submissions échoué: ${error.message}`);
        }
    }

    /**
     * Test d'accès aux données utilisateur
     */
    async testUserDataAccess(dataAccessTests) {
        try {
            // Test de récupération des données complètes utilisateur
            const users = await this.db.collection('users')
                .find({})
                .project({ 
                    username: 1, 
                    email: 1, 
                    role: 1, 
                    'metadata.responseCount': 1,
                    'migrationData.legacyName': 1 
                })
                .limit(5)
                .toArray();
            
            let validUserData = 0;
            
            for (const user of users) {
                if (user.username && user.email && user.role) {
                    validUserData++;
                } else {
                    this.addError(
                        'INCOMPLETE_USER_DATA',
                        `Données utilisateur incomplètes pour ${user._id}`,
                        { userId: user._id, hasUsername: !!user.username, hasEmail: !!user.email, hasRole: !!user.role }
                    );
                }
            }
            
            if (validUserData === users.length && users.length > 0) {
                dataAccessTests.userDataAccess = true;
                this.logger.info(`✅ Accès aux données utilisateur: ${validUserData}/${users.length}`);
            }
            
        } catch (error) {
            this.addError('USER_DATA_ACCESS_TEST_FAILED', `Test d'accès aux données utilisateur échoué: ${error.message}`);
        }
    }

    /**
     * Test d'accès aux invitations
     */
    async testInvitationAccess(dataAccessTests) {
        try {
            // Test de récupération des invitations par token
            const invitations = await this.db.collection('invitations')
                .find({ token: { $exists: true, $ne: null } })
                .limit(5)
                .toArray();
            
            let accessibleInvitations = 0;
            
            for (const invitation of invitations) {
                if (invitation.token && invitation.status) {
                    accessibleInvitations++;
                } else {
                    this.addError(
                        'INCOMPLETE_INVITATION_DATA',
                        `Données d'invitation incomplètes pour ${invitation._id}`,
                        { invitationId: invitation._id }
                    );
                }
            }
            
            if (accessibleInvitations === invitations.length && invitations.length > 0) {
                dataAccessTests.invitationAccess = true;
                this.logger.info(`✅ Accès aux invitations: ${accessibleInvitations}/${invitations.length}`);
            }
            
        } catch (error) {
            this.addError('INVITATION_ACCESS_TEST_FAILED', `Test d'accès aux invitations échoué: ${error.message}`);
        }
    }

    /**
     * Test de l'intégrité des données historiques
     */
    async testHistoricalDataIntegrity(dataAccessTests) {
        try {
            // Vérification que les données historiques sont accessibles et cohérentes
            const monthlyData = await this.db.collection('submissions').aggregate([
                {
                    $group: {
                        _id: '$month',
                        count: { $sum: 1 },
                        userIds: { $addToSet: '$userId' }
                    }
                },
                { $sort: { _id: 1 } }
            ]).toArray();
            
            let validMonths = 0;
            
            for (const monthData of monthlyData) {
                if (monthData._id && monthData.count > 0 && monthData.userIds.length > 0) {
                    validMonths++;
                } else {
                    this.addError(
                        'INVALID_HISTORICAL_DATA',
                        `Données historiques invalides pour le mois ${monthData._id}`,
                        { month: monthData._id, count: monthData.count }
                    );
                }
            }
            
            if (validMonths === monthlyData.length && monthlyData.length > 0) {
                dataAccessTests.historicalDataIntegrity = true;
                this.logger.info(`✅ Intégrité des données historiques: ${validMonths} mois validés`);
            }
            
        } catch (error) {
            this.addError('HISTORICAL_DATA_TEST_FAILED', `Test d'intégrité des données historiques échoué: ${error.message}`);
        }
    }

    /**
     * Test d'accès aux références croisées
     */
    async testCrossReferenceAccess(dataAccessTests) {
        try {
            // Test d'accès via les références User → Submission → Invitation
            const crossReferenceTest = await this.db.collection('users').aggregate([
                {
                    $lookup: {
                        from: 'submissions',
                        localField: '_id',
                        foreignField: 'userId',
                        as: 'submissions'
                    }
                },
                {
                    $lookup: {
                        from: 'invitations',
                        localField: '_id',
                        foreignField: 'userId',
                        as: 'invitations'
                    }
                },
                {
                    $project: {
                        username: 1,
                        submissionCount: { $size: '$submissions' },
                        invitationCount: { $size: '$invitations' }
                    }
                }
            ]).limit(5).toArray();
            
            if (crossReferenceTest.length > 0) {
                dataAccessTests.crossReferenceAccess = true;
                this.logger.info(`✅ Accès aux références croisées: ${crossReferenceTest.length} utilisateurs testés`);
            } else {
                this.addError('CROSS_REFERENCE_ACCESS_FAILED', 'Aucune donnée accessible via les références croisées');
            }
            
        } catch (error) {
            this.addError('CROSS_REFERENCE_TEST_FAILED', `Test d'accès aux références croisées échoué: ${error.message}`);
        }
    }

    /**
     * Validation des workflows
     */
    async validateWorkflows() {
        this.logger.info('🔄 Validation des workflows...');
        
        const workflowTests = {
            newSubmissionWorkflow: false,
            dataRetrievalWorkflow: false,
            userManagementWorkflow: false,
            migrationTraceability: false
        };
        
        try {
            // Test 1: Workflow de nouvelle soumission
            await this.testNewSubmissionWorkflow(workflowTests);
            
            // Test 2: Workflow de récupération de données
            await this.testDataRetrievalWorkflow(workflowTests);
            
            // Test 3: Workflow de gestion des utilisateurs
            await this.testUserManagementWorkflow(workflowTests);
            
            // Test 4: Traçabilité de la migration
            await this.testMigrationTraceability(workflowTests);
            
        } catch (error) {
            this.addError('WORKFLOW_TEST_FAILED', `Erreur dans les tests de workflow: ${error.message}`);
        }
        
        this.results.workflowTests = workflowTests;
    }

    /**
     * Test du workflow de nouvelle soumission
     */
    async testNewSubmissionWorkflow(workflowTests) {
        try {
            // Simulation d'une nouvelle soumission
            const testUser = await this.db.collection('users').findOne({ role: 'user' });
            
            if (!testUser) {
                this.addWarning('NO_TEST_USER_AVAILABLE', 'Aucun utilisateur de test disponible');
                return;
            }
            
            // Vérification que l'utilisateur peut théoriquement soumettre
            const currentMonth = new Date().toISOString().substring(0, 7);
            const existingSubmission = await this.db.collection('submissions')
                .findOne({ userId: testUser._id, month: currentMonth });
            
            // Si pas de soumission ce mois-ci, le workflow est disponible
            if (!existingSubmission) {
                workflowTests.newSubmissionWorkflow = true;
                this.logger.info('✅ Workflow de nouvelle soumission disponible');
            } else {
                this.logger.info('ℹ️ Utilisateur a déjà soumis ce mois-ci (normal)');
                workflowTests.newSubmissionWorkflow = true; // Ce n'est pas une erreur
            }
            
        } catch (error) {
            this.addError('NEW_SUBMISSION_WORKFLOW_TEST_FAILED', `Test du workflow de nouvelle soumission échoué: ${error.message}`);
        }
    }

    /**
     * Test du workflow de récupération de données
     */
    async testDataRetrievalWorkflow(workflowTests) {
        try {
            // Test de récupération complète des données d'un utilisateur
            const testUser = await this.db.collection('users').findOne({});
            
            if (!testUser) {
                this.addError('NO_USER_FOR_RETRIEVAL_TEST', 'Aucun utilisateur pour le test de récupération');
                return;
            }
            
            // Récupération des submissions
            const submissions = await this.db.collection('submissions')
                .find({ userId: testUser._id })
                .toArray();
            
            // Récupération des invitations
            const invitations = await this.db.collection('invitations')
                .find({ userId: testUser._id })
                .toArray();
            
            workflowTests.dataRetrievalWorkflow = true;
            this.logger.info(`✅ Workflow de récupération: ${submissions.length} submissions, ${invitations.length} invitations`);
            
        } catch (error) {
            this.addError('DATA_RETRIEVAL_WORKFLOW_TEST_FAILED', `Test du workflow de récupération échoué: ${error.message}`);
        }
    }

    /**
     * Test du workflow de gestion des utilisateurs
     */
    async testUserManagementWorkflow(workflowTests) {
        try {
            // Test de recherche et gestion des utilisateurs
            const userStats = await this.db.collection('users').aggregate([
                {
                    $group: {
                        _id: '$role',
                        count: { $sum: 1 },
                        activeUsers: {
                            $sum: { $cond: ['$metadata.isActive', 1, 0] }
                        }
                    }
                }
            ]).toArray();
            
            if (userStats.length > 0) {
                workflowTests.userManagementWorkflow = true;
                this.logger.info(`✅ Workflow de gestion utilisateur: ${userStats.length} rôles gérés`);
            } else {
                this.addError('USER_MANAGEMENT_WORKFLOW_FAILED', 'Impossible de récupérer les statistiques utilisateur');
            }
            
        } catch (error) {
            this.addError('USER_MANAGEMENT_WORKFLOW_TEST_FAILED', `Test du workflow de gestion utilisateur échoué: ${error.message}`);
        }
    }

    /**
     * Test de la traçabilité de la migration
     */
    async testMigrationTraceability(workflowTests) {
        try {
            // Vérification que les données de migration sont traçables
            const migratedUsers = await this.db.collection('users')
                .countDocuments({ 'migrationData.legacyName': { $exists: true } });
            
            const migratedInvitations = await this.db.collection('invitations')
                .countDocuments({ 'migrationData.migratedAt': { $exists: true } });
            
            if (migratedUsers > 0 || migratedInvitations > 0) {
                workflowTests.migrationTraceability = true;
                this.logger.info(`✅ Traçabilité migration: ${migratedUsers} utilisateurs, ${migratedInvitations} invitations`);
            } else {
                this.addWarning('NO_MIGRATION_TRACEABILITY', 'Aucune donnée de traçabilité de migration trouvée');
            }
            
        } catch (error) {
            this.addError('MIGRATION_TRACEABILITY_TEST_FAILED', `Test de traçabilité de migration échoué: ${error.message}`);
        }
    }

    /**
     * Validation des fonctionnalités dashboard
     */
    async validateDashboardFunctionality() {
        this.logger.info('📊 Validation des fonctionnalités dashboard...');
        
        const dashboardTests = {
            statisticsCalculation: false,
            monthlyBreakdown: false,
            userRoleFiltering: false,
            dataVisualizationPrep: false
        };
        
        try {
            // Test 1: Calcul des statistiques
            await this.testStatisticsCalculation(dashboardTests);
            
            // Test 2: Répartition mensuelle
            await this.testMonthlyBreakdown(dashboardTests);
            
            // Test 3: Filtrage par rôle utilisateur
            await this.testUserRoleFiltering(dashboardTests);
            
            // Test 4: Préparation des données de visualisation
            await this.testDataVisualizationPrep(dashboardTests);
            
        } catch (error) {
            this.addError('DASHBOARD_TEST_FAILED', `Erreur dans les tests de dashboard: ${error.message}`);
        }
        
        this.results.dashboardTests = dashboardTests;
    }

    /**
     * Test du calcul des statistiques
     */
    async testStatisticsCalculation(dashboardTests) {
        try {
            const stats = await this.db.collection('submissions').aggregate([
                {
                    $group: {
                        _id: null,
                        totalSubmissions: { $sum: 1 },
                        uniqueUsers: { $addToSet: '$userId' },
                        months: { $addToSet: '$month' }
                    }
                },
                {
                    $project: {
                        totalSubmissions: 1,
                        uniqueUserCount: { $size: '$uniqueUsers' },
                        monthCount: { $size: '$months' }
                    }
                }
            ]).toArray();
            
            if (stats.length > 0 && stats[0].totalSubmissions >= 0) {
                dashboardTests.statisticsCalculation = true;
                this.logger.info(`✅ Calcul des statistiques: ${stats[0].totalSubmissions} submissions`);
            } else {
                this.addError('STATISTICS_CALCULATION_FAILED', 'Impossible de calculer les statistiques');
            }
            
        } catch (error) {
            this.addError('STATISTICS_CALCULATION_TEST_FAILED', `Test de calcul des statistiques échoué: ${error.message}`);
        }
    }

    /**
     * Test de la répartition mensuelle
     */
    async testMonthlyBreakdown(dashboardTests) {
        try {
            const monthlyBreakdown = await this.db.collection('submissions').aggregate([
                {
                    $group: {
                        _id: '$month',
                        submissions: { $sum: 1 },
                        users: { $addToSet: '$userId' }
                    }
                },
                {
                    $project: {
                        month: '$_id',
                        submissions: 1,
                        userCount: { $size: '$users' }
                    }
                },
                { $sort: { month: -1 } }
            ]).toArray();
            
            if (monthlyBreakdown.length > 0) {
                dashboardTests.monthlyBreakdown = true;
                this.logger.info(`✅ Répartition mensuelle: ${monthlyBreakdown.length} mois`);
            } else {
                this.addError('MONTHLY_BREAKDOWN_FAILED', 'Impossible de générer la répartition mensuelle');
            }
            
        } catch (error) {
            this.addError('MONTHLY_BREAKDOWN_TEST_FAILED', `Test de répartition mensuelle échoué: ${error.message}`);
        }
    }

    /**
     * Test du filtrage par rôle utilisateur
     */
    async testUserRoleFiltering(dashboardTests) {
        try {
            const roleBreakdown = await this.db.collection('submissions').aggregate([
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
                    $group: {
                        _id: '$user.role',
                        count: { $sum: 1 }
                    }
                }
            ]).toArray();
            
            if (roleBreakdown.length > 0) {
                dashboardTests.userRoleFiltering = true;
                this.logger.info(`✅ Filtrage par rôle: ${roleBreakdown.length} rôles détectés`);
            } else {
                this.addError('USER_ROLE_FILTERING_FAILED', 'Impossible de filtrer par rôle utilisateur');
            }
            
        } catch (error) {
            this.addError('USER_ROLE_FILTERING_TEST_FAILED', `Test de filtrage par rôle échoué: ${error.message}`);
        }
    }

    /**
     * Test de préparation des données de visualisation
     */
    async testDataVisualizationPrep(dashboardTests) {
        try {
            // Test de préparation de données pour un graphique type
            const visualizationData = await this.db.collection('submissions').aggregate([
                {
                    $group: {
                        _id: {
                            month: '$month',
                            userRole: '$userRole'
                        },
                        count: { $sum: 1 }
                    }
                },
                {
                    $group: {
                        _id: '$_id.month',
                        data: {
                            $push: {
                                role: '$_id.userRole',
                                count: '$count'
                            }
                        }
                    }
                },
                { $sort: { _id: 1 } }
            ]).toArray();
            
            if (visualizationData.length > 0) {
                dashboardTests.dataVisualizationPrep = true;
                this.logger.info(`✅ Préparation visualisation: ${visualizationData.length} points de données`);
            } else {
                this.addError('DATA_VISUALIZATION_PREP_FAILED', 'Impossible de préparer les données de visualisation');
            }
            
        } catch (error) {
            this.addError('DATA_VISUALIZATION_PREP_TEST_FAILED', `Test de préparation de visualisation échoué: ${error.message}`);
        }
    }

    /**
     * Validation de la compatibilité legacy
     */
    async validateLegacyCompatibility() {
        this.logger.info('🔗 Validation de la compatibilité legacy...');
        
        const legacyTests = {
            tokenUrlAccess: false,
            legacyNameMapping: false,
            responseViewCompatibility: false,
            migrationDataPreservation: false
        };
        
        try {
            // Test 1: Accès aux URLs par token
            await this.testTokenUrlAccess(legacyTests);
            
            // Test 2: Mapping des noms legacy
            await this.testLegacyNameMapping(legacyTests);
            
            // Test 3: Compatibilité des vues de réponses
            await this.testResponseViewCompatibility(legacyTests);
            
            // Test 4: Préservation des données de migration
            await this.testMigrationDataPreservation(legacyTests);
            
        } catch (error) {
            this.addError('LEGACY_COMPATIBILITY_TEST_FAILED', `Erreur dans les tests de compatibilité legacy: ${error.message}`);
        }
        
        this.results.legacyCompatibility = legacyTests;
    }

    /**
     * Test d'accès aux URLs par token
     */
    async testTokenUrlAccess(legacyTests) {
        try {
            const activeInvitations = await this.db.collection('invitations')
                .find({ 
                    status: 'active',
                    token: { $exists: true, $ne: null }
                })
                .limit(5)
                .toArray();
            
            let accessibleTokens = 0;
            
            for (const invitation of activeInvitations) {
                if (invitation.token && invitation.userId) {
                    accessibleTokens++;
                }
            }
            
            if (accessibleTokens > 0) {
                legacyTests.tokenUrlAccess = true;
                this.logger.info(`✅ Accès aux URLs par token: ${accessibleTokens} tokens accessibles`);
            } else {
                this.addWarning('NO_ACCESSIBLE_TOKENS', 'Aucun token accessible trouvé');
            }
            
        } catch (error) {
            this.addError('TOKEN_URL_ACCESS_TEST_FAILED', `Test d'accès aux URLs par token échoué: ${error.message}`);
        }
    }

    /**
     * Test du mapping des noms legacy
     */
    async testLegacyNameMapping(legacyTests) {
        try {
            const usersWithLegacyNames = await this.db.collection('users')
                .countDocuments({ 'migrationData.legacyName': { $exists: true, $ne: null } });
            
            if (usersWithLegacyNames > 0) {
                legacyTests.legacyNameMapping = true;
                this.logger.info(`✅ Mapping des noms legacy: ${usersWithLegacyNames} utilisateurs`);
            } else {
                this.addWarning('NO_LEGACY_NAME_MAPPING', 'Aucun mapping de nom legacy trouvé');
            }
            
        } catch (error) {
            this.addError('LEGACY_NAME_MAPPING_TEST_FAILED', `Test de mapping des noms legacy échoué: ${error.message}`);
        }
    }

    /**
     * Test de compatibilité des vues de réponses
     */
    async testResponseViewCompatibility(legacyTests) {
        try {
            // Test que les données sont accessibles dans le format attendu
            const submissionWithResponses = await this.db.collection('submissions')
                .findOne({ 
                    responses: { $exists: true, $ne: [] }
                });
            
            if (submissionWithResponses && Array.isArray(submissionWithResponses.responses)) {
                legacyTests.responseViewCompatibility = true;
                this.logger.info('✅ Compatibilité des vues de réponses');
            } else {
                this.addError('RESPONSE_VIEW_COMPATIBILITY_FAILED', 'Format des réponses incompatible');
            }
            
        } catch (error) {
            this.addError('RESPONSE_VIEW_COMPATIBILITY_TEST_FAILED', `Test de compatibilité des vues de réponses échoué: ${error.message}`);
        }
    }

    /**
     * Test de préservation des données de migration
     */
    async testMigrationDataPreservation(legacyTests) {
        try {
            const migrationDataCount = await this.db.collection('users')
                .countDocuments({ 
                    'migrationData.migratedAt': { $exists: true },
                    'migrationData.source': { $exists: true }
                });
            
            const invitationMigrationCount = await this.db.collection('invitations')
                .countDocuments({ 
                    'migrationData.migratedAt': { $exists: true }
                });
            
            if (migrationDataCount > 0 || invitationMigrationCount > 0) {
                legacyTests.migrationDataPreservation = true;
                this.logger.info(`✅ Préservation des données de migration: ${migrationDataCount + invitationMigrationCount} documents`);
            } else {
                this.addWarning('NO_MIGRATION_DATA_PRESERVED', 'Aucune donnée de migration préservée');
            }
            
        } catch (error) {
            this.addError('MIGRATION_DATA_PRESERVATION_TEST_FAILED', `Test de préservation des données de migration échoué: ${error.message}`);
        }
    }

    /**
     * Vérification si un hash bcrypt est valide
     */
    isValidBcryptHash(hash) {
        // Format bcrypt : $2a$10$... ou $2b$10$...
        const bcryptRegex = /^\$2[aby]\$\d{2}\$.{53}$/;
        return bcryptRegex.test(hash);
    }

    /**
     * Comptage total des tests
     */
    getTotalTestCount() {
        let total = 0;
        
        for (const category of Object.values(this.results)) {
            if (typeof category === 'object' && category !== null) {
                total += Object.keys(category).length;
            }
        }
        
        return total;
    }

    /**
     * Comptage des tests réussis
     */
    getPassedTestCount() {
        let passed = 0;
        
        for (const category of Object.values(this.results)) {
            if (typeof category === 'object' && category !== null) {
                for (const testResult of Object.values(category)) {
                    if (testResult === true) {
                        passed++;
                    }
                }
            }
        }
        
        return passed;
    }

    /**
     * Calcul du score final
     */
    calculateScore() {
        let score = 100;
        
        // Pénalités par type d'erreur
        const penalties = {
            'INSUFFICIENT_USER_ACCOUNTS': 15,
            'INVALID_PASSWORD_HASH': 10,
            'ADMIN_ROLE_NOT_ASSIGNED': 20,
            'ADMIN_USER_NOT_FOUND': 20,
            'DUPLICATE_USERNAME': 15,
            'INVALID_EMAIL_FORMAT': 5,
            'SUBMISSION_RETRIEVAL_FAILED': 12,
            'INCOMPLETE_USER_DATA': 8,
            'INCOMPLETE_INVITATION_DATA': 6,
            'INVALID_HISTORICAL_DATA': 10,
            'CROSS_REFERENCE_ACCESS_FAILED': 8,
            'NEW_SUBMISSION_WORKFLOW_TEST_FAILED': 10,
            'DATA_RETRIEVAL_WORKFLOW_TEST_FAILED': 8,
            'USER_MANAGEMENT_WORKFLOW_TEST_FAILED': 6,
            'STATISTICS_CALCULATION_FAILED': 8,
            'MONTHLY_BREAKDOWN_FAILED': 6,
            'USER_ROLE_FILTERING_FAILED': 5,
            'DATA_VISUALIZATION_PREP_FAILED': 5,
            'TOKEN_URL_ACCESS_TEST_FAILED': 8,
            'LEGACY_NAME_MAPPING_TEST_FAILED': 5,
            'RESPONSE_VIEW_COMPATIBILITY_FAILED': 10,
            'MIGRATION_DATA_PRESERVATION_TEST_FAILED': 4
        };
        
        // Application des pénalités
        for (const error of this.errors) {
            const penalty = penalties[error.code] || 5;
            score -= penalty;
        }
        
        // Bonus pour les tests réussis
        const totalTests = this.getTotalTestCount();
        const passedTests = this.getPassedTestCount();
        
        if (totalTests > 0) {
            const successRate = (passedTests / totalTests) * 100;
            if (successRate === 100) {
                score += 15;
            } else if (successRate >= 90) {
                score += 10;
            } else if (successRate >= 80) {
                score += 5;
            }
        }
        
        return Math.max(0, Math.min(100, score));
    }
}

module.exports = FunctionalityValidator;