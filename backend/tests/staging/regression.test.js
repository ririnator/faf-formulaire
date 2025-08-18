/**
 * Tests de régression complète pour migration staging
 * Test de tous les endpoints API, workflows existants, sécurité, rate limits
 */

const request = require('supertest');
const mongoose = require('mongoose');
const StagingEnvironment = require('./staging-config');

describe('🔄 Tests de Régression Post-Migration', () => {
    let stagingEnv;
    let app;
    let User, Response, Submission;

    beforeAll(async () => {
        stagingEnv = new StagingEnvironment();
        await stagingEnv.initialize();
        await stagingEnv.connectDatabase();

        // Chargement des modèles
        User = require('../../models/User');
        Response = require('../../models/Response');
        
        // Mock du modèle Submission
        const submissionSchema = new mongoose.Schema({
            userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
            responses: [{
                question: { type: String, required: true },
                answer: { type: String, required: true }
            }],
            month: { type: String, required: true },
            legacyToken: { type: String },
            migrationData: {
                originalResponseId: { type: mongoose.Schema.Types.ObjectId },
                migratedAt: { type: Date, default: Date.now },
                migrationVersion: { type: String, default: '1.0' }
            },
            createdAt: { type: Date, default: Date.now }
        });
        
        Submission = mongoose.model('Submission', submissionSchema);

        app = require('../../app');
    }, 30000);

    beforeEach(async () => {
        // Nettoyage des collections
        await User.deleteMany({});
        await Response.deleteMany({});
        await Submission.deleteMany({});
    });

    afterAll(async () => {
        await stagingEnv.cleanup();
    });

    describe('Test de Tous les Endpoints API', () => {
        let userCookies, adminCookies, testUserId, testSubmissionId;

        beforeEach(async () => {
            // Création d'utilisateurs de test
            const testUser = new User({
                username: 'regression_user',
                email: 'regression@test.com',
                password: await require('bcrypt').hash('password123', 10),
                role: 'user'
            });
            const savedUser = await testUser.save();
            testUserId = savedUser._id;

            const adminUser = new User({
                username: 'regression_admin',
                email: 'regression@admin.com',
                password: await require('bcrypt').hash('adminpass123', 10),
                role: 'admin'
            });
            await adminUser.save();

            // Connexions
            const userLogin = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'regression@test.com',
                    password: 'password123'
                });
            userCookies = userLogin.headers['set-cookie'];

            const adminLogin = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'regression@admin.com',
                    password: 'adminpass123'
                });
            adminCookies = adminLogin.headers['set-cookie'];

            // Création d'une soumission de test
            const submission = new Submission({
                userId: testUserId,
                responses: [
                    { question: 'Test Question', answer: 'Test Answer' }
                ],
                month: '2024-12',
                legacyToken: 'regression_test_token'
            });
            const savedSubmission = await submission.save();
            testSubmissionId = savedSubmission._id;
        });

        describe('Endpoints d\'Authentification', () => {
            test('POST /api/auth/register - Inscription utilisateur', async () => {
                const userData = {
                    username: 'new_regression_user',
                    email: 'new@regression.com',
                    password: 'newpassword123',
                    firstName: 'New',
                    lastName: 'User'
                };

                const response = await request(app)
                    .post('/api/auth/register')
                    .send(userData)
                    .expect(201);

                expect(response.body.success).toBe(true);
                expect(response.body.user.username).toBe('new_regression_user');
                expect(response.body.user.email).toBe('new@regression.com');
            });

            test('POST /api/auth/login - Connexion utilisateur', async () => {
                const response = await request(app)
                    .post('/api/auth/login')
                    .send({
                        email: 'regression@test.com',
                        password: 'password123'
                    })
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.user.username).toBe('regression_user');
                expect(response.headers['set-cookie']).toBeDefined();
            });

            test('POST /api/auth/logout - Déconnexion utilisateur', async () => {
                const response = await request(app)
                    .post('/api/auth/logout')
                    .set('Cookie', userCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
            });

            test('GET /api/auth/me - Informations utilisateur connecté', async () => {
                const response = await request(app)
                    .get('/api/auth/me')
                    .set('Cookie', userCookies)
                    .expect(200);

                expect(response.body.user.username).toBe('regression_user');
            });
        });

        describe('Endpoints Utilisateur', () => {
            test('GET /api/user/profile - Profil utilisateur', async () => {
                const response = await request(app)
                    .get('/api/user/profile')
                    .set('Cookie', userCookies)
                    .expect(200);

                expect(response.body.user.username).toBe('regression_user');
                expect(response.body.user.email).toBe('regression@test.com');
            });

            test('PUT /api/user/profile - Modification profil', async () => {
                const updateData = {
                    profile: {
                        firstName: 'Updated',
                        lastName: 'Name',
                        profession: 'Developer'
                    }
                };

                const response = await request(app)
                    .put('/api/user/profile')
                    .set('Cookie', userCookies)
                    .send(updateData)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.user.profile.firstName).toBe('Updated');
            });

            test('GET /api/user/submissions - Soumissions utilisateur', async () => {
                const response = await request(app)
                    .get('/api/user/submissions')
                    .set('Cookie', userCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(Array.isArray(response.body.submissions)).toBe(true);
                expect(response.body.submissions.length).toBeGreaterThanOrEqual(1);
            });

            test('DELETE /api/user/account - Suppression compte', async () => {
                const response = await request(app)
                    .delete('/api/user/account')
                    .set('Cookie', userCookies)
                    .send({ password: 'password123' })
                    .expect(200);

                expect(response.body.success).toBe(true);

                // Vérification que l'utilisateur est supprimé
                const deletedUser = await User.findById(testUserId);
                expect(deletedUser).toBeNull();
            });
        });

        describe('Endpoints de Soumission', () => {
            test('POST /api/submissions - Création soumission', async () => {
                const submissionData = {
                    responses: [
                        { question: 'Nouvelle Question 1', answer: 'Nouvelle Réponse 1' },
                        { question: 'Nouvelle Question 2', answer: 'Nouvelle Réponse 2' }
                    ]
                };

                const response = await request(app)
                    .post('/api/submissions')
                    .set('Cookie', userCookies)
                    .send(submissionData)
                    .expect(201);

                expect(response.body.success).toBe(true);
                expect(response.body.submission.responses.length).toBe(2);
                expect(response.body.submission.userId.toString()).toBe(testUserId.toString());
            });

            test('GET /api/submissions/:id - Récupération soumission', async () => {
                const response = await request(app)
                    .get(`/api/submissions/${testSubmissionId}`)
                    .set('Cookie', userCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.submission._id.toString()).toBe(testSubmissionId.toString());
            });

            test('PUT /api/submissions/:id - Modification soumission', async () => {
                const updateData = {
                    responses: [
                        { question: 'Question Modifiée', answer: 'Réponse Modifiée' }
                    ]
                };

                const response = await request(app)
                    .put(`/api/submissions/${testSubmissionId}`)
                    .set('Cookie', userCookies)
                    .send(updateData)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.submission.responses[0].question).toBe('Question Modifiée');
            });

            test('DELETE /api/submissions/:id - Suppression soumission', async () => {
                const response = await request(app)
                    .delete(`/api/submissions/${testSubmissionId}`)
                    .set('Cookie', userCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);

                // Vérification suppression
                const deletedSubmission = await Submission.findById(testSubmissionId);
                expect(deletedSubmission).toBeNull();
            });
        });

        describe('Endpoints Admin', () => {
            test('GET /api/admin/dashboard - Dashboard admin', async () => {
                const response = await request(app)
                    .get('/api/admin/dashboard')
                    .set('Cookie', adminCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.statistics).toBeDefined();
            });

            test('GET /api/admin/users - Liste utilisateurs', async () => {
                const response = await request(app)
                    .get('/api/admin/users')
                    .set('Cookie', adminCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(Array.isArray(response.body.users)).toBe(true);
                expect(response.body.users.length).toBeGreaterThanOrEqual(2);
            });

            test('GET /api/admin/submissions - Liste soumissions', async () => {
                const response = await request(app)
                    .get('/api/admin/submissions')
                    .set('Cookie', adminCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(Array.isArray(response.body.submissions)).toBe(true);
            });

            test('GET /api/admin/statistics - Statistiques', async () => {
                const response = await request(app)
                    .get('/api/admin/statistics')
                    .set('Cookie', adminCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.totalUsers).toBeDefined();
                expect(response.body.totalSubmissions).toBeDefined();
            });

            test('GET /api/admin/search - Recherche', async () => {
                const response = await request(app)
                    .get('/api/admin/search?q=test&month=2024-12')
                    .set('Cookie', adminCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(Array.isArray(response.body.results)).toBe(true);
            });

            test('PUT /api/admin/users/:id - Modification utilisateur', async () => {
                const updateData = {
                    role: 'admin',
                    profile: {
                        firstName: 'Admin Updated'
                    }
                };

                const response = await request(app)
                    .put(`/api/admin/users/${testUserId}`)
                    .set('Cookie', adminCookies)
                    .send(updateData)
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.user.role).toBe('admin');
            });

            test('DELETE /api/admin/users/:id - Suppression utilisateur', async () => {
                const response = await request(app)
                    .delete(`/api/admin/users/${testUserId}`)
                    .set('Cookie', adminCookies)
                    .expect(200);

                expect(response.body.success).toBe(true);
            });
        });

        describe('Endpoints de Visualisation Legacy', () => {
            test('GET /api/view/:token - Accès par token legacy', async () => {
                const response = await request(app)
                    .get('/api/view/regression_test_token')
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.submission.legacyToken).toBe('regression_test_token');
            });

            test('GET /view/:token - Page HTML legacy', async () => {
                const response = await request(app)
                    .get('/view/regression_test_token')
                    .expect(200);

                expect(response.text).toContain('Test Answer');
                expect(response.headers['content-type']).toContain('text/html');
            });
        });

        describe('Endpoints d\'Upload', () => {
            test('POST /api/upload - Upload image', async () => {
                const imageBuffer = Buffer.from('fake image data');
                
                const response = await request(app)
                    .post('/api/upload')
                    .set('Cookie', userCookies)
                    .attach('image', imageBuffer, 'test.jpg')
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.imageUrl).toBeDefined();
            });

            test('POST /upload - Upload legacy', async () => {
                const imageBuffer = Buffer.from('fake image data legacy');
                
                const response = await request(app)
                    .post('/upload')
                    .attach('image', imageBuffer, 'legacy.jpg')
                    .expect(200);

                expect(response.body.success).toBe(true);
                expect(response.body.imageUrl).toBeDefined();
            });
        });
    });

    describe('Validation des Workflows Existants', () => {
        test('Workflow complet inscription → connexion → soumission → visualisation', async () => {
            // 1. Inscription
            const registrationData = {
                username: 'workflow_user',
                email: 'workflow@test.com',
                password: 'workflowpass123',
                firstName: 'Workflow',
                lastName: 'User'
            };

            const registerResponse = await request(app)
                .post('/api/auth/register')
                .send(registrationData)
                .expect(201);

            expect(registerResponse.body.success).toBe(true);
            const userId = registerResponse.body.user.id;

            // 2. Connexion
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'workflow@test.com',
                    password: 'workflowpass123'
                })
                .expect(200);

            const cookies = loginResponse.headers['set-cookie'];
            expect(loginResponse.body.success).toBe(true);

            // 3. Soumission
            const submissionData = {
                responses: [
                    { question: 'Question workflow 1', answer: 'Réponse workflow 1' },
                    { question: 'Question workflow 2', answer: 'Réponse workflow 2' }
                ]
            };

            const submissionResponse = await request(app)
                .post('/api/submissions')
                .set('Cookie', cookies)
                .send(submissionData)
                .expect(201);

            expect(submissionResponse.body.success).toBe(true);
            const submissionId = submissionResponse.body.submission._id;

            // 4. Visualisation par l'utilisateur
            const viewResponse = await request(app)
                .get(`/api/submissions/${submissionId}`)
                .set('Cookie', cookies)
                .expect(200);

            expect(viewResponse.body.success).toBe(true);
            expect(viewResponse.body.submission.responses.length).toBe(2);

            // 5. Modification
            const updateData = {
                responses: [
                    { question: 'Question modifiée', answer: 'Réponse modifiée' }
                ]
            };

            const updateResponse = await request(app)
                .put(`/api/submissions/${submissionId}`)
                .set('Cookie', cookies)
                .send(updateData)
                .expect(200);

            expect(updateResponse.body.success).toBe(true);

            // 6. Déconnexion
            const logoutResponse = await request(app)
                .post('/api/auth/logout')
                .set('Cookie', cookies)
                .expect(200);

            expect(logoutResponse.body.success).toBe(true);
        });

        test('Workflow admin complet : connexion → dashboard → gestion → statistiques', async () => {
            // Création d'un admin
            const adminUser = new User({
                username: 'workflow_admin',
                email: 'workflow@admin.com',
                password: await require('bcrypt').hash('adminworkflow123', 10),
                role: 'admin'
            });
            await adminUser.save();

            // Création de données de test
            const testUser = new User({
                username: 'admin_test_user',
                email: 'admintest@user.com',
                password: await require('bcrypt').hash('userpass', 10),
                role: 'user'
            });
            const savedTestUser = await testUser.save();

            const testSubmission = new Submission({
                userId: savedTestUser._id,
                responses: [
                    { question: 'Admin workflow question', answer: 'Admin workflow answer' }
                ],
                month: '2024-12',
                legacyToken: 'admin_workflow_token'
            });
            await testSubmission.save();

            // 1. Connexion admin
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'workflow@admin.com',
                    password: 'adminworkflow123'
                })
                .expect(200);

            const adminCookies = loginResponse.headers['set-cookie'];

            // 2. Dashboard
            const dashboardResponse = await request(app)
                .get('/api/admin/dashboard')
                .set('Cookie', adminCookies)
                .expect(200);

            expect(dashboardResponse.body.success).toBe(true);

            // 3. Gestion des utilisateurs
            const usersResponse = await request(app)
                .get('/api/admin/users')
                .set('Cookie', adminCookies)
                .expect(200);

            expect(usersResponse.body.users.length).toBeGreaterThanOrEqual(2);

            // 4. Gestion des soumissions
            const submissionsResponse = await request(app)
                .get('/api/admin/submissions')
                .set('Cookie', adminCookies)
                .expect(200);

            expect(submissionsResponse.body.submissions.length).toBeGreaterThanOrEqual(1);

            // 5. Modification d'une soumission
            const updateSubmissionResponse = await request(app)
                .put(`/api/admin/submissions/${testSubmission._id}`)
                .set('Cookie', adminCookies)
                .send({
                    responses: [
                        { question: 'Modified by admin', answer: 'Admin modification' }
                    ]
                })
                .expect(200);

            expect(updateSubmissionResponse.body.success).toBe(true);

            // 6. Statistiques
            const statsResponse = await request(app)
                .get('/api/admin/statistics')
                .set('Cookie', adminCookies)
                .expect(200);

            expect(statsResponse.body.success).toBe(true);
            expect(statsResponse.body.totalUsers).toBeGreaterThanOrEqual(2);

            // 7. Recherche
            const searchResponse = await request(app)
                .get('/api/admin/search?q=workflow&month=2024-12')
                .set('Cookie', adminCookies)
                .expect(200);

            expect(searchResponse.body.success).toBe(true);
        });

        test('Workflow de migration legacy : Response → User → Submission', async () => {
            // 1. Création d'une réponse legacy
            const legacyResponse = new Response({
                name: 'Legacy Migration User',
                responses: [
                    { question: 'Legacy Question 1', answer: 'Legacy Answer 1' },
                    { question: 'Legacy Question 2', answer: 'Legacy Answer 2' }
                ],
                month: '2024-12',
                isAdmin: false,
                token: 'legacy_migration_token_' + Date.now(),
                createdAt: new Date('2024-12-01')
            });
            await legacyResponse.save();

            // 2. Simulation de création d'utilisateur depuis la réponse
            const generatedUser = new User({
                username: 'legacy_migration_user',
                email: 'legacy.migration@test.com',
                password: await require('bcrypt').hash('migrated_password', 10),
                role: 'user',
                migrationData: {
                    legacyName: legacyResponse.name,
                    migratedAt: new Date(),
                    source: 'response_migration'
                }
            });
            await generatedUser.save();

            // 3. Création de la soumission migrée
            const migratedSubmission = new Submission({
                userId: generatedUser._id,
                responses: legacyResponse.responses,
                month: legacyResponse.month,
                legacyToken: legacyResponse.token,
                migrationData: {
                    originalResponseId: legacyResponse._id,
                    migratedAt: new Date(),
                    migrationVersion: '1.0'
                },
                createdAt: legacyResponse.createdAt
            });
            await migratedSubmission.save();

            // 4. Validation du workflow de migration
            const savedUser = await User.findById(generatedUser._id);
            expect(savedUser.migrationData.legacyName).toBe('Legacy Migration User');
            expect(savedUser.migrationData.source).toBe('response_migration');

            const savedSubmission = await Submission.findById(migratedSubmission._id).populate('userId');
            expect(savedSubmission.userId.username).toBe('legacy_migration_user');
            expect(savedSubmission.legacyToken).toBe(legacyResponse.token);
            expect(savedSubmission.migrationData.originalResponseId.toString()).toBe(legacyResponse._id.toString());

            // 5. Test d'accès via token legacy
            const legacyAccessResponse = await request(app)
                .get(`/api/view/${legacyResponse.token}`)
                .expect(200);

            expect(legacyAccessResponse.body.success).toBe(true);
            expect(legacyAccessResponse.body.submission.responses[0].answer).toBe('Legacy Answer 1');

            // 6. Test de connexion avec le compte migré
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'legacy.migration@test.com',
                    password: 'migrated_password'
                })
                .expect(200);

            expect(loginResponse.body.success).toBe(true);
            expect(loginResponse.body.user.username).toBe('legacy_migration_user');

            // 7. Accès aux données migrées via le nouveau système
            const cookies = loginResponse.headers['set-cookie'];
            const userSubmissionsResponse = await request(app)
                .get('/api/user/submissions')
                .set('Cookie', cookies)
                .expect(200);

            expect(userSubmissionsResponse.body.submissions.length).toBeGreaterThanOrEqual(1);
            expect(userSubmissionsResponse.body.submissions[0].legacyToken).toBe(legacyResponse.token);
        });
    });

    describe('Test de la Sécurité et Authentification', () => {
        test('Doit empêcher l\'accès non autorisé aux endpoints protégés', async () => {
            // Test endpoints utilisateur sans authentification
            await request(app).get('/api/user/profile').expect(401);
            await request(app).get('/api/user/submissions').expect(401);
            await request(app).post('/api/submissions').expect(401);

            // Test endpoints admin sans authentification
            await request(app).get('/api/admin/dashboard').expect(401);
            await request(app).get('/api/admin/users').expect(401);
            await request(app).get('/api/admin/submissions').expect(401);
        });

        test('Doit empêcher l\'escalade de privilèges', async () => {
            // Création d'un utilisateur normal
            const normalUser = new User({
                username: 'normal_user',
                email: 'normal@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await normalUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'normal@test.com',
                    password: 'password'
                });

            const userCookies = loginResponse.headers['set-cookie'];

            // Tentative d'accès aux endpoints admin
            await request(app)
                .get('/api/admin/dashboard')
                .set('Cookie', userCookies)
                .expect(403);

            await request(app)
                .get('/api/admin/users')
                .set('Cookie', userCookies)
                .expect(403);

            await request(app)
                .delete(`/api/admin/users/${normalUser._id}`)
                .set('Cookie', userCookies)
                .expect(403);
        });

        test('Doit valider les tokens de session', async () => {
            const testUser = new User({
                username: 'session_test',
                email: 'session@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            // Connexion valide
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'session@test.com',
                    password: 'password'
                });

            const validCookies = loginResponse.headers['set-cookie'];

            // Test avec session valide
            await request(app)
                .get('/api/user/profile')
                .set('Cookie', validCookies)
                .expect(200);

            // Test avec session invalide
            const invalidCookies = ['faf-session=invalid_session_token'];
            await request(app)
                .get('/api/user/profile')
                .set('Cookie', invalidCookies)
                .expect(401);

            // Test après déconnexion
            await request(app)
                .post('/api/auth/logout')
                .set('Cookie', validCookies)
                .expect(200);

            await request(app)
                .get('/api/user/profile')
                .set('Cookie', validCookies)
                .expect(401);
        });

        test('Doit protéger contre les injections XSS', async () => {
            const testUser = new User({
                username: 'xss_test',
                email: 'xss@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'xss@test.com',
                    password: 'password'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test soumission avec tentative XSS
            const xssData = {
                responses: [
                    { 
                        question: '<script>alert("xss")</script>Question', 
                        answer: '<img src="x" onerror="alert(\'xss\')">' 
                    },
                    { 
                        question: 'Normal question', 
                        answer: '"><script>alert("xss")</script>' 
                    }
                ]
            };

            const submissionResponse = await request(app)
                .post('/api/submissions')
                .set('Cookie', cookies)
                .send(xssData)
                .expect(201);

            // Vérification que le contenu est échappé
            const savedSubmission = submissionResponse.body.submission;
            expect(savedSubmission.responses[0].question).not.toContain('<script>');
            expect(savedSubmission.responses[0].answer).not.toContain('<img');
            expect(savedSubmission.responses[1].answer).not.toContain('<script>');
        });

        test('Doit protéger contre l\'injection NoSQL', async () => {
            // Tentative d'injection dans l'authentification
            const injectionAttempt = {
                email: { $ne: null },
                password: { $ne: null }
            };

            await request(app)
                .post('/api/auth/login')
                .send(injectionAttempt)
                .expect(400); // Validation d'entrée doit rejeter

            // Tentative d'injection dans la recherche
            const adminUser = new User({
                username: 'nosql_admin',
                email: 'nosql@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'nosql@admin.com',
                    password: 'adminpass'
                });

            const adminCookies = loginResponse.headers['set-cookie'];

            // Tentative d'injection dans la recherche
            await request(app)
                .get('/api/admin/search?q[$ne]=null&month=2024-12')
                .set('Cookie', adminCookies)
                .expect(400); // Validation des paramètres doit rejeter
        });
    });

    describe('Vérification des Rate Limits', () => {
        test('Doit appliquer le rate limiting sur les connexions', async () => {
            const testUser = new User({
                username: 'rate_limit_user',
                email: 'ratelimit@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            // Tentatives de connexion rapides
            const loginAttempts = [];
            for (let i = 0; i < 10; i++) {
                loginAttempts.push(
                    request(app)
                        .post('/api/auth/login')
                        .send({
                            email: 'ratelimit@test.com',
                            password: 'wrongpassword' // Mot de passe incorrect
                        })
                );
            }

            const responses = await Promise.all(loginAttempts);
            
            // Les premières tentatives devraient échouer avec 401
            const unauthorizedResponses = responses.filter(r => r.status === 401);
            // Les dernières tentatives devraient être bloquées avec 429
            const rateLimitedResponses = responses.filter(r => r.status === 429);

            expect(unauthorizedResponses.length).toBeGreaterThan(0);
            expect(rateLimitedResponses.length).toBeGreaterThan(0);
        });

        test('Doit appliquer le rate limiting sur les soumissions', async () => {
            const testUser = new User({
                username: 'submission_rate_user',
                email: 'submissionrate@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'submissionrate@test.com',
                    password: 'password'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Multiples soumissions rapides
            const submissionAttempts = [];
            for (let i = 0; i < 6; i++) {
                submissionAttempts.push(
                    request(app)
                        .post('/api/submissions')
                        .set('Cookie', cookies)
                        .send({
                            responses: [
                                { question: `Rate limit test ${i}`, answer: `Answer ${i}` }
                            ]
                        })
                );
            }

            const responses = await Promise.all(submissionAttempts);
            
            // Les premières soumissions devraient réussir
            const successfulSubmissions = responses.filter(r => r.status === 201);
            // Les dernières devraient être bloquées
            const rateLimitedSubmissions = responses.filter(r => r.status === 429);

            expect(successfulSubmissions.length).toBeGreaterThan(0);
            expect(rateLimitedSubmissions.length).toBeGreaterThan(0);
        }, 15000);

        test('Doit appliquer le rate limiting sur les recherches admin', async () => {
            const adminUser = new User({
                username: 'search_rate_admin',
                email: 'searchrate@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'searchrate@admin.com',
                    password: 'adminpass'
                });

            const adminCookies = loginResponse.headers['set-cookie'];

            // Multiples recherches rapides
            const searchAttempts = [];
            for (let i = 0; i < 20; i++) {
                searchAttempts.push(
                    request(app)
                        .get(`/api/admin/search?q=test${i}&month=2024-12`)
                        .set('Cookie', adminCookies)
                );
            }

            const responses = await Promise.all(searchAttempts);
            
            // Vérification du rate limiting
            const successfulSearches = responses.filter(r => r.status === 200);
            const rateLimitedSearches = responses.filter(r => r.status === 429);

            expect(successfulSearches.length).toBeGreaterThan(0);
            // Selon la configuration, certaines recherches devraient être limitées
            console.log(`Recherches réussies: ${successfulSearches.length}, Limitées: ${rateLimitedSearches.length}`);
        });
    });

    describe('Test des Middlewares de Sécurité', () => {
        test('Doit avoir les headers de sécurité appropriés', async () => {
            const response = await request(app)
                .get('/')
                .expect(200);

            // Vérification des headers de sécurité
            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['x-frame-options']).toBe('DENY');
            expect(response.headers['x-xss-protection']).toBe('1; mode=block');
            expect(response.headers['content-security-policy']).toBeDefined();
        });

        test('Doit valider les tailles de requête', async () => {
            const testUser = new User({
                username: 'size_test',
                email: 'size@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'size@test.com',
                    password: 'password'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Tentative de soumission avec contenu trop volumineux
            const largeData = {
                responses: [{
                    question: 'A'.repeat(1000), // Question très longue
                    answer: 'B'.repeat(100000) // Réponse très longue
                }]
            };

            await request(app)
                .post('/api/submissions')
                .set('Cookie', cookies)
                .send(largeData)
                .expect(413); // Payload Too Large
        });

        test('Doit valider les types de fichiers uploadés', async () => {
            const testUser = new User({
                username: 'upload_test',
                email: 'upload@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'upload@test.com',
                    password: 'password'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Tentative d'upload d'un fichier non autorisé
            const maliciousFile = Buffer.from('malicious content');

            await request(app)
                .post('/api/upload')
                .set('Cookie', cookies)
                .attach('image', maliciousFile, 'malicious.exe')
                .expect(400); // Bad Request pour type de fichier non autorisé
        });
    });
});