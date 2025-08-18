/**
 * Tests des fonctionnalités complètes après migration staging
 * Validation workflows authentification, APIs, compatibilité URLs, dashboards
 */

const request = require('supertest');
const mongoose = require('mongoose');
const StagingEnvironment = require('./staging-config');

describe('🚀 Tests des Fonctionnalités Post-Migration', () => {
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

        // Initialisation de l'application Express pour les tests
        app = require('../../app');
    });

    beforeEach(async () => {
        // Nettoyage des collections
        await User.deleteMany({});
        await Response.deleteMany({});
        await Submission.deleteMany({});
    });

    afterAll(async () => {
        await stagingEnv.cleanup();
    });

    describe('Workflow d\'Authentification Complet', () => {
        test('Doit permettre l\'inscription d\'un nouvel utilisateur', async () => {
            const userData = {
                username: 'nouveau_user',
                email: 'nouveau@test.com',
                password: 'motdepasse123',
                firstName: 'Nouveau',
                lastName: 'User'
            };

            const response = await request(app)
                .post('/api/auth/register')
                .send(userData)
                .expect(201);

            expect(response.body.success).toBe(true);
            expect(response.body.user.username).toBe('nouveau_user');
            expect(response.body.user.email).toBe('nouveau@test.com');
            expect(response.body.user.role).toBe('user');

            // Vérification en base
            const savedUser = await User.findOne({ username: 'nouveau_user' });
            expect(savedUser).toBeTruthy();
            expect(savedUser.profile.firstName).toBe('Nouveau');
        });

        test('Doit permettre la connexion avec les nouvelles credentials', async () => {
            // Création d'un utilisateur de test
            const testUser = new User({
                username: 'test_login',
                email: 'test@login.com',
                password: await require('bcrypt').hash('password123', 10),
                role: 'user'
            });
            await testUser.save();

            const loginData = {
                email: 'test@login.com',
                password: 'password123'
            };

            const response = await request(app)
                .post('/api/auth/login')
                .send(loginData)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.user.username).toBe('test_login');
            expect(response.headers['set-cookie']).toBeDefined();
        });

        test('Doit supporter l\'authentification admin legacy', async () => {
            // Test de l'authentification admin via l'ancien système
            const adminData = {
                username: process.env.LOGIN_ADMIN_USER,
                password: process.env.LOGIN_ADMIN_PASS
            };

            const response = await request(app)
                .post('/admin-login')
                .send(adminData)
                .expect(302); // Redirection après succès

            expect(response.headers.location).toMatch(/\/admin/);
        });

        test('Doit gérer l\'authentification hybride (legacy + nouveau système)', async () => {
            // Création d'un admin dans le nouveau système
            const adminUser = new User({
                username: 'admin_hybrid',
                email: 'admin@hybrid.com',
                password: await require('bcrypt').hash('adminpass123', 10),
                role: 'admin'
            });
            await adminUser.save();

            // Test authentification via nouveau système
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'admin@hybrid.com',
                    password: 'adminpass123'
                })
                .expect(200);

            expect(loginResponse.body.user.role).toBe('admin');

            // Test accès aux routes admin avec le nouveau système
            const cookies = loginResponse.headers['set-cookie'];
            
            const adminResponse = await request(app)
                .get('/api/admin/dashboard')
                .set('Cookie', cookies)
                .expect(200);

            expect(adminResponse.body.success).toBe(true);
        });

        test('Doit maintenir les sessions entre les requêtes', async () => {
            // Connexion utilisateur
            const testUser = new User({
                username: 'session_test',
                email: 'session@test.com',
                password: await require('bcrypt').hash('password123', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'session@test.com',
                    password: 'password123'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test de maintien de session
            const profileResponse = await request(app)
                .get('/api/user/profile')
                .set('Cookie', cookies)
                .expect(200);

            expect(profileResponse.body.user.username).toBe('session_test');

            // Test déconnexion
            await request(app)
                .post('/api/auth/logout')
                .set('Cookie', cookies)
                .expect(200);

            // Vérification que la session est invalidée
            await request(app)
                .get('/api/user/profile')
                .set('Cookie', cookies)
                .expect(401);
        });
    });

    describe('Validation des APIs Après Migration', () => {
        test('API de soumission doit fonctionner avec le nouveau système', async () => {
            const testUser = new User({
                username: 'submission_user',
                email: 'submission@test.com',
                password: await require('bcrypt').hash('password123', 10),
                role: 'user'
            });
            await testUser.save();

            // Connexion
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'submission@test.com',
                    password: 'password123'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Soumission de réponses
            const submissionData = {
                responses: [
                    { question: 'Quelle est votre couleur préférée ?', answer: 'Bleu océan' },
                    { question: 'Quel est votre plat favori ?', answer: 'Ratatouille' }
                ]
            };

            const submissionResponse = await request(app)
                .post('/api/submissions')
                .set('Cookie', cookies)
                .send(submissionData)
                .expect(201);

            expect(submissionResponse.body.success).toBe(true);
            expect(submissionResponse.body.submission.responses).toHaveLength(2);

            // Vérification en base
            const savedSubmission = await Submission.findOne({ userId: testUser._id });
            expect(savedSubmission).toBeTruthy();
            expect(savedSubmission.responses[0].answer).toBe('Bleu océan');
        });

        test('API de consultation doit supporter les tokens legacy', async () => {
            const testUser = new User({
                username: 'legacy_user',
                email: 'legacy@test.com',
                password: await require('bcrypt').hash('password123', 10),
                role: 'user'
            });
            await testUser.save();

            // Création d'une soumission avec token legacy
            const legacyToken = 'legacy_token_' + Date.now();
            const submission = new Submission({
                userId: testUser._id,
                responses: [
                    { question: 'Question legacy', answer: 'Réponse legacy' }
                ],
                month: '2024-12',
                legacyToken
            });
            await submission.save();

            // Test d'accès via token legacy
            const viewResponse = await request(app)
                .get(`/api/view/${legacyToken}`)
                .expect(200);

            expect(viewResponse.body.success).toBe(true);
            expect(viewResponse.body.submission.responses[0].answer).toBe('Réponse legacy');
        });

        test('API admin doit fonctionner avec l\'authentification hybride', async () => {
            const adminUser = new User({
                username: 'api_admin',
                email: 'api@admin.com',
                password: await require('bcrypt').hash('adminpass123', 10),
                role: 'admin'
            });
            await adminUser.save();

            // Connexion admin
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'api@admin.com',
                    password: 'adminpass123'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test des différentes APIs admin
            
            // 1. Dashboard
            const dashboardResponse = await request(app)
                .get('/api/admin/dashboard')
                .set('Cookie', cookies)
                .expect(200);

            expect(dashboardResponse.body.success).toBe(true);

            // 2. Liste des soumissions
            const submissionsResponse = await request(app)
                .get('/api/admin/submissions')
                .set('Cookie', cookies)
                .expect(200);

            expect(submissionsResponse.body.success).toBe(true);
            expect(Array.isArray(submissionsResponse.body.submissions)).toBe(true);

            // 3. Statistiques
            const statsResponse = await request(app)
                .get('/api/admin/statistics')
                .set('Cookie', cookies)
                .expect(200);

            expect(statsResponse.body.success).toBe(true);
        });

        test('API de recherche doit fonctionner avec les nouvelles données', async () => {
            // Création de données de test
            const users = await User.insertMany([
                {
                    username: 'search_user1',
                    email: 'search1@test.com',
                    password: await require('bcrypt').hash('password123', 10),
                    role: 'user'
                },
                {
                    username: 'search_user2',
                    email: 'search2@test.com',
                    password: await require('bcrypt').hash('password123', 10),
                    role: 'user'
                }
            ]);

            await Submission.insertMany([
                {
                    userId: users[0]._id,
                    responses: [{ question: 'Test', answer: 'Recherche test 1' }],
                    month: '2024-12'
                },
                {
                    userId: users[1]._id,
                    responses: [{ question: 'Test', answer: 'Recherche test 2' }],
                    month: '2024-12'
                }
            ]);

            // Admin pour faire la recherche
            const adminUser = new User({
                username: 'search_admin',
                email: 'search@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'search@admin.com',
                    password: 'adminpass'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test de recherche
            const searchResponse = await request(app)
                .get('/api/admin/search?q=recherche&month=2024-12')
                .set('Cookie', cookies)
                .expect(200);

            expect(searchResponse.body.success).toBe(true);
            expect(searchResponse.body.results.length).toBeGreaterThanOrEqual(1);
        });
    });

    describe('Test de Compatibilité avec URLs Existantes', () => {
        test('URLs legacy doivent rediriger correctement', async () => {
            // Test redirection ancienne page login
            const loginRedirect = await request(app)
                .get('/login.html')
                .expect(301);

            expect(loginRedirect.headers.location).toMatch(/\/login/);

            // Test redirection ancien dashboard admin
            const adminRedirect = await request(app)
                .get('/admin.html')
                .expect(301);

            expect(adminRedirect.headers.location).toMatch(/\/admin/);
        });

        test('Tokens de visualisation legacy doivent fonctionner', async () => {
            // Création d'une réponse legacy avec token
            const legacyResponse = new Response({
                name: 'Legacy User',
                responses: [{ question: 'Question legacy', answer: 'Réponse legacy' }],
                month: '2024-12',
                isAdmin: false,
                token: 'legacy_view_token_123',
                createdAt: new Date()
            });
            await legacyResponse.save();

            // Test d'accès via l'ancienne URL
            const viewResponse = await request(app)
                .get('/view/legacy_view_token_123')
                .expect(200);

            expect(viewResponse.text).toContain('Legacy User');
            expect(viewResponse.text).toContain('Réponse legacy');
        });

        test('API endpoints legacy doivent être maintenus', async () => {
            // Test ancien endpoint de soumission
            const legacySubmissionData = {
                name: 'Legacy Submission User',
                responses: [
                    { question: 'Question 1', answer: 'Réponse 1' },
                    { question: 'Question 2', answer: 'Réponse 2' }
                ]
            };

            const submissionResponse = await request(app)
                .post('/submit-response')
                .send(legacySubmissionData)
                .expect(200);

            expect(submissionResponse.body.success).toBe(true);
            expect(submissionResponse.body.token).toBeDefined();

            // Vérification que la soumission a été créée
            const savedResponse = await Response.findOne({ name: 'Legacy Submission User' });
            expect(savedResponse).toBeTruthy();
        });

        test('Ancien système d\'upload d\'images doit fonctionner', async () => {
            // Test upload via l'ancien endpoint
            const uploadResponse = await request(app)
                .post('/upload')
                .attach('image', Buffer.from('fake image data'), 'test.jpg')
                .expect(200);

            expect(uploadResponse.body.success).toBe(true);
            expect(uploadResponse.body.imageUrl).toBeDefined();
        });
    });

    describe('Vérification des Dashboards et Interfaces', () => {
        test('Dashboard admin doit afficher les données migrées', async () => {
            // Création de données mixtes (legacy + nouveau)
            const adminUser = new User({
                username: 'dashboard_admin',
                email: 'dashboard@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            // Données legacy
            await Response.create({
                name: 'Legacy Dashboard User',
                responses: [{ question: 'Legacy Q', answer: 'Legacy A' }],
                month: '2024-12',
                isAdmin: false,
                token: 'legacy_dashboard_token',
                createdAt: new Date()
            });

            // Données nouveau système
            const newUser = new User({
                username: 'new_dashboard_user',
                email: 'new@dashboard.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await newUser.save();

            await Submission.create({
                userId: newUser._id,
                responses: [{ question: 'New Q', answer: 'New A' }],
                month: '2024-12',
                createdAt: new Date()
            });

            // Connexion admin
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'dashboard@admin.com',
                    password: 'adminpass'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test dashboard
            const dashboardResponse = await request(app)
                .get('/api/admin/dashboard-data')
                .set('Cookie', cookies)
                .expect(200);

            expect(dashboardResponse.body.success).toBe(true);
            expect(dashboardResponse.body.totalSubmissions).toBeGreaterThanOrEqual(2);
            expect(dashboardResponse.body.totalUsers).toBeGreaterThanOrEqual(1);

            // Test données détaillées
            const detailsResponse = await request(app)
                .get('/api/admin/submissions?month=2024-12')
                .set('Cookie', cookies)
                .expect(200);

            expect(detailsResponse.body.submissions.length).toBeGreaterThanOrEqual(2);
        });

        test('Interface utilisateur doit supporter les deux types de données', async () => {
            const testUser = new User({
                username: 'interface_user',
                email: 'interface@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            // Connexion
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'interface@test.com',
                    password: 'password'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test accès à l'interface principale
            const mainPageResponse = await request(app)
                .get('/')
                .set('Cookie', cookies)
                .expect(200);

            expect(mainPageResponse.text).toContain('Form-a-Friend');

            // Test accès au profil utilisateur
            const profileResponse = await request(app)
                .get('/api/user/profile')
                .set('Cookie', cookies)
                .expect(200);

            expect(profileResponse.body.user.username).toBe('interface_user');
        });

        test('Graphiques et statistiques doivent inclure toutes les données', async () => {
            // Création d'un admin
            const adminUser = new User({
                username: 'stats_admin',
                email: 'stats@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            // Données pour statistiques
            await Response.insertMany([
                {
                    name: 'Stats User 1',
                    responses: [{ question: 'Q1', answer: 'A1' }],
                    month: '2024-12',
                    isAdmin: false,
                    token: 'stats_token_1',
                    createdAt: new Date('2024-12-01')
                },
                {
                    name: 'Stats User 2',
                    responses: [{ question: 'Q1', answer: 'A2' }],
                    month: '2024-12',
                    isAdmin: false,
                    token: 'stats_token_2',
                    createdAt: new Date('2024-12-02')
                }
            ]);

            const statsUsers = await User.insertMany([
                {
                    username: 'stats_user_3',
                    email: 'stats3@test.com',
                    password: await require('bcrypt').hash('password', 10),
                    role: 'user'
                },
                {
                    username: 'stats_user_4',
                    email: 'stats4@test.com',
                    password: await require('bcrypt').hash('password', 10),
                    role: 'user'
                }
            ]);

            await Submission.insertMany([
                {
                    userId: statsUsers[0]._id,
                    responses: [{ question: 'Q1', answer: 'A3' }],
                    month: '2024-12',
                    createdAt: new Date('2024-12-03')
                },
                {
                    userId: statsUsers[1]._id,
                    responses: [{ question: 'Q1', answer: 'A4' }],
                    month: '2024-12',
                    createdAt: new Date('2024-12-04')
                }
            ]);

            // Connexion admin
            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'stats@admin.com',
                    password: 'adminpass'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test API statistiques
            const statsResponse = await request(app)
                .get('/api/admin/statistics?month=2024-12')
                .set('Cookie', cookies)
                .expect(200);

            expect(statsResponse.body.success).toBe(true);
            expect(statsResponse.body.totalResponses).toBe(4); // 2 legacy + 2 nouveau
            expect(statsResponse.body.responsesByDay).toBeDefined();
            
            // Test données pour graphiques
            const chartsResponse = await request(app)
                .get('/api/admin/charts-data?month=2024-12')
                .set('Cookie', cookies)
                .expect(200);

            expect(chartsResponse.body.success).toBe(true);
            expect(chartsResponse.body.questionsData).toBeDefined();
        });
    });

    describe('Tests des Fonctionnalités Admin et User', () => {
        test('Fonctionnalités admin complètes après migration', async () => {
            const adminUser = new User({
                username: 'full_admin',
                email: 'full@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'full@admin.com',
                    password: 'adminpass'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // 1. Création de soumission admin
            const adminSubmissionResponse = await request(app)
                .post('/api/admin/submissions')
                .set('Cookie', cookies)
                .send({
                    responses: [
                        { question: 'Question admin', answer: 'Réponse admin' }
                    ]
                })
                .expect(201);

            expect(adminSubmissionResponse.body.success).toBe(true);

            // 2. Modification de soumission
            const submissionId = adminSubmissionResponse.body.submission._id;
            const updateResponse = await request(app)
                .put(`/api/admin/submissions/${submissionId}`)
                .set('Cookie', cookies)
                .send({
                    responses: [
                        { question: 'Question admin modifiée', answer: 'Réponse admin modifiée' }
                    ]
                })
                .expect(200);

            expect(updateResponse.body.success).toBe(true);

            // 3. Suppression de soumission
            const deleteResponse = await request(app)
                .delete(`/api/admin/submissions/${submissionId}`)
                .set('Cookie', cookies)
                .expect(200);

            expect(deleteResponse.body.success).toBe(true);

            // 4. Gestion des utilisateurs
            const usersResponse = await request(app)
                .get('/api/admin/users')
                .set('Cookie', cookies)
                .expect(200);

            expect(usersResponse.body.success).toBe(true);
            expect(Array.isArray(usersResponse.body.users)).toBe(true);
        });

        test('Fonctionnalités utilisateur complètes après migration', async () => {
            const testUser = new User({
                username: 'full_user',
                email: 'full@user.com',
                password: await require('bcrypt').hash('userpass', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'full@user.com',
                    password: 'userpass'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // 1. Consultation du profil
            const profileResponse = await request(app)
                .get('/api/user/profile')
                .set('Cookie', cookies)
                .expect(200);

            expect(profileResponse.body.user.username).toBe('full_user');

            // 2. Modification du profil
            const updateProfileResponse = await request(app)
                .put('/api/user/profile')
                .set('Cookie', cookies)
                .send({
                    profile: {
                        firstName: 'Updated',
                        lastName: 'User'
                    }
                })
                .expect(200);

            expect(updateProfileResponse.body.success).toBe(true);

            // 3. Soumission de réponses
            const submissionResponse = await request(app)
                .post('/api/submissions')
                .set('Cookie', cookies)
                .send({
                    responses: [
                        { question: 'Question utilisateur', answer: 'Réponse utilisateur' }
                    ]
                })
                .expect(201);

            expect(submissionResponse.body.success).toBe(true);

            // 4. Consultation de ses propres soumissions
            const userSubmissionsResponse = await request(app)
                .get('/api/user/submissions')
                .set('Cookie', cookies)
                .expect(200);

            expect(userSubmissionsResponse.body.success).toBe(true);
            expect(userSubmissionsResponse.body.submissions.length).toBeGreaterThanOrEqual(1);
        });
    });
});