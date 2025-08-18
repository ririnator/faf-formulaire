/**
 * Tests de performance et stress testing pour migration staging
 * Load testing, stress testing, memory leak detection, database performance
 */

const request = require('supertest');
const mongoose = require('mongoose');
const StagingEnvironment = require('./staging-config');

describe('⚡ Tests de Performance Post-Migration', () => {
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
        
        // Index pour optimiser les performances
        submissionSchema.index({ userId: 1, month: 1 });
        submissionSchema.index({ legacyToken: 1 });
        submissionSchema.index({ createdAt: -1 });
        
        Submission = mongoose.model('Submission', submissionSchema);

        app = require('../../app');
    }, 30000);

    beforeEach(async () => {
        // Nettoyage minimal pour les tests de performance
        await User.deleteMany({});
        await Response.deleteMany({});
        await Submission.deleteMany({});
    });

    afterAll(async () => {
        await stagingEnv.cleanup();
    });

    describe('Load Testing avec Volumes Réalistes', () => {
        test('Doit gérer 100 utilisateurs simultanés', async () => {
            const startTime = Date.now();
            
            // Génération de données de volume
            await stagingEnv.generateVolumeData(200, 100);
            
            const setupTime = Date.now() - startTime;
            console.log(`📊 Setup de 200 soumissions et 100 utilisateurs: ${setupTime}ms`);

            // Test de charge avec utilisateurs simultanés
            const testUser = new User({
                username: 'load_test_user',
                email: 'load@test.com',
                password: await require('bcrypt').hash('password123', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'load@test.com',
                    password: 'password123'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Simulation de 50 requêtes simultanées
            const concurrentRequests = [];
            const requestStartTime = Date.now();

            for (let i = 0; i < 50; i++) {
                concurrentRequests.push(
                    request(app)
                        .get('/api/user/submissions')
                        .set('Cookie', cookies)
                );
            }

            const responses = await Promise.all(concurrentRequests);
            const requestEndTime = Date.now();

            // Validation des performances
            const totalTime = requestEndTime - requestStartTime;
            const avgResponseTime = totalTime / 50;

            console.log(`📈 50 requêtes simultanées en ${totalTime}ms (avg: ${avgResponseTime}ms)`);

            // Critères de performance
            expect(totalTime).toBeLessThan(10000); // Moins de 10 secondes total
            expect(avgResponseTime).toBeLessThan(500); // Moins de 500ms par requête

            // Toutes les requêtes doivent réussir
            responses.forEach(response => {
                expect(response.status).toBe(200);
            });
        }, 30000);

        test('Doit maintenir des performances acceptables avec 1000 soumissions', async () => {
            // Génération de gros volume de données
            const startTime = Date.now();
            await stagingEnv.generateVolumeData(1000, 500);
            const generationTime = Date.now() - startTime;
            
            console.log(`📊 Génération de 1000 soumissions: ${generationTime}ms`);

            // Admin pour tester les requêtes complexes
            const adminUser = new User({
                username: 'perf_admin',
                email: 'perf@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'perf@admin.com',
                    password: 'adminpass'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Test des requêtes gourmandes
            const dashboardStartTime = Date.now();
            const dashboardResponse = await request(app)
                .get('/api/admin/dashboard')
                .set('Cookie', cookies)
                .expect(200);
            const dashboardTime = Date.now() - dashboardStartTime;

            const submissionsStartTime = Date.now();
            const submissionsResponse = await request(app)
                .get('/api/admin/submissions?limit=100')
                .set('Cookie', cookies)
                .expect(200);
            const submissionsTime = Date.now() - submissionsStartTime;

            const searchStartTime = Date.now();
            const searchResponse = await request(app)
                .get('/api/admin/search?q=test&month=2024-12')
                .set('Cookie', cookies)
                .expect(200);
            const searchTime = Date.now() - searchStartTime;

            // Métriques de performance
            console.log(`📊 Dashboard: ${dashboardTime}ms`);
            console.log(`📊 Submissions list: ${submissionsTime}ms`);
            console.log(`📊 Search: ${searchTime}ms`);

            // Critères de performance avec gros volume
            expect(dashboardTime).toBeLessThan(2000); // Dashboard en moins de 2s
            expect(submissionsTime).toBeLessThan(1500); // Liste en moins de 1.5s
            expect(searchTime).toBeLessThan(3000); // Recherche en moins de 3s

            // Validation des données
            expect(dashboardResponse.body.success).toBe(true);
            expect(submissionsResponse.body.submissions.length).toBeGreaterThan(0);
            expect(searchResponse.body.success).toBe(true);
        }, 45000);

        test('Doit optimiser les requêtes de base de données', async () => {
            // Création de données pour test d'optimisation
            const users = [];
            for (let i = 0; i < 20; i++) {
                users.push({
                    username: `opt_user_${i}`,
                    email: `opt${i}@test.com`,
                    password: await require('bcrypt').hash('password', 10),
                    role: 'user'
                });
            }
            const savedUsers = await User.insertMany(users);

            const submissions = [];
            for (let i = 0; i < 100; i++) {
                submissions.push({
                    userId: savedUsers[i % 20]._id,
                    responses: [
                        { question: `Question ${i}`, answer: `Answer ${i}` }
                    ],
                    month: '2024-12',
                    legacyToken: `token_${i}`,
                    createdAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000)
                });
            }
            await Submission.insertMany(submissions);

            // Test des requêtes optimisées
            const queryStartTime = Date.now();

            // Requête avec populate optimisée
            const submissionsWithUsers = await Submission
                .find({ month: '2024-12' })
                .populate('userId', 'username email')
                .limit(50)
                .sort({ createdAt: -1 })
                .lean(); // Utilisation de lean() pour optimiser

            const queryTime = Date.now() - queryStartTime;

            console.log(`📊 Requête optimisée avec populate: ${queryTime}ms`);

            // Validation optimisation
            expect(queryTime).toBeLessThan(200); // Moins de 200ms
            expect(submissionsWithUsers.length).toBeLessThanOrEqual(50);
            expect(submissionsWithUsers[0].userId.username).toBeDefined();

            // Test requête d'agrégation
            const aggregationStartTime = Date.now();

            const stats = await Submission.aggregate([
                { $match: { month: '2024-12' } },
                {
                    $group: {
                        _id: '$month',
                        totalSubmissions: { $sum: 1 },
                        avgResponsesLength: { $avg: { $size: '$responses' } },
                        firstSubmission: { $min: '$createdAt' },
                        lastSubmission: { $max: '$createdAt' }
                    }
                }
            ]);

            const aggregationTime = Date.now() - aggregationStartTime;

            console.log(`📊 Requête d'agrégation: ${aggregationTime}ms`);

            expect(aggregationTime).toBeLessThan(150); // Moins de 150ms
            expect(stats.length).toBe(1);
            expect(stats[0].totalSubmissions).toBe(100);
        });
    });

    describe('Stress Testing des Opérations Critiques', () => {
        test('Doit résister à un pic de connexions simultanées', async () => {
            // Création de multiples utilisateurs pour le stress test
            const users = [];
            for (let i = 0; i < 20; i++) {
                users.push({
                    username: `stress_user_${i}`,
                    email: `stress${i}@test.com`,
                    password: await require('bcrypt').hash('password123', 10),
                    role: 'user'
                });
            }
            await User.insertMany(users);

            // Test de connexions simultanées
            const loginPromises = [];
            const loginStartTime = Date.now();

            for (let i = 0; i < 20; i++) {
                loginPromises.push(
                    request(app)
                        .post('/api/auth/login')
                        .send({
                            email: `stress${i}@test.com`,
                            password: 'password123'
                        })
                );
            }

            const loginResponses = await Promise.all(loginPromises);
            const loginEndTime = Date.now();

            const totalLoginTime = loginEndTime - loginStartTime;
            const avgLoginTime = totalLoginTime / 20;

            console.log(`🔥 20 connexions simultanées: ${totalLoginTime}ms (avg: ${avgLoginTime}ms)`);

            // Validation du stress test
            expect(totalLoginTime).toBeLessThan(15000); // Moins de 15 secondes
            expect(avgLoginTime).toBeLessThan(1000); // Moins de 1 seconde par login

            // Toutes les connexions doivent réussir
            loginResponses.forEach(response => {
                expect(response.status).toBe(200);
                expect(response.body.success).toBe(true);
            });
        }, 30000);

        test('Doit gérer un volume élevé de soumissions simultanées', async () => {
            const testUser = new User({
                username: 'submission_stress',
                email: 'submission@stress.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            // Stress test avec plusieurs utilisateurs soumettant en parallèle
            const stressUsers = [];
            for (let i = 0; i < 15; i++) {
                const user = new User({
                    username: `stress_submit_${i}`,
                    email: `stress_submit${i}@test.com`,
                    password: await require('bcrypt').hash('password', 10),
                    role: 'user'
                });
                stressUsers.push(await user.save());
            }

            // Connexions pour tous les utilisateurs
            const loginPromises = stressUsers.map(user => 
                request(app)
                    .post('/api/auth/login')
                    .send({
                        email: user.email,
                        password: 'password'
                    })
            );

            const loginResponses = await Promise.all(loginPromises);

            // Soumissions simultanées
            const submissionPromises = [];
            const submissionStartTime = Date.now();

            loginResponses.forEach((loginResponse, index) => {
                const cookies = loginResponse.headers['set-cookie'];
                submissionPromises.push(
                    request(app)
                        .post('/api/submissions')
                        .set('Cookie', cookies)
                        .send({
                            responses: [
                                { question: `Stress Question ${index}`, answer: `Stress Answer ${index}` }
                            ]
                        })
                );
            });

            const submissionResponses = await Promise.all(submissionPromises);
            const submissionEndTime = Date.now();

            const totalSubmissionTime = submissionEndTime - submissionStartTime;
            const avgSubmissionTime = totalSubmissionTime / 15;

            console.log(`🔥 15 soumissions simultanées: ${totalSubmissionTime}ms (avg: ${avgSubmissionTime}ms)`);

            // Validation du stress test
            expect(totalSubmissionTime).toBeLessThan(20000); // Moins de 20 secondes
            expect(avgSubmissionTime).toBeLessThan(2000); // Moins de 2 secondes par soumission

            // Toutes les soumissions doivent réussir
            submissionResponses.forEach(response => {
                expect(response.status).toBe(201);
                expect(response.body.success).toBe(true);
            });

            // Vérification en base
            const savedSubmissions = await Submission.find({});
            expect(savedSubmissions.length).toBe(15);
        }, 45000);

        test('Doit maintenir les performances sous charge administrative', async () => {
            // Génération d'un grand volume de données
            await stagingEnv.generateVolumeData(500, 250);

            const adminUser = new User({
                username: 'admin_stress',
                email: 'admin@stress.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'admin@stress.com',
                    password: 'adminpass'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Stress test des opérations admin simultanées
            const adminOperations = [];
            const operationStartTime = Date.now();

            // Multiples requêtes admin simultanées
            for (let i = 0; i < 10; i++) {
                adminOperations.push(
                    request(app)
                        .get('/api/admin/dashboard')
                        .set('Cookie', cookies)
                );
                
                adminOperations.push(
                    request(app)
                        .get('/api/admin/submissions?limit=50')
                        .set('Cookie', cookies)
                );
                
                adminOperations.push(
                    request(app)
                        .get('/api/admin/statistics')
                        .set('Cookie', cookies)
                );
            }

            const operationResponses = await Promise.all(adminOperations);
            const operationEndTime = Date.now();

            const totalOperationTime = operationEndTime - operationStartTime;
            const avgOperationTime = totalOperationTime / 30;

            console.log(`🔥 30 opérations admin simultanées: ${totalOperationTime}ms (avg: ${avgOperationTime}ms)`);

            // Validation performance sous stress administratif
            expect(totalOperationTime).toBeLessThan(25000); // Moins de 25 secondes
            expect(avgOperationTime).toBeLessThan(1000); // Moins de 1 seconde par opération

            // Toutes les opérations doivent réussir
            operationResponses.forEach(response => {
                expect(response.status).toBe(200);
            });
        }, 60000);
    });

    describe('Memory Leak Detection', () => {
        test('Doit détecter les fuites mémoire lors d\'opérations répétées', async () => {
            const getMemoryUsage = () => {
                const usage = process.memoryUsage();
                return {
                    rss: Math.round(usage.rss / 1024 / 1024), // MB
                    heapUsed: Math.round(usage.heapUsed / 1024 / 1024), // MB
                    heapTotal: Math.round(usage.heapTotal / 1024 / 1024), // MB
                    external: Math.round(usage.external / 1024 / 1024) // MB
                };
            };

            const testUser = new User({
                username: 'memory_test',
                email: 'memory@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            const loginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'memory@test.com',
                    password: 'password'
                });

            const cookies = loginResponse.headers['set-cookie'];

            // Mesure initiale
            const initialMemory = getMemoryUsage();
            console.log(`🧠 Mémoire initiale:`, initialMemory);

            // Simulation d'opérations répétées
            for (let i = 0; i < 50; i++) {
                await request(app)
                    .post('/api/submissions')
                    .set('Cookie', cookies)
                    .send({
                        responses: [
                            { question: `Memory test ${i}`, answer: `Answer ${i}` }
                        ]
                    });

                await request(app)
                    .get('/api/user/submissions')
                    .set('Cookie', cookies);

                // Force garbage collection si disponible
                if (global.gc) {
                    global.gc();
                }
            }

            // Mesure finale
            const finalMemory = getMemoryUsage();
            console.log(`🧠 Mémoire finale:`, finalMemory);

            // Calcul de l'augmentation mémoire
            const heapIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
            const rssIncrease = finalMemory.rss - initialMemory.rss;

            console.log(`📈 Augmentation heap: ${heapIncrease}MB`);
            console.log(`📈 Augmentation RSS: ${rssIncrease}MB`);

            // Critères de détection de fuite mémoire
            expect(heapIncrease).toBeLessThan(50); // Moins de 50MB d'augmentation heap
            expect(rssIncrease).toBeLessThan(100); // Moins de 100MB d'augmentation RSS

            // Nettoyage des données créées
            await Submission.deleteMany({ userId: testUser._id });
        }, 30000);

        test('Doit optimiser l\'utilisation mémoire des requêtes de base', async () => {
            // Génération de données pour test mémoire
            await stagingEnv.generateVolumeData(200, 100);

            const getMemoryUsage = () => process.memoryUsage().heapUsed;

            const memoryBefore = getMemoryUsage();

            // Test de requêtes optimisées pour la mémoire
            const submissions = await Submission
                .find({ month: '2024-12' })
                .select('responses month createdAt') // Sélection de champs spécifiques
                .limit(100)
                .lean(); // Utilisation de lean() pour économiser la mémoire

            const memoryAfter = getMemoryUsage();
            const memoryIncrease = (memoryAfter - memoryBefore) / 1024 / 1024; // MB

            console.log(`🧠 Utilisation mémoire pour 100 submissions: ${memoryIncrease.toFixed(2)}MB`);

            // Validation utilisation mémoire raisonnable
            expect(memoryIncrease).toBeLessThan(10); // Moins de 10MB pour 100 submissions
            expect(submissions.length).toBeLessThanOrEqual(100);

            // Test avec stream pour gros volumes
            const memoryStreamBefore = getMemoryUsage();
            
            let streamCount = 0;
            const submissionStream = Submission.find({ month: '2024-12' }).cursor();
            
            for (let doc = await submissionStream.next(); doc != null; doc = await submissionStream.next()) {
                streamCount++;
                // Traitement minimal pour simuler
                const processedData = {
                    id: doc._id,
                    responseCount: doc.responses.length
                };
            }

            const memoryStreamAfter = getMemoryUsage();
            const memoryStreamIncrease = (memoryStreamAfter - memoryStreamBefore) / 1024 / 1024;

            console.log(`🧠 Utilisation mémoire avec stream: ${memoryStreamIncrease.toFixed(2)}MB`);
            console.log(`📊 Documents traités avec stream: ${streamCount}`);

            // Le stream doit utiliser moins de mémoire
            expect(memoryStreamIncrease).toBeLessThan(5); // Moins de 5MB avec stream
        });
    });

    describe('Database Performance Validation', () => {
        test('Doit valider les performances des index de base de données', async () => {
            // Génération de données pour test d'index
            await stagingEnv.generateVolumeData(1000, 500);

            // Test des différents types de requêtes avec explain
            const explainQuery = async (query) => {
                return await query.explain('executionStats');
            };

            // Test index sur userId
            const userIdQuery = Submission.find({ userId: new mongoose.Types.ObjectId() });
            const userIdExplain = await explainQuery(userIdQuery);
            
            console.log(`📊 Index userId - Docs examinés: ${userIdExplain.executionStats.totalDocsExamined}`);
            console.log(`📊 Index userId - Temps: ${userIdExplain.executionStats.executionTimeMillis}ms`);

            // Test index sur legacyToken
            const tokenQuery = Submission.find({ legacyToken: 'test_token' });
            const tokenExplain = await explainQuery(tokenQuery);
            
            console.log(`📊 Index legacyToken - Docs examinés: ${tokenExplain.executionStats.totalDocsExamined}`);
            console.log(`📊 Index legacyToken - Temps: ${tokenExplain.executionStats.executionTimeMillis}ms`);

            // Test tri par date
            const sortQuery = Submission.find().sort({ createdAt: -1 }).limit(10);
            const sortExplain = await explainQuery(sortQuery);
            
            console.log(`📊 Sort createdAt - Docs examinés: ${sortExplain.executionStats.totalDocsExamined}`);
            console.log(`📊 Sort createdAt - Temps: ${sortExplain.executionStats.executionTimeMillis}ms`);

            // Validation des performances d'index
            expect(userIdExplain.executionStats.executionTimeMillis).toBeLessThan(50);
            expect(tokenExplain.executionStats.executionTimeMillis).toBeLessThan(50);
            expect(sortExplain.executionStats.executionTimeMillis).toBeLessThan(100);
        });

        test('Doit optimiser les requêtes d\'agrégation complexes', async () => {
            // Génération de données avec variation temporelle
            const users = [];
            for (let i = 0; i < 50; i++) {
                users.push({
                    username: `agg_user_${i}`,
                    email: `agg${i}@test.com`,
                    password: await require('bcrypt').hash('password', 10),
                    role: i % 10 === 0 ? 'admin' : 'user'
                });
            }
            const savedUsers = await User.insertMany(users);

            const submissions = [];
            for (let i = 0; i < 200; i++) {
                const baseDate = new Date('2024-12-01');
                const randomDays = Math.floor(Math.random() * 30);
                submissions.push({
                    userId: savedUsers[i % 50]._id,
                    responses: Array.from({ length: Math.floor(Math.random() * 5) + 1 }, (_, j) => ({
                        question: `Question ${j + 1}`,
                        answer: `Answer ${j + 1} for submission ${i}`
                    })),
                    month: '2024-12',
                    legacyToken: Math.random() > 0.5 ? `token_${i}` : null,
                    createdAt: new Date(baseDate.getTime() + randomDays * 24 * 60 * 60 * 1000)
                });
            }
            await Submission.insertMany(submissions);

            // Test d'agrégation complexe avec mesure de performance
            const aggregationStartTime = Date.now();

            const complexStats = await Submission.aggregate([
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
                        _id: {
                            month: '$month',
                            userRole: '$user.role'
                        },
                        totalSubmissions: { $sum: 1 },
                        avgResponseCount: { $avg: { $size: '$responses' } },
                        submissionsWithToken: {
                            $sum: { $cond: [{ $ne: ['$legacyToken', null] }, 1, 0] }
                        },
                        firstSubmission: { $min: '$createdAt' },
                        lastSubmission: { $max: '$createdAt' }
                    }
                },
                {
                    $sort: { '_id.userRole': 1 }
                }
            ]);

            const aggregationTime = Date.now() - aggregationStartTime;

            console.log(`📊 Agrégation complexe: ${aggregationTime}ms`);
            console.log(`📊 Résultats d'agrégation:`, complexStats);

            // Validation performance agrégation
            expect(aggregationTime).toBeLessThan(1000); // Moins de 1 seconde
            expect(complexStats.length).toBeGreaterThan(0);
            expect(complexStats[0].totalSubmissions).toBeDefined();
        });
    });

    describe('Response Time Benchmarking', () => {
        test('Doit mesurer les temps de réponse des endpoints critiques', async () => {
            // Préparation des données de test
            await stagingEnv.generateVolumeData(100, 50);

            const testUser = new User({
                username: 'benchmark_user',
                email: 'benchmark@test.com',
                password: await require('bcrypt').hash('password', 10),
                role: 'user'
            });
            await testUser.save();

            const adminUser = new User({
                username: 'benchmark_admin',
                email: 'benchmark@admin.com',
                password: await require('bcrypt').hash('adminpass', 10),
                role: 'admin'
            });
            await adminUser.save();

            // Connexions
            const userLoginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'benchmark@test.com',
                    password: 'password'
                });

            const adminLoginResponse = await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'benchmark@admin.com',
                    password: 'adminpass'
                });

            const userCookies = userLoginResponse.headers['set-cookie'];
            const adminCookies = adminLoginResponse.headers['set-cookie'];

            // Benchmark des endpoints
            const benchmarks = {};

            // 1. Login benchmark
            const loginStartTime = Date.now();
            await request(app)
                .post('/api/auth/login')
                .send({
                    email: 'benchmark@test.com',
                    password: 'password'
                });
            benchmarks.login = Date.now() - loginStartTime;

            // 2. User profile benchmark
            const profileStartTime = Date.now();
            await request(app)
                .get('/api/user/profile')
                .set('Cookie', userCookies);
            benchmarks.userProfile = Date.now() - profileStartTime;

            // 3. Submission creation benchmark
            const submissionStartTime = Date.now();
            await request(app)
                .post('/api/submissions')
                .set('Cookie', userCookies)
                .send({
                    responses: [
                        { question: 'Benchmark question', answer: 'Benchmark answer' }
                    ]
                });
            benchmarks.createSubmission = Date.now() - submissionStartTime;

            // 4. Admin dashboard benchmark
            const dashboardStartTime = Date.now();
            await request(app)
                .get('/api/admin/dashboard')
                .set('Cookie', adminCookies);
            benchmarks.adminDashboard = Date.now() - dashboardStartTime;

            // 5. Admin submissions list benchmark
            const adminListStartTime = Date.now();
            await request(app)
                .get('/api/admin/submissions?limit=50')
                .set('Cookie', adminCookies);
            benchmarks.adminSubmissionsList = Date.now() - adminListStartTime;

            // 6. Search benchmark
            const searchStartTime = Date.now();
            await request(app)
                .get('/api/admin/search?q=test')
                .set('Cookie', adminCookies);
            benchmarks.search = Date.now() - searchStartTime;

            // Affichage des résultats
            console.log('📊 Benchmarks des temps de réponse:');
            Object.entries(benchmarks).forEach(([endpoint, time]) => {
                console.log(`   ${endpoint}: ${time}ms`);
            });

            // Validation des seuils de performance
            expect(benchmarks.login).toBeLessThan(300);
            expect(benchmarks.userProfile).toBeLessThan(100);
            expect(benchmarks.createSubmission).toBeLessThan(200);
            expect(benchmarks.adminDashboard).toBeLessThan(500);
            expect(benchmarks.adminSubmissionsList).toBeLessThan(300);
            expect(benchmarks.search).toBeLessThan(1000);

            // Calcul de la moyenne
            const avgResponseTime = Object.values(benchmarks).reduce((a, b) => a + b, 0) / Object.keys(benchmarks).length;
            console.log(`📊 Temps de réponse moyen: ${avgResponseTime.toFixed(2)}ms`);

            expect(avgResponseTime).toBeLessThan(400); // Moyenne sous 400ms
        });
    });
});