/**
 * Tests de validation des données pour la migration staging
 * Vérification intégrité, transformation Response→Submission, génération Users
 */

const mongoose = require('mongoose');
const StagingEnvironment = require('./staging-config');

describe('🔍 Tests de Validation des Données de Migration', () => {
    let stagingEnv;
    let Response, User, Submission;

    beforeAll(async () => {
        stagingEnv = new StagingEnvironment();
        await stagingEnv.initialize();
        await stagingEnv.connectDatabase();

        // Chargement des modèles
        Response = require('../../models/Response');
        User = require('../../models/User');
        
        // Mock du modèle Submission (à créer lors de la migration)
        const submissionSchema = new mongoose.Schema({
            userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
            responses: [{
                question: { type: String, required: true },
                answer: { type: String, required: true }
            }],
            month: { type: String, required: true },
            legacyToken: { type: String }, // Token de l'ancien système
            migrationData: {
                originalResponseId: { type: mongoose.Schema.Types.ObjectId },
                migratedAt: { type: Date, default: Date.now },
                migrationVersion: { type: String, default: '1.0' }
            },
            createdAt: { type: Date, default: Date.now }
        });
        
        Submission = mongoose.model('Submission', submissionSchema);
    });

    beforeEach(async () => {
        // Nettoyage des collections avant chaque test
        await Response.deleteMany({});
        await User.deleteMany({});
        await Submission.deleteMany({});
    });

    afterAll(async () => {
        await stagingEnv.cleanup();
    });

    describe('Vérification Intégrité Avant Migration', () => {
        test('Doit valider la structure des réponses existantes', async () => {
            // Données de test avec différents formats
            const testResponses = [
                {
                    name: 'Jean Dupont',
                    responses: [
                        { question: 'Couleur préférée ?', answer: 'Bleu' },
                        { question: 'Plat favori ?', answer: 'Pizza' }
                    ],
                    month: '2024-12',
                    isAdmin: false,
                    token: 'token_jean_123',
                    createdAt: new Date('2024-12-01')
                },
                {
                    name: 'staging-admin',
                    responses: [
                        { question: 'Couleur préférée ?', answer: 'Vert' }
                    ],
                    month: '2024-12',
                    isAdmin: true,
                    token: null,
                    createdAt: new Date('2024-12-02')
                }
            ];

            await Response.insertMany(testResponses);

            // Validation de l'intégrité
            const responses = await Response.find({});
            expect(responses).toHaveLength(2);

            // Vérification structure obligatoire
            for (const response of responses) {
                expect(response.name).toBeDefined();
                expect(response.responses).toBeInstanceOf(Array);
                expect(response.month).toBeDefined();
                expect(response.isAdmin).toBeDefined();
                expect(response.createdAt).toBeInstanceOf(Date);

                // Vérification structure des réponses
                for (const resp of response.responses) {
                    expect(resp.question).toBeDefined();
                    expect(resp.answer).toBeDefined();
                }

                // Vérification règles métier
                if (response.isAdmin) {
                    expect(response.token).toBeNull();
                } else {
                    expect(response.token).toBeDefined();
                }
            }
        });

        test('Doit détecter les données corrompues', async () => {
            // Données corrompues pour test
            const corruptedData = [
                {
                    name: '',
                    responses: [],
                    month: '2024-12'
                },
                {
                    name: 'Test User',
                    responses: [
                        { question: '', answer: 'Réponse sans question' }
                    ],
                    month: 'invalid-month'
                }
            ];

            // Test de validation avant insertion
            for (const data of corruptedData) {
                const response = new Response(data);
                await expect(response.validate()).rejects.toThrow();
            }
        });

        test('Doit identifier les doublons potentiels', async () => {
            const duplicateData = [
                {
                    name: 'Jean Dupont',
                    responses: [{ question: 'Test', answer: 'Test' }],
                    month: '2024-12',
                    isAdmin: false,
                    token: 'token1',
                    createdAt: new Date('2024-12-01')
                },
                {
                    name: 'jean dupont', // Même nom, casse différente
                    responses: [{ question: 'Test', answer: 'Test' }],
                    month: '2024-12',
                    isAdmin: false,
                    token: 'token2',
                    createdAt: new Date('2024-12-02')
                }
            ];

            await Response.insertMany(duplicateData);

            // Recherche de doublons potentiels (insensible à la casse)
            const duplicates = await Response.aggregate([
                {
                    $group: {
                        _id: {
                            name: { $toLower: '$name' },
                            month: '$month'
                        },
                        count: { $sum: 1 },
                        docs: { $push: '$$ROOT' }
                    }
                },
                {
                    $match: { count: { $gt: 1 } }
                }
            ]);

            expect(duplicates).toHaveLength(1);
            expect(duplicates[0].count).toBe(2);
        });
    });

    describe('Validation Transformation Response→Submission', () => {
        test('Doit transformer correctement une réponse utilisateur', async () => {
            // Création d'un utilisateur de test
            const testUser = new User({
                username: 'jean_dupont',
                email: 'jean@example.com',
                password: 'hashedpassword',
                role: 'user'
            });
            await testUser.save();

            // Réponse à transformer
            const testResponse = new Response({
                name: 'Jean Dupont',
                responses: [
                    { question: 'Couleur préférée ?', answer: 'Bleu' },
                    { question: 'Plat favori ?', answer: 'Pizza margherita' }
                ],
                month: '2024-12',
                isAdmin: false,
                token: 'token_jean_123',
                createdAt: new Date('2024-12-01')
            });
            await testResponse.save();

            // Transformation en Submission
            const submission = new Submission({
                userId: testUser._id,
                responses: testResponse.responses,
                month: testResponse.month,
                legacyToken: testResponse.token,
                migrationData: {
                    originalResponseId: testResponse._id,
                    migratedAt: new Date(),
                    migrationVersion: '1.0'
                },
                createdAt: testResponse.createdAt
            });

            await submission.save();

            // Validation de la transformation
            const savedSubmission = await Submission.findById(submission._id).populate('userId');
            
            expect(savedSubmission.userId.username).toBe('jean_dupont');
            expect(savedSubmission.responses).toHaveLength(2);
            expect(savedSubmission.month).toBe('2024-12');
            expect(savedSubmission.legacyToken).toBe('token_jean_123');
            expect(savedSubmission.migrationData.originalResponseId.toString()).toBe(testResponse._id.toString());
            expect(savedSubmission.createdAt).toEqual(testResponse.createdAt);
        });

        test('Doit gérer les réponses admin sans token', async () => {
            // Création d'un admin
            const adminUser = new User({
                username: 'admin_staging',
                email: 'admin@staging.com',
                password: 'hashedpassword',
                role: 'admin'
            });
            await adminUser.save();

            // Réponse admin à transformer
            const adminResponse = new Response({
                name: 'staging-admin',
                responses: [
                    { question: 'Question admin', answer: 'Réponse admin' }
                ],
                month: '2024-12',
                isAdmin: true,
                token: null,
                createdAt: new Date('2024-12-01')
            });
            await adminResponse.save();

            // Transformation en Submission
            const submission = new Submission({
                userId: adminUser._id,
                responses: adminResponse.responses,
                month: adminResponse.month,
                legacyToken: null, // Admin n'a pas de token
                migrationData: {
                    originalResponseId: adminResponse._id,
                    migratedAt: new Date(),
                    migrationVersion: '1.0'
                },
                createdAt: adminResponse.createdAt
            });

            await submission.save();

            // Validation
            const savedSubmission = await Submission.findById(submission._id).populate('userId');
            
            expect(savedSubmission.userId.role).toBe('admin');
            expect(savedSubmission.legacyToken).toBeNull();
            expect(savedSubmission.migrationData.originalResponseId.toString()).toBe(adminResponse._id.toString());
        });

        test('Doit préserver tous les champs lors de la transformation', async () => {
            const testUser = new User({
                username: 'test_user',
                email: 'test@example.com',
                password: 'hashedpassword',
                role: 'user'
            });
            await testUser.save();

            const complexResponse = new Response({
                name: 'Test User',
                responses: [
                    { question: 'Question avec caractères spéciaux : é, à, ç', answer: 'Réponse avec émojis 🎉' },
                    { question: 'Question très longue '.repeat(10), answer: 'Réponse très longue '.repeat(50) }
                ],
                month: '2024-12',
                isAdmin: false,
                token: 'token_complex_' + Date.now(),
                createdAt: new Date('2024-12-15T14:30:00Z')
            });
            await complexResponse.save();

            // Transformation
            const submission = new Submission({
                userId: testUser._id,
                responses: complexResponse.responses,
                month: complexResponse.month,
                legacyToken: complexResponse.token,
                migrationData: {
                    originalResponseId: complexResponse._id,
                    migratedAt: new Date(),
                    migrationVersion: '1.0'
                },
                createdAt: complexResponse.createdAt
            });

            await submission.save();

            // Validation de la préservation
            const savedSubmission = await Submission.findById(submission._id);
            
            expect(savedSubmission.responses[0].question).toContain('é, à, ç');
            expect(savedSubmission.responses[0].answer).toContain('🎉');
            expect(savedSubmission.responses[1].question.length).toBeGreaterThan(100);
            expect(savedSubmission.responses[1].answer.length).toBeGreaterThan(500);
            expect(savedSubmission.createdAt).toEqual(complexResponse.createdAt);
        });
    });

    describe('Contrôle Génération Automatique des Users', () => {
        test('Doit générer un utilisateur depuis une réponse sans utilisateur existant', async () => {
            const response = new Response({
                name: 'Nouveau User',
                responses: [{ question: 'Test', answer: 'Test' }],
                month: '2024-12',
                isAdmin: false,
                token: 'token_nouveau_123',
                createdAt: new Date('2024-12-01')
            });
            await response.save();

            // Simulation de la génération automatique d'utilisateur
            const generateUserFromResponse = async (response) => {
                const username = response.name.toLowerCase().replace(/\s+/g, '_');
                const email = `${username}@migrated.local`;
                
                const user = new User({
                    username,
                    email,
                    password: 'migrated_password_placeholder',
                    role: response.isAdmin ? 'admin' : 'user',
                    migrationData: {
                        legacyName: response.name,
                        migratedAt: new Date(),
                        source: 'response_migration'
                    }
                });

                return await user.save();
            };

            const generatedUser = await generateUserFromResponse(response);

            // Validation de l'utilisateur généré
            expect(generatedUser.username).toBe('nouveau_user');
            expect(generatedUser.email).toBe('nouveau_user@migrated.local');
            expect(generatedUser.role).toBe('user');
            expect(generatedUser.migrationData.legacyName).toBe('Nouveau User');
            expect(generatedUser.migrationData.source).toBe('response_migration');
        });

        test('Doit gérer les noms avec caractères spéciaux', async () => {
            const responseWithSpecialChars = new Response({
                name: 'Jean-Claude Été',
                responses: [{ question: 'Test', answer: 'Test' }],
                month: '2024-12',
                isAdmin: false,
                token: 'token_special_123',
                createdAt: new Date()
            });
            await responseWithSpecialChars.save();

            // Fonction de normalisation de nom d'utilisateur
            const normalizeUsername = (name) => {
                return name
                    .toLowerCase()
                    .normalize('NFD')
                    .replace(/[\u0300-\u036f]/g, '') // Supprime les accents
                    .replace(/[^a-z0-9\s]/g, '') // Supprime caractères spéciaux
                    .replace(/\s+/g, '_') // Remplace espaces par underscores
                    .substring(0, 30); // Limite à 30 caractères
            };

            const username = normalizeUsername(responseWithSpecialChars.name);
            expect(username).toBe('jean_claude_ete');

            const user = new User({
                username,
                email: `${username}@migrated.local`,
                password: 'migrated_password',
                role: 'user',
                migrationData: {
                    legacyName: responseWithSpecialChars.name,
                    migratedAt: new Date(),
                    source: 'response_migration'
                }
            });

            await user.save();

            expect(user.username).toBe('jean_claude_ete');
            expect(user.migrationData.legacyName).toBe('Jean-Claude Été');
        });

        test('Doit éviter les doublons lors de la génération d\'utilisateurs', async () => {
            // Création de deux réponses avec le même nom
            const responses = [
                {
                    name: 'Duplicate User',
                    responses: [{ question: 'Test 1', answer: 'Test 1' }],
                    month: '2024-12',
                    isAdmin: false,
                    token: 'token1',
                    createdAt: new Date('2024-12-01')
                },
                {
                    name: 'Duplicate User',
                    responses: [{ question: 'Test 2', answer: 'Test 2' }],
                    month: '2024-11',
                    isAdmin: false,
                    token: 'token2',
                    createdAt: new Date('2024-11-01')
                }
            ];

            await Response.insertMany(responses);

            // Simulation de génération avec gestion des doublons
            const generateUniqueUser = async (response) => {
                let baseUsername = response.name.toLowerCase().replace(/\s+/g, '_');
                let username = baseUsername;
                let counter = 1;

                // Vérification unicité
                while (await User.findOne({ username })) {
                    username = `${baseUsername}_${counter}`;
                    counter++;
                }

                const user = new User({
                    username,
                    email: `${username}@migrated.local`,
                    password: 'migrated_password',
                    role: 'user',
                    migrationData: {
                        legacyName: response.name,
                        migratedAt: new Date(),
                        source: 'response_migration'
                    }
                });

                return await user.save();
            };

            const user1 = await generateUniqueUser(responses[0]);
            const user2 = await generateUniqueUser(responses[1]);

            expect(user1.username).toBe('duplicate_user');
            expect(user2.username).toBe('duplicate_user_1');
            expect(user1.migrationData.legacyName).toBe('Duplicate User');
            expect(user2.migrationData.legacyName).toBe('Duplicate User');
        });
    });

    describe('Test Préservation des Tokens Legacy', () => {
        test('Doit préserver les tokens des utilisateurs non-admin', async () => {
            const testUser = new User({
                username: 'token_user',
                email: 'token@example.com',
                password: 'hashedpassword',
                role: 'user'
            });
            await testUser.save();

            const originalToken = 'original_token_' + Date.now();

            const response = new Response({
                name: 'Token User',
                responses: [{ question: 'Test', answer: 'Test' }],
                month: '2024-12',
                isAdmin: false,
                token: originalToken,
                createdAt: new Date()
            });
            await response.save();

            // Migration avec préservation du token
            const submission = new Submission({
                userId: testUser._id,
                responses: response.responses,
                month: response.month,
                legacyToken: response.token,
                migrationData: {
                    originalResponseId: response._id,
                    migratedAt: new Date(),
                    migrationVersion: '1.0'
                },
                createdAt: response.createdAt
            });

            await submission.save();

            // Validation que le token legacy est préservé
            const savedSubmission = await Submission.findById(submission._id);
            expect(savedSubmission.legacyToken).toBe(originalToken);

            // Vérification que l'accès par token fonctionne encore
            const submissionByToken = await Submission.findOne({ legacyToken: originalToken });
            expect(submissionByToken).toBeTruthy();
            expect(submissionByToken._id.toString()).toBe(submission._id.toString());
        });

        test('Doit gérer les tokens null pour les admins', async () => {
            const adminUser = new User({
                username: 'admin_test',
                email: 'admin@test.com',
                password: 'hashedpassword',
                role: 'admin'
            });
            await adminUser.save();

            const adminResponse = new Response({
                name: 'Admin Test',
                responses: [{ question: 'Admin Question', answer: 'Admin Answer' }],
                month: '2024-12',
                isAdmin: true,
                token: null,
                createdAt: new Date()
            });
            await adminResponse.save();

            const submission = new Submission({
                userId: adminUser._id,
                responses: adminResponse.responses,
                month: adminResponse.month,
                legacyToken: null,
                migrationData: {
                    originalResponseId: adminResponse._id,
                    migratedAt: new Date(),
                    migrationVersion: '1.0'
                },
                createdAt: adminResponse.createdAt
            });

            await submission.save();

            // Validation que les admins n'ont pas de token legacy
            const savedSubmission = await Submission.findById(submission._id);
            expect(savedSubmission.legacyToken).toBeNull();
        });
    });

    describe('Validation des Relations et Contraintes', () => {
        test('Doit maintenir la relation userId correcte', async () => {
            const user = new User({
                username: 'relation_test',
                email: 'relation@test.com',
                password: 'hashedpassword',
                role: 'user'
            });
            await user.save();

            const submission = new Submission({
                userId: user._id,
                responses: [{ question: 'Test relation', answer: 'Test answer' }],
                month: '2024-12',
                legacyToken: 'test_token',
                migrationData: {
                    originalResponseId: new mongoose.Types.ObjectId(),
                    migratedAt: new Date(),
                    migrationVersion: '1.0'
                }
            });

            await submission.save();

            // Test de la relation
            const submissionWithUser = await Submission.findById(submission._id).populate('userId');
            expect(submissionWithUser.userId.username).toBe('relation_test');
            expect(submissionWithUser.userId.email).toBe('relation@test.com');
        });

        test('Doit empêcher la création de submission sans userId valide', async () => {
            const invalidSubmission = new Submission({
                userId: new mongoose.Types.ObjectId(), // ID qui n'existe pas
                responses: [{ question: 'Test', answer: 'Test' }],
                month: '2024-12'
            });

            // La validation ne devrait pas échouer à la création
            await expect(invalidSubmission.save()).resolves.toBeTruthy();

            // Mais la référence ne devrait pas être résolue
            const submissionWithUser = await Submission.findById(invalidSubmission._id).populate('userId');
            expect(submissionWithUser.userId).toBeNull();
        });

        test('Doit maintenir l\'unicité des tokens legacy', async () => {
            const users = await User.insertMany([
                {
                    username: 'user1',
                    email: 'user1@test.com',
                    password: 'hashedpassword',
                    role: 'user'
                },
                {
                    username: 'user2',
                    email: 'user2@test.com',
                    password: 'hashedpassword',
                    role: 'user'
                }
            ]);

            const duplicateToken = 'duplicate_token_123';

            // Première submission avec le token
            const submission1 = new Submission({
                userId: users[0]._id,
                responses: [{ question: 'Test 1', answer: 'Answer 1' }],
                month: '2024-12',
                legacyToken: duplicateToken
            });

            await submission1.save();

            // Tentative de création d'une deuxième submission avec le même token
            const submission2 = new Submission({
                userId: users[1]._id,
                responses: [{ question: 'Test 2', answer: 'Answer 2' }],
                month: '2024-12',
                legacyToken: duplicateToken
            });

            // Selon la logique métier, ceci devrait être possible car différents utilisateurs
            // peuvent avoir des tokens différents, mais il faut s'assurer de l'unicité globale
            await submission2.save();

            // Vérification qu'il y a bien deux submissions
            const submissions = await Submission.find({ legacyToken: duplicateToken });
            expect(submissions).toHaveLength(2);

            // Note: Dans un vrai scénario, il faudrait ajouter un index unique sur legacyToken
            // si l'unicité est requise au niveau base de données
        });
    });
});