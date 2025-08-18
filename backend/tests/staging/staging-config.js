/**
 * Configuration de l'environnement staging pour tests de migration
 * Isolation complète des données de production avec MongoDB Memory Server
 */

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const path = require('path');

class StagingEnvironment {
    constructor() {
        this.mongoServer = null;
        this.originalEnv = {};
        this.testDatabaseName = `faf_staging_${Date.now()}`;
        this.isInitialized = false;
    }

    /**
     * Initialise l'environnement staging avec isolation complète
     */
    async initialize() {
        if (this.isInitialized) {
            return;
        }

        console.log('🚀 Initialisation environnement staging...');

        // Sauvegarde des variables d'environnement originales
        this.originalEnv = { ...process.env };

        // Configuration MongoDB Memory Server
        this.mongoServer = await MongoMemoryServer.create({
            instance: {
                dbName: this.testDatabaseName,
                storageEngine: 'wiredTiger'
            },
            binary: {
                version: '5.0.0'
            }
        });

        const mongoUri = this.mongoServer.getUri();

        // Configuration des variables d'environnement de test
        process.env.NODE_ENV = 'staging';
        process.env.MONGODB_URI = mongoUri;
        process.env.SESSION_SECRET = 'staging-secret-key-for-testing-only';
        process.env.LOGIN_ADMIN_USER = 'staging-admin';
        process.env.LOGIN_ADMIN_PASS = 'staging-password-123';
        process.env.FORM_ADMIN_NAME = 'staging-admin';
        process.env.APP_BASE_URL = 'http://localhost:3000';
        process.env.FRONTEND_URL = 'http://localhost:3000';
        process.env.CLOUDINARY_CLOUD_NAME = 'staging-cloud';
        process.env.CLOUDINARY_API_KEY = 'staging-api-key';
        process.env.CLOUDINARY_API_SECRET = 'staging-api-secret';

        // Configuration spécifique staging
        process.env.STAGING_MODE = 'true';
        process.env.MIGRATION_TEST_MODE = 'true';
        process.env.LOG_LEVEL = 'debug';

        console.log(`✅ MongoDB Staging URI: ${mongoUri}`);
        console.log(`✅ Database Name: ${this.testDatabaseName}`);

        this.isInitialized = true;
    }

    /**
     * Connecte à la base de données staging
     */
    async connectDatabase() {
        if (!this.isInitialized) {
            await this.initialize();
        }

        if (mongoose.connection.readyState === 0) {
            await mongoose.connect(process.env.MONGODB_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true
            });
        }

        console.log('✅ Connexion base de données staging établie');
    }

    /**
     * Génère des données de test réalistes pour la migration
     */
    async generateTestData() {
        const Response = require('../../models/Response');
        const User = require('../../models/User');
        const bcrypt = require('bcrypt');

        console.log('📊 Génération des données de test...');

        // Données de test pour les réponses legacy (format Response)
        const testResponses = [
            {
                name: 'Jean Dupont',
                responses: [
                    { question: 'Quelle est votre couleur préférée ?', answer: 'Bleu' },
                    { question: 'Quel est votre plat favori ?', answer: 'Pizza margherita' },
                    { question: 'Décrivez votre weekend idéal', answer: 'Randonnée en montagne avec des amis' }
                ],
                month: '2024-12',
                isAdmin: false,
                token: 'token_jean_' + Date.now(),
                createdAt: new Date('2024-12-01')
            },
            {
                name: 'Marie Martin',
                responses: [
                    { question: 'Quelle est votre couleur préférée ?', answer: 'Rouge' },
                    { question: 'Quel est votre plat favori ?', answer: 'Couscous royal' },
                    { question: 'Décrivez votre weekend idéal', answer: 'Lecture au bord de la mer' }
                ],
                month: '2024-12',
                isAdmin: false,
                token: 'token_marie_' + Date.now(),
                createdAt: new Date('2024-12-02')
            },
            {
                name: 'staging-admin',
                responses: [
                    { question: 'Quelle est votre couleur préférée ?', answer: 'Vert' },
                    { question: 'Quel est votre plat favori ?', answer: 'Ratatouille' },
                    { question: 'Décrivez votre weekend idéal', answer: 'Jardinage et bricolage' }
                ],
                month: '2024-12',
                isAdmin: true,
                token: null,
                createdAt: new Date('2024-12-03')
            }
        ];

        // Données de test pour les utilisateurs (format User)
        const testUsers = [
            {
                username: 'jean_dupont',
                email: 'jean.dupont@example.com',
                password: await bcrypt.hash('password123', 10),
                role: 'user',
                profile: {
                    firstName: 'Jean',
                    lastName: 'Dupont'
                },
                metadata: {
                    isActive: true,
                    emailVerified: true,
                    lastActive: new Date(),
                    responseCount: 1,
                    registeredAt: new Date('2024-12-01')
                }
            },
            {
                username: 'marie_martin',
                email: 'marie.martin@example.com',
                password: await bcrypt.hash('password456', 10),
                role: 'user',
                profile: {
                    firstName: 'Marie',
                    lastName: 'Martin'
                },
                metadata: {
                    isActive: true,
                    emailVerified: true,
                    lastActive: new Date(),
                    responseCount: 1,
                    registeredAt: new Date('2024-12-02')
                }
            },
            {
                username: 'staging-admin',
                email: 'admin@staging.com',
                password: await bcrypt.hash('staging-password-123', 10),
                role: 'admin',
                profile: {
                    firstName: 'Admin',
                    lastName: 'Staging'
                },
                metadata: {
                    isActive: true,
                    emailVerified: true,
                    lastActive: new Date(),
                    responseCount: 1,
                    registeredAt: new Date('2024-12-03')
                }
            }
        ];

        // Insertion des données de test
        await Response.insertMany(testResponses);
        await User.insertMany(testUsers);

        console.log(`✅ ${testResponses.length} réponses de test créées`);
        console.log(`✅ ${testUsers.length} utilisateurs de test créés`);

        return {
            responses: testResponses,
            users: testUsers
        };
    }

    /**
     * Génère des données de volume pour les tests de performance
     */
    async generateVolumeData(responseCount = 100, userCount = 50) {
        const Response = require('../../models/Response');
        const User = require('../../models/User');
        const bcrypt = require('bcrypt');

        console.log(`📈 Génération de ${responseCount} réponses et ${userCount} utilisateurs pour tests de performance...`);

        const responses = [];
        const users = [];

        // Génération de réponses en volume
        for (let i = 0; i < responseCount; i++) {
            responses.push({
                name: `User${i}`,
                responses: [
                    { question: 'Question 1', answer: `Réponse ${i} à la question 1` },
                    { question: 'Question 2', answer: `Réponse ${i} à la question 2` },
                    { question: 'Question 3', answer: `Réponse ${i} à la question 3` }
                ],
                month: '2024-12',
                isAdmin: false,
                token: `token_${i}_${Date.now()}`,
                createdAt: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000)
            });
        }

        // Génération d'utilisateurs en volume
        for (let i = 0; i < userCount; i++) {
            users.push({
                username: `user${i}`,
                email: `user${i}@example.com`,
                password: await bcrypt.hash('password123', 10),
                role: 'user',
                profile: {
                    firstName: `User${i}`,
                    lastName: `Lastname${i}`
                },
                metadata: {
                    isActive: true,
                    emailVerified: true,
                    lastActive: new Date(),
                    responseCount: 1,
                    registeredAt: new Date()
                }
            });
        }

        await Response.insertMany(responses);
        await User.insertMany(users);

        console.log(`✅ ${responseCount} réponses de volume créées`);
        console.log(`✅ ${userCount} utilisateurs de volume créés`);

        return { responses, users };
    }

    /**
     * Nettoie l'environnement staging
     */
    async cleanup() {
        console.log('🧹 Nettoyage environnement staging...');

        try {
            // Déconnexion de MongoDB
            if (mongoose.connection.readyState !== 0) {
                await mongoose.disconnect();
            }

            // Arrêt du serveur MongoDB Memory
            if (this.mongoServer) {
                await this.mongoServer.stop();
            }

            // Restauration des variables d'environnement
            process.env = { ...this.originalEnv };

            console.log('✅ Nettoyage terminé');
        } catch (error) {
            console.error('❌ Erreur lors du nettoyage:', error);
        }

        this.isInitialized = false;
    }

    /**
     * Vérifie l'état de l'environnement staging
     */
    async healthCheck() {
        const checks = {
            mongoConnection: false,
            environmentVariables: false,
            testDatabase: false
        };

        try {
            // Vérification connexion MongoDB
            checks.mongoConnection = mongoose.connection.readyState === 1;

            // Vérification variables d'environnement
            checks.environmentVariables = !!(
                process.env.MONGODB_URI &&
                process.env.SESSION_SECRET &&
                process.env.STAGING_MODE === 'true'
            );

            // Vérification base de données de test
            const db = mongoose.connection.db;
            if (db) {
                const collections = await db.listCollections().toArray();
                checks.testDatabase = collections.length >= 0;
            }

        } catch (error) {
            console.error('❌ Erreur health check:', error);
        }

        return checks;
    }

    /**
     * Génère un rapport de l'environnement staging
     */
    async generateEnvironmentReport() {
        const healthCheck = await this.healthCheck();
        const Response = require('../../models/Response');
        const User = require('../../models/User');

        const report = {
            timestamp: new Date().toISOString(),
            environment: {
                nodeEnv: process.env.NODE_ENV,
                stagingMode: process.env.STAGING_MODE,
                migrationTestMode: process.env.MIGRATION_TEST_MODE
            },
            database: {
                name: this.testDatabaseName,
                uri: process.env.MONGODB_URI,
                connected: healthCheck.mongoConnection
            },
            collections: {},
            healthCheck
        };

        if (healthCheck.mongoConnection) {
            try {
                report.collections.responses = await Response.countDocuments();
                report.collections.users = await User.countDocuments();
            } catch (error) {
                report.collections.error = error.message;
            }
        }

        return report;
    }
}

module.exports = StagingEnvironment;