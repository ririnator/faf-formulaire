/**
 * Gestionnaire de connexion à la base de données pour la validation
 * 
 * Gère la connexion MongoDB avec :
 * - Configuration automatique depuis l'environnement
 * - Pool de connexions optimisé
 * - Gestion des erreurs et reconnexion
 * - Métriques de performance
 * 
 * @author FAF Migration Team
 */

const { MongoClient } = require('mongodb');
const path = require('path');

class DatabaseConnection {
    constructor(options = {}) {
        this.options = {
            maxPoolSize: 10,
            minPoolSize: 2,
            maxIdleTimeMS: 30000,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            ...options
        };
        
        this.client = null;
        this.db = null;
        this.isConnected = false;
        this.connectionAttempts = 0;
        this.maxConnectionAttempts = 3;
        
        // Métriques
        this.metrics = {
            connectionTime: 0,
            queriesExecuted: 0,
            totalQueryTime: 0,
            lastActivity: null
        };
    }

    /**
     * Connexion à la base de données
     */
    async connect() {
        if (this.isConnected) {
            return this.db;
        }

        const startTime = Date.now();
        
        try {
            // Chargement de la configuration
            await this.loadConfiguration();
            
            // Tentatives de connexion avec retry
            await this.attemptConnection();
            
            // Validation de la connexion
            await this.validateConnection();
            
            this.metrics.connectionTime = Date.now() - startTime;
            this.metrics.lastActivity = new Date();
            
            console.log(`✅ Connexion MongoDB établie (${this.metrics.connectionTime}ms)`);
            return this.db;
            
        } catch (error) {
            console.error('❌ Échec de la connexion MongoDB:', error.message);
            throw new Error(`Connexion MongoDB impossible: ${error.message}`);
        }
    }

    /**
     * Chargement de la configuration
     */
    async loadConfiguration() {
        // Chargement des variables d'environnement depuis le backend
        const backendPath = path.join(__dirname, '../../../backend');
        
        try {
            // Chargement du .env depuis le backend
            require('dotenv').config({ path: path.join(backendPath, '.env') });
        } catch (error) {
            console.warn('⚠️ Impossible de charger .env, utilisation des variables système');
        }

        // Configuration de l'URI MongoDB
        this.mongoUri = process.env.MONGODB_URI;
        
        if (!this.mongoUri) {
            // Tentative de construction de l'URI depuis les composants
            const host = process.env.MONGODB_HOST || 'localhost';
            const port = process.env.MONGODB_PORT || '27017';
            const database = process.env.MONGODB_DATABASE || 'faf';
            const username = process.env.MONGODB_USERNAME;
            const password = process.env.MONGODB_PASSWORD;
            
            if (username && password) {
                this.mongoUri = `mongodb://${username}:${password}@${host}:${port}/${database}`;
            } else {
                this.mongoUri = `mongodb://${host}:${port}/${database}`;
            }
        }

        // Extraction du nom de la base de données
        this.databaseName = this.extractDatabaseName(this.mongoUri);
        
        console.log(`📋 Configuration MongoDB: ${this.sanitizeUri(this.mongoUri)}`);
    }

    /**
     * Tentative de connexion avec retry
     */
    async attemptConnection() {
        for (let attempt = 1; attempt <= this.maxConnectionAttempts; attempt++) {
            this.connectionAttempts = attempt;
            
            try {
                console.log(`🔄 Tentative de connexion ${attempt}/${this.maxConnectionAttempts}...`);
                
                this.client = new MongoClient(this.mongoUri, {
                    ...this.options,
                    appName: 'FAF-Integrity-Validator'
                });
                
                await this.client.connect();
                this.db = this.client.db(this.databaseName);
                this.isConnected = true;
                
                return;
                
            } catch (error) {
                console.error(`❌ Tentative ${attempt} échouée:`, error.message);
                
                if (this.client) {
                    try {
                        await this.client.close();
                    } catch (closeError) {
                        // Ignore les erreurs de fermeture
                    }
                    this.client = null;
                }
                
                if (attempt === this.maxConnectionAttempts) {
                    throw error;
                }
                
                // Attente avant la prochaine tentative
                await this.sleep(1000 * attempt);
            }
        }
    }

    /**
     * Validation de la connexion
     */
    async validateConnection() {
        try {
            // Test de ping
            await this.db.admin().ping();
            
            // Vérification des collections principales
            const collections = await this.db.listCollections().toArray();
            const collectionNames = collections.map(c => c.name);
            
            console.log(`📋 Collections disponibles: ${collectionNames.join(', ')}`);
            
            // Vérification des permissions
            await this.checkPermissions();
            
        } catch (error) {
            throw new Error(`Validation de connexion échouée: ${error.message}`);
        }
    }

    /**
     * Vérification des permissions
     */
    async checkPermissions() {
        try {
            // Test de lecture
            await this.db.collection('responses').findOne({});
            
            // Test de comptage
            await this.db.collection('responses').countDocuments({});
            
            console.log('✅ Permissions de lecture validées');
            
        } catch (error) {
            throw new Error(`Permissions insuffisantes: ${error.message}`);
        }
    }

    /**
     * Obtention d'une collection avec métriques
     */
    collection(name) {
        if (!this.isConnected || !this.db) {
            throw new Error('Base de données non connectée');
        }
        
        const collection = this.db.collection(name);
        
        // Wrapping pour les métriques
        return this.wrapCollectionWithMetrics(collection);
    }

    /**
     * Wrapping d'une collection avec métriques
     */
    wrapCollectionWithMetrics(collection) {
        const self = this;
        
        return new Proxy(collection, {
            get(target, prop) {
                const originalMethod = target[prop];
                
                if (typeof originalMethod === 'function') {
                    return function(...args) {
                        const startTime = Date.now();
                        
                        const result = originalMethod.apply(target, args);
                        
                        // Si c'est une promesse, mesurer le temps d'exécution
                        if (result && typeof result.then === 'function') {
                            return result.then(res => {
                                self.recordQuery(Date.now() - startTime);
                                return res;
                            }).catch(error => {
                                self.recordQuery(Date.now() - startTime);
                                throw error;
                            });
                        }
                        
                        self.recordQuery(Date.now() - startTime);
                        return result;
                    };
                }
                
                return originalMethod;
            }
        });
    }

    /**
     * Enregistrement des métriques de requête
     */
    recordQuery(duration) {
        this.metrics.queriesExecuted++;
        this.metrics.totalQueryTime += duration;
        this.metrics.lastActivity = new Date();
    }

    /**
     * Obtention des métriques
     */
    getMetrics() {
        return {
            ...this.metrics,
            averageQueryTime: this.metrics.queriesExecuted > 0 
                ? this.metrics.totalQueryTime / this.metrics.queriesExecuted 
                : 0,
            isConnected: this.isConnected,
            connectionAttempts: this.connectionAttempts
        };
    }

    /**
     * Liste des collections
     */
    async listCollections() {
        if (!this.isConnected || !this.db) {
            throw new Error('Base de données non connectée');
        }
        
        return await this.db.listCollections().toArray();
    }

    /**
     * Exécution d'un pipeline d'agrégation global
     */
    async aggregate(collection, pipeline) {
        return await this.collection(collection).aggregate(pipeline).toArray();
    }

    /**
     * Déconnexion
     */
    async disconnect() {
        if (this.client && this.isConnected) {
            try {
                await this.client.close();
                console.log('✅ Connexion MongoDB fermée');
            } catch (error) {
                console.error('⚠️ Erreur lors de la fermeture:', error.message);
            }
        }
        
        this.client = null;
        this.db = null;
        this.isConnected = false;
    }

    /**
     * Extraction du nom de la base de données depuis l'URI
     */
    extractDatabaseName(uri) {
        try {
            const url = new URL(uri.replace('mongodb://', 'http://').replace('mongodb+srv://', 'https://'));
            const pathname = url.pathname.slice(1); // Retirer le '/' initial
            return pathname.split('?')[0] || 'faf'; // Retirer les paramètres de requête
        } catch (error) {
            console.warn('⚠️ Impossible d\'extraire le nom de la base de données, utilisation de "faf"');
            return 'faf';
        }
    }

    /**
     * Nettoyage de l'URI pour l'affichage (masquage des mots de passe)
     */
    sanitizeUri(uri) {
        return uri.replace(/:([^:@]+)@/, ':****@');
    }

    /**
     * Utilitaire de pause
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Test de connexion
     */
    async testConnection() {
        try {
            await this.connect();
            const metrics = this.getMetrics();
            await this.disconnect();
            return { success: true, metrics };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

module.exports = DatabaseConnection;