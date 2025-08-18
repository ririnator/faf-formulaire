/**
 * Setup global pour les tests de migration staging
 * Configuration automatique et nettoyage après tests
 */

const StagingEnvironment = require('./staging-config');

// Instance globale de l'environnement staging
global.stagingEnv = new StagingEnvironment();

/**
 * Setup global avant tous les tests
 */
beforeAll(async () => {
    console.log('🔧 Setup global des tests staging...');
    
    // Initialisation de l'environnement staging
    await global.stagingEnv.initialize();
    await global.stagingEnv.connectDatabase();
    
    // Génération des données de test de base
    await global.stagingEnv.generateTestData();
    
    console.log('✅ Setup staging terminé');
}, 30000); // Timeout de 30 secondes

/**
 * Nettoyage global après tous les tests
 */
afterAll(async () => {
    console.log('🧹 Nettoyage global des tests staging...');
    
    if (global.stagingEnv) {
        await global.stagingEnv.cleanup();
    }
    
    console.log('✅ Nettoyage staging terminé');
}, 15000); // Timeout de 15 secondes

/**
 * Configuration Jest pour les tests staging
 */
module.exports = {
    testEnvironment: 'node',
    setupFilesAfterEnv: [__filename],
    testTimeout: 30000,
    maxWorkers: 1, // Tests séquentiels pour éviter les conflits
    detectOpenHandles: true,
    forceExit: true,
    clearMocks: true,
    resetMocks: true,
    restoreMocks: true,
    collectCoverageFrom: [
        '../**/*.js',
        '!../tests/**',
        '!../node_modules/**',
        '!../coverage/**'
    ],
    coverageDirectory: '../coverage/staging',
    coverageReporters: ['text', 'lcov', 'html'],
    verbose: true
};