/**
 * Setup d'environnement pour les tests staging
 * Configuration des variables d'environnement avant chargement des modules
 */

// Configuration des variables d'environnement pour staging
process.env.NODE_ENV = 'staging';
process.env.STAGING_MODE = 'true';
process.env.MIGRATION_TEST_MODE = 'true';
process.env.LOG_LEVEL = 'debug';

// Configuration MongoDB (sera remplacée par MongoDB Memory Server)
process.env.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/faf_staging_test';

// Configuration session pour tests
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'staging-secret-key-for-testing-only';

// Configuration admin de test
process.env.LOGIN_ADMIN_USER = process.env.LOGIN_ADMIN_USER || 'staging-admin';
process.env.LOGIN_ADMIN_PASS = process.env.LOGIN_ADMIN_PASS || 'staging-password-123';
process.env.FORM_ADMIN_NAME = process.env.FORM_ADMIN_NAME || 'staging-admin';

// Configuration URLs de test
process.env.APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:3000';
process.env.FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Configuration Cloudinary pour tests (mock)
process.env.CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || 'staging-cloud';
process.env.CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY || 'staging-api-key';
process.env.CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || 'staging-api-secret';

// Configuration spécifique staging
process.env.STAGING_ISOLATION = 'true';
process.env.STAGING_DATA_CLEANUP = 'true';
process.env.STAGING_PERFORMANCE_MONITORING = 'true';

// Désactivation des timeouts externes pour les tests
process.env.HTTP_TIMEOUT = '10000';
process.env.DB_TIMEOUT = '5000';

// Configuration logging pour debugging
process.env.DEBUG = 'faf:staging:*';

// Éviter les warnings dans les tests
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Configuration Jest spécifique
process.env.JEST_WORKER_ID = process.env.JEST_WORKER_ID || '1';

console.log('🔧 Environment staging configuré:', {
    nodeEnv: process.env.NODE_ENV,
    stagingMode: process.env.STAGING_MODE,
    migrationTestMode: process.env.MIGRATION_TEST_MODE,
    workerId: process.env.JEST_WORKER_ID
});