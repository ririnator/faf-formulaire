/**
 * Configuration Jest spécifique pour les tests de migration staging
 * Optimisée pour l'isolation, la performance et les rapports détaillés
 */

module.exports = {
    // Environnement de test
    testEnvironment: 'node',
    
    // Répertoire racine des tests staging
    rootDir: '../../',
    
    // Pattern de fichiers de test
    testMatch: [
        '<rootDir>/tests/staging/*.test.js'
    ],
    
    // Setup files
    setupFilesAfterEnv: [
        '<rootDir>/tests/staging/setup-staging.js'
    ],
    
    // Timeout global pour les tests staging (plus élevé que les tests normaux)
    testTimeout: 30000,
    
    // Configuration de coverage
    collectCoverageFrom: [
        '<rootDir>/**/*.js',
        '!<rootDir>/tests/**',
        '!<rootDir>/node_modules/**',
        '!<rootDir>/coverage/**',
        '!<rootDir>/reports/**',
        '!<rootDir>/*.config.js'
    ],
    
    // Répertoire de coverage spécifique staging
    coverageDirectory: '<rootDir>/coverage/staging',
    
    // Formats de rapport de coverage
    coverageReporters: [
        'text',
        'text-summary',
        'lcov',
        'html',
        'json'
    ],
    
    // Seuils de coverage pour staging
    coverageThreshold: {
        global: {
            branches: 70,
            functions: 75,
            lines: 80,
            statements: 80
        }
    },
    
    // Patterns à ignorer
    testPathIgnorePatterns: [
        '<rootDir>/node_modules/',
        '<rootDir>/tests/(?!staging)',
        '<rootDir>/coverage/',
        '<rootDir>/reports/'
    ],
    
    // Configuration des workers (séquentiel pour éviter les conflits DB)
    maxWorkers: 1,
    
    // Options Jest
    verbose: true,
    detectOpenHandles: true,
    forceExit: true,
    clearMocks: true,
    resetMocks: true,
    restoreMocks: true,
    
    // Variables d'environnement pour les tests staging
    setupFiles: [
        '<rootDir>/tests/staging/setup-env.js'
    ],
    
    // Mapping des modules
    moduleNameMapping: {},
    
    // Extensions de fichiers
    moduleFileExtensions: [
        'js',
        'json',
        'node'
    ],
    
    // Transformation des fichiers
    transform: {},
    
    // Configuration des reporters personnalisés
    reporters: [
        'default',
        [
            'jest-html-reporters',
            {
                publicPath: '<rootDir>/reports/staging',
                filename: 'staging-test-report.html',
                pageTitle: 'Tests de Migration Staging - FAF',
                logoImgPath: undefined,
                hideIcon: false,
                expand: true,
                openReport: false,
                inlineSource: false
            }
        ],
        [
            'jest-junit',
            {
                outputDirectory: '<rootDir>/reports/staging',
                outputName: 'staging-junit.xml',
                ancestorSeparator: ' › ',
                uniqueOutputName: false,
                suiteNameTemplate: '{title}',
                classNameTemplate: '{classname}',
                titleTemplate: '{title}',
                addFileAttribute: false,
                includeShortConsoleOutput: true
            }
        ]
    ],
    
    // Configuration des mocks globaux
    globals: {
        'ts-jest': {
            useESM: false
        }
    },
    
    // Hooks pour les tests
    globalSetup: undefined,
    globalTeardown: undefined,
    
    // Cache
    cache: false, // Désactivé pour éviter les problèmes entre runs
    
    // Notifications
    notify: false,
    notifyMode: 'failure-change',
    
    // Comportement des erreurs
    bail: false, // Continue même en cas d'erreur
    errorOnDeprecated: true,
    
    // Configuration spécifique staging
    testResultsProcessor: undefined,
    
    // Logging
    silent: false,
    verbose: true,
    
    // Configuration MongoDB Memory Server
    testEnvironmentOptions: {
        NODE_ENV: 'staging',
        STAGING_MODE: 'true',
        MIGRATION_TEST_MODE: 'true'
    }
};