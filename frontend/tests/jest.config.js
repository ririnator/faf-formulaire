module.exports = {
  testEnvironment: 'node',
  testMatch: [
    '**/frontend/tests/**/*.test.js'
  ],
  setupFilesAfterEnv: ['<rootDir>/frontend/tests/setup.js'],
  collectCoverageFrom: [
    'frontend/**/*.js',
    'frontend/**/*.html',
    '!frontend/tests/**',
    '!frontend/node_modules/**'
  ],
  coverageReporters: ['text', 'lcov', 'html'],
  verbose: true,
  
  // Configuration spécifique pour les tests DOM
  testEnvironmentOptions: {
    url: 'http://localhost:3000'
  },
  
  // Timeouts pour tests d'intégration
  testTimeout: 10000,
  
  // Mock des modules externes (supprimé car non supporté dans Jest 30)
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/frontend/$1'
  }
};