module.exports = {
  testEnvironment: 'jsdom',
  testMatch: [
    '**/frontend/tests/**/*.test.js'
  ],
  setupFilesAfterEnv: ['<rootDir>/frontend/tests/setup.js'],
  collectCoverageFrom: [
    'frontend/**/*.js',
    '!frontend/tests/**',
    '!frontend/node_modules/**'
  ],
  coverageReporters: ['text', 'lcov', 'html'],
  verbose: true
};