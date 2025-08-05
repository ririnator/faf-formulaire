const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env.test') });

module.exports = {
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  testMatch: ['<rootDir>/tests/**/*.test.js'],
  collectCoverageFrom: [
    'routes/**/*.js',
    'models/**/*.js',
    'config/**/*.js',
    '!**/node_modules/**'
  ],
  coverageDirectory: 'coverage',
  verbose: false, // Reduce noise
  testTimeout: 15000,
  maxWorkers: 1, // Run tests serially to avoid DB conflicts
  forceExit: true // Ensure clean exit
};