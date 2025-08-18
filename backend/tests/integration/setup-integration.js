// Unified integration test setup - redirects to global setup
const { 
  setupGlobalDatabase, 
  cleanupGlobalDatabase, 
  cleanupBetweenTests,
  getMongoUri 
} = require('../setup-global');

// Alias functions to maintain backward compatibility
const setupTestDatabase = setupGlobalDatabase;
const teardownTestDatabase = cleanupGlobalDatabase;
const cleanupDatabase = cleanupBetweenTests;

module.exports = {
  setupTestDatabase,
  teardownTestDatabase,
  cleanupDatabase,
  setupGlobalDatabase,
  cleanupGlobalDatabase,
  cleanupBetweenTests,
  getMongoUri
};