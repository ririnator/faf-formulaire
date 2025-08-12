// Simplified setup that uses global database instance
const { setupGlobalDatabase, cleanupGlobalDatabase, cleanupBetweenTests } = require('./setup-global');

// Global setup - runs once for entire test suite
beforeAll(async () => {
  await setupGlobalDatabase();
}, 60000);

// Global teardown - runs once after all tests
afterAll(async () => {
  await cleanupGlobalDatabase();
}, 30000);

// Clean between each test
afterEach(async () => {
  await cleanupBetweenTests();
}, 10000);