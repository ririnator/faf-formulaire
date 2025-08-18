// test-cleanup.js - Cleanup utility for test environment
// Prevents setInterval timers from preventing Jest exit

/**
 * Comprehensive cleanup utility for FAF backend tests
 * Cleans up all setInterval timers and resources to prevent Jest hanging
 */

const cleanupAllTimers = async () => {
  console.log('🧹 Starting test cleanup...');
  
  try {
    // Cleanup middleware timers
    const auth = require('../middleware/auth');
    if (auth && typeof auth.cleanup === 'function') {
      auth.cleanup();
      console.log('✓ Auth middleware cleaned up');
    }

    const validation = require('../middleware/validation');
    if (validation && typeof validation.cleanup === 'function') {
      validation.cleanup();
      console.log('✓ Validation middleware cleaned up');
    }

    // Cleanup route timers
    try {
      const uploadRoutes = require('../routes/upload');
      if (uploadRoutes && typeof uploadRoutes.cleanup === 'function') {
        uploadRoutes.cleanup();
        console.log('✓ Upload routes cleaned up');
      }
    } catch (error) {
      console.log('⚠ Upload routes cleanup skipped:', error.message);
    }

    const adminRoutes = require('../routes/adminRoutes');
    if (adminRoutes && typeof adminRoutes.cleanup === 'function') {
      adminRoutes.cleanup();
      console.log('✓ Admin routes cleaned up');
    }

    // Clear any remaining timers
    const highestTimeoutId = setTimeout(() => {}, 0);
    for (let i = 1; i <= highestTimeoutId; i++) {
      clearTimeout(i);
      clearInterval(i);
    }

    console.log('✅ Test cleanup completed successfully');
    
  } catch (error) {
    console.error('❌ Error during test cleanup:', error.message);
  }
};

/**
 * Setup test environment cleanup hooks
 * Call this in test setup files to ensure proper cleanup
 */
const setupTestCleanup = () => {
  // Cleanup on process exit
  process.on('exit', cleanupAllTimers);
  process.on('SIGINT', cleanupAllTimers);
  process.on('SIGTERM', cleanupAllTimers);
  process.on('beforeExit', cleanupAllTimers);

  // Jest-specific cleanup
  if (typeof afterAll !== 'undefined') {
    afterAll(cleanupAllTimers);
  }
};

/**
 * Force cleanup for Jest
 * Use when Jest is hanging due to timers
 */
const forceCleanupForJest = async () => {
  await cleanupAllTimers();
  
  // Additional Jest-specific cleanup
  if (typeof jest !== 'undefined') {
    jest.clearAllTimers();
    jest.useRealTimers();
  }
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
};

module.exports = {
  cleanupAllTimers,
  setupTestCleanup,
  forceCleanupForJest
};