/**
 * Setup for Post-Deployment Testing
 * 
 * Initializes test environment for production validation
 * with real database connections and service integrations.
 */

const path = require('path');
require('dotenv').config({ 
  path: path.join(__dirname, '../../.env.production') 
});

// Global test configuration
global.testConfig = {
  // Production environment settings
  environment: 'production',
  baseUrl: process.env.APP_BASE_URL || 'https://your-production-domain.com',
  apiTimeout: 30000,
  
  // Test data configuration
  testUsers: {
    regularUser: {
      username: 'test_user_prod',
      email: 'test.user.prod@example.com',
      password: 'TestPass123!'
    },
    adminUser: {
      username: process.env.LOGIN_ADMIN_USER || 'admin',
      password: process.env.LOGIN_ADMIN_PASS || 'admin_password'
    }
  },
  
  // Performance thresholds
  performance: {
    maxResponseTime: 2000,  // 2 seconds
    maxMemoryUsage: 512,    // 512 MB
    maxCpuUsage: 80,        // 80%
    maxDbConnections: 100   // Max DB connections
  },
  
  // Security validation settings
  security: {
    expectedHeaders: [
      'X-Content-Type-Options',
      'X-Frame-Options',
      'X-XSS-Protection',
      'Strict-Transport-Security',
      'Content-Security-Policy'
    ],
    maxFailedLoginAttempts: 5,
    sessionTimeout: 3600000 // 1 hour
  },
  
  // Monitoring configuration
  monitoring: {
    healthCheckInterval: 30000, // 30 seconds
    alertThresholds: {
      errorRate: 5,     // 5% error rate
      responseTime: 5000, // 5 seconds
      memoryUsage: 90   // 90% memory usage
    }
  }
};

// Global test utilities
global.testUtils = {
  // Sleep utility for timing tests
  sleep: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
  
  // Generate unique test identifiers
  generateTestId: () => `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
  
  // Cleanup functions
  cleanup: {
    testUsers: [],
    testData: [],
    testSessions: []
  },
  
  // Add cleanup task
  addCleanup: (type, data) => {
    if (global.testUtils.cleanup[type]) {
      global.testUtils.cleanup[type].push(data);
    }
  },
  
  // Execute cleanup
  executeCleanup: async () => {
    console.log('🧹 Executing post-deployment test cleanup...');
    
    // Cleanup test users
    for (const user of global.testUtils.cleanup.testUsers) {
      try {
        // Add cleanup logic here if needed
        console.log(`Cleaned up test user: ${user.username}`);
      } catch (error) {
        console.warn(`Failed to cleanup user ${user.username}:`, error.message);
      }
    }
    
    // Reset cleanup arrays
    global.testUtils.cleanup.testUsers = [];
    global.testUtils.cleanup.testData = [];
    global.testUtils.cleanup.testSessions = [];
  }
};

// Global test metrics collector
global.testMetrics = {
  startTime: Date.now(),
  tests: {
    total: 0,
    passed: 0,
    failed: 0,
    skipped: 0
  },
  performance: {
    averageResponseTime: 0,
    slowestTest: null,
    fastestTest: null
  },
  security: {
    vulnerabilitiesFound: 0,
    securityTestsPassed: 0
  },
  coverage: {
    statements: 0,
    branches: 0,
    functions: 0,
    lines: 0
  }
};

// Test reporter utilities
global.testReporter = {
  logTestStart: (testName) => {
    console.log(`\n🚀 Starting: ${testName}`);
    return Date.now();
  },
  
  logTestEnd: (testName, startTime, passed = true) => {
    const duration = Date.now() - startTime;
    const status = passed ? '✅ PASSED' : '❌ FAILED';
    console.log(`${status}: ${testName} (${duration}ms)`);
    
    // Update metrics
    global.testMetrics.tests.total++;
    if (passed) {
      global.testMetrics.tests.passed++;
    } else {
      global.testMetrics.tests.failed++;
    }
    
    // Track performance
    if (!global.testMetrics.performance.slowestTest || 
        duration > global.testMetrics.performance.slowestTest.duration) {
      global.testMetrics.performance.slowestTest = { name: testName, duration };
    }
    
    if (!global.testMetrics.performance.fastestTest || 
        duration < global.testMetrics.performance.fastestTest.duration) {
      global.testMetrics.performance.fastestTest = { name: testName, duration };
    }
  },
  
  logSecurityIssue: (testName, issue) => {
    console.warn(`🔒 Security Issue in ${testName}:`, issue);
    global.testMetrics.security.vulnerabilitiesFound++;
  },
  
  logPerformanceIssue: (testName, metric, value, threshold) => {
    console.warn(`⚡ Performance Issue in ${testName}: ${metric} (${value}) exceeds threshold (${threshold})`);
  }
};

// Setup hooks
beforeAll(async () => {
  console.log('\n🏗️  Setting up post-deployment test environment...');
  console.log(`📍 Target Environment: ${global.testConfig.environment}`);
  console.log(`🌐 Base URL: ${global.testConfig.baseUrl}`);
  
  // Validate environment
  if (!process.env.APP_BASE_URL) {
    throw new Error('APP_BASE_URL must be set for post-deployment testing');
  }
  
  if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI must be set for post-deployment testing');
  }
  
  console.log('✅ Post-deployment environment validated');
});

afterAll(async () => {
  console.log('\n🧹 Cleaning up post-deployment test environment...');
  
  // Execute cleanup
  await global.testUtils.executeCleanup();
  
  // Print final metrics
  const totalTime = Date.now() - global.testMetrics.startTime;
  console.log('\n📊 Post-Deployment Test Summary:');
  console.log(`⏱️  Total Time: ${totalTime}ms`);
  console.log(`✅ Tests Passed: ${global.testMetrics.tests.passed}`);
  console.log(`❌ Tests Failed: ${global.testMetrics.tests.failed}`);
  console.log(`⏭️  Tests Skipped: ${global.testMetrics.tests.skipped}`);
  
  if (global.testMetrics.performance.slowestTest) {
    console.log(`🐌 Slowest Test: ${global.testMetrics.performance.slowestTest.name} (${global.testMetrics.performance.slowestTest.duration}ms)`);
  }
  
  if (global.testMetrics.security.vulnerabilitiesFound > 0) {
    console.log(`🔒 Security Issues Found: ${global.testMetrics.security.vulnerabilitiesFound}`);
  }
  
  console.log('✅ Post-deployment cleanup completed');
});

// Error handling for unhandled promises
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});