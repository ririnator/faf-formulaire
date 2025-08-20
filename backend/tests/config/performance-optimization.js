/**
 * Performance Optimization for Test Suites
 * Provides utilities for optimizing concurrent test execution
 */

const { performance } = require('perf_hooks');

class TestPerformanceOptimizer {
  constructor() {
    this.startTime = null;
    this.metrics = new Map();
    this.concurrentLimits = {
      database: 5,    // Max concurrent DB operations
      api: 10,        // Max concurrent API requests
      setup: 3        // Max concurrent test setup operations
    };
  }

  // Start performance monitoring
  startMonitoring(testName) {
    this.startTime = performance.now();
    this.metrics.set(testName, {
      startTime: this.startTime,
      endTime: null,
      duration: null,
      memoryUsage: process.memoryUsage()
    });
  }

  // End performance monitoring
  endMonitoring(testName) {
    const endTime = performance.now();
    const metric = this.metrics.get(testName);
    if (metric) {
      metric.endTime = endTime;
      metric.duration = endTime - metric.startTime;
      metric.finalMemoryUsage = process.memoryUsage();
    }
  }

  // Batch database operations for better performance
  async batchDatabaseOperations(operations, batchSize = 5) {
    const results = [];
    for (let i = 0; i < operations.length; i += batchSize) {
      const batch = operations.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch);
      results.push(...batchResults);
      
      // Small delay to prevent overwhelming the database
      if (i + batchSize < operations.length) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }
    return results;
  }

  // Optimized test data creation with connection pooling awareness
  async createTestDataOptimized(Model, dataArray) {
    // Use insertMany for better performance with multiple documents
    if (dataArray.length > 1) {
      return await Model.insertMany(dataArray, { ordered: false });
    } else {
      return await Model.create(dataArray[0]);
    }
  }

  // Parallel cleanup with controlled concurrency
  async parallelCleanup(collections, maxConcurrency = 3) {
    const cleanupTasks = collections.map(collection => 
      () => collection.deleteMany({})
    );

    // Execute cleanup in controlled batches
    const results = [];
    for (let i = 0; i < cleanupTasks.length; i += maxConcurrency) {
      const batch = cleanupTasks.slice(i, i + maxConcurrency);
      const batchPromises = batch.map(task => task());
      const batchResults = await Promise.allSettled(batchPromises);
      results.push(...batchResults);
    }

    return results;
  }

  // Memory usage monitoring
  getMemoryUsage() {
    const usage = process.memoryUsage();
    return {
      rss: Math.round(usage.rss / 1024 / 1024), // MB
      heapUsed: Math.round(usage.heapUsed / 1024 / 1024), // MB
      heapTotal: Math.round(usage.heapTotal / 1024 / 1024), // MB
      external: Math.round(usage.external / 1024 / 1024) // MB
    };
  }

  // Generate performance report
  generateReport() {
    const report = {
      totalTests: this.metrics.size,
      averageDuration: 0,
      slowestTests: [],
      memoryTrends: [],
      recommendations: []
    };

    let totalDuration = 0;
    const testResults = [];

    this.metrics.forEach((metric, testName) => {
      if (metric.duration) {
        totalDuration += metric.duration;
        testResults.push({ name: testName, duration: metric.duration });
      }
    });

    report.averageDuration = totalDuration / testResults.length;
    report.slowestTests = testResults
      .sort((a, b) => b.duration - a.duration)
      .slice(0, 5);

    // Add performance recommendations
    if (report.averageDuration > 1000) {
      report.recommendations.push('Consider optimizing test setup and teardown');
    }
    
    const slowTests = testResults.filter(test => test.duration > 2000);
    if (slowTests.length > 0) {
      report.recommendations.push(`${slowTests.length} tests taking >2s - consider optimization`);
    }

    return report;
  }
}

// Singleton instance
const performanceOptimizer = new TestPerformanceOptimizer();

// Jest setup helpers
const setupPerformanceMonitoring = () => {
  // Monitor each test
  beforeEach(() => {
    const testName = expect.getState().currentTestName || 'unknown';
    performanceOptimizer.startMonitoring(testName);
  });

  afterEach(() => {
    const testName = expect.getState().currentTestName || 'unknown';
    performanceOptimizer.endMonitoring(testName);
  });

  // Generate report after all tests
  afterAll(() => {
    const report = performanceOptimizer.generateReport();
    if (process.env.TEST_PERFORMANCE_REPORT) {
      console.log('\n📊 Test Performance Report:', JSON.stringify(report, null, 2));
    }
  });
};

module.exports = {
  TestPerformanceOptimizer,
  performanceOptimizer,
  setupPerformanceMonitoring
};