const DBPerformanceMonitor = require('../services/dbPerformanceMonitor');
const Response = require('../models/Response');
const User = require('../models/User');

const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

beforeAll(async () => {
  app = getTestApp();
}, 30000);

describe('DBPerformanceMonitor', () => {
  let performanceMonitor;
  let originalModels;

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI_TEST || 'mongodb://127.0.0.1:27017/faf-test');
    }
    
    // Store original models
    originalModels = {
      Response: mongoose.models.Response,
      User: mongoose.models.User
    };
  });

  beforeEach(async () => {
    // Clean database
    await Response.deleteMany({});
    await User.deleteMany({});
    
    // Create fresh monitor instance
    performanceMonitor = new DBPerformanceMonitor({
      slowQueryThreshold: 50,
      sampleRate: 1.0,
      enableProfiling: false, // Disable for tests
      enableExplainAnalysis: false,
      maxMetricsBuffer: 100
    });
  });

  afterEach(async () => {
    if (performanceMonitor && performanceMonitor.isMonitoring) {
      performanceMonitor.stopMonitoring();
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      }
  });

  describe('Initialization and Configuration', () => {
    test('should initialize with default configuration', () => {
      const monitor = new DBPerformanceMonitor();
      
      expect(monitor.config.slowQueryThreshold).toBe(100);
      expect(monitor.config.sampleRate).toBe(1.0);
      expect(monitor.config.enableProfiling).toBe(true);
      expect(monitor.isMonitoring).toBe(false);
    });

    test('should initialize with custom configuration', () => {
      const customConfig = {
        slowQueryThreshold: 200,
        sampleRate: 0.5,
        maxMetricsBuffer: 500
      };
      
      const monitor = new DBPerformanceMonitor(customConfig);
      
      expect(monitor.config.slowQueryThreshold).toBe(200);
      expect(monitor.config.sampleRate).toBe(0.5);
      expect(monitor.config.maxMetricsBuffer).toBe(500);
    });

    test('should initialize empty metrics', () => {
      expect(performanceMonitor.metrics.queries.size).toBe(0);
      expect(performanceMonitor.metrics.indexes.size).toBe(0);
      expect(performanceMonitor.metrics.collections.size).toBe(0);
      expect(performanceMonitor.metrics.slowQueries).toHaveLength(0);
    });
  });

  describe('Monitoring Lifecycle', () => {
    test('should start monitoring successfully', async () => {
      await performanceMonitor.startMonitoring();
      
      expect(performanceMonitor.isMonitoring).toBe(true);
      expect(performanceMonitor.metrics.indexes.size).toBeGreaterThan(0);
    });

    test('should stop monitoring successfully', async () => {
      await performanceMonitor.startMonitoring();
      performanceMonitor.stopMonitoring();
      
      expect(performanceMonitor.isMonitoring).toBe(false);
    });

    test('should not start monitoring twice', async () => {
      await performanceMonitor.startMonitoring();
      
      // Should not throw error
      await performanceMonitor.startMonitoring();
      
      expect(performanceMonitor.isMonitoring).toBe(true);
    });

    test('should handle monitoring errors gracefully', async () => {
      // Mock mongoose.connection.db to throw error
      const originalDb = mongoose.connection.db;
      mongoose.connection.db = null;
      
      await expect(performanceMonitor.startMonitoring()).rejects.toThrow();
      
      // Restore
      mongoose.connection.db = originalDb;
    });
  });

  describe('Query Metrics Recording', () => {
    test('should record query metrics correctly', () => {
      const queryData = {
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01' },
        executionTime: 75,
        resultCount: 10,
        timestamp: new Date()
      };

      performanceMonitor.recordQueryMetrics(queryData);
      
      expect(performanceMonitor.metrics.queries.size).toBe(1);
      expect(performanceMonitor.metrics.collections.has('responses')).toBe(true);
      expect(performanceMonitor.metrics.aggregatedStats.totalQueries).toBe(1);
    });

    test('should detect slow queries', () => {
      const slowQueryData = {
        collection: 'responses',
        operation: 'find',
        filter: { name: 'test' },
        executionTime: 150, // Above threshold
        resultCount: 5,
        timestamp: new Date()
      };

      performanceMonitor.recordQueryMetrics(slowQueryData);
      
      expect(performanceMonitor.metrics.slowQueries).toHaveLength(1);
      expect(performanceMonitor.metrics.aggregatedStats.slowQueries).toBe(1);
      
      const slowQuery = performanceMonitor.metrics.slowQueries[0];
      expect(slowQuery.executionTime).toBe(150);
      expect(slowQuery.collection).toBe('responses');
    });

    test('should group similar queries by signature', () => {
      const queryData1 = {
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01' },
        executionTime: 30,
        resultCount: 5,
        timestamp: new Date()
      };
      
      const queryData2 = {
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-02' }, // Different value, same structure
        executionTime: 45,
        resultCount: 8,
        timestamp: new Date()
      };

      performanceMonitor.recordQueryMetrics(queryData1);
      performanceMonitor.recordQueryMetrics(queryData2);
      
      // Should be grouped under same signature
      expect(performanceMonitor.metrics.queries.size).toBe(1);
      
      const queryMetrics = Array.from(performanceMonitor.metrics.queries.values())[0];
      expect(queryMetrics.count).toBe(2);
      expect(queryMetrics.avgTime).toBe(37.5); // (30 + 45) / 2
    });

    test('should update aggregated statistics', () => {
      const queries = [
        { collection: 'responses', operation: 'find', filter: {}, executionTime: 20, resultCount: 1, timestamp: new Date() },
        { collection: 'responses', operation: 'find', filter: {}, executionTime: 80, resultCount: 2, timestamp: new Date() },
        { collection: 'users', operation: 'find', filter: {}, executionTime: 120, resultCount: 3, timestamp: new Date() }
      ];

      queries.forEach(query => performanceMonitor.recordQueryMetrics(query));
      
      expect(performanceMonitor.metrics.aggregatedStats.totalQueries).toBe(3);
      expect(performanceMonitor.metrics.aggregatedStats.slowQueries).toBe(1); // 120ms query
      expect(performanceMonitor.metrics.collections.size).toBe(2); // responses and users
    });
  });

  describe('Hybrid Index Analysis', () => {
    test('should analyze hybrid user-unique index usage', () => {
      const filter = {
        month: '2025-01',
        userId: new mongoose.Types.ObjectId(),
        authMethod: 'user'
      };

      const analysis = performanceMonitor.analyzeHybridIndexUsage(filter);
      
      expect(analysis.type).toBe('hybrid-user-unique');
      expect(analysis.efficiency).toBe(0.95);
      expect(analysis.index).toBe('{ month: 1, userId: 1 }');
    });

    test('should analyze hybrid admin-unique index usage', () => {
      const filter = {
        month: '2025-01',
        isAdmin: true,
        name: 'admin',
        authMethod: 'token'
      };

      const analysis = performanceMonitor.analyzeHybridIndexUsage(filter);
      
      expect(analysis.type).toBe('hybrid-admin-unique');
      expect(analysis.efficiency).toBe(0.95);
      expect(analysis.index).toBe('{ month: 1, isAdmin: 1, name: 1 }');
    });

    test('should detect token-based queries', () => {
      const filter = { token: 'abc123' };

      const analysis = performanceMonitor.analyzeHybridIndexUsage(filter);
      
      expect(analysis.type).toBe('token-unique');
      expect(analysis.efficiency).toBe(0.98);
    });

    test('should detect collection scans', () => {
      const filter = { nonIndexedField: 'value' };

      const analysis = performanceMonitor.analyzeHybridIndexUsage(filter);
      
      expect(analysis.type).toBe('collection-scan');
      expect(analysis.efficiency).toBe(0.10);
    });

    test('should handle empty or invalid filters', () => {
      expect(performanceMonitor.analyzeHybridIndexUsage(null)).toEqual({
        type: 'none',
        efficiency: 0
      });
      
      expect(performanceMonitor.analyzeHybridIndexUsage({})).toEqual({
        type: 'collection-scan',
        efficiency: 0.10,
        index: 'none'
      });
    });
  });

  describe('Index Pattern Detection', () => {
    test('should detect different index patterns', () => {
      const testCases = [
        { filter: { userId: 'user123' }, expected: 'userAuth' },
        { filter: { token: 'token123' }, expected: 'tokenAuth' },
        { filter: { month: '2025-01' }, expected: 'monthQuery' },
        { filter: { isAdmin: true }, expected: 'adminQuery' },
        { filter: { createdAt: { $gte: new Date() } }, expected: 'timeRange' },
        { filter: { randomField: 'value' }, expected: 'unknown' }
      ];

      testCases.forEach(({ filter, expected }) => {
        const pattern = performanceMonitor.detectIndexPattern(filter);
        if (expected === 'unknown') {
          expect(pattern).toBe('unknown');
        } else {
          // Pattern detection uses regex matching, so we check if it contains expected pattern
          expect(pattern).toBe(expected);
        }
      });
    });
  });

  describe('Performance Summary Generation', () => {
    test('should generate comprehensive performance summary', () => {
      // Add some test data
      const queries = [
        { collection: 'responses', operation: 'find', filter: { month: '2025-01' }, executionTime: 25, resultCount: 5, timestamp: new Date() },
        { collection: 'responses', operation: 'find', filter: { token: 'abc' }, executionTime: 75, resultCount: 1, timestamp: new Date() },
        { collection: 'users', operation: 'find', filter: { email: 'test@example.com' }, executionTime: 120, resultCount: 1, timestamp: new Date() }
      ];

      queries.forEach(query => performanceMonitor.recordQueryMetrics(query));

      const summary = performanceMonitor.getPerformanceSummary();
      
      expect(summary).toHaveProperty('monitoring');
      expect(summary).toHaveProperty('aggregatedStats');
      expect(summary).toHaveProperty('collections');
      expect(summary).toHaveProperty('topSlowQueries');
      expect(summary).toHaveProperty('indexUsage');
      expect(summary).toHaveProperty('hybridIndexEfficiency');
      expect(summary).toHaveProperty('recommendations');
      
      expect(summary.aggregatedStats.totalQueries).toBe(3);
      expect(summary.collections).toHaveLength(2);
    });

    test('should generate appropriate recommendations', () => {
      // Create conditions that trigger recommendations
      
      // High slow query rate
      for (let i = 0; i < 10; i++) {
        performanceMonitor.recordQueryMetrics({
          collection: 'responses',
          operation: 'find',
          filter: { field: i },
          executionTime: 200, // Slow query
          resultCount: 1,
          timestamp: new Date()
        });
      }

      const summary = performanceMonitor.getPerformanceSummary();
      
      expect(summary.recommendations).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'high_slow_query_rate',
            priority: 'high'
          })
        ])
      );
    });

    test('should calculate hybrid index efficiency correctly', () => {
      // Add queries with different hybrid index usage
      const queries = [
        { collection: 'responses', operation: 'find', filter: { month: '2025-01', userId: new mongoose.Types.ObjectId(), authMethod: 'user' }, executionTime: 30, resultCount: 1, timestamp: new Date() },
        { collection: 'responses', operation: 'find', filter: { token: 'abc123' }, executionTime: 20, resultCount: 1, timestamp: new Date() },
        { collection: 'responses', operation: 'find', filter: { randomField: 'value' }, executionTime: 150, resultCount: 1, timestamp: new Date() }
      ];

      queries.forEach(query => performanceMonitor.recordQueryMetrics(query));

      const efficiency = performanceMonitor.calculateHybridIndexEfficiency();
      
      expect(efficiency.totalHybridQueries).toBe(2); // First two queries use hybrid indexes
      expect(efficiency.avgEfficiency).toBeGreaterThan(0.9); // High efficiency for indexed queries
      expect(efficiency.indexTypes).toHaveProperty('hybrid-user-unique');
      expect(efficiency.indexTypes).toHaveProperty('token-unique');
    });
  });

  describe('Data Export and Management', () => {
    test('should export performance data correctly', () => {
      // Add some test data
      performanceMonitor.recordQueryMetrics({
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01' },
        executionTime: 50,
        resultCount: 3,
        timestamp: new Date()
      });

      const exportData = performanceMonitor.exportPerformanceData();
      
      expect(exportData).toHaveProperty('timestamp');
      expect(exportData).toHaveProperty('config');
      expect(exportData).toHaveProperty('metrics');
      expect(exportData.metrics).toHaveProperty('aggregatedStats');
      expect(exportData.metrics).toHaveProperty('queries');
      expect(exportData.metrics).toHaveProperty('collections');
      expect(exportData.metrics).toHaveProperty('indexes');
    });

    test('should reset metrics correctly', () => {
      // Add some data
      performanceMonitor.recordQueryMetrics({
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01' },
        executionTime: 50,
        resultCount: 3,
        timestamp: new Date()
      });

      expect(performanceMonitor.metrics.queries.size).toBe(1);
      
      performanceMonitor.resetMetrics();
      
      expect(performanceMonitor.metrics.queries.size).toBe(0);
      expect(performanceMonitor.metrics.slowQueries).toHaveLength(0);
      expect(performanceMonitor.metrics.aggregatedStats.totalQueries).toBe(0);
    });

    test('should handle metrics buffer overflow', () => {
      const monitor = new DBPerformanceMonitor({ maxMetricsBuffer: 5 });
      
      // Add more slow queries than buffer can hold
      for (let i = 0; i < 10; i++) {
        monitor.recordQueryMetrics({
          collection: 'responses',
          operation: 'find',
          filter: { field: i },
          executionTime: 200, // Slow query
          resultCount: 1,
          timestamp: new Date()
        });
      }
      
      // Should maintain buffer limit
      expect(monitor.metrics.slowQueries.length).toBeLessThanOrEqual(5);
    });
  });

  describe('Query Signature Generation', () => {
    test('should generate consistent signatures for similar queries', () => {
      const filter1 = { month: '2025-01', userId: 'user1' };
      const filter2 = { month: '2025-02', userId: 'user2' };
      
      const signature1 = performanceMonitor.generateQuerySignature('responses', 'find', filter1);
      const signature2 = performanceMonitor.generateQuerySignature('responses', 'find', filter2);
      
      expect(signature1).toBe(signature2); // Same structure, different values
    });

    test('should generate different signatures for different query structures', () => {
      const filter1 = { month: '2025-01' };
      const filter2 = { token: 'abc123' };
      
      const signature1 = performanceMonitor.generateQuerySignature('responses', 'find', filter1);
      const signature2 = performanceMonitor.generateQuerySignature('responses', 'find', filter2);
      
      expect(signature1).not.toBe(signature2);
    });

    test('should handle complex nested filters', () => {
      const filter = {
        month: '2025-01',
        createdAt: { $gte: new Date(), $lt: new Date() },
        responses: { $elemMatch: { question: 'test' } }
      };
      
      const signature = performanceMonitor.generateQuerySignature('responses', 'find', filter);
      
      expect(typeof signature).toBe('string');
      expect(signature.length).toBeGreaterThan(0);
    });
  });

  describe('Filter Sanitization', () => {
    test('should sanitize sensitive data in filters', () => {
      const filter = {
        email: 'user@example.com',
        password: 'secretpassword',
        token: 'sensitivetoken',
        month: '2025-01'
      };

      const sanitized = performanceMonitor.sanitizeFilter(filter);
      
      expect(sanitized.password).toBe('[REDACTED]');
      expect(sanitized.token).toBe('[REDACTED]');
      expect(sanitized.email).toBe('user@example.com'); // Not in sensitive list
      expect(sanitized.month).toBe('2025-01');
    });

    test('should handle null and undefined filters', () => {
      expect(performanceMonitor.sanitizeFilter(null)).toBe(null);
      expect(performanceMonitor.sanitizeFilter(undefined)).toBe(undefined);
      expect(performanceMonitor.sanitizeFilter('string')).toBe('string');
    });
  });

  describe('Error Handling', () => {
    test('should handle errors in query metrics recording gracefully', () => {
      // Test with malformed query data
      const badQueryData = {
        collection: null,
        operation: undefined,
        filter: 'not an object',
        executionTime: 'not a number',
        timestamp: 'not a date'
      };

      expect(() => {
        performanceMonitor.recordQueryMetrics(badQueryData);
      }).not.toThrow();
    });

    test('should handle database connection errors during index analysis', async () => {
      // Mock mongoose.connection.db to throw error
      const originalDb = mongoose.connection.db;
      mongoose.connection.db = null;
      
      await performanceMonitor.analyzeCurrentIndexes();
      
      // Should not throw and should log error
      expect(performanceMonitor.metrics.indexes.size).toBe(0);
      
      // Restore
      mongoose.connection.db = originalDb;
    });
  });

  describe('Event Emission', () => {
    test('should emit events for query recording', (done) => {
      performanceMonitor.on('query-recorded', (queryData) => {
        expect(queryData).toHaveProperty('collection');
        expect(queryData).toHaveProperty('executionTime');
        done();
      });

      performanceMonitor.recordQueryMetrics({
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01' },
        executionTime: 30,
        resultCount: 1,
        timestamp: new Date()
      });
    });

    test('should emit events for slow query detection', (done) => {
      performanceMonitor.on('slow-query-detected', (queryData) => {
        expect(queryData.executionTime).toBeGreaterThanOrEqual(50);
        done();
      });

      performanceMonitor.recordQueryMetrics({
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01' },
        executionTime: 150, // Above threshold
        resultCount: 1,
        timestamp: new Date()
      });
    });
  });
});