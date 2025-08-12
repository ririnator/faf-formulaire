const RealTimeMetrics = require('../services/realTimeMetrics');
const DBPerformanceMonitor = require('../services/dbPerformanceMonitor');

describe('RealTimeMetrics', () => {
  let realTimeMetrics;
  let mockDbMonitor;

  beforeEach(() => {
    // Create mock DB monitor
    mockDbMonitor = {
      config: { slowQueryThreshold: 100 },
      analyzeHybridIndexUsage: jest.fn().mockReturnValue({ 
        type: 'hybrid-user-unique', 
        efficiency: 0.85 
      }),
      on: jest.fn(),
      removeAllListeners: jest.fn(),
      emit: jest.fn()
    };

    realTimeMetrics = new RealTimeMetrics(mockDbMonitor, {
      windowSize: 5 * 60 * 1000, // 5 minutes
      updateInterval: 1000, // 1 second for faster testing
      alertThresholds: {
        slowQueryRate: 0.2,
        avgExecutionTime: 150,
        queryVolume: 100,
        indexEfficiency: 0.7
      },
      retainWindows: 10
    });
  });

  afterEach(() => {
    if (realTimeMetrics && realTimeMetrics.isCollecting) {
      realTimeMetrics.stopCollection();
    }
  });

  describe('Initialization', () => {
    test('should initialize with correct configuration', () => {
      expect(realTimeMetrics.config.windowSize).toBe(5 * 60 * 1000);
      expect(realTimeMetrics.config.updateInterval).toBe(1000);
      expect(realTimeMetrics.config.alertThresholds.slowQueryRate).toBe(0.2);
      expect(realTimeMetrics.isCollecting).toBe(false);
    });

    test('should create initial window', () => {
      expect(realTimeMetrics.currentWindow).toBeDefined();
      expect(realTimeMetrics.currentWindow.queries).toEqual([]);
      expect(realTimeMetrics.currentWindow.totalQueries).toBe(0);
      expect(realTimeMetrics.windows).toEqual([]);
    });

    test('should initialize realtime stats', () => {
      expect(realTimeMetrics.realtimeStats).toBeDefined();
      expect(realTimeMetrics.realtimeStats.queriesPerSecond).toBe(0);
      expect(realTimeMetrics.realtimeStats.avgExecutionTime).toBe(0);
      expect(realTimeMetrics.realtimeStats.slowQueryRate).toBe(0);
    });
  });

  describe('Collection Lifecycle', () => {
    test('should start collection successfully', () => {
      realTimeMetrics.startCollection();
      
      expect(realTimeMetrics.isCollecting).toBe(true);
      expect(mockDbMonitor.on).toHaveBeenCalledWith('query-recorded', expect.any(Function));
      expect(mockDbMonitor.on).toHaveBeenCalledWith('slow-query-detected', expect.any(Function));
    });

    test('should stop collection successfully', () => {
      realTimeMetrics.startCollection();
      realTimeMetrics.stopCollection();
      
      expect(realTimeMetrics.isCollecting).toBe(false);
      expect(mockDbMonitor.removeAllListeners).toHaveBeenCalled();
    });

    test('should not start collection twice', () => {
      realTimeMetrics.startCollection();
      realTimeMetrics.startCollection();
      
      expect(realTimeMetrics.isCollecting).toBe(true);
    });

    test('should handle stop when not collecting', () => {
      expect(() => realTimeMetrics.stopCollection()).not.toThrow();
    });
  });

  describe('Query Recording', () => {
    beforeEach(() => {
      realTimeMetrics.startCollection();
    });

    test('should record queries in current window', () => {
      const queryData = {
        timestamp: new Date(),
        executionTime: 50,
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01' }
      };

      realTimeMetrics.handleQueryRecorded(queryData);
      
      expect(realTimeMetrics.currentWindow.queries).toHaveLength(1);
      expect(realTimeMetrics.currentWindow.totalQueries).toBe(1);
      expect(realTimeMetrics.currentWindow.totalExecutionTime).toBe(50);
    });

    test('should handle slow queries', () => {
      const slowQueryData = {
        timestamp: new Date(),
        executionTime: 200,
        collection: 'responses',
        operation: 'find',
        filter: { name: 'test' }
      };

      realTimeMetrics.handleSlowQueryDetected(slowQueryData);
      
      expect(realTimeMetrics.currentWindow.slowQueries).toBe(1);
    });

    test('should analyze hybrid index usage for queries', () => {
      const queryData = {
        timestamp: new Date(),
        executionTime: 50,
        collection: 'responses',
        operation: 'find',
        filter: { month: '2025-01', userId: 'user123' }
      };

      realTimeMetrics.handleQueryRecorded(queryData);
      
      expect(mockDbMonitor.analyzeHybridIndexUsage).toHaveBeenCalledWith(queryData.filter);
      expect(realTimeMetrics.currentWindow.queries[0].hybridIndex).toBeDefined();
    });

    test('should emit events for query recording', () => {
      const emitSpy = jest.spyOn(realTimeMetrics, 'emit');
      const queryData = {
        timestamp: new Date(),
        executionTime: 50,
        collection: 'responses',
        operation: 'find'
      };

      realTimeMetrics.handleQueryRecorded(queryData);
      
      expect(emitSpy).toHaveBeenCalledWith('query-added', queryData);
    });
  });

  describe('Window Management', () => {
    test('should create new windows correctly', () => {
      const window = realTimeMetrics.createWindow();
      
      expect(window.startTime).toBeInstanceOf(Date);
      expect(window.endTime).toBeNull();
      expect(window.queries).toEqual([]);
      expect(window.totalQueries).toBe(0);
      expect(window.slowQueries).toBe(0);
    });

    test('should aggregate windows correctly', () => {
      // Add some data to current window
      realTimeMetrics.currentWindow.queries.push({
        timestamp: new Date(),
        executionTime: 100,
        collection: 'responses',
        operation: 'find',
        hybridIndex: { type: 'hybrid-user-unique', efficiency: 0.9 }
      });
      realTimeMetrics.currentWindow.totalQueries = 1;
      realTimeMetrics.currentWindow.totalExecutionTime = 100;
      realTimeMetrics.currentWindow.slowQueries = 0;

      realTimeMetrics.aggregateCurrentWindow();
      
      expect(realTimeMetrics.windows).toHaveLength(1);
      expect(realTimeMetrics.windows[0].endTime).not.toBeNull();
      expect(realTimeMetrics.windows[0].stats).toBeDefined();
      expect(realTimeMetrics.windows[0].stats.avgExecutionTime).toBe(100);
      
      // Should create new current window
      expect(realTimeMetrics.currentWindow.queries).toEqual([]);
      expect(realTimeMetrics.currentWindow.totalQueries).toBe(0);
    });

    test('should maintain window count limit', () => {
      // Add windows beyond limit
      for (let i = 0; i < 15; i++) {
        realTimeMetrics.windows.push({
          startTime: new Date(Date.now() - i * 1000),
          endTime: new Date(Date.now() - i * 1000 + 500),
          stats: { avgExecutionTime: 50 }
        });
      }
      
      realTimeMetrics.aggregateCurrentWindow();
      
      expect(realTimeMetrics.windows.length).toBeLessThanOrEqual(realTimeMetrics.config.retainWindows);
    });

    test('should calculate window statistics correctly', () => {
      const window = {
        queries: [
          { executionTime: 50, collection: 'responses', hybridIndex: { efficiency: 0.9 } },
          { executionTime: 150, collection: 'responses', hybridIndex: { efficiency: 0.8 } }, // slow query
          { executionTime: 75, collection: 'users', hybridIndex: { efficiency: 0.95 } }
        ],
        totalQueries: 3,
        totalExecutionTime: 275,
        slowQueries: 1,
        duration: 5000, // 5 seconds
        collections: new Map(),
        hybridIndexUsage: new Map()
      };

      realTimeMetrics.calculateWindowStats(window);
      
      expect(window.stats.avgExecutionTime).toBe(275 / 3);
      expect(window.stats.queriesPerSecond).toBe(3 / 5);
      expect(window.stats.slowQueryRate).toBe(1 / 3);
      expect(window.stats.indexEfficiency).toBeCloseTo(0.883, 2); // Average of efficiencies
    });

    test('should get recent windows correctly', () => {
      const now = Date.now();
      
      // Add windows at different times
      realTimeMetrics.windows = [
        { endTime: new Date(now - 10 * 60 * 1000) }, // 10 minutes ago
        { endTime: new Date(now - 3 * 60 * 1000) },  // 3 minutes ago
        { endTime: new Date(now - 1 * 60 * 1000) }   // 1 minute ago
      ];
      
      const recentWindows = realTimeMetrics.getRecentWindows(5 * 60 * 1000); // 5 minutes
      
      expect(recentWindows).toHaveLength(2); // Last 2 windows within 5 minutes
    });
  });

  describe('Real-time Statistics Calculation', () => {
    beforeEach(() => {
      // Add some test windows
      realTimeMetrics.windows = [
        {
          startTime: new Date(Date.now() - 2 * 60 * 1000),
          endTime: new Date(Date.now() - 1 * 60 * 1000),
          duration: 60 * 1000,
          totalQueries: 10,
          slowQueries: 2,
          totalExecutionTime: 500,
          queries: [
            { hybridIndex: { type: 'hybrid-user-unique', efficiency: 0.9 } },
            { hybridIndex: { type: 'token-unique', efficiency: 0.95 } }
          ],
          stats: { indexEfficiency: 0.85 }
        },
        {
          startTime: new Date(Date.now() - 1 * 60 * 1000),
          endTime: new Date(),
          duration: 60 * 1000,
          totalQueries: 15,
          slowQueries: 1,
          totalExecutionTime: 600,
          queries: [
            { hybridIndex: { type: 'hybrid-user-unique', efficiency: 0.85 } }
          ],
          stats: { indexEfficiency: 0.90 }
        }
      ];
    });

    test('should calculate real-time statistics correctly', () => {
      realTimeMetrics.calculateRealtimeStats();
      
      const stats = realTimeMetrics.realtimeStats;
      
      expect(stats.queriesPerSecond).toBeCloseTo(25 / 120, 2); // 25 queries in 2 minutes
      expect(stats.avgExecutionTime).toBeCloseTo(1100 / 25, 2); // Total time / total queries
      expect(stats.slowQueryRate).toBeCloseTo(3 / 25, 2); // 3 slow queries out of 25
      expect(stats.hybridIndexEfficiency).toBeCloseTo(0.875, 2); // Average of window efficiencies
    });

    test('should handle empty windows gracefully', () => {
      realTimeMetrics.windows = [];
      realTimeMetrics.calculateRealtimeStats();
      
      // Should not throw and stats should remain at defaults
      expect(realTimeMetrics.realtimeStats.queriesPerSecond).toBe(0);
    });

    test('should calculate index hit ratio correctly', () => {
      const windows = [
        {
          queries: [
            { hybridIndex: { type: 'hybrid-user-unique' } },
            { hybridIndex: { type: 'collection-scan' } },
            { hybridIndex: { type: 'token-unique' } },
            { hybridIndex: { type: 'none' } }
          ]
        }
      ];

      const hitRatio = realTimeMetrics.calculateIndexHitRatio(windows);
      
      expect(hitRatio).toBeCloseTo(0.5, 2); // 2 out of 4 queries used indexes
    });
  });

  describe('Alert Management', () => {
    beforeEach(() => {
      realTimeMetrics.startCollection();
    });

    test('should trigger alerts when thresholds exceeded', () => {
      const emitSpy = jest.spyOn(realTimeMetrics, 'emit');
      
      // Set high slow query rate
      realTimeMetrics.realtimeStats.slowQueryRate = 0.3; // Above 0.2 threshold
      
      realTimeMetrics.checkSlowQueryAlert();
      
      expect(realTimeMetrics.activeAlerts.has('slow_query_rate')).toBe(true);
      expect(emitSpy).toHaveBeenCalledWith('alert-triggered', expect.any(Object));
    });

    test('should resolve alerts when conditions improve', () => {
      const emitSpy = jest.spyOn(realTimeMetrics, 'emit');
      
      // First trigger alert
      realTimeMetrics.realtimeStats.avgExecutionTime = 200; // Above 150 threshold
      realTimeMetrics.checkExecutionTimeAlert();
      
      expect(realTimeMetrics.activeAlerts.has('avg_execution_time')).toBe(true);
      
      // Then resolve it
      realTimeMetrics.realtimeStats.avgExecutionTime = 100; // Below threshold
      realTimeMetrics.checkExecutionTimeAlert();
      
      expect(realTimeMetrics.activeAlerts.has('avg_execution_time')).toBe(false);
      expect(emitSpy).toHaveBeenCalledWith('alert-resolved', expect.any(Object));
    });

    test('should track alert statistics', () => {
      // Trigger and resolve alerts
      realTimeMetrics.realtimeStats.slowQueryRate = 0.3;
      realTimeMetrics.checkSlowQueryAlert();
      
      realTimeMetrics.realtimeStats.slowQueryRate = 0.1;
      realTimeMetrics.checkSlowQueryAlert();
      
      // Check that alert count is updated in real-time stats
      realTimeMetrics.calculateRealtimeStats();
      expect(realTimeMetrics.realtimeStats.alertsCount).toBe(0); // Should be resolved
    });

    test('should handle multiple alert types', () => {
      realTimeMetrics.realtimeStats.slowQueryRate = 0.3;
      realTimeMetrics.realtimeStats.avgExecutionTime = 200;
      realTimeMetrics.realtimeStats.hybridIndexEfficiency = 0.5;
      
      realTimeMetrics.checkAlerts();
      
      expect(realTimeMetrics.activeAlerts.size).toBe(3);
      expect(realTimeMetrics.activeAlerts.has('slow_query_rate')).toBe(true);
      expect(realTimeMetrics.activeAlerts.has('avg_execution_time')).toBe(true);
      expect(realTimeMetrics.activeAlerts.has('index_efficiency')).toBe(true);
    });
  });

  describe('Window Analysis', () => {
    beforeEach(() => {
      // Setup test windows with collection and index usage data
      realTimeMetrics.windows = [
        {
          startTime: new Date(Date.now() - 2 * 60 * 1000),
          endTime: new Date(Date.now() - 1 * 60 * 1000),
          totalQueries: 10,
          collections: new Map([
            ['responses', { count: 8, totalTime: 400, slowCount: 1 }],
            ['users', { count: 2, totalTime: 100, slowCount: 0 }]
          ]),
          hybridIndexUsage: new Map([
            ['hybrid-user-unique', { count: 5, totalEfficiency: 4.5, totalTime: 250 }],
            ['token-unique', { count: 3, totalEfficiency: 2.85, totalTime: 150 }]
          ])
        }
      ];
    });

    test('should provide detailed window analysis', () => {
      const analysis = realTimeMetrics.getWindowAnalysis();
      
      expect(analysis).toHaveProperty('windowsAnalyzed');
      expect(analysis).toHaveProperty('collections');
      expect(analysis).toHaveProperty('hybridIndexUsage');
      
      expect(analysis.collections).toHaveLength(2);
      expect(analysis.hybridIndexUsage).toHaveLength(2);
      
      const responsesCollection = analysis.collections.find(c => c.name === 'responses');
      expect(responsesCollection.totalQueries).toBe(8);
      expect(responsesCollection.avgTime).toBe(50); // 400/8
      expect(responsesCollection.slowQueryRate).toBe(0.125); // 1/8
    });

    test('should handle empty analysis gracefully', () => {
      realTimeMetrics.windows = [];
      
      const analysis = realTimeMetrics.getWindowAnalysis();
      
      expect(analysis).toHaveProperty('error');
      expect(analysis.error).toBe('No data available');
    });

    test('should filter analysis by timespan', () => {
      const timespan = 30 * 60 * 1000; // 30 minutes
      
      const analysis = realTimeMetrics.getWindowAnalysis(timespan);
      
      expect(analysis.timespan).toBe(timespan);
      expect(analysis.windowsAnalyzed).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Data Export and Management', () => {
    test('should export metrics data correctly', () => {
      // Add some test data
      realTimeMetrics.windows.push({
        startTime: new Date(),
        endTime: new Date(),
        totalQueries: 5
      });
      
      realTimeMetrics.activeAlerts.set('test_alert', {
        ruleId: 'test',
        severity: 'medium',
        triggeredAt: new Date()
      });

      const exportData = realTimeMetrics.exportMetricsData();
      
      expect(exportData).toHaveProperty('timestamp');
      expect(exportData).toHaveProperty('config');
      expect(exportData).toHaveProperty('realtimeStats');
      expect(exportData).toHaveProperty('windows');
      expect(exportData).toHaveProperty('activeAlerts');
      expect(exportData).toHaveProperty('alertHistory');
      
      expect(exportData.windows).toHaveLength(1);
      expect(exportData.activeAlerts).toHaveLength(1);
    });

    test('should reset metrics correctly', () => {
      // Add some data
      realTimeMetrics.windows.push({ startTime: new Date() });
      realTimeMetrics.activeAlerts.set('test', { severity: 'high' });
      realTimeMetrics.alertHistory.push({ ruleId: 'test' });
      
      realTimeMetrics.resetMetrics();
      
      expect(realTimeMetrics.windows).toHaveLength(0);
      expect(realTimeMetrics.activeAlerts.size).toBe(0);
      expect(realTimeMetrics.alertHistory).toHaveLength(0);
      expect(realTimeMetrics.realtimeStats.queriesPerSecond).toBe(0);
    });

    test('should get current stats correctly', () => {
      realTimeMetrics.windows = [{ startTime: new Date() }];
      realTimeMetrics.activeAlerts.set('test', { severity: 'high' });

      const stats = realTimeMetrics.getCurrentStats();
      
      expect(stats).toHaveProperty('realtime');
      expect(stats).toHaveProperty('windows');
      expect(stats).toHaveProperty('alerts');
      
      expect(stats.windows.total).toBe(1);
      expect(stats.alerts.active).toBe(1);
    });
  });

  describe('Memory Usage Tracking', () => {
    test('should get memory usage information', () => {
      const memUsage = realTimeMetrics.getMemoryUsage();
      
      expect(memUsage).toHaveProperty('heapUsed');
      expect(memUsage).toHaveProperty('heapTotal');
      expect(memUsage).toHaveProperty('rss');
      expect(memUsage).toHaveProperty('external');
      expect(memUsage).toHaveProperty('heapUsedMB');
      expect(memUsage).toHaveProperty('heapTotalMB');
      
      expect(typeof memUsage.heapUsedMB).toBe('number');
      expect(memUsage.heapUsedMB).toBeGreaterThan(0);
    });

    test('should include memory usage in real-time stats', () => {
      realTimeMetrics.calculateRealtimeStats();
      
      expect(realTimeMetrics.realtimeStats.memoryUsage).toBeDefined();
      expect(realTimeMetrics.realtimeStats.memoryUsage.heapUsedMB).toBeGreaterThan(0);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid query data gracefully', () => {
      expect(() => {
        realTimeMetrics.handleQueryRecorded(null);
      }).not.toThrow();
      
      expect(() => {
        realTimeMetrics.handleQueryRecorded({});
      }).not.toThrow();
    });

    test('should handle errors in window calculation', () => {
      const invalidWindow = {
        queries: null,
        totalQueries: 'invalid',
        duration: null
      };
      
      expect(() => {
        realTimeMetrics.calculateWindowStats(invalidWindow);
      }).not.toThrow();
    });

    test('should handle DB monitor connection errors', () => {
      // Simulate DB monitor errors
      mockDbMonitor.analyzeHybridIndexUsage = jest.fn(() => {
        throw new Error('DB connection error');
      });
      
      expect(() => {
        realTimeMetrics.handleQueryRecorded({
          timestamp: new Date(),
          executionTime: 50,
          collection: 'responses',
          operation: 'find',
          filter: { month: '2025-01' }
        });
      }).not.toThrow();
    });
  });
});