const HybridIndexMonitor = require('../services/hybridIndexMonitor');
const PerformanceAlerting = require('../services/performanceAlerting');

// Mock SecureLogger to capture debug logs
jest.mock('../utils/secureLogger', () => ({
  logInfo: jest.fn(),
  logError: jest.fn(),
  logWarning: jest.fn(),
  logDebug: jest.fn()
}));

const SecureLogger = require('../utils/secureLogger');

// Mock mongoose to avoid connection issues during tests
jest.mock('mongoose', () => ({
  startSession: jest.fn().mockResolvedValue({
    withTransaction: jest.fn().mockImplementation(async (fn) => await fn()),
    endSession: jest.fn()
  }),
  Query: {
    prototype: {
      exec: jest.fn()
    }
  },
  connection: {
    db: {
      collections: jest.fn().mockResolvedValue([{
        collectionName: 'responses',
        aggregate: jest.fn().mockReturnValue({
          toArray: jest.fn().mockResolvedValue([])
        })
      }])
    }
  }
}));

describe('HybridIndexMonitor Safety Checks', () => {
  let monitor;

  beforeEach(async () => {
    jest.clearAllMocks();
    monitor = new HybridIndexMonitor({
      enableDetailedLogging: true,
      monitoringInterval: 1000,
      slowQueryThreshold: 50
    });
    
    // Start monitoring for tests that need it
    await monitor.startMonitoring();
  });

  afterEach(() => {
    if (monitor && monitor.isMonitoring) {
      monitor.stopMonitoring();
    }
  });

  describe('Query Interception Safety', () => {
    it('should handle query with null model', async () => {
      const mockQuery = {
        model: null
      };

      await monitor.analyzeQuery(mockQuery, 100, null);

      expect(monitor.debugMetrics.invalidQueryObjects).toBe(1);
      expect(SecureLogger.logDebug).toHaveBeenCalledWith(
        'Query analysis skipped - invalid query object',
        expect.objectContaining({
          hasGetQuery: false,
          invalidQueryCount: 1
        })
      );
    });

    it('should handle query with undefined model.collection', async () => {
      const mockQuery = {
        model: {},
        getQuery: jest.fn().mockReturnValue({})
      };

      // This would be caught earlier in setupQueryInterception, but testing analyzeQuery
      await monitor.analyzeQuery(mockQuery, 100, null);

      // Should proceed to analyze since getQuery exists
      expect(monitor.debugMetrics.invalidQueryObjects).toBe(0);
    });

    it('should handle query without getQuery method', async () => {
      const mockQuery = {
        model: { collection: { name: 'responses' } }
        // Missing getQuery method
      };

      await monitor.analyzeQuery(mockQuery, 100, null);

      expect(monitor.debugMetrics.invalidQueryObjects).toBe(1);
      expect(SecureLogger.logDebug).toHaveBeenCalledWith(
        'Query analysis skipped - invalid query object',
        expect.objectContaining({
          hasGetQuery: false,
          getQueryType: 'undefined'
        })
      );
    });

    it('should handle query with non-function getQuery', async () => {
      const mockQuery = {
        model: { collection: { name: 'responses' } },
        getQuery: 'not-a-function'
      };

      await monitor.analyzeQuery(mockQuery, 100, null);

      expect(monitor.debugMetrics.invalidQueryObjects).toBe(1);
      expect(SecureLogger.logDebug).toHaveBeenCalledWith(
        'Query analysis skipped - invalid query object',
        expect.objectContaining({
          hasGetQuery: true,
          getQueryType: 'string'
        })
      );
    });

    it('should continue monitoring after safety check failures', async () => {
      // First, analyze an invalid query
      const invalidQuery = { model: null };
      await monitor.analyzeQuery(invalidQuery, 100, null);

      // Then, analyze a valid query
      const validQuery = {
        model: { collection: { name: 'responses' } },
        getQuery: jest.fn().mockReturnValue({ userId: '123' })
      };

      await monitor.analyzeQuery(validQuery, 100, null);

      // Should have one invalid and monitoring should still work
      expect(monitor.debugMetrics.invalidQueryObjects).toBe(1);
      expect(validQuery.getQuery).toHaveBeenCalled();
    });
  });

  describe('Debug Metrics Tracking', () => {
    it('should track debug metrics correctly', async () => {
      const initialMetrics = monitor.getDebugMetrics();
      expect(initialMetrics.invalidQueryObjects).toBe(0);
      expect(initialMetrics.interceptRate).toBe('0%');

      // Trigger some invalid queries
      await monitor.analyzeQuery({ model: null }, 100, null);
      await monitor.analyzeQuery({ getQuery: 'invalid' }, 100, null);

      const updatedMetrics = monitor.getDebugMetrics();
      expect(updatedMetrics.invalidQueryObjects).toBe(2);
      expect(updatedMetrics.uptime).toBeGreaterThan(0);
    });

    it('should reset debug metrics', () => {
      // Add some metrics
      monitor.debugMetrics.invalidQueryObjects = 5;
      monitor.debugMetrics.totalQueriesIntercepted = 10;

      const beforeReset = monitor.getDebugMetrics();
      expect(beforeReset.invalidQueryObjects).toBe(5);

      monitor.resetDebugMetrics();

      const afterReset = monitor.getDebugMetrics();
      expect(afterReset.invalidQueryObjects).toBe(0);
      expect(afterReset.totalQueriesIntercepted).toBe(0);
      expect(SecureLogger.logInfo).toHaveBeenCalledWith('Hybrid index monitor debug metrics reset');
    });

    it('should calculate intercept rate correctly', () => {
      monitor.debugMetrics.totalQueriesIntercepted = 100;
      monitor.debugMetrics.invalidModelQueries = 25;

      const metrics = monitor.getDebugMetrics();
      expect(metrics.interceptRate).toBe('25.00%');
    });
  });

  describe('Error Recovery', () => {
    it('should continue functioning after JSON.stringify errors', async () => {
      const circularRef = {};
      circularRef.self = circularRef;

      const mockQuery = {
        model: { collection: { name: 'responses' } },
        getQuery: jest.fn().mockReturnValue(circularRef)
      };

      // Should not throw, should be caught and logged
      await expect(monitor.analyzeQuery(mockQuery, 100, null)).resolves.not.toThrow();
      
      expect(SecureLogger.logError).toHaveBeenCalledWith('Query analysis failed', expect.any(Error));
    });

    it('should handle monitoring state changes gracefully', async () => {
      monitor.isMonitoring = true;
      
      const mockQuery = {
        model: { collection: { name: 'responses' } },
        getQuery: jest.fn().mockReturnValue({ test: true })
      };

      await monitor.analyzeQuery(mockQuery, 100, null);
      expect(mockQuery.getQuery).toHaveBeenCalled();

      // Stop monitoring mid-analysis
      monitor.isMonitoring = false;
      await monitor.analyzeQuery(mockQuery, 100, null);
      // Should return early without processing
    });
  });

  describe('Logging Behavior', () => {
    it('should only log debug messages when detailed logging is enabled', async () => {
      // Create monitor with detailed logging disabled
      const quietMonitor = new HybridIndexMonitor({
        enableDetailedLogging: false
      });

      const mockQuery = { model: null };
      await quietMonitor.analyzeQuery(mockQuery, 100, null);

      // Should still track metrics but not log debug messages
      expect(quietMonitor.debugMetrics.invalidQueryObjects).toBe(1);
      expect(SecureLogger.logDebug).not.toHaveBeenCalled();
    });

    it('should log debug messages when detailed logging is enabled', async () => {
      const mockQuery = { model: null };
      await monitor.analyzeQuery(mockQuery, 100, null);

      expect(SecureLogger.logDebug).toHaveBeenCalledWith(
        'Query analysis skipped - invalid query object',
        expect.any(Object)
      );
    });
  });
});

describe('PerformanceAlerting Safety Checks', () => {
  let mockRealTimeMetrics;
  let alerting;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockRealTimeMetrics = {
      getRecentWindows: jest.fn().mockReturnValue([])
    };

    alerting = new PerformanceAlerting(mockRealTimeMetrics, {
      enableDetailedLogging: true
    });
  });

  afterEach(() => {
    if (alerting.isActive) {
      alerting.stopAlerting();
    }
  });

  describe('Metrics Validation', () => {
    it('should handle null currentMetrics gracefully', () => {
      expect(() => {
        alerting.checkAlertConditions(null);
      }).not.toThrow();

      expect(SecureLogger.logDebug).toHaveBeenCalledWith(
        expect.stringContaining('skipped - metrics not available'),
        expect.objectContaining({
          hasCurrentMetrics: false
        })
      );
    });

    it('should handle missing realtime metrics', () => {
      const incompleteMetrics = {
        // Missing realtime property
        historical: {}
      };

      expect(() => {
        alerting.checkAlertConditions(incompleteMetrics);
      }).not.toThrow();

      expect(SecureLogger.logDebug).toHaveBeenCalledWith(
        expect.stringContaining('skipped - metrics not available'),
        expect.objectContaining({
          hasRealtimeMetrics: false
        })
      );
    });

    it('should process valid metrics without safety check triggers', () => {
      const validMetrics = {
        realtime: {
          slowQueryRate: 0.1,
          avgExecutionTime: 150,
          hybridIndexEfficiency: 0.9,
          queriesPerSecond: 10,
          memoryUsage: { heapUsedMB: 200 }
        }
      };

      expect(() => {
        alerting.checkAlertConditions(validMetrics);
      }).not.toThrow();

      // Should not have logged any safety check messages
      expect(SecureLogger.logDebug).not.toHaveBeenCalledWith(
        expect.stringContaining('skipped - metrics not available'),
        expect.any(Object)
      );
    });
  });

  describe('Alert Rule Condition Safety', () => {
    it('should handle undefined properties in slowQueryRate condition', () => {
      const metricsWithMissingProperty = {
        realtime: {
          // Missing slowQueryRate
          avgExecutionTime: 150
        }
      };

      expect(() => {
        alerting.checkAlertConditions(metricsWithMissingProperty);
      }).not.toThrow();

      // Condition should return false for missing property
      const slowQueryRule = alerting.alertRules.get('slow_query_rate');
      expect(slowQueryRule.condition(metricsWithMissingProperty.realtime)).toBe(false);
    });

    it('should handle non-numeric values in avgExecutionTime condition', () => {
      const metricsWithInvalidType = {
        realtime: {
          avgExecutionTime: 'not-a-number'
        }
      };

      const avgTimeRule = alerting.alertRules.get('avg_execution_time');
      expect(avgTimeRule.condition(metricsWithInvalidType.realtime)).toBe(false);
    });

    it('should handle missing memoryUsage object in memory condition', () => {
      const metricsWithoutMemory = {
        realtime: {
          // Missing memoryUsage
        }
      };

      const memoryRule = alerting.alertRules.get('memory_usage');
      expect(memoryRule.condition(metricsWithoutMemory.realtime)).toBe(false);
    });

    it('should handle incomplete memoryUsage object', () => {
      const metricsWithIncompleteMemory = {
        realtime: {
          memoryUsage: {
            // Missing heapUsedMB property
            totalMB: 1000
          }
        }
      };

      const memoryRule = alerting.alertRules.get('memory_usage');
      expect(memoryRule.condition(metricsWithIncompleteMemory.realtime)).toBe(false);
    });
  });

  describe('Historical Data Safety', () => {
    it('should handle missing historical data in query volume spike', () => {
      const metricsWithoutHistorical = {
        realtime: {
          queriesPerSecond: 100
        }
      };

      const volumeRule = alerting.alertRules.get('query_volume_spike');
      expect(volumeRule.condition(metricsWithoutHistorical.realtime, null)).toBe(false);
      expect(volumeRule.condition(metricsWithoutHistorical.realtime, [])).toBe(false);
      expect(volumeRule.condition(metricsWithoutHistorical.realtime, [{}])).toBe(false); // Too few entries
    });

    it('should handle corrupted historical data', () => {
      const metrics = {
        realtime: {
          queriesPerSecond: 100
        }
      };

      const corruptedHistorical = [
        { queriesPerSecond: 10 },
        { queriesPerSecond: null }, // Corrupted entry
        { queriesPerSecond: 15 },
        { queriesPerSecond: undefined } // Another corrupted entry
      ];

      const volumeRule = alerting.alertRules.get('query_volume_spike');
      expect(() => {
        volumeRule.condition(metrics.realtime, corruptedHistorical);
      }).not.toThrow();
    });
  });

  describe('Service Continuity', () => {
    it('should continue processing other rules when one rule fails', () => {
      const validMetrics = {
        realtime: {
          slowQueryRate: 0.5, // Should trigger alert
          avgExecutionTime: 300, // Should trigger alert
          queriesPerSecond: 50
        }
      };

      // Mock one rule to throw an error
      const originalCondition = alerting.alertRules.get('slow_query_rate').condition;
      alerting.alertRules.get('slow_query_rate').condition = () => {
        throw new Error('Test error in condition');
      };

      expect(() => {
        alerting.checkAlertConditions(validMetrics);
      }).not.toThrow();

      // Should have logged the error but continued processing
      expect(SecureLogger.logError).toHaveBeenCalledWith(
        'Error checking alert rule slow_query_rate',
        expect.any(Error)
      );

      // Restore original condition
      alerting.alertRules.get('slow_query_rate').condition = originalCondition;
    });

    it('should maintain alerting system state after errors', () => {
      alerting.startAlerting();
      expect(alerting.isActive).toBe(true);

      // Trigger an error condition
      alerting.checkAlertConditions(null);

      // System should still be active
      expect(alerting.isActive).toBe(true);
      
      alerting.stopAlerting();
    });
  });
});