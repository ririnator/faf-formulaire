const PerformanceAlerting = require('../services/performanceAlerting');
const RealTimeMetrics = require('../services/realTimeMetrics');

describe('PerformanceAlerting', () => {
  let alerting;
  let mockRealTimeMetrics;

  beforeEach(() => {
    // Create mock real-time metrics
    mockRealTimeMetrics = {
      config: {
        alertThresholds: {
          slowQueryRate: 0.15,
          avgExecutionTime: 150,
          queryVolume: 500,
          indexEfficiency: 0.75
        }
      },
      getRecentWindows: jest.fn().mockReturnValue([]),
      on: jest.fn(),
      removeAllListeners: jest.fn(),
      emit: jest.fn()
    };

    alerting = new PerformanceAlerting(mockRealTimeMetrics, {
      escalationTimeouts: {
        low: 1000,    // 1 second for faster testing
        medium: 2000, // 2 seconds
        high: 3000    // 3 seconds
      },
      notificationCooldown: 500, // 0.5 seconds
      autoRemediation: true
    });
  });

  afterEach(() => {
    if (alerting && alerting.isActive) {
      alerting.stopAlerting();
    }
  });

  describe('Initialization', () => {
    test('should initialize with default alert rules', () => {
      expect(alerting.alertRules.size).toBeGreaterThan(0);
      expect(alerting.alertRules.has('slow_query_rate')).toBe(true);
      expect(alerting.alertRules.has('avg_execution_time')).toBe(true);
      expect(alerting.alertRules.has('index_efficiency')).toBe(true);
    });

    test('should initialize with empty active alerts', () => {
      expect(alerting.activeNotifications.size).toBe(0);
      expect(alerting.escalationTimers.size).toBe(0);
      expect(alerting.suppressedAlerts.size).toBe(0);
    });

    test('should initialize alerting metrics', () => {
      expect(alerting.alertingMetrics.totalAlertsTriggered).toBe(0);
      expect(alerting.alertingMetrics.totalAlertsResolved).toBe(0);
      expect(alerting.alertingMetrics.escalationsTriggered).toBe(0);
    });

    test('should not be active initially', () => {
      expect(alerting.isActive).toBe(false);
    });
  });

  describe('Alert Rule Management', () => {
    test('should add custom alert rule', () => {
      const customRule = {
        name: 'Custom Rule',
        description: 'Test rule',
        condition: (metrics) => metrics.customValue > 100,
        severity: 'medium',
        cooldown: 5000,
        recommendations: ['Fix the issue']
      };

      alerting.addAlertRule('custom_rule', customRule);
      
      expect(alerting.alertRules.has('custom_rule')).toBe(true);
      const rule = alerting.alertRules.get('custom_rule');
      expect(rule.name).toBe('Custom Rule');
      expect(rule.severity).toBe('medium');
    });

    test('should remove alert rule', () => {
      expect(alerting.removeAlertRule('slow_query_rate')).toBe(true);
      expect(alerting.alertRules.has('slow_query_rate')).toBe(false);
      
      expect(alerting.removeAlertRule('nonexistent_rule')).toBe(false);
    });

    test('should update alert rule', () => {
      const updates = {
        severity: 'critical',
        cooldown: 10000
      };

      expect(alerting.updateAlertRule('slow_query_rate', updates)).toBe(true);
      
      const rule = alerting.alertRules.get('slow_query_rate');
      expect(rule.severity).toBe('critical');
      expect(rule.cooldown).toBe(10000);
      expect(rule.name).toBe('High Slow Query Rate'); // Should keep original name
    });

    test('should handle updating nonexistent rule', () => {
      expect(alerting.updateAlertRule('nonexistent_rule', { severity: 'high' })).toBe(false);
    });

    test('should get all alert rules', () => {
      const rules = alerting.getAlertRules();
      
      expect(Array.isArray(rules)).toBe(true);
      expect(rules.length).toBeGreaterThan(0);
      expect(rules[0]).toHaveProperty('id');
      expect(rules[0]).toHaveProperty('name');
      expect(rules[0]).toHaveProperty('severity');
    });
  });

  describe('Alerting Lifecycle', () => {
    test('should start alerting successfully', () => {
      alerting.startAlerting();
      
      expect(alerting.isActive).toBe(true);
      expect(mockRealTimeMetrics.on).toHaveBeenCalledWith('metrics-updated', expect.any(Function));
      expect(mockRealTimeMetrics.on).toHaveBeenCalledWith('alert-triggered', expect.any(Function));
      expect(mockRealTimeMetrics.on).toHaveBeenCalledWith('alert-resolved', expect.any(Function));
    });

    test('should stop alerting successfully', () => {
      alerting.startAlerting();
      alerting.stopAlerting();
      
      expect(alerting.isActive).toBe(false);
      expect(mockRealTimeMetrics.removeAllListeners).toHaveBeenCalled();
    });

    test('should not start alerting twice', () => {
      alerting.startAlerting();
      alerting.startAlerting();
      
      expect(alerting.isActive).toBe(true);
    });

    test('should handle stop when not active', () => {
      expect(() => alerting.stopAlerting()).not.toThrow();
    });
  });

  describe('Alert Condition Checking', () => {
    beforeEach(() => {
      alerting.startAlerting();
    });

    test('should trigger alert when condition is met', () => {
      const emitSpy = jest.spyOn(alerting, 'emit');
      const currentMetrics = {
        realtime: {
          slowQueryRate: 0.25 // Above 0.15 threshold
        }
      };

      alerting.checkAlertConditions(currentMetrics);
      
      expect(alerting.activeNotifications.has('slow_query_rate')).toBe(true);
      expect(emitSpy).toHaveBeenCalledWith('alert-triggered', expect.any(Object));
      expect(alerting.alertingMetrics.totalAlertsTriggered).toBe(1);
    });

    test('should not trigger alert when condition is not met', () => {
      const currentMetrics = {
        realtime: {
          slowQueryRate: 0.05 // Below threshold
        }
      };

      alerting.checkAlertConditions(currentMetrics);
      
      expect(alerting.activeNotifications.size).toBe(0);
      expect(alerting.alertingMetrics.totalAlertsTriggered).toBe(0);
    });

    test('should respect cooldown periods', () => {
      const currentMetrics = {
        realtime: {
          slowQueryRate: 0.25
        }
      };

      // First trigger
      alerting.checkAlertConditions(currentMetrics);
      expect(alerting.activeNotifications.size).toBe(1);
      
      // Should not trigger again immediately (within cooldown)
      alerting.checkAlertConditions(currentMetrics);
      expect(alerting.alertingMetrics.totalAlertsTriggered).toBe(1);
    });

    test('should handle multiple alert types', () => {
      const currentMetrics = {
        realtime: {
          slowQueryRate: 0.25, // Above threshold
          avgExecutionTime: 200, // Above threshold
          hybridIndexEfficiency: 0.5 // Below threshold
        }
      };

      alerting.checkAlertConditions(currentMetrics);
      
      expect(alerting.activeNotifications.size).toBe(3);
      expect(alerting.alertingMetrics.totalAlertsTriggered).toBe(3);
    });

    test('should handle suppressed alerts', () => {
      alerting.suppressAlert('slow_query_rate', 1000);
      
      const currentMetrics = {
        realtime: {
          slowQueryRate: 0.25
        }
      };

      alerting.checkAlertConditions(currentMetrics);
      
      expect(alerting.activeNotifications.size).toBe(0);
    });

    test('should handle errors in condition checking gracefully', () => {
      // Add rule with faulty condition
      alerting.addAlertRule('faulty_rule', {
        name: 'Faulty Rule',
        condition: () => { throw new Error('Test error'); },
        severity: 'low'
      });

      const currentMetrics = { realtime: {} };

      expect(() => {
        alerting.checkAlertConditions(currentMetrics);
      }).not.toThrow();
    });
  });

  describe('Alert Resolution', () => {
    beforeEach(() => {
      alerting.startAlerting();
    });

    test('should resolve alerts when conditions improve', () => {
      const emitSpy = jest.spyOn(alerting, 'emit');
      
      // First trigger alert
      alerting.triggerAlert('slow_query_rate', alerting.alertRules.get('slow_query_rate'), {
        slowQueryRate: 0.25
      });
      
      expect(alerting.activeNotifications.has('slow_query_rate')).toBe(true);
      
      // Then resolve it
      alerting.resolveAlert('slow_query_rate');
      
      expect(alerting.activeNotifications.has('slow_query_rate')).toBe(false);
      expect(alerting.alertingMetrics.totalAlertsResolved).toBe(1);
      expect(emitSpy).toHaveBeenCalledWith('alert-resolved', expect.any(Object));
    });

    test('should handle resolution of non-existent alerts', () => {
      expect(() => {
        alerting.resolveAlert('nonexistent_alert');
      }).not.toThrow();
      
      expect(alerting.alertingMetrics.totalAlertsResolved).toBe(0);
    });

    test('should clear escalation timers on resolution', () => {
      // Trigger alert (creates escalation timer)
      alerting.triggerAlert('slow_query_rate', alerting.alertRules.get('slow_query_rate'), {});
      
      expect(alerting.escalationTimers.has('slow_query_rate')).toBe(true);
      
      // Resolve alert
      alerting.resolveAlert('slow_query_rate');
      
      expect(alerting.escalationTimers.has('slow_query_rate')).toBe(false);
    });
  });

  describe('Alert Escalation', () => {
    beforeEach(() => {
      alerting.startAlerting();
    });

    test('should escalate alerts after timeout', (done) => {
      const emitSpy = jest.spyOn(alerting, 'emit');
      
      const alert = {
        ruleId: 'slow_query_rate',
        ruleName: 'High Slow Query Rate',
        severity: 'medium'
      };

      alerting.setupEscalationTimer(alert);
      
      setTimeout(() => {
        expect(alert.severity).toBe('high');
        expect(alert.escalated).toBe(true);
        expect(alerting.alertingMetrics.escalationsTriggered).toBe(1);
        expect(emitSpy).toHaveBeenCalledWith('alert-escalated', expect.any(Object));
        done();
      }, 2500); // Wait for escalation timeout
    });

    test('should not escalate already critical alerts', () => {
      const alert = {
        ruleId: 'test_alert',
        severity: 'critical'
      };

      alerting.escalateAlert(alert);
      
      expect(alert.severity).toBe('critical'); // Should remain critical
      expect(alerting.alertingMetrics.escalationsTriggered).toBe(0);
    });

    test('should clear escalation timer', () => {
      const timer = setTimeout(() => {}, 1000);
      alerting.escalationTimers.set('test_rule', timer);
      
      alerting.clearEscalationTimer('test_rule');
      
      expect(alerting.escalationTimers.has('test_rule')).toBe(false);
    });
  });

  describe('Auto-remediation', () => {
    beforeEach(() => {
      alerting.startAlerting();
    });

    test('should attempt auto-remediation when enabled', async () => {
      const alert = {
        ruleId: 'avg_execution_time',
        ruleName: 'High Average Execution Time',
        metrics: { avgExecutionTime: 200 }
      };

      const remediationConfig = {
        enabled: true,
        actions: ['performance_analysis', 'index_analysis']
      };

      await alerting.attemptAutoRemediation(alert, remediationConfig);
      
      expect(alert.autoRemediationAttempted).toBe(true);
      expect(alert.autoRemediationResults).toBeDefined();
      expect(alert.autoRemediationResults).toHaveLength(2);
      expect(alerting.alertingMetrics.autoRemediationsAttempted).toBe(1);
    });

    test('should execute specific remediation actions', async () => {
      const alert = {
        ruleId: 'index_efficiency',
        metrics: { hybridIndexEfficiency: 0.5 }
      };

      const result = await alerting.executeRemediationAction('hybrid_index_analysis', alert);
      
      expect(result.success).toBe(true);
      expect(result.action).toBe('hybrid_index_analysis');
      expect(result.results).toBeDefined();
      expect(result.timestamp).toBeInstanceOf(Date);
    });

    test('should handle unknown remediation actions', async () => {
      const result = await alerting.executeRemediationAction('unknown_action', {});
      
      expect(result.success).toBe(false);
      expect(result.message).toBe('Unknown remediation action');
    });

    test('should handle remediation errors gracefully', async () => {
      // Mock a remediation action that throws
      const originalMethod = alerting.performIndexAnalysis;
      alerting.performIndexAnalysis = jest.fn().mockRejectedValue(new Error('Test error'));

      const result = await alerting.executeRemediationAction('index_analysis', {});
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Test error');
      
      // Restore original method
      alerting.performIndexAnalysis = originalMethod;
    });

    test('should emit auto-remediation events', async () => {
      const emitSpy = jest.spyOn(alerting, 'emit');
      
      const alert = { ruleId: 'test' };
      const remediationConfig = { enabled: true, actions: ['performance_analysis'] };

      await alerting.attemptAutoRemediation(alert, remediationConfig);
      
      expect(emitSpy).toHaveBeenCalledWith('auto-remediation-attempted', expect.any(Object));
    });
  });

  describe('Historical Metrics Analysis', () => {
    test('should get historical metrics for trend analysis', () => {
      const mockWindows = [
        {
          endTime: new Date(Date.now() - 1000),
          stats: {
            queriesPerSecond: 10,
            avgTime: 50,
            slowQueryRate: 0.1,
            indexEfficiency: 0.9
          }
        },
        {
          endTime: new Date(Date.now() - 2000),
          stats: {
            queriesPerSecond: 15,
            avgTime: 75,
            slowQueryRate: 0.2,
            indexEfficiency: 0.8
          }
        }
      ];

      mockRealTimeMetrics.getRecentWindows = jest.fn().mockReturnValue(mockWindows);
      
      const historical = alerting.getHistoricalMetrics(2);
      
      expect(historical).toHaveLength(2);
      expect(historical[0].queriesPerSecond).toBe(15);
      expect(historical[1].queriesPerSecond).toBe(10);
    });

    test('should handle trend-based alerts', () => {
      const historical = [
        { queriesPerSecond: 10 },
        { queriesPerSecond: 12 },
        { queriesPerSecond: 11 }
      ];

      mockRealTimeMetrics.getRecentWindows = jest.fn().mockReturnValue([]);
      alerting.getHistoricalMetrics = jest.fn().mockReturnValue(historical);

      const currentMetrics = {
        realtime: { queriesPerSecond: 30 } // Spike: 30 vs avg ~11
      };

      alerting.checkAlertConditions(currentMetrics);
      
      expect(alerting.activeNotifications.has('query_volume_spike')).toBe(true);
    });
  });

  describe('Alert Suppression', () => {
    test('should suppress alerts for specified duration', (done) => {
      alerting.suppressAlert('slow_query_rate', 100); // 100ms
      
      expect(alerting.suppressedAlerts.has('slow_query_rate')).toBe(true);
      
      setTimeout(() => {
        expect(alerting.suppressedAlerts.has('slow_query_rate')).toBe(false);
        done();
      }, 150);
    });

    test('should not trigger suppressed alerts', () => {
      alerting.suppressAlert('slow_query_rate');
      alerting.startAlerting();
      
      const currentMetrics = {
        realtime: { slowQueryRate: 0.25 }
      };

      alerting.checkAlertConditions(currentMetrics);
      
      expect(alerting.activeNotifications.size).toBe(0);
    });
  });

  describe('Status and Reporting', () => {
    test('should get alerting system status', () => {
      alerting.startAlerting();
      alerting.activeNotifications.set('test_alert', new Date());
      
      const status = alerting.getAlertingStatus();
      
      expect(status.isActive).toBe(true);
      expect(status.metrics).toBeDefined();
      expect(status.rules.total).toBeGreaterThan(0);
      expect(status.activeAlerts).toBe(1);
      expect(status.config).toBeDefined();
    });

    test('should export alerting data', () => {
      alerting.activeNotifications.set('test', new Date());
      alerting.suppressedAlerts.add('suppressed_test');
      
      const exportData = alerting.exportAlertingData();
      
      expect(exportData.timestamp).toBeInstanceOf(Date);
      expect(exportData.status).toBeDefined();
      expect(exportData.rules).toBeDefined();
      expect(exportData.activeNotifications).toHaveLength(1);
      expect(exportData.suppressedAlerts).toHaveLength(1);
    });

    test('should reset alerting metrics', () => {
      // Set some metrics
      alerting.alertingMetrics.totalAlertsTriggered = 5;
      alerting.alertingMetrics.escalationsTriggered = 2;
      
      const rule = alerting.alertRules.get('slow_query_rate');
      rule.triggeredCount = 3;
      
      alerting.resetMetrics();
      
      expect(alerting.alertingMetrics.totalAlertsTriggered).toBe(0);
      expect(alerting.alertingMetrics.escalationsTriggered).toBe(0);
      expect(rule.triggeredCount).toBe(0);
    });
  });

  describe('Notification System', () => {
    beforeEach(() => {
      alerting.startAlerting();
    });

    test('should send notifications for alerts', () => {
      const emitSpy = jest.spyOn(alerting, 'emit');
      
      const alert = {
        ruleName: 'Test Alert',
        severity: 'high',
        ruleId: 'test_rule'
      };

      alerting.sendNotification(alert);
      
      expect(emitSpy).toHaveBeenCalledWith('notification-sent', alert);
    });

    test('should handle real-time metrics alerts', () => {
      const alert = {
        key: 'realtime_alert',
        details: { message: 'Test alert' }
      };

      expect(() => {
        alerting.handleMetricsAlert(alert);
      }).not.toThrow();
    });

    test('should handle resolved real-time metrics alerts', () => {
      const alert = {
        key: 'resolved_alert'
      };

      expect(() => {
        alerting.handleMetricsAlertResolved(alert);
      }).not.toThrow();
    });
  });

  describe('Metrics Sanitization', () => {
    test('should sanitize metrics for logging', () => {
      const metrics = {
        avgExecutionTime: 150,
        slowQueryRate: 0.2,
        memoryUsage: { heapUsed: 1000000 },
        breakdown: { detailed: 'data' },
        safeField: 'safe_value'
      };

      const sanitized = alerting.sanitizeMetrics(metrics);
      
      expect(sanitized.avgExecutionTime).toBe(150);
      expect(sanitized.slowQueryRate).toBe(0.2);
      expect(sanitized.safeField).toBe('safe_value');
      expect(sanitized.memoryUsage).toBeUndefined();
      expect(sanitized.breakdown).toBeUndefined();
    });
  });

  describe('Error Handling', () => {
    test('should handle errors in condition evaluation', () => {
      alerting.addAlertRule('error_rule', {
        name: 'Error Rule',
        condition: () => { throw new Error('Condition error'); },
        severity: 'low'
      });

      alerting.startAlerting();
      
      expect(() => {
        alerting.checkAlertConditions({ realtime: {} });
      }).not.toThrow();
    });

    test('should handle missing real-time metrics gracefully', () => {
      const alertingWithoutMetrics = new PerformanceAlerting(null);
      
      expect(() => {
        alertingWithoutMetrics.getHistoricalMetrics();
      }).not.toThrow();
    });

    test('should handle cleanup during shutdown', () => {
      alerting.startAlerting();
      
      // Add some escalation timers
      alerting.escalationTimers.set('test1', setTimeout(() => {}, 1000));
      alerting.escalationTimers.set('test2', setTimeout(() => {}, 2000));
      
      alerting.stopAlerting();
      
      expect(alerting.escalationTimers.size).toBe(0);
    });
  });
});