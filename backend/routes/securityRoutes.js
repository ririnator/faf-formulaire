/**
 * Security Monitoring and Management Routes
 * 
 * Provides comprehensive security monitoring, event analysis,
 * and threat management capabilities for administrators.
 * 
 * Security Features:
 * - Real-time security dashboard
 * - Attack pattern analysis
 * - Threat source monitoring
 * - Security event export
 * - Incident management
 * 
 * @author FAF Security Team
 * @version 2.0.0
 */

const express = require('express');
const router = express.Router();
const { globalSecurityMonitor } = require('../utils/securityMonitoring');
const { getSecurityEvents, clearSecurityEvents } = require('../middleware/querySanitization');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { createQuerySanitizationMiddleware } = require('../middleware/querySanitization');

// Apply middleware to all security routes
router.use(createAdminBodyParser());
router.use(createQuerySanitizationMiddleware());

// Middleware to ensure admin authentication
function requireAdminAuth(req, res, next) {
  if (!req.session || !req.session.isAdmin) {
    return res.status(401).json({
      error: 'Admin authentication required',
      code: 'AUTH_REQUIRED'
    });
  }
  next();
}

// Apply admin authentication to all routes
router.use(requireAdminAuth);

/**
 * GET /api/security/dashboard
 * Get comprehensive security dashboard data
 */
router.get('/dashboard', async (req, res) => {
  try {
    const dashboardData = globalSecurityMonitor.getDashboardData();
    const querySanitizationEvents = getSecurityEvents();
    
    // Combine data from different security sources
    const combinedData = {
      ...dashboardData,
      querySecurityEvents: {
        total: querySanitizationEvents.length,
        recent: querySanitizationEvents.slice(-20)
      },
      systemStatus: {
        monitoring: {
          active: true,
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          nodeVersion: process.version
        },
        security: {
          realTimeAnalysis: globalSecurityMonitor.config.enableRealTimeAnalysis,
          eventRetention: globalSecurityMonitor.config.retentionPeriod / (24 * 60 * 60 * 1000), // days
          maxEvents: globalSecurityMonitor.config.maxEvents
        }
      }
    };

    res.json({
      success: true,
      data: combinedData,
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting security dashboard:', error);
    res.status(500).json({
      error: 'Failed to get security dashboard data',
      code: 'DASHBOARD_ERROR'
    });
  }
});

/**
 * GET /api/security/events
 * Get security events with filtering and pagination
 */
router.get('/events', async (req, res) => {
  try {
    const {
      severity,
      source,
      eventType,
      limit = 100,
      offset = 0,
      startDate,
      endDate,
      ipAddress
    } = req.query;

    // Get all events from security monitor
    const allEvents = [...globalSecurityMonitor.events];
    
    // Apply filters
    let filteredEvents = allEvents;
    
    if (severity) {
      filteredEvents = filteredEvents.filter(e => e.severity === severity);
    }
    
    if (source) {
      filteredEvents = filteredEvents.filter(e => e.source === source);
    }
    
    if (eventType) {
      filteredEvents = filteredEvents.filter(e => e.event.includes(eventType));
    }
    
    if (ipAddress) {
      filteredEvents = filteredEvents.filter(e => 
        e.metadata?.ipAddress === ipAddress
      );
    }
    
    if (startDate) {
      const start = new Date(startDate);
      filteredEvents = filteredEvents.filter(e => e.timestamp >= start);
    }
    
    if (endDate) {
      const end = new Date(endDate);
      filteredEvents = filteredEvents.filter(e => e.timestamp <= end);
    }

    // Sort by timestamp (newest first)
    filteredEvents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    // Apply pagination
    const paginatedEvents = filteredEvents.slice(
      parseInt(offset), 
      parseInt(offset) + parseInt(limit)
    );

    res.json({
      success: true,
      data: {
        events: paginatedEvents,
        pagination: {
          total: filteredEvents.length,
          limit: parseInt(limit),
          offset: parseInt(offset),
          hasMore: filteredEvents.length > parseInt(offset) + parseInt(limit)
        },
        filters: {
          severity,
          source,
          eventType,
          ipAddress,
          startDate,
          endDate
        }
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting security events:', error);
    res.status(500).json({
      error: 'Failed to get security events',
      code: 'EVENTS_ERROR'
    });
  }
});

/**
 * GET /api/security/threats
 * Get threat analysis and top threat sources
 */
router.get('/threats', async (req, res) => {
  try {
    const { timeRange = '24h' } = req.query;
    
    // Calculate time range
    const now = Date.now();
    let timeRangeMs;
    switch (timeRange) {
      case '1h': timeRangeMs = 60 * 60 * 1000; break;
      case '24h': timeRangeMs = 24 * 60 * 60 * 1000; break;
      case '7d': timeRangeMs = 7 * 24 * 60 * 60 * 1000; break;
      case '30d': timeRangeMs = 30 * 24 * 60 * 60 * 1000; break;
      default: timeRangeMs = 24 * 60 * 60 * 1000;
    }
    
    const cutoffTime = now - timeRangeMs;
    
    // Get events in time range
    const recentEvents = globalSecurityMonitor.events.filter(e => 
      e.timestamp.getTime() > cutoffTime
    );

    // Analyze threat sources
    const threatSources = new Map();
    const attackTypes = new Map();
    const severityStats = { critical: 0, high: 0, medium: 0, low: 0 };

    recentEvents.forEach(event => {
      // Track threat sources
      if (event.metadata?.ipAddress) {
        const ip = event.metadata.ipAddress;
        const current = threatSources.get(ip) || {
          ip,
          events: 0,
          lastSeen: event.timestamp,
          severities: { critical: 0, high: 0, medium: 0, low: 0 },
          attackTypes: new Set()
        };
        
        current.events++;
        current.lastSeen = event.timestamp;
        current.severities[event.severity]++;
        
        if (event.metadata.attackType) {
          current.attackTypes.add(event.metadata.attackType);
        }
        
        threatSources.set(ip, current);
      }
      
      // Track attack types
      if (event.metadata?.attackType) {
        const type = event.metadata.attackType;
        attackTypes.set(type, (attackTypes.get(type) || 0) + 1);
      }
      
      // Track severity stats
      if (severityStats.hasOwnProperty(event.severity)) {
        severityStats[event.severity]++;
      }
    });

    // Convert to arrays and sort
    const topThreatSources = Array.from(threatSources.values())
      .map(source => ({
        ...source,
        attackTypes: Array.from(source.attackTypes),
        riskScore: source.severities.critical * 10 + 
                  source.severities.high * 5 + 
                  source.severities.medium * 2 + 
                  source.severities.low * 1
      }))
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 20);

    const topAttackTypes = Array.from(attackTypes.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([type, count]) => ({ type, count }));

    res.json({
      success: true,
      data: {
        timeRange,
        totalEvents: recentEvents.length,
        threatSources: topThreatSources,
        attackTypes: topAttackTypes,
        severityStats,
        trends: {
          eventsPerHour: Math.round(recentEvents.length / (timeRangeMs / (60 * 60 * 1000))),
          uniqueThreatSources: threatSources.size,
          uniqueAttackTypes: attackTypes.size
        }
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting threat analysis:', error);
    res.status(500).json({
      error: 'Failed to get threat analysis',
      code: 'THREATS_ERROR'
    });
  }
});

/**
 * GET /api/security/incidents
 * Get active security incidents
 */
router.get('/incidents', async (req, res) => {
  try {
    const activeIncidents = Array.from(globalSecurityMonitor.activeIncidents.values());
    
    // Sort by timestamp (newest first)
    activeIncidents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({
      success: true,
      data: {
        incidents: activeIncidents,
        summary: {
          total: activeIncidents.length,
          critical: activeIncidents.filter(i => i.severity === 'critical').length,
          high: activeIncidents.filter(i => i.severity === 'high').length,
          active: activeIncidents.filter(i => i.status === 'active').length
        }
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting incidents:', error);
    res.status(500).json({
      error: 'Failed to get security incidents',
      code: 'INCIDENTS_ERROR'
    });
  }
});

/**
 * POST /api/security/incidents/:id/resolve
 * Resolve a security incident
 */
router.post('/incidents/:id/resolve', async (req, res) => {
  try {
    const { id } = req.params;
    const { resolution, notes } = req.body;

    const incident = globalSecurityMonitor.activeIncidents.get(id);
    
    if (!incident) {
      return res.status(404).json({
        error: 'Incident not found',
        code: 'INCIDENT_NOT_FOUND'
      });
    }

    // Update incident status
    incident.status = 'resolved';
    incident.resolvedAt = new Date();
    incident.resolution = {
      resolvedBy: req.session.adminId || 'admin',
      resolution: resolution || 'manual_resolution',
      notes: notes || '',
      timestamp: new Date()
    };

    globalSecurityMonitor.activeIncidents.set(id, incident);

    // Log resolution
    globalSecurityMonitor.recordEvent({
      event: 'INCIDENT_RESOLVED',
      severity: 'low',
      source: 'admin_action',
      metadata: {
        incidentId: id,
        resolvedBy: req.session.adminId || 'admin',
        resolution: resolution
      }
    });

    res.json({
      success: true,
      data: {
        incident,
        message: 'Incident resolved successfully'
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error resolving incident:', error);
    res.status(500).json({
      error: 'Failed to resolve incident',
      code: 'RESOLVE_ERROR'
    });
  }
});

/**
 * GET /api/security/export
 * Export security data for analysis
 */
router.get('/export', async (req, res) => {
  try {
    const {
      format = 'json',
      includeEvents = 'true',
      includePatterns = 'true',
      includeMetrics = 'true',
      includeIncidents = 'true',
      startDate,
      endDate
    } = req.query;

    const options = {
      includeEvents: includeEvents === 'true',
      includePatterns: includePatterns === 'true',
      includeMetrics: includeMetrics === 'true',
      includeIncidents: includeIncidents === 'true'
    };

    if (startDate && endDate) {
      options.timeRange = {
        start: startDate,
        end: endDate
      };
    }

    const exportData = globalSecurityMonitor.exportSecurityData(options);
    
    // Add query sanitization events
    if (options.includeEvents) {
      exportData.querySanitizationEvents = getSecurityEvents();
    }

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 
        `attachment; filename="security-export-${Date.now()}.json"`
      );
      res.json(exportData);
    } else {
      res.status(400).json({
        error: 'Unsupported export format. Use: json',
        code: 'INVALID_FORMAT'
      });
    }

  } catch (error) {
    console.error('❌ Error exporting security data:', error);
    res.status(500).json({
      error: 'Failed to export security data',
      code: 'EXPORT_ERROR'
    });
  }
});

/**
 * POST /api/security/clear-events
 * Clear security events (admin only, with confirmation)
 */
router.post('/clear-events', async (req, res) => {
  try {
    const { confirm, source } = req.body;

    if (!confirm || confirm !== 'CLEAR_SECURITY_EVENTS') {
      return res.status(400).json({
        error: 'Confirmation required. Set confirm to "CLEAR_SECURITY_EVENTS"',
        code: 'CONFIRMATION_REQUIRED'
      });
    }

    let clearedCount = 0;

    if (source === 'querySanitization') {
      const events = getSecurityEvents();
      clearedCount = events.length;
      clearSecurityEvents();
    } else if (source === 'securityMonitor') {
      clearedCount = globalSecurityMonitor.events.length;
      globalSecurityMonitor.events = [];
      globalSecurityMonitor.attackPatterns.clear();
      globalSecurityMonitor.threatSources.clear();
    } else {
      // Clear all
      const queryEvents = getSecurityEvents();
      const monitorEvents = globalSecurityMonitor.events.length;
      clearedCount = queryEvents.length + monitorEvents;
      
      clearSecurityEvents();
      globalSecurityMonitor.events = [];
      globalSecurityMonitor.attackPatterns.clear();
      globalSecurityMonitor.threatSources.clear();
    }

    // Log the clear action
    globalSecurityMonitor.recordEvent({
      event: 'SECURITY_EVENTS_CLEARED',
      severity: 'low',
      source: 'admin_action',
      metadata: {
        clearedBy: req.session.adminId || 'admin',
        clearedCount,
        source: source || 'all'
      }
    });

    res.json({
      success: true,
      data: {
        clearedCount,
        source: source || 'all',
        message: 'Security events cleared successfully'
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error clearing security events:', error);
    res.status(500).json({
      error: 'Failed to clear security events',
      code: 'CLEAR_ERROR'
    });
  }
});

/**
 * PUT /api/security/config
 * Update security monitoring configuration
 */
router.put('/config', async (req, res) => {
  try {
    const {
      alertThresholds,
      enableRealTimeAnalysis,
      retentionPeriod,
      maxEvents
    } = req.body;

    const currentConfig = globalSecurityMonitor.config;
    const newConfig = { ...currentConfig };

    if (alertThresholds && typeof alertThresholds === 'object') {
      newConfig.alertThresholds = { ...currentConfig.alertThresholds, ...alertThresholds };
    }

    if (typeof enableRealTimeAnalysis === 'boolean') {
      newConfig.enableRealTimeAnalysis = enableRealTimeAnalysis;
    }

    if (retentionPeriod && Number.isInteger(retentionPeriod) && retentionPeriod > 0) {
      newConfig.retentionPeriod = retentionPeriod;
    }

    if (maxEvents && Number.isInteger(maxEvents) && maxEvents > 0) {
      newConfig.maxEvents = maxEvents;
    }

    // Update configuration
    globalSecurityMonitor.config = newConfig;

    // Log configuration change
    globalSecurityMonitor.recordEvent({
      event: 'SECURITY_CONFIG_UPDATED',
      severity: 'low',
      source: 'admin_action',
      metadata: {
        updatedBy: req.session.adminId || 'admin',
        changes: Object.keys(req.body)
      }
    });

    res.json({
      success: true,
      data: {
        config: newConfig,
        message: 'Security configuration updated successfully'
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error updating security config:', error);
    res.status(500).json({
      error: 'Failed to update security configuration',
      code: 'CONFIG_ERROR'
    });
  }
});

/**
 * GET /api/security/status
 * Get security system status
 */
router.get('/status', async (req, res) => {
  try {
    const status = {
      securityMonitor: {
        active: true,
        eventsCount: globalSecurityMonitor.events.length,
        activeIncidents: globalSecurityMonitor.activeIncidents.size,
        uptime: process.uptime(),
        config: globalSecurityMonitor.config
      },
      querySanitization: {
        active: true,
        eventsCount: getSecurityEvents().length,
        lastActivity: getSecurityEvents().length > 0 ? 
          getSecurityEvents()[getSecurityEvents().length - 1].timestamp : null
      },
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        memoryUsage: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development'
      }
    };

    res.json({
      success: true,
      data: status,
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting security status:', error);
    res.status(500).json({
      error: 'Failed to get security status',
      code: 'STATUS_ERROR'
    });
  }
});

module.exports = router;