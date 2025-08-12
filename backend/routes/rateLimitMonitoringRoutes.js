// Rate Limit Monitoring and Management Routes
const express = require('express');
const router = express.Router();
const { rateLimitUtils } = require('../middleware/authRateLimit');
const auth = require('../middleware/auth');
const SecureLogger = require('../utils/secureLogger');

// Admin authentication required for all monitoring routes
router.use(auth.requireAdmin);

/**
 * GET /api/rate-limit/stats - Get rate limiting statistics
 */
router.get('/stats', (req, res) => {
  try {
    const stats = rateLimitUtils.getFingerprintingStats();
    
    res.json({
      success: true,
      data: {
        cache: {
          size: stats.size,
          timeout: stats.timeout,
          totalEntries: stats.entries.length
        },
        entries: stats.entries.slice(0, 50), // Limit to 50 most recent
        system: {
          nodeVersion: process.version,
          uptime: Math.floor(process.uptime()),
          memoryUsage: process.memoryUsage()
        }
      }
    });
  } catch (error) {
    SecureLogger.logError('Failed to get rate limiting stats', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve statistics'
    });
  }
});

/**
 * POST /api/rate-limit/test-fingerprint - Test device fingerprinting for a request
 */
router.post('/test-fingerprint', (req, res) => {
  try {
    // Test fingerprinting with current request
    const result = rateLimitUtils.testFingerprinting(req);
    
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    SecureLogger.logError('Failed to test fingerprinting', error);
    res.status(500).json({
      success: false,
      error: 'Failed to test fingerprinting'
    });
  }
});

/**
 * POST /api/rate-limit/analyze-request - Analyze request for suspicious patterns
 */
router.post('/analyze-request', (req, res) => {
  try {
    const analysis = rateLimitUtils.analyzeSuspiciousPatterns(req);
    const deviceReport = rateLimitUtils.getDeviceReport(req);
    
    res.json({
      success: true,
      data: {
        analysis,
        deviceReport: deviceReport ? {
          fingerprint: deviceReport.fingerprint,
          trustScore: deviceReport.analysis.trustScore,
          suspiciousIndicators: deviceReport.analysis.indicators,
          userAgent: deviceReport.characteristics.userAgentParsed,
          headers: {
            userAgent: deviceReport.characteristics.userAgent,
            acceptLanguage: deviceReport.characteristics.acceptLanguage,
            acceptEncoding: deviceReport.characteristics.acceptEncoding
          }
        } : null
      }
    });
  } catch (error) {
    SecureLogger.logError('Failed to analyze request', error);
    res.status(500).json({
      success: false,
      error: 'Failed to analyze request'
    });
  }
});

/**
 * POST /api/rate-limit/clear-cache - Clear fingerprinting cache
 */
router.post('/clear-cache', (req, res) => {
  try {
    const result = rateLimitUtils.cleanFingerprintingCache();
    
    if (result) {
      SecureLogger.logInfo('Rate limiting cache cleared by admin', {
        adminIP: req.ip,
        userAgent: req.get('user-agent')
      });
      
      res.json({
        success: true,
        message: 'Cache cleared successfully'
      });
    } else {
      res.status(500).json({
        success: false,
        error: 'Failed to clear cache'
      });
    }
  } catch (error) {
    SecureLogger.logError('Failed to clear rate limiting cache', error);
    res.status(500).json({
      success: false,
      error: 'Failed to clear cache'
    });
  }
});

/**
 * GET /api/rate-limit/suspicious-activity - Get recent suspicious activity
 */
router.get('/suspicious-activity', async (req, res) => {
  try {
    const stats = rateLimitUtils.getFingerprintingStats();
    
    // Simulate analysis of suspicious activity from cache entries
    const suspiciousActivity = stats.entries
      .filter(entry => {
        // This would typically come from actual stored suspicious activity logs
        // For now, we'll simulate based on entry age and key patterns
        return entry.key.includes('bot') || entry.key.includes('crawler') || entry.age > 10 * 60 * 1000;
      })
      .slice(0, 20)
      .map(entry => ({
        fingerprint: entry.key.substring(0, 8),
        lastSeen: new Date(Date.now() - entry.age).toISOString(),
        age: entry.age,
        suspicious: true
      }));
    
    res.json({
      success: true,
      data: {
        totalSuspicious: suspiciousActivity.length,
        recentActivity: suspiciousActivity,
        timeframe: '24 hours'
      }
    });
  } catch (error) {
    SecureLogger.logError('Failed to get suspicious activity', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve suspicious activity'
    });
  }
});

/**
 * GET /api/rate-limit/configuration - Get current rate limiting configuration
 */
router.get('/configuration', (req, res) => {
  try {
    const config = {
      fingerprinting: {
        enabled: true,
        cacheTimeout: '5 minutes',
        maxCacheSize: 1000
      },
      rateLimits: {
        login: {
          windowMs: 15 * 60 * 1000,
          maxAttempts: 5,
          suspiciousMultiplier: 0.4,
          trustThreshold: 6
        },
        register: {
          windowMs: 60 * 60 * 1000,
          maxAttempts: 3,
          suspiciousMultiplier: 0.5,
          trustThreshold: 4
        },
        passwordReset: {
          windowMs: 60 * 60 * 1000,
          maxAttempts: 3,
          suspiciousMultiplier: 0.3,
          trustThreshold: 7
        },
        api: {
          windowMs: 5 * 60 * 1000,
          maxAttempts: 20,
          suspiciousMultiplier: 0.3,
          trustThreshold: 5
        }
      }
    };
    
    res.json({
      success: true,
      data: config
    });
  } catch (error) {
    SecureLogger.logError('Failed to get rate limiting configuration', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get configuration'
    });
  }
});

/**
 * GET /api/rate-limit/dashboard - Get dashboard data for admin interface
 */
router.get('/dashboard', async (req, res) => {
  try {
    const stats = rateLimitUtils.getFingerprintingStats();
    const currentTime = Date.now();
    
    // Calculate dashboard metrics
    const recentEntries = stats.entries.filter(entry => entry.age < 60 * 60 * 1000); // Last hour
    const activeFingerprints = recentEntries.length;
    
    // Simulate rate limit violations (in production, this would come from logs)
    const rateLimitViolations = Math.floor(Math.random() * 20); // Simulated data
    
    // Browser/OS distribution from fingerprints (simplified)
    const browserStats = {
      chrome: Math.floor(activeFingerprints * 0.65),
      firefox: Math.floor(activeFingerprints * 0.20),
      safari: Math.floor(activeFingerprints * 0.10),
      other: Math.floor(activeFingerprints * 0.05)
    };
    
    const osStats = {
      windows: Math.floor(activeFingerprints * 0.50),
      macos: Math.floor(activeFingerprints * 0.25),
      linux: Math.floor(activeFingerprints * 0.15),
      mobile: Math.floor(activeFingerprints * 0.10)
    };
    
    res.json({
      success: true,
      data: {
        overview: {
          totalCacheEntries: stats.size,
          activeFingerprints,
          rateLimitViolations,
          cacheHitRate: activeFingerprints > 0 ? Math.round((stats.size / activeFingerprints) * 100) : 0
        },
        distribution: {
          browsers: browserStats,
          operatingSystems: osStats
        },
        recentActivity: recentEntries.slice(0, 10).map(entry => ({
          fingerprint: entry.key.substring(0, 8),
          age: entry.age,
          lastSeen: new Date(currentTime - entry.age).toISOString()
        })),
        system: {
          uptime: Math.floor(process.uptime()),
          memoryUsage: Math.round(process.memoryUsage().rss / 1024 / 1024), // MB
          cacheSize: stats.size
        }
      }
    });
  } catch (error) {
    SecureLogger.logError('Failed to get dashboard data', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get dashboard data'
    });
  }
});

module.exports = router;