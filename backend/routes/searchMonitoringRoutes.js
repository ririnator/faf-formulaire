// routes/searchMonitoringRoutes.js

/**
 * Search Monitoring Admin Routes
 * 
 * Provides endpoints for administrators to monitor search patterns,
 * abuse detection, and system health related to search functionality.
 */

const express = require('express');
const router = express.Router();
const { adminLimiter } = require('../middleware/rateLimiting');
const { requireAdminAccess } = require('../middleware/hybridAuth');
const searchMonitoringService = require('../services/searchMonitoringService');
const { getSearchBlockingStatus } = require('../middleware/searchBlockingMiddleware');

// Apply admin authentication to all routes
router.use(requireAdminAccess);

/**
 * GET /api/admin/search-monitoring/stats - Get search monitoring statistics
 */
router.get('/stats', adminLimiter, async (req, res) => {
  try {
    const { timeWindow = 'medium' } = req.query;
    
    const stats = searchMonitoringService.getSearchStatistics(timeWindow);
    
    res.json({
      success: true,
      stats,
      systemHealth: {
        monitoringActive: true,
        activePatterns: searchMonitoringService.searchPatterns.size,
        blockedUsers: searchMonitoringService.blockedSearchers.size,
        lastCleanup: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('❌ Error getting search monitoring stats:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des statistiques de surveillance'
    });
  }
});

/**
 * GET /api/admin/search-monitoring/blocked-users - Get list of blocked users
 */
router.get('/blocked-users', adminLimiter, async (req, res) => {
  try {
    const blockedUsers = Array.from(searchMonitoringService.blockedSearchers);
    
    const blockedUsersInfo = blockedUsers.map(identifier => {
      const profile = searchMonitoringService.getUserSearchProfile(identifier);
      const blockingStatus = getSearchBlockingStatus(identifier);
      
      return {
        identifier,
        profile: profile ? {
          searchCount: profile.metrics.searchCount,
          failedSearches: profile.metrics.failedSearchCount,
          suspiciousQueries: profile.metrics.suspiciousQueryCount,
          warnings: profile.metrics.warnings.length,
          lastActivity: profile.metrics.lastSearchTime,
          riskLevel: blockingStatus.riskLevel
        } : null,
        blockedAt: new Date().toISOString() // Approximation - could be enhanced with actual block time
      };
    });
    
    res.json({
      success: true,
      blockedUsers: blockedUsersInfo,
      total: blockedUsers.length
    });
  } catch (error) {
    console.error('❌ Error getting blocked users:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des utilisateurs bloqués'
    });
  }
});

/**
 * GET /api/admin/search-monitoring/user-profile/:identifier - Get detailed user search profile
 */
router.get('/user-profile/:identifier', adminLimiter, async (req, res) => {
  try {
    const { identifier } = req.params;
    
    const profile = searchMonitoringService.getUserSearchProfile(identifier);
    const blockingStatus = getSearchBlockingStatus(identifier);
    
    if (!profile) {
      return res.status(404).json({
        success: false,
        error: 'Profil utilisateur non trouvé'
      });
    }
    
    res.json({
      success: true,
      profile: {
        identifier,
        metrics: profile.metrics,
        recentActivity: profile.recentActivity,
        blockingStatus,
        timeline: profile.timeline,
        riskAssessment: {
          level: blockingStatus.riskLevel,
          factors: analyzeRiskFactors(profile.metrics),
          recommendations: generateRecommendations(profile.metrics, blockingStatus)
        }
      }
    });
  } catch (error) {
    console.error('❌ Error getting user profile:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération du profil utilisateur'
    });
  }
});

/**
 * POST /api/admin/search-monitoring/unblock-user - Manually unblock a user
 */
router.post('/unblock-user', adminLimiter, async (req, res) => {
  try {
    const { identifier, reason = 'manual_admin_action' } = req.body;
    
    if (!identifier) {
      return res.status(400).json({
        success: false,
        error: 'Identifiant utilisateur requis'
      });
    }
    
    const wasBlocked = searchMonitoringService.isBlocked(identifier);
    
    if (!wasBlocked) {
      return res.status(404).json({
        success: false,
        error: 'Utilisateur non bloqué'
      });
    }
    
    // Remove from blocked set
    searchMonitoringService.blockedSearchers.delete(identifier);
    
    // Log the manual unblock action
    console.log('👤 Admin manually unblocked user:', {
      identifier,
      reason,
      adminUser: req.user?.username || 'unknown',
      timestamp: new Date().toISOString()
    });
    
    res.json({
      success: true,
      message: 'Utilisateur débloqué avec succès',
      identifier,
      unblocked: true
    });
  } catch (error) {
    console.error('❌ Error unblocking user:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors du déblocage de l\'utilisateur'
    });
  }
});

/**
 * GET /api/admin/search-monitoring/alerts - Get recent security alerts
 */
router.get('/alerts', adminLimiter, async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    
    // Get recent abuse events from all user profiles
    const alerts = [];
    const now = Date.now();
    const alertWindow = 60 * 60 * 1000; // Last hour
    
    for (const [identifier, metrics] of searchMonitoringService.abuseDetection.entries()) {
      const recentWarnings = metrics.warnings.filter(
        warning => now - warning.timestamp < alertWindow
      );
      
      recentWarnings.forEach(warning => {
        alerts.push({
          identifier,
          type: warning.type,
          severity: warning.severity,
          details: warning.details,
          timestamp: warning.timestamp,
          userMetrics: {
            totalSearches: metrics.searchCount,
            failedSearches: metrics.failedSearchCount,
            suspiciousQueries: metrics.suspiciousQueryCount
          }
        });
      });
    }
    
    // Sort by timestamp (most recent first) and limit
    alerts.sort((a, b) => b.timestamp - a.timestamp);
    const limitedAlerts = alerts.slice(0, parseInt(limit));
    
    res.json({
      success: true,
      alerts: limitedAlerts,
      total: alerts.length,
      timeWindow: 'last_hour'
    });
  } catch (error) {
    console.error('❌ Error getting security alerts:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de la récupération des alertes'
    });
  }
});

/**
 * POST /api/admin/search-monitoring/clear-warnings - Clear warnings for a user
 */
router.post('/clear-warnings', adminLimiter, async (req, res) => {
  try {
    const { identifier, reason = 'admin_cleared' } = req.body;
    
    if (!identifier) {
      return res.status(400).json({
        success: false,
        error: 'Identifiant utilisateur requis'
      });
    }
    
    const metrics = searchMonitoringService.abuseDetection.get(identifier);
    
    if (!metrics) {
      return res.status(404).json({
        success: false,
        error: 'Utilisateur non trouvé'
      });
    }
    
    const warningCount = metrics.warnings.length;
    metrics.warnings = [];
    
    console.log('🧹 Admin cleared user warnings:', {
      identifier,
      clearedWarnings: warningCount,
      reason,
      adminUser: req.user?.username || 'unknown',
      timestamp: new Date().toISOString()
    });
    
    res.json({
      success: true,
      message: 'Avertissements effacés avec succès',
      identifier,
      clearedWarnings: warningCount
    });
  } catch (error) {
    console.error('❌ Error clearing warnings:', error);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de l\'effacement des avertissements'
    });
  }
});

/**
 * Analyze risk factors for a user's search behavior
 * @param {Object} metrics - User search metrics
 * @returns {Array} Risk factors
 */
function analyzeRiskFactors(metrics) {
  const factors = [];
  
  if (metrics.searchCount > 100) {
    factors.push('High search volume');
  }
  
  const failureRate = metrics.searchCount > 0 ? 
    (metrics.failedSearchCount / metrics.searchCount) : 0;
  if (failureRate > 0.3) {
    factors.push(`High failure rate (${(failureRate * 100).toFixed(1)}%)`);
  }
  
  if (metrics.suspiciousQueryCount > 0) {
    factors.push(`Suspicious queries detected (${metrics.suspiciousQueryCount})`);
  }
  
  if (metrics.warnings.length > 2) {
    factors.push(`Multiple warnings (${metrics.warnings.length})`);
  }
  
  const complexRate = metrics.searchCount > 0 ? 
    (metrics.complexSearchCount / metrics.searchCount) : 0;
  if (complexRate > 0.5) {
    factors.push(`High complex search ratio (${(complexRate * 100).toFixed(1)}%)`);
  }
  
  return factors;
}

/**
 * Generate recommendations based on user behavior
 * @param {Object} metrics - User search metrics
 * @param {Object} blockingStatus - Current blocking status
 * @returns {Array} Recommendations
 */
function generateRecommendations(metrics, blockingStatus) {
  const recommendations = [];
  
  if (blockingStatus.isBlocked) {
    recommendations.push('Consider manual review before unblocking');
  }
  
  if (metrics.warnings.length > 3) {
    recommendations.push('Recommend user education on proper search usage');
  }
  
  const failureRate = metrics.searchCount > 0 ? 
    (metrics.failedSearchCount / metrics.searchCount) : 0;
  if (failureRate > 0.5) {
    recommendations.push('Investigate potential technical issues or user confusion');
  }
  
  if (metrics.suspiciousQueryCount > 5) {
    recommendations.push('Consider security investigation for potential attacks');
  }
  
  if (blockingStatus.riskLevel === 'high' || blockingStatus.riskLevel === 'critical') {
    recommendations.push('Monitor closely and consider account restrictions');
  }
  
  return recommendations;
}

module.exports = router;