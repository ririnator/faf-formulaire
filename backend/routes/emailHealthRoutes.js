const express = require('express');
const { requireAdminAccess } = require('../middleware/hybridAuth');
const { getEmailMonitoringServiceInstance } = require('../services/emailMonitoringServiceInstance');
const Contact = require('../models/Contact');
const SecureLogger = require('../utils/secureLogger');

const router = express.Router();

/**
 * Email Health Dashboard Routes for Form-a-Friend v2
 * 
 * Provides comprehensive email health monitoring and analytics:
 * - Real-time deliverability metrics
 * - Bounce and complaint tracking
 * - Contact deliverability reports
 * - Email reputation monitoring
 * - GDPR compliance tracking
 */

/**
 * Get email health dashboard overview
 */
router.get('/dashboard', requireAdminAccess, async (req, res) => {
  try {
    const emailMonitoring = getEmailMonitoringServiceInstance();
    
    // Get current monitoring status
    const status = emailMonitoring.getStatus();
    
    // Calculate health score
    const healthScore = emailMonitoring.calculateHealthScore();
    
    // Get recent alert summary
    const alertSummary = {
      alertsToday: status.alerts.alertsToday,
      lastBounceAlert: status.alerts.lastBounceAlert,
      lastComplaintAlert: status.alerts.lastComplaintAlert,
      lastDeliverabilityAlert: status.alerts.lastDeliverabilityAlert
    };

    // Get contact statistics
    const contactStats = await getContactStatistics();

    const dashboard = {
      timestamp: new Date(),
      monitoring: {
        isRunning: status.isRunning,
        lastUpdate: status.lastMonitoringCycle
      },
      metrics: status.metrics,
      healthScore,
      alertSummary,
      contactStats,
      recommendations: generateRecommendations(status.metrics, healthScore)
    };

    res.json({
      success: true,
      dashboard
    });

  } catch (error) {
    SecureLogger.logError('Failed to get email health dashboard', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to load dashboard'
    });
  }
});

/**
 * Get detailed email metrics
 */
router.get('/metrics', requireAdminAccess, async (req, res) => {
  try {
    const emailMonitoring = getEmailMonitoringServiceInstance();
    
    // Force recalculation if requested
    const { recalculate } = req.query;
    if (recalculate === 'true') {
      await emailMonitoring.recalculateMetrics();
    }
    
    const metrics = emailMonitoring.getStatus().metrics;
    const healthScore = emailMonitoring.calculateHealthScore();

    res.json({
      success: true,
      metrics,
      healthScore,
      timestamp: new Date()
    });

  } catch (error) {
    SecureLogger.logError('Failed to get email metrics', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to load metrics'
    });
  }
});

/**
 * Get contact deliverability report
 */
router.get('/deliverability-report', requireAdminAccess, async (req, res) => {
  try {
    const emailMonitoring = getEmailMonitoringServiceInstance();
    const { limit = 50 } = req.query;
    
    const report = await emailMonitoring.getContactDeliverabilityReport(parseInt(limit));

    res.json({
      success: true,
      report,
      timestamp: new Date()
    });

  } catch (error) {
    SecureLogger.logError('Failed to get deliverability report', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to load deliverability report'
    });
  }
});

/**
 * Get bounced contacts list
 */
router.get('/bounced-contacts', requireAdminAccess, async (req, res) => {
  try {
    const { page = 1, limit = 20, bounceType } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    let filter = {
      emailStatus: { $in: ['bounced_temporary', 'bounced_permanent'] }
    };

    if (bounceType === 'permanent') {
      filter.emailStatus = 'bounced_permanent';
    } else if (bounceType === 'temporary') {
      filter.emailStatus = 'bounced_temporary';
    }

    const contacts = await Contact.find(filter)
      .sort({ lastBounceAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('email firstName lastName emailStatus bounceCount lastBounceAt bounceReason isActive');

    const total = await Contact.countDocuments(filter);

    res.json({
      success: true,
      contacts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to get bounced contacts', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to load bounced contacts'
    });
  }
});

/**
 * Get complained contacts list
 */
router.get('/complained-contacts', requireAdminAccess, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const contacts = await Contact.find({
      emailStatus: 'complained'
    })
      .sort({ lastComplaintAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('email firstName lastName lastComplaintAt complaintReason optedOut optedOutAt');

    const total = await Contact.countDocuments({ emailStatus: 'complained' });

    res.json({
      success: true,
      contacts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to get complained contacts', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to load complained contacts'
    });
  }
});

/**
 * Get unsubscribed contacts list
 */
router.get('/unsubscribed-contacts', requireAdminAccess, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const contacts = await Contact.find({
      optedOut: true
    })
      .sort({ optedOutAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .select('email firstName lastName optedOutAt optOutReason emailStatus');

    const total = await Contact.countDocuments({ optedOut: true });

    res.json({
      success: true,
      contacts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to get unsubscribed contacts', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to load unsubscribed contacts'
    });
  }
});

/**
 * Reactivate a contact (admin action)
 */
router.post('/reactivate-contact', requireAdminAccess, async (req, res) => {
  try {
    const { contactId, note } = req.body;

    if (!contactId) {
      return res.status(400).json({
        success: false,
        error: 'Contact ID required'
      });
    }

    const contact = await Contact.findById(contactId);
    if (!contact) {
      return res.status(404).json({
        success: false,
        error: 'Contact not found'
      });
    }

    // Use the Contact model method
    await contact.reactivate(note);

    SecureLogger.logInfo('Contact reactivated by admin', {
      contactId,
      email: contact.email,
      note
    });

    res.json({
      success: true,
      message: 'Contact reactivated successfully',
      contact: {
        id: contact._id,
        email: contact.email,
        emailStatus: contact.emailStatus,
        isActive: contact.isActive,
        optedOut: contact.optedOut
      }
    });

  } catch (error) {
    SecureLogger.logError('Failed to reactivate contact', {
      error: error.message,
      contactId: req.body.contactId
    });
    
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * Force monitoring update
 */
router.post('/refresh-monitoring', requireAdminAccess, async (req, res) => {
  try {
    const emailMonitoring = getEmailMonitoringServiceInstance();
    
    await emailMonitoring.recalculateMetrics();
    
    const status = emailMonitoring.getStatus();
    const healthScore = emailMonitoring.calculateHealthScore();

    SecureLogger.logInfo('Email monitoring manually refreshed');

    res.json({
      success: true,
      message: 'Monitoring data refreshed',
      metrics: status.metrics,
      healthScore
    });

  } catch (error) {
    SecureLogger.logError('Failed to refresh monitoring', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to refresh monitoring'
    });
  }
});

/**
 * Reset monitoring alerts (for testing)
 */
router.post('/reset-alerts', requireAdminAccess, async (req, res) => {
  try {
    const emailMonitoring = getEmailMonitoringServiceInstance();
    
    emailMonitoring.resetAlerts();

    SecureLogger.logInfo('Email monitoring alerts reset');

    res.json({
      success: true,
      message: 'Alerts reset successfully'
    });

  } catch (error) {
    SecureLogger.logError('Failed to reset alerts', {
      error: error.message
    });
    
    res.status(500).json({
      success: false,
      error: 'Failed to reset alerts'
    });
  }
});

/**
 * Get contact statistics helper function
 */
async function getContactStatistics() {
  try {
    const [
      totalContacts,
      activeContacts,
      bouncedContacts,
      complainedContacts,
      unsubscribedContacts,
      recentlyAddedContacts
    ] = await Promise.all([
      Contact.countDocuments({}),
      Contact.countDocuments({ isActive: true, optedOut: false }),
      Contact.countDocuments({ emailStatus: { $in: ['bounced_temporary', 'bounced_permanent'] } }),
      Contact.countDocuments({ emailStatus: 'complained' }),
      Contact.countDocuments({ optedOut: true }),
      Contact.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } 
      })
    ]);

    return {
      totalContacts,
      activeContacts,
      bouncedContacts,
      complainedContacts,
      unsubscribedContacts,
      recentlyAddedContacts,
      deliverableContacts: activeContacts,
      undeliverableContacts: bouncedContacts + complainedContacts + unsubscribedContacts
    };

  } catch (error) {
    SecureLogger.logError('Failed to get contact statistics', {
      error: error.message
    });
    throw error;
  }
}

/**
 * Generate recommendations based on metrics
 */
function generateRecommendations(metrics, healthScore) {
  const recommendations = [];

  if (metrics.bounceRate > 5) {
    recommendations.push({
      type: 'warning',
      category: 'bounce_rate',
      message: 'High bounce rate detected. Consider cleaning your contact list and validating email addresses.',
      priority: 'high'
    });
  }

  if (metrics.complaintRate > 0.5) {
    recommendations.push({
      type: 'critical',
      category: 'complaint_rate',
      message: 'High complaint rate detected. Review email content and sending frequency.',
      priority: 'critical'
    });
  }

  if (metrics.deliverabilityScore < 90) {
    recommendations.push({
      type: 'warning',
      category: 'deliverability',
      message: 'Low deliverability score. Check sender reputation and email authentication.',
      priority: 'high'
    });
  }

  if (healthScore.score < 80) {
    recommendations.push({
      type: 'info',
      category: 'health',
      message: 'Overall email health needs improvement. Focus on list hygiene and content quality.',
      priority: 'medium'
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      type: 'success',
      category: 'health',
      message: 'Email system is performing well. Continue monitoring for optimal performance.',
      priority: 'low'
    });
  }

  return recommendations;
}

module.exports = router;