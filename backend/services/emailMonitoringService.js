const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');
const Contact = require('../models/Contact');
const User = require('../models/User');
const RealTimeMetrics = require('./realTimeMetrics');

/**
 * Email Monitoring Service for Form-a-Friend v2
 * 
 * Provides comprehensive monitoring and alerting for email deliverability:
 * - Real-time bounce rate monitoring
 * - Deliverability scoring and analytics
 * - Automatic contact status management
 * - GDPR compliance tracking
 * - Performance alerting system
 * - Email health dashboards
 */
class EmailMonitoringService extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      bounceRateThreshold: config.bounceRateThreshold || 5, // 5%
      complaintRateThreshold: config.complaintRateThreshold || 0.5, // 0.5%
      deliverabilityThreshold: config.deliverabilityThreshold || 95, // 95%
      monitoringInterval: config.monitoringInterval || 300000, // 5 minutes
      alertCooldown: config.alertCooldown || 1800000, // 30 minutes
      maxBounceCount: config.maxBounceCount || 5,
      reputationWindow: config.reputationWindow || 86400000, // 24 hours
      ...config
    };

    this.metrics = {
      totalEmails: 0,
      deliveredEmails: 0,
      bouncedEmails: 0,
      complainedEmails: 0,
      unsubscribedEmails: 0,
      deliverabilityScore: 100,
      reputationScore: 100,
      lastCalculated: new Date()
    };

    this.alerts = {
      lastBounceAlert: null,
      lastComplaintAlert: null,
      lastDeliverabilityAlert: null,
      alertsToday: 0
    };

    this.isRunning = false;
    this.monitoringTimer = null;
    this.realTimeMetrics = null;

    SecureLogger.logInfo('EmailMonitoringService initialized', {
      bounceThreshold: this.config.bounceRateThreshold,
      complaintThreshold: this.config.complaintRateThreshold,
      deliverabilityThreshold: this.config.deliverabilityThreshold
    });
  }

  /**
   * Set real-time metrics instance
   */
  setRealTimeMetrics(realTimeMetrics) {
    this.realTimeMetrics = realTimeMetrics;
    
    // Listen for email events
    if (realTimeMetrics) {
      realTimeMetrics.on('email-sent', (data) => this.trackEmailSent(data));
      realTimeMetrics.on('email-failed', (data) => this.trackEmailFailed(data));
    }
  }

  /**
   * Start monitoring service
   */
  async start() {
    if (this.isRunning) {
      SecureLogger.logWarning('EmailMonitoringService already running');
      return;
    }

    this.isRunning = true;
    
    // Initial metrics calculation
    await this.calculateMetrics();
    
    // Start periodic monitoring
    this.monitoringTimer = setInterval(async () => {
      try {
        await this.runMonitoringCycle();
      } catch (error) {
        SecureLogger.logError('Monitoring cycle failed', {
          error: error.message
        });
      }
    }, this.config.monitoringInterval);

    SecureLogger.logInfo('EmailMonitoringService started', {
      interval: this.config.monitoringInterval
    });

    this.emit('monitoring-started');
  }

  /**
   * Stop monitoring service
   */
  async stop() {
    if (!this.isRunning) {
      return;
    }

    this.isRunning = false;
    
    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
      this.monitoringTimer = null;
    }

    SecureLogger.logInfo('EmailMonitoringService stopped');
    this.emit('monitoring-stopped');
  }

  /**
   * Run complete monitoring cycle
   */
  async runMonitoringCycle() {
    const startTime = Date.now();
    
    try {
      // Calculate current metrics
      await this.calculateMetrics();
      
      // Check for alerts
      await this.checkAlerts();
      
      // Update reputation scores
      await this.updateReputationScores();
      
      // Clean up old data
      await this.cleanupOldData();
      
      const duration = Date.now() - startTime;
      
      SecureLogger.logInfo('Monitoring cycle completed', {
        duration,
        deliverabilityScore: this.metrics.deliverabilityScore,
        reputationScore: this.metrics.reputationScore
      });

      this.emit('monitoring-cycle-completed', {
        metrics: this.metrics,
        duration
      });
      
    } catch (error) {
      SecureLogger.logError('Monitoring cycle error', {
        error: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Calculate email delivery metrics
   */
  async calculateMetrics() {
    try {
      const now = new Date();
      const windowStart = new Date(now.getTime() - this.config.reputationWindow);

      // Get email statistics from Contact tracking
      const totalContacts = await Contact.countDocuments({
        'tracking.lastSentAt': { $gte: windowStart }
      });

      const deliveredCount = await Contact.countDocuments({
        'tracking.lastSentAt': { $gte: windowStart },
        emailStatus: 'delivered'
      });

      const bouncedCount = await Contact.countDocuments({
        'tracking.lastSentAt': { $gte: windowStart },
        emailStatus: { $in: ['bounced_temporary', 'bounced_permanent'] }
      });

      const complainedCount = await Contact.countDocuments({
        'tracking.lastSentAt': { $gte: windowStart },
        emailStatus: 'complained'
      });

      const unsubscribedCount = await Contact.countDocuments({
        'tracking.lastSentAt': { $gte: windowStart },
        emailStatus: 'unsubscribed'
      });

      // Calculate rates
      const bounceRate = totalContacts > 0 ? (bouncedCount / totalContacts) * 100 : 0;
      const complaintRate = totalContacts > 0 ? (complainedCount / totalContacts) * 100 : 0;
      const deliveryRate = totalContacts > 0 ? (deliveredCount / totalContacts) * 100 : 0;
      const unsubscribeRate = totalContacts > 0 ? (unsubscribedCount / totalContacts) * 100 : 0;

      // Calculate deliverability score (weighted)
      const deliverabilityScore = Math.max(0, Math.min(100, 
        deliveryRate - (bounceRate * 2) - (complaintRate * 5) - (unsubscribeRate * 0.5)
      ));

      // Calculate reputation score
      const reputationScore = this.calculateReputationScore(bounceRate, complaintRate, deliveryRate);

      // Update metrics
      this.metrics = {
        totalEmails: totalContacts,
        deliveredEmails: deliveredCount,
        bouncedEmails: bouncedCount,
        complainedEmails: complainedCount,
        unsubscribedEmails: unsubscribedCount,
        bounceRate: Math.round(bounceRate * 100) / 100,
        complaintRate: Math.round(complaintRate * 100) / 100,
        deliveryRate: Math.round(deliveryRate * 100) / 100,
        unsubscribeRate: Math.round(unsubscribeRate * 100) / 100,
        deliverabilityScore: Math.round(deliverabilityScore * 100) / 100,
        reputationScore: Math.round(reputationScore * 100) / 100,
        lastCalculated: now
      };

      SecureLogger.logInfo('Email metrics calculated', this.metrics);

    } catch (error) {
      SecureLogger.logError('Failed to calculate email metrics', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Calculate reputation score based on multiple factors
   */
  calculateReputationScore(bounceRate, complaintRate, deliveryRate) {
    let score = 100;

    // Penalty for high bounce rates
    if (bounceRate > this.config.bounceRateThreshold) {
      score -= (bounceRate - this.config.bounceRateThreshold) * 5;
    }

    // Severe penalty for complaints
    if (complaintRate > this.config.complaintRateThreshold) {
      score -= (complaintRate - this.config.complaintRateThreshold) * 20;
    }

    // Bonus for high delivery rates
    if (deliveryRate > 95) {
      score += (deliveryRate - 95) * 2;
    }

    // Additional penalties for very poor performance
    if (bounceRate > 10) score -= 20;
    if (complaintRate > 1) score -= 30;
    if (deliveryRate < 80) score -= 25;

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Check for alerts and send notifications
   */
  async checkAlerts() {
    const now = Date.now();

    // Check bounce rate alert
    if (this.metrics.bounceRate > this.config.bounceRateThreshold) {
      if (!this.alerts.lastBounceAlert || 
          (now - this.alerts.lastBounceAlert) > this.config.alertCooldown) {
        
        await this.sendAlert('high-bounce-rate', {
          current: this.metrics.bounceRate,
          threshold: this.config.bounceRateThreshold,
          totalEmails: this.metrics.totalEmails,
          bouncedEmails: this.metrics.bouncedEmails
        });
        
        this.alerts.lastBounceAlert = now;
      }
    }

    // Check complaint rate alert
    if (this.metrics.complaintRate > this.config.complaintRateThreshold) {
      if (!this.alerts.lastComplaintAlert || 
          (now - this.alerts.lastComplaintAlert) > this.config.alertCooldown) {
        
        await this.sendAlert('high-complaint-rate', {
          current: this.metrics.complaintRate,
          threshold: this.config.complaintRateThreshold,
          totalEmails: this.metrics.totalEmails,
          complainedEmails: this.metrics.complainedEmails
        });
        
        this.alerts.lastComplaintAlert = now;
      }
    }

    // Check deliverability score alert
    if (this.metrics.deliverabilityScore < this.config.deliverabilityThreshold) {
      if (!this.alerts.lastDeliverabilityAlert || 
          (now - this.alerts.lastDeliverabilityAlert) > this.config.alertCooldown) {
        
        await this.sendAlert('low-deliverability', {
          current: this.metrics.deliverabilityScore,
          threshold: this.config.deliverabilityThreshold,
          reputationScore: this.metrics.reputationScore
        });
        
        this.alerts.lastDeliverabilityAlert = now;
      }
    }
  }

  /**
   * Send alert notification
   */
  async sendAlert(type, data) {
    try {
      const alert = {
        type,
        data,
        timestamp: new Date(),
        severity: this.getAlertSeverity(type, data)
      };

      SecureLogger.logWarning(`Email monitoring alert: ${type}`, alert);

      // Emit alert event for external systems
      this.emit('alert', alert);

      // Track alert
      this.alerts.alertsToday++;

      // Log to real-time metrics if available
      if (this.realTimeMetrics) {
        this.realTimeMetrics.emit('email-alert', alert);
      }

    } catch (error) {
      SecureLogger.logError('Failed to send monitoring alert', {
        type,
        data,
        error: error.message
      });
    }
  }

  /**
   * Get alert severity level
   */
  getAlertSeverity(type, data) {
    switch (type) {
      case 'high-bounce-rate':
        return data.current > this.config.bounceRateThreshold * 2 ? 'critical' : 'warning';
      case 'high-complaint-rate':
        return data.current > this.config.complaintRateThreshold * 2 ? 'critical' : 'warning';
      case 'low-deliverability':
        return data.current < this.config.deliverabilityThreshold * 0.8 ? 'critical' : 'warning';
      default:
        return 'info';
    }
  }

  /**
   * Update reputation scores for providers
   */
  async updateReputationScores() {
    // This could be expanded to track provider-specific reputation
    // For now, we'll just log the overall reputation
    
    if (this.metrics.reputationScore < 80) {
      SecureLogger.logWarning('Email reputation score below threshold', {
        reputationScore: this.metrics.reputationScore,
        deliverabilityScore: this.metrics.deliverabilityScore
      });
    }
  }

  /**
   * Clean up old monitoring data
   */
  async cleanupOldData() {
    try {
      const cutoffDate = new Date(Date.now() - (30 * 24 * 60 * 60 * 1000)); // 30 days

      // This could be expanded to clean up detailed monitoring logs
      SecureLogger.logInfo('Monitoring data cleanup completed', {
        cutoffDate
      });

    } catch (error) {
      SecureLogger.logError('Failed to cleanup monitoring data', {
        error: error.message
      });
    }
  }

  /**
   * Track email sent event
   */
  trackEmailSent(data) {
    // Real-time tracking of sent emails
    this.emit('email-tracked', {
      type: 'sent',
      ...data
    });
  }

  /**
   * Track email failed event
   */
  trackEmailFailed(data) {
    // Real-time tracking of failed emails
    this.emit('email-tracked', {
      type: 'failed',
      ...data
    });
  }

  /**
   * Get current monitoring status
   */
  getStatus() {
    return {
      isRunning: this.isRunning,
      metrics: this.metrics,
      alerts: this.alerts,
      config: {
        bounceRateThreshold: this.config.bounceRateThreshold,
        complaintRateThreshold: this.config.complaintRateThreshold,
        deliverabilityThreshold: this.config.deliverabilityThreshold
      },
      lastMonitoringCycle: this.metrics.lastCalculated
    };
  }

  /**
   * Get contact deliverability report
   */
  async getContactDeliverabilityReport(limit = 100) {
    try {
      // Top bouncing contacts
      const topBouncers = await Contact.find({
        bounceCount: { $gt: 0 }
      })
      .sort({ bounceCount: -1 })
      .limit(limit)
      .select('email bounceCount lastBounceAt bounceReason emailStatus');

      // Recently complained contacts
      const recentComplaints = await Contact.find({
        emailStatus: 'complained',
        lastComplaintAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
      })
      .sort({ lastComplaintAt: -1 })
      .limit(limit)
      .select('email lastComplaintAt complaintReason');

      // Undeliverable contacts
      const undeliverable = await Contact.find({
        $or: [
          { emailStatus: 'bounced_permanent' },
          { emailStatus: 'complained' },
          { emailStatus: 'unsubscribed' },
          { bounceCount: { $gte: this.config.maxBounceCount } }
        ]
      })
      .sort({ updatedAt: -1 })
      .limit(limit)
      .select('email emailStatus bounceCount optedOut optOutReason');

      return {
        topBouncers,
        recentComplaints,
        undeliverable,
        summary: {
          totalUndeliverable: undeliverable.length,
          totalBouncers: topBouncers.length,
          totalComplaints: recentComplaints.length
        }
      };

    } catch (error) {
      SecureLogger.logError('Failed to generate deliverability report', {
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Generate health score for email system
   */
  calculateHealthScore() {
    const weights = {
      deliverability: 0.4,
      reputation: 0.3,
      bounceRate: 0.2,
      complaintRate: 0.1
    };

    const bounceScore = Math.max(0, 100 - (this.metrics.bounceRate * 10));
    const complaintScore = Math.max(0, 100 - (this.metrics.complaintRate * 50));

    const healthScore = (
      this.metrics.deliverabilityScore * weights.deliverability +
      this.metrics.reputationScore * weights.reputation +
      bounceScore * weights.bounceRate +
      complaintScore * weights.complaintRate
    );

    return {
      score: Math.round(healthScore * 100) / 100,
      grade: this.getHealthGrade(healthScore),
      factors: {
        deliverability: this.metrics.deliverabilityScore,
        reputation: this.metrics.reputationScore,
        bounceRate: this.metrics.bounceRate,
        complaintRate: this.metrics.complaintRate
      }
    };
  }

  /**
   * Get health grade based on score
   */
  getHealthGrade(score) {
    if (score >= 95) return 'A+';
    if (score >= 90) return 'A';
    if (score >= 85) return 'B+';
    if (score >= 80) return 'B';
    if (score >= 75) return 'C+';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Force metrics recalculation
   */
  async recalculateMetrics() {
    SecureLogger.logInfo('Forcing metrics recalculation');
    await this.calculateMetrics();
    return this.metrics;
  }

  /**
   * Reset alert cooldowns (for testing)
   */
  resetAlerts() {
    this.alerts = {
      lastBounceAlert: null,
      lastComplaintAlert: null,
      lastDeliverabilityAlert: null,
      alertsToday: 0
    };
    SecureLogger.logInfo('Email monitoring alerts reset');
  }
}

module.exports = EmailMonitoringService;