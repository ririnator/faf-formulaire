const EmailMonitoringService = require('./emailMonitoringService');
const EnvironmentConfig = require('../config/environment');

/**
 * Email Monitoring Service Instance for Form-a-Friend v2
 * 
 * Singleton instance for email monitoring with configuration from environment
 */

let emailMonitoringServiceInstance = null;

function createEmailMonitoringServiceInstance() {
  if (emailMonitoringServiceInstance) {
    return emailMonitoringServiceInstance;
  }

  const config = EnvironmentConfig.getConfig();
  
  const emailMonitoringConfig = {
    // Thresholds
    bounceRateThreshold: parseFloat(process.env.EMAIL_BOUNCE_RATE_THRESHOLD) || 5, // 5%
    complaintRateThreshold: parseFloat(process.env.EMAIL_COMPLAINT_RATE_THRESHOLD) || 0.5, // 0.5%
    deliverabilityThreshold: parseFloat(process.env.EMAIL_DELIVERABILITY_THRESHOLD) || 95, // 95%
    
    // Monitoring intervals
    monitoringInterval: parseInt(process.env.EMAIL_MONITORING_INTERVAL) || 300000, // 5 minutes
    alertCooldown: parseInt(process.env.EMAIL_ALERT_COOLDOWN) || 1800000, // 30 minutes
    
    // Limits
    maxBounceCount: parseInt(process.env.EMAIL_MAX_BOUNCE_COUNT) || 5,
    reputationWindow: parseInt(process.env.EMAIL_REPUTATION_WINDOW) || 86400000, // 24 hours
    
    // Features
    enableRealTimeAlerts: process.env.EMAIL_ENABLE_REALTIME_ALERTS !== 'false',
    enableHealthDashboard: process.env.EMAIL_ENABLE_HEALTH_DASHBOARD !== 'false',
    enableReputationTracking: process.env.EMAIL_ENABLE_REPUTATION_TRACKING !== 'false'
  };

  emailMonitoringServiceInstance = new EmailMonitoringService(emailMonitoringConfig);

  // Set up event listeners for logging and alerting
  emailMonitoringServiceInstance.on('alert', (alert) => {
    // This could be expanded to send notifications to admins
    console.warn(`📧 Email Alert [${alert.severity.toUpperCase()}]:`, alert);
  });

  emailMonitoringServiceInstance.on('monitoring-cycle-completed', (data) => {
    console.log(`📊 Email monitoring cycle completed - Health: ${data.metrics.deliverabilityScore}%`);
  });

  emailMonitoringServiceInstance.on('email-tracked', (event) => {
    // Real-time email event tracking
    if (process.env.NODE_ENV === 'development') {
      console.log(`📧 Email tracked: ${event.type} - ${event.timestamp}`);
    }
  });

  return emailMonitoringServiceInstance;
}

function getEmailMonitoringServiceInstance() {
  if (!emailMonitoringServiceInstance) {
    return createEmailMonitoringServiceInstance();
  }
  return emailMonitoringServiceInstance;
}

module.exports = {
  createEmailMonitoringServiceInstance,
  getEmailMonitoringServiceInstance
};