const NotificationService = require('./notificationService');

// Create and configure notification service instance
const notificationServiceInstance = new NotificationService({
  realTimeEnabled: process.env.ENABLE_REALTIME_NOTIFICATIONS !== 'false',
  maxNotificationsPerUser: parseInt(process.env.MAX_NOTIFICATIONS_PER_USER) || 1000,
  cleanupIntervalHours: parseInt(process.env.NOTIFICATION_CLEANUP_INTERVAL_HOURS) || 6,
  defaultExpirationDays: parseInt(process.env.NOTIFICATION_EXPIRATION_DAYS) || 7,
  batchSize: parseInt(process.env.NOTIFICATION_BATCH_SIZE) || 50
});

module.exports = notificationServiceInstance;