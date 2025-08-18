class EnvironmentConfig {
  static requiredVars = [
    'MONGODB_URI',
    'SESSION_SECRET',
    'LOGIN_ADMIN_USER',
    'LOGIN_ADMIN_PASS',
    'FORM_ADMIN_NAME',
    'APP_BASE_URL'
  ];

  static optionalVars = [
    'FRONTEND_URL',
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET',
    'PORT',
    // Service configurations
    'CONTACT_MAX_CSV_SIZE',
    'CONTACT_MAX_BATCH_SIZE',
    'CONTACT_MAX_TAGS',
    'INVITATION_TOKEN_LENGTH',
    'INVITATION_EXPIRATION_DAYS',
    'INVITATION_MAX_IP_CHANGES',
    'SUBMISSION_MAX_TEXT_RESPONSES',
    'SUBMISSION_MAX_PHOTO_RESPONSES',
    'SUBMISSION_MIN_COMPLETION_RATE',
    'HANDSHAKE_EXPIRATION_DAYS',
    'HANDSHAKE_MAX_PENDING',
    'HANDSHAKE_CLEANUP_INTERVAL_HOURS',
    // Email service configurations
    'RESEND_API_KEY',
    'POSTMARK_API_KEY',
    'EMAIL_FROM_ADDRESS',
    'EMAIL_FROM_NAME',
    'EMAIL_BATCH_SIZE',
    'EMAIL_RATE_LIMIT_PER_MINUTE',
    'EMAIL_WEBHOOK_SECRET',
    'EMAIL_TEMPLATE_CACHE_TTL',
    // Email monitoring configurations
    'EMAIL_BOUNCE_RATE_THRESHOLD',
    'EMAIL_COMPLAINT_RATE_THRESHOLD',
    'EMAIL_DELIVERABILITY_THRESHOLD',
    'EMAIL_MONITORING_INTERVAL',
    'EMAIL_ALERT_COOLDOWN',
    'EMAIL_MAX_BOUNCE_COUNT',
    'EMAIL_REPUTATION_WINDOW',
    'ENABLE_EMAIL_MONITORING',
    // Email domain validation configurations
    'EMAIL_DOMAIN_WHITELIST',
    'EMAIL_DOMAIN_BLACKLIST',
    'EMAIL_MX_VALIDATION',
    'EMAIL_DISPOSABLE_CHECK',
    'EMAIL_SUSPICIOUS_PATTERN_CHECK',
    'EMAIL_LOG_BLOCKED',
    // Scheduler service configurations
    'SCHEDULER_MONTHLY_JOB_DAY',
    'SCHEDULER_MONTHLY_JOB_HOUR',
    'SCHEDULER_TIMEZONE',
    'SCHEDULER_BATCH_SIZE',
    'SCHEDULER_INVITATION_BATCH_SIZE',
    'SCHEDULER_MAX_WORKERS',
    'SCHEDULER_WORKER_TIMEOUT',
    'SCHEDULER_MAX_MEMORY_MB',
    'SCHEDULER_MAX_JOB_DURATION_HOURS',
    'SCHEDULER_FIRST_REMINDER_DAYS',
    'SCHEDULER_SECOND_REMINDER_DAYS',
    'SCHEDULER_EXPIRED_TOKEN_RETENTION_DAYS',
    'SCHEDULER_METRICS_RETENTION_HOURS',
    'SCHEDULER_ERROR_RATE_THRESHOLD',
    'SCHEDULER_MEMORY_ALERT_THRESHOLD'
  ];

  static validate() {
    const missing = [];
    const warnings = [];

    // Vérifier les variables requises
    this.requiredVars.forEach(varName => {
      if (!process.env[varName]) {
        missing.push(varName);
      }
    });

    // Vérifier les variables optionnelles avec warning
    this.optionalVars.forEach(varName => {
      if (!process.env[varName]) {
        warnings.push(varName);
      }
    });

    if (missing.length > 0) {
      console.error('❌ Variables d\'environnement manquantes:', missing);
      throw new Error(`Variables d'environnement requises manquantes: ${missing.join(', ')}`);
    }

    if (warnings.length > 0) {
      console.warn('⚠️  Variables d\'environnement optionnelles manquantes:', warnings);
    }

    console.log('✅ Variables d\'environnement validées');
    return true;
  }

  static getConfig() {
    return {
      port: process.env.PORT || 3000,
      nodeEnv: process.env.NODE_ENV || 'development',
      mongodb: {
        uri: process.env.MONGODB_URI
      },
      session: {
        secret: process.env.SESSION_SECRET
      },
      admin: {
        user: process.env.LOGIN_ADMIN_USER,
        password: process.env.LOGIN_ADMIN_PASS,
        formName: process.env.FORM_ADMIN_NAME
      },
      urls: {
        appBase: process.env.APP_BASE_URL,
        frontend: process.env.FRONTEND_URL
      },
      cloudinary: {
        cloudName: process.env.CLOUDINARY_CLOUD_NAME,
        apiKey: process.env.CLOUDINARY_API_KEY,
        apiSecret: process.env.CLOUDINARY_API_SECRET
      },
      services: {
        contact: {
          maxCsvSize: parseInt(process.env.CONTACT_MAX_CSV_SIZE) || (5 * 1024 * 1024), // 5MB
          maxBatchSize: parseInt(process.env.CONTACT_MAX_BATCH_SIZE) || 100,
          maxTags: parseInt(process.env.CONTACT_MAX_TAGS) || 10,
          maxNameLength: 100,
          maxEmailLength: 320,
          maxNotesLength: 1000,
          maxTagLength: 50
        },
        invitation: {
          tokenLength: parseInt(process.env.INVITATION_TOKEN_LENGTH) || 32,
          shortCodeLength: 8,
          expirationDays: parseInt(process.env.INVITATION_EXPIRATION_DAYS) || 60,
          antiTransferWindowHours: 24,
          maxIpChanges: parseInt(process.env.INVITATION_MAX_IP_CHANGES) || 3,
          rateLimitAttempts: 5
        },
        submission: {
          maxTextResponses: parseInt(process.env.SUBMISSION_MAX_TEXT_RESPONSES) || 8,
          maxPhotoResponses: parseInt(process.env.SUBMISSION_MAX_PHOTO_RESPONSES) || 5,
          minCompletionRate: parseInt(process.env.SUBMISSION_MIN_COMPLETION_RATE) || 50,
          maxQuestionTextLength: 500,
          maxAnswerTextLength: 10000,
          maxPhotoCaptionLength: 500,
          maxFreeTextLength: 5000
        },
        handshake: {
          expirationDays: parseInt(process.env.HANDSHAKE_EXPIRATION_DAYS) || 30,
          maxPending: parseInt(process.env.HANDSHAKE_MAX_PENDING) || 50,
          maxMessageLength: 500,
          cleanupIntervalHours: parseInt(process.env.HANDSHAKE_CLEANUP_INTERVAL_HOURS) || 6,
          notificationBeforeExpiryDays: 3
        },
        email: {
          resendApiKey: process.env.RESEND_API_KEY,
          postmarkApiKey: process.env.POSTMARK_API_KEY,
          fromAddress: process.env.EMAIL_FROM_ADDRESS || 'noreply@form-a-friend.com',
          fromName: process.env.EMAIL_FROM_NAME || 'Form-a-Friend',
          batchSize: parseInt(process.env.EMAIL_BATCH_SIZE) || 50,
          rateLimitPerMinute: parseInt(process.env.EMAIL_RATE_LIMIT_PER_MINUTE) || 100,
          webhookSecret: process.env.EMAIL_WEBHOOK_SECRET,
          templateCacheTTL: parseInt(process.env.EMAIL_TEMPLATE_CACHE_TTL) || 600000, // 10 minutes
          retryDelays: [1000, 5000, 15000], // exponential backoff: 1s, 5s, 15s
          maxRetries: 3,
          timeout: 30000 // 30 seconds
        },
        emailValidation: {
          whitelist: process.env.EMAIL_DOMAIN_WHITELIST ? process.env.EMAIL_DOMAIN_WHITELIST.split(',').map(d => d.trim()) : [],
          blacklist: process.env.EMAIL_DOMAIN_BLACKLIST ? process.env.EMAIL_DOMAIN_BLACKLIST.split(',').map(d => d.trim()) : [],
          enableMXValidation: process.env.EMAIL_MX_VALIDATION !== 'false',
          enableDisposableCheck: process.env.EMAIL_DISPOSABLE_CHECK !== 'false',
          enableSuspiciousPatternCheck: process.env.EMAIL_SUSPICIOUS_PATTERN_CHECK !== 'false',
          logBlockedAttempts: process.env.EMAIL_LOG_BLOCKED !== 'false'
        },
        scheduler: {
          // Monthly job scheduling
          monthlyJobDay: parseInt(process.env.SCHEDULER_MONTHLY_JOB_DAY) || 5,
          monthlyJobHour: parseInt(process.env.SCHEDULER_MONTHLY_JOB_HOUR) || 18,
          monthlyJobMinute: 0,
          timezone: process.env.SCHEDULER_TIMEZONE || 'Europe/Paris',
          
          // Reminder settings
          firstReminderDays: parseInt(process.env.SCHEDULER_FIRST_REMINDER_DAYS) || 3,
          secondReminderDays: parseInt(process.env.SCHEDULER_SECOND_REMINDER_DAYS) || 7,
          reminderCheckInterval: '0 */1 * * *', // Every hour
          
          // Batch processing
          batchSize: parseInt(process.env.SCHEDULER_BATCH_SIZE) || 50,
          invitationBatchSize: parseInt(process.env.SCHEDULER_INVITATION_BATCH_SIZE) || 100,
          maxConcurrentWorkers: parseInt(process.env.SCHEDULER_MAX_WORKERS) || 4,
          workerTimeout: parseInt(process.env.SCHEDULER_WORKER_TIMEOUT) || 300000, // 5 minutes
          
          // Performance limits
          maxMemoryUsage: (parseInt(process.env.SCHEDULER_MAX_MEMORY_MB) || 512) * 1024 * 1024,
          memoryCheckInterval: 30000, // 30 seconds
          maxJobDuration: (parseInt(process.env.SCHEDULER_MAX_JOB_DURATION_HOURS) || 1) * 60 * 60 * 1000,
          
          // Retry and error handling
          maxRetries: 3,
          retryDelays: [1000, 5000, 15000], // Exponential backoff
          
          // Cleanup settings
          cleanupInterval: '0 2 * * *', // Daily at 2 AM
          expiredTokenRetentionDays: parseInt(process.env.SCHEDULER_EXPIRED_TOKEN_RETENTION_DAYS) || 90,
          oldDataRetentionDays: 365,
          
          // Monitoring
          healthCheckInterval: '*/5 * * * *', // Every 5 minutes
          metricsRetentionHours: parseInt(process.env.SCHEDULER_METRICS_RETENTION_HOURS) || 72,
          alertThresholds: {
            errorRate: parseFloat(process.env.SCHEDULER_ERROR_RATE_THRESHOLD) || 0.05, // 5%
            memoryUsage: parseFloat(process.env.SCHEDULER_MEMORY_ALERT_THRESHOLD) || 0.8, // 80%
            jobDuration: 0.75, // 75% of max
            failedBatches: 3
          }
        }
      }
    };
  }

  static isDevelopment() {
    return process.env.NODE_ENV !== 'production';
  }

  static isProduction() {
    return process.env.NODE_ENV === 'production';
  }

  static logEnvironment() {
    const config = this.getConfig();
    console.log(`🚀 Environnement: ${config.nodeEnv}`);
    console.log(`📡 Port: ${config.port}`);
    console.log(`🔗 URL de base: ${config.urls.appBase}`);
  }
}

module.exports = EnvironmentConfig;