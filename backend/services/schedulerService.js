const cron = require('node-cron');
const { Worker } = require('worker_threads');
const path = require('path');
const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');
const RealTimeMetrics = require('./realTimeMetrics');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Invitation = require('../models/Invitation');

/**
 * Form-a-Friend v2 Scheduler Service
 * 
 * Complete automation orchestration for monthly invitation cycles with:
 * - Monthly job execution (5th at 6 PM Paris time)
 * - Intelligent reminder system (J+3 and J+7)
 * - Automatic cleanup and maintenance
 * - Real-time monitoring and metrics
 * - Worker thread integration for heavy operations
 * - Robust error handling and recovery
 * 
 * Expected Load: 5000+ users × 20 contacts = 100k+ invitations/month
 * Performance Target: <1 hour for complete monthly cycle
 * Memory Constraint: <512MB peak usage during processing
 * Reliability Target: <1% error rate on critical jobs
 */
class SchedulerService extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      // Scheduling parameters
      monthlyJobDay: config.monthlyJobDay || 5, // 5th of each month
      monthlyJobHour: config.monthlyJobHour || 18, // 6 PM
      monthlyJobMinute: config.monthlyJobMinute || 0,
      timezone: config.timezone || 'Europe/Paris',
      
      // Reminder settings
      firstReminderDays: config.firstReminderDays || 3, // J+3
      secondReminderDays: config.secondReminderDays || 7, // J+7
      reminderCheckInterval: config.reminderCheckInterval || '0 */1 * * *', // Every hour
      
      // Batch processing
      batchSize: config.batchSize || 50, // Users per batch
      invitationBatchSize: config.invitationBatchSize || 100, // Invitations per batch
      maxConcurrentWorkers: config.maxConcurrentWorkers || 4,
      workerTimeout: config.workerTimeout || 300000, // 5 minutes
      
      // Performance limits
      maxMemoryUsage: config.maxMemoryUsage || 512 * 1024 * 1024, // 512MB
      memoryCheckInterval: config.memoryCheckInterval || 30000, // 30 seconds
      maxJobDuration: config.maxJobDuration || 3600000, // 1 hour
      
      // Retry and error handling
      maxRetries: config.maxRetries || 3,
      retryDelays: config.retryDelays || [1000, 5000, 15000], // Exponential backoff
      
      // Cleanup settings
      cleanupInterval: config.cleanupInterval || '0 2 * * *', // Daily at 2 AM
      expiredTokenRetentionDays: config.expiredTokenRetentionDays || 90,
      oldDataRetentionDays: config.oldDataRetentionDays || 365,
      
      // Monitoring
      healthCheckInterval: config.healthCheckInterval || '*/5 * * * *', // Every 5 minutes
      metricsRetentionHours: config.metricsRetentionHours || 72,
      alertThresholds: {
        errorRate: config.alertThresholds?.errorRate || 0.05, // 5%
        memoryUsage: config.alertThresholds?.memoryUsage || 0.8, // 80%
        jobDuration: config.alertThresholds?.jobDuration || 0.75, // 75% of max
        failedBatches: config.alertThresholds?.failedBatches || 3
      },
      
      ...config
    };

    // Service state
    this.isRunning = false;
    this.activeJobs = new Map();
    this.workers = new Map();
    this.cronJobs = new Map();
    this.jobHistory = [];
    this.lastHealthCheck = null;
    
    // Metrics tracking
    this.metrics = {
      totalJobsRun: 0,
      totalJobsSuccess: 0,
      totalJobsFailed: 0,
      totalInvitationsSent: 0,
      totalRemindersSent: 0,
      averageJobDuration: 0,
      peakMemoryUsage: 0,
      lastJobTimestamp: null,
      lastJobStatus: null,
      currentJobsRunning: 0,
      errorRate: 0,
      performanceStats: {
        batchProcessingTimes: [],
        workerUtilization: [],
        memoryUsageHistory: []
      }
    };

    // Service dependencies (injected)
    this.invitationService = null;
    this.contactService = null;
    this.emailService = null;
    this.realTimeMetrics = null;

    SecureLogger.logInfo('SchedulerService initialized', {
      monthlyJobDay: this.config.monthlyJobDay,
      monthlyJobHour: this.config.monthlyJobHour,
      timezone: this.config.timezone,
      batchSize: this.config.batchSize,
      maxWorkers: this.config.maxConcurrentWorkers
    });
  }

  /**
   * Initialize and start the scheduler service
   * @param {Object} services - Service dependencies
   */
  async initialize(services = {}) {
    try {
      // Inject service dependencies
      this.invitationService = services.invitationService;
      this.contactService = services.contactService;
      this.emailService = services.emailService;
      this.realTimeMetrics = services.realTimeMetrics;

      if (!this.invitationService || !this.emailService) {
        throw new Error('Required services not provided: invitationService, emailService');
      }

      // Setup cron jobs
      await this.setupCronJobs();
      
      // Start health monitoring
      await this.startHealthMonitoring();
      
      // Start memory monitoring
      this.startMemoryMonitoring();
      
      this.isRunning = true;
      
      SecureLogger.logInfo('SchedulerService successfully initialized and started');
      this.emit('service-started');
      
      return true;
    } catch (error) {
      SecureLogger.logError('Failed to initialize SchedulerService', error);
      throw error;
    }
  }

  /**
   * Setup all cron jobs
   */
  async setupCronJobs() {
    try {
      // Monthly invitation job - 5th of month at 6 PM Paris time
      const monthlyJobCron = `${this.config.monthlyJobMinute} ${this.config.monthlyJobHour} ${this.config.monthlyJobDay} * *`;
      const monthlyJob = cron.schedule(monthlyJobCron, async () => {
        await this.runMonthlyInvitationJob();
      }, {
        scheduled: false,
        timezone: this.config.timezone
      });

      this.cronJobs.set('monthly-invitations', monthlyJob);
      
      // Reminder job - hourly check for pending reminders
      const reminderJob = cron.schedule(this.config.reminderCheckInterval, async () => {
        await this.runReminderJob();
      }, {
        scheduled: false,
        timezone: this.config.timezone
      });

      this.cronJobs.set('reminders', reminderJob);
      
      // Cleanup job - daily at 2 AM
      const cleanupJob = cron.schedule(this.config.cleanupInterval, async () => {
        await this.runCleanupJob();
      }, {
        scheduled: false,
        timezone: this.config.timezone
      });

      this.cronJobs.set('cleanup', cleanupJob);
      
      // Health check job - every 5 minutes
      const healthCheckJob = cron.schedule(this.config.healthCheckInterval, async () => {
        await this.runHealthCheck();
      }, {
        scheduled: false,
        timezone: this.config.timezone
      });

      this.cronJobs.set('health-check', healthCheckJob);

      SecureLogger.logInfo('Cron jobs configured', {
        monthlyJob: monthlyJobCron,
        reminderJob: this.config.reminderCheckInterval,
        cleanupJob: this.config.cleanupInterval,
        healthCheckJob: this.config.healthCheckInterval,
        timezone: this.config.timezone
      });

    } catch (error) {
      SecureLogger.logError('Failed to setup cron jobs', error);
      throw error;
    }
  }

  /**
   * Start all scheduled jobs
   */
  async start() {
    try {
      if (!this.isRunning) {
        throw new Error('SchedulerService not initialized. Call initialize() first.');
      }

      // Start all cron jobs
      for (const [jobName, cronJob] of this.cronJobs) {
        cronJob.start();
        SecureLogger.logInfo(`Started cron job: ${jobName}`);
      }

      SecureLogger.logInfo('All scheduled jobs started successfully');
      this.emit('jobs-started');
      
    } catch (error) {
      SecureLogger.logError('Failed to start scheduled jobs', error);
      throw error;
    }
  }

  /**
   * Stop all scheduled jobs
   */
  async stop() {
    try {
      // Stop all cron jobs
      for (const [jobName, cronJob] of this.cronJobs) {
        cronJob.stop();
        SecureLogger.logInfo(`Stopped cron job: ${jobName}`);
      }

      // Wait for active jobs to complete or timeout
      await this.waitForActiveJobsCompletion(30000); // 30 seconds timeout

      // Terminate any remaining workers
      await this.terminateAllWorkers();

      this.isRunning = false;

      SecureLogger.logInfo('SchedulerService stopped successfully');
      this.emit('service-stopped');
      
    } catch (error) {
      SecureLogger.logError('Error during SchedulerService shutdown', error);
      throw error;
    }
  }

  /**
   * Main monthly invitation job - sends invitations to all active users
   */
  async runMonthlyInvitationJob() {
    const jobId = `monthly-${Date.now()}`;
    const startTime = Date.now();
    
    try {
      SecureLogger.logInfo('Starting monthly invitation job', { jobId });
      
      this.activeJobs.set(jobId, {
        type: 'monthly-invitations',
        startTime,
        status: 'running',
        progress: 0,
        stats: {
          totalUsers: 0,
          processedUsers: 0,
          totalInvitations: 0,
          sentInvitations: 0,
          failedInvitations: 0,
          batchesProcessed: 0,
          errors: []
        }
      });

      this.metrics.currentJobsRunning++;
      this.emit('job-started', { jobId, type: 'monthly-invitations' });

      // Get current month in YYYY-MM format
      const currentMonth = new Date().toISOString().substring(0, 7);
      
      // Phase 1: Get all active users with contacts
      const users = await this.getActiveUsersForInvitations();
      
      if (users.length === 0) {
        SecureLogger.logInfo('No active users found for monthly invitations');
        await this.completeJob(jobId, 'success', { totalUsers: 0 });
        return;
      }

      const job = this.activeJobs.get(jobId);
      job.stats.totalUsers = users.length;
      
      SecureLogger.logInfo(`Found ${users.length} active users for monthly invitations`);

      // Phase 2: Process users in batches using worker threads
      const results = await this.processBatchesWithWorkers(
        users,
        'monthly-invitations',
        { month: currentMonth, jobId }
      );

      // Phase 3: Aggregate results and update metrics
      const finalStats = this.aggregateJobResults(results, job.stats);
      
      // Update job completion
      await this.completeJob(jobId, 'success', finalStats);
      
      // Update global metrics
      this.updateMetricsAfterJob('monthly-invitations', finalStats, Date.now() - startTime);
      
      SecureLogger.logInfo('Monthly invitation job completed successfully', {
        jobId,
        duration: Date.now() - startTime,
        stats: finalStats
      });

      this.emit('monthly-job-completed', { jobId, stats: finalStats });

    } catch (error) {
      await this.handleJobError(jobId, 'monthly-invitations', error, startTime);
    }
  }

  /**
   * Reminder job - checks and sends J+3 and J+7 reminders
   */
  async runReminderJob() {
    const jobId = `reminder-${Date.now()}`;
    const startTime = Date.now();
    
    try {
      SecureLogger.logInfo('Starting reminder job', { jobId });
      
      this.activeJobs.set(jobId, {
        type: 'reminders',
        startTime,
        status: 'running',
        progress: 0,
        stats: {
          firstRemindersChecked: 0,
          firstRemindersSent: 0,
          secondRemindersChecked: 0,
          secondRemindersSent: 0,
          errors: []
        }
      });

      this.metrics.currentJobsRunning++;
      this.emit('job-started', { jobId, type: 'reminders' });

      // Process J+3 reminders (first reminder)
      const firstReminderResults = await this.processReminders('first', this.config.firstReminderDays);
      
      // Process J+7 reminders (second reminder)
      const secondReminderResults = await this.processReminders('second', this.config.secondReminderDays);

      const finalStats = {
        firstRemindersChecked: firstReminderResults.checked,
        firstRemindersSent: firstReminderResults.sent,
        secondRemindersChecked: secondReminderResults.checked,
        secondRemindersSent: secondReminderResults.sent,
        totalSent: firstReminderResults.sent + secondReminderResults.sent,
        errors: [...firstReminderResults.errors, ...secondReminderResults.errors]
      };

      await this.completeJob(jobId, 'success', finalStats);
      
      this.updateMetricsAfterJob('reminders', finalStats, Date.now() - startTime);
      
      SecureLogger.logInfo('Reminder job completed successfully', {
        jobId,
        duration: Date.now() - startTime,
        stats: finalStats
      });

      this.emit('reminder-job-completed', { jobId, stats: finalStats });

    } catch (error) {
      await this.handleJobError(jobId, 'reminders', error, startTime);
    }
  }

  /**
   * Cleanup job - removes expired tokens and old data
   */
  async runCleanupJob() {
    const jobId = `cleanup-${Date.now()}`;
    const startTime = Date.now();
    
    try {
      SecureLogger.logInfo('Starting cleanup job', { jobId });
      
      this.activeJobs.set(jobId, {
        type: 'cleanup',
        startTime,
        status: 'running',
        progress: 0,
        stats: {
          expiredInvitations: 0,
          deletedInvitations: 0,
          cleanedContacts: 0,
          freedMemory: 0,
          errors: []
        }
      });

      this.metrics.currentJobsRunning++;
      this.emit('job-started', { jobId, type: 'cleanup' });

      // Clean expired invitations
      const expiredResult = await this.cleanupExpiredInvitations();
      
      // Clean old contact data
      const contactResult = await this.cleanupOldContactData();
      
      // Clean internal metrics and cache
      const memoryResult = await this.cleanupMemory();

      const finalStats = {
        expiredInvitations: expiredResult.expired,
        deletedInvitations: expiredResult.deleted,
        cleanedContacts: contactResult.cleaned,
        freedMemory: memoryResult.freed,
        errors: [...expiredResult.errors, ...contactResult.errors, ...memoryResult.errors]
      };

      await this.completeJob(jobId, 'success', finalStats);
      
      SecureLogger.logInfo('Cleanup job completed successfully', {
        jobId,
        duration: Date.now() - startTime,
        stats: finalStats
      });

      this.emit('cleanup-job-completed', { jobId, stats: finalStats });

    } catch (error) {
      await this.handleJobError(jobId, 'cleanup', error, startTime);
    }
  }

  /**
   * Health check job - monitors system health and performance
   */
  async runHealthCheck() {
    const startTime = Date.now();
    
    try {
      const healthData = {
        timestamp: new Date(),
        systemHealth: await this.checkSystemHealth(),
        serviceHealth: await this.checkServiceHealth(),
        databaseHealth: await this.checkDatabaseHealth(),
        memoryUsage: process.memoryUsage(),
        activeJobs: this.activeJobs.size,
        activeWorkers: this.workers.size,
        metrics: this.getBasicMetrics()
      };

      this.lastHealthCheck = healthData;
      
      // Check for alert conditions
      await this.checkAlertConditions(healthData);
      
      // Update performance metrics
      this.updatePerformanceMetrics(healthData);
      
      this.emit('health-check-completed', healthData);
      
      SecureLogger.logDebug('Health check completed', {
        duration: Date.now() - startTime,
        systemHealth: healthData.systemHealth.status,
        activeJobs: healthData.activeJobs
      });

    } catch (error) {
      SecureLogger.logError('Health check failed', error);
      this.emit('health-check-failed', { error: error.message });
    }
  }

  /**
   * Get active users eligible for monthly invitations
   */
  async getActiveUsersForInvitations() {
    try {
      const users = await User.find({
        'metadata.isActive': true,
        'preferences.sendDay': { $lte: new Date().getDate() }
      })
      .select('_id username email preferences statistics')
      .lean();

      // Filter users with contacts
      const usersWithContacts = [];
      
      for (const user of users) {
        const contactCount = await Contact.countDocuments({
          ownerId: user._id,
          isActive: true,
          optedOut: false,
          status: { $in: ['active', 'pending'] }
        });
        
        if (contactCount > 0) {
          user.contactCount = contactCount;
          usersWithContacts.push(user);
        }
      }

      return usersWithContacts;
    } catch (error) {
      SecureLogger.logError('Failed to get active users for invitations', error);
      throw error;
    }
  }

  /**
   * Process users in batches using worker threads
   */
  async processBatchesWithWorkers(users, jobType, options = {}) {
    const batches = this.createBatches(users, this.config.batchSize);
    const results = [];
    const activeWorkers = [];

    try {
      SecureLogger.logInfo(`Processing ${batches.length} batches with up to ${this.config.maxConcurrentWorkers} workers`);

      for (let i = 0; i < batches.length; i += this.config.maxConcurrentWorkers) {
        const batchGroup = batches.slice(i, i + this.config.maxConcurrentWorkers);
        const workerPromises = [];

        for (const batch of batchGroup) {
          const workerPromise = this.createWorkerForBatch(batch, jobType, options);
          workerPromises.push(workerPromise);
          activeWorkers.push(workerPromise);
        }

        // Wait for this group of workers to complete
        const batchResults = await Promise.allSettled(workerPromises);
        
        for (const result of batchResults) {
          if (result.status === 'fulfilled') {
            results.push(result.value);
          } else {
            SecureLogger.logError('Worker batch failed', result.reason);
            results.push({
              success: false,
              error: result.reason?.message || 'Unknown worker error',
              processed: 0,
              failed: batch?.length || 0
            });
          }
        }

        // Update progress
        const progressPercent = Math.round(((i + batchGroup.length) / batches.length) * 100);
        this.updateJobProgress(options.jobId, progressPercent);
      }

      return results;
    } catch (error) {
      SecureLogger.logError('Failed to process batches with workers', error);
      
      // Cleanup any remaining workers
      await this.terminateWorkers(activeWorkers);
      
      throw error;
    }
  }

  /**
   * Create a worker thread for processing a batch of users
   */
  async createWorkerForBatch(batch, jobType, options = {}) {
    return new Promise((resolve, reject) => {
      const workerId = `worker-${Date.now()}-${Math.random().toString(36).substring(7)}`;
      const workerPath = path.join(__dirname, 'workers', 'batchProcessor.js');
      
      const worker = new Worker(workerPath, {
        workerData: {
          batch,
          jobType,
          options,
          config: {
            invitation: {
              invitationBatchSize: this.config.invitationBatchSize,
              maxRetries: this.config.maxRetries,
              retryDelays: this.config.retryDelays,
              tokenLength: 32,
              expirationDays: 60
            },
            email: {
              resendApiKey: process.env.RESEND_API_KEY,
              postmarkApiKey: process.env.POSTMARK_API_KEY,
              fromAddress: process.env.EMAIL_FROM_ADDRESS || 'noreply@form-a-friend.com',
              fromName: process.env.EMAIL_FROM_NAME || 'Form-a-Friend',
              batchSize: 50,
              rateLimitPerMinute: 100,
              retryDelays: [1000, 5000, 15000],
              maxRetries: 3,
              timeout: 30000
            },
            contact: {
              maxBatchSize: 100,
              maxTags: 10,
              maxNameLength: 100,
              maxEmailLength: 320,
              maxNotesLength: 1000
            }
          }
        }
      });

      this.workers.set(workerId, {
        worker,
        startTime: Date.now(),
        type: jobType,
        batchSize: batch.length
      });

      // Set timeout for worker
      const timeout = setTimeout(() => {
        worker.terminate();
        this.workers.delete(workerId);
        reject(new Error(`Worker ${workerId} timed out after ${this.config.workerTimeout}ms`));
      }, this.config.workerTimeout);

      worker.on('message', (result) => {
        clearTimeout(timeout);
        this.workers.delete(workerId);
        resolve(result);
      });

      worker.on('error', (error) => {
        clearTimeout(timeout);
        this.workers.delete(workerId);
        reject(error);
      });

      worker.on('exit', (code) => {
        clearTimeout(timeout);
        this.workers.delete(workerId);
        
        if (code !== 0) {
          reject(new Error(`Worker ${workerId} exited with code ${code}`));
        }
      });
    });
  }

  /**
   * Process reminders for a specific type and day offset with ContactService integration
   */
  async processReminders(reminderType, daysAgo) {
    try {
      const cutoffDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
      
      // Find invitations that need reminders with enhanced filtering
      const invitations = await Invitation.find({
        'tracking.sentAt': { $lte: cutoffDate },
        status: { $in: ['sent', 'opened', 'started'] },
        expiresAt: { $gt: new Date() }, // Not expired
        [`reminders.type`]: { $ne: reminderType }, // Haven't received this reminder type
        'tracking.bounceCount': { $lt: 3 } // Exclude high-bounce contacts
      })
      .populate('fromUserId', 'username email preferences')
      .populate('toUserId', 'username email preferences')
      .limit(1000) // Process in chunks
      .sort({ 'tracking.sentAt': 1 }); // Oldest first

      const results = {
        checked: invitations.length,
        sent: 0,
        contactsUpdated: 0,
        errors: []
      };

      for (const invitation of invitations) {
        try {
          // Check user reminder preferences
          const fromUser = invitation.fromUserId;
          if (!fromUser || !this.shouldSendReminder(fromUser, reminderType)) {
            continue;
          }

          // Get contact information for enhanced recipient data
          let recipient = invitation.toUserId;
          let contact = null;

          if (!recipient) {
            // For external invitations, try to get contact info
            try {
              contact = await Contact.findOne({
                ownerId: fromUser._id,
                email: invitation.toEmail
              });

              if (contact) {
                // Validate contact status
                if (contact.optedOut || contact.status !== 'active' || contact.bounceCount >= 3) {
                  // Skip this invitation and mark contact as problematic
                  if (this.contactService) {
                    await this.contactService.updateContactTracking(
                      contact._id,
                      fromUser._id,
                      'reminder_skipped',
                      { reason: 'contact_status_invalid', reminderType }
                    );
                  }
                  continue;
                }

                recipient = {
                  email: contact.email,
                  username: contact.firstName || contact.email.split('@')[0],
                  name: `${contact.firstName || ''} ${contact.lastName || ''}`.trim()
                };
              } else {
                // Fallback for missing contact
                recipient = {
                  email: invitation.toEmail,
                  username: invitation.toEmail.split('@')[0],
                  name: invitation.toEmail.split('@')[0]
                };
              }
            } catch (contactError) {
              SecureLogger.logWarning('Failed to fetch contact for reminder', {
                invitationId: invitation._id,
                email: invitation.toEmail,
                error: contactError.message
              });
              
              // Use basic recipient info
              recipient = {
                email: invitation.toEmail,
                username: invitation.toEmail.split('@')[0]
              };
            }
          }

          // Send reminder email with enhanced error handling
          try {
            await this.emailService.sendReminder(invitation, recipient, reminderType, {
              unsubscribeUrl: `${process.env.APP_BASE_URL}/unsubscribe?email=${encodeURIComponent(invitation.toEmail)}`
            });

            // Update invitation with reminder info
            invitation.reminders.push({
              type: reminderType,
              sentAt: new Date(),
              recipientType: contact ? 'contact' : 'user'
            });
            
            // Update tracking
            invitation.tracking.lastReminderSent = new Date();
            invitation.tracking.reminderCount = (invitation.tracking.reminderCount || 0) + 1;
            
            await invitation.save();

            // Update contact tracking if available
            if (contact && this.contactService) {
              await this.contactService.updateContactTracking(
                contact._id,
                fromUser._id,
                'reminder_sent',
                {
                  reminderType,
                  invitationId: invitation._id,
                  reminderNumber: invitation.tracking.reminderCount
                }
              );
              results.contactsUpdated++;
            }

            results.sent++;
            
            SecureLogger.logDebug(`${reminderType} reminder sent successfully`, {
              invitationId: invitation._id,
              recipientEmail: invitation.toEmail,
              reminderType,
              hasContact: !!contact
            });

          } catch (emailError) {
            // Handle email bounce/failure
            invitation.tracking.lastFailedAt = new Date();
            invitation.tracking.bounceCount = (invitation.tracking.bounceCount || 0) + 1;
            
            if (invitation.tracking.bounceCount >= 3) {
              invitation.status = 'bounced';
            }
            
            await invitation.save();

            // Update contact with bounce info
            if (contact && this.contactService) {
              await Contact.findByIdAndUpdate(contact._id, {
                $inc: { bounceCount: 1 },
                $set: {
                  lastBounceAt: new Date(),
                  bounceReason: emailError.message,
                  emailStatus: invitation.tracking.bounceCount >= 3 ? 'bounced_permanent' : 'bounced_temporary'
                }
              });

              // Deactivate contact if too many bounces
              if (contact.bounceCount >= 2) {
                await Contact.findByIdAndUpdate(contact._id, {
                  $set: { 
                    status: 'bounced',
                    isActive: false 
                  }
                });
              }
            }

            throw emailError; // Re-throw to be caught by outer handler
          }

        } catch (error) {
          results.errors.push({
            invitationId: invitation._id,
            email: invitation.toEmail,
            reminderType,
            error: error.message,
            timestamp: new Date()
          });
          
          SecureLogger.logError(`Failed to send ${reminderType} reminder`, {
            invitationId: invitation._id,
            email: invitation.toEmail,
            reminderType,
            error: error.message
          });
        }
      }

      // Log summary
      SecureLogger.logInfo(`${reminderType} reminder processing completed`, {
        checked: results.checked,
        sent: results.sent,
        contactsUpdated: results.contactsUpdated,
        errors: results.errors.length,
        successRate: results.checked > 0 ? ((results.sent / results.checked) * 100).toFixed(2) + '%' : '0%'
      });

      return results;
    } catch (error) {
      SecureLogger.logError(`Failed to process ${reminderType} reminders`, error);
      throw error;
    }
  }

  /**
   * Check if reminder should be sent based on user preferences
   */
  shouldSendReminder(user, reminderType) {
    if (!user.preferences || !user.preferences.reminderSettings) {
      return true; // Default to sending reminders
    }

    const settings = user.preferences.reminderSettings;
    
    if (reminderType === 'first') {
      return settings.firstReminder !== false;
    } else if (reminderType === 'second') {
      return settings.secondReminder !== false;
    }
    
    return true;
  }

  /**
   * Cleanup expired invitations
   */
  async cleanupExpiredInvitations() {
    try {
      const now = new Date();
      const results = { expired: 0, deleted: 0, errors: [] };
      
      // Mark expired invitations
      const expiredResult = await Invitation.updateMany(
        {
          expiresAt: { $lt: now },
          status: { $nin: ['expired', 'submitted', 'cancelled'] }
        },
        { $set: { status: 'expired' } }
      );
      
      results.expired = expiredResult.modifiedCount;
      
      // Delete very old expired invitations
      const cutoffDate = new Date(now.getTime() - this.config.expiredTokenRetentionDays * 24 * 60 * 60 * 1000);
      const deletedResult = await Invitation.deleteMany({
        expiresAt: { $lt: cutoffDate },
        status: 'expired'
      });
      
      results.deleted = deletedResult.deletedCount;
      
      SecureLogger.logInfo('Invitation cleanup completed', results);
      return results;
      
    } catch (error) {
      SecureLogger.logError('Failed to cleanup expired invitations', error);
      return { expired: 0, deleted: 0, errors: [error.message] };
    }
  }

  /**
   * Cleanup old contact data with enhanced ContactService integration
   */
  async cleanupOldContactData() {
    try {
      const results = { 
        cleaned: 0, 
        deactivated: 0,
        reactivated: 0,
        updated: 0,
        errors: [] 
      };
      
      // Phase 1: Reset bounce counts for contacts that haven't bounced recently
      const bounceResetCutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days
      const bounceResetResult = await Contact.updateMany(
        {
          lastBounceAt: { $lt: bounceResetCutoff },
          bounceCount: { $gt: 0, $lt: 5 },
          emailStatus: 'bounced_temporary'
        },
        {
          $set: {
            bounceCount: 0,
            emailStatus: 'active',
            status: 'active',
            isActive: true
          },
          $unset: {
            bounceReason: 1
          }
        }
      );
      
      results.reactivated = bounceResetResult.modifiedCount;
      
      // Phase 2: Deactivate permanently bounced contacts
      const permanentBounceResult = await Contact.updateMany(
        {
          bounceCount: { $gte: 5 },
          status: { $ne: 'bounced' },
          isActive: true
        },
        {
          $set: {
            status: 'bounced',
            isActive: false,
            emailStatus: 'bounced_permanent'
          }
        }
      );
      
      results.deactivated = permanentBounceResult.modifiedCount;
      
      // Phase 3: Update contact statistics and tracking
      if (this.contactService) {
        try {
          // Get all users to update their contact statistics
          const users = await User.find(
            { 'metadata.isActive': true },
            { _id: 1 }
          ).limit(1000);
          
          for (const user of users) {
            try {
              // Update contact statistics for each user
              const contactStats = await this.contactService.getContactStats(user._id);
              
              await User.findByIdAndUpdate(user._id, {
                $set: {
                  'statistics.totalContacts': contactStats.basic.total,
                  'statistics.activeContacts': contactStats.basic.total - results.deactivated,
                  'statistics.averageResponseRate': contactStats.basic.avgResponseRate || 0,
                  'metadata.contactStatsUpdatedAt': new Date()
                }
              });
              
              results.updated++;
              
            } catch (userError) {
              results.errors.push({
                userId: user._id,
                error: userError.message
              });
            }
          }
        } catch (statsError) {
          SecureLogger.logWarning('Failed to update contact statistics during cleanup', {
            error: statsError.message
          });
        }
      }
      
      // Phase 4: Clean up orphaned contact data
      const orphanCleanupResult = await Contact.deleteMany({
        ownerId: { $exists: false },
        createdAt: { $lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) } // 90 days old
      });
      
      results.cleaned = orphanCleanupResult.deletedCount;
      
      // Phase 5: Update contact response rates based on recent invitation data
      const responseRateUpdateCutoff = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000); // 6 months
      const contactsToUpdate = await Contact.aggregate([
        {
          $match: {
            'tracking.lastSentAt': { $gte: responseRateUpdateCutoff },
            isActive: true
          }
        },
        {
          $lookup: {
            from: 'invitations',
            localField: 'email',
            foreignField: 'toEmail',
            as: 'recentInvitations'
          }
        },
        {
          $addFields: {
            recentInvitations: {
              $filter: {
                input: '$recentInvitations',
                cond: { $gte: ['$$this.createdAt', responseRateUpdateCutoff] }
              }
            }
          }
        },
        {
          $addFields: {
            totalSent: { $size: '$recentInvitations' },
            totalResponded: {
              $size: {
                $filter: {
                  input: '$recentInvitations',
                  cond: { $eq: ['$$this.status', 'submitted'] }
                }
              }
            }
          }
        },
        {
          $addFields: {
            newResponseRate: {
              $cond: [
                { $gt: ['$totalSent', 0] },
                { $multiply: [{ $divide: ['$totalResponded', '$totalSent'] }, 100] },
                0
              ]
            }
          }
        },
        {
          $match: {
            $expr: {
              $ne: ['$newResponseRate', '$tracking.responseRate']
            }
          }
        }
      ]);
      
      // Update response rates
      for (const contact of contactsToUpdate) {
        try {
          await Contact.findByIdAndUpdate(contact._id, {
            $set: {
              'tracking.responseRate': contact.newResponseRate,
              'tracking.responsesReceived': contact.totalResponded,
              'tracking.invitationsSent': contact.totalSent,
              'tracking.lastUpdated': new Date()
            }
          });
        } catch (updateError) {
          results.errors.push({
            contactId: contact._id,
            error: updateError.message
          });
        }
      }
      
      SecureLogger.logInfo('Enhanced contact data cleanup completed', {
        cleaned: results.cleaned,
        deactivated: results.deactivated,
        reactivated: results.reactivated,
        updated: results.updated,
        responseRatesUpdated: contactsToUpdate.length,
        errors: results.errors.length
      });
      
      return results;
      
    } catch (error) {
      SecureLogger.logError('Failed to cleanup old contact data', error);
      return { 
        cleaned: 0, 
        deactivated: 0,
        reactivated: 0,
        updated: 0,
        errors: [error.message] 
      };
    }
  }

  /**
   * Cleanup memory and internal caches
   */
  async cleanupMemory() {
    try {
      const beforeMemory = process.memoryUsage();
      const results = { freed: 0, errors: [] };
      
      // Clear old job history
      const cutoffTime = Date.now() - this.config.metricsRetentionHours * 60 * 60 * 1000;
      this.jobHistory = this.jobHistory.filter(job => job.startTime > cutoffTime);
      
      // Clear old performance stats
      this.metrics.performanceStats.batchProcessingTimes = 
        this.metrics.performanceStats.batchProcessingTimes.slice(-100);
      this.metrics.performanceStats.workerUtilization = 
        this.metrics.performanceStats.workerUtilization.slice(-100);
      this.metrics.performanceStats.memoryUsageHistory = 
        this.metrics.performanceStats.memoryUsageHistory.slice(-100);
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const afterMemory = process.memoryUsage();
      results.freed = beforeMemory.heapUsed - afterMemory.heapUsed;
      
      SecureLogger.logInfo('Memory cleanup completed', {
        freedBytes: results.freed,
        beforeHeapUsed: beforeMemory.heapUsed,
        afterHeapUsed: afterMemory.heapUsed
      });
      
      return results;
      
    } catch (error) {
      SecureLogger.logError('Failed to cleanup memory', error);
      return { freed: 0, errors: [error.message] };
    }
  }

  /**
   * Start memory monitoring
   */
  startMemoryMonitoring() {
    setInterval(() => {
      const memUsage = process.memoryUsage();
      const usagePercent = memUsage.heapUsed / this.config.maxMemoryUsage;
      
      // Update peak memory usage
      if (memUsage.heapUsed > this.metrics.peakMemoryUsage) {
        this.metrics.peakMemoryUsage = memUsage.heapUsed;
      }
      
      // Add to history
      this.metrics.performanceStats.memoryUsageHistory.push({
        timestamp: Date.now(),
        heapUsed: memUsage.heapUsed,
        heapTotal: memUsage.heapTotal,
        external: memUsage.external,
        usagePercent
      });
      
      // Check memory threshold
      if (usagePercent > this.config.alertThresholds.memoryUsage) {
        SecureLogger.logWarning('High memory usage detected', {
          heapUsed: memUsage.heapUsed,
          heapTotal: memUsage.heapTotal,
          usagePercent: Math.round(usagePercent * 100) + '%',
          threshold: Math.round(this.config.alertThresholds.memoryUsage * 100) + '%'
        });
        
        this.emit('high-memory-usage', { memUsage, usagePercent });
      }
      
    }, this.config.memoryCheckInterval);
  }

  /**
   * Start health monitoring
   */
  async startHealthMonitoring() {
    // Initial health check
    await this.runHealthCheck();
    
    SecureLogger.logInfo('Health monitoring started');
  }

  /**
   * Check system health
   */
  async checkSystemHealth() {
    try {
      const memUsage = process.memoryUsage();
      const uptime = process.uptime();
      
      return {
        status: 'healthy',
        uptime,
        memoryUsage: memUsage,
        nodeVersion: process.version,
        platform: process.platform
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  /**
   * Check service health
   */
  async checkServiceHealth() {
    try {
      const health = {
        status: 'healthy',
        isRunning: this.isRunning,
        activeJobs: this.activeJobs.size,
        activeWorkers: this.workers.size,
        cronJobsRunning: 0
      };
      
      // Check cron jobs
      for (const [jobName, cronJob] of this.cronJobs) {
        if (cronJob.running) {
          health.cronJobsRunning++;
        }
      }
      
      return health;
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }

  /**
   * Check database health
   */
  async checkDatabaseHealth() {
    try {
      // Simple database connectivity check
      await User.findOne().limit(1);
      await Contact.findOne().limit(1);
      await Invitation.findOne().limit(1);
      
      return {
        status: 'healthy',
        connected: true
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        connected: false,
        error: error.message
      };
    }
  }

  /**
   * Check alert conditions with enhanced monitoring
   */
  async checkAlertConditions(healthData) {
    const alerts = [];
    
    // Check error rate
    if (this.metrics.errorRate > this.config.alertThresholds.errorRate) {
      alerts.push({
        type: 'high-error-rate',
        value: this.metrics.errorRate,
        threshold: this.config.alertThresholds.errorRate,
        severity: 'high',
        message: `Error rate ${(this.metrics.errorRate * 100).toFixed(2)}% exceeds threshold ${(this.config.alertThresholds.errorRate * 100).toFixed(2)}%`
      });
    }
    
    // Check memory usage
    const memUsagePercent = healthData.memoryUsage.heapUsed / this.config.maxMemoryUsage;
    if (memUsagePercent > this.config.alertThresholds.memoryUsage) {
      alerts.push({
        type: 'high-memory-usage',
        value: memUsagePercent,
        threshold: this.config.alertThresholds.memoryUsage,
        severity: memUsagePercent > 0.9 ? 'critical' : 'high',
        message: `Memory usage ${(memUsagePercent * 100).toFixed(2)}% exceeds threshold ${(this.config.alertThresholds.memoryUsage * 100).toFixed(2)}%`,
        details: {
          heapUsed: Math.round(healthData.memoryUsage.heapUsed / 1024 / 1024) + 'MB',
          heapTotal: Math.round(healthData.memoryUsage.heapTotal / 1024 / 1024) + 'MB',
          external: Math.round(healthData.memoryUsage.external / 1024 / 1024) + 'MB'
        }
      });
    }
    
    // Check for stuck jobs
    const now = Date.now();
    for (const [jobId, job] of this.activeJobs) {
      const duration = now - job.startTime;
      const maxDuration = this.config.maxJobDuration;
      
      if (duration > maxDuration) {
        alerts.push({
          type: 'stuck-job',
          jobId,
          duration,
          maxDuration,
          severity: 'critical',
          message: `Job ${jobId} running for ${Math.round(duration / 60000)} minutes exceeds maximum ${Math.round(maxDuration / 60000)} minutes`,
          jobType: job.type,
          progress: job.progress || 0
        });
      }
    }
    
    // Check EmailService integration health
    if (this.emailService) {
      const emailMetrics = this.emailService.getMetrics();
      if (emailMetrics.deliveryRate < 0.95 && emailMetrics.totalSent > 10) {
        alerts.push({
          type: 'low-email-delivery-rate',
          value: emailMetrics.deliveryRate,
          threshold: 0.95,
          severity: 'high',
          message: `Email delivery rate ${(emailMetrics.deliveryRate * 100).toFixed(2)}% is below 95%`,
          details: {
            totalSent: emailMetrics.totalSent,
            totalFailed: emailMetrics.totalFailed,
            bounces: emailMetrics.bounces,
            providersAvailable: emailMetrics.providersAvailable
          }
        });
      }
    }
    
    // Check ContactService integration health
    if (this.contactService) {
      try {
        // Check for high bounce rate across all contacts
        const bounceStats = await Contact.aggregate([
          {
            $group: {
              _id: null,
              totalContacts: { $sum: 1 },
              highBounceContacts: {
                $sum: { $cond: [{ $gte: ['$bounceCount', 3] }, 1, 0] }
              }
            }
          }
        ]);
        
        if (bounceStats.length > 0) {
          const { totalContacts, highBounceContacts } = bounceStats[0];
          const bounceRate = totalContacts > 0 ? highBounceContacts / totalContacts : 0;
          
          if (bounceRate > 0.1 && totalContacts > 100) { // More than 10% bounce rate
            alerts.push({
              type: 'high-contact-bounce-rate',
              value: bounceRate,
              threshold: 0.1,
              severity: 'medium',
              message: `Contact bounce rate ${(bounceRate * 100).toFixed(2)}% exceeds 10% threshold`,
              details: {
                totalContacts,
                highBounceContacts,
                recommendation: 'Review contact list quality and implement better validation'
              }
            });
          }
        }
      } catch (error) {
        SecureLogger.logWarning('Failed to check contact bounce rates', { error: error.message });
      }
    }
    
    // Check worker performance
    const activeWorkerCount = this.workers.size;
    if (activeWorkerCount > this.config.maxConcurrentWorkers * 0.8) {
      alerts.push({
        type: 'high-worker-utilization',
        value: activeWorkerCount / this.config.maxConcurrentWorkers,
        threshold: 0.8,
        severity: 'medium',
        message: `Worker utilization ${activeWorkerCount}/${this.config.maxConcurrentWorkers} (${Math.round(activeWorkerCount / this.config.maxConcurrentWorkers * 100)}%) is high`,
        details: {
          activeWorkers: activeWorkerCount,
          maxWorkers: this.config.maxConcurrentWorkers
        }
      });
    }
    
    // Check database connectivity through models
    try {
      await User.findOne({}, { _id: 1 }).limit(1).maxTimeMS(5000);
    } catch (dbError) {
      alerts.push({
        type: 'database-connectivity',
        severity: 'critical',
        message: 'Database connectivity issues detected',
        details: {
          error: dbError.message,
          recommendation: 'Check database connection and server status'
        }
      });
    }
    
    if (alerts.length > 0) {
      // Sort alerts by severity
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      alerts.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));
      
      SecureLogger.logWarning('Alert conditions detected', { 
        alertCount: alerts.length,
        criticalAlerts: alerts.filter(a => a.severity === 'critical').length,
        highAlerts: alerts.filter(a => a.severity === 'high').length,
        alerts: alerts.map(a => ({ type: a.type, severity: a.severity, message: a.message }))
      });
      
      this.emit('alerts-triggered', { alerts, healthData, timestamp: new Date() });
      
      // Track alerts in metrics
      if (this.realTimeMetrics) {
        this.realTimeMetrics.emit('alerts-generated', {
          alerts,
          totalAlerts: alerts.length,
          criticalCount: alerts.filter(a => a.severity === 'critical').length,
          timestamp: new Date()
        });
      }
    }
    
    return alerts;
  }

  /**
   * Update performance metrics
   */
  updatePerformanceMetrics(healthData) {
    // Update worker utilization
    this.metrics.performanceStats.workerUtilization.push({
      timestamp: Date.now(),
      activeWorkers: healthData.activeWorkers,
      maxWorkers: this.config.maxConcurrentWorkers,
      utilization: healthData.activeWorkers / this.config.maxConcurrentWorkers
    });
    
    // Keep only recent data
    const cutoff = Date.now() - this.config.metricsRetentionHours * 60 * 60 * 1000;
    this.metrics.performanceStats.workerUtilization = 
      this.metrics.performanceStats.workerUtilization.filter(stat => stat.timestamp > cutoff);
  }

  /**
   * Utility methods for job management
   */
  
  createBatches(items, batchSize) {
    const batches = [];
    for (let i = 0; i < items.length; i += batchSize) {
      batches.push(items.slice(i, i + batchSize));
    }
    return batches;
  }

  updateJobProgress(jobId, progress) {
    const job = this.activeJobs.get(jobId);
    if (job) {
      job.progress = progress;
      this.emit('job-progress', { jobId, progress });
    }
  }

  async completeJob(jobId, status, stats) {
    const job = this.activeJobs.get(jobId);
    if (job) {
      job.status = status;
      job.endTime = Date.now();
      job.duration = job.endTime - job.startTime;
      job.stats = { ...job.stats, ...stats };
      
      // Move to history
      this.jobHistory.push({ ...job });
      this.activeJobs.delete(jobId);
      this.metrics.currentJobsRunning--;
      
      this.emit('job-completed', { jobId, status, stats, duration: job.duration });
    }
  }

  async handleJobError(jobId, jobType, error, startTime) {
    const duration = Date.now() - startTime;
    
    SecureLogger.logError(`Job ${jobType} failed`, {
      jobId,
      error: error.message,
      duration
    });
    
    await this.completeJob(jobId, 'failed', { error: error.message });
    
    this.metrics.totalJobsFailed++;
    this.updateErrorRate();
    
    this.emit('job-failed', { jobId, jobType, error: error.message, duration });
  }

  updateMetricsAfterJob(jobType, stats, duration) {
    this.metrics.totalJobsRun++;
    this.metrics.totalJobsSuccess++;
    this.metrics.lastJobTimestamp = new Date();
    this.metrics.lastJobStatus = 'success';
    
    // Update averages
    if (this.metrics.averageJobDuration === 0) {
      this.metrics.averageJobDuration = duration;
    } else {
      this.metrics.averageJobDuration = 
        (this.metrics.averageJobDuration + duration) / 2;
    }
    
    // Update job-specific metrics
    if (jobType === 'monthly-invitations') {
      this.metrics.totalInvitationsSent += stats.sentInvitations || 0;
    } else if (jobType === 'reminders') {
      this.metrics.totalRemindersSent += stats.totalSent || 0;
    }
    
    this.updateErrorRate();
  }

  updateErrorRate() {
    const total = this.metrics.totalJobsSuccess + this.metrics.totalJobsFailed;
    this.metrics.errorRate = total > 0 ? this.metrics.totalJobsFailed / total : 0;
  }

  aggregateJobResults(results, existingStats) {
    const aggregated = { ...existingStats };
    
    for (const result of results) {
      if (result.success) {
        aggregated.processedUsers += result.processed || 0;
        aggregated.sentInvitations += result.sent || 0;
        aggregated.totalInvitations += result.total || 0;
      } else {
        aggregated.failedInvitations += result.failed || 0;
        aggregated.errors.push(result.error);
      }
      aggregated.batchesProcessed++;
    }
    
    return aggregated;
  }

  async waitForActiveJobsCompletion(timeout = 30000) {
    const startTime = Date.now();
    
    while (this.activeJobs.size > 0 && (Date.now() - startTime) < timeout) {
      SecureLogger.logInfo(`Waiting for ${this.activeJobs.size} active jobs to complete...`);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    if (this.activeJobs.size > 0) {
      SecureLogger.logWarning(`${this.activeJobs.size} jobs still active after timeout`);
    }
  }

  async terminateAllWorkers() {
    const workerPromises = [];
    
    for (const [workerId, workerInfo] of this.workers) {
      workerPromises.push(
        workerInfo.worker.terminate().catch(error => {
          SecureLogger.logError(`Failed to terminate worker ${workerId}`, error);
        })
      );
    }
    
    await Promise.allSettled(workerPromises);
    this.workers.clear();
    
    SecureLogger.logInfo('All workers terminated');
  }

  async terminateWorkers(workerPromises) {
    for (const workerPromise of workerPromises) {
      try {
        if (workerPromise.worker) {
          await workerPromise.worker.terminate();
        }
      } catch (error) {
        SecureLogger.logError('Failed to terminate worker', error);
      }
    }
  }

  /**
   * Public API methods
   */

  /**
   * Get current service status
   */
  getStatus() {
    return {
      isRunning: this.isRunning,
      activeJobs: this.activeJobs.size,
      activeWorkers: this.workers.size,
      metrics: this.getBasicMetrics(),
      lastHealthCheck: this.lastHealthCheck,
      cronJobs: Array.from(this.cronJobs.keys())
    };
  }

  /**
   * Get basic metrics
   */
  getBasicMetrics() {
    return {
      totalJobsRun: this.metrics.totalJobsRun,
      totalJobsSuccess: this.metrics.totalJobsSuccess,
      totalJobsFailed: this.metrics.totalJobsFailed,
      errorRate: Math.round(this.metrics.errorRate * 100) / 100,
      totalInvitationsSent: this.metrics.totalInvitationsSent,
      totalRemindersSent: this.metrics.totalRemindersSent,
      averageJobDuration: Math.round(this.metrics.averageJobDuration),
      peakMemoryUsage: this.metrics.peakMemoryUsage,
      lastJobTimestamp: this.metrics.lastJobTimestamp,
      lastJobStatus: this.metrics.lastJobStatus,
      currentJobsRunning: this.metrics.currentJobsRunning
    };
  }

  /**
   * Get detailed metrics including performance stats
   */
  getDetailedMetrics() {
    return {
      ...this.getBasicMetrics(),
      performanceStats: this.metrics.performanceStats,
      jobHistory: this.jobHistory.slice(-10), // Last 10 jobs
      config: {
        batchSize: this.config.batchSize,
        maxWorkers: this.config.maxConcurrentWorkers,
        memoryLimit: this.config.maxMemoryUsage,
        timezone: this.config.timezone
      }
    };
  }

  /**
   * Manually trigger a job (for testing/admin purposes)
   */
  async triggerJob(jobType, options = {}) {
    if (!this.isRunning) {
      throw new Error('SchedulerService is not running');
    }

    switch (jobType) {
      case 'monthly-invitations':
        return await this.runMonthlyInvitationJob();
      case 'reminders':
        return await this.runReminderJob();
      case 'cleanup':
        return await this.runCleanupJob();
      case 'health-check':
        return await this.runHealthCheck();
      default:
        throw new Error(`Unknown job type: ${jobType}`);
    }
  }

  /**
   * Get job history with filtering
   */
  getJobHistory(filters = {}) {
    let history = [...this.jobHistory];
    
    if (filters.type) {
      history = history.filter(job => job.type === filters.type);
    }
    
    if (filters.status) {
      history = history.filter(job => job.status === filters.status);
    }
    
    if (filters.limit) {
      history = history.slice(-filters.limit);
    }
    
    return history;
  }
}

module.exports = SchedulerService;