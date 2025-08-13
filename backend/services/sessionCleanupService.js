const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const SecureLogger = require('../utils/secureLogger');
const User = require('../models/User');
const Response = require('../models/Response');

class SessionCleanupService {
  constructor() {
    this.cleanupStats = {
      expiredSessions: 0,
      inactiveUsers: 0,
      orphanedData: 0,
      totalCleaned: 0,
      lastCleanup: null
    };
    
    this.config = {
      sessionTTL: 14 * 24 * 60 * 60 * 1000, // 14 days in ms
      userInactivityThreshold: 90 * 24 * 60 * 60 * 1000, // 90 days in ms
      cleanupInterval: 24 * 60 * 60 * 1000, // 24 hours in ms
      batchSize: 1000,
      enableAutoCleanup: process.env.NODE_ENV === 'production'
    };
    
    this.cleanupTimer = null;
  }

  /**
   * Initialize automatic cleanup scheduler
   */
  initialize() {
    if (this.config.enableAutoCleanup) {
      this.scheduleCleanup();
      SecureLogger.logInfo('SessionCleanupService: Automatic cleanup scheduler initialized');
    } else {
      SecureLogger.logInfo('SessionCleanupService: Auto cleanup disabled in development mode');
    }
  }

  /**
   * Schedule automatic cleanup with interval
   */
  scheduleCleanup() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    
    this.cleanupTimer = setInterval(async () => {
      try {
        await this.runCompleteCleanup();
      } catch (error) {
        SecureLogger.logError('Scheduled cleanup failed', error);
      }
    }, this.config.cleanupInterval);

    // Run initial cleanup after 5 minutes (only in production)
    if (process.env.NODE_ENV === 'production') {
      setTimeout(async () => {
        await this.runCompleteCleanup();
      }, 5 * 60 * 1000);
    }
  }

  /**
   * Run complete cleanup process
   */
  async runCompleteCleanup(options = {}) {
    const startTime = Date.now();
    this.resetStats();
    
    SecureLogger.logInfo('Starting comprehensive session and user data cleanup');

    try {
      // 1. Clean expired sessions
      await this.cleanupExpiredSessions(options.dryRun);
      
      // 2. Clean inactive users
      await this.cleanupInactiveUsers(options.dryRun);
      
      // 3. Clean orphaned data
      await this.cleanupOrphanedData(options.dryRun);
      
      this.cleanupStats.lastCleanup = new Date();
      const duration = Date.now() - startTime;
      
      SecureLogger.logInfo('Session cleanup completed', {
        duration: `${duration}ms`,
        stats: this.cleanupStats,
        dryRun: options.dryRun || false
      });

      return this.generateCleanupReport();
      
    } catch (error) {
      SecureLogger.logError('Session cleanup failed', error);
      throw error;
    }
  }

  /**
   * Clean expired sessions from MongoDB store
   */
  async cleanupExpiredSessions(dryRun = false) {
    try {
      const db = mongoose.connection.db;
      const sessionsCollection = db.collection('sessions');
      
      const expireDate = new Date(Date.now() - this.config.sessionTTL);
      
      if (dryRun) {
        const expiredCount = await sessionsCollection.countDocuments({
          $or: [
            { expires: { $lt: new Date() } },
            { updatedAt: { $lt: expireDate } },
            { lastActivity: { $lt: expireDate } }
          ]
        });
        this.cleanupStats.expiredSessions = expiredCount;
        return;
      }

      // Delete expired sessions in batches
      let totalDeleted = 0;
      let batch = 0;
      
      while (true) {
        const expiredSessions = await sessionsCollection.find({
          $or: [
            { expires: { $lt: new Date() } },
            { updatedAt: { $lt: expireDate } },
            { lastActivity: { $lt: expireDate } }
          ]
        }).limit(this.config.batchSize).toArray();

        if (expiredSessions.length === 0) break;

        const result = await sessionsCollection.deleteMany({
          _id: { $in: expiredSessions.map(s => s._id) }
        });

        totalDeleted += result.deletedCount;
        
        if (result.deletedCount < this.config.batchSize) {
          break;
        }
        
        batch++;
        // Pause between batches to avoid overwhelming the database
        if (batch % 10 === 0) {
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }

      this.cleanupStats.expiredSessions = totalDeleted;
      this.cleanupStats.totalCleaned += totalDeleted;
      
      SecureLogger.logInfo(`Cleaned ${totalDeleted} expired sessions`);
      
    } catch (error) {
      SecureLogger.logError('Failed to clean expired sessions', error);
      throw error;
    }
  }

  /**
   * Clean inactive users and their associated data
   */
  async cleanupInactiveUsers(dryRun = false) {
    try {
      const inactivityThreshold = new Date(Date.now() - this.config.userInactivityThreshold);
      
      // Find inactive users (no activity for 90+ days)
      const inactiveUsers = await User.find({
        $and: [
          {
            $or: [
              { 'metadata.lastLoginAt': { $lt: inactivityThreshold } },
              { 'metadata.lastLoginAt': { $exists: false } }
            ]
          },
          { 'metadata.registeredAt': { $lt: inactivityThreshold } },
          // Don't delete users with recent responses
          { 
            _id: { 
              $nin: await Response.distinct('userId', {
                createdAt: { $gte: inactivityThreshold }
              })
            }
          }
        ]
      }).select('_id email username metadata.registeredAt metadata.lastLoginAt').limit(this.config.batchSize);

      if (dryRun) {
        this.cleanupStats.inactiveUsers = inactiveUsers.length;
        return;
      }

      let cleanedUsers = 0;
      
      for (const user of inactiveUsers) {
        try {
          // Delete user's responses first
          const responseDeleteResult = await Response.deleteMany({ userId: user._id });
          
          // Delete the user
          await User.deleteOne({ _id: user._id });
          
          cleanedUsers++;
          this.cleanupStats.orphanedData += responseDeleteResult.deletedCount;
          
          SecureLogger.logInfo(`Cleaned inactive user: ${user.email}`, {
            userId: user._id,
            responsesDeleted: responseDeleteResult.deletedCount,
            lastLogin: user.metadata?.lastLoginAt,
            created: user.metadata?.registeredAt
          });
          
        } catch (error) {
          SecureLogger.logError(`Failed to clean user ${user._id}`, error);
        }
      }

      this.cleanupStats.inactiveUsers = cleanedUsers;
      this.cleanupStats.totalCleaned += cleanedUsers;
      
      SecureLogger.logInfo(`Cleaned ${cleanedUsers} inactive users`);
      
    } catch (error) {
      SecureLogger.logError('Failed to clean inactive users', error);
      throw error;
    }
  }

  /**
   * Clean orphaned data (responses without valid users, invalid tokens, etc.)
   */
  async cleanupOrphanedData(dryRun = false) {
    try {
      // Find responses with invalid user references
      const invalidUserResponses = await Response.find({
        userId: { $exists: true, $ne: null },
        authMethod: 'user'
      }).populate('userId').limit(this.config.batchSize);

      const orphanedResponses = invalidUserResponses.filter(response => !response.userId);
      
      if (dryRun) {
        this.cleanupStats.orphanedData = orphanedResponses.length;
        return;
      }

      let cleanedOrphaned = 0;
      
      for (const response of orphanedResponses) {
        try {
          await Response.deleteOne({ _id: response._id });
          cleanedOrphaned++;
          
          SecureLogger.logInfo(`Cleaned orphaned response: ${response._id}`);
          
        } catch (error) {
          SecureLogger.logError(`Failed to clean orphaned response ${response._id}`, error);
        }
      }

      // Clean duplicate tokens
      const duplicateTokens = await Response.aggregate([
        { $match: { token: { $exists: true, $ne: null } } },
        { $group: { _id: '$token', count: { $sum: 1 }, docs: { $push: '$_id' } } },
        { $match: { count: { $gt: 1 } } }
      ]);

      for (const duplicate of duplicateTokens) {
        // Keep the first one, delete the rest
        const toDelete = duplicate.docs.slice(1);
        
        if (!dryRun) {
          await Response.deleteMany({ _id: { $in: toDelete } });
          cleanedOrphaned += toDelete.length;
        }
      }

      this.cleanupStats.orphanedData = cleanedOrphaned;
      this.cleanupStats.totalCleaned += cleanedOrphaned;
      
      SecureLogger.logInfo(`Cleaned ${cleanedOrphaned} orphaned data records`);
      
    } catch (error) {
      SecureLogger.logError('Failed to clean orphaned data', error);
      throw error;
    }
  }

  /**
   * Get cleanup statistics
   */
  getCleanupStats() {
    return { ...this.cleanupStats };
  }

  /**
   * Generate comprehensive cleanup report
   */
  generateCleanupReport() {
    const report = {
      timestamp: new Date(),
      stats: { ...this.cleanupStats },
      config: { ...this.config },
      recommendations: []
    };

    // Add recommendations based on cleanup results
    if (this.cleanupStats.expiredSessions > 1000) {
      report.recommendations.push('Consider reducing session TTL or increasing cleanup frequency');
    }

    if (this.cleanupStats.inactiveUsers > 100) {
      report.recommendations.push('Review user engagement strategies to reduce inactivity');
    }

    if (this.cleanupStats.orphanedData > 50) {
      report.recommendations.push('Investigate data integrity issues causing orphaned records');
    }

    if (this.cleanupStats.totalCleaned === 0) {
      report.recommendations.push('System is clean - maintain current cleanup schedule');
    }

    return report;
  }

  /**
   * Update cleanup configuration
   */
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    
    // Restart scheduler if interval changed
    if (newConfig.cleanupInterval && this.cleanupTimer) {
      this.scheduleCleanup();
    }
    
    SecureLogger.logInfo('Cleanup configuration updated', this.config);
  }

  /**
   * Manual cleanup trigger
   */
  async runManualCleanup(options = {}) {
    return await this.runCompleteCleanup({ ...options, manual: true });
  }

  /**
   * Reset cleanup statistics
   */
  resetStats() {
    this.cleanupStats = {
      expiredSessions: 0,
      inactiveUsers: 0,
      orphanedData: 0,
      totalCleaned: 0,
      lastCleanup: null
    };
  }

  /**
   * Shutdown cleanup service
   */
  shutdown() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    SecureLogger.logInfo('SessionCleanupService shutdown complete');
  }
}

module.exports = SessionCleanupService;