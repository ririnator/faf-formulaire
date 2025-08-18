#!/usr/bin/env node
/**
 * Development script to run the SchedulerService
 * Usage: npm run scheduler or node scripts/runScheduler.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const { initializeSchedulerService } = require('../services/schedulerServiceInstance');
const SecureLogger = require('../utils/secureLogger');

async function runScheduler() {
  try {
    SecureLogger.logInfo('Starting Form-a-Friend SchedulerService...');
    
    // Connect to MongoDB
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is required');
    }
    
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    SecureLogger.logInfo('Connected to MongoDB');
    
    // Initialize and start scheduler service
    const schedulerService = await initializeSchedulerService();
    await schedulerService.start();
    
    SecureLogger.logInfo('SchedulerService started successfully');
    
    // Setup graceful shutdown
    process.on('SIGINT', async () => {
      SecureLogger.logInfo('Received SIGINT, shutting down gracefully...');
      await shutdown(schedulerService);
    });
    
    process.on('SIGTERM', async () => {
      SecureLogger.logInfo('Received SIGTERM, shutting down gracefully...');
      await shutdown(schedulerService);
    });
    
    // Log service status every minute
    setInterval(() => {
      const status = schedulerService.getStatus();
      SecureLogger.logInfo('SchedulerService Status', {
        isRunning: status.isRunning,
        activeJobs: status.activeJobs,
        activeWorkers: status.activeWorkers,
        totalJobsRun: status.metrics.totalJobsRun,
        errorRate: status.metrics.errorRate
      });
    }, 60000);
    
    SecureLogger.logInfo('SchedulerService is running. Press Ctrl+C to stop.');
    
  } catch (error) {
    SecureLogger.logError('Failed to start SchedulerService', error);
    process.exit(1);
  }
}

async function shutdown(schedulerService) {
  try {
    SecureLogger.logInfo('Shutting down SchedulerService...');
    
    if (schedulerService) {
      await schedulerService.stop();
    }
    
    if (mongoose.connection.readyState === 1) {
      await mongoose.disconnect();
      SecureLogger.logInfo('Disconnected from MongoDB');
    }
    
    SecureLogger.logInfo('SchedulerService shutdown complete');
    process.exit(0);
    
  } catch (error) {
    SecureLogger.logError('Error during shutdown', error);
    process.exit(1);
  }
}

// Only run if this script is called directly
if (require.main === module) {
  runScheduler();
}

module.exports = { runScheduler, shutdown };