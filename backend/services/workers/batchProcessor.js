const { parentPort, workerData } = require('worker_threads');
const mongoose = require('mongoose');
const path = require('path');

// Initialize database connection for worker
async function initializeWorker() {
  try {
    // Connect to MongoDB using the same connection string
    if (!mongoose.connection.readyState) {
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
    }

    // Load models and services
    const User = require('../../models/User');
    const Contact = require('../../models/Contact');
    const Invitation = require('../../models/Invitation');
    const InvitationService = require('../invitationService');
    const EmailService = require('../emailService');
    const ContactService = require('../contactService');

    return { User, Contact, Invitation, InvitationService, EmailService, ContactService };
  } catch (error) {
    parentPort.postMessage({
      success: false,
      error: `Worker initialization failed: ${error.message}`,
      processed: 0,
      failed: workerData.batch?.length || 0
    });
    process.exit(1);
  }
}

/**
 * Worker thread for batch processing users
 * Handles monthly invitation sending and other batch operations
 */
async function processBatch() {
  const { batch, jobType, options, config } = workerData;
  const startTime = Date.now();
  
  try {
    const models = await initializeWorker();
    const { User, Contact, Invitation, InvitationService, EmailService, ContactService } = models;
    
    // Initialize services for this worker
    const invitationService = new InvitationService(config.invitation || {});
    const emailService = new EmailService(config.email || {});
    const contactService = new ContactService(config.contact || {});
    
    let result;
    
    switch (jobType) {
      case 'monthly-invitations':
        result = await processMonthlyInvitations(batch, options, models, { invitationService, emailService, contactService });
        break;
      
      case 'contact-sync':
        result = await processContactSync(batch, options, models);
        break;
        
      case 'data-migration':
        result = await processDataMigration(batch, options, models);
        break;
        
      default:
        throw new Error(`Unknown job type: ${jobType}`);
    }
    
    const duration = Date.now() - startTime;
    
    parentPort.postMessage({
      ...result,
      success: true,
      duration,
      workerId: process.pid,
      batchSize: batch.length
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    parentPort.postMessage({
      success: false,
      error: error.message,
      processed: 0,
      failed: batch?.length || 0,
      duration,
      workerId: process.pid
    });
  } finally {
    // Clean up database connection
    if (mongoose.connection.readyState) {
      await mongoose.connection.close();
    }
  }
}

/**
 * Process monthly invitations for a batch of users with full email integration
 */
async function processMonthlyInvitations(userBatch, options, models, services) {
  const { User, Contact, Invitation } = models;
  const { invitationService, emailService, contactService } = services;
  const { month, jobId } = options;
  
  const results = {
    processed: 0,
    sent: 0,
    failed: 0,
    total: 0,
    errors: []
  };
  
  for (const user of userBatch) {
    try {
      // Validate user preferences and active status
      if (!user.metadata?.isActive || user.preferences?.optedOut) {
        continue; // Skip inactive or opted-out users
      }

      // Get active contacts using ContactService for validation
      const contactResults = await contactService.getContactsWithStats(user._id, {
        status: 'active',
        hasHandshake: null // Include all contacts regardless of handshake status
      }, {
        limit: 200, // Increased limit for monthly processing
        sortBy: 'tracking.responseRate',
        sortOrder: 'desc' // Prioritize high-performing contacts
      });
      
      const contacts = contactResults.contacts || [];
      results.total += contacts.length;
      
      // Apply user preferences for contact filtering
      const filteredContacts = await filterContactsByPreferences(user, contacts);
      
      // Process contacts in sub-batches to avoid memory issues
      const contactBatches = createSubBatches(filteredContacts, 20);
      
      for (const contactBatch of contactBatches) {
        const batchResults = await processContactBatch(
          user,
          contactBatch,
          month,
          { invitationService, emailService, contactService }
        );
        
        results.sent += batchResults.sent;
        results.failed += batchResults.failed;
        results.errors.push(...batchResults.errors);
      }
      
      results.processed++;
      
      // Update user statistics with detailed tracking
      await User.findByIdAndUpdate(user._id, {
        $inc: { 
          'statistics.joinedCycles': 1,
          'statistics.totalInvitationsSent': results.sent
        },
        $set: { 
          'metadata.lastActive': new Date(),
          'metadata.lastMonthlyJobRun': new Date(),
          'statistics.lastJobStats': {
            month,
            invitationsSent: results.sent,
            contactsProcessed: contacts.length,
            completedAt: new Date()
          }
        }
      });
      
    } catch (error) {
      results.failed++;
      results.errors.push({
        userId: user._id,
        userEmail: user.email,
        error: error.message
      });
    }
  }
  
  return results;
}

/**
 * Process a batch of contacts for invitation creation with complete email integration
 */
async function processContactBatch(user, contacts, month, services) {
  const { invitationService, emailService, contactService } = services;
  const results = {
    sent: 0,
    failed: 0,
    errors: []
  };
  
  for (const contact of contacts) {
    try {
      // Double-check contact status and deliverability
      if (contact.status !== 'active' || contact.optedOut || contact.bounceCount >= 3) {
        continue; // Skip problematic contacts
      }

      // Check if invitation already exists for this month
      const existingInvitation = await Invitation.findOne({
        fromUserId: user._id,
        toEmail: contact.email,
        month
      });
      
      if (existingInvitation) {
        continue; // Skip if already sent
      }
      
      // Create invitation
      const invitationData = {
        fromUserId: user._id,
        toEmail: contact.email,
        toUserId: contact.contactUserId || null, // Include linked user if available
        month,
        type: contact.contactUserId ? 'internal' : 'external',
        metadata: {
          template: user.preferences?.emailTemplate || 'friendly',
          customMessage: user.preferences?.customMessage,
          priority: contact.tracking?.responseRate > 80 ? 'high' : 'normal',
          contactSource: contact.source,
          batchId: `monthly-${month}`,
          workerProcessed: true
        }
      };
      
      const securityContext = {
        ipAddress: '127.0.0.1', // Worker context
        userAgent: 'SchedulerService-Worker',
        source: 'monthly-automation'
      };
      
      // Create invitation through service
      const invitation = await invitationService.createInvitation(invitationData, securityContext);
      
      // Send email immediately using EmailService
      try {
        const recipient = {
          email: contact.email,
          username: contact.firstName || contact.email.split('@')[0],
          name: `${contact.firstName || ''} ${contact.lastName || ''}`.trim()
        };

        await emailService.sendInvitation(invitation, recipient, {
          unsubscribeUrl: `${process.env.APP_BASE_URL}/unsubscribe?email=${encodeURIComponent(contact.email)}`
        });

        // Update invitation status
        await Invitation.findByIdAndUpdate(invitation._id, {
          $set: {
            status: 'sent',
            'tracking.sentAt': new Date(),
            'tracking.emailProvider': 'sent'
          }
        });

        // Update contact tracking with success
        await contactService.updateContactTracking(contact._id, user._id, 'sent', {
          invitationId: invitation._id,
          month,
          sentVia: 'monthly-automation'
        });

        results.sent++;

      } catch (emailError) {
        // Handle email sending failure
        await Invitation.findByIdAndUpdate(invitation._id, {
          $set: {
            status: 'failed',
            'tracking.failedAt': new Date(),
            'tracking.failureReason': emailError.message
          }
        });

        // Update contact with bounce/failure info
        await Contact.findByIdAndUpdate(contact._id, {
          $inc: { bounceCount: 1 },
          $set: { 
            lastBounceAt: new Date(),
            bounceReason: emailError.message
          }
        });

        throw emailError; // Re-throw to be caught by outer catch
      }
      
    } catch (error) {
      results.failed++;
      results.errors.push({
        contactId: contact._id,
        email: contact.email,
        userId: user._id,
        error: error.message,
        timestamp: new Date()
      });
    }
  }
  
  return results;
}

/**
 * Process contact synchronization batch
 */
async function processContactSync(userBatch, options, models) {
  const { Contact } = models;
  
  const results = {
    processed: 0,
    synced: 0,
    failed: 0,
    errors: []
  };
  
  for (const user of userBatch) {
    try {
      // Sync contact statistics and status
      const contacts = await Contact.find({ ownerId: user._id });
      
      for (const contact of contacts) {
        try {
          // Update contact deliverability status based on recent activity
          if (contact.bounceCount >= 5) {
            contact.status = 'bounced';
            contact.isActive = false;
          } else if (contact.optedOut) {
            contact.status = 'opted_out';
            contact.isActive = false;
          } else if (contact.emailStatus === 'complained') {
            contact.status = 'opted_out';
            contact.isActive = false;
            contact.optedOut = true;
          }
          
          await contact.save();
          results.synced++;
          
        } catch (error) {
          results.errors.push({
            contactId: contact._id,
            error: error.message
          });
        }
      }
      
      results.processed++;
      
    } catch (error) {
      results.failed++;
      results.errors.push({
        userId: user._id,
        error: error.message
      });
    }
  }
  
  return results;
}

/**
 * Process data migration batch
 */
async function processDataMigration(dataBatch, options, models) {
  const { migrationMode } = options;
  
  const results = {
    processed: 0,
    migrated: 0,
    failed: 0,
    errors: []
  };
  
  for (const dataItem of dataBatch) {
    try {
      switch (migrationMode) {
        case 'user-preferences':
          await migrateUserPreferences(dataItem, models);
          break;
          
        case 'contact-cleanup':
          await migrateContactData(dataItem, models);
          break;
          
        default:
          throw new Error(`Unknown migration mode: ${migrationMode}`);
      }
      
      results.migrated++;
      results.processed++;
      
    } catch (error) {
      results.failed++;
      results.errors.push({
        itemId: dataItem._id || dataItem.id,
        error: error.message
      });
    }
  }
  
  return results;
}

/**
 * Migrate user preferences to new format
 */
async function migrateUserPreferences(user, models) {
  const { User } = models;
  
  const updates = {};
  
  // Migrate old preference formats
  if (!user.preferences) {
    updates['preferences'] = {
      sendTime: '18:00',
      timezone: 'Europe/Paris',
      sendDay: 5,
      reminderSettings: {
        firstReminder: true,
        secondReminder: true,
        reminderChannel: 'email'
      },
      emailTemplate: 'friendly'
    };
  }
  
  // Ensure statistics exist
  if (!user.statistics) {
    updates['statistics'] = {
      totalSubmissions: 0,
      totalContacts: 0,
      averageResponseRate: 0,
      joinedCycles: 0
    };
  }
  
  if (Object.keys(updates).length > 0) {
    await User.findByIdAndUpdate(user._id, { $set: updates });
  }
}

/**
 * Migrate contact data to new format
 */
async function migrateContactData(contact, models) {
  const { Contact } = models;
  
  const updates = {};
  
  // Ensure tracking data exists
  if (!contact.tracking) {
    updates['tracking'] = {
      addedAt: contact.createdAt || new Date(),
      invitationsSent: 0,
      responsesReceived: 0,
      responseRate: 0
    };
  }
  
  // Fix email status inconsistencies
  if (contact.optedOut && contact.emailStatus !== 'unsubscribed') {
    updates['emailStatus'] = 'unsubscribed';
  }
  
  if (contact.bounceCount >= 5 && contact.emailStatus !== 'bounced_permanent') {
    updates['emailStatus'] = 'bounced_permanent';
    updates['isActive'] = false;
  }
  
  if (Object.keys(updates).length > 0) {
    await Contact.findByIdAndUpdate(contact._id, { $set: updates });
  }
}

/**
 * Filter contacts based on user preferences
 */
async function filterContactsByPreferences(user, contacts) {
  const preferences = user.preferences || {};
  let filteredContacts = [...contacts];

  // Apply max contacts per cycle limit if set
  if (preferences.maxContactsPerCycle && preferences.maxContactsPerCycle > 0) {
    filteredContacts = filteredContacts.slice(0, preferences.maxContactsPerCycle);
  }

  // Filter by contact tags if preferences specify
  if (preferences.includeTags && preferences.includeTags.length > 0) {
    filteredContacts = filteredContacts.filter(contact => 
      contact.tags && contact.tags.some(tag => preferences.includeTags.includes(tag))
    );
  }

  // Filter out excluded tags
  if (preferences.excludeTags && preferences.excludeTags.length > 0) {
    filteredContacts = filteredContacts.filter(contact => 
      !contact.tags || !contact.tags.some(tag => preferences.excludeTags.includes(tag))
    );
  }

  // Filter by minimum response rate if set
  if (preferences.minResponseRate && preferences.minResponseRate > 0) {
    filteredContacts = filteredContacts.filter(contact => 
      !contact.tracking?.responseRate || contact.tracking.responseRate >= preferences.minResponseRate
    );
  }

  // Filter by recency - exclude contacts contacted too recently
  if (preferences.minDaysBetweenInvitations && preferences.minDaysBetweenInvitations > 0) {
    const cutoffDate = new Date(Date.now() - preferences.minDaysBetweenInvitations * 24 * 60 * 60 * 1000);
    filteredContacts = filteredContacts.filter(contact => 
      !contact.tracking?.lastSentAt || contact.tracking.lastSentAt < cutoffDate
    );
  }

  return filteredContacts;
}

/**
 * Utility function to create sub-batches
 */
function createSubBatches(items, batchSize) {
  const batches = [];
  for (let i = 0; i < items.length; i += batchSize) {
    batches.push(items.slice(i, i + batchSize));
  }
  return batches;
}

/**
 * Memory usage monitoring for worker
 */
function monitorMemoryUsage() {
  const memUsage = process.memoryUsage();
  const maxMemory = 256 * 1024 * 1024; // 256MB per worker
  
  if (memUsage.heapUsed > maxMemory) {
    console.warn('Worker memory usage high:', {
      heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
      heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB',
      external: Math.round(memUsage.external / 1024 / 1024) + 'MB'
    });
  }
}

// Monitor memory usage every 30 seconds
setInterval(monitorMemoryUsage, 30000);

// Start processing
processBatch().catch(error => {
  parentPort.postMessage({
    success: false,
    error: `Worker crashed: ${error.message}`,
    processed: 0,
    failed: workerData.batch?.length || 0
  });
  process.exit(1);
});

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Worker received SIGTERM, shutting down gracefully...');
  if (mongoose.connection.readyState) {
    await mongoose.connection.close();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('Worker received SIGINT, shutting down gracefully...');
  if (mongoose.connection.readyState) {
    await mongoose.connection.close();
  }
  process.exit(0);
});