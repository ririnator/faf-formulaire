#!/usr/bin/env node
/**
 * Demo script showing SchedulerService capabilities
 * Usage: node scripts/schedulerDemo.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const { initializeSchedulerService } = require('../services/schedulerServiceInstance');
const SecureLogger = require('../utils/secureLogger');
const User = require('../models/User');
const Contact = require('../models/Contact');

async function runDemo() {
  try {
    console.log('\n🚀 Form-a-Friend SchedulerService Demo\n');
    
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('✅ Connected to MongoDB');
    
    // Initialize scheduler service
    const schedulerService = await initializeSchedulerService();
    console.log('✅ SchedulerService initialized');
    
    // Show initial status
    console.log('\n📊 Initial Status:');
    displayStatus(schedulerService.getStatus());
    
    // Start the service
    await schedulerService.start();
    console.log('✅ SchedulerService started');
    
    // Show available demo options
    console.log('\n📋 Demo Options:');
    console.log('1. Create sample users and contacts');
    console.log('2. Run monthly invitation job manually');
    console.log('3. Run reminder job manually');
    console.log('4. Run cleanup job manually');
    console.log('5. Run health check');
    console.log('6. Show detailed metrics');
    console.log('7. Show job history');
    console.log('8. Monitor real-time status (30 seconds)');
    console.log('0. Exit');
    
    // Interactive demo
    await runInteractiveDemo(schedulerService);
    
  } catch (error) {
    console.error('❌ Demo failed:', error.message);
    process.exit(1);
  }
}

async function runInteractiveDemo(schedulerService) {
  const readline = require('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  
  const askQuestion = (question) => {
    return new Promise((resolve) => {
      rl.question(question, resolve);
    });
  };
  
  try {
    while (true) {
      const choice = await askQuestion('\nEnter your choice (0-8): ');
      
      switch (choice) {
        case '1':
          await createSampleData();
          break;
          
        case '2':
          console.log('\n🔄 Running monthly invitation job...');
          await schedulerService.triggerJob('monthly-invitations');
          console.log('✅ Monthly invitation job completed');
          break;
          
        case '3':
          console.log('\n🔄 Running reminder job...');
          await schedulerService.triggerJob('reminders');
          console.log('✅ Reminder job completed');
          break;
          
        case '4':
          console.log('\n🔄 Running cleanup job...');
          await schedulerService.triggerJob('cleanup');
          console.log('✅ Cleanup job completed');
          break;
          
        case '5':
          console.log('\n🔄 Running health check...');
          await schedulerService.triggerJob('health-check');
          const healthData = schedulerService.lastHealthCheck;
          console.log('✅ Health check completed:');
          console.log('  System Health:', healthData.systemHealth.status);
          console.log('  Service Health:', healthData.serviceHealth.status);
          console.log('  Database Health:', healthData.databaseHealth.status);
          break;
          
        case '6':
          console.log('\n📊 Detailed Metrics:');
          displayDetailedMetrics(schedulerService.getDetailedMetrics());
          break;
          
        case '7':
          console.log('\n📝 Job History:');
          displayJobHistory(schedulerService.getJobHistory({ limit: 10 }));
          break;
          
        case '8':
          await monitorRealTime(schedulerService);
          break;
          
        case '0':
          console.log('\n👋 Exiting demo...');
          await schedulerService.stop();
          await mongoose.disconnect();
          rl.close();
          return;
          
        default:
          console.log('❌ Invalid choice. Please enter a number between 0-8.');
      }
    }
  } catch (error) {
    console.error('❌ Demo error:', error.message);
  } finally {
    rl.close();
  }
}

async function createSampleData() {
  try {
    console.log('\n🔄 Creating sample users and contacts...');
    
    // Check if sample data already exists
    const existingUsers = await User.countDocuments({ 
      username: { $in: ['demo_user_1', 'demo_user_2', 'demo_user_3'] }
    });
    
    if (existingUsers > 0) {
      console.log('⚠️  Sample data already exists. Skipping creation.');
      return;
    }
    
    // Create sample users
    const users = await User.create([
      {
        username: 'demo_user_1',
        email: 'demo1@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: new Date().getDate(), // Today
          sendTime: '18:00',
          timezone: 'Europe/Paris',
          reminderSettings: {
            firstReminder: true,
            secondReminder: true,
            reminderChannel: 'email'
          },
          emailTemplate: 'friendly'
        },
        statistics: {
          totalSubmissions: 0,
          totalContacts: 0,
          joinedCycles: 0
        }
      },
      {
        username: 'demo_user_2',
        email: 'demo2@example.com',
        password: 'password123',
        metadata: { isActive: true },
        preferences: {
          sendDay: new Date().getDate(),
          sendTime: '19:00',
          timezone: 'Europe/Paris',
          reminderSettings: {
            firstReminder: false,
            secondReminder: true,
            reminderChannel: 'email'
          },
          emailTemplate: 'professional'
        },
        statistics: {
          totalSubmissions: 0,
          totalContacts: 0,
          joinedCycles: 0
        }
      },
      {
        username: 'demo_user_3',
        email: 'demo3@example.com',
        password: 'password123',
        metadata: { isActive: false }, // Inactive user
        preferences: {
          sendDay: new Date().getDate(),
          reminderSettings: {
            firstReminder: true,
            secondReminder: true
          }
        }
      }
    ]);
    
    // Create sample contacts
    const contacts = [];
    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      const userContacts = [];
      
      for (let j = 1; j <= 3; j++) {
        const contact = {
          ownerId: user._id,
          email: `contact${i + 1}_${j}@example.com`,
          firstName: `Contact${i + 1}`,
          lastName: `Number${j}`,
          status: j === 3 && i === 2 ? 'opted_out' : 'active', // Last contact of user 3 is opted out
          isActive: !(j === 3 && i === 2),
          optedOut: j === 3 && i === 2,
          emailStatus: j === 3 && i === 2 ? 'unsubscribed' : 'active'
        };
        userContacts.push(contact);
      }
      
      contacts.push(...userContacts);
    }
    
    await Contact.create(contacts);
    
    console.log(`✅ Created ${users.length} sample users and ${contacts.length} sample contacts`);
    console.log('   - demo_user_1: 3 active contacts');
    console.log('   - demo_user_2: 3 active contacts');
    console.log('   - demo_user_3: 2 active contacts, 1 opted out (inactive user)');
    
  } catch (error) {
    console.error('❌ Failed to create sample data:', error.message);
  }
}

function displayStatus(status) {
  console.log(`  Running: ${status.isRunning ? '✅' : '❌'}`);
  console.log(`  Active Jobs: ${status.activeJobs}`);
  console.log(`  Active Workers: ${status.activeWorkers}`);
  console.log(`  Cron Jobs: ${status.cronJobs.join(', ')}`);
  console.log(`  Total Jobs Run: ${status.metrics.totalJobsRun}`);
  console.log(`  Success Rate: ${(100 - status.metrics.errorRate * 100).toFixed(1)}%`);
}

function displayDetailedMetrics(metrics) {
  console.log('  📊 Basic Stats:');
  console.log(`    Total Jobs: ${metrics.totalJobsRun}`);
  console.log(`    Success: ${metrics.totalJobsSuccess}`);
  console.log(`    Failed: ${metrics.totalJobsFailed}`);
  console.log(`    Error Rate: ${(metrics.errorRate * 100).toFixed(2)}%`);
  console.log(`    Invitations Sent: ${metrics.totalInvitationsSent}`);
  console.log(`    Reminders Sent: ${metrics.totalRemindersSent}`);
  console.log(`    Avg Job Duration: ${metrics.averageJobDuration}ms`);
  console.log(`    Peak Memory: ${Math.round(metrics.peakMemoryUsage / 1024 / 1024)}MB`);
  
  console.log('\n  ⚙️  Configuration:');
  console.log(`    Batch Size: ${metrics.config.batchSize}`);
  console.log(`    Max Workers: ${metrics.config.maxWorkers}`);
  console.log(`    Memory Limit: ${Math.round(metrics.config.memoryLimit / 1024 / 1024)}MB`);
  console.log(`    Timezone: ${metrics.config.timezone}`);
}

function displayJobHistory(history) {
  if (history.length === 0) {
    console.log('  No jobs have been run yet.');
    return;
  }
  
  for (const job of history) {
    const duration = job.duration ? `${job.duration}ms` : 'N/A';
    const status = job.status === 'success' ? '✅' : '❌';
    console.log(`  ${status} ${job.type} - ${duration} - ${new Date(job.startTime).toLocaleString()}`);
    
    if (job.stats) {
      if (job.stats.processedUsers) {
        console.log(`      Users: ${job.stats.processedUsers}, Invitations: ${job.stats.sentInvitations || 0}`);
      }
      if (job.stats.totalSent) {
        console.log(`      Reminders: ${job.stats.totalSent}`);
      }
      if (job.stats.expired || job.stats.deleted) {
        console.log(`      Cleaned: ${job.stats.expired || 0} expired, ${job.stats.deleted || 0} deleted`);
      }
    }
  }
}

async function monitorRealTime(schedulerService) {
  console.log('\n📡 Real-time monitoring (30 seconds)...');
  console.log('   Press Ctrl+C to stop monitoring\n');
  
  const startTime = Date.now();
  const monitorInterval = setInterval(() => {
    const status = schedulerService.getStatus();
    const uptime = Math.round((Date.now() - startTime) / 1000);
    
    console.clear();
    console.log('📡 Real-time SchedulerService Monitoring');
    console.log(`⏱️  Monitor Uptime: ${uptime}s`);
    console.log('\n📊 Current Status:');
    displayStatus(status);
    
    const memUsage = process.memoryUsage();
    console.log('\n💾 Memory Usage:');
    console.log(`   Heap Used: ${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`);
    console.log(`   Heap Total: ${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`);
    console.log(`   External: ${Math.round(memUsage.external / 1024 / 1024)}MB`);
    
    if (status.lastHealthCheck) {
      console.log('\n🔍 Last Health Check:');
      console.log(`   Time: ${status.lastHealthCheck.timestamp.toLocaleString()}`);
      console.log(`   System: ${status.lastHealthCheck.systemHealth.status}`);
      console.log(`   Database: ${status.lastHealthCheck.databaseHealth.status}`);
    }
    
  }, 2000); // Update every 2 seconds
  
  // Stop monitoring after 30 seconds
  setTimeout(() => {
    clearInterval(monitorInterval);
    console.log('\n✅ Monitoring stopped');
  }, 30000);
}

// Only run if this script is called directly
if (require.main === module) {
  runDemo().catch(error => {
    console.error('❌ Demo failed:', error);
    process.exit(1);
  });
}

module.exports = { runDemo };