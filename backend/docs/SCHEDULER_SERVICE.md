# SchedulerService Documentation

## Overview

The SchedulerService is the complete automation orchestration system for Form-a-Friend v2, handling monthly invitation cycles, intelligent reminders, cleanup operations, and comprehensive monitoring.

## Features

### 🗓️ Monthly Automation Cycle
- **Primary Job**: Monthly invitations sent on the 5th at 6 PM Paris time
- **Expected Load**: 5000+ users × 20 contacts = 100k+ invitations/month
- **Performance Target**: Complete monthly cycle in <1 hour
- **Memory Constraint**: <512MB peak usage during processing

### 🔄 Intelligent Reminder System
- **J+3 Reminder**: First reminder 3 days after initial invitation
- **J+7 Reminder**: Second reminder 7 days after initial invitation
- **User Preferences**: Respects individual reminder settings
- **Status-based**: Only sends to sent/opened/started invitations

### 🧹 Automatic Cleanup
- **Expired Invitations**: Marks and removes old tokens
- **Contact Data**: Resets temporary bounce counts
- **Memory Management**: Cleans internal caches and metrics
- **Retention Policies**: Configurable data retention periods

### 📊 Real-time Monitoring
- **Health Checks**: Every 5 minutes system status verification
- **Performance Metrics**: Memory usage, job duration, success rates
- **Alert System**: Automatic alerting for performance degradation
- **Job Tracking**: Complete audit trail of all operations

### 🚀 Performance Optimization
- **Batch Processing**: Configurable batch sizes for optimal performance
- **Worker Threads**: Parallel processing for heavy operations
- **Memory Monitoring**: Automatic memory usage tracking and alerts
- **Error Recovery**: Robust error handling and retry mechanisms

## Architecture

### Service Dependencies
```javascript
{
  invitationService: InvitationService,  // Required
  emailService: EmailService,            // Required  
  contactService: ContactService,        // Optional
  realTimeMetrics: RealTimeMetrics      // Optional
}
```

### Core Components

#### 1. CronJob Management
- Monthly invitations: `0 18 5 * *` (5th at 6 PM Paris time)
- Reminder checks: `0 */1 * * *` (hourly)
- Cleanup jobs: `0 2 * * *` (daily at 2 AM)
- Health checks: `*/5 * * * *` (every 5 minutes)

#### 2. Worker Thread Integration
- Path: `services/workers/batchProcessor.js`
- Batch processing for users and contacts
- Isolated memory space for heavy operations
- Configurable timeout and concurrency limits

#### 3. Job Types
- **monthly-invitations**: Send invitations to all active users
- **reminders**: Process J+3 and J+7 reminder logic
- **cleanup**: Remove expired data and optimize memory
- **health-check**: System health monitoring

### Database Integration

#### Models Used
- **User**: Active user retrieval, preference checking
- **Contact**: Email deliverability, tracking updates
- **Invitation**: Creation, status tracking, reminder management

#### Indexes Required
```javascript
// User collection
{ 'metadata.isActive': 1, 'preferences.sendDay': 1 }
{ 'preferences.sendDay': 1, 'preferences.timezone': 1 }

// Contact collection  
{ ownerId: 1, email: 1 }
{ ownerId: 1, isActive: 1, optedOut: 1 }

// Invitation collection
{ month: 1, status: 1 }
{ 'tracking.sentAt': 1, status: 1, expiresAt: 1 }
{ 'reminders.type': 1 }
```

## Configuration

### Environment Variables

#### Core Scheduling
```bash
SCHEDULER_MONTHLY_JOB_DAY=5              # Day of month (1-28)
SCHEDULER_MONTHLY_JOB_HOUR=18            # Hour in 24h format
SCHEDULER_TIMEZONE=Europe/Paris          # Timezone for scheduling
```

#### Performance Settings
```bash
SCHEDULER_BATCH_SIZE=50                  # Users per batch
SCHEDULER_INVITATION_BATCH_SIZE=100      # Invitations per batch
SCHEDULER_MAX_WORKERS=4                  # Max concurrent workers
SCHEDULER_WORKER_TIMEOUT=300000          # Worker timeout (5 min)
SCHEDULER_MAX_MEMORY_MB=512              # Memory limit
SCHEDULER_MAX_JOB_DURATION_HOURS=1       # Job timeout (1 hour)
```

#### Reminder Configuration
```bash
SCHEDULER_FIRST_REMINDER_DAYS=3          # J+3 reminder
SCHEDULER_SECOND_REMINDER_DAYS=7         # J+7 reminder
```

#### Cleanup Settings
```bash
SCHEDULER_EXPIRED_TOKEN_RETENTION_DAYS=90    # Token cleanup
SCHEDULER_METRICS_RETENTION_HOURS=72         # Metrics history
```

#### Monitoring Thresholds
```bash
SCHEDULER_ERROR_RATE_THRESHOLD=0.05          # 5% error rate alert
SCHEDULER_MEMORY_ALERT_THRESHOLD=0.8         # 80% memory alert
```

### Service Configuration
```javascript
const config = {
  monthlyJobDay: 5,
  monthlyJobHour: 18,
  timezone: 'Europe/Paris',
  batchSize: 50,
  maxConcurrentWorkers: 4,
  firstReminderDays: 3,
  secondReminderDays: 7,
  maxMemoryUsage: 512 * 1024 * 1024,
  alertThresholds: {
    errorRate: 0.05,
    memoryUsage: 0.8,
    jobDuration: 0.75
  }
};
```

## Usage

### Basic Initialization
```javascript
const { initializeSchedulerService } = require('./services/schedulerServiceInstance');

// Initialize with service dependencies
const schedulerService = await initializeSchedulerService();

// Start all scheduled jobs
await schedulerService.start();
```

### Manual Job Triggering
```javascript
// Trigger specific jobs manually
await schedulerService.triggerJob('monthly-invitations');
await schedulerService.triggerJob('reminders');
await schedulerService.triggerJob('cleanup');
await schedulerService.triggerJob('health-check');
```

### Status Monitoring
```javascript
// Get current status
const status = schedulerService.getStatus();
console.log(status);
/*
{
  isRunning: true,
  activeJobs: 0,
  activeWorkers: 0,
  cronJobs: ['monthly-invitations', 'reminders', 'cleanup', 'health-check'],
  metrics: { totalJobsRun: 10, errorRate: 0.1, ... },
  lastHealthCheck: { ... }
}
*/

// Get detailed metrics
const metrics = schedulerService.getDetailedMetrics();

// Get job history
const history = schedulerService.getJobHistory({ 
  type: 'monthly-invitations',
  limit: 10 
});
```

### Event Handling
```javascript
schedulerService.on('job-started', ({ jobId, type }) => {
  console.log(`Job ${type} started: ${jobId}`);
});

schedulerService.on('job-completed', ({ jobId, status, stats }) => {
  console.log(`Job completed: ${jobId}, Status: ${status}`);
});

schedulerService.on('monthly-job-completed', ({ stats }) => {
  console.log(`Monthly job finished: ${stats.sentInvitations} invitations sent`);
});

schedulerService.on('high-memory-usage', ({ usagePercent }) => {
  console.warn(`High memory usage: ${usagePercent * 100}%`);
});

schedulerService.on('alerts-triggered', ({ alerts }) => {
  console.error('Alerts triggered:', alerts);
});
```

## Development & Testing

### Running Tests
```bash
# Unit tests
npm run test:scheduler

# Integration tests (requires MongoDB)
npm test schedulerService.integration.test.js

# All tests
npm test
```

### Development Scripts
```bash
# Run scheduler service standalone
npm run scheduler

# Interactive demo with sample data
npm run scheduler:demo
```

### Demo Features
The interactive demo (`npm run scheduler:demo`) provides:
1. Sample user and contact creation
2. Manual job triggering
3. Real-time status monitoring
4. Metrics and history visualization
5. Health check demonstrations

## Production Deployment

### Resource Requirements
- **Memory**: 512MB minimum, 1GB recommended
- **CPU**: 2 cores minimum for worker threads
- **Storage**: Database space for job history and metrics
- **Network**: Outbound email service connectivity

### Monitoring Setup
```javascript
// Production monitoring
schedulerService.on('alerts-triggered', async ({ alerts, healthData }) => {
  // Send alerts to monitoring system
  await notificationService.sendAlert({
    type: 'scheduler-alert',
    alerts,
    healthData,
    timestamp: new Date()
  });
});

// Job completion tracking
schedulerService.on('job-completed', async ({ jobId, status, stats, duration }) => {
  // Log to monitoring system
  await metricsService.recordJobCompletion({
    jobId,
    status,
    duration,
    stats
  });
});
```

### Graceful Shutdown
```javascript
process.on('SIGTERM', async () => {
  console.log('Received SIGTERM, shutting down gracefully...');
  
  // Stop accepting new jobs
  await schedulerService.stop();
  
  // Close database connection
  await mongoose.disconnect();
  
  process.exit(0);
});
```

### Health Check Endpoint
```javascript
// Express health check route
app.get('/health/scheduler', (req, res) => {
  const status = schedulerService.getStatus();
  const healthCheck = schedulerService.lastHealthCheck;
  
  if (!status.isRunning || healthCheck?.systemHealth?.status !== 'healthy') {
    return res.status(503).json({
      status: 'unhealthy',
      details: status
    });
  }
  
  res.json({
    status: 'healthy',
    details: status
  });
});
```

## Performance Characteristics

### Benchmarks
- **5000 users**: ~45 minutes processing time
- **100k invitations**: ~30 minutes with 4 workers
- **Memory usage**: 256-512MB peak during monthly job
- **Error rate**: <1% under normal conditions

### Scaling Considerations
- **Horizontal**: Multiple instances with different timezones
- **Vertical**: Increase worker count and memory limit
- **Database**: Ensure proper indexing for large datasets
- **Email**: Configure multiple email providers for redundancy

### Optimization Tips
1. **Batch Size**: Tune based on memory constraints and email limits
2. **Worker Count**: Match CPU cores, typically 2-8 workers
3. **Memory Limit**: Set 20% below container limit for safety margin
4. **Database Connections**: Use connection pooling for worker threads

## Error Handling & Recovery

### Error Classification
- **Critical**: Database connectivity, service initialization
- **High**: Job failures, worker crashes, memory exceeded
- **Medium**: Email delivery failures, individual contact errors
- **Low**: Temporary network issues, retry-able operations

### Recovery Strategies
- **Automatic Retry**: Exponential backoff for transient errors
- **Circuit Breaker**: Disable failing components temporarily
- **Graceful Degradation**: Continue processing when possible
- **Manual Intervention**: Detailed logging for complex issues

### Monitoring & Alerts
- **Error Rate**: Alert when >5% of operations fail
- **Memory Usage**: Alert when >80% of limit reached
- **Job Duration**: Alert when >75% of timeout reached
- **Worker Failures**: Alert on worker crash or timeout

## Integration Examples

### With Express.js Application
```javascript
// app.js
const express = require('express');
const { initializeSchedulerService } = require('./services/schedulerServiceInstance');

const app = express();

// Initialize scheduler during app startup
app.locals.schedulerService = null;

async function startServer() {
  // Initialize scheduler service
  app.locals.schedulerService = await initializeSchedulerService();
  await app.locals.schedulerService.start();
  
  // Start Express server
  app.listen(3000, () => {
    console.log('Server started with SchedulerService');
  });
}

startServer();
```

### With Admin Dashboard
```javascript
// Admin routes for scheduler management
app.get('/admin/scheduler/status', requireAdmin, (req, res) => {
  const status = req.app.locals.schedulerService.getStatus();
  res.json(status);
});

app.post('/admin/scheduler/jobs/:jobType/trigger', requireAdmin, async (req, res) => {
  try {
    await req.app.locals.schedulerService.triggerJob(req.params.jobType);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/admin/scheduler/metrics', requireAdmin, (req, res) => {
  const metrics = req.app.locals.schedulerService.getDetailedMetrics();
  res.json(metrics);
});

app.get('/admin/scheduler/history', requireAdmin, (req, res) => {
  const history = req.app.locals.schedulerService.getJobHistory({
    type: req.query.type,
    status: req.query.status,
    limit: parseInt(req.query.limit) || 20
  });
  res.json(history);
});
```

## Troubleshooting

### Common Issues

#### 1. Jobs Not Running
```bash
# Check if service is running
curl http://localhost:3000/health/scheduler

# Verify cron configuration
# Check timezone settings
# Confirm service initialization
```

#### 2. High Memory Usage
```javascript
// Monitor memory patterns
const memUsage = process.memoryUsage();
console.log('Memory:', {
  heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
  heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB'
});

// Reduce batch size if needed
// Increase cleanup frequency
// Check for memory leaks in worker threads
```

#### 3. Worker Thread Failures
```javascript
// Check worker timeout settings
// Verify database connectivity in workers
// Monitor worker process resources
// Review error logs for worker crashes
```

#### 4. Email Delivery Issues
```javascript
// Verify email service configuration
// Check rate limiting settings
// Monitor bounce rates and complaints
// Validate email provider connectivity
```

### Debug Logging
```bash
# Enable debug logging
NODE_ENV=development DEBUG_STACK_TRACES=true npm run scheduler

# Enable performance logging
PERFORMANCE_LOGGING=true npm run scheduler

# Monitor specific job types
npm run scheduler:demo
```

### Database Query Optimization
```javascript
// Monitor slow queries
db.setProfilingLevel(2, { slowms: 100 });

// Review index usage
db.users.explain().find({ 'metadata.isActive': true });
db.contacts.explain().find({ ownerId: ObjectId(...) });
db.invitations.explain().find({ month: '2024-01', status: 'sent' });

// Optimize queries based on results
```

## Migration & Upgrades

### Version Compatibility
- **Node.js**: 14+ required, 18+ recommended
- **MongoDB**: 4.4+ required, 5.0+ recommended
- **Dependencies**: node-cron, worker_threads (Node.js built-in)

### Configuration Migration
When upgrading, ensure environment variables are updated:
```bash
# Old format (if any)
MONTHLY_JOB_DAY=5

# New format
SCHEDULER_MONTHLY_JOB_DAY=5
```

### Data Migration
No database schema changes required. The service works with existing User, Contact, and Invitation collections.

## Support & Maintenance

### Regular Maintenance
1. **Weekly**: Review job history and error rates
2. **Monthly**: Analyze performance metrics and optimize
3. **Quarterly**: Update dependencies and review configuration
4. **Annually**: Performance benchmark and capacity planning

### Log Analysis
```bash
# Error pattern analysis
grep "ERROR" logs/scheduler.log | tail -100

# Performance monitoring
grep "PERF" logs/scheduler.log | awk '{print $NF}' | sort -n

# Job completion rates
grep "job-completed" logs/scheduler.log | grep -c "success"
```

### Backup Considerations
- **Job History**: Consider archiving old job history
- **Metrics**: Export performance metrics for long-term analysis
- **Configuration**: Backup environment configuration files

---

## API Reference

### SchedulerService Methods

#### `initialize(services)`
Initialize the service with dependencies.
- **services**: Object with service dependencies
- **Returns**: Promise<boolean>

#### `start()`
Start all scheduled cron jobs.
- **Returns**: Promise<void>

#### `stop()`
Stop all jobs and cleanup resources.
- **Returns**: Promise<void>

#### `getStatus()`
Get current service status.
- **Returns**: Object with status information

#### `getBasicMetrics()`
Get basic performance metrics.
- **Returns**: Object with metrics

#### `getDetailedMetrics()`
Get detailed metrics including performance stats.
- **Returns**: Object with detailed metrics

#### `triggerJob(jobType, options)`
Manually trigger a specific job.
- **jobType**: 'monthly-invitations' | 'reminders' | 'cleanup' | 'health-check'
- **options**: Optional job parameters
- **Returns**: Promise<void>

#### `getJobHistory(filters)`
Get job execution history.
- **filters**: Object with type, status, limit filters
- **Returns**: Array of job records

### Events

#### `job-started`
Emitted when any job starts.
- **Data**: { jobId, type }

#### `job-completed`
Emitted when any job completes.
- **Data**: { jobId, status, stats, duration }

#### `job-failed` 
Emitted when any job fails.
- **Data**: { jobId, jobType, error, duration }

#### `monthly-job-completed`
Emitted when monthly invitation job completes.
- **Data**: { jobId, stats }

#### `reminder-job-completed`
Emitted when reminder job completes.
- **Data**: { jobId, stats }

#### `cleanup-job-completed`
Emitted when cleanup job completes.
- **Data**: { jobId, stats }

#### `high-memory-usage`
Emitted when memory usage exceeds threshold.
- **Data**: { memUsage, usagePercent }

#### `alerts-triggered`
Emitted when alert conditions are detected.
- **Data**: { alerts, healthData }

---

For additional support or questions, please refer to the test files or create an issue in the project repository.