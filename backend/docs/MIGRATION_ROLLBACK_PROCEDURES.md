# Migration Rollback Procedures

## Overview

This document provides comprehensive procedures for rolling back the dual authentication system migration from user-based to token-based authentication. The rollback process is designed to safely revert all changes made during the migration while preserving data integrity.

## ⚠️ **CRITICAL SAFETY NOTICE**

**Before executing ANY rollback procedure:**

1. **Create a complete database backup**
2. **Verify backup integrity** 
3. **Inform all users of maintenance window**
4. **Have emergency contact information ready**
5. **Test rollback procedure in staging environment first**

## Rollback Scenarios

### 1. **Emergency Rollback** (Production Issues)
Use when the migration causes production issues requiring immediate reversion.

### 2. **Planned Rollback** (Business Decision) 
Use when a strategic decision is made to revert to the legacy system.

### 3. **Partial Rollback** (Keep User Accounts)
Use when user accounts should be preserved but authentication method reverted.

## Pre-Rollback Checklist

### System Assessment
- [ ] **Database Connection**: Verify stable connection to MongoDB
- [ ] **Service Status**: Confirm all services are running
- [ ] **User Activity**: Check for active user sessions
- [ ] **Data Integrity**: Run integrity checks on both collections
- [ ] **Backup Verification**: Confirm recent backup exists and is valid

### Environment Preparation
- [ ] **Maintenance Mode**: Enable maintenance mode if possible
- [ ] **User Notification**: Inform users of upcoming maintenance
- [ ] **Monitor Setup**: Prepare monitoring dashboards
- [ ] **Team Availability**: Ensure technical team is available
- [ ] **Rollback Script**: Verify rollback script is up-to-date

### Safety Measures
- [ ] **Backup Creation**: Create pre-rollback backup
- [ ] **Test Environment**: Verify rollback works in staging
- [ ] **Recovery Plan**: Prepare data recovery procedures
- [ ] **Communication Plan**: Set up incident communication channels

## Rollback Execution Methods

### Method 1: Interactive Rollback Script (Recommended)

The safest method using the interactive rollback utility.

#### Step-by-Step Execution

1. **Connect to Production Server**
   ```bash
   ssh user@production-server
   cd /path/to/faf/backend
   ```

2. **Run Interactive Rollback**
   ```bash
   node scripts/migrationRollback.js
   ```

3. **Follow Interactive Prompts**
   ```
   🔄 MIGRATION ROLLBACK UTILITY
   ⚠️  WARNING: This will revert the migration to legacy token system
   
   Continue with rollback? (yes/no): yes
   
   Select mode:
   1. Dry run (preview changes)
   2. Full rollback  
   3. Partial rollback (keep user accounts)
   Choice (1-3): 1  # Always start with dry run
   ```

4. **Review Dry Run Results**
   - Examine proposed changes
   - Verify expected behavior
   - Check for any warnings or errors

5. **Execute Full Rollback** (if dry run looks good)
   ```bash
   # Run script again and select option 2 or 3
   node scripts/migrationRollback.js
   ```

6. **Monitor Progress**
   - Watch console output for progress updates
   - Monitor database performance
   - Check for error messages

### Method 2: Programmatic Rollback

For automated or scripted rollback execution.

#### Code Example
```javascript
const MigrationRollback = require('./scripts/migrationRollback');

async function executeRollback() {
  const rollback = new MigrationRollback();
  
  try {
    // Connect to database
    await rollback.connect();
    
    // Create backup
    await rollback.createBackup();
    
    // Execute rollback steps
    await rollback.rollbackResponses({ dryRun: false });
    await rollback.rollbackUsers({ dryRun: false, preserveAccounts: true });
    await rollback.rollbackIndexes({ dryRun: false });
    
    // Verify integrity
    await rollback.verifyRollback();
    
    console.log('✅ Rollback completed successfully');
  } catch (error) {
    console.error('❌ Rollback failed:', error.message);
    // Implement recovery procedures here
  } finally {
    await rollback.cleanup();
  }
}
```

## Rollback Process Details

### Phase 1: Data Backup
```
📦 Creating backup before rollback...
✅ Backed up 1,247 responses
✅ Backed up 523 users
✅ Backup saved to backup-1234567890123.json
```

**What happens:**
- All migrated responses are backed up
- User accounts with migration markers are saved
- Backup file is created with timestamp
- Backup integrity is verified

**Duration:** ~2-5 minutes depending on data size

### Phase 2: Response Rollback
```
🔄 Starting response rollback...
Found 1,247 migrated responses
Processed 100/1247 responses
Processed 200/1247 responses
...
✅ Rolled back 1,247 responses
```

**What happens:**
- Locate all responses with `authMethod: 'user'`
- Generate new secure tokens for each response
- Convert `userId` references to user names
- Update `authMethod` to `'token'`
- Remove `userId` field from responses
- Process in batches to avoid memory issues

**Duration:** ~5-15 minutes depending on data volume

### Phase 3: User Account Rollback
```
🔄 Starting user rollback...
Found 523 migrated users
ℹ️  Preserving user accounts (removing migration markers only)
✅ Processed 523 users
```

**Options:**
- **Full Deletion**: Remove all user accounts created during migration
- **Preserve Accounts**: Keep accounts but remove migration markers
- **Selective**: Manual review and decision per user

**Duration:** ~1-3 minutes

### Phase 4: Index Rollback
```
🔄 Rolling back indexes...
✅ Dropped index: userId_1_month_1
✅ Dropped index: authMethod_1_month_1
✅ Created index: token_1
✅ Created index: month_1_isAdmin_1
✅ Created index: createdAt_1
```

**What happens:**
- Drop migration-specific indexes
- Recreate original legacy indexes
- Ensure query performance is maintained
- Verify index creation success

**Duration:** ~30 seconds - 2 minutes

### Phase 5: Verification
```
🔍 Verifying rollback integrity...
User auth responses: 0 ✅
Responses without tokens: 0 ✅
Orphaned userId references: 0 ✅
Duplicate admin months: 0 ✅

✅ Rollback verification PASSED
```

**Verification checks:**
- No responses with `authMethod: 'user'` remain
- All responses have valid tokens
- No orphaned `userId` references exist
- Database constraints are satisfied
- Index performance is acceptable

## Post-Rollback Procedures

### Immediate Actions (0-15 minutes)

1. **System Verification**
   ```bash
   # Check application startup
   npm start
   
   # Verify API endpoints
   curl -X GET http://localhost:3000/health
   
   # Test form submission
   curl -X POST http://localhost:3000/api/response -d '{"name":"Test","responses":[]}'
   ```

2. **Database Integrity**
   ```bash
   # Run integrity checks
   mongosh your-database
   db.responses.countDocuments({authMethod: "user"})  # Should be 0
   db.responses.countDocuments({token: {$exists: false}})  # Should be 0
   ```

3. **Performance Monitoring**
   - Monitor query response times
   - Check database connection health
   - Verify index usage statistics
   - Watch for error rates

### Extended Monitoring (15 minutes - 24 hours)

1. **Application Monitoring**
   - Monitor application logs for errors
   - Check user authentication flows
   - Verify form submission processes
   - Monitor session management

2. **Database Performance**
   - Query performance metrics
   - Index efficiency statistics
   - Connection pool health
   - Storage utilization

3. **User Experience**
   - Form loading times
   - Submission success rates
   - Error message clarity
   - Mobile compatibility

## Recovery Procedures

### Rollback Failure Recovery

If the rollback process fails midway:

1. **Immediate Actions**
   ```bash
   # Stop the application
   sudo systemctl stop faf-application
   
   # Assess database state
   node scripts/assessDatabaseState.js
   
   # Restore from backup if needed
   mongorestore --drop /path/to/backup
   ```

2. **Data Recovery**
   ```bash
   # Use backup file created during rollback
   node scripts/restoreFromBackup.js backup-1234567890123.json
   
   # Verify restoration
   node scripts/verifyDataIntegrity.js
   ```

3. **Manual Cleanup**
   ```bash
   # Clean up partial changes
   node scripts/cleanupPartialRollback.js
   
   # Reset to known good state
   node scripts/resetToBaseline.js
   ```

### Performance Issues

If rollback causes performance problems:

1. **Index Optimization**
   ```javascript
   // Add missing indexes
   db.responses.createIndex({token: 1, month: 1});
   db.responses.createIndex({createdAt: -1, isAdmin: 1});
   
   // Check index usage
   db.responses.explain("executionStats").find({token: "abc123"});
   ```

2. **Query Optimization**
   ```javascript
   // Monitor slow queries
   db.setProfilingLevel(1, {slowms: 100});
   
   // Analyze problematic queries
   db.system.profile.find().sort({ts: -1}).limit(5);
   ```

### Data Integrity Issues

If verification fails:

1. **Orphaned Data Cleanup**
   ```javascript
   // Remove orphaned userId references
   db.responses.updateMany(
     {userId: {$exists: true}},
     {$unset: {userId: 1}}
   );
   
   // Fix missing tokens
   const responses = db.responses.find({token: {$exists: false}});
   responses.forEach(response => {
     db.responses.updateOne(
       {_id: response._id},
       {$set: {token: generateSecureToken()}}
     );
   });
   ```

2. **Constraint Violations**
   ```javascript
   // Fix duplicate admin entries
   const duplicates = db.responses.aggregate([
     {$match: {isAdmin: true}},
     {$group: {_id: "$month", docs: {$push: "$$ROOT"}, count: {$sum: 1}}},
     {$match: {count: {$gt: 1}}}
   ]);
   
   // Manual resolution required - contact dev team
   ```

## Troubleshooting Guide

### Common Issues

#### Issue: "Database connection timeout"
**Symptoms:**
```
❌ Database connection failed: MongoTimeoutError
```
**Resolution:**
1. Check MongoDB service status
2. Verify connection string
3. Check firewall rules
4. Increase connection timeout
5. Restart MongoDB if necessary

#### Issue: "Backup creation failed" 
**Symptoms:**
```
❌ Backup failed: Insufficient disk space
```
**Resolution:**
1. Check available disk space: `df -h`
2. Clean up temporary files
3. Use external storage for backup
4. Compress backup files

#### Issue: "Token generation errors"
**Symptoms:**
```
❌ Response rollback failed: Token generation failed
```
**Resolution:**
1. Check crypto module availability
2. Verify system entropy
3. Restart Node.js process
4. Use alternative token generation

#### Issue: "Index creation timeout"
**Symptoms:**
```
❌ Index rollback failed: Index build timeout
```
**Resolution:**
1. Check database load
2. Create indexes during low usage
3. Use background index creation
4. Increase timeout settings

### Emergency Contacts

#### Development Team
- **Lead Developer**: [Contact Information]
- **Database Administrator**: [Contact Information] 
- **DevOps Engineer**: [Contact Information]

#### Escalation Path
1. **Level 1**: Application Team
2. **Level 2**: Database Team  
3. **Level 3**: Infrastructure Team
4. **Level 4**: External Support

## Testing Rollback Procedures

### Staging Environment Test

1. **Setup Test Environment**
   ```bash
   # Create staging database copy
   mongodump --db production_faf --out /tmp/staging_backup
   mongorestore --db staging_faf /tmp/staging_backup/production_faf
   
   # Update environment variables
   export MONGODB_URI="mongodb://localhost:27017/staging_faf"
   export NODE_ENV="staging"
   ```

2. **Execute Test Rollback**
   ```bash
   # Run complete rollback test
   node scripts/migrationRollback.js
   
   # Verify all steps complete successfully
   # Document any issues or timing
   ```

3. **Validate Results**
   ```bash
   # Check data integrity
   node scripts/validateRollback.js
   
   # Performance testing
   node scripts/performanceTest.js
   
   # User flow testing
   npm run test:integration
   ```

### Load Testing After Rollback

```bash
# Install load testing tools
npm install -g loadtest

# Test form submissions
loadtest -n 1000 -c 10 --method POST \
  --data '{"name":"LoadTest","responses":[]}' \
  --headers "Content-Type: application/json" \
  http://localhost:3000/api/response

# Test view endpoints  
loadtest -n 1000 -c 10 \
  http://localhost:3000/api/view/sample-token

# Monitor performance during tests
node scripts/monitorPerformance.js
```

## Rollback Success Criteria

### Technical Criteria
- [ ] All migrated responses converted to token-based
- [ ] No orphaned data remains
- [ ] All database constraints satisfied
- [ ] Index performance acceptable
- [ ] Application startup successful
- [ ] API endpoints responsive
- [ ] No critical errors in logs

### Business Criteria
- [ ] Users can submit forms normally
- [ ] Private links work correctly
- [ ] Admin interface functional
- [ ] Data privacy maintained
- [ ] Performance meets SLA requirements
- [ ] No data loss reported

### Performance Criteria
- [ ] Form submission time < 2 seconds
- [ ] Page load time < 3 seconds
- [ ] Database query time < 100ms average
- [ ] API response time < 500ms
- [ ] Zero critical errors
- [ ] Memory usage within normal range

## Documentation Updates Required

After successful rollback:

1. **Update Architecture Documentation**
   - Remove user authentication references
   - Update database schema documentation
   - Revise API documentation

2. **Update Deployment Guides**
   - Remove migration-related steps
   - Update environment variables
   - Revise monitoring procedures

3. **Update User Documentation**  
   - Remove account creation references
   - Update privacy policy if needed
   - Revise user guides

## Risk Assessment

### High Risk Scenarios
- **Data Loss**: Improper backup or restore procedures
- **Extended Downtime**: Complex rollback requiring manual intervention
- **Performance Degradation**: Missing or inefficient indexes
- **User Impact**: Broken authentication or form submissions

### Mitigation Strategies
- **Multiple Backups**: Create redundant backups before rollback
- **Staging Testing**: Always test rollback in staging first
- **Rollback Windows**: Schedule during low-usage periods
- **Monitoring**: Continuous monitoring during and after rollback
- **Communication**: Clear user communication about maintenance

## Compliance and Audit

### Data Privacy (GDPR)
- User data handling during rollback must comply with GDPR
- Document data processing activities
- Maintain audit trail of all changes
- Notify DPO of any data privacy implications

### Audit Trail
```javascript
// Log all rollback activities
const auditLog = {
  timestamp: new Date(),
  action: 'MIGRATION_ROLLBACK',
  operator: process.env.USER,
  details: {
    responsesProcessed: 1247,
    usersProcessed: 523,
    indexesModified: 5,
    backupLocation: 'backup-1234567890123.json'
  },
  verification: {
    integrityCheck: 'PASSED',
    performanceCheck: 'PASSED',
    functionalCheck: 'PASSED'
  }
};
```

### Compliance Checklist
- [ ] Data processing documented
- [ ] User consent implications reviewed
- [ ] Privacy policy updates (if needed)
- [ ] Audit trail complete
- [ ] Security assessment performed
- [ ] Change management approval

---

## Appendix

### A. Rollback Script Reference

The main rollback script (`scripts/migrationRollback.js`) provides:

- **Interactive Mode**: Guided rollback with prompts
- **Programmatic API**: For automated execution
- **Dry Run Mode**: Preview changes without execution
- **Backup Creation**: Automatic data protection
- **Verification**: Post-rollback integrity checks

### B. Database Schema Changes

#### Before Rollback (User-based Auth)
```javascript
{
  _id: ObjectId,
  name: String,
  responses: Array,
  month: String,
  isAdmin: Boolean,
  userId: ObjectId,        // Will be removed
  authMethod: "user",      // Will become "token"
  createdAt: Date
}
```

#### After Rollback (Token-based Auth)
```javascript
{
  _id: ObjectId,
  name: String,
  responses: Array,
  month: String,
  isAdmin: Boolean,
  token: String,           // Generated during rollback
  authMethod: "token",     // Changed from "user"
  createdAt: Date
}
```

### C. Performance Monitoring Queries

```javascript
// Monitor rollback performance
db.responses.aggregate([
  {$match: {createdAt: {$gte: new Date(Date.now() - 3600000)}}},
  {$group: {
    _id: "$authMethod",
    count: {$sum: 1},
    avgResponseTime: {$avg: "$processingTime"}
  }}
]);

// Check index usage
db.responses.aggregate([{$indexStats: {}}]);

// Monitor query performance  
db.runCommand({collStats: "responses", indexDetails: true});
```

This documentation provides comprehensive guidance for safely rolling back the migration. Always test procedures in staging environment before production execution.