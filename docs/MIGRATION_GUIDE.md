# FAF Migration Guide - Response to Submission

## Overview

This guide covers the complete migration from FAF v1 (Response-based architecture) to Form-a-Friend v2 (User-Submission architecture). The migration process automatically creates User accounts from existing Response data and transforms all responses into the new Submission format while preserving data integrity and backward compatibility.

## 🎯 Migration Objectives

- **Data Transformation**: Convert all Response documents to Submission format
- **User Account Creation**: Generate User accounts from unique Response.name values
- **Legacy Compatibility**: Preserve existing tokens through Invitation mapping
- **Zero Data Loss**: Maintain complete data integrity throughout the process
- **Backward Compatibility**: Ensure existing URLs and tokens continue to work

## 📋 Pre-Migration Requirements

### Environment Setup
```bash
# Required environment variables
export MONGODB_URI="mongodb://localhost:27017/faf"
export FORM_ADMIN_NAME="admin_username"  # Name of the admin user in responses
export SESSION_SECRET="your-session-secret"
```

### System Requirements
- Node.js 14+
- MongoDB 4.4+
- Sufficient disk space (recommended: 2x current database size for backups)
- Network connectivity to MongoDB instance

### Data Prerequisites
- At least one Response document in the database
- Valid names in Response documents (non-empty, non-null)
- Access to database with read/write permissions

## 🚀 Quick Start

### Method 1: Interactive Helper (Recommended)
```bash
cd /Users/ririnator/Desktop/FAF
node scripts/migration-helper.js
```

The interactive helper provides:
- Environment validation
- Data preview
- Guided migration execution
- Post-migration verification
- Emergency rollback capabilities

### Method 2: Direct Script Execution
```bash
# Dry-run (recommended first)
node scripts/migrate-to-form-a-friend.js --dry-run --verbose

# Production migration
node scripts/migrate-to-form-a-friend.js --verbose
```

## 📊 Migration Phases

### Phase 1: PREPARATION
- **Data Analysis**: Scans existing Response documents
- **Feasibility Check**: Validates migration requirements
- **Backup Creation**: Creates complete database backup
- **Statistics Collection**: Gathers pre-migration metrics

**Example Output:**
```
=== PHASE 1: PREPARATION ===
[2025-08-17T10:00:00.000Z] INFO: Analyzing existing database structure...
[2025-08-17T10:00:01.000Z] SUCCESS: Data analysis completed
  Total Responses: 245
  Unique Names: 87
  Admin Responses: 12
  Tokens: 233

[2025-08-17T10:00:02.000Z] INFO: Creating database backup...
[2025-08-17T10:00:15.000Z] SUCCESS: Database backup completed
  Backup Path: ./migration-backups/migration-2025-08-17T10-00-02-000Z
```

### Phase 2: MIGRATION
- **User Account Creation**: Generates User documents from unique names
- **Username Generation**: Creates sanitized usernames with collision handling
- **Password Creation**: Generates secure temporary passwords
- **Role Assignment**: Assigns admin role based on FORM_ADMIN_NAME
- **Response Conversion**: Transforms Response documents to Submissions

**User Creation Process:**
```javascript
// Example transformation
Response: { name: "Jean-François", ... }
↓
User: {
  username: "jean_francois",
  email: "jean_francois@migration.faf.local",
  password: "[hashed]",
  role: "user",
  migrationData: {
    legacyName: "Jean-François",
    migratedAt: "2025-08-17T10:05:00.000Z",
    source: "migration"
  }
}
```

### Phase 3: ACTIVATION
- **Token Mapping**: Maps legacy Response tokens to Invitation system
- **Legacy URL Preservation**: Ensures existing private links continue working
- **Relationship Linking**: Connects Submissions to newly created Users

**Token Mapping:**
```javascript
// Legacy Response token preserved in Invitation
Response: { token: "abc123def456", ... }
↓
Invitation: {
  token: "abc123def456",  // Preserved original token
  fromUserId: ObjectId("..."),
  toUserId: ObjectId("..."),
  status: "submitted",
  metadata: { migrationSource: "response_token" }
}
```

### Phase 4: CLEANUP
- **Data Integrity Verification**: Validates all relationships and counts
- **Report Generation**: Creates detailed migration report with statistics
- **Recommendation Generation**: Provides post-migration action items

## 🔧 Configuration Options

### Migration Script Options
```bash
# Available command-line options
--dry-run, -d    # Simulate migration without making changes
--verbose, -v    # Enable detailed logging
--help, -h       # Show help information
```

### Configuration Constants
```javascript
MIGRATION_CONFIG = {
  BATCH_SIZE: 100,                    // Documents processed per batch
  MAX_CONCURRENT_OPERATIONS: 10,     // Parallel operation limit
  TEMP_PASSWORD_LENGTH: 12,          // Generated password length
  BCRYPT_SALT_ROUNDS: 12,           // Password hashing rounds
  TEMP_EMAIL_DOMAIN: 'migration.faf.local',
  MAX_ALLOWED_FAILURES: 5,          // Error tolerance threshold
  ENABLE_AUTO_BACKUP: true,         // Automatic backup creation
  ENABLE_AUTO_ROLLBACK: true        // Automatic rollback on failure
}
```

## 📝 Data Transformation Details

### Username Generation Rules
1. **Normalization**: Convert to lowercase, trim whitespace
2. **Accent Removal**: Replace accented characters (é→e, à→a, etc.)
3. **Special Characters**: Replace non-alphanumeric with underscores
4. **Length Constraints**: Minimum 3, maximum 30 characters
5. **Collision Handling**: Append counter for duplicates (user_1, user_2)

### Response to Submission Mapping
```javascript
// Field mapping
Response.name          → User.migrationData.legacyName
Response.responses[]   → Submission.responses[] (with questionId transformation)
Response.month         → Submission.month
Response.createdAt     → Submission.submittedAt
Response.isAdmin       → User.role ('admin' or 'user')
Response.token         → Invitation.token (if present)
```

### Email Generation
- Pattern: `{username}@migration.faf.local`
- Ensures uniqueness through username uniqueness
- Temporary domain indicates migration origin

## 🛡️ Safety Features

### Automatic Backup
- **Complete Database Export**: All collections saved as JSON
- **Backup Manifest**: Metadata and verification checksums
- **Rollback Ready**: Structured for easy restoration

### Dry-Run Mode
- **Zero Database Changes**: Simulates entire migration process
- **Complete Validation**: Checks all transformation logic
- **Statistical Reporting**: Shows what would happen in production
- **Error Detection**: Identifies issues before production run

### Error Handling
- **Graceful Failures**: Continues processing despite individual errors
- **Error Threshold**: Stops migration if too many errors occur
- **Detailed Logging**: Comprehensive error information for debugging
- **Automatic Rollback**: Restores database on critical failures

### Data Integrity Validation
- **Count Verification**: Ensures all documents were processed
- **Relationship Validation**: Verifies User↔Submission connections
- **Token Preservation**: Confirms legacy token mapping
- **Admin Role Verification**: Validates admin user creation

## 📊 Monitoring & Reporting

### Real-Time Progress
```
User creation progress: 67%
  Created: 58/87
  ETA: 12s

Conversion progress: 34%
  Processed: 83/245
  Created: 83
  ETA: 45s
```

### Migration Report Structure
```json
{
  "migration": {
    "migrationId": "a1b2c3d4",
    "timestamp": "2025-08-17T10:00:00.000Z",
    "elapsedTime": 127,
    "phases": {
      "preparation": { "status": "completed", "errors": [] },
      "migration": { "status": "completed", "errors": [] },
      "activation": { "status": "completed", "errors": [] },
      "cleanup": { "status": "completed", "errors": [] }
    },
    "statistics": {
      "totalResponses": 245,
      "uniqueNames": 87,
      "usersCreated": 87,
      "submissionsCreated": 245,
      "invitationsCreated": 233,
      "errorsEncountered": 0
    }
  },
  "dataIntegrity": {
    "passed": true,
    "verification": { ... }
  },
  "recommendations": [...]
}
```

## 🚨 Rollback Procedures

### Automatic Rollback
- **Triggered by**: Critical errors during migration
- **Scope**: Complete database restoration
- **Speed**: Typically 2-5 minutes for full rollback

### Manual Rollback
```bash
# Using migration helper
node scripts/migration-helper.js
# Select option 7: Emergency Rollback

# Direct backup restoration
node -e "
const { BackupManager, MigrationLogger } = require('./scripts/migrate-to-form-a-friend');
const logger = new MigrationLogger(true);
const backup = new BackupManager(logger);
backup.restoreBackup('./migration-backups/migration-[timestamp]', logger);
"
```

### Rollback Verification
After rollback, verify:
- All User accounts created by migration are removed
- All Submission documents created by migration are removed
- All Invitation documents created by migration are removed
- Original Response documents are intact and unchanged

## 🔍 Troubleshooting

### Common Issues

#### "No valid names found in Response documents"
**Cause**: Response documents have null/empty name fields
**Solution**: 
```javascript
// Check for invalid names
db.responses.find({
  $or: [
    { name: null },
    { name: "" },
    { name: { $exists: false } }
  ]
})

// Fix invalid names before migration
db.responses.updateMany(
  { name: null },
  { $set: { name: "Unknown User" } }
)
```

#### "Username collision detected"
**Cause**: Multiple responses with same normalized name
**Solution**: The migration automatically handles this by appending counters

#### "Migration fails with timeout"
**Cause**: Large dataset or slow database connection
**Solution**: Increase batch size or reduce MAX_CONCURRENT_OPERATIONS

#### "MONGODB_URI connection failed"
**Cause**: Database not accessible or credentials invalid
**Solution**: Verify connection string and database status

### Performance Optimization

#### Large Datasets (1000+ responses)
```javascript
// Recommended configuration adjustments
MIGRATION_CONFIG.BATCH_SIZE = 50;           // Reduce batch size
MIGRATION_CONFIG.MAX_CONCURRENT_OPERATIONS = 5;  // Reduce concurrency
```

#### Memory Constraints
```bash
# Increase Node.js memory limit
node --max-old-space-size=4096 scripts/migrate-to-form-a-friend.js
```

### Debugging

#### Enable Detailed Logging
```bash
node scripts/migrate-to-form-a-friend.js --verbose --dry-run
```

#### Database Query Debugging
```javascript
// Check migration progress
db.users.countDocuments({ "migrationData.source": "migration" })
db.submissions.countDocuments()
db.invitations.countDocuments({ "metadata.migrationSource": "response_token" })
```

## 📚 Post-Migration Tasks

### Immediate Actions
1. **Verify Migration Report**: Review generated report for any issues
2. **Test User Authentication**: Verify admin and user login functionality
3. **Validate Legacy URLs**: Test existing response view links
4. **Check Admin Dashboard**: Ensure all data displays correctly

### User Communication
```
Subject: FAF System Migration - Important Login Changes

Dear FAF Users,

We have successfully migrated to our new Form-a-Friend v2 system. 

Your new login credentials:
- Username: [generated_username]
- Temporary Password: [secure_password]
- Email: [username]@migration.faf.local

Please log in and change your password immediately.

All your previous responses have been preserved and are accessible through the new system.

Best regards,
The FAF Team
```

### Security Hardening
1. **Force Password Reset**: Require all migrated users to change passwords
2. **Email Verification**: Update to real email addresses
3. **Review Admin Roles**: Confirm admin role assignments
4. **Monitor Login Attempts**: Watch for authentication issues

### System Maintenance
1. **Archive Legacy Data**: Consider moving Response documents to archive collection
2. **Update Documentation**: Reflect new system architecture
3. **Monitor Performance**: Ensure system performance with new data structure
4. **Schedule Backups**: Update backup procedures for new schema

## 🧪 Testing

### Run Migration Tests
```bash
cd backend
npm test -- migration.complete.test.js
```

### Test Coverage Areas
- Username generation and collision handling
- Password generation and hashing
- Response to Submission transformation
- Token mapping to Invitation system
- Backup and rollback procedures
- Error handling and recovery
- Data integrity validation

## 📞 Support

### Get Help
1. **Check Logs**: Review migration logs for error details
2. **Run Verification**: Use migration helper to verify data integrity
3. **Review Reports**: Check generated migration reports
4. **Test Rollback**: Use dry-run mode to test rollback procedures

### Emergency Contacts
- **Critical Issues**: Use emergency rollback procedures
- **Data Integrity Concerns**: Stop application, review migration report
- **Performance Issues**: Check database indexes and query performance

## 📖 Additional Resources

- [Data Model Documentation](./DATA-MODELS.md)
- [Architecture Overview](./ARCHITECTURE.md)
- [API Documentation](./API.md)
- [Security Guidelines](./SECURITY.md)

---

**Migration Script Location**: `/Users/ririnator/Desktop/FAF/scripts/migrate-to-form-a-friend.js`
**Helper Script Location**: `/Users/ririnator/Desktop/FAF/scripts/migration-helper.js`
**Test Suite Location**: `/Users/ririnator/Desktop/FAF/backend/tests/migration.complete.test.js`