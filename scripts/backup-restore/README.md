# FAF Backup & Restore System v2.0

## 🎯 Overview

The FAF Backup & Restore System is a comprehensive, enterprise-grade solution for database backup, restoration, and disaster recovery. It provides intelligent backup creation, automatic rollback procedures, security validation, and system health monitoring with complete audit trails and compliance reporting.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 FAF Backup & Restore System                │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ Intelligent     │  │ Automatic       │  │ System      │ │
│  │ Backup System   │  │ Rollback System │  │ Health      │ │
│  │                 │  │                 │  │ Validator   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ Security        │  │ CLI Interface   │  │ Test Suite  │ │
│  │ Validation      │  │                 │  │             │ │
│  │ System          │  │                 │  │             │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ 
- MongoDB 4.4+
- Sufficient disk space for backups
- Required npm packages: `mongoose`, `chalk` (for CLI)

### Installation

```bash
# Navigate to the backup-restore directory
cd scripts/backup-restore

# Install dependencies (if needed)
npm install mongoose chalk

# Set environment variables
export MONGODB_URI="mongodb://localhost:27017/your_database"
export BACKUP_PATH="./backups"
```

### Basic Usage

#### Command Line Interface

```bash
# Start interactive CLI
node BackupRestoreCLI.js

# With verbose logging
node BackupRestoreCLI.js --verbose

# With file logging
node BackupRestoreCLI.js --log-file
```

#### Programmatic Usage

```javascript
const { IntelligentBackupSystem } = require('./IntelligentBackupSystem');
const { AutomaticRollbackSystem } = require('./AutomaticRollbackSystem');

// Initialize systems
const backupSystem = new IntelligentBackupSystem();
const rollbackSystem = new AutomaticRollbackSystem();

// Register your models
backupSystem.registerModels({
  users: UserModel,
  responses: ResponseModel,
  submissions: SubmissionModel
});

// Create a backup
const backup = await backupSystem.createIntelligentBackup({
  type: 'full',
  compression: true
});

// Restore from backup if needed
const restore = await rollbackSystem.executeRollback(backup.backupPath);
```

## 📦 Components

### 1. Intelligent Backup System (`IntelligentBackupSystem.js`)

Advanced backup creation with compression, versioning, and metadata tracking.

**Key Features:**
- **Incremental Backups**: Only backup changed data since last backup
- **Compression**: Gzip compression with configurable levels (1-9)
- **Metadata Tracking**: Comprehensive backup metadata with checksums
- **Progress Monitoring**: Real-time progress with ETA calculations
- **Memory Management**: Efficient handling of large datasets
- **Version Control**: Automatic backup versioning and retention policies

**Usage Example:**
```javascript
const backupSystem = new IntelligentBackupSystem({
  DEFAULT_BACKUP_ROOT: './backups',
  COMPRESSION_LEVEL: 6,
  MAX_BACKUP_VERSIONS: 10
});

// Full backup with compression
const result = await backupSystem.createIntelligentBackup({
  type: 'full',
  compression: true,
  compressionLevel: 9
});

// Incremental backup
const incremental = await backupSystem.createIntelligentBackup({
  type: 'incremental',
  since: lastBackupDate
});
```

### 2. Automatic Rollback System (`AutomaticRollbackSystem.js`)

Comprehensive database restoration with failure detection and emergency procedures.

**Key Features:**
- **Automatic Failure Detection**: Configurable thresholds for error rates and consecutive failures
- **Emergency Rollback**: Fast rollback procedures for critical situations
- **Multi-Phase Restoration**: Preparation → Database Clear → Data Restore → Index Rebuild → Verification
- **Health Monitoring**: Real-time monitoring during rollback operations
- **Notification System**: Administrator alerts via multiple channels

**Usage Example:**
```javascript
const rollbackSystem = new AutomaticRollbackSystem({
  MAX_CONSECUTIVE_ERRORS: 5,
  OPERATION_TIMEOUT: 300000,
  ENABLE_EMERGENCY_ROLLBACK: true
});

// Execute rollback from backup
const result = await rollbackSystem.executeRollback('/path/to/backup', {
  validateIntegrity: true,
  notifyAdmins: true
});
```

### 3. System Health Validator (`SystemHealthValidator.js`)

Comprehensive database and application health monitoring.

**Key Features:**
- **Data Integrity Validation**: Document structure, required fields, data types
- **Index Health Analysis**: Index usage, efficiency, and recommendations
- **Performance Monitoring**: Query performance, system resources
- **Referential Integrity**: Cross-collection reference validation
- **Application Testing**: CRUD operations and workflow validation

**Usage Example:**
```javascript
const healthValidator = new SystemHealthValidator({
  ENABLE_PERFORMANCE_VALIDATION: true,
  ENABLE_APPLICATION_TESTING: true
});

// Comprehensive health check
const health = await healthValidator.validateSystemHealth({
  ENABLE_DOCUMENT_VALIDATION: true,
  ENABLE_INDEX_VALIDATION: true,
  ENABLE_REFERENTIAL_INTEGRITY: true
});

console.log(`Health Score: ${health.results.overall.score}/100`);
```

### 4. Security Validation System (`SecurityValidationSystem.js`)

Multi-layer security validation with checksum verification and tamper detection.

**Key Features:**
- **Multi-Hash Checksums**: SHA256, SHA512, MD5 for comprehensive validation
- **Permission Validation**: File and directory access control verification
- **Corruption Detection**: Advanced algorithms for detecting data corruption
- **Security Audit Logging**: Comprehensive audit trails for compliance
- **Tamper Detection**: File integrity monitoring with forensic analysis

**Usage Example:**
```javascript
const securitySystem = new SecurityValidationSystem({
  ENABLE_MULTI_HASH: true,
  ENABLE_TAMPER_DETECTION: true,
  QUARANTINE_SUSPICIOUS_FILES: true
});

// Validate backup security
const security = await securitySystem.validateBackupSecurity('/path/to/backup');

console.log(`Security Score: ${security.results.overall.score}/100`);
```

### 5. CLI Interface (`BackupRestoreCLI.js`)

Interactive command-line interface for all backup and restore operations.

**Key Features:**
- **Interactive Menus**: User-friendly navigation with progress indicators
- **Real-time Progress**: Live progress bars with ETA calculations
- **Colored Output**: Enhanced readability with color-coded messages
- **Comprehensive Logging**: Configurable log levels with file output
- **Safety Confirmations**: Multiple confirmation steps for destructive operations

**Menu Options:**
- Create Backup (Full/Incremental/Custom)
- Restore from Backup
- List Available Backups
- Validate System Health
- Emergency Rollback
- Backup Management
- System Diagnostics
- Configuration Settings

### 6. Test Suite (`BackupRestoreTests.js`)

Comprehensive integration tests with performance benchmarking.

**Key Features:**
- **End-to-End Testing**: Complete backup-restore cycle validation
- **Performance Benchmarking**: Response time and throughput testing
- **Error Simulation**: Failure scenario testing and error handling
- **Mock Data Generation**: Realistic test data for comprehensive testing
- **Detailed Reporting**: Test results with metrics and recommendations

**Running Tests:**
```bash
# Run all tests
node BackupRestoreTests.js

# Verbose output with cleanup
node BackupRestoreTests.js --verbose --cleanup

# Test specific components
node BackupRestoreTests.js --suite="Backup System Tests"
```

## 🔧 Configuration

### Environment Variables

```bash
# Required
MONGODB_URI="mongodb://localhost:27017/faf_database"

# Optional
BACKUP_ROOT="./migration-backups"
LOG_LEVEL="info"                    # debug, info, warn, error
MAX_BACKUP_VERSIONS="10"
RETENTION_DAYS="30"
COMPRESSION_LEVEL="6"               # 1-9
ENABLE_AUDIT_LOGGING="true"
NOTIFICATION_CHANNELS="console,file" # console, file, email, webhook
```

### Configuration Files

#### Backup Configuration
```javascript
const BACKUP_CONFIG = {
  // Storage paths
  DEFAULT_BACKUP_ROOT: './migration-backups',
  
  // Compression settings
  COMPRESSION_LEVEL: 6,
  ENABLE_COMPRESSION: true,
  
  // Versioning and retention
  MAX_BACKUP_VERSIONS: 10,
  RETENTION_DAYS: 30,
  
  // Performance tuning
  BATCH_SIZE: 1000,
  MAX_MEMORY_USAGE: 512 * 1024 * 1024,
  
  // Security
  ENABLE_CHECKSUMS: true,
  HASH_ALGORITHM: 'sha256'
};
```

#### Security Configuration
```javascript
const SECURITY_CONFIG = {
  // Checksum algorithms
  PRIMARY_HASH_ALGORITHM: 'sha256',
  SECONDARY_HASH_ALGORITHM: 'sha512',
  ENABLE_MULTI_HASH: true,
  
  // Security thresholds
  MAX_VALIDATION_FAILURES: 5,
  QUARANTINE_SUSPICIOUS_FILES: true,
  
  // Audit logging
  ENABLE_SECURITY_AUDIT: true,
  AUDIT_LOG_PATH: './logs/security-audit',
  RETENTION_DAYS: 365
};
```

## 📋 Usage Scenarios

### Scenario 1: Regular Backup Schedule

```javascript
// Daily incremental backups
const dailyBackup = async () => {
  const backup = await backupSystem.createIntelligentBackup({
    type: 'incremental',
    compression: true
  });
  
  // Validate backup integrity
  const security = await securitySystem.validateBackupSecurity(backup.backupPath);
  
  if (security.results.overall.score < 95) {
    throw new Error('Backup security validation failed');
  }
  
  return backup;
};

// Weekly full backups
const weeklyBackup = async () => {
  const backup = await backupSystem.createIntelligentBackup({
    type: 'full',
    compression: true,
    compressionLevel: 9
  });
  
  // Clean up old backups
  await backupSystem.cleanupOldBackups();
  
  return backup;
};
```

### Scenario 2: Emergency Rollback

```javascript
const emergencyRollback = async () => {
  // Get most recent successful backup
  const backups = await backupSystem.listAllBackups();
  const lastGoodBackup = backups
    .filter(b => b.status === 'completed')
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
  
  if (!lastGoodBackup) {
    throw new Error('No valid backup available for emergency rollback');
  }
  
  // Execute emergency rollback
  const result = await rollbackSystem.executeRollback(lastGoodBackup.path, {
    emergencyMode: true,
    skipValidation: false,
    notifyAdmins: true
  });
  
  // Validate system after rollback
  const health = await healthValidator.validateSystemHealth();
  
  if (health.results.overall.score < 80) {
    throw new Error('System health critical after rollback');
  }
  
  return result;
};
```

### Scenario 3: Migration with Rollback Safety

```javascript
const safeMigration = async (migrationFunction) => {
  // Create safety backup before migration
  const safetyBackup = await backupSystem.createIntelligentBackup({
    type: 'full',
    compression: true
  });
  
  try {
    // Execute migration
    const migrationResult = await migrationFunction();
    
    // Validate system after migration
    const health = await healthValidator.validateSystemHealth();
    
    if (health.results.overall.score < 90) {
      throw new Error('Migration validation failed');
    }
    
    return migrationResult;
    
  } catch (error) {
    // Automatic rollback on migration failure
    console.log('Migration failed, initiating rollback...');
    
    await rollbackSystem.executeRollback(safetyBackup.backupPath);
    
    throw new Error(`Migration failed and rolled back: ${error.message}`);
  }
};
```

## 🔒 Security Features

### Data Protection
- **Multi-layer checksums** (SHA256, SHA512, MD5)
- **File integrity monitoring** with tamper detection
- **Permission validation** for all backup operations
- **Audit logging** for compliance and forensic analysis

### Access Control
- **Role-based permissions** for backup operations
- **Emergency lockdown** procedures for security incidents
- **Quarantine system** for suspicious files
- **Encrypted audit logs** for sensitive operations

### Compliance
- **Comprehensive audit trails** for all operations
- **Retention policies** for backup and log data
- **Security reporting** with detailed metrics
- **Compliance validation** for regulatory requirements

## 📈 Performance Optimization

### Backup Optimization
- **Incremental backups** reduce backup time by 60-80%
- **Compression** reduces storage requirements by 40-70%
- **Batch processing** optimizes memory usage for large datasets
- **Progress monitoring** provides accurate ETAs

### Restore Optimization
- **Parallel restoration** for faster recovery times
- **Index rebuilding** optimized for large collections
- **Memory management** prevents system overload during restore
- **Checkpoint validation** ensures restoration integrity

### System Monitoring
- **Real-time metrics** for backup and restore operations
- **Performance alerts** for degraded system performance
- **Resource monitoring** prevents system overload
- **Optimization recommendations** for improved performance

## 🛠️ Troubleshooting

### Common Issues

#### Issue: Backup fails with "Out of memory" error
**Solution:**
```javascript
// Reduce batch size and memory usage
const backupSystem = new IntelligentBackupSystem({
  BATCH_SIZE: 500,  // Reduce from default 1000
  MAX_MEMORY_USAGE: 256 * 1024 * 1024  // Reduce to 256MB
});
```

#### Issue: Checksum validation fails
**Solution:**
```javascript
// Regenerate checksums and validate backup integrity
const manifest = await checksumValidator.generateSecureManifest(backupPath);
const validation = await checksumValidator.validateMultipleFiles(manifest.files);

if (validation.invalidFiles > 0) {
  // Quarantine corrupted files and regenerate backup
  await corruptionDetector.quarantineFile(corruptedFilePath, 'checksum_mismatch');
}
```

#### Issue: Rollback fails with permission errors
**Solution:**
```bash
# Check and fix file permissions
chmod -R 755 /path/to/backup/directory
chown -R $(whoami) /path/to/backup/directory

# Validate permissions programmatically
const permissionResult = await permissionValidator.validateBackupDirectoryPermissions(backupPath);
```

### Debugging

#### Enable verbose logging
```javascript
const logger = new CLILogger({
  level: 'debug',
  logFile: './logs/backup-debug.log'
});
```

#### Monitor system performance
```javascript
const performanceMonitor = new PerformanceMonitor();
const { metrics } = await performanceMonitor.measureQuery('backup_operation', backupFunction);
console.log(`Operation took ${metrics.executionTime}ms`);
```

## 📚 API Reference

### IntelligentBackupSystem

#### Methods

##### `createIntelligentBackup(options)`
Creates a new backup with specified options.

**Parameters:**
- `options.type` (string): 'full' | 'incremental' | 'differential'
- `options.compression` (boolean): Enable compression
- `options.compressionLevel` (number): 1-9, compression level
- `options.collections` (array): Specific collections to backup

**Returns:** Promise resolving to backup result object

##### `listAllBackups()`
Lists all available backups with metadata.

**Returns:** Promise resolving to array of backup objects

##### `deleteBackup(backupPath)`
Deletes a specific backup directory.

**Parameters:**
- `backupPath` (string): Path to backup directory

**Returns:** Promise resolving when deletion is complete

### AutomaticRollbackSystem

#### Methods

##### `executeRollback(backupPath, options)`
Executes database rollback from specified backup.

**Parameters:**
- `backupPath` (string): Path to backup directory
- `options.emergencyMode` (boolean): Skip some validations for speed
- `options.notifyAdmins` (boolean): Send administrator notifications

**Returns:** Promise resolving to rollback result object

### SystemHealthValidator

#### Methods

##### `validateSystemHealth(options)`
Performs comprehensive system health validation.

**Parameters:**
- `options.ENABLE_DOCUMENT_VALIDATION` (boolean): Validate document structure
- `options.ENABLE_INDEX_VALIDATION` (boolean): Validate index health
- `options.ENABLE_PERFORMANCE_VALIDATION` (boolean): Test performance metrics

**Returns:** Promise resolving to health validation results

### SecurityValidationSystem

#### Methods

##### `validateBackupSecurity(backupPath, options)`
Validates backup security and integrity.

**Parameters:**
- `backupPath` (string): Path to backup directory
- `options` (object): Validation configuration options

**Returns:** Promise resolving to security validation results

## 🧪 Testing

### Running Tests

```bash
# Run all tests
node BackupRestoreTests.js

# Run with verbose output
node BackupRestoreTests.js --verbose

# Clean up test files after completion
node BackupRestoreTests.js --cleanup

# Run specific test suite
node BackupRestoreTests.js --suite="Security Validation Tests"
```

### Test Coverage

The test suite covers:
- ✅ **Backup System Tests** (6 tests)
- ✅ **Rollback System Tests** (5 tests)
- ✅ **Health Validation Tests** (4 tests)
- ✅ **Security Validation Tests** (4 tests)
- ✅ **Integration Tests** (3 tests)
- ✅ **Performance Tests** (3 tests)
- ✅ **Error Handling Tests** (3 tests)

**Total: 28 comprehensive tests**

### Performance Benchmarks

| Operation | Target Time | Typical Performance |
|-----------|-------------|-------------------|
| Full Backup (1000 docs) | < 60s | ~15-30s |
| Incremental Backup | < 30s | ~5-15s |
| Database Restore | < 120s | ~30-60s |
| Health Validation | < 30s | ~10-20s |
| Security Validation | < 45s | ~15-30s |

## 📝 Changelog

### v2.0.0 (2025-08-17)
- ✨ **NEW:** Complete rewrite with enterprise-grade features
- ✨ **NEW:** Intelligent backup system with compression and versioning
- ✨ **NEW:** Automatic rollback with failure detection
- ✨ **NEW:** Comprehensive security validation system
- ✨ **NEW:** Interactive CLI with colored output and progress bars
- ✨ **NEW:** System health monitoring and validation
- ✨ **NEW:** Complete test suite with performance benchmarking
- 🔧 **IMPROVED:** Memory-efficient batch processing
- 🔧 **IMPROVED:** Real-time progress monitoring with ETAs
- 🔧 **IMPROVED:** Multi-layer security with audit logging
- 🛡️ **SECURITY:** Multi-hash checksums with tamper detection
- 🛡️ **SECURITY:** Permission validation and access control
- 🛡️ **SECURITY:** Comprehensive audit trails for compliance

## 🤝 Contributing

### Development Setup

```bash
# Clone the repository
git clone [repository-url]
cd faf/scripts/backup-restore

# Install dependencies
npm install

# Set up test environment
export MONGODB_URI="mongodb://localhost:27017/faf_backup_test"

# Run tests
npm test
```

### Code Style

- Use ES6+ features and async/await
- Follow JSDoc commenting conventions
- Implement comprehensive error handling
- Include unit tests for new features
- Update documentation for API changes

### Submitting Changes

1. Create feature branch: `git checkout -b feature/backup-enhancement`
2. Make changes with tests: `git commit -m "Add backup compression feature"`
3. Push to branch: `git push origin feature/backup-enhancement`
4. Submit pull request with detailed description

## 📞 Support

### Documentation
- 📖 **API Reference**: See sections above for detailed API documentation
- 🎯 **Examples**: Check usage scenarios for common implementations
- 🧪 **Testing**: Review test suite for integration examples

### Troubleshooting
- 🔍 **Logs**: Check `./logs/` directory for detailed operation logs
- 📊 **Metrics**: Use health validation for system performance insights
- 🚨 **Alerts**: Monitor security audit logs for potential issues

### Getting Help
- 📋 **Issues**: Create detailed issue reports with reproduction steps
- 💬 **Discussions**: Use project discussions for questions and suggestions
- 📧 **Contact**: Reach out to the development team for urgent issues

---

**Built with ❤️ by the FAF Development Team**

*This documentation is maintained alongside the codebase and is updated with each release.*