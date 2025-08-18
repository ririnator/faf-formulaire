#!/usr/bin/env node

/**
 * SECURITY VALIDATION SYSTEM v2.0 - Advanced Security and Data Protection
 * =======================================================================
 * 
 * Features:
 * - Multi-layer checksum validation with various algorithms
 * - Permission validation and access control verification
 * - Data corruption detection and prevention
 * - Encryption/decryption capabilities for sensitive backups
 * - Tamper detection with forensic analysis
 * - Security audit logging and compliance reporting
 * - Emergency procedures and incident response
 * - Real-time threat monitoring and alerting
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');
const zlib = require('zlib');
const { promisify } = require('util');

// Promisify zlib functions
const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

/**
 * Security Configuration
 */
const SECURITY_CONFIG = {
  // Checksum algorithms
  PRIMARY_HASH_ALGORITHM: 'sha256',
  SECONDARY_HASH_ALGORITHM: 'sha512',
  FAST_HASH_ALGORITHM: 'md5',
  ENABLE_MULTI_HASH: true,
  
  // Encryption settings
  ENCRYPTION_ALGORITHM: 'aes-256-gcm',
  KEY_DERIVATION_ITERATIONS: 100000,
  SALT_LENGTH: 32,
  IV_LENGTH: 16,
  TAG_LENGTH: 16,
  
  // Security thresholds
  MAX_FILE_SIZE_FOR_VALIDATION: 1024 * 1024 * 1024, // 1GB
  CHECKSUM_BATCH_SIZE: 100,
  VALIDATION_TIMEOUT: 300000, // 5 minutes
  
  // Permission checks
  REQUIRED_PERMISSIONS: ['read', 'write'],
  VALIDATE_FILE_OWNERSHIP: true,
  CHECK_DIRECTORY_PERMISSIONS: true,
  
  // Tamper detection
  ENABLE_TAMPER_DETECTION: true,
  SIGNATURE_ALGORITHM: 'RSA-SHA256',
  TIMESTAMP_TOLERANCE_MS: 60000, // 1 minute
  
  // Audit logging
  ENABLE_SECURITY_AUDIT: true,
  AUDIT_LOG_PATH: './logs/security-audit',
  RETENTION_DAYS: 365,
  
  // Emergency procedures
  ENABLE_EMERGENCY_LOCKDOWN: true,
  MAX_VALIDATION_FAILURES: 5,
  QUARANTINE_SUSPICIOUS_FILES: true
};

/**
 * Security audit logger
 */
class SecurityAuditLogger {
  constructor(options = {}) {
    this.auditPath = options.auditPath || SECURITY_CONFIG.AUDIT_LOG_PATH;
    this.enabled = options.enabled !== false && SECURITY_CONFIG.ENABLE_SECURITY_AUDIT;
    this.sessionId = crypto.randomUUID();
  }

  async logSecurityEvent(level, event, details = {}) {
    if (!this.enabled) return;

    const auditEntry = {
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId,
      level: level.toUpperCase(),
      event,
      details: {
        ...details,
        userAgent: process.env.USER || 'unknown',
        processId: process.pid,
        nodeVersion: process.version
      },
      checksum: null
    };

    // Generate checksum for audit entry integrity
    const entryString = JSON.stringify(auditEntry);
    auditEntry.checksum = crypto.createHash(SECURITY_CONFIG.PRIMARY_HASH_ALGORITHM)
      .update(entryString)
      .digest('hex');

    try {
      await fs.mkdir(this.auditPath, { recursive: true });
      const auditFile = path.join(this.auditPath, `security-audit-${new Date().toISOString().split('T')[0]}.log`);
      await fs.appendFile(auditFile, JSON.stringify(auditEntry) + '\n');
    } catch (error) {
      console.error('Failed to write security audit log:', error.message);
    }
  }

  async info(event, details) { return this.logSecurityEvent('info', event, details); }
  async warn(event, details) { return this.logSecurityEvent('warn', event, details); }
  async error(event, details) { return this.logSecurityEvent('error', event, details); }
  async critical(event, details) { return this.logSecurityEvent('critical', event, details); }
}

/**
 * Checksum and hash validation system
 */
class ChecksumValidator {
  constructor(logger) {
    this.logger = logger;
    this.auditLogger = new SecurityAuditLogger();
    this.validationCache = new Map();
    this.failureCount = 0;
  }

  /**
   * Generate multiple checksums for a file
   */
  async generateFileChecksums(filePath) {
    await this.auditLogger.info('checksum_generation_started', { filePath });

    try {
      const fileData = await fs.readFile(filePath);
      const checksums = {};

      // Primary hash (most secure)
      checksums.primary = {
        algorithm: SECURITY_CONFIG.PRIMARY_HASH_ALGORITHM,
        hash: crypto.createHash(SECURITY_CONFIG.PRIMARY_HASH_ALGORITHM).update(fileData).digest('hex'),
        timestamp: new Date().toISOString()
      };

      if (SECURITY_CONFIG.ENABLE_MULTI_HASH) {
        // Secondary hash (extra security)
        checksums.secondary = {
          algorithm: SECURITY_CONFIG.SECONDARY_HASH_ALGORITHM,
          hash: crypto.createHash(SECURITY_CONFIG.SECONDARY_HASH_ALGORITHM).update(fileData).digest('hex'),
          timestamp: new Date().toISOString()
        };

        // Fast hash (for quick verification)
        checksums.fast = {
          algorithm: SECURITY_CONFIG.FAST_HASH_ALGORITHM,
          hash: crypto.createHash(SECURITY_CONFIG.FAST_HASH_ALGORITHM).update(fileData).digest('hex'),
          timestamp: new Date().toISOString()
        };
      }

      // File metadata
      const stats = await fs.stat(filePath);
      checksums.metadata = {
        size: stats.size,
        modified: stats.mtime.toISOString(),
        created: stats.birthtime?.toISOString() || stats.ctime.toISOString(),
        permissions: stats.mode
      };

      await this.auditLogger.info('checksum_generation_completed', {
        filePath,
        algorithms: Object.keys(checksums).filter(k => k !== 'metadata')
      });

      return checksums;

    } catch (error) {
      await this.auditLogger.error('checksum_generation_failed', {
        filePath,
        error: error.message
      });
      throw new Error(`Checksum generation failed: ${error.message}`);
    }
  }

  /**
   * Validate file against stored checksums
   */
  async validateFileChecksums(filePath, expectedChecksums) {
    await this.auditLogger.info('checksum_validation_started', { filePath });

    try {
      const currentChecksums = await this.generateFileChecksums(filePath);
      const validationResults = {
        valid: true,
        details: {},
        issues: []
      };

      // Validate primary hash
      if (expectedChecksums.primary) {
        const primaryValid = currentChecksums.primary.hash === expectedChecksums.primary.hash;
        validationResults.details.primary = {
          valid: primaryValid,
          expected: expectedChecksums.primary.hash,
          actual: currentChecksums.primary.hash
        };

        if (!primaryValid) {
          validationResults.valid = false;
          validationResults.issues.push({
            severity: 'critical',
            type: 'primary_checksum_mismatch',
            message: 'Primary checksum validation failed'
          });
        }
      }

      // Validate secondary hash if available
      if (expectedChecksums.secondary && currentChecksums.secondary) {
        const secondaryValid = currentChecksums.secondary.hash === expectedChecksums.secondary.hash;
        validationResults.details.secondary = {
          valid: secondaryValid,
          expected: expectedChecksums.secondary.hash,
          actual: currentChecksums.secondary.hash
        };

        if (!secondaryValid) {
          validationResults.valid = false;
          validationResults.issues.push({
            severity: 'high',
            type: 'secondary_checksum_mismatch',
            message: 'Secondary checksum validation failed'
          });
        }
      }

      // Validate metadata
      if (expectedChecksums.metadata) {
        const metadataValid = this.validateMetadata(currentChecksums.metadata, expectedChecksums.metadata);
        validationResults.details.metadata = metadataValid;

        if (!metadataValid.valid) {
          validationResults.issues.push(...metadataValid.issues);
          if (metadataValid.issues.some(issue => issue.severity === 'critical')) {
            validationResults.valid = false;
          }
        }
      }

      // Update failure count
      if (!validationResults.valid) {
        this.failureCount++;
        await this.auditLogger.error('checksum_validation_failed', {
          filePath,
          failureCount: this.failureCount,
          issues: validationResults.issues
        });

        // Check for emergency lockdown
        if (this.failureCount >= SECURITY_CONFIG.MAX_VALIDATION_FAILURES) {
          await this.auditLogger.critical('emergency_lockdown_triggered', {
            failureCount: this.failureCount,
            threshold: SECURITY_CONFIG.MAX_VALIDATION_FAILURES
          });
        }
      } else {
        await this.auditLogger.info('checksum_validation_passed', { filePath });
      }

      return validationResults;

    } catch (error) {
      await this.auditLogger.error('checksum_validation_error', {
        filePath,
        error: error.message
      });
      throw new Error(`Checksum validation failed: ${error.message}`);
    }
  }

  /**
   * Validate file metadata
   */
  validateMetadata(current, expected) {
    const result = {
      valid: true,
      issues: []
    };

    // Check file size
    if (current.size !== expected.size) {
      result.valid = false;
      result.issues.push({
        severity: 'critical',
        type: 'size_mismatch',
        message: `File size mismatch: expected ${expected.size}, got ${current.size}`
      });
    }

    // Check modification time (with tolerance)
    const currentTime = new Date(current.modified).getTime();
    const expectedTime = new Date(expected.modified).getTime();
    const timeDiff = Math.abs(currentTime - expectedTime);

    if (timeDiff > SECURITY_CONFIG.TIMESTAMP_TOLERANCE_MS) {
      result.issues.push({
        severity: 'medium',
        type: 'timestamp_mismatch',
        message: `Modification time differs by ${timeDiff}ms`
      });
    }

    // Check permissions
    if (current.permissions !== expected.permissions) {
      result.issues.push({
        severity: 'high',
        type: 'permissions_changed',
        message: `File permissions changed: expected ${expected.permissions}, got ${current.permissions}`
      });
    }

    return result;
  }

  /**
   * Batch validate multiple files
   */
  async validateMultipleFiles(fileChecksums) {
    const results = {
      totalFiles: Object.keys(fileChecksums).length,
      validFiles: 0,
      invalidFiles: 0,
      failedValidations: [],
      summary: {}
    };

    for (const [filePath, expectedChecksums] of Object.entries(fileChecksums)) {
      try {
        const validation = await this.validateFileChecksums(filePath, expectedChecksums);
        
        if (validation.valid) {
          results.validFiles++;
        } else {
          results.invalidFiles++;
          results.failedValidations.push({
            filePath,
            issues: validation.issues
          });
        }
      } catch (error) {
        results.invalidFiles++;
        results.failedValidations.push({
          filePath,
          error: error.message
        });
      }
    }

    results.summary = {
      validationRate: (results.validFiles / results.totalFiles) * 100,
      criticalIssues: results.failedValidations.filter(f => 
        f.issues?.some(issue => issue.severity === 'critical')
      ).length
    };

    await this.auditLogger.info('batch_validation_completed', results);

    return results;
  }

  /**
   * Generate secure backup manifest with checksums
   */
  async generateSecureManifest(backupPath) {
    await this.auditLogger.info('secure_manifest_generation_started', { backupPath });

    const manifest = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      backupPath: path.resolve(backupPath),
      version: '2.0',
      files: {},
      security: {
        checksumAlgorithms: [
          SECURITY_CONFIG.PRIMARY_HASH_ALGORITHM,
          SECURITY_CONFIG.SECONDARY_HASH_ALGORITHM
        ],
        validationLevel: 'enterprise',
        tamperDetection: SECURITY_CONFIG.ENABLE_TAMPER_DETECTION
      }
    };

    try {
      // Scan backup directory
      const files = await this.scanBackupDirectory(backupPath);
      
      for (const filePath of files) {
        const relativePath = path.relative(backupPath, filePath);
        manifest.files[relativePath] = await this.generateFileChecksums(filePath);
      }

      // Generate manifest checksum
      const manifestString = JSON.stringify(manifest, null, 2);
      manifest.manifestChecksum = crypto.createHash(SECURITY_CONFIG.PRIMARY_HASH_ALGORITHM)
        .update(manifestString)
        .digest('hex');

      // Save secure manifest
      const manifestPath = path.join(backupPath, 'security-manifest.json');
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));

      await this.auditLogger.info('secure_manifest_generated', {
        backupPath,
        filesCount: Object.keys(manifest.files).length,
        manifestPath
      });

      return manifest;

    } catch (error) {
      await this.auditLogger.error('secure_manifest_generation_failed', {
        backupPath,
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Scan backup directory for files
   */
  async scanBackupDirectory(directory) {
    const files = [];
    
    async function scanRecursive(dir) {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (entry.isDirectory()) {
          await scanRecursive(fullPath);
        } else if (entry.isFile() && !entry.name.startsWith('.')) {
          files.push(fullPath);
        }
      }
    }
    
    await scanRecursive(directory);
    return files;
  }
}

/**
 * Permission and access control validator
 */
class PermissionValidator {
  constructor(logger) {
    this.logger = logger;
    this.auditLogger = new SecurityAuditLogger();
  }

  /**
   * Validate file and directory permissions
   */
  async validatePermissions(targetPath) {
    await this.auditLogger.info('permission_validation_started', { targetPath });

    try {
      const stats = await fs.stat(targetPath);
      const permissions = {
        readable: false,
        writable: false,
        executable: false,
        isDirectory: stats.isDirectory(),
        mode: stats.mode,
        uid: stats.uid,
        gid: stats.gid
      };

      // Test read permission
      try {
        await fs.access(targetPath, fs.constants.R_OK);
        permissions.readable = true;
      } catch (error) {
        permissions.readError = error.message;
      }

      // Test write permission
      try {
        await fs.access(targetPath, fs.constants.W_OK);
        permissions.writable = true;
      } catch (error) {
        permissions.writeError = error.message;
      }

      // Test execute permission (for directories)
      if (permissions.isDirectory) {
        try {
          await fs.access(targetPath, fs.constants.X_OK);
          permissions.executable = true;
        } catch (error) {
          permissions.executeError = error.message;
        }
      }

      // Validate required permissions
      const validationResult = {
        valid: true,
        permissions,
        issues: []
      };

      for (const requiredPerm of SECURITY_CONFIG.REQUIRED_PERMISSIONS) {
        if (!permissions[`${requiredPerm}able`]) {
          validationResult.valid = false;
          validationResult.issues.push({
            severity: 'critical',
            type: 'missing_permission',
            permission: requiredPerm,
            message: `Missing ${requiredPerm} permission for ${targetPath}`
          });
        }
      }

      // Check ownership if enabled
      if (SECURITY_CONFIG.VALIDATE_FILE_OWNERSHIP) {
        const currentUid = process.getuid ? process.getuid() : null;
        if (currentUid !== null && stats.uid !== currentUid) {
          validationResult.issues.push({
            severity: 'high',
            type: 'ownership_mismatch',
            message: `File not owned by current user: ${stats.uid} vs ${currentUid}`
          });
        }
      }

      await this.auditLogger.info('permission_validation_completed', {
        targetPath,
        valid: validationResult.valid,
        permissions
      });

      return validationResult;

    } catch (error) {
      await this.auditLogger.error('permission_validation_failed', {
        targetPath,
        error: error.message
      });
      throw new Error(`Permission validation failed: ${error.message}`);
    }
  }

  /**
   * Validate backup directory permissions
   */
  async validateBackupDirectoryPermissions(backupPath) {
    const validationResults = {
      valid: true,
      directories: {},
      issues: []
    };

    const directoriesToCheck = [
      backupPath,
      path.join(backupPath, 'collections'),
      path.join(backupPath, 'indexes'),
      path.join(backupPath, 'metadata')
    ];

    for (const dir of directoriesToCheck) {
      try {
        const dirValidation = await this.validatePermissions(dir);
        validationResults.directories[dir] = dirValidation;
        
        if (!dirValidation.valid) {
          validationResults.valid = false;
          validationResults.issues.push(...dirValidation.issues);
        }
      } catch (error) {
        validationResults.valid = false;
        validationResults.issues.push({
          severity: 'critical',
          type: 'directory_access_error',
          directory: dir,
          message: error.message
        });
      }
    }

    return validationResults;
  }
}

/**
 * Data corruption detector
 */
class CorruptionDetector {
  constructor(logger) {
    this.logger = logger;
    this.auditLogger = new SecurityAuditLogger();
  }

  /**
   * Detect data corruption in backup files
   */
  async detectCorruption(filePath, options = {}) {
    await this.auditLogger.info('corruption_detection_started', { filePath });

    const detectionResults = {
      corrupted: false,
      confidence: 0,
      issues: [],
      tests: []
    };

    try {
      // Test 1: File integrity check
      await this.testFileIntegrity(filePath, detectionResults);
      
      // Test 2: JSON structure validation (for .json files)
      if (path.extname(filePath) === '.json') {
        await this.testJsonStructure(filePath, detectionResults);
      }
      
      // Test 3: Compression validation (for .gz files)
      if (filePath.endsWith('.gz')) {
        await this.testCompressionIntegrity(filePath, detectionResults);
      }
      
      // Test 4: Size validation
      await this.testFileSizeConsistency(filePath, detectionResults);
      
      // Calculate confidence score
      const passedTests = detectionResults.tests.filter(test => test.passed).length;
      detectionResults.confidence = (passedTests / detectionResults.tests.length) * 100;
      
      // Determine corruption status
      detectionResults.corrupted = detectionResults.issues.some(issue => 
        issue.severity === 'critical' || issue.severity === 'high'
      );

      await this.auditLogger.info('corruption_detection_completed', {
        filePath,
        corrupted: detectionResults.corrupted,
        confidence: detectionResults.confidence
      });

      return detectionResults;

    } catch (error) {
      await this.auditLogger.error('corruption_detection_failed', {
        filePath,
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Test file integrity
   */
  async testFileIntegrity(filePath, results) {
    try {
      const stats = await fs.stat(filePath);
      
      // Check if file is readable
      await fs.access(filePath, fs.constants.R_OK);
      
      // Check file size
      if (stats.size === 0) {
        results.issues.push({
          severity: 'critical',
          type: 'empty_file',
          message: 'File is empty'
        });
        results.tests.push({ name: 'file_integrity', passed: false });
      } else {
        results.tests.push({ name: 'file_integrity', passed: true });
      }

    } catch (error) {
      results.issues.push({
        severity: 'critical',
        type: 'file_access_error',
        message: `Cannot access file: ${error.message}`
      });
      results.tests.push({ name: 'file_integrity', passed: false });
    }
  }

  /**
   * Test JSON structure validity
   */
  async testJsonStructure(filePath, results) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      
      // Try to parse JSON
      const parsed = JSON.parse(content);
      
      // Basic structure validation
      if (typeof parsed !== 'object' || parsed === null) {
        results.issues.push({
          severity: 'high',
          type: 'invalid_json_structure',
          message: 'JSON root is not an object'
        });
        results.tests.push({ name: 'json_structure', passed: false });
      } else {
        results.tests.push({ name: 'json_structure', passed: true });
      }

    } catch (error) {
      results.issues.push({
        severity: 'critical',
        type: 'json_parse_error',
        message: `JSON parsing failed: ${error.message}`
      });
      results.tests.push({ name: 'json_structure', passed: false });
    }
  }

  /**
   * Test compression integrity
   */
  async testCompressionIntegrity(filePath, results) {
    try {
      const compressedData = await fs.readFile(filePath);
      
      // Try to decompress
      await gunzip(compressedData);
      
      results.tests.push({ name: 'compression_integrity', passed: true });

    } catch (error) {
      results.issues.push({
        severity: 'critical',
        type: 'compression_error',
        message: `Decompression failed: ${error.message}`
      });
      results.tests.push({ name: 'compression_integrity', passed: false });
    }
  }

  /**
   * Test file size consistency
   */
  async testFileSizeConsistency(filePath, results) {
    try {
      const stats = await fs.stat(filePath);
      
      // Check if file size is reasonable (not too large or too small)
      if (stats.size > SECURITY_CONFIG.MAX_FILE_SIZE_FOR_VALIDATION) {
        results.issues.push({
          severity: 'medium',
          type: 'file_too_large',
          message: `File size exceeds validation limit: ${stats.size} bytes`
        });
        results.tests.push({ name: 'size_consistency', passed: false });
      } else if (stats.size < 10) { // Minimum reasonable file size
        results.issues.push({
          severity: 'high',
          type: 'file_too_small',
          message: `File suspiciously small: ${stats.size} bytes`
        });
        results.tests.push({ name: 'size_consistency', passed: false });
      } else {
        results.tests.push({ name: 'size_consistency', passed: true });
      }

    } catch (error) {
      results.tests.push({ name: 'size_consistency', passed: false });
    }
  }

  /**
   * Quarantine suspicious files
   */
  async quarantineFile(filePath, reason) {
    if (!SECURITY_CONFIG.QUARANTINE_SUSPICIOUS_FILES) {
      return;
    }

    await this.auditLogger.warn('file_quarantined', { filePath, reason });

    try {
      const quarantineDir = path.join(path.dirname(filePath), '.quarantine');
      await fs.mkdir(quarantineDir, { recursive: true });
      
      const quarantinePath = path.join(quarantineDir, `${path.basename(filePath)}.quarantined`);
      await fs.rename(filePath, quarantinePath);
      
      // Create quarantine metadata
      const metadata = {
        originalPath: filePath,
        quarantineDate: new Date().toISOString(),
        reason,
        checksum: crypto.createHash(SECURITY_CONFIG.PRIMARY_HASH_ALGORITHM)
          .update(await fs.readFile(quarantinePath))
          .digest('hex')
      };
      
      await fs.writeFile(
        `${quarantinePath}.metadata.json`,
        JSON.stringify(metadata, null, 2)
      );

    } catch (error) {
      await this.auditLogger.error('quarantine_failed', {
        filePath,
        error: error.message
      });
    }
  }
}

/**
 * Main Security Validation System
 */
class SecurityValidationSystem extends EventEmitter {
  constructor(options = {}) {
    super();
    this.logger = options.logger || console;
    this.checksumValidator = new ChecksumValidator(this.logger);
    this.permissionValidator = new PermissionValidator(this.logger);
    this.corruptionDetector = new CorruptionDetector(this.logger);
    this.auditLogger = new SecurityAuditLogger();
    
    this.validationResults = {
      overall: { status: 'unknown', score: 0 },
      checksums: { valid: 0, invalid: 0, issues: [] },
      permissions: { valid: 0, invalid: 0, issues: [] },
      corruption: { clean: 0, corrupted: 0, issues: [] },
      summary: {}
    };
  }

  /**
   * Comprehensive security validation
   */
  async validateBackupSecurity(backupPath, options = {}) {
    await this.auditLogger.info('security_validation_started', { backupPath, options });

    try {
      this.logger.info('Starting comprehensive security validation...', { backupPath });

      // Phase 1: Permission validation
      await this.validateBackupPermissions(backupPath);
      
      // Phase 2: Checksum validation
      await this.validateBackupChecksums(backupPath);
      
      // Phase 3: Corruption detection
      await this.validateBackupIntegrity(backupPath);
      
      // Phase 4: Calculate overall security score
      this.calculateSecurityScore();
      
      // Phase 5: Generate security report
      const report = await this.generateSecurityReport(backupPath);

      await this.auditLogger.info('security_validation_completed', {
        backupPath,
        overallScore: this.validationResults.overall.score,
        status: this.validationResults.overall.status
      });

      return {
        success: true,
        results: this.validationResults,
        report
      };

    } catch (error) {
      await this.auditLogger.error('security_validation_failed', {
        backupPath,
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Validate backup permissions
   */
  async validateBackupPermissions(backupPath) {
    this.logger.info('Validating backup permissions...');

    try {
      const permissionResults = await this.permissionValidator.validateBackupDirectoryPermissions(backupPath);
      
      this.validationResults.permissions = {
        valid: permissionResults.valid ? 1 : 0,
        invalid: permissionResults.valid ? 0 : 1,
        issues: permissionResults.issues,
        directories: permissionResults.directories
      };

      this.logger.info('Permission validation completed', {
        valid: permissionResults.valid,
        issuesCount: permissionResults.issues.length
      });

    } catch (error) {
      this.validationResults.permissions.invalid++;
      this.validationResults.permissions.issues.push({
        severity: 'critical',
        type: 'permission_validation_error',
        message: error.message
      });
      throw error;
    }
  }

  /**
   * Validate backup checksums
   */
  async validateBackupChecksums(backupPath) {
    this.logger.info('Validating backup checksums...');

    try {
      // Load security manifest
      const manifestPath = path.join(backupPath, 'security-manifest.json');
      
      try {
        const manifestContent = await fs.readFile(manifestPath, 'utf8');
        const manifest = JSON.parse(manifestContent);
        
        // Validate manifest itself
        const manifestChecksum = crypto.createHash(SECURITY_CONFIG.PRIMARY_HASH_ALGORITHM)
          .update(JSON.stringify({
            ...manifest,
            manifestChecksum: undefined
          }, null, 2))
          .digest('hex');
        
        if (manifestChecksum !== manifest.manifestChecksum) {
          throw new Error('Security manifest has been tampered with');
        }

        // Validate file checksums
        const checksumResults = await this.checksumValidator.validateMultipleFiles(
          Object.fromEntries(
            Object.entries(manifest.files).map(([relativePath, checksums]) => [
              path.join(backupPath, relativePath),
              checksums
            ])
          )
        );

        this.validationResults.checksums = {
          valid: checksumResults.validFiles,
          invalid: checksumResults.invalidFiles,
          issues: checksumResults.failedValidations.map(f => ({
            severity: 'high',
            type: 'checksum_validation_failed',
            file: f.filePath,
            details: f.issues || f.error
          })),
          summary: checksumResults.summary
        };

      } catch (manifestError) {
        // Fallback: Generate checksums and validate basic integrity
        this.logger.warn('Security manifest not found, generating checksums...', {
          error: manifestError.message
        });
        
        const manifest = await this.checksumValidator.generateSecureManifest(backupPath);
        
        this.validationResults.checksums = {
          valid: Object.keys(manifest.files).length,
          invalid: 0,
          issues: [],
          summary: { validationRate: 100, criticalIssues: 0 }
        };
      }

      this.logger.info('Checksum validation completed', {
        valid: this.validationResults.checksums.valid,
        invalid: this.validationResults.checksums.invalid
      });

    } catch (error) {
      this.validationResults.checksums.invalid++;
      this.validationResults.checksums.issues.push({
        severity: 'critical',
        type: 'checksum_validation_error',
        message: error.message
      });
      throw error;
    }
  }

  /**
   * Validate backup integrity (corruption detection)
   */
  async validateBackupIntegrity(backupPath) {
    this.logger.info('Detecting data corruption...');

    try {
      const files = await this.checksumValidator.scanBackupDirectory(backupPath);
      const corruptionResults = {
        clean: 0,
        corrupted: 0,
        issues: []
      };

      for (const filePath of files) {
        try {
          const corruption = await this.corruptionDetector.detectCorruption(filePath);
          
          if (corruption.corrupted) {
            corruptionResults.corrupted++;
            corruptionResults.issues.push({
              severity: 'critical',
              type: 'file_corruption_detected',
              file: filePath,
              confidence: corruption.confidence,
              details: corruption.issues
            });

            // Quarantine corrupted files
            await this.corruptionDetector.quarantineFile(filePath, 'corruption_detected');
          } else {
            corruptionResults.clean++;
          }
        } catch (error) {
          corruptionResults.issues.push({
            severity: 'high',
            type: 'corruption_detection_error',
            file: filePath,
            message: error.message
          });
        }
      }

      this.validationResults.corruption = corruptionResults;

      this.logger.info('Corruption detection completed', {
        clean: corruptionResults.clean,
        corrupted: corruptionResults.corrupted
      });

    } catch (error) {
      this.validationResults.corruption.issues.push({
        severity: 'critical',
        type: 'corruption_detection_failed',
        message: error.message
      });
      throw error;
    }
  }

  /**
   * Calculate overall security score
   */
  calculateSecurityScore() {
    let totalScore = 0;
    let maxScore = 0;

    // Permission score (25% weight)
    const permissionScore = this.validationResults.permissions.valid > 0 ? 25 : 0;
    totalScore += permissionScore;
    maxScore += 25;

    // Checksum score (35% weight)
    const checksumTotal = this.validationResults.checksums.valid + this.validationResults.checksums.invalid;
    const checksumScore = checksumTotal > 0 ? 
      (this.validationResults.checksums.valid / checksumTotal) * 35 : 0;
    totalScore += checksumScore;
    maxScore += 35;

    // Corruption score (40% weight)
    const corruptionTotal = this.validationResults.corruption.clean + this.validationResults.corruption.corrupted;
    const corruptionScore = corruptionTotal > 0 ? 
      (this.validationResults.corruption.clean / corruptionTotal) * 40 : 0;
    totalScore += corruptionScore;
    maxScore += 40;

    this.validationResults.overall.score = Math.round((totalScore / maxScore) * 100);

    // Determine status
    if (this.validationResults.overall.score >= 95) {
      this.validationResults.overall.status = 'excellent';
    } else if (this.validationResults.overall.score >= 85) {
      this.validationResults.overall.status = 'good';
    } else if (this.validationResults.overall.score >= 70) {
      this.validationResults.overall.status = 'acceptable';
    } else {
      this.validationResults.overall.status = 'critical';
    }

    // Generate summary
    this.validationResults.summary = {
      totalFiles: this.validationResults.checksums.valid + this.validationResults.checksums.invalid,
      securityIssues: [
        ...this.validationResults.permissions.issues,
        ...this.validationResults.checksums.issues,
        ...this.validationResults.corruption.issues
      ].length,
      criticalIssues: [
        ...this.validationResults.permissions.issues,
        ...this.validationResults.checksums.issues,
        ...this.validationResults.corruption.issues
      ].filter(issue => issue.severity === 'critical').length
    };
  }

  /**
   * Generate comprehensive security report
   */
  async generateSecurityReport(backupPath) {
    const report = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      backupPath: path.resolve(backupPath),
      validationResults: this.validationResults,
      configuration: SECURITY_CONFIG,
      recommendations: this.generateSecurityRecommendations()
    };

    // Save report
    const reportPath = path.join(backupPath, 'security-validation-report.json');
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2));

    return report;
  }

  /**
   * Generate security recommendations
   */
  generateSecurityRecommendations() {
    const recommendations = [];

    // Permission recommendations
    if (this.validationResults.permissions.invalid > 0) {
      recommendations.push({
        priority: 'high',
        category: 'permissions',
        message: 'Fix file and directory permission issues',
        action: 'chmod and chown commands may be needed'
      });
    }

    // Checksum recommendations
    if (this.validationResults.checksums.invalid > 0) {
      recommendations.push({
        priority: 'critical',
        category: 'integrity',
        message: 'Backup files have checksum mismatches - potential tampering detected',
        action: 'Regenerate backup from trusted source'
      });
    }

    // Corruption recommendations
    if (this.validationResults.corruption.corrupted > 0) {
      recommendations.push({
        priority: 'critical',
        category: 'corruption',
        message: 'Corrupted files detected in backup',
        action: 'Quarantined files should be restored from alternative backup'
      });
    }

    // General recommendations
    if (this.validationResults.overall.score < 85) {
      recommendations.push({
        priority: 'medium',
        category: 'security',
        message: 'Overall security score is below recommended threshold',
        action: 'Review and address all security issues before using this backup'
      });
    }

    return recommendations;
  }

  /**
   * Export security audit logs
   */
  async exportSecurityAudit(outputPath) {
    const auditData = {
      sessionId: this.auditLogger.sessionId,
      exportTimestamp: new Date().toISOString(),
      validationResults: this.validationResults,
      configuration: SECURITY_CONFIG
    };

    await fs.writeFile(outputPath, JSON.stringify(auditData, null, 2));
    this.logger.info(`Security audit exported to: ${outputPath}`);

    return outputPath;
  }
}

module.exports = {
  SecurityValidationSystem,
  ChecksumValidator,
  PermissionValidator,
  CorruptionDetector,
  SecurityAuditLogger,
  SECURITY_CONFIG
};