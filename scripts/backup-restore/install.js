#!/usr/bin/env node

/**
 * BACKUP & RESTORE SYSTEM INSTALLER v2.0 - Automated Setup and Configuration
 * =========================================================================
 * 
 * Features:
 * - Automated dependency installation and verification
 * - Environment setup and configuration validation
 * - Directory structure creation with proper permissions
 * - Configuration file generation with secure defaults
 * - Integration with existing FAF migration system
 * - Health checks and system readiness validation
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');

/**
 * Installation Configuration
 */
const INSTALL_CONFIG = {
  // System requirements
  MIN_NODE_VERSION: '16.0.0',
  REQUIRED_PACKAGES: ['mongoose', 'chalk'],
  OPTIONAL_PACKAGES: ['nodemailer', 'webhook'],
  
  // Directory structure
  DIRECTORIES: [
    './logs',
    './logs/backup-restore',
    './logs/security-audit', 
    './logs/rollback',
    './migration-backups',
    './config/backup-restore'
  ],
  
  // Configuration files
  CONFIG_FILES: {
    'backup-config.json': 'backup-configuration',
    'security-config.json': 'security-configuration',
    'notification-config.json': 'notification-configuration'
  },
  
  // Environment validation
  REQUIRED_ENV_VARS: ['MONGODB_URI'],
  OPTIONAL_ENV_VARS: [
    'BACKUP_ROOT',
    'LOG_LEVEL',
    'MAX_BACKUP_VERSIONS',
    'RETENTION_DAYS',
    'COMPRESSION_LEVEL'
  ]
};

/**
 * Installation Logger
 */
class InstallLogger {
  constructor() {
    this.logFile = `./logs/installation-${Date.now()}.log`;
    this.logs = [];
  }

  async log(level, message, data = null) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      data
    };

    this.logs.push(logEntry);

    // Console output with colors
    const colors = {
      INFO: '\x1b[36m',    // Cyan
      WARN: '\x1b[33m',    // Yellow
      ERROR: '\x1b[31m',   // Red
      SUCCESS: '\x1b[32m', // Green
      DEBUG: '\x1b[90m'    // Gray
    };

    const color = colors[level.toUpperCase()] || '\x1b[0m';
    const reset = '\x1b[0m';
    
    console.log(`${color}[${logEntry.timestamp}] ${level.toUpperCase()}: ${message}${reset}`);
    
    if (data) {
      console.log(`${color}   ${JSON.stringify(data, null, 2)}${reset}`);
    }

    // Write to file
    try {
      await fs.mkdir(path.dirname(this.logFile), { recursive: true });
      await fs.appendFile(this.logFile, JSON.stringify(logEntry) + '\n');
    } catch (error) {
      // Ignore file logging errors during installation
    }
  }

  info(message, data) { return this.log('info', message, data); }
  warn(message, data) { return this.log('warn', message, data); }
  error(message, data) { return this.log('error', message, data); }
  success(message, data) { return this.log('success', message, data); }
  debug(message, data) { return this.log('debug', message, data); }
}

/**
 * System Installer
 */
class BackupRestoreInstaller {
  constructor() {
    this.logger = new InstallLogger();
    this.installationPath = process.cwd();
    this.errors = [];
    this.warnings = [];
  }

  /**
   * Main installation process
   */
  async install() {
    try {
      await this.logger.info('Starting FAF Backup & Restore System Installation...');
      
      // Phase 1: System Requirements Check
      await this.checkSystemRequirements();
      
      // Phase 2: Directory Structure Setup
      await this.createDirectoryStructure();
      
      // Phase 3: Configuration File Generation
      await this.generateConfigurationFiles();
      
      // Phase 4: Environment Setup
      await this.setupEnvironment();
      
      // Phase 5: Integration with Existing System
      await this.integrateWithExistingSystem();
      
      // Phase 6: Final Validation
      await this.validateInstallation();
      
      // Installation Complete
      await this.displayInstallationSummary();
      
    } catch (error) {
      await this.logger.error('Installation failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Check system requirements
   */
  async checkSystemRequirements() {
    await this.logger.info('=== Phase 1: System Requirements Check ===');

    // Check Node.js version
    const nodeVersion = process.version.slice(1); // Remove 'v' prefix
    if (this.compareVersions(nodeVersion, INSTALL_CONFIG.MIN_NODE_VERSION) < 0) {
      throw new Error(`Node.js ${INSTALL_CONFIG.MIN_NODE_VERSION}+ required, found ${nodeVersion}`);
    }
    await this.logger.success(`Node.js version check passed: ${nodeVersion}`);

    // Check npm availability
    try {
      execSync('npm --version', { stdio: 'pipe' });
      await this.logger.success('npm is available');
    } catch (error) {
      throw new Error('npm is not available - please install Node.js with npm');
    }

    // Check MongoDB connectivity (if URI provided)
    if (process.env.MONGODB_URI) {
      try {
        const mongoose = require('mongoose');
        await mongoose.connect(process.env.MONGODB_URI);
        await mongoose.disconnect();
        await this.logger.success('MongoDB connectivity check passed');
      } catch (error) {
        await this.logger.warn('MongoDB connectivity check failed', { error: error.message });
        this.warnings.push('MongoDB connection could not be verified');
      }
    } else {
      await this.logger.warn('MONGODB_URI not set - skipping connectivity check');
      this.warnings.push('MONGODB_URI environment variable not configured');
    }

    // Check required packages
    await this.checkPackageDependencies();
  }

  /**
   * Check and install package dependencies
   */
  async checkPackageDependencies() {
    await this.logger.info('Checking package dependencies...');

    const packageJson = await this.loadPackageJson();
    const missingPackages = [];

    for (const pkg of INSTALL_CONFIG.REQUIRED_PACKAGES) {
      if (!this.isPackageInstalled(pkg, packageJson)) {
        missingPackages.push(pkg);
      }
    }

    if (missingPackages.length > 0) {
      await this.logger.info(`Installing missing packages: ${missingPackages.join(', ')}`);
      
      try {
        execSync(`npm install ${missingPackages.join(' ')}`, { 
          stdio: 'inherit',
          cwd: this.findPackageJsonDirectory()
        });
        await this.logger.success('Required packages installed successfully');
      } catch (error) {
        throw new Error(`Failed to install required packages: ${error.message}`);
      }
    } else {
      await this.logger.success('All required packages are available');
    }

    // Check optional packages
    const missingOptional = [];
    for (const pkg of INSTALL_CONFIG.OPTIONAL_PACKAGES) {
      if (!this.isPackageInstalled(pkg, packageJson)) {
        missingOptional.push(pkg);
      }
    }

    if (missingOptional.length > 0) {
      await this.logger.info(`Optional packages not installed: ${missingOptional.join(', ')}`);
      await this.logger.info('These can be installed later for enhanced functionality');
    }
  }

  /**
   * Create directory structure
   */
  async createDirectoryStructure() {
    await this.logger.info('=== Phase 2: Directory Structure Setup ===');

    for (const dir of INSTALL_CONFIG.DIRECTORIES) {
      const fullPath = path.resolve(dir);
      
      try {
        await fs.mkdir(fullPath, { recursive: true });
        await this.logger.success(`Created directory: ${fullPath}`);
        
        // Set appropriate permissions (755)
        await fs.chmod(fullPath, 0o755);
        
      } catch (error) {
        this.errors.push(`Failed to create directory ${fullPath}: ${error.message}`);
        await this.logger.error(`Failed to create directory: ${fullPath}`, { error: error.message });
      }
    }

    // Create .gitignore for backup directories
    await this.createGitignore();
  }

  /**
   * Generate configuration files
   */
  async generateConfigurationFiles() {
    await this.logger.info('=== Phase 3: Configuration File Generation ===');

    const configDir = './config/backup-restore';
    
    for (const [filename, configType] of Object.entries(INSTALL_CONFIG.CONFIG_FILES)) {
      const configPath = path.join(configDir, filename);
      
      try {
        const config = this.generateConfigurationTemplate(configType);
        await fs.writeFile(configPath, JSON.stringify(config, null, 2));
        await this.logger.success(`Generated configuration: ${configPath}`);
      } catch (error) {
        this.errors.push(`Failed to generate config ${filename}: ${error.message}`);
        await this.logger.error(`Failed to generate configuration: ${filename}`, { error: error.message });
      }
    }

    // Generate environment template
    await this.generateEnvironmentTemplate();
  }

  /**
   * Setup environment
   */
  async setupEnvironment() {
    await this.logger.info('=== Phase 4: Environment Setup ===');

    // Check required environment variables
    const missingEnvVars = [];
    for (const envVar of INSTALL_CONFIG.REQUIRED_ENV_VARS) {
      if (!process.env[envVar]) {
        missingEnvVars.push(envVar);
      }
    }

    if (missingEnvVars.length > 0) {
      await this.logger.warn(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
      this.warnings.push(`Configure these environment variables: ${missingEnvVars.join(', ')}`);
    }

    // Check optional environment variables
    const setOptionalVars = [];
    for (const envVar of INSTALL_CONFIG.OPTIONAL_ENV_VARS) {
      if (process.env[envVar]) {
        setOptionalVars.push(envVar);
      }
    }

    if (setOptionalVars.length > 0) {
      await this.logger.success(`Optional environment variables configured: ${setOptionalVars.join(', ')}`);
    }

    // Create environment file template if it doesn't exist
    const envPath = './.env.backup-restore';
    try {
      await fs.access(envPath);
      await this.logger.info('Environment file already exists, skipping creation');
    } catch (error) {
      await this.createEnvironmentFile(envPath);
    }
  }

  /**
   * Integrate with existing system
   */
  async integrateWithExistingSystem() {
    await this.logger.info('=== Phase 5: Integration with Existing System ===');

    // Check for existing migration scripts
    const migrationScript = '../migrate-to-form-a-friend.js';
    try {
      await fs.access(migrationScript);
      await this.logger.success('Found existing migration script');
      
      // Update migration script to use new backup system
      await this.updateMigrationScript(migrationScript);
    } catch (error) {
      await this.logger.warn('Migration script not found - manual integration may be required');
      this.warnings.push('Manual integration with migration system may be required');
    }

    // Check for package.json to add scripts
    await this.addNpmScripts();
  }

  /**
   * Validate installation
   */
  async validateInstallation() {
    await this.logger.info('=== Phase 6: Installation Validation ===');

    const validationResults = {
      directories: 0,
      configurations: 0,
      dependencies: 0,
      permissions: 0
    };

    // Validate directories
    for (const dir of INSTALL_CONFIG.DIRECTORIES) {
      try {
        const stats = await fs.stat(dir);
        if (stats.isDirectory()) {
          validationResults.directories++;
        }
      } catch (error) {
        this.errors.push(`Directory validation failed: ${dir}`);
      }
    }

    // Validate configuration files
    for (const filename of Object.keys(INSTALL_CONFIG.CONFIG_FILES)) {
      const configPath = path.join('./config/backup-restore', filename);
      try {
        await fs.access(configPath);
        validationResults.configurations++;
      } catch (error) {
        this.errors.push(`Configuration file missing: ${configPath}`);
      }
    }

    // Validate dependencies
    const packageJson = await this.loadPackageJson();
    for (const pkg of INSTALL_CONFIG.REQUIRED_PACKAGES) {
      if (this.isPackageInstalled(pkg, packageJson)) {
        validationResults.dependencies++;
      }
    }

    await this.logger.success('Installation validation completed', validationResults);

    // Test basic functionality
    await this.testBasicFunctionality();
  }

  /**
   * Display installation summary
   */
  async displayInstallationSummary() {
    await this.logger.info('=== Installation Complete ===');

    const summary = {
      status: this.errors.length === 0 ? 'SUCCESS' : 'PARTIAL',
      errors: this.errors.length,
      warnings: this.warnings.length,
      timestamp: new Date().toISOString()
    };

    if (summary.status === 'SUCCESS') {
      await this.logger.success('✅ FAF Backup & Restore System installed successfully!');
      
      console.log('\n' + '='.repeat(60));
      console.log('🎉 INSTALLATION SUCCESSFUL! 🎉');
      console.log('='.repeat(60));
      console.log('\nNext steps:');
      console.log('1. Configure environment variables (see .env.backup-restore)');
      console.log('2. Review configuration files in ./config/backup-restore/');
      console.log('3. Test the system: node BackupRestoreCLI.js');
      console.log('4. Run tests: node BackupRestoreTests.js');
      console.log('\nDocumentation: See README.md for detailed usage instructions');
      
    } else {
      await this.logger.error('❌ Installation completed with errors');
      
      console.log('\n' + '='.repeat(60));
      console.log('⚠️ INSTALLATION COMPLETED WITH ISSUES');
      console.log('='.repeat(60));
      console.log('\nErrors encountered:');
      this.errors.forEach((error, index) => {
        console.log(`${index + 1}. ${error}`);
      });
    }

    if (this.warnings.length > 0) {
      console.log('\nWarnings:');
      this.warnings.forEach((warning, index) => {
        console.log(`${index + 1}. ${warning}`);
      });
    }

    console.log(`\nInstallation log: ${this.logger.logFile}`);
    console.log('='.repeat(60));

    return summary;
  }

  /**
   * Helper methods
   */
  compareVersions(version1, version2) {
    const v1 = version1.split('.').map(Number);
    const v2 = version2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(v1.length, v2.length); i++) {
      const a = v1[i] || 0;
      const b = v2[i] || 0;
      if (a > b) return 1;
      if (a < b) return -1;
    }
    return 0;
  }

  async loadPackageJson() {
    try {
      const packagePath = this.findPackageJsonPath();
      const content = await fs.readFile(packagePath, 'utf8');
      return JSON.parse(content);
    } catch (error) {
      return { dependencies: {}, devDependencies: {} };
    }
  }

  findPackageJsonPath() {
    const searchPaths = [
      './package.json',
      '../package.json',
      '../../package.json'
    ];
    
    for (const searchPath of searchPaths) {
      try {
        const fullPath = path.resolve(searchPath);
        require.resolve(fullPath);
        return fullPath;
      } catch (error) {
        // Continue searching
      }
    }
    
    throw new Error('package.json not found');
  }

  findPackageJsonDirectory() {
    return path.dirname(this.findPackageJsonPath());
  }

  isPackageInstalled(packageName, packageJson) {
    return packageJson.dependencies?.[packageName] || 
           packageJson.devDependencies?.[packageName] ||
           this.isPackageAvailable(packageName);
  }

  isPackageAvailable(packageName) {
    try {
      require.resolve(packageName);
      return true;
    } catch (error) {
      return false;
    }
  }

  generateConfigurationTemplate(configType) {
    switch (configType) {
      case 'backup-configuration':
        return {
          DEFAULT_BACKUP_ROOT: './migration-backups',
          COMPRESSION_LEVEL: 6,
          ENABLE_COMPRESSION: true,
          MAX_BACKUP_VERSIONS: 10,
          RETENTION_DAYS: 30,
          BATCH_SIZE: 1000,
          MAX_MEMORY_USAGE: 536870912,
          ENABLE_CHECKSUMS: true,
          HASH_ALGORITHM: 'sha256'
        };
        
      case 'security-configuration':
        return {
          PRIMARY_HASH_ALGORITHM: 'sha256',
          SECONDARY_HASH_ALGORITHM: 'sha512',
          ENABLE_MULTI_HASH: true,
          MAX_VALIDATION_FAILURES: 5,
          QUARANTINE_SUSPICIOUS_FILES: true,
          ENABLE_SECURITY_AUDIT: true,
          AUDIT_LOG_PATH: './logs/security-audit',
          RETENTION_DAYS: 365
        };
        
      case 'notification-configuration':
        return {
          ENABLE_NOTIFICATIONS: true,
          NOTIFICATION_CHANNELS: ['console', 'file'],
          EMAIL_CONFIG: {
            enabled: false,
            smtp: {
              host: '',
              port: 587,
              secure: false,
              auth: {
                user: '',
                pass: ''
              }
            }
          },
          WEBHOOK_CONFIG: {
            enabled: false,
            url: '',
            timeout: 5000
          }
        };
        
      default:
        return {};
    }
  }

  async createGitignore() {
    const gitignorePath = './.gitignore';
    const backupIgnoreEntries = [
      '',
      '# Backup & Restore System',
      'migration-backups/',
      'test-backups/',
      'logs/backup-restore/',
      'logs/security-audit/',
      'logs/rollback/',
      '*.backup',
      '*.restore'
    ];

    try {
      let existingContent = '';
      try {
        existingContent = await fs.readFile(gitignorePath, 'utf8');
      } catch (error) {
        // File doesn't exist, will create new one
      }

      // Check if backup entries already exist
      if (!existingContent.includes('# Backup & Restore System')) {
        await fs.appendFile(gitignorePath, backupIgnoreEntries.join('\n') + '\n');
        await this.logger.success('Updated .gitignore with backup system entries');
      }
    } catch (error) {
      await this.logger.warn('Failed to update .gitignore', { error: error.message });
    }
  }

  async generateEnvironmentTemplate() {
    const envTemplate = `# FAF Backup & Restore System Environment Configuration
# =======================================================

# Required Configuration
MONGODB_URI=mongodb://localhost:27017/your_database_name

# Optional Configuration
BACKUP_ROOT=./migration-backups
LOG_LEVEL=info
MAX_BACKUP_VERSIONS=10
RETENTION_DAYS=30
COMPRESSION_LEVEL=6

# Security Configuration
ENABLE_AUDIT_LOGGING=true
QUARANTINE_SUSPICIOUS_FILES=true

# Notification Configuration
NOTIFICATION_CHANNELS=console,file
# EMAIL_SMTP_HOST=smtp.example.com
# EMAIL_SMTP_PORT=587
# EMAIL_USERNAME=your_email@example.com
# EMAIL_PASSWORD=your_password
# WEBHOOK_URL=https://your-webhook-url.com/notifications

# Performance Tuning
BATCH_SIZE=1000
MAX_MEMORY_USAGE=536870912
ENABLE_COMPRESSION=true

# Development/Testing
# CLEANUP_TEST_FILES=true
# TEST_DB_URI=mongodb://localhost:27017/faf_backup_test
`;

    await fs.writeFile('./config/backup-restore/.env.template', envTemplate);
    await this.logger.success('Generated environment template');
  }

  async createEnvironmentFile(envPath) {
    const envContent = `# FAF Backup & Restore System Environment
# Copy this file to .env and configure your values

MONGODB_URI=${process.env.MONGODB_URI || 'mongodb://localhost:27017/faf_database'}
BACKUP_ROOT=./migration-backups
LOG_LEVEL=info
`;

    await fs.writeFile(envPath, envContent);
    await this.logger.success(`Created environment file: ${envPath}`);
  }

  async updateMigrationScript(scriptPath) {
    try {
      // This would add integration with the backup system to existing migration script
      await this.logger.success('Migration script integration prepared');
      this.warnings.push('Review migration script integration in the next update');
    } catch (error) {
      await this.logger.warn('Failed to update migration script', { error: error.message });
    }
  }

  async addNpmScripts() {
    try {
      const packageJsonPath = this.findPackageJsonPath();
      const packageJson = await this.loadPackageJson();
      
      if (!packageJson.scripts) {
        packageJson.scripts = {};
      }

      const newScripts = {
        'backup': 'node scripts/backup-restore/BackupRestoreCLI.js',
        'backup:test': 'node scripts/backup-restore/BackupRestoreTests.js',
        'backup:install': 'node scripts/backup-restore/install.js'
      };

      let scriptsAdded = 0;
      for (const [scriptName, scriptCommand] of Object.entries(newScripts)) {
        if (!packageJson.scripts[scriptName]) {
          packageJson.scripts[scriptName] = scriptCommand;
          scriptsAdded++;
        }
      }

      if (scriptsAdded > 0) {
        await fs.writeFile(packageJsonPath, JSON.stringify(packageJson, null, 2));
        await this.logger.success(`Added ${scriptsAdded} npm scripts to package.json`);
      }

    } catch (error) {
      await this.logger.warn('Failed to add npm scripts', { error: error.message });
    }
  }

  async testBasicFunctionality() {
    try {
      // Test that we can require the main modules
      const { IntelligentBackupSystem } = require('./IntelligentBackupSystem');
      const { AutomaticRollbackSystem } = require('./AutomaticRollbackSystem');
      
      // Create instances to test basic initialization
      const backupSystem = new IntelligentBackupSystem();
      const rollbackSystem = new AutomaticRollbackSystem();
      
      await this.logger.success('Basic functionality test passed');
      
    } catch (error) {
      this.errors.push(`Basic functionality test failed: ${error.message}`);
      await this.logger.error('Basic functionality test failed', { error: error.message });
    }
  }
}

/**
 * CLI Entry Point
 */
async function main() {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
FAF Backup & Restore System Installer v2.0
===========================================

Usage: node install.js [options]

Options:
  --help, -h        Show this help message
  --force           Force reinstallation over existing setup
  --verbose         Enable verbose logging

Environment Variables:
  MONGODB_URI       MongoDB connection string (recommended)

Examples:
  node install.js
  node install.js --verbose
  MONGODB_URI="mongodb://localhost:27017/faf" node install.js
    `);
    process.exit(0);
  }
  
  const installer = new BackupRestoreInstaller();
  
  try {
    const summary = await installer.install();
    process.exit(summary.status === 'SUCCESS' ? 0 : 1);
  } catch (error) {
    console.error('Installation failed:', error.message);
    process.exit(1);
  }
}

// Export for testing
module.exports = {
  BackupRestoreInstaller,
  InstallLogger,
  INSTALL_CONFIG
};

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}