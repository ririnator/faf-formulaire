/**
 * Production Environment Validation Script
 * Validates all required environment variables and configurations for production deployment
 */

const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const https = require('https');
const { MongoClient } = require('mongodb');

class ProductionValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.info = [];
  }

  /**
   * Main validation function
   */
  async validate() {
    console.log('🔍 Starting production environment validation...\n');

    await this.validateEnvironmentVariables();
    await this.validateDatabaseConnection();
    await this.validateSSLConfiguration();
    await this.validateEmailConfiguration();
    await this.validateCloudinaryConfiguration();
    await this.validateSecuritySettings();
    await this.validateFilePermissions();
    await this.validateDiskSpace();
    await this.validateSystemResources();

    this.printResults();
    
    if (this.errors.length > 0) {
      console.error('\n❌ Production validation failed. Please fix all errors before deploying.');
      process.exit(1);
    } else {
      console.log('\n✅ Production validation successful! Environment is ready for deployment.');
      process.exit(0);
    }
  }

  /**
   * Validate all required environment variables
   */
  validateEnvironmentVariables() {
    console.log('📋 Validating environment variables...');

    const requiredVars = [
      'NODE_ENV',
      'MONGODB_URI',
      'SESSION_SECRET',
      'LOGIN_ADMIN_USER',
      'LOGIN_ADMIN_PASS',
      'FORM_ADMIN_NAME',
      'APP_BASE_URL'
    ];

    const productionRequiredVars = [
      'HTTPS',
      'COOKIE_DOMAIN',
      'SSL_CERT_PATH',
      'SSL_KEY_PATH'
    ];

    // Check basic required variables
    requiredVars.forEach(varName => {
      if (!process.env[varName]) {
        this.errors.push(`Missing required environment variable: ${varName}`);
      }
    });

    // Check production-specific variables
    productionRequiredVars.forEach(varName => {
      if (!process.env[varName]) {
        this.warnings.push(`Missing production environment variable: ${varName}`);
      }
    });

    // Validate NODE_ENV
    if (process.env.NODE_ENV !== 'production') {
      this.errors.push('NODE_ENV must be set to "production"');
    }

    // Validate URLs
    if (process.env.APP_BASE_URL && !process.env.APP_BASE_URL.startsWith('https://')) {
      this.warnings.push('APP_BASE_URL should use HTTPS in production');
    }

    // Validate session secret strength
    if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length < 32) {
      this.errors.push('SESSION_SECRET must be at least 32 characters long');
    }

    // Validate admin password is hashed
    if (process.env.LOGIN_ADMIN_PASS && !process.env.LOGIN_ADMIN_PASS.startsWith('$2b$')) {
      this.warnings.push('LOGIN_ADMIN_PASS should be bcrypt hashed for security');
    }

    this.info.push(`Environment validation completed: ${requiredVars.length + productionRequiredVars.length} variables checked`);
  }

  /**
   * Validate MongoDB connection
   */
  async validateDatabaseConnection() {
    console.log('🗄️  Validating database connection...');

    if (!process.env.MONGODB_URI) {
      this.errors.push('MONGODB_URI is required for database connection');
      return;
    }

    try {
      const client = new MongoClient(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 5000,
        connectTimeoutMS: 5000
      });

      await client.connect();
      
      // Test database operations
      const db = client.db();
      await db.admin().ping();
      
      // Check collections exist
      const collections = await db.listCollections().toArray();
      const expectedCollections = ['responses', 'users', 'sessions'];
      
      expectedCollections.forEach(collectionName => {
        const exists = collections.some(col => col.name === collectionName);
        if (!exists) {
          this.warnings.push(`Database collection '${collectionName}' does not exist yet`);
        }
      });

      await client.close();
      this.info.push('Database connection successful');
    } catch (error) {
      this.errors.push(`Database connection failed: ${error.message}`);
    }
  }

  /**
   * Validate SSL certificate configuration
   */
  async validateSSLConfiguration() {
    console.log('🔒 Validating SSL configuration...');

    const certPath = process.env.SSL_CERT_PATH;
    const keyPath = process.env.SSL_KEY_PATH;

    if (!certPath || !keyPath) {
      this.warnings.push('SSL certificate paths not configured. Using Let\'s Encrypt or load balancer SSL?');
      return;
    }

    // Check certificate files exist
    try {
      if (!fs.existsSync(certPath)) {
        this.errors.push(`SSL certificate file not found: ${certPath}`);
      }
      if (!fs.existsSync(keyPath)) {
        this.errors.push(`SSL private key file not found: ${keyPath}`);
      }

      // Check file permissions
      if (fs.existsSync(certPath)) {
        const certStats = fs.statSync(certPath);
        if ((certStats.mode & parseInt('077', 8)) !== 0) {
          this.warnings.push('SSL certificate file has overly permissive permissions');
        }
      }

      if (fs.existsSync(keyPath)) {
        const keyStats = fs.statSync(keyPath);
        if ((keyStats.mode & parseInt('077', 8)) !== 0) {
          this.errors.push('SSL private key file has overly permissive permissions (should be 600)');
        }
      }

      this.info.push('SSL certificate files validation completed');
    } catch (error) {
      this.errors.push(`SSL configuration validation failed: ${error.message}`);
    }
  }

  /**
   * Validate email service configuration
   */
  async validateEmailConfiguration() {
    console.log('📧 Validating email configuration...');

    const hasResend = process.env.RESEND_API_KEY;
    const hasPostmark = process.env.POSTMARK_API_KEY;

    if (!hasResend && !hasPostmark) {
      this.warnings.push('No email service configured (RESEND_API_KEY or POSTMARK_API_KEY)');
    }

    // Validate email domain
    const fromAddress = process.env.EMAIL_FROM_ADDRESS;
    if (fromAddress) {
      const domain = fromAddress.split('@')[1];
      if (domain) {
        try {
          const mxRecords = await dns.resolveMx(domain);
          if (mxRecords.length === 0) {
            this.warnings.push(`No MX records found for email domain: ${domain}`);
          } else {
            this.info.push(`Email domain ${domain} has valid MX records`);
          }
        } catch (error) {
          this.warnings.push(`Could not validate email domain ${domain}: ${error.message}`);
        }
      }
    }

    // Validate email rate limits
    const rateLimit = parseInt(process.env.EMAIL_RATE_LIMIT_PER_MINUTE);
    if (rateLimit && rateLimit > 1000) {
      this.warnings.push('Email rate limit seems very high, ensure your provider supports this');
    }

    this.info.push('Email configuration validation completed');
  }

  /**
   * Validate Cloudinary configuration
   */
  validateCloudinaryConfiguration() {
    console.log('☁️  Validating Cloudinary configuration...');

    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      this.warnings.push('Cloudinary configuration incomplete (image uploads will not work)');
    } else {
      this.info.push('Cloudinary configuration appears complete');
    }
  }

  /**
   * Validate security settings
   */
  validateSecuritySettings() {
    console.log('🛡️  Validating security settings...');

    // Check if HTTPS is enabled
    if (process.env.HTTPS !== 'true') {
      this.errors.push('HTTPS must be enabled in production (HTTPS=true)');
    }

    // Check cookie domain
    if (!process.env.COOKIE_DOMAIN) {
      this.warnings.push('COOKIE_DOMAIN not set - cookies will be limited to exact domain');
    }

    // Check if maintenance mode is disabled
    if (process.env.MAINTENANCE_MODE === 'true') {
      this.warnings.push('Maintenance mode is enabled');
    }

    // Check monitoring settings
    if (process.env.ENABLE_SECURITY_MONITORING !== 'true') {
      this.warnings.push('Security monitoring is disabled');
    }

    this.info.push('Security settings validation completed');
  }

  /**
   * Validate file permissions and directories
   */
  validateFilePermissions() {
    console.log('📁 Validating file permissions...');

    const directories = [
      { path: '/var/log/faf', required: false, description: 'Log directory' },
      { path: '/var/backups/faf', required: false, description: 'Backup directory' },
      { path: process.env.BACKUP_STORAGE_PATH, required: false, description: 'Backup storage' }
    ].filter(dir => dir.path);

    directories.forEach(dir => {
      try {
        if (fs.existsSync(dir.path)) {
          const stats = fs.statSync(dir.path);
          if (!stats.isDirectory()) {
            this.errors.push(`${dir.description} exists but is not a directory: ${dir.path}`);
          } else {
            // Check write permissions
            fs.accessSync(dir.path, fs.constants.W_OK);
            this.info.push(`${dir.description} is accessible: ${dir.path}`);
          }
        } else if (dir.required) {
          this.errors.push(`Required directory does not exist: ${dir.path}`);
        } else {
          this.warnings.push(`Directory does not exist: ${dir.path}`);
        }
      } catch (error) {
        if (dir.required) {
          this.errors.push(`Cannot access required directory ${dir.path}: ${error.message}`);
        } else {
          this.warnings.push(`Cannot access directory ${dir.path}: ${error.message}`);
        }
      }
    });
  }

  /**
   * Validate disk space
   */
  validateDiskSpace() {
    console.log('💾 Validating disk space...');

    try {
      const stats = fs.statSync('.');
      // This is a basic check - in a real implementation you'd use statvfs or similar
      this.info.push('Disk space check completed (implement full disk monitoring in production)');
    } catch (error) {
      this.warnings.push(`Could not check disk space: ${error.message}`);
    }
  }

  /**
   * Validate system resources
   */
  validateSystemResources() {
    console.log('⚡ Validating system resources...');

    const totalMemory = require('os').totalmem();
    const freeMemory = require('os').freemem();
    const usedMemory = totalMemory - freeMemory;
    const memoryUsagePercent = (usedMemory / totalMemory) * 100;

    if (memoryUsagePercent > 80) {
      this.warnings.push(`High memory usage detected: ${memoryUsagePercent.toFixed(2)}%`);
    }

    const cpuCount = require('os').cpus().length;
    if (cpuCount < 2) {
      this.warnings.push('Low CPU count detected - consider upgrading for production workload');
    }

    this.info.push(`System resources: ${cpuCount} CPUs, ${(totalMemory / 1024 / 1024 / 1024).toFixed(2)}GB RAM`);
  }

  /**
   * Print validation results
   */
  printResults() {
    console.log('\n📊 VALIDATION RESULTS');
    console.log('========================\n');

    if (this.errors.length > 0) {
      console.log('❌ ERRORS (Must be fixed):');
      this.errors.forEach(error => console.log(`   • ${error}`));
      console.log('');
    }

    if (this.warnings.length > 0) {
      console.log('⚠️  WARNINGS (Should be addressed):');
      this.warnings.forEach(warning => console.log(`   • ${warning}`));
      console.log('');
    }

    if (this.info.length > 0) {
      console.log('ℹ️  INFORMATION:');
      this.info.forEach(info => console.log(`   • ${info}`));
      console.log('');
    }

    console.log(`Summary: ${this.errors.length} errors, ${this.warnings.length} warnings, ${this.info.length} info items`);
  }
}

// Run validation if called directly
if (require.main === module) {
  const validator = new ProductionValidator();
  validator.validate().catch(error => {
    console.error('❌ Validation script failed:', error);
    process.exit(1);
  });
}

module.exports = ProductionValidator;