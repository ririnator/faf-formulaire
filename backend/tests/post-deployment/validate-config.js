#!/usr/bin/env node

/**
 * Post-Deployment Configuration Validator
 * 
 * Validates environment configuration before running post-deployment tests.
 */

const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env.production') });

class ConfigValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.info = [];
  }

  validate() {
    console.log('🔍 Validating Post-Deployment Configuration');
    console.log('==========================================\n');

    this.validateRequiredEnvVars();
    this.validateUrls();
    this.validateSecrets();
    this.validateOptionalServices();
    this.validateThresholds();
    
    this.displayResults();
    
    return this.errors.length === 0;
  }

  validateRequiredEnvVars() {
    console.log('📋 Checking Required Environment Variables...');
    
    const requiredVars = [
      { name: 'APP_BASE_URL', description: 'Application base URL' },
      { name: 'MONGODB_URI', description: 'MongoDB connection string' },
      { name: 'SESSION_SECRET', description: 'Session encryption secret' },
      { name: 'LOGIN_ADMIN_USER', description: 'Admin username' },
      { name: 'LOGIN_ADMIN_PASS', description: 'Admin password' },
      { name: 'FORM_ADMIN_NAME', description: 'Admin form name' }
    ];

    requiredVars.forEach(varInfo => {
      const value = process.env[varInfo.name];
      
      if (!value) {
        this.errors.push(`Missing required environment variable: ${varInfo.name} (${varInfo.description})`);
      } else {
        this.info.push(`✅ ${varInfo.name}: configured`);
      }
    });

    console.log(`   Required variables checked: ${requiredVars.length}`);
    console.log(`   Missing: ${this.errors.length}\n`);
  }

  validateUrls() {
    console.log('🌐 Validating URLs...');
    
    const urls = [
      { name: 'APP_BASE_URL', required: true },
      { name: 'FRONTEND_URL', required: false }
    ];

    urls.forEach(urlInfo => {
      const url = process.env[urlInfo.name];
      
      if (url) {
        try {
          const urlObj = new URL(url);
          
          // Check protocol
          if (!['http:', 'https:'].includes(urlObj.protocol)) {
            this.errors.push(`Invalid protocol for ${urlInfo.name}: ${urlObj.protocol} (should be http: or https:)`);
          } else if (urlObj.protocol === 'http:' && process.env.NODE_ENV === 'production') {
            this.warnings.push(`Using HTTP for ${urlInfo.name} in production is not recommended`);
          }
          
          // Check hostname
          if (!urlObj.hostname || urlObj.hostname === 'localhost') {
            if (process.env.NODE_ENV === 'production') {
              this.warnings.push(`Using localhost for ${urlInfo.name} in production`);
            }
          }
          
          this.info.push(`✅ ${urlInfo.name}: ${url} (valid)`);
          
        } catch (error) {
          this.errors.push(`Invalid URL format for ${urlInfo.name}: ${url}`);
        }
      } else if (urlInfo.required) {
        this.errors.push(`Missing required URL: ${urlInfo.name}`);
      }
    });

    console.log(`   URLs validated: ${urls.length}\n`);
  }

  validateSecrets() {
    console.log('🔐 Validating Secrets and Security...');
    
    // Session secret validation
    const sessionSecret = process.env.SESSION_SECRET;
    if (sessionSecret) {
      if (sessionSecret.length < 32) {
        this.warnings.push('SESSION_SECRET should be at least 32 characters long');
      }
      
      if (sessionSecret === 'your-secret-here' || sessionSecret.includes('example')) {
        this.errors.push('SESSION_SECRET appears to be a placeholder value');
      }
      
      this.info.push(`✅ SESSION_SECRET: ${sessionSecret.length} characters`);
    }

    // Admin credentials validation
    const adminUser = process.env.LOGIN_ADMIN_USER;
    const adminPass = process.env.LOGIN_ADMIN_PASS;
    
    if (adminUser && adminUser.length < 3) {
      this.warnings.push('LOGIN_ADMIN_USER should be at least 3 characters long');
    }
    
    if (adminPass) {
      if (adminPass.length < 8) {
        this.warnings.push('LOGIN_ADMIN_PASS should be at least 8 characters long');
      }
      
      if (adminPass === 'admin' || adminPass === 'password' || adminPass.includes('123')) {
        this.warnings.push('LOGIN_ADMIN_PASS appears to be weak');
      }
      
      this.info.push(`✅ LOGIN_ADMIN_PASS: ${adminPass.length} characters`);
    }

    console.log(`   Security validation completed\n`);
  }

  validateOptionalServices() {
    console.log('🔌 Checking Optional Services...');
    
    const optionalServices = [
      {
        name: 'Cloudinary',
        vars: ['CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'],
        description: 'Image upload service'
      },
      {
        name: 'Email Service',
        vars: ['EMAIL_SERVICE_API_KEY', 'EMAIL_FROM_ADDRESS'],
        description: 'Email notification service'
      }
    ];

    optionalServices.forEach(service => {
      const configuredVars = service.vars.filter(varName => process.env[varName]);
      
      if (configuredVars.length === 0) {
        this.info.push(`ℹ️  ${service.name}: Not configured (${service.description})`);
      } else if (configuredVars.length === service.vars.length) {
        this.info.push(`✅ ${service.name}: Fully configured`);
      } else {
        this.warnings.push(`${service.name}: Partially configured (${configuredVars.length}/${service.vars.length} variables)`);
        this.warnings.push(`   Missing: ${service.vars.filter(v => !process.env[v]).join(', ')}`);
      }
    });

    console.log(`   Optional services checked: ${optionalServices.length}\n`);
  }

  validateThresholds() {
    console.log('⚡ Validating Performance Thresholds...');
    
    const thresholds = [
      { name: 'MAX_RESPONSE_TIME', default: 2000, min: 500, max: 10000, unit: 'ms' },
      { name: 'MAX_MEMORY_USAGE', default: 512, min: 128, max: 4096, unit: 'MB' },
      { name: 'MAX_DB_CONNECTIONS', default: 100, min: 10, max: 1000, unit: 'connections' },
      { name: 'MAX_CPU_USAGE', default: 80, min: 50, max: 95, unit: '%' }
    ];

    thresholds.forEach(threshold => {
      const value = parseInt(process.env[threshold.name]) || threshold.default;
      
      if (value < threshold.min) {
        this.warnings.push(`${threshold.name} (${value}${threshold.unit}) is below recommended minimum (${threshold.min}${threshold.unit})`);
      } else if (value > threshold.max) {
        this.warnings.push(`${threshold.name} (${value}${threshold.unit}) is above recommended maximum (${threshold.max}${threshold.unit})`);
      } else {
        this.info.push(`✅ ${threshold.name}: ${value}${threshold.unit}`);
      }
    });

    console.log(`   Thresholds validated: ${thresholds.length}\n`);
  }

  displayResults() {
    console.log('📊 Configuration Validation Results');
    console.log('==================================');
    
    // Display errors
    if (this.errors.length > 0) {
      console.log(`\n❌ Errors (${this.errors.length}):`);
      this.errors.forEach(error => console.log(`   ${error}`));
    }
    
    // Display warnings
    if (this.warnings.length > 0) {
      console.log(`\n⚠️  Warnings (${this.warnings.length}):`);
      this.warnings.forEach(warning => console.log(`   ${warning}`));
    }
    
    // Display info
    if (this.info.length > 0 && process.env.VERBOSE) {
      console.log(`\nℹ️  Information (${this.info.length}):`);
      this.info.forEach(info => console.log(`   ${info}`));
    }
    
    // Overall status
    console.log('\n📋 Overall Status:');
    if (this.errors.length === 0) {
      if (this.warnings.length === 0) {
        console.log('✅ Configuration is valid and ready for post-deployment testing');
      } else {
        console.log(`⚠️  Configuration is valid but has ${this.warnings.length} warnings`);
        console.log('   Post-deployment testing can proceed, but review warnings');
      }
    } else {
      console.log(`❌ Configuration has ${this.errors.length} errors that must be fixed`);
      console.log('   Post-deployment testing cannot proceed');
    }
    
    console.log('\n==================================\n');
  }

  generateConfigTemplate() {
    console.log('📄 Generating configuration template...');
    
    const template = `# Post-Deployment Test Configuration
# Generated on ${new Date().toISOString()}

# Required Variables
APP_BASE_URL=${process.env.APP_BASE_URL || 'https://your-production-domain.com'}
MONGODB_URI=${process.env.MONGODB_URI || 'mongodb://username:password@host:port/database'}
SESSION_SECRET=${process.env.SESSION_SECRET || 'generate-a-secure-secret-here'}
LOGIN_ADMIN_USER=${process.env.LOGIN_ADMIN_USER || 'admin-username'}
LOGIN_ADMIN_PASS=${process.env.LOGIN_ADMIN_PASS || 'secure-admin-password'}
FORM_ADMIN_NAME=${process.env.FORM_ADMIN_NAME || 'admin-name'}

# Optional Variables
FRONTEND_URL=${process.env.FRONTEND_URL || ''}
CLOUDINARY_CLOUD_NAME=${process.env.CLOUDINARY_CLOUD_NAME || ''}
CLOUDINARY_API_KEY=${process.env.CLOUDINARY_API_KEY || ''}
CLOUDINARY_API_SECRET=${process.env.CLOUDINARY_API_SECRET || ''}

# Performance Thresholds
MAX_RESPONSE_TIME=${process.env.MAX_RESPONSE_TIME || '2000'}
MAX_MEMORY_USAGE=${process.env.MAX_MEMORY_USAGE || '512'}
MAX_DB_CONNECTIONS=${process.env.MAX_DB_CONNECTIONS || '100'}
MAX_CPU_USAGE=${process.env.MAX_CPU_USAGE || '80'}

# Test Configuration
POST_DEPLOYMENT_VERBOSE=${process.env.POST_DEPLOYMENT_VERBOSE || 'false'}
POST_DEPLOYMENT_TIMEOUT=${process.env.POST_DEPLOYMENT_TIMEOUT || '30000'}
`;

    const templatePath = path.join(__dirname, '.env.generated');
    fs.writeFileSync(templatePath, template);
    
    console.log(`✅ Configuration template saved to: ${templatePath}`);
    console.log('   Review and customize as needed, then copy to .env.production\n');
  }
}

// CLI Interface
if (require.main === module) {
  const validator = new ConfigValidator();
  
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: node validate-config.js [options]

Options:
  --help, -h          Show help information
  --verbose, -v       Show detailed information
  --generate, -g      Generate configuration template
  --template, -t      Generate configuration template

Examples:
  node validate-config.js
  node validate-config.js --verbose
  node validate-config.js --generate
    `);
    process.exit(0);
  }

  if (args.includes('--verbose') || args.includes('-v')) {
    process.env.VERBOSE = 'true';
  }

  if (args.includes('--generate') || args.includes('-g') || args.includes('--template') || args.includes('-t')) {
    validator.generateConfigTemplate();
    process.exit(0);
  }

  const isValid = validator.validate();
  
  if (isValid) {
    console.log('🎉 Configuration validation passed!');
    console.log('   Ready to run post-deployment tests');
    process.exit(0);
  } else {
    console.log('💥 Configuration validation failed!');
    console.log('   Fix the errors above before running post-deployment tests');
    process.exit(1);
  }
}

module.exports = ConfigValidator;