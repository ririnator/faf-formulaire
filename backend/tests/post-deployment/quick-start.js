#!/usr/bin/env node

/**
 * Post-Deployment Quick Start Helper
 * 
 * Interactive setup and execution helper for post-deployment tests.
 */

const readline = require('readline');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class QuickStartHelper {
  constructor() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    this.config = {};
  }

  async start() {
    console.log('🚀 Form-a-Friend Post-Deployment Test Quick Start');
    console.log('================================================\n');
    
    try {
      await this.checkPrerequisites();
      await this.setupConfiguration();
      await this.runTests();
    } catch (error) {
      console.error('❌ Quick start failed:', error.message);
      process.exit(1);
    } finally {
      this.rl.close();
    }
  }

  async checkPrerequisites() {
    console.log('🔍 Checking Prerequisites...\n');
    
    // Check Node.js version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
    
    if (majorVersion < 16) {
      throw new Error(`Node.js v16+ required. Current version: ${nodeVersion}`);
    }
    
    console.log(`✅ Node.js ${nodeVersion} (compatible)`);
    
    // Check if in correct directory
    const packageJsonPath = path.join(process.cwd(), 'package.json');
    if (!fs.existsSync(packageJsonPath)) {
      throw new Error('package.json not found. Please run from the backend directory');
    }
    
    console.log('✅ Running from correct directory');
    
    // Check if dependencies are installed
    const nodeModulesPath = path.join(process.cwd(), 'node_modules');
    if (!fs.existsSync(nodeModulesPath)) {
      console.log('📦 Installing dependencies...');
      try {
        execSync('npm install', { stdio: 'inherit' });
        console.log('✅ Dependencies installed');
      } catch (error) {
        throw new Error('Failed to install dependencies');
      }
    } else {
      console.log('✅ Dependencies are installed');
    }
    
    console.log('\n✅ All prerequisites met!\n');
  }

  async setupConfiguration() {
    console.log('⚙️  Configuration Setup...\n');
    
    const envPath = path.join(__dirname, '.env.production');
    const envExamplePath = path.join(__dirname, '.env.example');
    
    if (fs.existsSync(envPath)) {
      const useExisting = await this.askQuestion('Existing configuration found. Use it? (y/n): ');
      if (useExisting.toLowerCase() === 'y') {
        console.log('✅ Using existing configuration\n');
        return;
      }
    }
    
    console.log('Setting up new configuration...\n');
    
    // Ask for essential configuration
    this.config.APP_BASE_URL = await this.askQuestion('Production URL (e.g., https://faf.example.com): ');
    this.config.MONGODB_URI = await this.askQuestion('MongoDB URI: ');
    this.config.SESSION_SECRET = await this.askQuestion('Session secret (leave blank for auto-generated): ');
    this.config.LOGIN_ADMIN_USER = await this.askQuestion('Admin username: ');
    this.config.LOGIN_ADMIN_PASS = await this.askQuestion('Admin password: ');
    this.config.FORM_ADMIN_NAME = await this.askQuestion('Admin form name: ');
    
    // Generate session secret if not provided
    if (!this.config.SESSION_SECRET) {
      this.config.SESSION_SECRET = require('crypto').randomBytes(32).toString('hex');
      console.log('🔐 Generated secure session secret');
    }
    
    // Optional services
    const configureOptional = await this.askQuestion('\nConfigure optional services (Cloudinary, Email)? (y/n): ');
    if (configureOptional.toLowerCase() === 'y') {
      this.config.CLOUDINARY_CLOUD_NAME = await this.askQuestion('Cloudinary cloud name (optional): ');
      this.config.CLOUDINARY_API_KEY = await this.askQuestion('Cloudinary API key (optional): ');
      this.config.CLOUDINARY_API_SECRET = await this.askQuestion('Cloudinary API secret (optional): ');
      this.config.EMAIL_SERVICE_API_KEY = await this.askQuestion('Email service API key (optional): ');
    }
    
    // Save configuration
    await this.saveConfiguration(envPath);
    console.log('✅ Configuration saved\n');
  }

  async saveConfiguration(envPath) {
    let envContent = '# Post-Deployment Test Configuration\n';
    envContent += `# Generated on ${new Date().toISOString()}\n\n`;
    
    envContent += '# Required Configuration\n';
    envContent += `NODE_ENV=production\n`;
    envContent += `APP_BASE_URL=${this.config.APP_BASE_URL}\n`;
    envContent += `MONGODB_URI=${this.config.MONGODB_URI}\n`;
    envContent += `SESSION_SECRET=${this.config.SESSION_SECRET}\n`;
    envContent += `LOGIN_ADMIN_USER=${this.config.LOGIN_ADMIN_USER}\n`;
    envContent += `LOGIN_ADMIN_PASS=${this.config.LOGIN_ADMIN_PASS}\n`;
    envContent += `FORM_ADMIN_NAME=${this.config.FORM_ADMIN_NAME}\n\n`;
    
    if (this.config.CLOUDINARY_CLOUD_NAME) {
      envContent += '# Cloudinary Configuration\n';
      envContent += `CLOUDINARY_CLOUD_NAME=${this.config.CLOUDINARY_CLOUD_NAME}\n`;
      envContent += `CLOUDINARY_API_KEY=${this.config.CLOUDINARY_API_KEY || ''}\n`;
      envContent += `CLOUDINARY_API_SECRET=${this.config.CLOUDINARY_API_SECRET || ''}\n\n`;
    }
    
    if (this.config.EMAIL_SERVICE_API_KEY) {
      envContent += '# Email Service Configuration\n';
      envContent += `EMAIL_SERVICE_API_KEY=${this.config.EMAIL_SERVICE_API_KEY}\n\n`;
    }
    
    envContent += '# Performance Thresholds\n';
    envContent += 'MAX_RESPONSE_TIME=2000\n';
    envContent += 'MAX_MEMORY_USAGE=512\n';
    envContent += 'MAX_DB_CONNECTIONS=100\n';
    envContent += 'MAX_CPU_USAGE=80\n\n';
    
    envContent += '# Test Configuration\n';
    envContent += 'POST_DEPLOYMENT_VERBOSE=false\n';
    envContent += 'POST_DEPLOYMENT_TIMEOUT=30000\n';
    
    fs.writeFileSync(envPath, envContent);
  }

  async runTests() {
    console.log('🧪 Test Execution...\n');
    
    // Validate configuration first
    console.log('Validating configuration...');
    try {
      execSync('node validate-config.js', { 
        stdio: 'inherit',
        cwd: __dirname 
      });
    } catch (error) {
      throw new Error('Configuration validation failed. Please fix the errors and try again.');
    }
    
    // Ask which tests to run
    console.log('\nTest Options:');
    console.log('1. Run all tests (recommended)');
    console.log('2. Run critical tests only (functionality, performance, security)');
    console.log('3. Run specific test suite');
    console.log('4. Validate configuration only');
    
    const choice = await this.askQuestion('\nChoose option (1-4): ');
    
    let command;
    
    switch (choice) {
      case '1':
        command = 'npm run test:post-deployment:verbose';
        break;
      case '2':
        command = 'npm run test:post-deployment:critical';
        break;
      case '3':
        const suite = await this.askTestSuite();
        command = `npm run test:post-deployment:${suite}`;
        break;
      case '4':
        console.log('✅ Configuration validation completed');
        return;
      default:
        throw new Error('Invalid choice');
    }
    
    console.log(`\n🚀 Running: ${command}\n`);
    console.log('This may take several minutes...\n');
    
    try {
      execSync(command, { 
        stdio: 'inherit',
        cwd: path.join(__dirname, '../..'),
        env: {
          ...process.env,
          NODE_ENV: 'production'
        }
      });
      
      console.log('\n🎉 Post-deployment tests completed!');
      console.log('📄 Check the reports in backend/coverage/post-deployment/');
      
    } catch (error) {
      console.log('\n💥 Tests failed or had issues');
      console.log('📄 Check the detailed reports for more information');
      throw new Error('Test execution failed');
    }
  }

  async askTestSuite() {
    console.log('\nAvailable test suites:');
    console.log('  functionality - Core application features');
    console.log('  performance   - Load and response time testing');
    console.log('  security      - Security validation');
    console.log('  integration   - External service integration');
    console.log('  regression    - Backward compatibility');
    console.log('  monitoring    - Health checks and monitoring');
    
    const suite = await this.askQuestion('\nEnter test suite name: ');
    
    const validSuites = ['functionality', 'performance', 'security', 'integration', 'regression', 'monitoring'];
    if (!validSuites.includes(suite.toLowerCase())) {
      throw new Error(`Invalid test suite. Choose from: ${validSuites.join(', ')}`);
    }
    
    return suite.toLowerCase();
  }

  askQuestion(question) {
    return new Promise((resolve) => {
      this.rl.question(question, (answer) => {
        resolve(answer.trim());
      });
    });
  }
}

// CLI Interface
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: node quick-start.js

Interactive setup and execution helper for post-deployment tests.

This script will:
1. Check prerequisites (Node.js version, dependencies)
2. Help you configure environment variables
3. Validate the configuration
4. Run the appropriate tests

Options:
  --help, -h    Show this help message

Examples:
  node quick-start.js
    `);
    process.exit(0);
  }

  const helper = new QuickStartHelper();
  helper.start().catch(error => {
    console.error('\n💥 Quick start failed:', error.message);
    process.exit(1);
  });
}

module.exports = QuickStartHelper;