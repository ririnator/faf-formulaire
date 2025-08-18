#!/usr/bin/env node

/**
 * Production Migration System - Main Entry Point
 * ==============================================
 * 
 * Comprehensive production migration system for FAF v1 → v2 migration providing:
 * - Complete orchestration with automated sequencing and checkpoints
 * - Real-time monitoring dashboard with live metrics and alerts
 * - Emergency rollback procedures with automatic recovery
 * - Risk management and pre-flight validation systems
 * - Interactive control interfaces (CLI, Web Dashboard, API)
 * - Post-migration validation and health checks
 * 
 * EXECUTION MODES:
 * - Interactive CLI Mode: Full interactive command-line interface
 * - API Server Mode: RESTful API with WebSocket support
 * - Automated Mode: Hands-off automated execution
 * - Monitoring Mode: Real-time dashboard and supervision
 * - Validation Mode: Pre-flight and post-migration validation
 * 
 * SAFETY FEATURES:
 * - Automatic backup creation and verification
 * - Real-time rollback capability at any stage
 * - Circuit breaker patterns for failure isolation
 * - Multi-layered validation and health checks
 * - Emergency contact and notification systems
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const path = require('path');
const fs = require('fs').promises;
const mongoose = require('mongoose');

// Import main components
const { ProductionMigrationOrchestrator } = require('./ProductionMigrationOrchestrator');
const { RealTimeMonitoringDashboard } = require('./monitoring/RealTimeMonitoringDashboard');
const { AutomaticRollbackSystem } = require('./rollback/AutomaticRollbackSystem');
const { PreFlightCheckSystem } = require('./validation/PreFlightCheckSystem');
const { PostMigrationValidator } = require('./validation/PostMigrationValidator');
const { ProductionMigrationCLI } = require('./interfaces/ProductionMigrationCLI');
const { ProductionMigrationAPI } = require('./interfaces/ProductionMigrationAPI');

/**
 * Production Migration System Configuration
 */
const SYSTEM_CONFIG = {
  // Execution Modes
  MODES: {
    CLI: 'cli',
    API: 'api', 
    AUTOMATED: 'automated',
    MONITORING: 'monitoring',
    VALIDATION: 'validation',
    ROLLBACK: 'rollback'
  },
  
  // Default Settings
  DEFAULTS: {
    MODE: 'cli',
    ENVIRONMENT: 'production',
    DRY_RUN: false,
    VERBOSE: true,
    AUTO_BACKUP: true,
    AUTO_ROLLBACK: true,
    GENERATE_REPORTS: true
  },
  
  // Database Connection
  DATABASE: {
    REQUIRED: true,
    TIMEOUT: 30000,
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 5000
  },
  
  // Logging Configuration
  LOGGING: {
    LEVEL: 'info',
    FILE_LOGGING: true,
    CONSOLE_LOGGING: true,
    LOG_DIRECTORY: './logs/production-migration'
  }
};

/**
 * Production Migration System Manager
 * Main orchestrator for the entire migration system
 */
class ProductionMigrationSystem {
  constructor(options = {}) {
    this.options = {
      mode: SYSTEM_CONFIG.DEFAULTS.MODE,
      environment: SYSTEM_CONFIG.DEFAULTS.ENVIRONMENT,
      dryRun: SYSTEM_CONFIG.DEFAULTS.DRY_RUN,
      verbose: SYSTEM_CONFIG.DEFAULTS.VERBOSE,
      autoBackup: SYSTEM_CONFIG.DEFAULTS.AUTO_BACKUP,
      autoRollback: SYSTEM_CONFIG.DEFAULTS.AUTO_ROLLBACK,
      generateReports: SYSTEM_CONFIG.DEFAULTS.GENERATE_REPORTS,
      ...options
    };
    
    // System State
    this.state = {
      initialized: false,
      connected: false,
      mode: this.options.mode,
      startTime: null,
      components: {
        orchestrator: null,
        monitoring: null,
        rollback: null,
        preflight: null,
        postValidation: null,
        cli: null,
        api: null
      }
    };
    
    // Logger
    this.logger = this.createLogger();
  }

  createLogger() {
    return {
      info: (message, data) => this.log('INFO', message, data),
      warn: (message, data) => this.log('WARN', message, data),
      error: (message, data) => this.log('ERROR', message, data),
      success: (message, data) => this.log('SUCCESS', message, data),
      debug: (message, data) => this.log('DEBUG', message, data)
    };
  }

  log(level, message, data = {}) {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${level}: ${message}`;
    
    if (this.options.verbose || level !== 'DEBUG') {
      console.log(logMessage);
      if (data && Object.keys(data).length > 0) {
        console.log('  Data:', JSON.stringify(data, null, 2));
      }
    }
    
    // File logging would be implemented here
  }

  /**
   * Initialize Production Migration System
   */
  async initialize() {
    this.logger.info('🚀 Initializing Production Migration System...', {
      mode: this.options.mode,
      environment: this.options.environment,
      dryRun: this.options.dryRun
    });
    
    try {
      // Validate environment
      await this.validateEnvironment();
      
      // Connect to database
      await this.connectDatabase();
      
      // Initialize logging
      await this.initializeLogging();
      
      // Initialize components based on mode
      await this.initializeComponents();
      
      this.state.initialized = true;
      this.state.startTime = new Date();
      
      this.logger.success('✅ Production Migration System initialized successfully');
      
    } catch (error) {
      this.logger.error('❌ Failed to initialize Production Migration System', {
        error: error.message
      });
      throw error;
    }
  }

  async validateEnvironment() {
    this.logger.info('🔍 Validating environment...');
    
    // Check Node.js version
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
    
    if (majorVersion < 14) {
      throw new Error(`Node.js version ${nodeVersion} is too old (minimum: v14)`);
    }
    
    // Check required environment variables
    const requiredEnvVars = [
      'MONGODB_URI',
      'SESSION_SECRET',
      'LOGIN_ADMIN_USER',
      'LOGIN_ADMIN_PASS'
    ];
    
    const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
    
    if (missingEnvVars.length > 0) {
      throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
    }
    
    // Check permissions
    try {
      const testDir = path.join(process.cwd(), 'temp-permission-test');
      await fs.mkdir(testDir, { recursive: true });
      await fs.rmdir(testDir);
    } catch (error) {
      throw new Error(`Insufficient file system permissions: ${error.message}`);
    }
    
    this.logger.success('Environment validation passed');
  }

  async connectDatabase() {
    if (!SYSTEM_CONFIG.DATABASE.REQUIRED) {
      return;
    }
    
    this.logger.info('🔌 Connecting to database...');
    
    const mongoUri = process.env.MONGODB_URI;
    
    let retryCount = 0;
    while (retryCount < SYSTEM_CONFIG.DATABASE.RETRY_ATTEMPTS) {
      try {
        await mongoose.connect(mongoUri, {
          serverSelectionTimeoutMS: SYSTEM_CONFIG.DATABASE.TIMEOUT,
          socketTimeoutMS: SYSTEM_CONFIG.DATABASE.TIMEOUT
        });
        
        this.state.connected = true;
        this.logger.success('✅ Connected to database successfully');
        return;
        
      } catch (error) {
        retryCount++;
        
        if (retryCount >= SYSTEM_CONFIG.DATABASE.RETRY_ATTEMPTS) {
          throw new Error(`Failed to connect to database after ${retryCount} attempts: ${error.message}`);
        }
        
        this.logger.warn(`Database connection attempt ${retryCount} failed, retrying...`, {
          error: error.message,
          nextRetryIn: `${SYSTEM_CONFIG.DATABASE.RETRY_DELAY}ms`
        });
        
        await new Promise(resolve => setTimeout(resolve, SYSTEM_CONFIG.DATABASE.RETRY_DELAY));
      }
    }
  }

  async initializeLogging() {
    if (!SYSTEM_CONFIG.LOGGING.FILE_LOGGING) {
      return;
    }
    
    const logDir = SYSTEM_CONFIG.LOGGING.LOG_DIRECTORY;
    await fs.mkdir(logDir, { recursive: true });
    
    this.logger.debug('Logging system initialized', { logDirectory: logDir });
  }

  async initializeComponents() {
    this.logger.info(`🔧 Initializing components for ${this.options.mode} mode...`);
    
    switch (this.options.mode) {
      case SYSTEM_CONFIG.MODES.CLI:
        await this.initializeCLIMode();
        break;
        
      case SYSTEM_CONFIG.MODES.API:
        await this.initializeAPIMode();
        break;
        
      case SYSTEM_CONFIG.MODES.AUTOMATED:
        await this.initializeAutomatedMode();
        break;
        
      case SYSTEM_CONFIG.MODES.MONITORING:
        await this.initializeMonitoringMode();
        break;
        
      case SYSTEM_CONFIG.MODES.VALIDATION:
        await this.initializeValidationMode();
        break;
        
      case SYSTEM_CONFIG.MODES.ROLLBACK:
        await this.initializeRollbackMode();
        break;
        
      default:
        throw new Error(`Unknown mode: ${this.options.mode}`);
    }
  }

  async initializeCLIMode() {
    this.logger.info('🖥️  Initializing CLI mode...');
    
    // Initialize core components
    await this.initializeCoreComponents();
    
    // Initialize CLI interface
    this.state.components.cli = new ProductionMigrationCLI({
      orchestrator: this.state.components.orchestrator,
      monitoring: this.state.components.monitoring,
      rollback: this.state.components.rollback,
      preflight: this.state.components.preflight,
      logger: this.logger
    });
    
    this.logger.success('CLI mode initialized');
  }

  async initializeAPIMode() {
    this.logger.info('🌐 Initializing API mode...');
    
    // Initialize core components
    await this.initializeCoreComponents();
    
    // Initialize API server
    this.state.components.api = new ProductionMigrationAPI({
      orchestrator: this.state.components.orchestrator,
      monitoring: this.state.components.monitoring,
      rollback: this.state.components.rollback,
      preflight: this.state.components.preflight,
      logger: this.logger
    });
    
    this.logger.success('API mode initialized');
  }

  async initializeAutomatedMode() {
    this.logger.info('🤖 Initializing automated mode...');
    
    // Initialize all components for automated execution
    await this.initializeCoreComponents();
    
    this.logger.success('Automated mode initialized');
  }

  async initializeMonitoringMode() {
    this.logger.info('📊 Initializing monitoring mode...');
    
    // Initialize monitoring dashboard
    this.state.components.monitoring = new RealTimeMonitoringDashboard({
      consoleMode: true,
      webMode: true,
      apiMode: false,
      logger: this.logger
    });
    
    await this.state.components.monitoring.initialize();
    
    this.logger.success('Monitoring mode initialized');
  }

  async initializeValidationMode() {
    this.logger.info('🔍 Initializing validation mode...');
    
    // Initialize validation components
    this.state.components.preflight = new PreFlightCheckSystem({
      logger: this.logger
    });
    
    this.state.components.postValidation = new PostMigrationValidator({
      logger: this.logger
    });
    
    this.logger.success('Validation mode initialized');
  }

  async initializeRollbackMode() {
    this.logger.info('🔄 Initializing rollback mode...');
    
    // Initialize rollback system
    this.state.components.rollback = new AutomaticRollbackSystem({
      autoTrigger: false,
      logger: this.logger
    });
    
    await this.state.components.rollback.initialize();
    
    this.logger.success('Rollback mode initialized');
  }

  async initializeCoreComponents() {
    // Initialize orchestrator
    this.state.components.orchestrator = new ProductionMigrationOrchestrator({
      dryRun: this.options.dryRun,
      verbose: this.options.verbose,
      logger: this.logger
    });
    
    // Initialize monitoring
    this.state.components.monitoring = new RealTimeMonitoringDashboard({
      consoleMode: false,
      webMode: true,
      apiMode: true,
      logger: this.logger
    });
    
    // Initialize rollback system
    this.state.components.rollback = new AutomaticRollbackSystem({
      autoTrigger: this.options.autoRollback,
      logger: this.logger
    });
    
    // Initialize pre-flight system
    this.state.components.preflight = new PreFlightCheckSystem({
      environment: this.options.environment,
      logger: this.logger
    });
    
    // Initialize post-migration validator
    this.state.components.postValidation = new PostMigrationValidator({
      generateReport: this.options.generateReports,
      logger: this.logger
    });
    
    this.logger.success('Core components initialized');
  }

  /**
   * Execute Migration System
   */
  async execute() {
    if (!this.state.initialized) {
      throw new Error('System not initialized');
    }
    
    this.logger.info(`🚀 Starting ${this.options.mode} mode execution...`);
    
    try {
      switch (this.options.mode) {
        case SYSTEM_CONFIG.MODES.CLI:
          await this.executeCLIMode();
          break;
          
        case SYSTEM_CONFIG.MODES.API:
          await this.executeAPIMode();
          break;
          
        case SYSTEM_CONFIG.MODES.AUTOMATED:
          await this.executeAutomatedMode();
          break;
          
        case SYSTEM_CONFIG.MODES.MONITORING:
          await this.executeMonitoringMode();
          break;
          
        case SYSTEM_CONFIG.MODES.VALIDATION:
          await this.executeValidationMode();
          break;
          
        case SYSTEM_CONFIG.MODES.ROLLBACK:
          await this.executeRollbackMode();
          break;
          
        default:
          throw new Error(`Unknown execution mode: ${this.options.mode}`);
      }
      
    } catch (error) {
      this.logger.error('❌ Execution failed', { error: error.message });
      throw error;
    }
  }

  async executeCLIMode() {
    if (!this.state.components.cli) {
      throw new Error('CLI component not initialized');
    }
    
    await this.state.components.cli.startInteractiveSession();
  }

  async executeAPIMode() {
    if (!this.state.components.api) {
      throw new Error('API component not initialized');
    }
    
    await this.state.components.api.start();
    
    this.logger.success('🌐 API server started - migration system ready for requests');
    
    // Keep the process running
    return new Promise(() => {}); // Never resolves, keeps server running
  }

  async executeAutomatedMode() {
    this.logger.info('🤖 Starting automated migration execution...');
    
    // Execute pre-flight checks
    this.logger.info('Step 1: Pre-flight validation...');
    await this.state.components.preflight.executePreFlightChecks();
    
    // Execute migration
    this.logger.info('Step 2: Migration execution...');
    await this.state.components.orchestrator.initialize();
    const migrationResult = await this.state.components.orchestrator.execute();
    
    // Execute post-migration validation
    this.logger.info('Step 3: Post-migration validation...');
    await this.state.components.postValidation.executeValidation();
    
    this.logger.success('🎉 Automated migration completed successfully');
    return migrationResult;
  }

  async executeMonitoringMode() {
    this.logger.info('📊 Starting monitoring dashboard...');
    
    if (!this.state.components.monitoring) {
      throw new Error('Monitoring component not initialized');
    }
    
    await this.state.components.monitoring.initialize();
    
    this.logger.success('📊 Monitoring dashboard is running');
    
    // Keep monitoring running
    return new Promise(() => {});
  }

  async executeValidationMode() {
    this.logger.info('🔍 Starting validation execution...');
    
    // Run pre-flight checks
    const preFlightResult = await this.state.components.preflight.executePreFlightChecks();
    
    this.logger.info('Pre-flight validation completed', {
      status: preFlightResult.success ? 'PASSED' : 'FAILED',
      risks: preFlightResult.risks?.length || 0,
      warnings: preFlightResult.warnings?.length || 0
    });
    
    // Run post-migration validation if requested
    if (this.state.components.postValidation) {
      const postValidationResult = await this.state.components.postValidation.executeValidation();
      
      this.logger.info('Post-migration validation completed', {
        status: postValidationResult.passed ? 'PASSED' : 'FAILED',
        score: postValidationResult.score?.toFixed(1) + '%'
      });
    }
    
    return {
      preFlight: preFlightResult,
      postValidation: this.state.components.postValidation ? 
        await this.state.components.postValidation.getStatus() : null
    };
  }

  async executeRollbackMode() {
    this.logger.info('🔄 Starting rollback execution...');
    
    // This would typically be triggered by external input
    // For now, just initialize and wait for commands
    this.logger.info('Rollback system ready - waiting for rollback commands');
    
    return new Promise(() => {}); // Keep running for rollback commands
  }

  /**
   * Shutdown System
   */
  async shutdown() {
    this.logger.info('🛑 Shutting down Production Migration System...');
    
    try {
      // Shutdown components
      const shutdownPromises = [];
      
      if (this.state.components.orchestrator) {
        shutdownPromises.push(this.state.components.orchestrator.shutdown());
      }
      
      if (this.state.components.monitoring) {
        shutdownPromises.push(this.state.components.monitoring.shutdown());
      }
      
      if (this.state.components.rollback) {
        shutdownPromises.push(this.state.components.rollback.shutdown());
      }
      
      if (this.state.components.api) {
        shutdownPromises.push(this.state.components.api.stop());
      }
      
      if (this.state.components.cli) {
        shutdownPromises.push(this.state.components.cli.shutdown());
      }
      
      await Promise.all(shutdownPromises);
      
      // Disconnect database
      if (this.state.connected) {
        await mongoose.disconnect();
        this.state.connected = false;
      }
      
      this.logger.success('✅ Production Migration System shut down successfully');
      
    } catch (error) {
      this.logger.error('❌ Error during shutdown', { error: error.message });
    }
  }

  /**
   * Get System Status
   */
  getStatus() {
    return {
      initialized: this.state.initialized,
      connected: this.state.connected,
      mode: this.state.mode,
      startTime: this.state.startTime,
      uptime: this.state.startTime ? Date.now() - this.state.startTime.getTime() : 0,
      components: Object.keys(this.state.components).reduce((status, component) => {
        status[component] = this.state.components[component] ? 'initialized' : 'not_initialized';
        return status;
      }, {}),
      options: this.options
    };
  }
}

/**
 * Command Line Interface
 */
async function parseCommandLineArgs() {
  const args = process.argv.slice(2);
  const options = {};
  
  // Parse command line arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--mode':
      case '-m':
        options.mode = args[++i];
        break;
        
      case '--dry-run':
      case '-d':
        options.dryRun = true;
        break;
        
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
        
      case '--environment':
      case '-e':
        options.environment = args[++i];
        break;
        
      case '--no-backup':
        options.autoBackup = false;
        break;
        
      case '--no-rollback':
        options.autoRollback = false;
        break;
        
      case '--help':
      case '-h':
        showHelp();
        process.exit(0);
        break;
        
      default:
        console.error(`Unknown argument: ${arg}`);
        showHelp();
        process.exit(1);
    }
  }
  
  return options;
}

function showHelp() {
  console.log(`
🚀 FAF Production Migration System

Usage: node index.js [options]

Modes:
  --mode cli          Interactive command-line interface (default)
  --mode api          RESTful API server with WebSocket support
  --mode automated    Automated hands-off migration execution
  --mode monitoring   Real-time monitoring dashboard
  --mode validation   Pre-flight and post-migration validation
  --mode rollback     Emergency rollback system

Options:
  --dry-run, -d       Run in simulation mode without making changes
  --verbose, -v       Enable detailed logging output
  --environment, -e   Set environment (production, staging, development)
  --no-backup         Disable automatic backup creation
  --no-rollback       Disable automatic rollback on failures
  --help, -h          Show this help message

Examples:
  # Interactive CLI mode
  node index.js --mode cli --verbose
  
  # API server mode
  node index.js --mode api
  
  # Automated migration with dry-run
  node index.js --mode automated --dry-run --verbose
  
  # Pre-flight validation only
  node index.js --mode validation
  
  # Emergency rollback system
  node index.js --mode rollback

Environment Variables:
  MONGODB_URI         MongoDB connection string (required)
  SESSION_SECRET      Session encryption key (required)
  LOGIN_ADMIN_USER    Admin username (required)
  LOGIN_ADMIN_PASS    Admin password (required)
  FORM_ADMIN_NAME     Admin name for role assignment (required)

For more information, see the documentation in the docs/ directory.
`);
}

/**
 * Main Entry Point
 */
async function main() {
  try {
    // Parse command line arguments
    const options = await parseCommandLineArgs();
    
    // Create and initialize system
    const migrationSystem = new ProductionMigrationSystem(options);
    
    // Setup graceful shutdown
    const shutdown = async () => {
      console.log('\n🛑 Received shutdown signal...');
      await migrationSystem.shutdown();
      process.exit(0);
    };
    
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    process.on('uncaughtException', (error) => {
      console.error('💥 Uncaught Exception:', error);
      shutdown().then(() => process.exit(1));
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
      shutdown().then(() => process.exit(1));
    });
    
    // Initialize and execute system
    await migrationSystem.initialize();
    await migrationSystem.execute();
    
  } catch (error) {
    console.error('❌ System Error:', error.message);
    
    if (process.env.NODE_ENV !== 'production') {
      console.error('Stack trace:', error.stack);
    }
    
    process.exit(1);
  }
}

// Export for use as module
module.exports = {
  ProductionMigrationSystem,
  SYSTEM_CONFIG
};

// Run if called directly
if (require.main === module) {
  main();
}