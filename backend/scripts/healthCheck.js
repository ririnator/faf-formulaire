#!/usr/bin/env node

// Migration Health Check CLI Tool
const MigrationHealthMonitor = require('../utils/migrationHealthMonitor');
const mongoose = require('mongoose');
require('dotenv').config();

const readline = require('readline');
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

class HealthCheckCLI {
  constructor() {
    this.monitor = null;
    this.connected = false;
  }

  /**
   * Connect to database
   */
  async connect() {
    try {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('✅ Connected to database');
      this.connected = true;
      return true;
    } catch (error) {
      console.error('❌ Database connection failed:', error.message);
      return false;
    }
  }

  /**
   * Initialize health monitor with configuration
   */
  initializeMonitor(config = {}) {
    this.monitor = new MigrationHealthMonitor({
      checkInterval: 5 * 60 * 1000, // 5 minutes
      autoCleanup: false,
      autoOptimize: false,
      ...config
    });

    // Setup event listeners for real-time monitoring
    this.monitor.on('alert', (alert) => {
      this.displayAlert(alert);
    });

    this.monitor.on('health_check_completed', (status) => {
      if (status.overall !== 'healthy') {
        console.log(`📊 Health status changed: ${status.overall.toUpperCase()}`);
      }
    });

    this.monitor.on('monitoring_error', (error) => {
      console.error('⚠️  Monitoring error:', error.message);
    });
  }

  /**
   * Display formatted alert
   */
  displayAlert(alert) {
    const colors = {
      critical: '\x1b[91m', // Red
      high: '\x1b[93m',     // Yellow
      warning: '\x1b[36m',  // Cyan
      reset: '\x1b[0m'
    };

    const color = colors[alert.level] || colors.reset;
    console.log(`\n${color}${alert.title}${colors.reset}`);
    console.log(`${alert.message}`);
    
    if (alert.issues && alert.issues.length > 0) {
      console.log('\nIssue Details:');
      alert.issues.slice(0, 3).forEach((issue, i) => {
        console.log(`  ${i + 1}. ${issue.message}`);
      });
      if (alert.issues.length > 3) {
        console.log(`  ... and ${alert.issues.length - 3} more issues`);
      }
    }
    console.log('');
  }

  /**
   * Interactive main menu
   */
  async showMenu() {
    console.log('\n=================================');
    console.log('🏥 MIGRATION HEALTH MONITOR');
    console.log('=================================');
    console.log('1. Run single health check');
    console.log('2. Start continuous monitoring');
    console.log('3. Stop monitoring');
    console.log('4. View current status');
    console.log('5. Generate detailed report');
    console.log('6. Configure alerts');
    console.log('7. Auto-remediation settings');
    console.log('8. Manual remediation');
    console.log('9. Exit');
    console.log('=================================');

    const choice = await this.prompt('Select option (1-9): ');
    await this.handleMenuChoice(choice);
  }

  /**
   * Handle menu selection
   */
  async handleMenuChoice(choice) {
    if (!this.monitor) {
      this.initializeMonitor();
    }

    switch (choice) {
      case '1':
        await this.runSingleHealthCheck();
        break;
      case '2':
        await this.startContinuousMonitoring();
        break;
      case '3':
        this.stopMonitoring();
        break;
      case '4':
        this.viewCurrentStatus();
        break;
      case '5':
        await this.generateDetailedReport();
        break;
      case '6':
        await this.configureAlerts();
        break;
      case '7':
        await this.configureAutoRemediation();
        break;
      case '8':
        await this.manualRemediation();
        break;
      case '9':
        await this.exit();
        return;
      default:
        console.log('❌ Invalid option');
    }

    // Show menu again
    setTimeout(() => this.showMenu(), 1000);
  }

  /**
   * Run single health check
   */
  async runSingleHealthCheck() {
    console.log('\n🔍 Running comprehensive health check...');
    try {
      const result = await this.monitor.performHealthCheck();
      
      console.log('\n📊 HEALTH CHECK RESULTS');
      console.log('=======================');
      console.log(`Overall Status: ${this.getStatusIcon(result.overall)} ${result.overall.toUpperCase()}`);
      console.log(`Issues Found: ${result.issues.length}`);
      console.log(`Alerts Generated: ${result.alerts.length}`);
      
      if (result.issues.length > 0) {
        console.log('\n🚨 Issues Summary:');
        const groupedIssues = this.groupIssuesBySeverity(result.issues);
        
        Object.entries(groupedIssues).forEach(([severity, issues]) => {
          console.log(`  ${this.getSeverityIcon(severity)} ${severity.toUpperCase()}: ${issues.length} issues`);
        });
      }
      
    } catch (error) {
      console.error('❌ Health check failed:', error.message);
    }
  }

  /**
   * Start continuous monitoring
   */
  async startContinuousMonitoring() {
    console.log('\n🚀 Starting continuous monitoring...');
    
    const interval = await this.prompt('Check interval in minutes (default: 5): ');
    const intervalMs = parseInt(interval) * 60 * 1000 || 5 * 60 * 1000;
    
    this.monitor.config.checkInterval = intervalMs;
    this.monitor.startMonitoring();
    
    console.log(`✅ Monitoring started (checking every ${intervalMs/60000} minutes)`);
    console.log('💡 Press Ctrl+C anytime to stop monitoring and return to menu');
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    if (this.monitor && this.monitor.monitoring) {
      this.monitor.stopMonitoring();
      console.log('⏹️  Monitoring stopped');
    } else {
      console.log('ℹ️  Monitoring is not currently running');
    }
  }

  /**
   * View current status
   */
  viewCurrentStatus() {
    const status = this.monitor.getHealthStatus();
    
    console.log('\n📊 CURRENT STATUS');
    console.log('=================');
    console.log(`Status: ${this.getStatusIcon(status.status)} ${status.status.toUpperCase()}`);
    console.log(`Monitoring: ${status.monitoring ? '🟢 Active' : '🔴 Stopped'}`);
    console.log(`Last Check: ${status.lastCheck || 'Never'}`);
    console.log(`Issues: ${status.issues}`);
    console.log(`Alerts: ${status.alerts}`);
  }

  /**
   * Generate detailed report
   */
  async generateDetailedReport() {
    console.log('\n📋 Generating detailed health report...');
    
    const report = this.monitor.generateHealthReport();
    const filename = `health-report-${Date.now()}.json`;
    
    // Save to file
    const fs = require('fs');
    fs.writeFileSync(filename, JSON.stringify(report, null, 2));
    
    console.log('📊 DETAILED HEALTH REPORT');
    console.log('=========================');
    console.log(`Overall Status: ${this.getStatusIcon(report.overall)} ${report.overall.toUpperCase()}`);
    console.log(`Total Issues: ${report.summary.totalIssues}`);
    console.log(`  Critical: ${report.summary.critical}`);
    console.log(`  High: ${report.summary.high}`);
    console.log(`  Warning: ${report.summary.warning}`);
    console.log(`Active Alerts: ${report.summary.alerts}`);
    console.log(`Report saved to: ${filename}`);
  }

  /**
   * Configure alert settings
   */
  async configureAlerts() {
    console.log('\n⚙️  CONFIGURE ALERTS');
    console.log('====================');
    
    const currentThresholds = this.monitor.config.alertThresholds;
    console.log('Current thresholds:');
    Object.entries(currentThresholds).forEach(([key, value]) => {
      console.log(`  ${key}: ${value}`);
    });
    
    console.log('\nUpdate thresholds (press Enter to keep current):');
    
    const newThresholds = {};
    
    for (const [key, currentValue] of Object.entries(currentThresholds)) {
      const input = await this.prompt(`${key} (${currentValue}): `);
      if (input.trim()) {
        const numValue = parseFloat(input);
        if (!isNaN(numValue)) {
          newThresholds[key] = numValue;
        }
      }
    }
    
    if (Object.keys(newThresholds).length > 0) {
      this.monitor.configureThresholds(newThresholds);
      console.log('✅ Alert thresholds updated');
    } else {
      console.log('ℹ️  No changes made');
    }
  }

  /**
   * Configure auto-remediation
   */
  async configureAutoRemediation() {
    console.log('\n🔧 CONFIGURE AUTO-REMEDIATION');
    console.log('==============================');
    
    const currentConfig = this.monitor.config;
    console.log(`Current settings:`);
    console.log(`  Auto-cleanup: ${currentConfig.autoCleanup ? 'Enabled' : 'Disabled'}`);
    console.log(`  Auto-optimize: ${currentConfig.autoOptimize ? 'Enabled' : 'Disabled'}`);
    
    const cleanup = await this.prompt('Enable auto-cleanup? (y/n): ');
    const optimize = await this.prompt('Enable auto-optimize? (y/n): ');
    
    const enableCleanup = cleanup.toLowerCase() === 'y';
    const enableOptimize = optimize.toLowerCase() === 'y';
    
    this.monitor.setAutoRemediation(enableCleanup, enableOptimize);
    console.log('✅ Auto-remediation settings updated');
  }

  /**
   * Manual remediation options
   */
  async manualRemediation() {
    console.log('\n🔧 MANUAL REMEDIATION');
    console.log('====================');
    console.log('1. Run data cleanup');
    console.log('2. Optimize indexes');
    console.log('3. Back to main menu');
    
    const choice = await this.prompt('Select option (1-3): ');
    
    switch (choice) {
      case '1':
        await this.runManualCleanup();
        break;
      case '2':
        await this.runManualOptimization();
        break;
      case '3':
        return;
      default:
        console.log('❌ Invalid option');
    }
  }

  /**
   * Run manual data cleanup
   */
  async runManualCleanup() {
    console.log('\n🧹 Manual Data Cleanup');
    const dryRun = await this.prompt('Dry run first? (y/n): ');
    
    try {
      const isDryRun = dryRun.toLowerCase() === 'y';
      const result = await this.monitor.monitors.orphanedCleanup.runCleanup({ 
        dryRun: isDryRun 
      });
      
      console.log(`✅ Cleanup ${isDryRun ? 'preview' : 'completed'}`);
      console.log(`Total issues ${isDryRun ? 'found' : 'resolved'}: ${result.totalCleaned}`);
      
    } catch (error) {
      console.error('❌ Cleanup failed:', error.message);
    }
  }

  /**
   * Run manual index optimization
   */
  async runManualOptimization() {
    console.log('\n📊 Manual Index Optimization');
    const dryRun = await this.prompt('Dry run first? (y/n): ');
    
    try {
      const isDryRun = dryRun.toLowerCase() === 'y';
      await this.monitor.monitors.indexOptimizer.analyzeIndexes();
      const result = await this.monitor.monitors.indexOptimizer.applyOptimizations({ 
        dryRun: isDryRun,
        priorities: ['critical', 'high', 'medium']
      });
      
      console.log(`✅ Optimization ${isDryRun ? 'preview' : 'completed'}`);
      console.log(`Actions ${isDryRun ? 'planned' : 'applied'}: ${result.applied}`);
      console.log(`Skipped: ${result.skipped}`);
      console.log(`Errors: ${result.errors}`);
      
    } catch (error) {
      console.error('❌ Optimization failed:', error.message);
    }
  }

  /**
   * Helper methods
   */
  getStatusIcon(status) {
    const icons = {
      healthy: '🟢',
      warning: '🟡',
      degraded: '🟠',
      critical: '🔴',
      error: '💥',
      unknown: '❓'
    };
    return icons[status] || icons.unknown;
  }

  getSeverityIcon(severity) {
    const icons = {
      critical: '🚨',
      high: '⚠️',
      warning: '📋',
      info: 'ℹ️'
    };
    return icons[severity] || icons.info;
  }

  groupIssuesBySeverity(issues) {
    return issues.reduce((groups, issue) => {
      const severity = issue.severity || 'unknown';
      if (!groups[severity]) groups[severity] = [];
      groups[severity].push(issue);
      return groups;
    }, {});
  }

  /**
   * Prompt helper
   */
  prompt(question) {
    return new Promise(resolve => {
      rl.question(question, answer => {
        resolve(answer);
      });
    });
  }

  /**
   * Exit application
   */
  async exit() {
    console.log('\n👋 Shutting down health monitor...');
    
    if (this.monitor) {
      this.monitor.cleanup();
    }
    
    if (this.connected) {
      await mongoose.disconnect();
      console.log('✅ Database disconnected');
    }
    
    rl.close();
    console.log('✅ Goodbye!');
    process.exit(0);
  }
}

// Main execution
async function main() {
  const cli = new HealthCheckCLI();
  
  console.log('🏥 Migration Health Check Tool');
  console.log('===============================');
  
  if (await cli.connect()) {
    await cli.showMenu();
  } else {
    console.log('❌ Cannot continue without database connection');
    process.exit(1);
  }
}

// Handle interrupts
process.on('SIGINT', () => {
  console.log('\n\n⏹️  Interrupted by user');
  process.exit(0);
});

process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled error:', error.message);
  process.exit(1);
});

// Run if executed directly
if (require.main === module) {
  main();
}

module.exports = HealthCheckCLI;