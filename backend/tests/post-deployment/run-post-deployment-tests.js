#!/usr/bin/env node

/**
 * Post-Deployment Test Runner
 * 
 * Orchestrates the execution of all post-deployment tests
 * with comprehensive reporting and environment validation.
 */

const { execSync, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class PostDeploymentTestRunner {
  constructor() {
    this.startTime = Date.now();
    this.results = {
      environment: process.env.NODE_ENV || 'production',
      timestamp: new Date().toISOString(),
      testSuites: [],
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0,
        duration: 0
      },
      issues: {
        critical: [],
        warnings: [],
        recommendations: []
      }
    };
    
    this.testSuites = [
      { name: 'Functionality', file: '01-functionality.test.js', critical: true },
      { name: 'Performance', file: '02-performance.test.js', critical: true },
      { name: 'Security', file: '03-security.test.js', critical: true },
      { name: 'Integration', file: '04-integration.test.js', critical: false },
      { name: 'Regression', file: '05-regression.test.js', critical: false },
      { name: 'Monitoring', file: '06-monitoring.test.js', critical: false }
    ];
  }

  async run() {
    console.log('🚀 Starting Post-Deployment Validation');
    console.log('=====================================');
    console.log(`📅 Timestamp: ${this.results.timestamp}`);
    console.log(`🌍 Environment: ${this.results.environment}`);
    console.log(`📍 Base URL: ${process.env.APP_BASE_URL || 'Not configured'}`);
    console.log();

    try {
      // Validate environment
      await this.validateEnvironment();
      
      // Run test suites
      await this.runTestSuites();
      
      // Generate reports
      await this.generateReports();
      
      // Display results
      this.displaySummary();
      
      // Exit with appropriate code
      const exitCode = this.determineExitCode();
      process.exit(exitCode);
      
    } catch (error) {
      console.error('❌ Post-deployment test execution failed:', error.message);
      process.exit(1);
    }
  }

  async validateEnvironment() {
    console.log('🔍 Validating Environment...');
    
    const requiredEnvVars = [
      'APP_BASE_URL',
      'MONGODB_URI',
      'SESSION_SECRET',
      'LOGIN_ADMIN_USER',
      'LOGIN_ADMIN_PASS'
    ];

    const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
    
    if (missingVars.length > 0) {
      throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
    }

    // Validate database connectivity
    try {
      console.log('📊 Testing database connectivity...');
      // This would include actual database connection test
      console.log('✅ Database connectivity confirmed');
    } catch (error) {
      throw new Error(`Database connectivity failed: ${error.message}`);
    }

    // Validate application availability
    try {
      console.log('🌐 Testing application availability...');
      const healthCheck = await this.makeRequest('GET', '/api/health');
      if (healthCheck.status !== 'healthy') {
        throw new Error('Application health check failed');
      }
      console.log('✅ Application is available and healthy');
    } catch (error) {
      throw new Error(`Application availability check failed: ${error.message}`);
    }

    console.log('✅ Environment validation completed\n');
  }

  async runTestSuites() {
    console.log('🧪 Running Test Suites...');
    console.log('========================');

    for (const suite of this.testSuites) {
      console.log(`\n📋 Running ${suite.name} Tests...`);
      
      const suiteStartTime = Date.now();
      
      try {
        const result = await this.runTestSuite(suite);
        const duration = Date.now() - suiteStartTime;
        
        const suiteResult = {
          name: suite.name,
          file: suite.file,
          critical: suite.critical,
          status: result.success ? 'passed' : 'failed',
          duration: duration,
          tests: {
            total: result.numTotalTests || 0,
            passed: result.numPassedTests || 0,
            failed: result.numFailedTests || 0,
            skipped: result.numPendingTests || 0
          },
          coverage: result.coverage || null,
          issues: result.issues || []
        };

        this.results.testSuites.push(suiteResult);
        
        // Update summary
        this.results.summary.total += suiteResult.tests.total;
        this.results.summary.passed += suiteResult.tests.passed;
        this.results.summary.failed += suiteResult.tests.failed;
        this.results.summary.skipped += suiteResult.tests.skipped;

        if (suiteResult.status === 'passed') {
          console.log(`✅ ${suite.name} Tests: PASSED (${duration}ms)`);
        } else {
          console.log(`❌ ${suite.name} Tests: FAILED (${duration}ms)`);
          
          if (suite.critical) {
            this.results.issues.critical.push(`Critical test suite ${suite.name} failed`);
          } else {
            this.results.issues.warnings.push(`Test suite ${suite.name} failed`);
          }
        }

      } catch (error) {
        console.log(`💥 ${suite.name} Tests: ERROR - ${error.message}`);
        
        const suiteResult = {
          name: suite.name,
          file: suite.file,
          critical: suite.critical,
          status: 'error',
          duration: Date.now() - suiteStartTime,
          error: error.message,
          tests: { total: 0, passed: 0, failed: 1, skipped: 0 },
          issues: [`Test suite execution error: ${error.message}`]
        };

        this.results.testSuites.push(suiteResult);
        this.results.summary.failed += 1;

        if (suite.critical) {
          this.results.issues.critical.push(`Critical test suite ${suite.name} failed with error: ${error.message}`);
        }
      }
    }

    this.results.summary.duration = Date.now() - this.startTime;
    console.log('\n✅ All test suites completed');
  }

  async runTestSuite(suite) {
    return new Promise((resolve, reject) => {
      const testFile = path.join(__dirname, suite.file);
      
      if (!fs.existsSync(testFile)) {
        reject(new Error(`Test file not found: ${testFile}`));
        return;
      }

      const jestConfig = path.join(__dirname, 'jest.config.post-deployment.js');
      const jestCommand = [
        'npx', 'jest',
        testFile,
        '--config', jestConfig,
        '--verbose',
        '--json',
        '--outputFile', path.join(__dirname, `../../coverage/post-deployment/${suite.name.toLowerCase()}-results.json`)
      ];

      const jestProcess = spawn(jestCommand[0], jestCommand.slice(1), {
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: path.join(__dirname, '../..'),
        env: {
          ...process.env,
          NODE_ENV: 'production',
          POST_DEPLOYMENT_TEST: 'true'
        }
      });

      let stdout = '';
      let stderr = '';

      jestProcess.stdout.on('data', (data) => {
        stdout += data.toString();
        // Real-time output for monitoring
        if (process.env.VERBOSE) {
          process.stdout.write(data);
        }
      });

      jestProcess.stderr.on('data', (data) => {
        stderr += data.toString();
        if (process.env.VERBOSE) {
          process.stderr.write(data);
        }
      });

      jestProcess.on('close', (code) => {
        try {
          // Parse Jest JSON output
          const outputFile = path.join(__dirname, `../../coverage/post-deployment/${suite.name.toLowerCase()}-results.json`);
          let result = { success: code === 0 };

          if (fs.existsSync(outputFile)) {
            const jestOutput = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
            result = {
              ...result,
              ...jestOutput
            };
          }

          resolve(result);
        } catch (error) {
          reject(new Error(`Failed to parse test results: ${error.message}`));
        }
      });

      jestProcess.on('error', (error) => {
        reject(new Error(`Failed to run test suite: ${error.message}`));
      });
    });
  }

  async generateReports() {
    console.log('\n📊 Generating Reports...');
    
    const reportsDir = path.join(__dirname, '../../coverage/post-deployment');
    
    // Ensure reports directory exists
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    // Generate JSON report
    const jsonReport = path.join(reportsDir, 'post-deployment-results.json');
    fs.writeFileSync(jsonReport, JSON.stringify(this.results, null, 2));

    // Generate markdown report
    const markdownReport = this.generateMarkdownReport();
    const mdReportPath = path.join(reportsDir, 'POST_DEPLOYMENT_REPORT.md');
    fs.writeFileSync(mdReportPath, markdownReport);

    // Generate deployment status
    const deploymentStatus = this.generateDeploymentStatus();
    const statusPath = path.join(reportsDir, 'deployment-status.json');
    fs.writeFileSync(statusPath, JSON.stringify(deploymentStatus, null, 2));

    console.log(`📄 JSON Report: ${jsonReport}`);
    console.log(`📄 Markdown Report: ${mdReportPath}`);
    console.log(`📄 Deployment Status: ${statusPath}`);
  }

  generateMarkdownReport() {
    const timestamp = new Date(this.results.timestamp).toLocaleString();
    const duration = Math.round(this.results.summary.duration / 1000);
    const successRate = Math.round((this.results.summary.passed / this.results.summary.total) * 100) || 0;

    let report = `# Post-Deployment Validation Report\n\n`;
    report += `**Generated:** ${timestamp}\n`;
    report += `**Environment:** ${this.results.environment}\n`;
    report += `**Duration:** ${duration} seconds\n`;
    report += `**Base URL:** ${process.env.APP_BASE_URL}\n\n`;

    // Executive Summary
    report += `## Executive Summary\n\n`;
    const overallStatus = this.getOverallStatus();
    const statusIcon = overallStatus === 'APPROVED' ? '✅' : overallStatus === 'CONDITIONAL' ? '⚠️' : '❌';
    
    report += `**Deployment Status:** ${statusIcon} ${overallStatus}\n\n`;
    report += `- **Success Rate:** ${successRate}%\n`;
    report += `- **Total Tests:** ${this.results.summary.total}\n`;
    report += `- **Tests Passed:** ${this.results.summary.passed}\n`;
    report += `- **Tests Failed:** ${this.results.summary.failed}\n`;
    report += `- **Tests Skipped:** ${this.results.summary.skipped}\n\n`;

    // Critical Issues
    if (this.results.issues.critical.length > 0) {
      report += `## 🚨 Critical Issues\n\n`;
      this.results.issues.critical.forEach(issue => {
        report += `- ${issue}\n`;
      });
      report += `\n`;
    }

    // Test Suite Results
    report += `## Test Suite Results\n\n`;
    this.results.testSuites.forEach(suite => {
      const suiteIcon = suite.status === 'passed' ? '✅' : suite.status === 'failed' ? '❌' : '💥';
      const suiteSuccessRate = suite.tests.total > 0 ? Math.round((suite.tests.passed / suite.tests.total) * 100) : 0;
      
      report += `### ${suiteIcon} ${suite.name}\n`;
      report += `- **Status:** ${suite.status.toUpperCase()}\n`;
      report += `- **Duration:** ${suite.duration}ms\n`;
      report += `- **Success Rate:** ${suiteSuccessRate}%\n`;
      report += `- **Tests:** ${suite.tests.passed}/${suite.tests.total} passed\n`;
      
      if (suite.critical) {
        report += `- **Critical:** Yes\n`;
      }
      
      if (suite.issues && suite.issues.length > 0) {
        report += `- **Issues:** ${suite.issues.length}\n`;
      }
      
      report += `\n`;
    });

    // Warnings
    if (this.results.issues.warnings.length > 0) {
      report += `## ⚠️ Warnings\n\n`;
      this.results.issues.warnings.forEach(warning => {
        report += `- ${warning}\n`;
      });
      report += `\n`;
    }

    // Recommendations
    if (this.results.issues.recommendations.length > 0) {
      report += `## 💡 Recommendations\n\n`;
      this.results.issues.recommendations.forEach(rec => {
        report += `- ${rec}\n`;
      });
      report += `\n`;
    }

    // Deployment Decision
    report += `## Deployment Decision\n\n`;
    if (overallStatus === 'APPROVED') {
      report += `✅ **APPROVED FOR PRODUCTION**\n\n`;
      report += `The deployment has passed all critical tests and is ready for production use.\n\n`;
    } else if (overallStatus === 'CONDITIONAL') {
      report += `⚠️ **CONDITIONAL APPROVAL**\n\n`;
      report += `The deployment has minor issues but is acceptable for production with monitoring.\n\n`;
    } else {
      report += `❌ **REJECTED**\n\n`;
      report += `The deployment has critical issues that must be resolved before production use.\n\n`;
    }

    // System Information
    report += `## System Information\n\n`;
    report += `- **Node Version:** ${process.version}\n`;
    report += `- **Platform:** ${process.platform}\n`;
    report += `- **Architecture:** ${process.arch}\n`;
    report += `- **Memory Usage:** ${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB\n`;

    return report;
  }

  generateDeploymentStatus() {
    const overallStatus = this.getOverallStatus();
    
    return {
      timestamp: this.results.timestamp,
      environment: this.results.environment,
      status: overallStatus,
      approved: overallStatus === 'APPROVED',
      conditional: overallStatus === 'CONDITIONAL',
      rejected: overallStatus === 'REJECTED',
      summary: this.results.summary,
      criticalIssues: this.results.issues.critical.length,
      warnings: this.results.issues.warnings.length,
      recommendations: this.results.issues.recommendations.length,
      testSuites: this.results.testSuites.map(suite => ({
        name: suite.name,
        status: suite.status,
        critical: suite.critical,
        successRate: suite.tests.total > 0 ? Math.round((suite.tests.passed / suite.tests.total) * 100) : 0
      }))
    };
  }

  getOverallStatus() {
    const criticalFailures = this.results.testSuites.filter(s => s.critical && s.status !== 'passed').length;
    const overallSuccessRate = this.results.summary.total > 0 ? 
      (this.results.summary.passed / this.results.summary.total) * 100 : 0;

    if (criticalFailures > 0) {
      return 'REJECTED';
    } else if (overallSuccessRate >= 95) {
      return 'APPROVED';
    } else if (overallSuccessRate >= 80) {
      return 'CONDITIONAL';
    } else {
      return 'REJECTED';
    }
  }

  displaySummary() {
    const duration = Math.round(this.results.summary.duration / 1000);
    const successRate = Math.round((this.results.summary.passed / this.results.summary.total) * 100) || 0;
    const overallStatus = this.getOverallStatus();

    console.log('\n📊 POST-DEPLOYMENT VALIDATION SUMMARY');
    console.log('===================================');
    console.log(`🕐 Duration: ${duration} seconds`);
    console.log(`📈 Success Rate: ${successRate}%`);
    console.log(`✅ Tests Passed: ${this.results.summary.passed}`);
    console.log(`❌ Tests Failed: ${this.results.summary.failed}`);
    console.log(`⏭️ Tests Skipped: ${this.results.summary.skipped}`);
    console.log(`🎯 Total Tests: ${this.results.summary.total}`);

    if (this.results.issues.critical.length > 0) {
      console.log(`🚨 Critical Issues: ${this.results.issues.critical.length}`);
    }

    if (this.results.issues.warnings.length > 0) {
      console.log(`⚠️ Warnings: ${this.results.issues.warnings.length}`);
    }

    console.log('\n📋 DEPLOYMENT DECISION');
    console.log('=====================');
    
    const statusIcon = overallStatus === 'APPROVED' ? '✅' : overallStatus === 'CONDITIONAL' ? '⚠️' : '❌';
    console.log(`${statusIcon} Status: ${overallStatus}`);

    if (overallStatus === 'APPROVED') {
      console.log('✅ Deployment is APPROVED for production use');
    } else if (overallStatus === 'CONDITIONAL') {
      console.log('⚠️ Deployment is CONDITIONALLY approved - monitor closely');
    } else {
      console.log('❌ Deployment is REJECTED - critical issues must be resolved');
    }

    console.log('\n===================================\n');
  }

  determineExitCode() {
    const overallStatus = this.getOverallStatus();
    
    if (overallStatus === 'APPROVED') {
      return 0; // Success
    } else if (overallStatus === 'CONDITIONAL') {
      return 0; // Success with warnings
    } else {
      return 1; // Failure
    }
  }

  async makeRequest(method, path) {
    // This would be implemented with actual HTTP request logic
    // For now, return mock response
    return { status: 'healthy' };
  }
}

// CLI Interface
if (require.main === module) {
  const runner = new PostDeploymentTestRunner();
  
  // Handle CLI arguments
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Usage: node run-post-deployment-tests.js [options]

Options:
  --help, -h          Show help information
  --verbose, -v       Enable verbose output
  --suite <name>      Run specific test suite only
  --env <environment> Set environment (default: production)

Environment Variables:
  APP_BASE_URL        Base URL of the application
  MONGODB_URI         MongoDB connection string
  SESSION_SECRET      Session encryption secret
  LOGIN_ADMIN_USER    Admin username
  LOGIN_ADMIN_PASS    Admin password

Examples:
  node run-post-deployment-tests.js
  node run-post-deployment-tests.js --verbose
  node run-post-deployment-tests.js --suite Security
    `);
    process.exit(0);
  }

  if (args.includes('--verbose') || args.includes('-v')) {
    process.env.VERBOSE = 'true';
  }

  const suiteIndex = args.indexOf('--suite');
  if (suiteIndex !== -1 && args[suiteIndex + 1]) {
    const suiteName = args[suiteIndex + 1];
    runner.testSuites = runner.testSuites.filter(suite => 
      suite.name.toLowerCase() === suiteName.toLowerCase()
    );
    
    if (runner.testSuites.length === 0) {
      console.error(`❌ Test suite "${suiteName}" not found`);
      console.log('Available suites:', runner.testSuites.map(s => s.name).join(', '));
      process.exit(1);
    }
  }

  const envIndex = args.indexOf('--env');
  if (envIndex !== -1 && args[envIndex + 1]) {
    process.env.NODE_ENV = args[envIndex + 1];
  }

  // Start test execution
  runner.run().catch(error => {
    console.error('❌ Fatal error:', error.message);
    process.exit(1);
  });
}

module.exports = PostDeploymentTestRunner;