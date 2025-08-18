/**
 * Post-Deployment Test Results Processor
 * 
 * Processes test results and generates comprehensive reports
 * for production deployment validation.
 */

const fs = require('fs');
const path = require('path');

/**
 * Process test results and generate reports
 * @param {Object} results - Jest test results
 */
function processResults(results) {
  const timestamp = new Date().toISOString();
  const reportDir = path.join(__dirname, '../../coverage/post-deployment');
  
  // Ensure report directory exists
  if (!fs.existsSync(reportDir)) {
    fs.mkdirSync(reportDir, { recursive: true });
  }
  
  // Generate summary report
  const summary = generateSummaryReport(results, timestamp);
  
  // Save detailed report
  const detailedReport = generateDetailedReport(results, timestamp);
  
  // Save reports to files
  fs.writeFileSync(
    path.join(reportDir, 'summary-report.json'),
    JSON.stringify(summary, null, 2)
  );
  
  fs.writeFileSync(
    path.join(reportDir, 'detailed-report.json'),
    JSON.stringify(detailedReport, null, 2)
  );
  
  // Generate human-readable report
  const humanReport = generateHumanReadableReport(summary, detailedReport);
  fs.writeFileSync(
    path.join(reportDir, 'deployment-validation-report.md'),
    humanReport
  );
  
  // Console output
  console.log('\n📋 Post-Deployment Test Results:');
  console.log(`✅ Success Rate: ${summary.successRate}%`);
  console.log(`⏱️  Total Duration: ${summary.totalDuration}ms`);
  console.log(`🧪 Tests Run: ${summary.totalTests}`);
  console.log(`📊 Report saved to: ${reportDir}/deployment-validation-report.md`);
  
  if (summary.criticalFailures > 0) {
    console.error(`🚨 CRITICAL: ${summary.criticalFailures} critical tests failed!`);
    process.exit(1);
  }
  
  if (summary.securityIssues > 0) {
    console.warn(`🔒 WARNING: ${summary.securityIssues} security issues detected!`);
  }
  
  return results;
}

/**
 * Generate summary report
 */
function generateSummaryReport(results, timestamp) {
  const summary = {
    timestamp,
    environment: process.env.NODE_ENV || 'production',
    deployment: {
      baseUrl: process.env.APP_BASE_URL || 'unknown',
      version: process.env.npm_package_version || 'unknown',
      nodeVersion: process.version
    },
    testExecution: {
      totalTests: results.numTotalTests,
      passedTests: results.numPassedTests,
      failedTests: results.numFailedTests,
      skippedTests: results.numPendingTests,
      totalDuration: results.testResults.reduce((sum, test) => sum + (test.perfStats?.end - test.perfStats?.start || 0), 0),
      successRate: Math.round((results.numPassedTests / results.numTotalTests) * 100)
    },
    categories: {
      functionality: { passed: 0, failed: 0, total: 0 },
      performance: { passed: 0, failed: 0, total: 0 },
      security: { passed: 0, failed: 0, total: 0 },
      integration: { passed: 0, failed: 0, total: 0 },
      regression: { passed: 0, failed: 0, total: 0 },
      monitoring: { passed: 0, failed: 0, total: 0 }
    },
    issues: {
      criticalFailures: 0,
      securityIssues: 0,
      performanceIssues: 0,
      regressionIssues: 0
    }
  };
  
  // Categorize test results
  results.testResults.forEach(testFile => {
    testFile.testResults.forEach(test => {
      const category = getCategoryFromTestPath(testFile.testFilePath);
      
      if (summary.categories[category]) {
        summary.categories[category].total++;
        
        if (test.status === 'passed') {
          summary.categories[category].passed++;
        } else if (test.status === 'failed') {
          summary.categories[category].failed++;
          
          // Classify issues
          if (category === 'security') {
            summary.issues.securityIssues++;
          }
          if (category === 'performance') {
            summary.issues.performanceIssues++;
          }
          if (category === 'regression') {
            summary.issues.regressionIssues++;
          }
          if (isCriticalTest(test.fullName)) {
            summary.issues.criticalFailures++;
          }
        }
      }
    });
  });
  
  return summary;
}

/**
 * Generate detailed report
 */
function generateDetailedReport(results, timestamp) {
  return {
    timestamp,
    environment: {
      nodeEnv: process.env.NODE_ENV,
      baseUrl: process.env.APP_BASE_URL,
      nodeVersion: process.version,
      platform: process.platform,
      memoryUsage: process.memoryUsage()
    },
    testFiles: results.testResults.map(testFile => ({
      filePath: testFile.testFilePath,
      fileName: path.basename(testFile.testFilePath),
      category: getCategoryFromTestPath(testFile.testFilePath),
      duration: testFile.perfStats?.end - testFile.perfStats?.start || 0,
      numTests: testFile.numPassingTests + testFile.numFailingTests,
      numPassing: testFile.numPassingTests,
      numFailing: testFile.numFailingTests,
      tests: testFile.testResults.map(test => ({
        name: test.fullName,
        status: test.status,
        duration: test.duration || 0,
        failureMessages: test.failureMessages || [],
        ancestorTitles: test.ancestorTitles || []
      }))
    })),
    coverage: results.coverageMap ? {
      statements: results.coverageMap.getCoverageSummary().statements.pct,
      branches: results.coverageMap.getCoverageSummary().branches.pct,
      functions: results.coverageMap.getCoverageSummary().functions.pct,
      lines: results.coverageMap.getCoverageSummary().lines.pct
    } : null,
    systemInfo: {
      timestamp,
      uptime: process.uptime(),
      loadAverage: process.platform !== 'win32' ? require('os').loadavg() : null,
      totalMemory: require('os').totalmem(),
      freeMemory: require('os').freemem()
    }
  };
}

/**
 * Generate human-readable report
 */
function generateHumanReadableReport(summary, detailed) {
  const timestamp = new Date(summary.timestamp).toLocaleString();
  
  let report = `# Post-Deployment Validation Report\n\n`;
  report += `**Generated:** ${timestamp}\n`;
  report += `**Environment:** ${summary.environment}\n`;
  report += `**Base URL:** ${summary.deployment.baseUrl}\n`;
  report += `**Node Version:** ${summary.deployment.nodeVersion}\n\n`;
  
  // Executive Summary
  report += `## Executive Summary\n\n`;
  report += `- **Overall Success Rate:** ${summary.testExecution.successRate}%\n`;
  report += `- **Total Tests:** ${summary.testExecution.totalTests}\n`;
  report += `- **Tests Passed:** ${summary.testExecution.passedTests}\n`;
  report += `- **Tests Failed:** ${summary.testExecution.failedTests}\n`;
  report += `- **Tests Skipped:** ${summary.testExecution.skippedTests}\n`;
  report += `- **Total Duration:** ${summary.testExecution.totalDuration}ms\n\n`;
  
  // Status Icons
  const statusIcon = summary.testExecution.successRate >= 95 ? '✅' : 
                    summary.testExecution.successRate >= 80 ? '⚠️' : '❌';
  report += `**Deployment Status:** ${statusIcon} ${getDeploymentStatus(summary.testExecution.successRate)}\n\n`;
  
  // Critical Issues
  if (summary.issues.criticalFailures > 0) {
    report += `## 🚨 Critical Issues\n\n`;
    report += `**${summary.issues.criticalFailures} critical test(s) failed!**\n\n`;
    report += `This deployment should be reviewed immediately.\n\n`;
  }
  
  // Category Breakdown
  report += `## Test Categories\n\n`;
  Object.entries(summary.categories).forEach(([category, stats]) => {
    const successRate = stats.total > 0 ? Math.round((stats.passed / stats.total) * 100) : 0;
    const icon = successRate >= 95 ? '✅' : successRate >= 80 ? '⚠️' : '❌';
    
    report += `### ${icon} ${category.charAt(0).toUpperCase() + category.slice(1)}\n`;
    report += `- **Success Rate:** ${successRate}%\n`;
    report += `- **Passed:** ${stats.passed}/${stats.total}\n`;
    if (stats.failed > 0) {
      report += `- **Failed:** ${stats.failed}\n`;
    }
    report += `\n`;
  });
  
  // Issues Summary
  report += `## Issues Summary\n\n`;
  if (summary.issues.securityIssues > 0) {
    report += `🔒 **Security Issues:** ${summary.issues.securityIssues}\n`;
  }
  if (summary.issues.performanceIssues > 0) {
    report += `⚡ **Performance Issues:** ${summary.issues.performanceIssues}\n`;
  }
  if (summary.issues.regressionIssues > 0) {
    report += `🔄 **Regression Issues:** ${summary.issues.regressionIssues}\n`;
  }
  
  if (summary.issues.securityIssues === 0 && 
      summary.issues.performanceIssues === 0 && 
      summary.issues.regressionIssues === 0) {
    report += `✅ No major issues detected.\n`;
  }
  report += `\n`;
  
  // Recommendations
  report += `## Recommendations\n\n`;
  if (summary.testExecution.successRate >= 95) {
    report += `✅ **Deployment is ready for production use.**\n\n`;
  } else if (summary.testExecution.successRate >= 80) {
    report += `⚠️ **Deployment has minor issues but is acceptable for production.**\n`;
    report += `Consider monitoring closely and addressing failed tests.\n\n`;
  } else {
    report += `❌ **Deployment is not recommended for production.**\n`;
    report += `Significant issues detected that require immediate attention.\n\n`;
  }
  
  // Failed Tests Detail
  if (summary.testExecution.failedTests > 0) {
    report += `## Failed Tests Detail\n\n`;
    detailed.testFiles.forEach(testFile => {
      const failedTests = testFile.tests.filter(test => test.status === 'failed');
      if (failedTests.length > 0) {
        report += `### ${testFile.fileName}\n\n`;
        failedTests.forEach(test => {
          report += `- **${test.name}**\n`;
          if (test.failureMessages.length > 0) {
            report += `  - Error: ${test.failureMessages[0].split('\n')[0]}\n`;
          }
        });
        report += `\n`;
      }
    });
  }
  
  // System Information
  report += `## System Information\n\n`;
  report += `- **Platform:** ${process.platform}\n`;
  report += `- **Uptime:** ${Math.round(detailed.systemInfo.uptime)}s\n`;
  report += `- **Memory Usage:** ${Math.round((detailed.systemInfo.totalMemory - detailed.systemInfo.freeMemory) / 1024 / 1024)}MB / ${Math.round(detailed.systemInfo.totalMemory / 1024 / 1024)}MB\n`;
  
  if (detailed.coverage) {
    report += `\n## Code Coverage\n\n`;
    report += `- **Statements:** ${detailed.coverage.statements}%\n`;
    report += `- **Branches:** ${detailed.coverage.branches}%\n`;
    report += `- **Functions:** ${detailed.coverage.functions}%\n`;
    report += `- **Lines:** ${detailed.coverage.lines}%\n`;
  }
  
  return report;
}

/**
 * Get category from test file path
 */
function getCategoryFromTestPath(filePath) {
  const fileName = path.basename(filePath).toLowerCase();
  
  if (fileName.includes('functionality') || fileName.includes('workflow')) {
    return 'functionality';
  }
  if (fileName.includes('performance') || fileName.includes('load')) {
    return 'performance';
  }
  if (fileName.includes('security') || fileName.includes('auth')) {
    return 'security';
  }
  if (fileName.includes('integration') || fileName.includes('api')) {
    return 'integration';
  }
  if (fileName.includes('regression') || fileName.includes('legacy')) {
    return 'regression';
  }
  if (fileName.includes('monitoring') || fileName.includes('health')) {
    return 'monitoring';
  }
  
  return 'other';
}

/**
 * Check if test is critical
 */
function isCriticalTest(testName) {
  const criticalKeywords = [
    'authentication',
    'security',
    'data integrity',
    'user registration',
    'admin access',
    'database connection',
    'api availability'
  ];
  
  return criticalKeywords.some(keyword => 
    testName.toLowerCase().includes(keyword)
  );
}

/**
 * Get deployment status
 */
function getDeploymentStatus(successRate) {
  if (successRate >= 95) return 'APPROVED';
  if (successRate >= 80) return 'CONDITIONAL';
  return 'REJECTED';
}

module.exports = processResults;