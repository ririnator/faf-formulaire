#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Function to run a single test file and extract results
function runSingleTest(testFile) {
  try {
    console.log(`Testing: ${testFile}`);
    const result = execSync(`NODE_ENV=test npx jest "${testFile}" --testTimeout=30000 --forceExit --silent`, {
      encoding: 'utf8',
      timeout: 120000 // 2 minutes per test file
    });
    
    // Extract test counts from output
    const lines = result.split('\n');
    const summaryLine = lines.find(line => line.includes('Tests:'));
    const suitesLine = lines.find(line => line.includes('Test Suites:'));
    
    return {
      file: testFile,
      status: 'PASS',
      summary: summaryLine || 'No summary found',
      suites: suitesLine || 'No suites info found',
      output: result
    };
  } catch (error) {
    return {
      file: testFile,
      status: 'FAIL',
      summary: 'Test failed',
      error: error.message,
      output: error.stdout || error.stderr || 'No output'
    };
  }
}

// Get all test files
const testFiles = fs.readdirSync('./tests')
  .filter(file => file.endsWith('.test.js'))
  .map(file => `tests/${file}`)
  .sort();

console.log(`Found ${testFiles.length} test files`);

const results = [];
let totalPassed = 0;
let totalFailed = 0;
let totalTests = 0;
let totalSuites = 0;

// Test each file individually
for (const testFile of testFiles) {
  const result = runSingleTest(testFile);
  results.push(result);
  
  if (result.status === 'PASS') {
    totalPassed++;
    // Extract numbers from summary line
    const testMatch = result.summary.match(/(\d+) passed/);
    if (testMatch) {
      totalTests += parseInt(testMatch[1]);
    }
    const suiteMatch = result.suites.match(/(\d+) passed/);
    if (suiteMatch) {
      totalSuites += parseInt(suiteMatch[1]);
    }
  } else {
    totalFailed++;
  }
  
  console.log(`  ${result.status}: ${result.file}`);
}

// Generate report
console.log('\n' + '='.repeat(80));
console.log('FAF APPLICATION TEST SUITE COMPREHENSIVE REPORT');
console.log('='.repeat(80));
console.log(`\n📊 OVERALL STATISTICS:`);
console.log(`Total Test Files: ${testFiles.length}`);
console.log(`Files Passed: ${totalPassed}`);
console.log(`Files Failed: ${totalFailed}`);
console.log(`Individual Tests Passed: ${totalTests}`);
console.log(`Test Suites Passed: ${totalSuites}`);
console.log(`Success Rate: ${((totalPassed / testFiles.length) * 100).toFixed(1)}%`);

console.log(`\n✅ PASSING TEST FILES (${totalPassed}):`);
results.filter(r => r.status === 'PASS').forEach(r => {
  console.log(`  ✓ ${r.file}`);
  console.log(`    ${r.summary}`);
});

console.log(`\n❌ FAILING TEST FILES (${totalFailed}):`);
results.filter(r => r.status === 'FAIL').forEach(r => {
  console.log(`  ✗ ${r.file}`);
  console.log(`    Error: ${r.error}`);
});

// Save detailed report to file
const detailedReport = {
  timestamp: new Date().toISOString(),
  summary: {
    totalFiles: testFiles.length,
    passed: totalPassed,
    failed: totalFailed,
    totalTests,
    totalSuites,
    successRate: ((totalPassed / testFiles.length) * 100).toFixed(1)
  },
  results
};

fs.writeFileSync('./test_analysis_report.json', JSON.stringify(detailedReport, null, 2));
console.log(`\n📋 Detailed report saved to: test_analysis_report.json`);