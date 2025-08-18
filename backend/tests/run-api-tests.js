#!/usr/bin/env node

// tests/run-api-tests.js
// Comprehensive Test Runner for Form-a-Friend v2 API Integration Tests

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const TEST_SUITES = {
  'api.contacts.integration.test.js': {
    name: 'Contact API Integration Tests',
    description: 'CRUD operations, search, bulk operations, security validation',
    timeout: '60s',
    estimatedTime: '45s'
  },
  'api.handshakes.integration.test.js': {
    name: 'Handshake API Integration Tests', 
    description: 'Social connections, request/accept/decline workflows, suggestions',
    timeout: '60s',
    estimatedTime: '50s'
  },
  'api.invitations.integration.test.js': {
    name: 'Invitation API Integration Tests',
    description: 'Token-based invitations, bulk operations, public registration flow',
    timeout: '60s', 
    estimatedTime: '55s'
  },
  'api.submissions.integration.test.js': {
    name: 'Submission API Integration Tests',
    description: 'Form submissions, timeline view, monthly comparisons, statistics',
    timeout: '60s',
    estimatedTime: '40s'
  },
  'api.end-to-end.integration.test.js': {
    name: 'End-to-End Integration Tests',
    description: 'Complete user workflows, cross-service integration, complex scenarios',
    timeout: '120s',
    estimatedTime: '90s'
  },
  'api.performance.load.test.js': {
    name: 'Performance & Load Tests',
    description: 'Response time validation, concurrent load, memory usage, stress testing',
    timeout: '180s',
    estimatedTime: '120s'
  },
  'api.security.comprehensive.test.js': {
    name: 'Comprehensive Security Tests',
    description: 'XSS protection, CSRF validation, authentication bypass, injection prevention',
    timeout: '90s',
    estimatedTime: '75s'
  }
};

const COLORS = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function colorize(text, color) {
  return `${COLORS[color]}${text}${COLORS.reset}`;
}

function printHeader() {
  console.log(colorize('\n🧪 Form-a-Friend v2 API Integration Test Suite', 'bright'));
  console.log(colorize('=' .repeat(60), 'cyan'));
  console.log(colorize('Comprehensive testing of all new API endpoints and workflows', 'blue'));
  console.log(colorize('Testing: /api/contacts, /api/handshakes, /api/invitations, /api/submissions\n', 'blue'));
}

function printTestSuiteInfo() {
  console.log(colorize('📋 Available Test Suites:', 'bright'));
  console.log(colorize('-'.repeat(40), 'cyan'));
  
  Object.entries(TEST_SUITES).forEach(([file, info], index) => {
    console.log(colorize(`${index + 1}. ${info.name}`, 'bright'));
    console.log(`   ${info.description}`);
    console.log(colorize(`   Estimated time: ${info.estimatedTime}`, 'yellow'));
    console.log();
  });
}

function runTestSuite(testFile, options = {}) {
  const suite = TEST_SUITES[testFile];
  if (!suite) {
    console.error(colorize(`❌ Test suite ${testFile} not found`, 'red'));
    return false;
  }

  console.log(colorize(`\n🚀 Running: ${suite.name}`, 'bright'));
  console.log(colorize(`📝 ${suite.description}`, 'blue'));
  console.log(colorize(`⏱️  Estimated time: ${suite.estimatedTime}`, 'yellow'));
  console.log(colorize('-'.repeat(60), 'cyan'));

  const testPath = path.join(__dirname, testFile);
  
  if (!fs.existsSync(testPath)) {
    console.error(colorize(`❌ Test file not found: ${testPath}`, 'red'));
    return false;
  }

  const jestCommand = [
    'npx jest',
    `"${testPath}"`,
    '--verbose',
    '--colors',
    `--testTimeout=${options.timeout || suite.timeout || '60000'}`,
    options.coverage ? '--coverage' : '',
    options.silent ? '--silent' : '',
    options.bail ? '--bail' : '',
    options.watchAll ? '--watchAll' : ''
  ].filter(Boolean).join(' ');

  const startTime = Date.now();
  
  try {
    console.log(colorize(`\n▶️  Command: ${jestCommand}\n`, 'cyan'));
    
    execSync(jestCommand, {
      stdio: 'inherit',
      cwd: path.dirname(__dirname),
      env: {
        ...process.env,
        NODE_ENV: 'test',
        DISABLE_RATE_LIMITING: 'true'
      }
    });

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.log(colorize(`\n✅ ${suite.name} completed successfully in ${duration}s`, 'green'));
    return true;
    
  } catch (error) {
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    console.error(colorize(`\n❌ ${suite.name} failed after ${duration}s`, 'red'));
    console.error(colorize(`Error: ${error.message}`, 'red'));
    return false;
  }
}

function runAllTests(options = {}) {
  console.log(colorize('\n🎯 Running All API Integration Test Suites', 'bright'));
  console.log(colorize('=' .repeat(60), 'cyan'));
  
  const results = [];
  const startTime = Date.now();
  
  for (const [testFile, suite] of Object.entries(TEST_SUITES)) {
    const success = runTestSuite(testFile, options);
    results.push({ testFile, suite: suite.name, success });
    
    if (!success && options.bail) {
      console.log(colorize('\n🛑 Stopping due to test failure (--bail)', 'yellow'));
      break;
    }
  }
  
  const totalTime = ((Date.now() - startTime) / 1000).toFixed(2);
  
  console.log(colorize('\n📊 Test Suite Summary', 'bright'));
  console.log(colorize('=' .repeat(60), 'cyan'));
  
  results.forEach(result => {
    const status = result.success ? 
      colorize('✅ PASSED', 'green') : 
      colorize('❌ FAILED', 'red');
    console.log(`${status} - ${result.suite}`);
  });
  
  const passed = results.filter(r => r.success).length;
  const total = results.length;
  const successRate = ((passed / total) * 100).toFixed(1);
  
  console.log(colorize(`\n🏁 Final Results: ${passed}/${total} suites passed (${successRate}%)`, 'bright'));
  console.log(colorize(`⏱️  Total execution time: ${totalTime}s`, 'yellow'));
  
  if (passed === total) {
    console.log(colorize('\n🎉 All test suites passed! API is ready for production.', 'green'));
  } else {
    console.log(colorize(`\n⚠️  ${total - passed} test suite(s) failed. Please review and fix issues.`, 'red'));
  }
  
  return passed === total;
}

function showUsage() {
  console.log(colorize('\nUsage: node run-api-tests.js [options] [test-name]', 'bright'));
  console.log('\nOptions:');
  console.log('  --all, -a        Run all test suites');
  console.log('  --coverage, -c   Generate coverage reports');
  console.log('  --bail, -b       Stop on first failure');
  console.log('  --silent, -s     Suppress verbose output');
  console.log('  --watch, -w      Run in watch mode');
  console.log('  --list, -l       List available test suites');
  console.log('  --help, -h       Show this help message');
  
  console.log('\nTest Names:');
  Object.entries(TEST_SUITES).forEach(([file, info]) => {
    const shortName = file.replace('.test.js', '').replace('api.', '');
    console.log(`  ${shortName.padEnd(20)} ${info.name}`);
  });
  
  console.log('\nExamples:');
  console.log('  node run-api-tests.js --all                    # Run all tests');
  console.log('  node run-api-tests.js --all --coverage         # Run all with coverage');
  console.log('  node run-api-tests.js contacts                 # Run contact tests only');
  console.log('  node run-api-tests.js security --bail          # Run security tests, stop on failure');
  console.log('  node run-api-tests.js performance --watch      # Run performance tests in watch mode');
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    printHeader();
    printTestSuiteInfo();
    showUsage();
    return;
  }
  
  if (args.includes('--list') || args.includes('-l')) {
    printHeader();
    printTestSuiteInfo();
    return;
  }
  
  printHeader();
  
  const options = {
    coverage: args.includes('--coverage') || args.includes('-c'),
    bail: args.includes('--bail') || args.includes('-b'),
    silent: args.includes('--silent') || args.includes('-s'),
    watchAll: args.includes('--watch') || args.includes('-w')
  };
  
  if (args.includes('--all') || args.includes('-a')) {
    const success = runAllTests(options);
    process.exit(success ? 0 : 1);
    return;
  }
  
  // Find specific test to run
  const testArg = args.find(arg => !arg.startsWith('--') && !arg.startsWith('-'));
  
  if (!testArg) {
    console.error(colorize('❌ No test specified. Use --all or specify a test name.', 'red'));
    showUsage();
    process.exit(1);
  }
  
  // Map short names to full filenames
  const testMapping = {
    'contacts': 'api.contacts.integration.test.js',
    'handshakes': 'api.handshakes.integration.test.js', 
    'invitations': 'api.invitations.integration.test.js',
    'submissions': 'api.submissions.integration.test.js',
    'end-to-end': 'api.end-to-end.integration.test.js',
    'e2e': 'api.end-to-end.integration.test.js',
    'performance': 'api.performance.load.test.js',
    'load': 'api.performance.load.test.js',
    'security': 'api.security.comprehensive.test.js'
  };
  
  const testFile = testMapping[testArg] || testArg;
  
  if (!testFile.endsWith('.test.js')) {
    console.error(colorize(`❌ Invalid test name: ${testArg}`, 'red'));
    console.log('\nAvailable tests:');
    Object.keys(testMapping).forEach(name => {
      console.log(`  ${name}`);
    });
    process.exit(1);
  }
  
  const success = runTestSuite(testFile, options);
  process.exit(success ? 0 : 1);
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error(colorize('\n💥 Uncaught Exception:', 'red'));
  console.error(error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error(colorize('\n💥 Unhandled Rejection:', 'red'));
  console.error(reason);
  process.exit(1);
});

if (require.main === module) {
  main();
}

module.exports = {
  TEST_SUITES,
  runTestSuite,
  runAllTests
};