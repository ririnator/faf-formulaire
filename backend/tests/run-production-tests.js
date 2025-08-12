#!/usr/bin/env node

// Production Test Runner
const { spawn } = require('child_process');
const path = require('path');

console.log('🚀 Starting Production Test Suite');
console.log('==================================\n');

const testSuites = [
  {
    name: '📝 Production Authentication Suite',
    pattern: 'production-auth-suite.test.js',
    critical: true
  },
  {
    name: '🔄 Migration Integration Tests',
    pattern: 'migration.integration.test.js',
    critical: true
  },
  {
    name: '⚡ Edge Cases Critical Tests',
    pattern: 'edge-cases.critical.test.js',
    critical: true
  },
  {
    name: '🔐 Hybrid Auth Middleware Tests',
    pattern: 'hybrid-auth.middleware.test.js',
    critical: true
  },
  {
    name: '📊 Performance Dual-Auth Tests',
    pattern: 'performance.dual-auth.test.js',
    critical: false
  },
  {
    name: '🛡️ Security & Validation Tests',
    pattern: 'validation.*.test.js',
    critical: true
  }
];

async function runTestSuite(suite) {
  return new Promise((resolve, reject) => {
    console.log(`\n🧪 Running: ${suite.name}`);
    console.log('-'.repeat(50));
    
    const jest = spawn('npx', [
      'jest',
      '--testPathPatterns',
      suite.pattern,
      '--verbose',
      '--detectOpenHandles',
      '--forceExit'
    ], {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..')
    });

    jest.on('close', (code) => {
      if (code === 0) {
        console.log(`✅ ${suite.name} - PASSED`);
        resolve({ suite: suite.name, status: 'PASSED', critical: suite.critical });
      } else {
        console.log(`❌ ${suite.name} - FAILED (exit code: ${code})`);
        resolve({ suite: suite.name, status: 'FAILED', critical: suite.critical, code });
      }
    });

    jest.on('error', (err) => {
      console.error(`💥 ${suite.name} - ERROR:`, err.message);
      reject({ suite: suite.name, status: 'ERROR', error: err.message });
    });
  });
}

async function runAllTests() {
  const results = [];
  
  try {
    // Run critical tests first
    const criticalSuites = testSuites.filter(s => s.critical);
    const nonCriticalSuites = testSuites.filter(s => !s.critical);
    
    console.log('🔥 Running CRITICAL test suites first...\n');
    
    for (const suite of criticalSuites) {
      const result = await runTestSuite(suite);
      results.push(result);
      
      if (result.status === 'FAILED' && result.critical) {
        console.log('\n💀 CRITICAL TEST FAILED - Stopping execution');
        break;
      }
    }
    
    // Only run non-critical if all critical passed
    const criticalFailures = results.filter(r => r.status === 'FAILED' && r.critical);
    
    if (criticalFailures.length === 0) {
      console.log('\n✅ All critical tests passed! Running performance tests...\n');
      
      for (const suite of nonCriticalSuites) {
        const result = await runTestSuite(suite);
        results.push(result);
      }
    }
    
  } catch (error) {
    console.error('\n💥 Fatal error running tests:', error);
    results.push({ suite: 'RUNNER', status: 'ERROR', error: error.message });
  }
  
  // Generate summary
  console.log('\n' + '='.repeat(60));
  console.log('📋 PRODUCTION TEST SUMMARY');
  console.log('='.repeat(60));
  
  const passed = results.filter(r => r.status === 'PASSED').length;
  const failed = results.filter(r => r.status === 'FAILED').length;
  const errors = results.filter(r => r.status === 'ERROR').length;
  const criticalFailed = results.filter(r => r.status === 'FAILED' && r.critical).length;
  
  console.log(`\n📊 Results:`);
  console.log(`   ✅ Passed: ${passed}`);
  console.log(`   ❌ Failed: ${failed}`);
  console.log(`   💥 Errors: ${errors}`);
  console.log(`   🔥 Critical Failures: ${criticalFailed}`);
  
  results.forEach(result => {
    const icon = result.status === 'PASSED' ? '✅' : 
                result.status === 'FAILED' ? '❌' : '💥';
    const critical = result.critical ? ' [CRITICAL]' : '';
    console.log(`   ${icon} ${result.suite}${critical}`);
  });
  
  console.log('\n' + '='.repeat(60));
  
  if (criticalFailed > 0) {
    console.log('💀 PRODUCTION NOT READY - Critical tests failed');
    process.exit(1);
  } else if (failed === 0 && errors === 0) {
    console.log('🎉 PRODUCTION READY - All tests passed!');
    process.exit(0);
  } else {
    console.log('⚠️  PRODUCTION READY - Critical tests passed (some non-critical issues)');
    process.exit(0);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n\n⏹️  Test execution interrupted by user');
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('\n\n⏹️  Test execution terminated');
  process.exit(1);
});

// Run the tests
runAllTests().catch(error => {
  console.error('💥 Unhandled error:', error);
  process.exit(1);
});