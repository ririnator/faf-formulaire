#!/usr/bin/env node

// Script to run API integration tests with proper environment setup
const { execSync } = require('child_process');

console.log('🧪 Setting up test environment...');

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.DISABLE_RATE_LIMITING = 'true';
process.env.MONGODB_URI = 'mongodb://localhost:27017/faf-test';

console.log('🔧 Environment configured:');
console.log('  NODE_ENV:', process.env.NODE_ENV);
console.log('  DISABLE_RATE_LIMITING:', process.env.DISABLE_RATE_LIMITING);

try {
  console.log('\n🧪 Running API integration tests...');
  
  // Run specific API tests
  const testCommand = 'npx jest --testPathPatterns="api\\.(contacts|handshakes|invitations|submissions)\\.integration\\.test\\.js" --verbose --maxWorkers=1 --forceExit --detectOpenHandles';
  
  execSync(testCommand, { 
    stdio: 'inherit',
    cwd: process.cwd(),
    timeout: 120000 // 2 minute timeout
  });
  
  console.log('\n✅ API integration tests completed successfully!');
  
} catch (error) {
  console.error('\n❌ API integration tests failed:');
  console.error(error.message);
  process.exit(1);
}