/**
 * Jest Configuration for Post-Deployment Testing
 * 
 * Configuration optimized for production environment validation
 * with comprehensive reporting and monitoring capabilities.
 */

module.exports = {
  // Test environment and setup
  testEnvironment: 'node',
  setupFilesAfterEnv: [
    '<rootDir>/tests/post-deployment/setup-post-deployment.js'
  ],
  
  // Test file patterns
  testMatch: [
    '<rootDir>/tests/post-deployment/**/*.test.js'
  ],
  
  // Test timeouts for production environment
  testTimeout: 30000, // 30 seconds for network operations
  
  // Coverage configuration
  collectCoverage: true,
  coverageDirectory: '<rootDir>/coverage/post-deployment',
  coverageReporters: [
    'text',
    'lcov',
    'html',
    'json',
    'json-summary'
  ],
  
  // Coverage paths
  collectCoverageFrom: [
    'app.js',
    'routes/**/*.js',
    'middleware/**/*.js',
    'services/**/*.js',
    'models/**/*.js',
    'config/**/*.js',
    'utils/**/*.js',
    '!tests/**',
    '!coverage/**',
    '!node_modules/**'
  ],
  
  // Custom reporters for detailed post-deployment reports
  reporters: [
    'default',
    ['jest-html-reporters', {
      publicPath: './coverage/post-deployment/html-report',
      filename: 'post-deployment-report.html',
      expand: true,
      hideIcon: false,
      pageTitle: 'FAF Post-Deployment Test Report',
      logoImgPath: undefined,
      includeFailureMsg: true,
      includeSuiteFailure: true
    }],
    ['jest-junit', {
      outputDirectory: './coverage/post-deployment',
      outputName: 'junit-report.xml',
      ancestorSeparator: ' › ',
      uniqueOutputName: false,
      suiteNameTemplate: '{filepath}',
      classNameTemplate: '{classname}',
      titleTemplate: '{title}'
    }]
  ],
  
  // Module resolution
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/$1',
    '^@tests/(.*)$': '<rootDir>/tests/$1'
  },
  
  // Global variables for post-deployment testing
  globals: {
    'process.env.NODE_ENV': 'production',
    'process.env.POST_DEPLOYMENT_TEST': 'true'
  },
  
  // Verbose output for detailed production validation
  verbose: true,
  
  // Detection and error handling
  detectOpenHandles: true,
  forceExit: true,
  
  // Transform configuration
  transform: {
    '^.+\\.js$': 'babel-jest'
  },
  
  // Test sequence configuration
  runInBand: true, // Run tests serially for production safety
  maxWorkers: 1,   // Single worker for controlled execution
  
  // Clear mocks between tests
  clearMocks: true,
  restoreMocks: true,
  
  // Custom test results processor
  testResultsProcessor: '<rootDir>/tests/post-deployment/results-processor.js'
};