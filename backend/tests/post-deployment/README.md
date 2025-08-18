# Post-Deployment Test Suite

Comprehensive validation suite for Form-a-Friend v2 production deployments.

## Overview

This test suite provides comprehensive validation of a Form-a-Friend v2 deployment, ensuring all critical functionality, security, and performance requirements are met before approving production use.

### Test Categories

1. **🎯 Functionality Tests** (`01-functionality.test.js`)
   - User registration and authentication workflows
   - Form submission and response management  
   - Admin dashboard operations
   - Invitation and handshake systems
   - Contact management
   - Data migration validation

2. **⚡ Performance Tests** (`02-performance.test.js`)
   - Response time validation
   - Concurrent load testing
   - Memory usage monitoring
   - Database performance
   - Network connectivity

3. **🔒 Security Tests** (`03-security.test.js`)
   - XSS protection validation
   - Authentication and authorization
   - CSRF protection
   - Rate limiting
   - Security headers
   - Injection attack prevention

4. **🔗 Integration Tests** (`04-integration.test.js`)
   - External service integration
   - API endpoint validation
   - Service layer interactions
   - Configuration validation

5. **🔄 Regression Tests** (`05-regression.test.js`)
   - Legacy URL compatibility
   - Migration data integrity
   - Legacy feature compatibility
   - Performance regression checks

6. **📊 Monitoring Tests** (`06-monitoring.test.js`)
   - Health check validation
   - Metrics collection
   - Alerting systems
   - Continuous monitoring

## Quick Start

### Prerequisites

- Node.js v16 or higher
- Access to production environment
- Valid environment variables configured

### Environment Variables

Required environment variables:

```bash
APP_BASE_URL=https://your-production-domain.com
MONGODB_URI=mongodb://your-mongo-connection
SESSION_SECRET=your-session-secret
LOGIN_ADMIN_USER=admin-username
LOGIN_ADMIN_PASS=admin-password
FORM_ADMIN_NAME=admin-form-name
```

Optional variables:

```bash
CLOUDINARY_CLOUD_NAME=your-cloudinary-cloud
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret
FRONTEND_URL=https://your-frontend-domain.com
```

### Running Tests

#### Run All Tests

```bash
# Basic execution
node run-post-deployment-tests.js

# Verbose output
node run-post-deployment-tests.js --verbose

# Specific environment
node run-post-deployment-tests.js --env production
```

#### Run Specific Test Suite

```bash
# Run only security tests
node run-post-deployment-tests.js --suite Security

# Run only functionality tests
node run-post-deployment-tests.js --suite Functionality
```

#### Available Test Suites

- `Functionality` - Core application features
- `Performance` - Load and response time testing
- `Security` - Security validation
- `Integration` - External service integration
- `Regression` - Backward compatibility
- `Monitoring` - Health checks and monitoring

### Using Jest Directly

```bash
# Run all post-deployment tests
npm run test:post-deployment

# Run with coverage
npm run test:post-deployment:coverage

# Run specific test file
npx jest tests/post-deployment/01-functionality.test.js --config tests/post-deployment/jest.config.post-deployment.js
```

## Test Results & Reporting

### Output Locations

Test results are saved to `/backend/coverage/post-deployment/`:

- `post-deployment-results.json` - Detailed JSON results
- `POST_DEPLOYMENT_REPORT.md` - Human-readable report
- `deployment-status.json` - Deployment decision summary
- `{suite-name}-results.json` - Individual suite results

### Deployment Status

The test suite provides three possible deployment statuses:

- **✅ APPROVED** - All critical tests pass, deployment ready for production
- **⚠️ CONDITIONAL** - Minor issues detected, acceptable with monitoring
- **❌ REJECTED** - Critical issues found, deployment should not proceed

### Success Criteria

| Metric | Threshold | Impact |
|--------|-----------|---------|
| Overall Success Rate | ≥95% | APPROVED |
| Overall Success Rate | ≥80% | CONDITIONAL |
| Critical Test Failures | 0 | Required for approval |
| Security Test Failures | 0 | Critical |
| Performance Issues | ≤5% | Warning threshold |

## Test Configuration

### Jest Configuration

The test suite uses a specialized Jest configuration (`jest.config.post-deployment.js`) optimized for production testing:

- 30-second test timeout for network operations
- Serial execution for production safety
- Comprehensive coverage reporting
- Custom result processing and reporting

### Environment Setup

Tests automatically configure the environment for production validation:

- Production-like session handling
- Real database connections
- External service integration
- Security header validation

## Troubleshooting

### Common Issues

#### Environment Variables Not Set

```
Error: Missing required environment variables: APP_BASE_URL, MONGODB_URI
```

**Solution:** Ensure all required environment variables are properly configured.

#### Database Connection Failed

```
Error: Database connectivity failed
```

**Solutions:**
- Verify MONGODB_URI is correct
- Check network connectivity
- Ensure database is accessible from test environment

#### Application Not Available

```
Error: Application availability check failed
```

**Solutions:**
- Verify APP_BASE_URL is correct and accessible
- Check if application is running
- Verify DNS resolution and SSL certificates

#### Test Timeouts

```
Error: Test timeout after 30000ms
```

**Solutions:**
- Check network latency to production environment
- Verify application performance
- Consider increasing timeout in jest config

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
# Enable verbose output
node run-post-deployment-tests.js --verbose

# Enable Jest verbose mode
DEBUG=true node run-post-deployment-tests.js
```

### Test Data Cleanup

The test suite automatically cleans up test data created during execution. However, if tests are interrupted, manual cleanup may be required:

```bash
# Connect to your database and remove test data
# Look for entries with usernames/emails containing 'test_', 'security_', etc.
```

## Best Practices

### Pre-Deployment

1. **Environment Validation**
   - Verify all environment variables are set correctly
   - Test database connectivity manually
   - Confirm application is accessible

2. **Staging Validation**
   - Run tests against staging environment first
   - Validate test data cleanup
   - Review performance baselines

### During Deployment

1. **Monitoring**
   - Monitor application logs during test execution
   - Watch for performance degradation
   - Check for security alerts

2. **Incremental Testing**
   - Run critical tests first (functionality, security)
   - Proceed to non-critical tests if critical tests pass
   - Stop execution if critical failures occur

### Post-Deployment

1. **Report Review**
   - Analyze detailed test reports
   - Address any warnings or recommendations
   - Document any conditional approvals

2. **Continuous Monitoring**
   - Set up regular health checks
   - Monitor metrics identified during testing
   - Schedule periodic regression testing

## Extending the Test Suite

### Adding New Tests

1. **Create Test File**
   ```javascript
   // tests/post-deployment/07-custom.test.js
   describe('Custom Tests', () => {
     test('should validate custom functionality', async () => {
       // Test implementation
     });
   });
   ```

2. **Update Test Runner**
   ```javascript
   // Add to testSuites array in run-post-deployment-tests.js
   { name: 'Custom', file: '07-custom.test.js', critical: false }
   ```

### Custom Validation Logic

Extend the results processor (`results-processor.js`) to add custom validation logic:

```javascript
function customValidation(results) {
  // Add custom validation logic
  return {
    passed: true,
    issues: []
  };
}
```

### Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: Post-Deployment Validation
on:
  deployment_status:
    
jobs:
  validate:
    runs-on: ubuntu-latest
    if: github.event.deployment_status.state == 'success'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          
      - name: Install dependencies
        run: npm ci
        working-directory: backend
        
      - name: Run post-deployment tests
        run: node tests/post-deployment/run-post-deployment-tests.js
        working-directory: backend
        env:
          APP_BASE_URL: ${{ secrets.PRODUCTION_URL }}
          MONGODB_URI: ${{ secrets.PRODUCTION_MONGODB_URI }}
          SESSION_SECRET: ${{ secrets.SESSION_SECRET }}
          LOGIN_ADMIN_USER: ${{ secrets.ADMIN_USER }}
          LOGIN_ADMIN_PASS: ${{ secrets.ADMIN_PASS }}
          
      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: post-deployment-results
          path: backend/coverage/post-deployment/
```

## Support

For issues with the post-deployment test suite:

1. Check the troubleshooting section above
2. Review test logs in verbose mode
3. Validate environment configuration
4. Consult the main project documentation

---

**Note:** This test suite is designed for production validation and should be used carefully. Always test in a staging environment first and ensure proper backup procedures are in place.