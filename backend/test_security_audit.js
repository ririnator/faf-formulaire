#!/usr/bin/env node

/**
 * Comprehensive Security Audit Test for FAF New API Routes
 * Tests actual security implementations vs claims
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// Test configurations
const BASE_URL = 'http://localhost:3000';
const TEST_ROUTES = [
  '/api/contacts',
  '/api/handshakes',
  '/api/invitations',
  '/api/submissions'
];

// Test payloads for various attack vectors
const XSS_PAYLOADS = [
  '<script>alert("XSS")</script>',
  'javascript:alert("XSS")',
  '<img src=x onerror=alert("XSS")>',
  '<svg/onload=alert("XSS")>',
  '"><script>alert("XSS")</script>',
  '\';alert("XSS");//',
  '<iframe src="javascript:alert(\'XSS\')"></iframe>',
  '<object data="javascript:alert(\'XSS\')"></object>'
];

const SQL_INJECTION_PAYLOADS = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  "' UNION SELECT * FROM users --",
  "1' OR 1=1 --",
  "admin' --",
  "' OR '1'='1' /*",
  "'; EXEC xp_cmdshell('dir'); --"
];

const CSRF_TEST_HEADERS = {
  'Content-Type': 'application/json',
  'Origin': 'http://malicious-site.com',
  'Referer': 'http://malicious-site.com/attack.html'
};

const RATE_LIMIT_TESTS = {
  burst: 50,  // Number of requests to send rapidly
  interval: 100  // Milliseconds between requests
};

// Security test results
const auditResults = {
  xssProtection: { tested: 0, blocked: 0, bypassed: 0 },
  sqlInjection: { tested: 0, blocked: 0, bypassed: 0 },
  csrfProtection: { tested: 0, blocked: 0, bypassed: 0 },
  rateLimiting: { tested: 0, blocked: 0, bypassed: 0 },
  authentication: { tested: 0, blocked: 0, bypassed: 0 },
  inputValidation: { tested: 0, blocked: 0, bypassed: 0 },
  fileUpload: { tested: 0, blocked: 0, bypassed: 0 },
  criticalVulnerabilities: [],
  recommendations: []
};

console.log('🔍 Starting Comprehensive Security Audit of FAF API Routes...\n');

/**
 * Test XSS Protection
 */
async function testXSSProtection() {
  console.log('🚨 Testing XSS Protection...');
  
  for (const route of TEST_ROUTES) {
    for (const payload of XSS_PAYLOADS) {
      auditResults.xssProtection.tested++;
      
      // Test in various request bodies
      const testData = {
        name: payload,
        email: `test${payload}@example.com`,
        firstName: payload,
        lastName: payload,
        message: payload,
        responses: [{ 
          questionId: 'q1', 
          type: 'text', 
          answer: payload 
        }]
      };
      
      try {
        const response = await makeRequest('POST', route, testData);
        
        if (response.statusCode >= 400) {
          auditResults.xssProtection.blocked++;
          console.log(`  ✅ XSS blocked on ${route}: ${response.statusCode}`);
        } else {
          auditResults.xssProtection.bypassed++;
          console.log(`  ⚠️  XSS potentially bypassed on ${route}: ${response.statusCode}`);
          auditResults.criticalVulnerabilities.push({
            type: 'XSS_BYPASS',
            route: route,
            payload: payload,
            response: response.statusCode
          });
        }
      } catch (error) {
        console.log(`  🔴 XSS test error on ${route}: ${error.message}`);
      }
    }
  }
}

/**
 * Test SQL Injection Protection
 */
async function testSQLInjection() {
  console.log('💉 Testing SQL Injection Protection...');
  
  for (const route of TEST_ROUTES) {
    for (const payload of SQL_INJECTION_PAYLOADS) {
      auditResults.sqlInjection.tested++;
      
      // Test in various parameters and body fields
      const testData = {
        email: `${payload}@example.com`,
        search: payload,
        month: `2024-01${payload}`,
        responses: [{ 
          questionId: payload, 
          type: 'text', 
          answer: payload 
        }]
      };
      
      try {
        const response = await makeRequest('GET', `${route}?search=${encodeURIComponent(payload)}`);
        
        if (response.statusCode >= 400 || response.body.includes('error')) {
          auditResults.sqlInjection.blocked++;
          console.log(`  ✅ SQL injection blocked on ${route}: ${response.statusCode}`);
        } else {
          auditResults.sqlInjection.bypassed++;
          console.log(`  ⚠️  SQL injection potentially bypassed on ${route}: ${response.statusCode}`);
          auditResults.criticalVulnerabilities.push({
            type: 'SQL_INJECTION_BYPASS',
            route: route,
            payload: payload,
            response: response.statusCode
          });
        }
      } catch (error) {
        console.log(`  🔴 SQL injection test error on ${route}: ${error.message}`);
      }
    }
  }
}

/**
 * Test CSRF Protection
 */
async function testCSRFProtection() {
  console.log('🔒 Testing CSRF Protection...');
  
  for (const route of TEST_ROUTES) {
    auditResults.csrfProtection.tested++;
    
    const testData = {
      email: 'test@example.com',
      name: 'Test User',
      responses: [{ 
        questionId: 'q1', 
        type: 'text', 
        answer: 'test answer' 
      }]
    };
    
    try {
      // Test without CSRF token
      const response = await makeRequest('POST', route, testData, CSRF_TEST_HEADERS);
      
      if (response.statusCode === 403 || response.body.includes('CSRF')) {
        auditResults.csrfProtection.blocked++;
        console.log(`  ✅ CSRF protection active on ${route}: ${response.statusCode}`);
      } else {
        auditResults.csrfProtection.bypassed++;
        console.log(`  ⚠️  CSRF protection bypassed on ${route}: ${response.statusCode}`);
        auditResults.criticalVulnerabilities.push({
          type: 'CSRF_BYPASS',
          route: route,
          response: response.statusCode,
          details: 'Request accepted without CSRF token'
        });
      }
    } catch (error) {
      console.log(`  🔴 CSRF test error on ${route}: ${error.message}`);
    }
  }
}

/**
 * Test Rate Limiting
 */
async function testRateLimiting() {
  console.log('⏱️  Testing Rate Limiting...');
  
  for (const route of TEST_ROUTES) {
    console.log(`  Testing rate limits on ${route}...`);
    const requests = [];
    
    // Send rapid burst of requests
    for (let i = 0; i < RATE_LIMIT_TESTS.burst; i++) {
      auditResults.rateLimiting.tested++;
      
      const promise = makeRequest('GET', route)
        .then(response => {
          if (response.statusCode === 429) {
            auditResults.rateLimiting.blocked++;
            return { blocked: true, index: i };
          } else {
            auditResults.rateLimiting.bypassed++;
            return { blocked: false, index: i };
          }
        })
        .catch(error => ({ error: true, index: i }));
      
      requests.push(promise);
      
      // Small delay between requests
      await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_TESTS.interval));
    }
    
    const results = await Promise.all(requests);
    const blockedCount = results.filter(r => r.blocked).length;
    const bypassedCount = results.filter(r => !r.blocked && !r.error).length;
    
    console.log(`    Rate limiting results: ${blockedCount} blocked, ${bypassedCount} bypassed`);
    
    if (bypassedCount === RATE_LIMIT_TESTS.burst) {
      auditResults.criticalVulnerabilities.push({
        type: 'RATE_LIMIT_BYPASS',
        route: route,
        details: `All ${RATE_LIMIT_TESTS.burst} requests bypassed rate limiting`
      });
    }
  }
}

/**
 * Test Authentication Controls
 */
async function testAuthentication() {
  console.log('🔐 Testing Authentication Controls...');
  
  for (const route of TEST_ROUTES) {
    auditResults.authentication.tested++;
    
    try {
      // Test without authentication
      const response = await makeRequest('POST', route, { test: 'data' });
      
      if (response.statusCode === 401 || response.statusCode === 403) {
        auditResults.authentication.blocked++;
        console.log(`  ✅ Authentication required on ${route}: ${response.statusCode}`);
      } else {
        auditResults.authentication.bypassed++;
        console.log(`  ⚠️  Authentication bypassed on ${route}: ${response.statusCode}`);
        auditResults.criticalVulnerabilities.push({
          type: 'AUTH_BYPASS',
          route: route,
          response: response.statusCode,
          details: 'Unauthenticated request accepted'
        });
      }
    } catch (error) {
      console.log(`  🔴 Authentication test error on ${route}: ${error.message}`);
    }
  }
}

/**
 * Test File Upload Security (CSV import)
 */
async function testFileUploadSecurity() {
  console.log('📁 Testing File Upload Security...');
  
  const maliciousPayloads = [
    '<script>alert("XSS")</script>,test@example.com',
    '<?php system($_GET["cmd"]); ?>,test@example.com',
    '../../../etc/passwd,test@example.com',
    'test@example.com\x00malicious.php',
    'test@example.com"onload="alert(\'XSS\')"'
  ];
  
  const route = '/api/contacts/import';
  
  for (const payload of maliciousPayloads) {
    auditResults.fileUpload.tested++;
    
    const testData = {
      csvData: payload,
      mimeType: 'text/csv',
      fileName: 'test.csv'
    };
    
    try {
      const response = await makeRequest('POST', route, testData);
      
      if (response.statusCode >= 400) {
        auditResults.fileUpload.blocked++;
        console.log(`  ✅ Malicious CSV blocked: ${response.statusCode}`);
      } else {
        auditResults.fileUpload.bypassed++;
        console.log(`  ⚠️  Malicious CSV potentially accepted: ${response.statusCode}`);
        auditResults.criticalVulnerabilities.push({
          type: 'FILE_UPLOAD_BYPASS',
          route: route,
          payload: payload.substring(0, 50) + '...',
          response: response.statusCode
        });
      }
    } catch (error) {
      console.log(`  🔴 File upload test error: ${error.message}`);
    }
  }
}

/**
 * Make HTTP request
 */
function makeRequest(method, path, data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const isHttps = url.protocol === 'https:';
    const httpModule = isHttps ? https : http;
    
    const options = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: method,
      headers: {
        'User-Agent': 'SecurityAuditBot/1.0',
        'Accept': 'application/json',
        ...headers
      }
    };
    
    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      const postData = JSON.stringify(data);
      options.headers['Content-Type'] = 'application/json';
      options.headers['Content-Length'] = Buffer.byteLength(postData);
    }
    
    const req = httpModule.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk;
      });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body
        });
      });
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    req.setTimeout(5000, () => {
      req.abort();
      reject(new Error('Request timeout'));
    });
    
    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      req.write(JSON.stringify(data));
    }
    
    req.end();
  });
}

/**
 * Generate security report
 */
function generateSecurityReport() {
  console.log('\n📊 COMPREHENSIVE SECURITY AUDIT REPORT\n');
  console.log('=' .repeat(60));
  
  // Calculate overall scores
  const totalTests = Object.values(auditResults)
    .filter(result => typeof result === 'object' && result.tested)
    .reduce((sum, result) => sum + result.tested, 0);
  
  const totalBlocked = Object.values(auditResults)
    .filter(result => typeof result === 'object' && result.blocked)
    .reduce((sum, result) => sum + result.blocked, 0);
  
  const securityScore = totalTests > 0 ? Math.round((totalBlocked / totalTests) * 100) : 0;
  
  console.log(`🎯 OVERALL SECURITY SCORE: ${securityScore}%\n`);
  
  // Detailed results
  console.log('📋 DETAILED TEST RESULTS:');
  console.log('-'.repeat(40));
  
  Object.entries(auditResults).forEach(([category, result]) => {
    if (typeof result === 'object' && result.tested) {
      const score = result.tested > 0 ? Math.round((result.blocked / result.tested) * 100) : 0;
      const status = score >= 80 ? '✅' : score >= 60 ? '⚠️' : '🔴';
      
      console.log(`${status} ${category.toUpperCase()}:`);
      console.log(`   Tests: ${result.tested} | Blocked: ${result.blocked} | Bypassed: ${result.bypassed} | Score: ${score}%`);
    }
  });
  
  // Critical vulnerabilities
  if (auditResults.criticalVulnerabilities.length > 0) {
    console.log('\n🚨 CRITICAL VULNERABILITIES FOUND:');
    console.log('-'.repeat(40));
    auditResults.criticalVulnerabilities.forEach((vuln, index) => {
      console.log(`${index + 1}. ${vuln.type} on ${vuln.route}`);
      if (vuln.payload) console.log(`   Payload: ${vuln.payload}`);
      if (vuln.details) console.log(`   Details: ${vuln.details}`);
      console.log(`   Response: ${vuln.response}\n`);
    });
  }
  
  // Production readiness assessment
  console.log('🏭 PRODUCTION READINESS ASSESSMENT:');
  console.log('-'.repeat(40));
  
  if (securityScore >= 90) {
    console.log('✅ PRODUCTION READY - Strong security implementation');
  } else if (securityScore >= 75) {
    console.log('⚠️  PRODUCTION READY WITH CAUTION - Minor security gaps');
  } else if (securityScore >= 50) {
    console.log('🔶 NOT PRODUCTION READY - Significant security issues');
  } else {
    console.log('🔴 NOT PRODUCTION READY - Critical security vulnerabilities');
  }
  
  // Generate recommendations
  generateRecommendations(securityScore);
}

/**
 * Generate security recommendations
 */
function generateRecommendations(score) {
  console.log('\n💡 SECURITY RECOMMENDATIONS:');
  console.log('-'.repeat(40));
  
  const recommendations = [];
  
  if (auditResults.xssProtection.bypassed > 0) {
    recommendations.push('Implement comprehensive XSS filtering using Content Security Policy (CSP)');
    recommendations.push('Ensure all user input is properly sanitized with smartEscape() function');
  }
  
  if (auditResults.sqlInjection.bypassed > 0) {
    recommendations.push('Use parameterized queries and input validation for all database operations');
    recommendations.push('Implement proper MongoDB query sanitization');
  }
  
  if (auditResults.csrfProtection.bypassed > 0) {
    recommendations.push('Implement CSRF tokens for all state-changing operations');
    recommendations.push('Validate Origin and Referer headers on sensitive endpoints');
  }
  
  if (auditResults.rateLimiting.bypassed === auditResults.rateLimiting.tested) {
    recommendations.push('Implement proper rate limiting with Redis or in-memory storage');
    recommendations.push('Use progressive delays and IP-based tracking');
  }
  
  if (auditResults.authentication.bypassed > 0) {
    recommendations.push('Ensure all sensitive endpoints require proper authentication');
    recommendations.push('Implement proper session management and user verification');
  }
  
  if (auditResults.fileUpload.bypassed > 0) {
    recommendations.push('Implement strict file upload validation (MIME type, size, content)');
    recommendations.push('Sanitize and validate all CSV import data');
  }
  
  if (score < 75) {
    recommendations.push('Conduct regular security audits and penetration testing');
    recommendations.push('Implement proper logging and monitoring for security events');
    recommendations.push('Consider using additional security middleware like Helmet.js');
  }
  
  recommendations.forEach((rec, index) => {
    console.log(`${index + 1}. ${rec}`);
  });
  
  if (recommendations.length === 0) {
    console.log('✅ No major security recommendations - well implemented!');
  }
}

/**
 * Main audit function
 */
async function runSecurityAudit() {
  try {
    // Wait for server to be ready
    console.log('🔄 Waiting for server to be ready...\n');
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Run all security tests
    await testXSSProtection();
    await testSQLInjection();
    await testCSRFProtection();
    await testRateLimiting();
    await testAuthentication();
    await testFileUploadSecurity();
    
    // Generate comprehensive report
    generateSecurityReport();
    
  } catch (error) {
    console.error('❌ Security audit failed:', error);
    process.exit(1);
  }
}

// Run the audit
if (require.main === module) {
  runSecurityAudit();
}

module.exports = {
  runSecurityAudit,
  auditResults
};