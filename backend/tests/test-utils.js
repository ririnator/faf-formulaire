// tests/test-utils.js - Standardized test utilities for FAF backend
const request = require('supertest');

/**
 * Test utilities to ensure consistent test behavior across all test files
 * Prevents MongoDB connection issues and provides standardized helpers
 */

/**
 * Get the shared app instance - prevents multiple MongoDB connections
 * This should be used instead of requiring app.js directly in test files
 */
const getTestApp = () => {
  // Use the global app instance if available, otherwise require it
  if (global.testApp) {
    return global.testApp;
  }
  
  // Ensure test environment is set before requiring app
  process.env.NODE_ENV = 'test';
  process.env.DISABLE_RATE_LIMITING = 'true';
  
  global.testApp = require('../app');
  return global.testApp;
};

/**
 * Get CSRF token for authenticated requests
 * Handles both session-based and standalone CSRF token requests
 */
const getCsrfToken = async (app, authenticatedAgent = null) => {
  try {
    const agent = authenticatedAgent || request(app);
    
    // Try API endpoint first
    let response = await agent.get('/api/csrf-token');
    
    if (response.status === 200 && response.body && response.body.csrfToken) {
      return response.body.csrfToken;
    }
    
    if (response.status === 200 && response.body && response.body.token) {
      return response.body.token;
    }
    
    // Fallback to admin endpoint
    response = await agent.get('/csrf-token');
    
    if (response.status === 200 && response.body && response.body.csrfToken) {
      return response.body.csrfToken;
    }
    
    if (response.status === 200 && response.body && response.body.token) {
      return response.body.token;
    }
    
    // Fallback: Try to extract from headers
    const csrfHeader = response.headers['x-csrf-token'];
    if (csrfHeader) {
      return csrfHeader;
    }
    
    // Generate a test token if CSRF is disabled
    return 'test-csrf-token';
  } catch (error) {
    console.warn('Warning: Could not get CSRF token, using test token:', error.message);
    return 'test-csrf-token';
  }
};

/**
 * Create an authenticated admin session for testing
 * Returns a supertest agent with admin session
 */
const createAuthenticatedAdmin = async (app) => {
  const agent = request.agent(app);
  
  // Set consistent headers for all requests to avoid security detection
  const headers = {
    'User-Agent': 'test-agent/1.0',
    'Accept': 'application/json, text/html',
    'Accept-Language': 'en-US,en;q=0.9'
  };
  
  try {
    // First get CSRF token with consistent headers
    const csrfResponse = await agent
      .get('/api/csrf-token')
      .set(headers);
    
    let csrfToken = 'test-csrf-token'; // fallback
    if (csrfResponse.status === 200 && csrfResponse.body) {
      csrfToken = csrfResponse.body.csrfToken || csrfResponse.body.token || csrfToken;
    }
    
    // Login with consistent headers
    const loginResponse = await agent
      .post('/admin-login')
      .set(headers)
      .set('X-CSRF-Token', csrfToken)
      .send({
        username: process.env.LOGIN_ADMIN_USER || 'testadmin',
        password: 'testpass123' // Use plain password, bcrypt comparison happens server-side
      });
    
    if (loginResponse.status !== 302 && loginResponse.status !== 200) {
      throw new Error(`Admin login failed with status ${loginResponse.status}: ${loginResponse.text}`);
    }
    
    // Create a wrapper that automatically adds headers to all requests
    const originalGet = agent.get;
    const originalPost = agent.post;
    const originalPut = agent.put;
    const originalDelete = agent.delete;
    
    agent.get = function(url) {
      return originalGet.call(this, url).set(headers);
    };
    
    agent.post = function(url) {
      return originalPost.call(this, url).set(headers);
    };
    
    agent.put = function(url) {
      return originalPut.call(this, url).set(headers);
    };
    
    agent.delete = function(url) {
      return originalDelete.call(this, url).set(headers);
    };
    
    return agent;
  } catch (error) {
    console.warn('Warning: Admin authentication failed:', error.message);
    return agent; // Return agent anyway for tests that mock authentication
  }
};

/**
 * Standard test environment setup
 * Sets required environment variables for testing
 */
const setupTestEnvironment = () => {
  process.env.NODE_ENV = 'test';
  process.env.DISABLE_RATE_LIMITING = 'true';
  process.env.FORM_ADMIN_NAME = process.env.FORM_ADMIN_NAME || 'testadmin';
  process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret-key-for-sessions';
  process.env.APP_BASE_URL = process.env.APP_BASE_URL || 'http://localhost:3000';
  process.env.LOGIN_ADMIN_USER = process.env.LOGIN_ADMIN_USER || 'testadmin';
  process.env.LOGIN_ADMIN_PASS = process.env.LOGIN_ADMIN_PASS || '$2b$10$exOvJIZPqaZu./LsS29XUOIn0lsYsvROI4UV6UY1tVu.QXHkhCRfe'; // testpass123
};

/**
 * Standard test data generators
 */
const generateTestUser = (overrides = {}) => ({
  username: 'testuser',
  email: 'test@example.com',
  password: 'password123',
  role: 'user',
  ...overrides
});

const generateTestResponse = (overrides = {}) => ({
  name: 'Test User',
  responses: [
    { question: 'Test Question 1', answer: 'Test Answer 1' },
    { question: 'Test Question 2', answer: 'Test Answer 2' }
  ],
  month: '2025-01',
  isAdmin: false,
  ...overrides
});

const generateTestContact = (overrides = {}) => ({
  userId: 'test-user-id',
  name: 'Test Contact',
  email: 'contact@example.com',
  relationship: 'friend',
  ...overrides
});

const generateTestHandshake = (overrides = {}) => ({
  requesterId: 'test-requester-id',
  targetId: 'test-target-id',
  message: 'Test handshake message',
  status: 'pending',
  ...overrides
});

const generateTestInvitation = (overrides = {}) => ({
  senderId: 'test-sender-id',
  recipientEmail: 'recipient@example.com',
  message: 'Test invitation message',
  ...overrides
});

const generateTestSubmission = (overrides = {}) => ({
  userId: 'test-user-id',
  formData: {
    question1: 'answer1',
    question2: 'answer2'
  },
  month: '2025-01',
  ...overrides
});

/**
 * Validation helpers for common test assertions
 */
const validateResponseStructure = (response, requiredFields = []) => {
  expect(response).toBeDefined();
  expect(typeof response).toBe('object');
  
  requiredFields.forEach(field => {
    expect(response).toHaveProperty(field);
  });
};

const validateErrorResponse = (response, expectedStatus = 400) => {
  expect(response.status).toBe(expectedStatus);
  expect(response.body).toHaveProperty('error');
  expect(typeof response.body.error).toBe('string');
};

/**
 * XSS and security test payloads
 */
const XSS_PAYLOADS = [
  '<script>alert("xss")</script>',
  '"><script>alert("xss")</script>',
  '\';alert("xss");//',
  '<img src=x onerror=alert("xss")>',
  'javascript:alert("xss")',
  '<svg onload=alert("xss")>',
  '<iframe src="javascript:alert(\'xss\')"></iframe>',
  '<body onload=alert("xss")>',
  '<input onfocus=alert("xss") autofocus>',
  '<select onfocus=alert("xss") autofocus>'
];

const INJECTION_PAYLOADS = [
  "'; DROP TABLE users; --",
  '{ "$ne": null }',
  '{ "$gt": "" }',
  '{"$where": "this.username == this.password"}',
  'admin\'; --',
  '" OR "1"="1',
  "' OR '1'='1",
  '{"$regex": ".*"}',
  '{"$exists": true}',
  '{ "$or": [ {}, {"username": {"$ne": ""}} ] }'
];

module.exports = {
  getTestApp,
  getCsrfToken,
  createAuthenticatedAdmin,
  setupTestEnvironment,
  generateTestUser,
  generateTestResponse,
  generateTestContact,
  generateTestHandshake,
  generateTestInvitation,
  generateTestSubmission,
  validateResponseStructure,
  validateErrorResponse,
  XSS_PAYLOADS,
  INJECTION_PAYLOADS
};