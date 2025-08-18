// Test authentication helper for API tests
const User = require('../../models/User');

/**
 * Creates a test authentication middleware that bypasses session issues
 * and directly injects the user into the request
 */
function createTestAuthMiddleware(userId) {
  return async (req, res, next) => {
    if (process.env.NODE_ENV === 'test' && userId) {
      try {
        const user = await User.findById(userId);
        if (user) {
          // Inject user data similar to enrichUserData middleware
          req.currentUser = user;
          req.user = user;
          req.session = req.session || {};
          req.session.userId = userId;
          req.session.user = user.toPublicJSON();
          
          // Debug: Log user ID extraction (disabled)
          // console.log('Test auth - User ID extraction:', ...);
        }
      } catch (error) {
        console.warn('Test auth middleware error:', error.message);
      }
    }
    next();
  };
}

/**
 * Simulates authentication for supertest requests
 */
async function authenticateRequest(app, user) {
  const request = require('supertest');
  
  // Login to get session
  const loginResponse = await request(app)
    .post('/api/auth/login')
    .send({
      login: user.email,
      password: 'password123'
    });
    
  if (loginResponse.status !== 200) {
    throw new Error(`Login failed: ${loginResponse.status} ${JSON.stringify(loginResponse.body)}`);
  }
  
  const authCookie = loginResponse.headers['set-cookie'];
  
  // Get CSRF token
  const csrfResponse = await request(app)
    .get('/api/csrf-token')
    .set('Cookie', authCookie);
    
  if (csrfResponse.status !== 200) {
    throw new Error(`CSRF token failed: ${csrfResponse.status} ${JSON.stringify(csrfResponse.body)}`);
  }
  
  return {
    cookie: authCookie,
    csrfToken: csrfResponse.body.csrfToken || csrfResponse.body.token,
    user: loginResponse.body.user
  };
}

/**
 * Creates authenticated supertest agent with proper session and CSRF token
 */
async function createAuthenticatedAgent(app, user) {
  const request = require('supertest');
  
  // Create a supertest agent that maintains cookies across requests
  const agent = request.agent(app);
  
  // Login to establish session
  const loginResponse = await agent
    .post('/api/auth/login')
    .send({
      login: user.email,
      password: 'password123'
    });
    
  if (loginResponse.status !== 200) {
    throw new Error(`Login failed: ${loginResponse.status} ${JSON.stringify(loginResponse.body)}`);
  }
  
  // Get CSRF token using the same agent (maintains session)
  const csrfResponse = await agent.get('/api/csrf-token');
    
  if (csrfResponse.status !== 200) {
    throw new Error(`CSRF token failed: ${csrfResponse.status} ${JSON.stringify(csrfResponse.body)}`);
  }
  
  const csrfToken = csrfResponse.body.csrfToken || csrfResponse.body.token;
  
  // Return agent with helper methods that include CSRF token
  return {
    get: (path) => agent.get(path),
    post: (path) => agent.post(path).set('X-CSRF-Token', csrfToken),
    put: (path) => agent.put(path).set('X-CSRF-Token', csrfToken),
    delete: (path) => agent.delete(path).set('X-CSRF-Token', csrfToken),
    agent: agent,
    csrfToken: csrfToken,
    user: loginResponse.body.user
  };
}

module.exports = {
  createTestAuthMiddleware,
  authenticateRequest,
  createAuthenticatedAgent
};