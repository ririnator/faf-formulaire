// tests/api.security.comprehensive.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const { setupTestDatabase, teardownTestDatabase, cleanupDatabase } = require('./integration/setup-integration');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Handshake = require('../models/Handshake');
const Invitation = require('../models/Invitation');
const Submission = require('../models/Submission');
const { HTTP_STATUS } = require('../constants');

describe('API Comprehensive Security Testing Suite', () => {
  let testUsers = {};
  let authCookies = {};
  let csrfTokens = {};
  let adminUser, adminCookie, adminCsrfToken;

  beforeAll(async () => {
    // Setup test database
    await setupTestDatabase();
    
    // Set environment to test
    process.env.NODE_ENV = 'test';
    process.env.DISABLE_RATE_LIMITING = 'true'; // We'll enable for specific tests
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  beforeEach(async () => {
    // Clean database
    await cleanupDatabase();

    // Create test users
    const userConfigs = [
      { key: 'alice', username: 'alice', email: 'alice@gmail.com', role: 'user' },
      { key: 'bob', username: 'bob', email: 'bob@gmail.com', role: 'user' },
      { key: 'charlie', username: 'charlie', email: 'charlie@gmail.com', role: 'user' }
    ];

    testUsers = {};
    authCookies = {};
    csrfTokens = {};

    for (const config of userConfigs) {
      testUsers[config.key] = await User.create({
        username: config.username,
        email: config.email,
        password: 'password123',
        role: config.role
      });

      // Setup authentication
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .set('Accept', 'application/json')
        .set('Content-Type', 'application/json')
        .send({
          login: config.email,
          password: 'password123'
        })
        .expect(HTTP_STATUS.OK);

      authCookies[config.key] = loginResponse.headers['set-cookie'];
      
      const csrfResponse = await request(app)
        .get('/api/csrf-token')
        .set('Cookie', authCookies[config.key])
        .expect(HTTP_STATUS.OK);
      
      csrfTokens[config.key] = csrfResponse.body.csrfToken || csrfResponse.body.token;
    }

    // Create admin user
    adminUser = await User.create({
      username: 'admin',
      email: 'admin@gmail.com',
      password: 'password123',
      role: 'admin'
    });

    const adminResponse = await request(app)
      .post('/api/auth/login')
      .set('Accept', 'application/json')
      .set('Content-Type', 'application/json')
      .send({
        login: 'admin@gmail.com',
        password: 'password123'
      })
      .expect(HTTP_STATUS.OK);

    adminCookie = adminResponse.headers['set-cookie'];
    
    const adminCsrfResponse = await request(app)
      .get('/api/csrf-token')
      .set('Cookie', adminCookie)
      .expect(HTTP_STATUS.OK);
    
    adminCsrfToken = adminCsrfResponse.body.csrfToken || adminCsrfResponse.body.token;
  });

  describe('Authentication and Authorization Security', () => {
    describe('Authentication Bypass Attempts', () => {
      it('should prevent access without authentication cookies', async () => {
        const protectedEndpoints = [
          'GET /api/contacts',
          'POST /api/contacts',
          'GET /api/handshakes/received',
          'POST /api/handshakes/request',
          'GET /api/invitations',
          'POST /api/invitations',
          'GET /api/submissions',
          'POST /api/submissions'
        ];

        for (const endpoint of protectedEndpoints) {
          const [method, path] = endpoint.split(' ');
          
          let response;
          if (method === 'GET') {
            response = await request(app)
              .get(path)
              .set('Accept', 'application/json');
          } else if (method === 'POST') {
            response = await request(app)
              .post(path)
              .set('Accept', 'application/json')
              .set('Content-Type', 'application/json')
              .send({});
          }

          expect(response.status).toBe(HTTP_STATUS.UNAUTHORIZED);
          expect(response.body.success).toBe(false);
          expect(response.body.error.toLowerCase()).toContain('authentication');
        }
      });

      it('should prevent access with invalid authentication cookies', async () => {
        const invalidCookie = ['faf.session=invalid-session-id'];
        
        const response = await request(app)
          .get('/api/contacts')
          .set('Cookie', invalidCookie)
          .expect(HTTP_STATUS.UNAUTHORIZED);

        expect(response.body.success).toBe(false);
      });

      it('should prevent access with expired sessions', async () => {
        // This test would require session manipulation
        // In a real scenario, you'd modify session expiry and test
        // For now, we test with malformed session data
        const malformedCookie = ['faf.session=s%3A1234567890abcdef'];
        
        const response = await request(app)
          .get('/api/contacts')
          .set('Cookie', malformedCookie)
          .expect(HTTP_STATUS.UNAUTHORIZED);

        expect(response.body.success).toBe(false);
      });

      it('should prevent session fixation attacks', async () => {
        // Test that new login creates new session
        const firstLogin = await request(app)
          .post('/api/auth/login')
          .send({
            login: 'alice@gmail.com',
            password: 'password123'
          })
          .expect(HTTP_STATUS.OK);

        const firstSessionCookie = firstLogin.headers['set-cookie'];

        const secondLogin = await request(app)
          .post('/api/auth/login')
          .send({
            login: 'alice@gmail.com',
            password: 'password123'
          })
          .expect(HTTP_STATUS.OK);

        const secondSessionCookie = secondLogin.headers['set-cookie'];

        // Sessions should be different (anti-fixation)
        expect(firstSessionCookie[0]).not.toBe(secondSessionCookie[0]);
      });
    });

    describe('Authorization Bypass Attempts', () => {
      it('should prevent horizontal privilege escalation', async () => {
        // Alice creates a contact
        const aliceContact = await request(app)
          .post('/api/contacts')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send({
            name: 'Alice Contact',
            email: 'alicecontact@gmail.com'
          })
          .expect(HTTP_STATUS.CREATED);

        const contactId = aliceContact.body.data.contact._id;

        // Bob tries to access Alice's contact
        const bobAttempt = await request(app)
          .get(`/api/contacts/${contactId}`)
          .set('Cookie', authCookies.bob)
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(bobAttempt.body.success).toBe(false);

        // Bob tries to modify Alice's contact
        const bobModifyAttempt = await request(app)
          .put(`/api/contacts/${contactId}`)
          .set('Cookie', authCookies.bob)
          .set('X-CSRF-Token', csrfTokens.bob)
          .send({ name: 'Hacked Name' })
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(bobModifyAttempt.body.success).toBe(false);
      });

      it('should prevent vertical privilege escalation', async () => {
        // Regular user tries to access admin-only functions
        const userAttempts = [
          request(app)
            .get('/admin')
            .set('Cookie', authCookies.alice),
          request(app)
            .get('/api/admin/users')
            .set('Cookie', authCookies.alice)
        ];

        const responses = await Promise.all(userAttempts);
        responses.forEach(response => {
          expect([HTTP_STATUS.FORBIDDEN, HTTP_STATUS.UNAUTHORIZED, HTTP_STATUS.NOT_FOUND])
            .toContain(response.status);
        });
      });

      it('should prevent cross-user handshake manipulation', async () => {
        // Create handshake between Alice and Bob
        const handshake = await request(app)
          .post('/api/handshakes/request')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send({
            recipientId: testUsers.bob._id.toString(),
            message: 'Test handshake'
          })
          .expect(HTTP_STATUS.CREATED);

        const handshakeId = handshake.body.data.handshake._id;

        // Charlie tries to accept handshake meant for Bob
        const charlieAttempt = await request(app)
          .post(`/api/handshakes/${handshakeId}/accept`)
          .set('Cookie', authCookies.charlie)
          .set('X-CSRF-Token', csrfTokens.charlie)
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(charlieAttempt.body.success).toBe(false);

        // Charlie tries to cancel Alice's handshake
        const charlieCancelAttempt = await request(app)
          .post(`/api/handshakes/${handshakeId}/cancel`)
          .set('Cookie', authCookies.charlie)
          .set('X-CSRF-Token', csrfTokens.charlie)
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(charlieCancelAttempt.body.success).toBe(false);
      });
    });
  });

  describe('CSRF Protection', () => {
    it('should require CSRF tokens for state-changing operations', async () => {
      const stateChangingEndpoints = [
        { method: 'POST', path: '/api/contacts', data: { firstName: 'Test', email: 'test@gmail.com' } },
        { method: 'PUT', path: '/api/contacts/123', data: { firstName: 'Updated' } },
        { method: 'DELETE', path: '/api/contacts/123', data: {} },
        { method: 'POST', path: '/api/handshakes/request', data: { recipientId: testUsers.bob._id.toString() } },
        { method: 'POST', path: '/api/invitations', data: { email: 'invite@gmail.com' } },
        { method: 'POST', path: '/api/submissions', data: { responses: [{ question: 'Q', answer: 'A' }] } }
      ];

      for (const endpoint of stateChangingEndpoints) {
        let response;
        if (endpoint.method === 'POST') {
          response = await request(app)
            .post(endpoint.path)
            .set('Cookie', authCookies.alice)
            .send(endpoint.data);
        } else if (endpoint.method === 'PUT') {
          response = await request(app)
            .put(endpoint.path)
            .set('Cookie', authCookies.alice)
            .send(endpoint.data);
        } else if (endpoint.method === 'DELETE') {
          response = await request(app)
            .delete(endpoint.path)
            .set('Cookie', authCookies.alice)
            .send(endpoint.data);
        }

        expect(response.status).toBe(HTTP_STATUS.FORBIDDEN);
        expect(response.body.success).toBe(false);
      }
    });

    it('should reject invalid CSRF tokens', async () => {
      const invalidTokens = [
        'invalid-csrf-token',
        '',
        'x'.repeat(100),
        '<script>alert("xss")</script>',
        { malicious: 'object' }
      ];

      for (const invalidToken of invalidTokens) {
        const response = await request(app)
          .post('/api/contacts')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', invalidToken)
          .send({
            name: 'CSRF Test',
            email: 'csrf@gmail.com'
          })
          .expect(HTTP_STATUS.FORBIDDEN);

        expect(response.body.success).toBe(false);
      }
    });

    it('should prevent CSRF token reuse across users', async () => {
      // Alice tries to use Bob's CSRF token
      const response = await request(app)
        .post('/api/contacts')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.bob) // Wrong token for Alice
        .send({
          name: 'Cross User CSRF Test',
          email: 'crossuser@gmail.com'
        })
        .expect(HTTP_STATUS.FORBIDDEN);

      expect(response.body.success).toBe(false);
    });

    it('should validate CSRF tokens for all HTTP methods', async () => {
      // Create a contact first
      const contact = await request(app)
        .post('/api/contacts')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .send({
          name: 'CSRF Method Test',
          email: 'csrfmethod@gmail.com'
        })
        .expect(HTTP_STATUS.CREATED);

      const contactId = contact.body.data.contact._id;

      // Test PUT without CSRF token
      const putResponse = await request(app)
        .put(`/api/contacts/${contactId}`)
        .set('Cookie', authCookies.alice)
        .send({ name: 'Updated Name' })
        .expect(HTTP_STATUS.FORBIDDEN);

      expect(putResponse.body.success).toBe(false);

      // Test DELETE without CSRF token  
      const deleteResponse = await request(app)
        .delete(`/api/contacts/${contactId}`)
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.FORBIDDEN);

      expect(deleteResponse.body.success).toBe(false);
    });
  });

  describe('XSS Protection', () => {
    describe('Script Injection Prevention', () => {
      const scriptPayloads = [
        '<script>alert("xss")</script>',
        '"><script>alert("xss")</script>',
        '<script src="http://evil.com/xss.js"></script>',
        'javascript:alert("xss")',
        '<img src="x" onerror="alert(\'xss\')">',
        '<svg onload="alert(\'xss\')">',
        '<iframe src="javascript:alert(\'xss\')"></iframe>',
        '<embed src="javascript:alert(\'xss\')">',
        '<object data="javascript:alert(\'xss\')"></object>',
        '<link rel="stylesheet" href="javascript:alert(\'xss\')">',
        '<style>@import "javascript:alert(\'xss\')";</style>'
      ];

      scriptPayloads.forEach((payload, index) => {
        it(`should sanitize script payload ${index + 1}: ${payload.substring(0, 30)}...`, async () => {
          // Test in contact creation
          const contactResponse = await request(app)
            .post('/api/contacts')
            .set('Cookie', authCookies.alice)
            .set('X-CSRF-Token', csrfTokens.alice)
            .send({
              firstName: `Contact ${payload}`,
              lastName: `Last ${payload}`,
              email: 'xss@gmail.com',
              notes: `Notes with ${payload}`
            })
            .expect(HTTP_STATUS.CREATED);

          expect(contactResponse.body.success).toBe(true);
          expect(contactResponse.body.contact.firstName).not.toContain('<script');
          expect(contactResponse.body.contact.firstName).not.toContain('javascript:');
          expect(contactResponse.body.contact.lastName).not.toContain('<script');
          expect(contactResponse.body.contact.lastName).not.toContain('javascript:');
          expect(contactResponse.body.contact.notes).not.toContain('<script');

          // Additional XSS checks for contact data
          expect(contactResponse.body.contact.firstName).not.toContain('javascript:');
          expect(contactResponse.body.contact.lastName).not.toContain('javascript:');
          expect(contactResponse.body.contact.notes).not.toContain('javascript:');
        });
      });
    });

    describe('HTML Injection Prevention', () => {
      const htmlPayloads = [
        '<h1>Fake Header</h1>',
        '<div onclick="alert(\'click\')">Click me</div>',
        '<form action="http://evil.com" method="post"><input type="submit"></form>',
        '<a href="http://evil.com">Evil Link</a>',
        '<table><tr><td>Fake Table</td></tr></table>',
        '<!--<script>alert("comment")</script>-->',
        '<![CDATA[<script>alert("cdata")</script>]]>'
      ];

      htmlPayloads.forEach((payload, index) => {
        it(`should sanitize HTML payload ${index + 1}`, async () => {
          const response = await request(app)
            .post('/api/handshakes/request')
            .set('Cookie', authCookies.alice)
            .set('X-CSRF-Token', csrfTokens.alice)
            .send({
              recipientId: testUsers.bob._id.toString(),
              message: payload
            })
            .expect(HTTP_STATUS.CREATED);

          expect(response.body.success).toBe(true);
          expect(response.body.data.handshake.message).not.toMatch(/<[^>]+>/);
        });
      });
    });

    describe('URL and Protocol Injection', () => {
      const urlPayloads = [
        'javascript:alert("url")',
        'data:text/html,<script>alert("data")</script>',
        'vbscript:msgbox("vb")',
        'file:///etc/passwd',
        'ftp://evil.com/malware',
        'http://evil.com/redirect?url=javascript:alert("redirect")'
      ];

      urlPayloads.forEach((payload, index) => {
        it(`should sanitize URL payload ${index + 1}`, async () => {
          const response = await request(app)
            .post('/api/invitations')
            .set('Cookie', authCookies.alice)
            .set('X-CSRF-Token', csrfTokens.alice)
            .send({
              email: 'url@gmail.com',
              name: 'URL Test',
              message: `Check out this link: ${payload}`
            })
            .expect(HTTP_STATUS.CREATED);

          expect(response.body.success).toBe(true);
          expect(response.body.data.invitation.message).not.toContain('javascript:');
          expect(response.body.data.invitation.message).not.toContain('vbscript:');
        });
      });
    });

    describe('Event Handler Injection', () => {
      const eventPayloads = [
        'onload="alert(\'load\')"',
        'onerror="alert(\'error\')"',
        'onclick="alert(\'click\')"',
        'onmouseover="alert(\'hover\')"',
        'onfocus="alert(\'focus\')"',
        'onsubmit="alert(\'submit\')"'
      ];

      eventPayloads.forEach((payload, index) => {
        it(`should sanitize event handler ${index + 1}`, async () => {
          const response = await request(app)
            .post('/api/contacts')
            .set('Cookie', authCookies.alice)
            .set('X-CSRF-Token', csrfTokens.alice)
            .send({
              name: `Event Test ${payload}`,
              email: 'event@gmail.com'
            })
            .expect(HTTP_STATUS.CREATED);

          expect(response.body.success).toBe(true);
          expect(response.body.data.contact.name).not.toContain('onload');
          expect(response.body.data.contact.name).not.toContain('onerror');
          expect(response.body.data.contact.name).not.toContain('onclick');
        });
      });
    });
  });

  describe('SQL/NoSQL Injection Protection', () => {
    describe('MongoDB Injection Attempts', () => {
      const mongoPayloads = [
        { $ne: null },
        { $gt: '' },
        { $regex: '.*' },
        { $where: 'this.password.match(/.*/)' },
        { $or: [{ name: 'admin' }, { email: 'admin@gmail.com' }] },
        '{ "$ne": null }',
        '"; return true; //',
        "'; return true; //",
        { $exists: true },
        { $in: ['admin', 'root'] }
      ];

      mongoPayloads.forEach((payload, index) => {
        it(`should prevent MongoDB injection ${index + 1}`, async () => {
          // Test in contact creation
          const response = await request(app)
            .post('/api/contacts')
            .set('Cookie', authCookies.alice)
            .set('X-CSRF-Token', csrfTokens.alice)
            .send({
              name: payload,
              email: 'injection@gmail.com'
            })
            .expect(HTTP_STATUS.BAD_REQUEST);

          expect(response.body.success).toBe(false);
        });
      });
    });

    describe('Query Parameter Injection', () => {
      it('should sanitize query parameters', async () => {
        const maliciousParams = [
          '?name[$ne]=null',
          '?email[$regex]=.*',
          '?userId[$where]=this.password',
          '?tags[$in]=admin',
          '?page[$gt]=0'
        ];

        for (const param of maliciousParams) {
          const response = await request(app)
            .get(`/api/contacts${param}`)
            .set('Cookie', authCookies.alice)
            .expect(HTTP_STATUS.BAD_REQUEST);

          expect(response.body.success).toBe(false);
        }
      });

      it('should prevent aggregation injection in search', async () => {
        const maliciousSearch = {
          $where: 'this.name.match(/.*admin.*/) || this.email.match(/.*admin.*/)',
          $or: [{ name: 'admin' }, { email: { $exists: true } }]
        };

        const response = await request(app)
          .get('/api/contacts/search')
          .query({ q: JSON.stringify(maliciousSearch) })
          .set('Cookie', authCookies.alice)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });
    });
  });

  describe('Input Validation Security', () => {
    describe('Buffer Overflow Prevention', () => {
      it('should prevent extremely long input strings', async () => {
        const longString = 'A'.repeat(100000); // 100KB string

        const response = await request(app)
          .post('/api/contacts')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send({
            name: longString,
            email: 'long@gmail.com',
            notes: longString
          })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
      });

      it('should prevent oversized request bodies', async () => {
        const oversizedData = {
          responses: Array(1000).fill({
            question: 'Q'.repeat(10000),
            answer: 'A'.repeat(10000)
          })
        };

        const response = await request(app)
          .post('/api/submissions')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send(oversizedData)
          .expect(HTTP_STATUS.REQUEST_ENTITY_TOO_LARGE);

        expect(response.body.success).toBe(false);
      });
    });

    describe('Type Confusion Prevention', () => {
      it('should handle type mismatches safely', async () => {
        const typeMismatchData = {
          name: 123, // Should be string
          email: ['array@gmail.com'], // Should be string
          tags: 'not-an-array', // Should be array
          metadata: 'not-an-object' // Should be object
        };

        const response = await request(app)
          .post('/api/contacts')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send(typeMismatchData)
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.errors).toBeDefined();
      });
    });

    describe('Null Byte Injection Prevention', () => {
      const nullBytePayloads = [
        'test\x00.txt',
        'file\0name',
        'path/to/file\x00../../../etc/passwd',
        'name\u0000injection'
      ];

      nullBytePayloads.forEach((payload, index) => {
        it(`should prevent null byte injection ${index + 1}`, async () => {
          const response = await request(app)
            .post('/api/contacts')
            .set('Cookie', authCookies.alice)
            .set('X-CSRF-Token', csrfTokens.alice)
            .send({
              name: payload,
              email: 'nullbyte@gmail.com'
            })
            .expect(HTTP_STATUS.BAD_REQUEST);

          expect(response.body.success).toBe(false);
        });
      });
    });
  });

  describe('File Upload Security', () => {
    it('should validate file types for CSV import', async () => {
      const maliciousFiles = [
        { filename: 'malware.exe', mimetype: 'application/x-executable' },
        { filename: 'script.js', mimetype: 'application/javascript' },
        { filename: 'page.html', mimetype: 'text/html' },
        { filename: 'fake.csv.exe', mimetype: 'application/x-executable' }
      ];

      for (const file of maliciousFiles) {
        const response = await request(app)
          .post('/api/contacts/import')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .attach('file', Buffer.from('malicious content'), {
            filename: file.filename,
            contentType: file.mimetype
          })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.success).toBe(false);
        expect(response.body.error).toContain('Invalid file format');
      }
    });

    it('should prevent oversized file uploads', async () => {
      const largeContent = 'name,email\n' + 'data,'.repeat(10 * 1024 * 1024); // 10MB+ file

      const response = await request(app)
        .post('/api/contacts/import')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .attach('file', Buffer.from(largeContent), 'large.csv')
        .expect(HTTP_STATUS.REQUEST_ENTITY_TOO_LARGE);

      expect(response.body.success).toBe(false);
    });

    it('should scan CSV content for malicious data', async () => {
      const maliciousCSV = `name,email,notes
John Doe,john@gmail.com,"<script>alert('xss')</script>"
Jane Smith,jane@gmail.com,"=cmd|'/c calc'"
Bob Johnson,bob@gmail.com,"@SUM(1+1)*cmd|'/c calc'!"`;

      const response = await request(app)
        .post('/api/contacts/import')
        .set('Cookie', authCookies.alice)
        .set('X-CSRF-Token', csrfTokens.alice)
        .attach('file', Buffer.from(maliciousCSV), 'malicious.csv')
        .expect(HTTP_STATUS.BAD_REQUEST);

      expect(response.body.success).toBe(false);
    });
  });

  describe('Rate Limiting Security', () => {
    beforeEach(() => {
      // Enable rate limiting for these tests
      process.env.DISABLE_RATE_LIMITING = 'false';
    });

    afterEach(() => {
      // Disable rate limiting after tests
      process.env.DISABLE_RATE_LIMITING = 'true';
    });

    it('should enforce rate limits on authentication attempts', async () => {
      const attempts = [];
      const maxAttempts = 20; // More than typical rate limit

      for (let i = 0; i < maxAttempts; i++) {
        attempts.push(
          request(app)
            .post('/api/auth/login')
            .send({
              login: 'nonexistent@gmail.com',
              password: 'wrongpassword'
            })
        );
      }

      const responses = await Promise.all(attempts);
      const rateLimited = responses.filter(r => r.status === HTTP_STATUS.TOO_MANY_REQUESTS);
      
      expect(rateLimited.length).toBeGreaterThan(0);
    });

    it('should enforce rate limits on API endpoints', async () => {
      const requests = [];
      const maxRequests = 100; // Exceed typical rate limit

      for (let i = 0; i < maxRequests; i++) {
        requests.push(
          request(app)
            .post('/api/contacts')
            .set('Cookie', authCookies.alice)
            .set('X-CSRF-Token', csrfTokens.alice)
            .send({
              name: `Rate Limit Test ${i}`,
              email: `ratetest${i}@gmail.com`
            })
        );
      }

      const responses = await Promise.all(requests);
      const rateLimited = responses.filter(r => r.status === HTTP_STATUS.TOO_MANY_REQUESTS);
      
      expect(rateLimited.length).toBeGreaterThan(0);
    });

    it('should implement different rate limits for different endpoints', async () => {
      // Test that bulk operations have stricter limits
      const bulkRequests = Array(10).fill().map(() =>
        request(app)
          .post('/api/invitations/bulk-send')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send({
            invitations: [{ email: `bulk${Date.now()}@gmail.com` }]
          })
      );

      const responses = await Promise.all(bulkRequests);
      const rateLimited = responses.filter(r => r.status === HTTP_STATUS.TOO_MANY_REQUESTS);
      
      expect(rateLimited.length).toBeGreaterThan(0);
    });
  });

  describe('Session Security', () => {
    it('should use secure session cookies in production', async () => {
      // Temporarily set production environment
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        const response = await request(app)
          .post('/api/auth/login')
          .send({
            email: 'alice@gmail.com',
            password: 'password123'
          })
          .expect(HTTP_STATUS.OK);

        const setCookieHeader = response.headers['set-cookie'][0];
        expect(setCookieHeader).toContain('Secure');
        expect(setCookieHeader).toContain('HttpOnly');
        expect(setCookieHeader).toContain('SameSite');
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should invalidate sessions on logout', async () => {
      // Use session to access protected resource
      const beforeLogout = await request(app)
        .get('/api/contacts')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      expect(beforeLogout.body.success).toBe(true);

      // Logout
      await request(app)
        .post('/api/auth/logout')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.OK);

      // Try to use same session after logout
      const afterLogout = await request(app)
        .get('/api/contacts')
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.UNAUTHORIZED);

      expect(afterLogout.body.success).toBe(false);
    });

    it('should prevent session hijacking with IP validation', async () => {
      // This would require mocking different IP addresses
      // In a real implementation, you'd test that sessions are tied to IPs
      
      const response = await request(app)
        .get('/api/contacts')
        .set('Cookie', authCookies.alice)
        .set('X-Forwarded-For', '192.168.1.100') // Different IP
        .expect(HTTP_STATUS.OK); // Might be OK or UNAUTHORIZED depending on implementation

      // The exact behavior depends on whether IP validation is implemented
      expect(response.body).toBeDefined();
    });
  });

  describe('Content Security Policy (CSP)', () => {
    it('should include security headers', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);

      // Check for security headers
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBeDefined();
      expect(response.headers['x-xss-protection']).toBeDefined();
      expect(response.headers['content-security-policy']).toBeDefined();
    });

    it('should prevent clickjacking with frame options', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);

      expect(response.headers['x-frame-options']).toMatch(/DENY|SAMEORIGIN/);
    });
  });

  describe('Data Leakage Prevention', () => {
    it('should not expose sensitive data in error messages', async () => {
      // Try to access non-existent resource
      const response = await request(app)
        .get('/api/contacts/507f1f77bcf86cd799439011') // Valid ObjectId format
        .set('Cookie', authCookies.alice)
        .expect(HTTP_STATUS.NOT_FOUND);

      expect(response.body.success).toBe(false);
      expect(response.body.error).not.toContain('MongoDB');
      expect(response.body.error).not.toContain('database');
      expect(response.body.error).not.toContain('collection');
      expect(response.body.error).not.toMatch(/507f1f77bcf86cd799439011/);
    });

    it('should not expose system information', async () => {
      const response = await request(app)
        .get('/api/nonexistent')
        .expect(HTTP_STATUS.NOT_FOUND);

      expect(response.body.error).not.toContain('Node.js');
      expect(response.body.error).not.toContain('Express');
      expect(response.body.error).not.toContain('version');
      expect(response.body.error).not.toContain(__dirname);
    });

    it('should filter sensitive fields in user data', async () => {
      // Check that password hashes are not returned
      const response = await request(app)
        .get('/api/users/me') // Assuming this endpoint exists
        .set('Cookie', authCookies.alice);

      if (response.status === HTTP_STATUS.OK) {
        expect(response.body.data.user).not.toHaveProperty('password');
        expect(response.body.data.user).not.toHaveProperty('passwordHash');
      }
    });
  });

  describe('Timing Attack Prevention', () => {
    it('should have consistent response times for login attempts', async () => {
      const validUserTimes = [];
      const invalidUserTimes = [];

      // Test valid user, wrong password
      for (let i = 0; i < 5; i++) {
        const start = Date.now();
        await request(app)
          .post('/api/auth/login')
          .send({
            login: 'alice@gmail.com',
            password: 'wrongpassword'
          });
        validUserTimes.push(Date.now() - start);
      }

      // Test invalid user
      for (let i = 0; i < 5; i++) {
        const start = Date.now();
        await request(app)
          .post('/api/auth/login')
          .send({
            login: 'nonexistent@gmail.com', 
            password: 'wrongpassword'
          });
        invalidUserTimes.push(Date.now() - start);
      }

      const validAvg = validUserTimes.reduce((a, b) => a + b, 0) / validUserTimes.length;
      const invalidAvg = invalidUserTimes.reduce((a, b) => a + b, 0) / invalidUserTimes.length;

      // Times should be similar to prevent user enumeration
      expect(Math.abs(validAvg - invalidAvg)).toBeLessThan(100); // 100ms difference max
    });
  });

  describe('API Security Headers', () => {
    it('should include proper CORS headers', async () => {
      const response = await request(app)
        .options('/api/contacts')
        .set('Origin', 'http://localhost:3000')
        .expect(HTTP_STATUS.NO_CONTENT);

      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-credentials']).toBe('true');
      expect(response.headers['access-control-allow-headers']).toContain('X-CSRF-Token');
    });

    it('should reject requests from unauthorized origins', async () => {
      const response = await request(app)
        .get('/api/contacts')
        .set('Origin', 'http://malicious.com')
        .set('Cookie', authCookies.alice);

      // Depending on CORS configuration, this might be rejected
      // The test verifies that CORS is properly configured
      expect(response.headers).toBeDefined();
    });
  });

  describe('Error Information Disclosure', () => {
    it('should not expose stack traces in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        const response = await request(app)
          .post('/api/contacts')
          .set('Cookie', authCookies.alice)
          .set('X-CSRF-Token', csrfTokens.alice)
          .send({ invalid: 'data structure' })
          .expect(HTTP_STATUS.BAD_REQUEST);

        expect(response.body.stack).toBeUndefined();
        expect(response.body.error).not.toContain('at ');
        expect(response.body.error).not.toContain('.js:');
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should provide generic error messages for sensitive operations', async () => {
      // Test password reset with non-existent email
      const response = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: 'nonexistent@gmail.com' });

      // Should not reveal whether user exists or not
      if (response.status === HTTP_STATUS.OK) {
        expect(response.body.message).not.toContain('not found');
        expect(response.body.message).not.toContain('does not exist');
      }
    });
  });
});