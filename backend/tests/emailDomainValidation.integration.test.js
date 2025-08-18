const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const User = require('../models/User');
const Contact = require('../models/Contact');
const { emailConfig } = require('../middleware/emailDomainValidation');

describe('Email Domain Validation Integration Tests', () => {
  let server;
  let testUser;
  let sessionCookie;

  beforeAll(async () => {
    // Connect to test database
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-test');
    }
    
    server = app.listen(0); // Use random port for testing
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
    await mongoose.connection.close();
  });

  beforeEach(async () => {
    // Clean up test data
    await User.deleteMany({});
    await Contact.deleteMany({});
    
    // Reset email config
    emailConfig.allowedDomains.clear();
    emailConfig.blockedDomains.clear();
    
    // Create test user for authenticated endpoints
    testUser = new User({
      username: 'testuser',
      email: 'testuser@example.com',
      password: 'password123',
      role: 'user'
    });
    await testUser.save();

    // Get session cookie for authenticated requests
    const loginResponse = await request(app)
      .post('/api/auth/login')
      .send({
        login: 'testuser@example.com',
        password: 'password123'
      });

    sessionCookie = loginResponse.headers['set-cookie'];
  });

  describe('User Registration with Email Domain Validation', () => {
    test('should allow registration with legitimate email domains', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'newuser',
          email: 'newuser@gmail.com',
          password: 'password123'
        });

      expect(response.status).toBe(201);
      expect(response.body.message).toContain('succès');
      expect(response.body.user.email).toBe('newuser@gmail.com');
    });

    test('should block registration with disposable email domains', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'spammer',
          email: 'spammer@10minutemail.com',
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Email non autorisé');
      expect(response.body.code).toBe('DISPOSABLE_DOMAIN');
      expect(response.body.message).toContain('temporaires');
    });

    test('should block registration with suspicious pattern domains', async () => {
      const suspiciousEmails = [
        'user@tempmail.test',
        'user@10mail.test',
        'user@disposable.test'
      ];

      for (const email of suspiciousEmails) {
        const response = await request(app)
          .post('/api/auth/register')
          .send({
            username: `user${Date.now()}`,
            email: email,
            password: 'password123'
          });

        expect(response.status).toBe(400);
        expect(response.body.code).toBe('SUSPICIOUS_PATTERN');
      }
    });

    test('should allow whitelisted domains even if suspicious', async () => {
      // Add suspicious domain to whitelist
      emailConfig.allowDomain('tempmail.test');

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'whitelisteduser',
          email: 'user@tempmail.test',
          password: 'password123'
        });

      expect(response.status).toBe(201);
      expect(response.body.message).toContain('succès');
    });

    test('should block custom blacklisted domains', async () => {
      // Add legitimate domain to blacklist
      emailConfig.blockDomain('blockedcompany.com');

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'blockeduser',
          email: 'user@blockedcompany.com',
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('BLACKLISTED');
    });
  });

  describe('Contact Creation with Email Domain Validation', () => {
    test('should allow creating contacts with legitimate email domains', async () => {
      const response = await request(app)
        .post('/api/contacts')
        .set('Cookie', sessionCookie)
        .send({
          email: 'contact@company.com',
          firstName: 'John',
          lastName: 'Doe',
          notes: 'Business contact'
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.contact.email).toBe('contact@company.com');
    });

    test('should block creating contacts with disposable email domains', async () => {
      const response = await request(app)
        .post('/api/contacts')
        .set('Cookie', sessionCookie)
        .send({
          email: 'temp@guerrillamail.com',
          firstName: 'Temp',
          lastName: 'User'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Email non autorisé');
      expect(response.body.code).toBe('DISPOSABLE_DOMAIN');
    });

    test('should block contacts with suspicious pattern domains', async () => {
      const response = await request(app)
        .post('/api/contacts')
        .set('Cookie', sessionCookie)
        .send({
          email: 'contact@trashmail.test',
          firstName: 'Suspicious',
          lastName: 'Contact'
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('SUSPICIOUS_PATTERN');
    });

    test('should validate email domain when updating contact email', async () => {
      // First create a contact with valid email
      const createResponse = await request(app)
        .post('/api/contacts')
        .set('Cookie', sessionCookie)
        .send({
          email: 'original@company.com',
          firstName: 'John',
          lastName: 'Doe'
        });

      const contactId = createResponse.body.contact._id;

      // Try to update with disposable email
      const updateResponse = await request(app)
        .put(`/api/contacts/${contactId}`)
        .set('Cookie', sessionCookie)
        .send({
          email: 'updated@mailinator.com'
        });

      expect(updateResponse.status).toBe(400);
      expect(updateResponse.body.code).toBe('DISPOSABLE_DOMAIN');
    });

    test('should allow updating contact without changing email', async () => {
      // First create a contact
      const createResponse = await request(app)
        .post('/api/contacts')
        .set('Cookie', sessionCookie)
        .send({
          email: 'contact@company.com',
          firstName: 'John',
          lastName: 'Doe'
        });

      const contactId = createResponse.body.contact._id;

      // Update without changing email
      const updateResponse = await request(app)
        .put(`/api/contacts/${contactId}`)
        .set('Cookie', sessionCookie)
        .send({
          firstName: 'Jane',
          notes: 'Updated notes'
        });

      expect(updateResponse.status).toBe(200);
      expect(updateResponse.body.success).toBe(true);
    });
  });

  describe('CSV Import with Email Domain Validation', () => {
    test('should filter out disposable emails during CSV import', async () => {
      const csvData = `email,firstName,lastName
legitimate@company.com,John,Doe
spam@10minutemail.com,Spam,User
valid@outlook.com,Jane,Smith
temp@yopmail.com,Temp,User`;

      const response = await request(app)
        .post('/api/contacts/import')
        .set('Cookie', sessionCookie)
        .send({
          csvData: csvData,
          options: {
            skipDuplicates: true
          }
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      
      // Should only import legitimate emails
      expect(response.body.imported.length).toBe(2);
      expect(response.body.errors.length).toBeGreaterThan(0);
      
      // Check that legitimate emails were imported
      const importedEmails = response.body.imported.map(contact => contact.email);
      expect(importedEmails).toContain('legitimate@company.com');
      expect(importedEmails).toContain('valid@outlook.com');
      expect(importedEmails).not.toContain('spam@10minutemail.com');
      expect(importedEmails).not.toContain('temp@yopmail.com');
    });

    test('should provide detailed error information for blocked emails', async () => {
      const csvData = `email,firstName,lastName
blocked@mailinator.com,Blocked,User`;

      const response = await request(app)
        .post('/api/contacts/import')
        .set('Cookie', sessionCookie)
        .send({
          csvData: csvData
        });

      expect(response.status).toBe(200);
      expect(response.body.errors.length).toBe(1);
      expect(response.body.errors[0].email).toBe('blocked@mailinator.com');
      expect(response.body.errors[0].error).toContain('non autorisé');
    });
  });

  describe('Error Handling and Logging', () => {
    test('should handle network errors gracefully during MX validation', async () => {
      // Test with a domain that will cause DNS resolution to fail
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'testuser2',
          email: 'user@nonexistentdomain12345.invalid',
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('DOMAIN_NOT_EXISTS');
    });

    test('should proceed if email validation service is down', async () => {
      // Mock DNS resolution to throw an error
      const dns = require('dns').promises;
      const originalResolveMx = dns.resolveMx;
      dns.resolveMx = jest.fn().mockRejectedValue(new Error('DNS service unavailable'));

      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'failsafeuser',
          email: 'user@example.com',
          password: 'password123'
        });

      // Should still allow registration to avoid blocking legitimate users
      expect(response.status).toBe(201);

      // Restore original function
      dns.resolveMx = originalResolveMx;
    });
  });

  describe('Configuration Management', () => {
    test('should respect environment variable configuration', async () => {
      // Test that configuration from environment variables is respected
      const originalEnv = process.env.EMAIL_DISPOSABLE_CHECK;
      process.env.EMAIL_DISPOSABLE_CHECK = 'false';

      // Reload the module to pick up new env var
      delete require.cache[require.resolve('../middleware/emailDomainValidation')];
      const { EmailDomainConfig } = require('../middleware/emailDomainValidation');
      const config = new EmailDomainConfig();

      expect(config.enableDisposableCheck).toBe(false);

      // Restore original value
      process.env.EMAIL_DISPOSABLE_CHECK = originalEnv;
    });

    test('should handle comma-separated domain lists from environment', async () => {
      const originalWhitelist = process.env.EMAIL_DOMAIN_WHITELIST;
      process.env.EMAIL_DOMAIN_WHITELIST = 'trusted1.com,trusted2.com,trusted3.com';

      // Reload configuration
      delete require.cache[require.resolve('../config/environment')];
      const EnvironmentConfig = require('../config/environment');
      const config = EnvironmentConfig.getConfig();

      expect(config.services.emailValidation.whitelist).toEqual([
        'trusted1.com',
        'trusted2.com', 
        'trusted3.com'
      ]);

      // Restore original value
      process.env.EMAIL_DOMAIN_WHITELIST = originalWhitelist;
    });
  });

  describe('Performance under load', () => {
    test('should handle multiple concurrent email validations', async () => {
      const registrationPromises = [];
      
      for (let i = 0; i < 10; i++) {
        registrationPromises.push(
          request(app)
            .post('/api/auth/register')
            .send({
              username: `user${i}`,
              email: `user${i}@gmail.com`,
              password: 'password123'
            })
        );
      }

      const responses = await Promise.all(registrationPromises);
      
      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(201);
      });
    });

    test('should handle mixed valid and invalid emails efficiently', async () => {
      const startTime = Date.now();
      
      const promises = [];
      const validEmails = ['user1@gmail.com', 'user2@yahoo.com', 'user3@outlook.com'];
      const invalidEmails = ['spam1@mailinator.com', 'spam2@10minutemail.com', 'spam3@guerrillamail.com'];
      
      [...validEmails, ...invalidEmails].forEach((email, index) => {
        promises.push(
          request(app)
            .post('/api/auth/register')
            .send({
              username: `user${index}`,
              email: email,
              password: 'password123'
            })
        );
      });

      const responses = await Promise.all(promises);
      const endTime = Date.now();
      
      // Should complete in reasonable time (under 5 seconds)
      expect(endTime - startTime).toBeLessThan(5000);
      
      // Valid emails should succeed, invalid should fail
      expect(responses.slice(0, 3).every(r => r.status === 201)).toBe(true);
      expect(responses.slice(3).every(r => r.status === 400)).toBe(true);
    });
  });

  describe('Security bypass prevention', () => {
    test('should not allow bypassing validation through case manipulation', async () => {
      const attempts = [
        'SPAM@MAILINATOR.COM',
        'Spam@MailinAtor.Com',
        'spam@MAILINATOR.com'
      ];

      for (const email of attempts) {
        const response = await request(app)
          .post('/api/auth/register')
          .send({
            username: `user${Date.now()}`,
            email: email,
            password: 'password123'
          });

        expect(response.status).toBe(400);
        expect(response.body.code).toBe('DISPOSABLE_DOMAIN');
      }
    });

    test('should not allow bypassing through URL encoding', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'encodeduser',
          email: 'user%40mailinator.com', // URL encoded @
          password: 'password123'
        });

      // Should be caught by express-validator email validation first
      expect(response.status).toBe(400);
    });

    test('should handle unicode domain names correctly', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'unicodeuser',
          email: 'user@société.fr',
          password: 'password123'
        });

      // Should handle unicode domains (may succeed or fail based on actual domain)
      expect([201, 400]).toContain(response.status);
    });
  });
});