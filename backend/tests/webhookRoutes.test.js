const request = require('supertest');
const express = require('express');
const crypto = require('crypto');
const webhookRoutes = require('../routes/webhookRoutes');
const Contact = require('../models/Contact');
const User = require('../models/User');

// Mock dependencies
jest.mock('../models/Contact');
jest.mock('../models/User');
jest.mock('../utils/secureLogger');

const SecureLogger = require('../utils/secureLogger');

describe('Webhook Routes', () => {
  let app;
  const webhookSecret = 'test-webhook-secret';
  
  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Setup Express app
    app = express();
    app.use(express.json());
    app.use('/webhooks', webhookRoutes);
    
    // Mock environment
    process.env.EMAIL_WEBHOOK_SECRET = webhookSecret;
    
    // Mock SecureLogger
    SecureLogger.logInfo = jest.fn();
    SecureLogger.logError = jest.fn();
    SecureLogger.logWarning = jest.fn();
    
    // Mock Contact model
    Contact.findOne = jest.fn();
    
    // Mock User model
    User.findOne = jest.fn();
  });

  describe('Webhook Signature Verification', () => {
    const createValidSignature = (payload, secret = webhookSecret) => {
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(payload, 'utf8');
      return 'sha256=' + hmac.digest('hex');
    };

    test('should accept request with valid signature', async () => {
      const payload = { type: 'delivery', data: { email: 'test@example.com' } };
      const payloadString = JSON.stringify(payload);
      const signature = createValidSignature(payloadString);
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    test('should reject request with invalid signature', async () => {
      const payload = { type: 'delivery', data: { email: 'test@example.com' } };
      const invalidSignature = 'sha256=invalid-signature';
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', invalidSignature)
        .send(payload);
      
      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Invalid signature');
    });

    test('should reject request without signature', async () => {
      const payload = { type: 'delivery', data: { email: 'test@example.com' } };
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .send(payload);
      
      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Signature required');
    });

    test('should accept Authorization header as signature', async () => {
      const payload = { type: 'delivery', data: { email: 'test@example.com' } };
      const payloadString = JSON.stringify(payload);
      const signature = createValidSignature(payloadString);
      
      const response = await request(app)
        .post('/webhooks/email/postmark')
        .set('Authorization', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
    });
  });

  describe('Provider Detection', () => {
    const createValidRequest = (payload) => {
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      return {
        signature: 'sha256=' + signature,
        payload
      };
    };

    test('should detect Resend provider from URL', async () => {
      const { signature, payload } = createValidRequest({ 
        type: 'email.delivered', 
        data: { email: 'test@example.com' } 
      });
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(SecureLogger.logInfo).toHaveBeenCalledWith(
        'Webhook provider detected',
        expect.objectContaining({ provider: 'resend' })
      );
    });

    test('should detect Postmark provider from URL', async () => {
      const { signature, payload } = createValidRequest({
        Type: 'Delivery',
        Email: 'test@example.com'
      });
      
      const response = await request(app)
        .post('/webhooks/email/postmark')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(SecureLogger.logInfo).toHaveBeenCalledWith(
        'Webhook provider detected',
        expect.objectContaining({ provider: 'postmark' })
      );
    });

    test('should detect provider from User-Agent', async () => {
      const { signature, payload } = createValidRequest({ 
        type: 'delivery', 
        data: { email: 'test@example.com' } 
      });
      
      const response = await request(app)
        .post('/webhooks/email')
        .set('X-Webhook-Signature', signature)
        .set('User-Agent', 'Resend-Webhook/1.0')
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(SecureLogger.logInfo).toHaveBeenCalledWith(
        'Webhook provider detected',
        expect.objectContaining({ provider: 'resend' })
      );
    });
  });

  describe('Resend Webhook Processing', () => {
    const createResendRequest = (type, data) => {
      const payload = { type, data };
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      return {
        signature: 'sha256=' + signature,
        payload
      };
    };

    test('should process email bounce from Resend', async () => {
      const mockContact = {
        email: 'bounced@example.com',
        emailStatus: 'active',
        bounceCount: 0,
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      User.findOne.mockResolvedValue(null);
      
      const { signature, payload } = createResendRequest('email.bounced', {
        to: 'bounced@example.com',
        email_id: 'resend-123',
        created_at: '2025-01-01T00:00:00Z',
        bounce_reason: 'User unknown'
      });
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(Contact.findOne).toHaveBeenCalledWith({ email: 'bounced@example.com' });
      expect(mockContact.save).toHaveBeenCalled();
      expect(mockContact.emailStatus).toBe('bounced_permanent');
      expect(mockContact.isActive).toBe(false);
    });

    test('should process email complaint from Resend', async () => {
      const mockContact = {
        email: 'complained@example.com',
        emailStatus: 'active',
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      User.findOne.mockResolvedValue(null);
      
      const { signature, payload } = createResendRequest('email.complained', {
        to: 'complained@example.com',
        email_id: 'resend-456',
        created_at: '2025-01-01T00:00:00Z',
        complaint_reason: 'Spam report'
      });
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockContact.emailStatus).toBe('complained');
      expect(mockContact.optedOut).toBe(true);
      expect(mockContact.isActive).toBe(false);
    });

    test('should process email delivery from Resend', async () => {
      const mockContact = {
        email: 'delivered@example.com',
        emailStatus: 'sent',
        deliveryCount: 0,
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      
      const { signature, payload } = createResendRequest('email.delivered', {
        to: 'delivered@example.com',
        email_id: 'resend-789',
        created_at: '2025-01-01T00:00:00Z'
      });
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockContact.emailStatus).toBe('delivered');
      expect(mockContact.deliveryCount).toBe(1);
    });

    test('should ignore unknown Resend event types', async () => {
      const { signature, payload } = createResendRequest('email.unknown', {
        to: 'test@example.com',
        email_id: 'resend-unknown'
      });
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(response.body.processed).toBe(false);
      expect(SecureLogger.logWarning).toHaveBeenCalledWith(
        'Unknown Resend event type',
        { type: 'email.unknown' }
      );
    });
  });

  describe('Postmark Webhook Processing', () => {
    const createPostmarkRequest = (Type, Email, additionalData = {}) => {
      const payload = { Type, Email, MessageID: 'postmark-123', ...additionalData };
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      return {
        signature: 'sha256=' + signature,
        payload
      };
    };

    test('should process bounce from Postmark', async () => {
      const mockContact = {
        email: 'bounce@example.com',
        emailStatus: 'active',
        bounceCount: 0,
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      User.findOne.mockResolvedValue(null);
      
      const { signature, payload } = createPostmarkRequest('Bounce', 'bounce@example.com', {
        BouncedAt: '2025-01-01T00:00:00Z',
        Description: 'Mailbox does not exist',
        TypeCode: 1 // Hard bounce
      });
      
      const response = await request(app)
        .post('/webhooks/email/postmark')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockContact.emailStatus).toBe('bounced_permanent');
      expect(mockContact.isActive).toBe(false);
    });

    test('should process spam complaint from Postmark', async () => {
      const mockContact = {
        email: 'spam@example.com',
        emailStatus: 'active',
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      User.findOne.mockResolvedValue(null);
      
      const { signature, payload } = createPostmarkRequest('SpamComplaint', 'spam@example.com', {
        ReceivedAt: '2025-01-01T00:00:00Z',
        Details: 'User marked as spam'
      });
      
      const response = await request(app)
        .post('/webhooks/email/postmark')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockContact.emailStatus).toBe('complained');
      expect(mockContact.optedOut).toBe(true);
    });

    test('should process delivery from Postmark', async () => {
      const mockContact = {
        email: 'delivery@example.com',
        emailStatus: 'sent',
        deliveryCount: 0,
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      
      const { signature, payload } = createPostmarkRequest('Delivery', 'delivery@example.com', {
        ReceivedAt: '2025-01-01T00:00:00Z'
      });
      
      const response = await request(app)
        .post('/webhooks/email/postmark')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockContact.emailStatus).toBe('delivered');
    });
  });

  describe('Bounce Type Classification', () => {
    const createBounceRequest = (reason, bounceType = null) => {
      const payload = {
        type: 'email.bounced',
        data: {
          to: 'test@example.com',
          email_id: 'test-123',
          bounce_reason: reason,
          bounce_type: bounceType
        }
      };
      
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      return { signature: 'sha256=' + signature, payload };
    };

    test('should classify permanent bounces correctly', async () => {
      const mockContact = {
        email: 'test@example.com',
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      User.findOne.mockResolvedValue(null);
      
      const permanentReasons = [
        'User unknown',
        'Mailbox does not exist',
        'Domain not found'
      ];
      
      for (const reason of permanentReasons) {
        const { signature, payload } = createBounceRequest(reason);
        
        const response = await request(app)
          .post('/webhooks/email/resend')
          .set('X-Webhook-Signature', signature)
          .send(payload);
        
        expect(response.status).toBe(200);
        expect(mockContact.emailStatus).toBe('bounced_permanent');
        expect(mockContact.isActive).toBe(false);
        
        // Reset for next iteration
        mockContact.emailStatus = 'active';
        mockContact.isActive = true;
      }
    });

    test('should classify temporary bounces correctly', async () => {
      const mockContact = {
        email: 'test@example.com',
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      User.findOne.mockResolvedValue(null);
      
      const { signature, payload } = createBounceRequest('Mailbox temporarily full');
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockContact.emailStatus).toBe('bounced_temporary');
      expect(mockContact.isActive).toBe(true);
    });
  });

  describe('User Model Updates', () => {
    test('should update User model on bounce', async () => {
      const mockUser = {
        email: 'user@example.com',
        metadata: {},
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(null);
      User.findOne.mockResolvedValue(mockUser);
      
      const payload = {
        type: 'email.bounced',
        data: {
          to: 'user@example.com',
          email_id: 'test-123',
          bounce_reason: 'User unknown'
        }
      };
      
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockUser.metadata.emailBounced).toBe(true);
      expect(mockUser.metadata.bounceReason).toBe('User unknown');
      expect(mockUser.save).toHaveBeenCalled();
    });

    test('should update User model on complaint', async () => {
      const mockUser = {
        email: 'user@example.com',
        metadata: {},
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(null);
      User.findOne.mockResolvedValue(mockUser);
      
      const payload = {
        type: 'email.complained',
        data: {
          to: 'user@example.com',
          email_id: 'test-123',
          complaint_reason: 'Spam report'
        }
      };
      
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(mockUser.metadata.emailComplained).toBe(true);
      expect(mockUser.metadata.isActive).toBe(false);
      expect(mockUser.save).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    test('should handle database errors gracefully', async () => {
      Contact.findOne.mockRejectedValue(new Error('Database connection failed'));
      
      const payload = {
        type: 'email.bounced',
        data: {
          to: 'test@example.com',
          email_id: 'test-123',
          bounce_reason: 'User unknown'
        }
      };
      
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(SecureLogger.logError).toHaveBeenCalledWith(
        'Webhook processing failed',
        expect.objectContaining({
          error: 'Database connection failed'
        })
      );
    });

    test('should return 200 for permanent errors to prevent retries', async () => {
      const payload = {
        type: 'email.bounced',
        data: {
          to: 'invalid-email-format',
          email_id: 'test-123'
        }
      };
      
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(false);
    });

    test('should handle malformed webhook data', async () => {
      const payload = { invalid: 'data' };
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      const response = await request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', signature)
        .send(payload);
      
      expect(response.status).toBe(200);
      expect(response.body.processed).toBe(false);
    });
  });

  describe('Manual Unsubscribe Endpoint', () => {
    test('should process unsubscribe by email', async () => {
      const mockContact = {
        email: 'unsubscribe@example.com',
        optedOut: false,
        save: jest.fn().mockResolvedValue()
      };
      
      Contact.findOne.mockResolvedValue(mockContact);
      
      const response = await request(app)
        .get('/webhooks/unsubscribe')
        .query({ email: 'unsubscribe@example.com' });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(mockContact.optedOut).toBe(true);
      expect(mockContact.optOutReason).toBe('manual_unsubscribe');
      expect(mockContact.isActive).toBe(false);
    });

    test('should process unsubscribe by token', async () => {
      const Invitation = require('../models/Invitation');
      
      // Mock Invitation model
      jest.doMock('../models/Invitation', () => ({
        findOne: jest.fn()
      }));
      
      const mockInvitation = {
        token: 'test-token',
        userId: {
          email: 'token-user@example.com'
        }
      };
      
      const mockContact = {
        email: 'token-user@example.com',
        optedOut: false,
        save: jest.fn().mockResolvedValue()
      };
      
      Invitation.findOne = jest.fn().mockReturnValue({
        populate: jest.fn().mockResolvedValue(mockInvitation)
      });
      
      Contact.findOne.mockResolvedValue(mockContact);
      
      const response = await request(app)
        .get('/webhooks/unsubscribe')
        .query({ token: 'test-token' });
      
      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(mockContact.optedOut).toBe(true);
    });

    test('should return 404 for non-existent contact', async () => {
      Contact.findOne.mockResolvedValue(null);
      
      const response = await request(app)
        .get('/webhooks/unsubscribe')
        .query({ email: 'nonexistent@example.com' });
      
      expect(response.status).toBe(404);
      expect(response.body.success).toBe(false);
    });

    test('should return 400 for missing parameters', async () => {
      const response = await request(app)
        .get('/webhooks/unsubscribe');
      
      expect(response.status).toBe(400);
      expect(response.body.error).toBe('Email or token required');
    });
  });

  describe('Health Check Endpoint', () => {
    test('should return health status', async () => {
      const response = await request(app)
        .get('/webhooks/health');
      
      expect(response.status).toBe(200);
      expect(response.body.status).toBe('ok');
      expect(response.body.service).toBe('email-webhooks');
      expect(response.body.timestamp).toBeDefined();
    });
  });

  describe('Security Tests', () => {
    test('should log suspicious activity', async () => {
      const payload = { type: 'test' };
      
      const response = await request(app)
        .post('/webhooks/email/unknown')
        .set('User-Agent', 'SuspiciousBot/1.0')
        .send(payload);
      
      expect(response.status).toBe(401);
      expect(SecureLogger.logWarning).toHaveBeenCalledWith(
        'Webhook signature missing',
        expect.objectContaining({
          userAgent: 'SuspiciousBot/1.0'
        })
      );
    });

    test('should handle timing attacks safely', async () => {
      const payload = { type: 'test' };
      const payloadString = JSON.stringify(payload);
      
      // Test with various signature lengths
      const signatures = [
        'sha256=short',
        'sha256=' + 'a'.repeat(64),
        'sha256=' + 'b'.repeat(128)
      ];
      
      const times = [];
      
      for (const signature of signatures) {
        const start = Date.now();
        
        await request(app)
          .post('/webhooks/email/test')
          .set('X-Webhook-Signature', signature)
          .send(payload);
        
        times.push(Date.now() - start);
      }
      
      // Verify timing differences are minimal (should be constant time)
      const maxTime = Math.max(...times);
      const minTime = Math.min(...times);
      const timeDiff = maxTime - minTime;
      
      expect(timeDiff).toBeLessThan(50); // Less than 50ms difference
    });
  });
});

describe('Webhook Routes Load Tests', () => {
  let app;
  const webhookSecret = 'load-test-secret';
  
  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use('/webhooks', webhookRoutes);
    
    process.env.EMAIL_WEBHOOK_SECRET = webhookSecret;
    
    // Mock all dependencies for load testing
    Contact.findOne = jest.fn().mockResolvedValue({
      email: 'test@example.com',
      save: jest.fn().mockResolvedValue()
    });
    
    SecureLogger.logInfo = jest.fn();
    SecureLogger.logError = jest.fn();
    SecureLogger.logWarning = jest.fn();
  });

  test('should handle concurrent webhook requests', async () => {
    const createRequest = (i) => {
      const payload = {
        type: 'email.delivered',
        data: {
          to: `user${i}@example.com`,
          email_id: `test-${i}`
        }
      };
      
      const payloadString = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', webhookSecret)
        .update(payloadString, 'utf8')
        .digest('hex');
      
      return request(app)
        .post('/webhooks/email/resend')
        .set('X-Webhook-Signature', 'sha256=' + signature)
        .send(payload);
    };
    
    // Create 50 concurrent requests
    const requests = Array.from({ length: 50 }, (_, i) => createRequest(i));
    
    const startTime = Date.now();
    const responses = await Promise.all(requests);
    const duration = Date.now() - startTime;
    
    // All requests should succeed
    expect(responses.every(r => r.status === 200)).toBe(true);
    
    // Should complete within reasonable time
    expect(duration).toBeLessThan(5000); // 5 seconds
    
    // Should have processed all contacts
    expect(Contact.findOne).toHaveBeenCalledTimes(50);
  });

  test('should maintain performance under high load', async () => {
    const batchSize = 100;
    const batches = 3;
    
    for (let batch = 0; batch < batches; batch++) {
      const requests = Array.from({ length: batchSize }, (_, i) => {
        const payload = {
          type: 'email.bounced',
          data: {
            to: `batch${batch}-user${i}@example.com`,
            email_id: `batch-${batch}-${i}`,
            bounce_reason: 'Test bounce'
          }
        };
        
        const payloadString = JSON.stringify(payload);
        const signature = crypto.createHmac('sha256', webhookSecret)
          .update(payloadString, 'utf8')
          .digest('hex');
        
        return request(app)
          .post('/webhooks/email/resend')
          .set('X-Webhook-Signature', 'sha256=' + signature)
          .send(payload);
      });
      
      const startTime = Date.now();
      const responses = await Promise.all(requests);
      const duration = Date.now() - startTime;
      
      expect(responses.every(r => r.status === 200)).toBe(true);
      expect(duration).toBeLessThan(3000); // 3 seconds per batch
    }
  });
});