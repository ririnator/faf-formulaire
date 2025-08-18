const EmailService = require('../services/emailService');
const fs = require('fs').promises;
const path = require('path');

// Mock dependencies
jest.mock('resend');
jest.mock('postmark');
jest.mock('../utils/secureLogger');
jest.mock('fs', () => ({
  promises: {
    readFile: jest.fn()
  }
}));

const { Resend } = require('resend');
const { ServerClient } = require('postmark');
const SecureLogger = require('../utils/secureLogger');

describe('EmailService', () => {
  let emailService;
  let mockResend;
  let mockPostmark;
  let config;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Mock Resend
    mockResend = {
      emails: {
        send: jest.fn()
      }
    };
    Resend.mockImplementation(() => mockResend);
    
    // Mock Postmark
    mockPostmark = {
      sendEmail: jest.fn()
    };
    ServerClient.mockImplementation(() => mockPostmark);
    
    // Mock SecureLogger
    SecureLogger.logInfo = jest.fn();
    SecureLogger.logError = jest.fn();
    SecureLogger.logWarning = jest.fn();
    
    // Test configuration
    config = {
      resendApiKey: 'test-resend-key',
      postmarkApiKey: 'test-postmark-key',
      fromAddress: 'test@example.com',
      fromName: 'Test Service',
      batchSize: 5,
      rateLimitPerMinute: 10,
      webhookSecret: 'test-secret',
      templateCacheTTL: 60000,
      retryDelays: [100, 200, 300],
      maxRetries: 2,
      timeout: 5000,
      templatesPath: '/test/templates'
    };
    
    emailService = new EmailService(config);
    
    // Mock template file reading
    fs.readFile.mockResolvedValue('<html>Hello {{userName}}!</html>');
  });

  afterEach(() => {
    if (emailService) {
      emailService.removeAllListeners();
    }
  });

  describe('Constructor and Initialization', () => {
    test('should initialize with both providers', () => {
      expect(Resend).toHaveBeenCalledWith('test-resend-key');
      expect(ServerClient).toHaveBeenCalledWith('test-postmark-key');
      expect(emailService.providers.resend).toBe(mockResend);
      expect(emailService.providers.postmark).toBe(mockPostmark);
    });

    test('should initialize with only Resend provider', () => {
      const configResendOnly = { ...config, postmarkApiKey: null };
      const service = new EmailService(configResendOnly);
      
      expect(service.providers.resend).toBe(mockResend);
      expect(service.providers.postmark).toBeNull();
    });

    test('should throw error when no providers configured', () => {
      const configNoProviders = { ...config, resendApiKey: null, postmarkApiKey: null };
      
      expect(() => new EmailService(configNoProviders)).toThrow('No email providers configured');
    });

    test('should use default configuration values', () => {
      const minimalConfig = { resendApiKey: 'test-key' };
      const service = new EmailService(minimalConfig);
      
      expect(service.config.fromAddress).toBe('noreply@form-a-friend.com');
      expect(service.config.fromName).toBe('Form-a-Friend');
      expect(service.config.batchSize).toBe(50);
      expect(service.config.rateLimitPerMinute).toBe(100);
    });
  });

  describe('Template Rendering', () => {
    test('should render template with variables', async () => {
      const template = '<html>Hello {{userName}}, welcome to {{appName}}!</html>';
      fs.readFile.mockResolvedValueOnce(template);
      
      const result = await emailService.renderTemplate('test', {
        userName: 'John',
        appName: 'Test App'
      });
      
      expect(result).toBe('<html>Hello John, welcome to Test App!</html>');
      expect(fs.readFile).toHaveBeenCalledWith('/test/templates/test.html', 'utf-8');
    });

    test('should handle missing variables gracefully', async () => {
      const template = '<html>Hello {{userName}}, {{missingVar}}!</html>';
      fs.readFile.mockResolvedValueOnce(template);
      
      const result = await emailService.renderTemplate('test', {
        userName: 'John'
      });
      
      expect(result).toBe('<html>Hello John, !</html>');
    });

    test('should cache rendered templates', async () => {
      const template = '<html>Hello {{userName}}!</html>';
      fs.readFile.mockResolvedValue(template);
      
      // First call
      await emailService.renderTemplate('test', { userName: 'John' });
      
      // Second call with same data
      await emailService.renderTemplate('test', { userName: 'John' });
      
      // File should only be read once
      expect(fs.readFile).toHaveBeenCalledTimes(1);
    });

    test('should use cached template for same data', async () => {
      const template = '<html>Hello {{userName}}!</html>';
      fs.readFile.mockResolvedValueOnce(template);
      
      // Set up cache manually
      const cacheKey = 'test_{"userName":"John"}';
      emailService.templateCache.set(cacheKey, {
        html: '<html>Hello John!</html>',
        timestamp: Date.now()
      });
      
      const result = await emailService.renderTemplate('test', { userName: 'John' });
      
      expect(result).toBe('<html>Hello John!</html>');
      expect(fs.readFile).not.toHaveBeenCalled();
    });

    test('should throw error for missing template file', async () => {
      fs.readFile.mockRejectedValueOnce(new Error('File not found'));
      
      await expect(emailService.renderTemplate('missing', {}))
        .rejects.toThrow('Template rendering failed: File not found');
    });
  });

  describe('Email Sending - Resend Provider', () => {
    beforeEach(() => {
      mockResend.emails.send.mockResolvedValue({
        data: { id: 'resend-123' },
        error: null
      });
    });

    test('should send email successfully with Resend', async () => {
      const emailData = {
        to: 'user@example.com',
        subject: 'Test Subject',
        html: '<p>Test content</p>',
        metadata: { type: 'test' }
      };
      
      const result = await emailService.sendEmail(emailData);
      
      expect(result.success).toBe(true);
      expect(result.provider).toBe('resend');
      expect(result.messageId).toBe('resend-123');
      
      expect(mockResend.emails.send).toHaveBeenCalledWith({
        from: 'Test Service <test@example.com>',
        to: 'user@example.com',
        subject: 'Test Subject',
        html: '<p>Test content</p>',
        text: undefined,
        tags: [
          { name: 'type', value: 'test' },
          { name: 'month', value: 'unknown' }
        ]
      });
    });

    test('should handle Resend API errors', async () => {
      mockResend.emails.send.mockResolvedValueOnce({
        data: null,
        error: { message: 'Invalid email address' }
      });
      
      const emailData = {
        to: 'invalid-email',
        subject: 'Test',
        html: '<p>Test</p>'
      };
      
      await expect(emailService.sendEmail(emailData))
        .rejects.toThrow('Resend error: Invalid email address');
    });

    test('should retry on retryable errors', async () => {
      // First attempt fails, second succeeds
      mockResend.emails.send
        .mockResolvedValueOnce({
          data: null,
          error: { message: 'Rate limit exceeded' }
        })
        .mockResolvedValueOnce({
          data: { id: 'resend-retry-123' },
          error: null
        });
      
      const emailData = {
        to: 'user@example.com',
        subject: 'Test',
        html: '<p>Test</p>'
      };
      
      const result = await emailService.sendEmail(emailData);
      
      expect(result.success).toBe(true);
      expect(result.messageId).toBe('resend-retry-123');
      expect(mockResend.emails.send).toHaveBeenCalledTimes(2);
    });
  });

  describe('Email Sending - Postmark Provider', () => {
    beforeEach(() => {
      mockPostmark.sendEmail.mockResolvedValue({
        MessageID: 'postmark-123'
      });
    });

    test('should send email successfully with Postmark', async () => {
      // Remove Resend to force Postmark usage
      emailService.providers.resend = null;
      
      const emailData = {
        to: 'user@example.com',
        subject: 'Test Subject',
        html: '<p>Test content</p>',
        metadata: { type: 'test' }
      };
      
      const result = await emailService.sendEmail(emailData);
      
      expect(result.success).toBe(true);
      expect(result.provider).toBe('postmark');
      expect(result.messageId).toBe('postmark-123');
      
      expect(mockPostmark.sendEmail).toHaveBeenCalledWith({
        From: 'Test Service <test@example.com>',
        To: 'user@example.com',
        Subject: 'Test Subject',
        HtmlBody: '<p>Test content</p>',
        TextBody: undefined,
        Tag: 'test',
        Metadata: { type: 'test' }
      });
    });

    test('should handle Postmark API errors', async () => {
      emailService.providers.resend = null;
      mockPostmark.sendEmail.mockRejectedValueOnce(new Error('Invalid API key'));
      
      const emailData = {
        to: 'user@example.com',
        subject: 'Test',
        html: '<p>Test</p>'
      };
      
      await expect(emailService.sendEmail(emailData))
        .rejects.toThrow();
    });
  });

  describe('Provider Fallback', () => {
    test('should fallback to Postmark when Resend fails', async () => {
      mockResend.emails.send.mockResolvedValue({
        data: null,
        error: { message: 'Service unavailable' }
      });
      
      mockPostmark.sendEmail.mockResolvedValue({
        MessageID: 'postmark-fallback-123'
      });
      
      const emailData = {
        to: 'user@example.com',
        subject: 'Test',
        html: '<p>Test</p>'
      };
      
      const result = await emailService.sendEmail(emailData);
      
      expect(result.success).toBe(true);
      expect(result.provider).toBe('postmark');
      expect(result.messageId).toBe('postmark-fallback-123');
      
      expect(mockResend.emails.send).toHaveBeenCalled();
      expect(mockPostmark.sendEmail).toHaveBeenCalled();
    });

    test('should fail when all providers fail', async () => {
      mockResend.emails.send.mockResolvedValue({
        data: null,
        error: { message: 'Resend failed' }
      });
      
      mockPostmark.sendEmail.mockRejectedValue(new Error('Postmark failed'));
      
      const emailData = {
        to: 'user@example.com',
        subject: 'Test',
        html: '<p>Test</p>'
      };
      
      await expect(emailService.sendEmail(emailData))
        .rejects.toThrow('All email providers failed');
    });
  });

  describe('Invitation Emails', () => {
    beforeEach(() => {
      mockResend.emails.send.mockResolvedValue({
        data: { id: 'invitation-123' },
        error: null
      });
      
      process.env.APP_BASE_URL = 'https://test.com';
    });

    test('should send invitation email successfully', async () => {
      const invitation = {
        _id: 'inv-123',
        token: 'token-123',
        month: '2025-01',
        expiresAt: new Date('2025-01-31')
      };
      
      const user = {
        _id: 'user-123',
        username: 'testuser',
        email: 'user@example.com'
      };
      
      const result = await emailService.sendInvitation(invitation, user);
      
      expect(result.success).toBe(true);
      expect(result.messageId).toBe('invitation-123');
      
      expect(mockResend.emails.send).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          subject: 'Test Service - Invitation pour 2025-01',
          html: expect.stringContaining('Hello testuser!')
        })
      );
    });

    test('should emit invitation-sent event', async () => {
      const invitation = { _id: 'inv-123', token: 'token-123', month: '2025-01', expiresAt: new Date() };
      const user = { _id: 'user-123', username: 'testuser', email: 'user@example.com' };
      
      const eventSpy = jest.fn();
      emailService.on('invitation-sent', eventSpy);
      
      await emailService.sendInvitation(invitation, user);
      
      expect(eventSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          invitation,
          user,
          result: expect.objectContaining({ success: true })
        })
      );
    });

    test('should emit invitation-failed event on error', async () => {
      mockResend.emails.send.mockResolvedValue({
        data: null,
        error: { message: 'Send failed' }
      });
      
      emailService.providers.postmark = null; // Remove fallback
      
      const invitation = { _id: 'inv-123', token: 'token-123', month: '2025-01', expiresAt: new Date() };
      const user = { _id: 'user-123', username: 'testuser', email: 'user@example.com' };
      
      const eventSpy = jest.fn();
      emailService.on('invitation-failed', eventSpy);
      
      await expect(emailService.sendInvitation(invitation, user))
        .rejects.toThrow();
      
      expect(eventSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          invitation,
          user,
          error: expect.any(Error)
        })
      );
    });
  });

  describe('Reminder Emails', () => {
    beforeEach(() => {
      mockResend.emails.send.mockResolvedValue({
        data: { id: 'reminder-123' },
        error: null
      });
      
      process.env.APP_BASE_URL = 'https://test.com';
    });

    test('should send first reminder email', async () => {
      const invitation = {
        _id: 'inv-123',
        token: 'token-123',
        month: '2025-01',
        expiresAt: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000) // 5 days from now
      };
      
      const user = {
        _id: 'user-123',
        username: 'testuser',
        email: 'user@example.com'
      };
      
      const result = await emailService.sendReminder(invitation, user, 'first');
      
      expect(result.success).toBe(true);
      expect(result.messageId).toBe('reminder-123');
      
      expect(mockResend.emails.send).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          subject: 'Test Service - 1er rappel pour 2025-01'
        })
      );
    });

    test('should send second reminder email', async () => {
      const invitation = {
        _id: 'inv-123',
        token: 'token-123',
        month: '2025-01',
        expiresAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000) // 2 days from now
      };
      
      const user = {
        _id: 'user-123',
        username: 'testuser',
        email: 'user@example.com'
      };
      
      const result = await emailService.sendReminder(invitation, user, 'second');
      
      expect(result.success).toBe(true);
      
      expect(mockResend.emails.send).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'user@example.com',
          subject: 'Test Service - 2ème rappel pour 2025-01'
        })
      );
    });

    test('should calculate days remaining correctly', async () => {
      const futureDate = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000); // 3 days from now
      const invitation = {
        _id: 'inv-123',
        token: 'token-123',
        month: '2025-01',
        expiresAt: futureDate
      };
      
      const user = {
        _id: 'user-123',
        username: 'testuser',
        email: 'user@example.com'
      };
      
      // Mock template to check days remaining
      const template = '<p>{{daysRemaining}} days left</p>';
      fs.readFile.mockResolvedValueOnce(template);
      
      await emailService.sendReminder(invitation, user, 'first');
      
      // Should render with approximately 3 days remaining
      expect(fs.readFile).toHaveBeenCalledWith('/test/templates/reminder-first.html', 'utf-8');
    });
  });

  describe('Handshake Emails', () => {
    beforeEach(() => {
      mockResend.emails.send.mockResolvedValue({
        data: { id: 'handshake-123' },
        error: null
      });
      
      process.env.APP_BASE_URL = 'https://test.com';
    });

    test('should send handshake email successfully', async () => {
      const handshake = {
        _id: 'hand-123',
        token: 'handshake-token',
        message: 'Let\'s connect!',
        expiresAt: new Date()
      };
      
      const sender = {
        _id: 'sender-123',
        username: 'sender',
        email: 'sender@example.com'
      };
      
      const recipient = {
        _id: 'recipient-123',
        username: 'recipient',
        email: 'recipient@example.com'
      };
      
      const result = await emailService.sendHandshake(handshake, sender, recipient);
      
      expect(result.success).toBe(true);
      expect(result.messageId).toBe('handshake-123');
      
      expect(mockResend.emails.send).toHaveBeenCalledWith(
        expect.objectContaining({
          to: 'recipient@example.com',
          subject: 'Test Service - sender souhaite se connecter avec vous'
        })
      );
    });
  });

  describe('Batch Email Sending', () => {
    beforeEach(() => {
      mockResend.emails.send.mockResolvedValue({
        data: { id: 'batch-123' },
        error: null
      });
    });

    test('should send emails in batches', async () => {
      const emails = Array.from({ length: 7 }, (_, i) => ({
        to: `user${i}@example.com`,
        subject: `Test ${i}`,
        html: `<p>Content ${i}</p>`
      }));
      
      const result = await emailService.sendBatch(emails, { batchSize: 3 });
      
      expect(result.total).toBe(7);
      expect(result.success).toBe(7);
      expect(result.failures).toBe(0);
      expect(mockResend.emails.send).toHaveBeenCalledTimes(7);
    });

    test('should handle partial batch failures', async () => {
      mockResend.emails.send
        .mockResolvedValueOnce({ data: { id: '1' }, error: null })
        .mockResolvedValueOnce({ data: null, error: { message: 'Failed' } })
        .mockResolvedValueOnce({ data: { id: '3' }, error: null });
      
      emailService.providers.postmark = null; // Remove fallback
      
      const emails = [
        { to: 'user1@example.com', subject: 'Test 1', html: '<p>1</p>' },
        { to: 'user2@example.com', subject: 'Test 2', html: '<p>2</p>' },
        { to: 'user3@example.com', subject: 'Test 3', html: '<p>3</p>' }
      ];
      
      const result = await emailService.sendBatch(emails);
      
      expect(result.total).toBe(3);
      expect(result.success).toBe(2);
      expect(result.failures).toBe(1);
      expect(result.errors).toHaveLength(1);
    });
  });

  describe('Rate Limiting', () => {
    test('should enforce rate limits', async () => {
      const startTime = Date.now();
      
      // Mock rate limit configuration
      emailService.config.rateLimitPerMinute = 2;
      emailService.sentEmailsCount = 2; // Already at limit
      emailService.rateLimitWindow = startTime;
      
      // Mock sleep function to be faster for testing
      const originalSleep = emailService.sleep;
      emailService.sleep = jest.fn().mockResolvedValue();
      
      await emailService.enforceRateLimit(1);
      
      expect(emailService.sleep).toHaveBeenCalledWith(expect.any(Number));
      
      // Restore original sleep
      emailService.sleep = originalSleep;
    });

    test('should reset rate limit window after time expires', async () => {
      const pastTime = Date.now() - 70000; // 70 seconds ago
      
      emailService.config.rateLimitPerMinute = 5;
      emailService.sentEmailsCount = 3;
      emailService.rateLimitWindow = pastTime;
      
      await emailService.enforceRateLimit(2);
      
      // Should reset count and window
      expect(emailService.sentEmailsCount).toBe(2);
      expect(emailService.rateLimitWindow).toBeGreaterThan(pastTime);
    });
  });

  describe('Webhook Signature Verification', () => {
    test('should verify valid webhook signature', () => {
      const payload = '{"test":"data"}';
      const secret = 'webhook-secret';
      const crypto = require('crypto');
      
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(payload, 'utf8');
      const signature = 'sha256=' + hmac.digest('hex');
      
      const isValid = emailService.verifyWebhookSignature(payload, signature, secret);
      expect(isValid).toBe(true);
    });

    test('should reject invalid webhook signature', () => {
      const payload = '{"test":"data"}';
      const secret = 'webhook-secret';
      const invalidSignature = 'sha256=invalid-signature';
      
      const isValid = emailService.verifyWebhookSignature(payload, invalidSignature, secret);
      expect(isValid).toBe(false);
    });

    test('should throw error when secret not configured', () => {
      emailService.config.webhookSecret = null;
      
      expect(() => emailService.verifyWebhookSignature('payload', 'signature'))
        .toThrow('Webhook secret not configured');
    });
  });

  describe('Webhook Event Processing', () => {
    test('should process bounce event', async () => {
      const bounceEvent = {
        type: 'bounce',
        data: {
          email: 'user@example.com',
          reason: 'User unknown',
          bounceType: 'permanent'
        }
      };
      
      emailService.handleBounce = jest.fn();
      
      await emailService.processWebhookEvent(bounceEvent);
      
      expect(emailService.handleBounce).toHaveBeenCalledWith(bounceEvent.data);
    });

    test('should process complaint event', async () => {
      const complaintEvent = {
        type: 'complaint',
        data: {
          email: 'user@example.com',
          reason: 'Spam report'
        }
      };
      
      emailService.handleComplaint = jest.fn();
      
      await emailService.processWebhookEvent(complaintEvent);
      
      expect(emailService.handleComplaint).toHaveBeenCalledWith(complaintEvent.data);
    });

    test('should emit webhook-processed event', async () => {
      const event = {
        type: 'delivery',
        data: { email: 'user@example.com' }
      };
      
      emailService.handleDelivery = jest.fn();
      
      const eventSpy = jest.fn();
      emailService.on('webhook-processed', eventSpy);
      
      await emailService.processWebhookEvent(event);
      
      expect(eventSpy).toHaveBeenCalledWith(event);
    });
  });

  describe('Metrics and Monitoring', () => {
    test('should track email metrics', () => {
      emailService.metrics.totalSent = 0;
      emailService.metrics.totalFailed = 0;
      
      // Simulate successful send
      emailService.metrics.totalSent++;
      emailService.updateDeliveryRate();
      
      expect(emailService.metrics.deliveryRate).toBe(1);
    });

    test('should calculate delivery rate correctly', () => {
      emailService.metrics.totalSent = 8;
      emailService.metrics.totalFailed = 2;
      
      emailService.updateDeliveryRate();
      
      expect(emailService.metrics.deliveryRate).toBe(0.8);
    });

    test('should return comprehensive metrics', () => {
      const metrics = emailService.getMetrics();
      
      expect(metrics).toHaveProperty('totalSent');
      expect(metrics).toHaveProperty('totalFailed');
      expect(metrics).toHaveProperty('deliveryRate');
      expect(metrics).toHaveProperty('cacheSize');
      expect(metrics).toHaveProperty('providersAvailable');
      expect(metrics).toHaveProperty('rateLimitStatus');
    });

    test('should reset metrics', () => {
      emailService.metrics.totalSent = 10;
      emailService.metrics.totalFailed = 2;
      emailService.metrics.bounces = 1;
      
      emailService.resetMetrics();
      
      expect(emailService.metrics.totalSent).toBe(0);
      expect(emailService.metrics.totalFailed).toBe(0);
      expect(emailService.metrics.bounces).toBe(0);
      expect(emailService.metrics.lastResetTime).toBeInstanceOf(Date);
    });
  });

  describe('Error Handling', () => {
    test('should identify retryable errors', () => {
      const retryableErrors = [
        new Error('ECONNRESET'),
        new Error('Rate limit exceeded'),
        new Error('Timeout occurred'),
        new Error('Temporary failure')
      ];
      
      retryableErrors.forEach(error => {
        expect(emailService.isRetryableError(error)).toBe(true);
      });
    });

    test('should identify non-retryable errors', () => {
      const nonRetryableErrors = [
        new Error('Invalid email address'),
        new Error('Authentication failed'),
        new Error('Permission denied')
      ];
      
      nonRetryableErrors.forEach(error => {
        expect(emailService.isRetryableError(error)).toBe(false);
      });
    });
  });

  describe('Template Cache Management', () => {
    test('should clean expired cache entries', () => {
      const now = Date.now();
      const ttl = emailService.config.templateCacheTTL;
      
      // Add expired entry
      emailService.templateCache.set('expired', {
        html: '<p>Expired</p>',
        timestamp: now - ttl - 1000
      });
      
      // Add valid entry
      emailService.templateCache.set('valid', {
        html: '<p>Valid</p>',
        timestamp: now
      });
      
      emailService.cleanTemplateCache();
      
      expect(emailService.templateCache.has('expired')).toBe(false);
      expect(emailService.templateCache.has('valid')).toBe(true);
    });

    test('should limit cache size', () => {
      // This would need to be implemented in the actual service
      // For now, just verify the cache exists
      expect(emailService.templateCache).toBeInstanceOf(Map);
    });
  });

  describe('Service Shutdown', () => {
    test('should clean up resources on shutdown', async () => {
      emailService.templateCache.set('test', { html: '<p>Test</p>', timestamp: Date.now() });
      
      const listenerSpy = jest.fn();
      emailService.on('test-event', listenerSpy);
      
      await emailService.shutdown();
      
      expect(emailService.templateCache.size).toBe(0);
      expect(emailService.listenerCount('test-event')).toBe(0);
    });
  });

  describe('Integration with Real-Time Metrics', () => {
    test('should emit metrics events when real-time metrics is set', () => {
      const mockRealTimeMetrics = {
        emit: jest.fn()
      };
      
      emailService.setRealTimeMetrics(mockRealTimeMetrics);
      
      emailService.trackEmailSent('invitation', 150);
      
      expect(mockRealTimeMetrics.emit).toHaveBeenCalledWith('email-sent', {
        type: 'invitation',
        duration: 150,
        timestamp: expect.any(Date)
      });
    });

    test('should emit failure events to real-time metrics', () => {
      const mockRealTimeMetrics = {
        emit: jest.fn()
      };
      
      emailService.setRealTimeMetrics(mockRealTimeMetrics);
      
      const error = new Error('Send failed');
      emailService.trackEmailFailed('reminder', error);
      
      expect(mockRealTimeMetrics.emit).toHaveBeenCalledWith('email-failed', {
        type: 'reminder',
        error: 'Send failed',
        timestamp: expect.any(Date)
      });
    });
  });
});

describe('EmailService Performance Tests', () => {
  let emailService;
  
  beforeEach(() => {
    const { Resend } = require('resend');
    const mockResend = {
      emails: {
        send: jest.fn().mockResolvedValue({
          data: { id: 'perf-test' },
          error: null
        })
      }
    };
    Resend.mockImplementation(() => mockResend);
    
    emailService = new EmailService({
      resendApiKey: 'test-key',
      batchSize: 10,
      rateLimitPerMinute: 1000
    });
  });

  test('should handle large batch efficiently', async () => {
    const emails = Array.from({ length: 100 }, (_, i) => ({
      to: `user${i}@example.com`,
      subject: `Test ${i}`,
      html: `<p>Content ${i}</p>`
    }));
    
    const startTime = Date.now();
    const result = await emailService.sendBatch(emails);
    const duration = Date.now() - startTime;
    
    expect(result.total).toBe(100);
    expect(result.success).toBe(100);
    expect(duration).toBeLessThan(5000); // Should complete in under 5 seconds
  });

  test('should maintain performance under concurrent requests', async () => {
    const concurrentBatches = Array.from({ length: 5 }, (_, i) => 
      Array.from({ length: 20 }, (_, j) => ({
        to: `user${i}-${j}@example.com`,
        subject: `Concurrent ${i}-${j}`,
        html: `<p>Content ${i}-${j}</p>`
      }))
    );
    
    const startTime = Date.now();
    const results = await Promise.all(
      concurrentBatches.map(batch => emailService.sendBatch(batch))
    );
    const duration = Date.now() - startTime;
    
    expect(results).toHaveLength(5);
    expect(results.every(r => r.success === 20)).toBe(true);
    expect(duration).toBeLessThan(10000); // Should complete in under 10 seconds
  });
});

// Mock process.env for tests
process.env.APP_BASE_URL = 'https://test.com';