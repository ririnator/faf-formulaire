const { Resend } = require('resend');
const { ServerClient } = require('postmark');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const SecureLogger = require('../utils/secureLogger');
const RealTimeMetrics = require('./realTimeMetrics');

/**
 * Multi-Provider Email Service for Form-a-Friend v2
 * 
 * Features:
 * - Multi-provider support (Resend primary, Postmark fallback)
 * - Batch processing with rate limiting
 * - Responsive HTML email templates
 * - Webhook handling for bounces/unsubscribes
 * - Template caching with TTL
 * - Real-time metrics integration
 * - Comprehensive error handling and retry logic
 */
class EmailService extends EventEmitter {
  constructor(config = {}) {
    super();
    
    this.config = {
      resendApiKey: config.resendApiKey,
      postmarkApiKey: config.postmarkApiKey,
      fromAddress: config.fromAddress || 'noreply@form-a-friend.com',
      fromName: config.fromName || 'Form-a-Friend',
      batchSize: config.batchSize || 50,
      rateLimitPerMinute: config.rateLimitPerMinute || 100,
      webhookSecret: config.webhookSecret,
      templateCacheTTL: config.templateCacheTTL || 600000, // 10 minutes
      retryDelays: config.retryDelays || [1000, 5000, 15000],
      maxRetries: config.maxRetries || 3,
      timeout: config.timeout || 30000,
      templatesPath: config.templatesPath || path.join(__dirname, '../templates/emails'),
      ...config
    };

    // Initialize providers
    this.providers = {
      resend: null,
      postmark: null
    };

    this.initializeProviders();

    // Template cache
    this.templateCache = new Map();
    
    // Rate limiting
    this.sentEmailsCount = 0;
    this.rateLimitWindow = Date.now();
    
    // Metrics
    this.metrics = {
      totalSent: 0,
      totalFailed: 0,
      bounces: 0,
      unsubscribes: 0,
      deliveryRate: 0,
      lastResetTime: new Date()
    };

    // Real-time metrics integration
    this.realTimeMetrics = null;
    
    SecureLogger.logInfo('EmailService initialized', {
      hasResend: !!this.config.resendApiKey,
      hasPostmark: !!this.config.postmarkApiKey,
      batchSize: this.config.batchSize,
      rateLimit: this.config.rateLimitPerMinute
    });
  }

  /**
   * Initialize email service providers
   */
  initializeProviders() {
    try {
      if (this.config.resendApiKey) {
        this.providers.resend = new Resend(this.config.resendApiKey);
        SecureLogger.logInfo('Resend provider initialized');
      }

      if (this.config.postmarkApiKey) {
        this.providers.postmark = new ServerClient(this.config.postmarkApiKey);
        SecureLogger.logInfo('Postmark provider initialized');
      }

      if (!this.providers.resend && !this.providers.postmark) {
        throw new Error('No email providers configured. Please set RESEND_API_KEY or POSTMARK_API_KEY');
      }
    } catch (error) {
      SecureLogger.logError('Failed to initialize email providers', { error: error.message });
      throw error;
    }
  }

  /**
   * Set real-time metrics instance for performance tracking
   */
  setRealTimeMetrics(realTimeMetrics) {
    this.realTimeMetrics = realTimeMetrics;
    SecureLogger.logInfo('Real-time metrics integration enabled for EmailService');
  }

  /**
   * Send invitation email
   * @param {Object} invitation - Invitation data
   * @param {Object} user - User data
   * @param {Object} options - Additional options
   */
  async sendInvitation(invitation, user, options = {}) {
    const startTime = Date.now();
    
    try {
      const templateData = {
        userName: user.username || user.name,
        invitationToken: invitation.token,
        invitationUrl: `${process.env.APP_BASE_URL}/form?token=${invitation.token}`,
        expiresAt: new Date(invitation.expiresAt).toLocaleDateString('fr-FR'),
        month: invitation.month,
        fromName: this.config.fromName,
        appBaseUrl: process.env.APP_BASE_URL,
        unsubscribeUrl: options.unsubscribeUrl || `${process.env.APP_BASE_URL}/unsubscribe?token=${invitation.token}`
      };

      const html = await this.renderTemplate('invitation', templateData);
      const subject = `${this.config.fromName} - Invitation pour ${invitation.month}`;

      const emailData = {
        to: user.email,
        subject,
        html,
        metadata: {
          type: 'invitation',
          invitationId: invitation._id?.toString(),
          userId: user._id?.toString(),
          month: invitation.month
        }
      };

      const result = await this.sendEmail(emailData);
      
      // Track metrics
      this.trackEmailSent('invitation', Date.now() - startTime);
      this.emit('invitation-sent', { invitation, user, result });
      
      SecureLogger.logInfo('Invitation email sent successfully', {
        invitationId: invitation._id?.toString(),
        userEmail: user.email,
        provider: result.provider,
        messageId: result.messageId
      });

      return result;
    } catch (error) {
      this.trackEmailFailed('invitation', error);
      this.emit('invitation-failed', { invitation, user, error });
      
      SecureLogger.logError('Failed to send invitation email', {
        invitationId: invitation._id?.toString(),
        userEmail: user.email,
        error: error.message
      });
      
      throw error;
    }
  }

  /**
   * Send reminder email
   * @param {Object} invitation - Invitation data
   * @param {Object} user - User data
   * @param {string} reminderType - 'first' or 'second'
   * @param {Object} options - Additional options
   */
  async sendReminder(invitation, user, reminderType = 'first', options = {}) {
    const startTime = Date.now();
    
    try {
      const templateName = `reminder-${reminderType}`;
      const templateData = {
        userName: user.username || user.name,
        invitationToken: invitation.token,
        invitationUrl: `${process.env.APP_BASE_URL}/form?token=${invitation.token}`,
        expiresAt: new Date(invitation.expiresAt).toLocaleDateString('fr-FR'),
        month: invitation.month,
        fromName: this.config.fromName,
        appBaseUrl: process.env.APP_BASE_URL,
        reminderNumber: reminderType === 'first' ? '1er' : '2ème',
        daysRemaining: Math.ceil((new Date(invitation.expiresAt) - new Date()) / (1000 * 60 * 60 * 24)),
        unsubscribeUrl: options.unsubscribeUrl || `${process.env.APP_BASE_URL}/unsubscribe?token=${invitation.token}`
      };

      const html = await this.renderTemplate(templateName, templateData);
      const subject = `${this.config.fromName} - ${templateData.reminderNumber} rappel pour ${invitation.month}`;

      const emailData = {
        to: user.email,
        subject,
        html,
        metadata: {
          type: 'reminder',
          reminderType,
          invitationId: invitation._id?.toString(),
          userId: user._id?.toString(),
          month: invitation.month
        }
      };

      const result = await this.sendEmail(emailData);
      
      // Track metrics
      this.trackEmailSent('reminder', Date.now() - startTime);
      this.emit('reminder-sent', { invitation, user, reminderType, result });
      
      SecureLogger.logInfo('Reminder email sent successfully', {
        invitationId: invitation._id?.toString(),
        userEmail: user.email,
        reminderType,
        provider: result.provider,
        messageId: result.messageId
      });

      return result;
    } catch (error) {
      this.trackEmailFailed('reminder', error);
      this.emit('reminder-failed', { invitation, user, reminderType, error });
      
      SecureLogger.logError('Failed to send reminder email', {
        invitationId: invitation._id?.toString(),
        userEmail: user.email,
        reminderType,
        error: error.message
      });
      
      throw error;
    }
  }

  /**
   * Send handshake email
   * @param {Object} handshake - Handshake data
   * @param {Object} sender - Sender user data
   * @param {Object} recipient - Recipient user data
   * @param {Object} options - Additional options
   */
  async sendHandshake(handshake, sender, recipient, options = {}) {
    const startTime = Date.now();
    
    try {
      const templateData = {
        recipientName: recipient.username || recipient.name,
        senderName: sender.username || sender.name,
        message: handshake.message,
        handshakeUrl: `${process.env.APP_BASE_URL}/handshake?token=${handshake.token}`,
        expiresAt: new Date(handshake.expiresAt).toLocaleDateString('fr-FR'),
        fromName: this.config.fromName,
        appBaseUrl: process.env.APP_BASE_URL,
        unsubscribeUrl: options.unsubscribeUrl || `${process.env.APP_BASE_URL}/unsubscribe?email=${recipient.email}`
      };

      const html = await this.renderTemplate('handshake', templateData);
      const subject = `${this.config.fromName} - ${sender.username || sender.name} souhaite se connecter avec vous`;

      const emailData = {
        to: recipient.email,
        subject,
        html,
        metadata: {
          type: 'handshake',
          handshakeId: handshake._id?.toString(),
          senderId: sender._id?.toString(),
          recipientId: recipient._id?.toString()
        }
      };

      const result = await this.sendEmail(emailData);
      
      // Track metrics
      this.trackEmailSent('handshake', Date.now() - startTime);
      this.emit('handshake-sent', { handshake, sender, recipient, result });
      
      SecureLogger.logInfo('Handshake email sent successfully', {
        handshakeId: handshake._id?.toString(),
        senderEmail: sender.email,
        recipientEmail: recipient.email,
        provider: result.provider,
        messageId: result.messageId
      });

      return result;
    } catch (error) {
      this.trackEmailFailed('handshake', error);
      this.emit('handshake-failed', { handshake, sender, recipient, error });
      
      SecureLogger.logError('Failed to send handshake email', {
        handshakeId: handshake._id?.toString(),
        senderEmail: sender.email,
        recipientEmail: recipient.email,
        error: error.message
      });
      
      throw error;
    }
  }

  /**
   * Send batch of emails
   * @param {Array} emailBatch - Array of email data objects
   * @param {Object} options - Batch options
   */
  async sendBatch(emailBatch, options = {}) {
    const batchSize = options.batchSize || this.config.batchSize;
    const results = [];
    const errors = [];

    SecureLogger.logInfo('Starting batch email send', {
      totalEmails: emailBatch.length,
      batchSize
    });

    // Process emails in batches
    for (let i = 0; i < emailBatch.length; i += batchSize) {
      const batch = emailBatch.slice(i, i + batchSize);
      
      // Check rate limiting
      await this.enforceRateLimit(batch.length);
      
      const batchPromises = batch.map(async (emailData, index) => {
        try {
          const result = await this.sendEmail(emailData);
          results.push({ index: i + index, success: true, result });
          return result;
        } catch (error) {
          errors.push({ index: i + index, error, emailData });
          results.push({ index: i + index, success: false, error });
          return null;
        }
      });

      await Promise.allSettled(batchPromises);
      
      SecureLogger.logInfo(`Batch ${Math.floor(i / batchSize) + 1} processed`, {
        processed: Math.min(i + batchSize, emailBatch.length),
        total: emailBatch.length
      });
    }

    const successCount = results.filter(r => r.success).length;
    const failureCount = results.filter(r => !r.success).length;

    SecureLogger.logInfo('Batch email send completed', {
      total: emailBatch.length,
      success: successCount,
      failures: failureCount,
      successRate: (successCount / emailBatch.length * 100).toFixed(2) + '%'
    });

    return {
      total: emailBatch.length,
      success: successCount,
      failures: failureCount,
      results,
      errors
    };
  }

  /**
   * Core email sending method with provider fallback
   * @param {Object} emailData - Email data object
   */
  async sendEmail(emailData) {
    const providers = ['resend', 'postmark'].filter(p => this.providers[p]);
    
    if (providers.length === 0) {
      throw new Error('No email providers available');
    }

    let lastError;
    
    for (const providerName of providers) {
      try {
        const result = await this.sendWithProvider(providerName, emailData);
        
        // Update metrics
        this.metrics.totalSent++;
        this.updateDeliveryRate();
        
        return {
          success: true,
          provider: providerName,
          messageId: result.messageId || result.id,
          ...result
        };
      } catch (error) {
        lastError = error;
        SecureLogger.logWarning(`Email send failed with ${providerName}, trying next provider`, {
          provider: providerName,
          error: error.message,
          to: emailData.to
        });
        continue;
      }
    }

    // All providers failed
    this.metrics.totalFailed++;
    this.updateDeliveryRate();
    
    throw new Error(`All email providers failed. Last error: ${lastError?.message || 'Unknown error'}`);
  }

  /**
   * Send email with specific provider
   * @param {string} providerName - Provider name ('resend' or 'postmark')
   * @param {Object} emailData - Email data
   */
  async sendWithProvider(providerName, emailData) {
    const provider = this.providers[providerName];
    
    if (!provider) {
      throw new Error(`Provider ${providerName} not available`);
    }

    const maxRetries = this.config.maxRetries;
    let lastError;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        if (attempt > 0) {
          const delay = this.config.retryDelays[Math.min(attempt - 1, this.config.retryDelays.length - 1)];
          await this.sleep(delay);
          SecureLogger.logInfo(`Retrying email send (attempt ${attempt + 1}/${maxRetries + 1})`, {
            provider: providerName,
            to: emailData.to,
            delay
          });
        }

        let result;
        
        if (providerName === 'resend') {
          result = await this.sendWithResend(provider, emailData);
        } else if (providerName === 'postmark') {
          result = await this.sendWithPostmark(provider, emailData);
        } else {
          throw new Error(`Unknown provider: ${providerName}`);
        }

        return result;
      } catch (error) {
        lastError = error;
        
        if (attempt === maxRetries || !this.isRetryableError(error)) {
          break;
        }
      }
    }

    throw lastError;
  }

  /**
   * Send email with Resend
   */
  async sendWithResend(resend, emailData) {
    const emailOptions = {
      from: `${this.config.fromName} <${this.config.fromAddress}>`,
      to: emailData.to,
      subject: emailData.subject,
      html: emailData.html,
      text: emailData.text,
      tags: emailData.metadata ? [
        { name: 'type', value: emailData.metadata.type },
        { name: 'month', value: emailData.metadata.month || 'unknown' }
      ] : undefined
    };

    const { data, error } = await resend.emails.send(emailOptions);
    
    if (error) {
      throw new Error(`Resend error: ${error.message || JSON.stringify(error)}`);
    }

    return {
      messageId: data.id,
      provider: 'resend'
    };
  }

  /**
   * Send email with Postmark
   */
  async sendWithPostmark(postmark, emailData) {
    const emailOptions = {
      From: `${this.config.fromName} <${this.config.fromAddress}>`,
      To: emailData.to,
      Subject: emailData.subject,
      HtmlBody: emailData.html,
      TextBody: emailData.text,
      Tag: emailData.metadata?.type || 'general',
      Metadata: emailData.metadata || {}
    };

    const result = await postmark.sendEmail(emailOptions);
    
    return {
      messageId: result.MessageID,
      provider: 'postmark'
    };
  }

  /**
   * Render email template with data
   * @param {string} templateName - Template name
   * @param {Object} data - Template data
   */
  async renderTemplate(templateName, data) {
    const cacheKey = `${templateName}_${JSON.stringify(data)}`;
    
    // Check cache first
    const cached = this.templateCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < this.config.templateCacheTTL) {
      return cached.html;
    }

    try {
      const templatePath = path.join(this.config.templatesPath, `${templateName}.html`);
      let template = await fs.readFile(templatePath, 'utf-8');
      
      // Simple template variable replacement
      for (const [key, value] of Object.entries(data)) {
        const regex = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
        template = template.replace(regex, value || '');
      }

      // Cache the rendered template
      this.templateCache.set(cacheKey, {
        html: template,
        timestamp: Date.now()
      });

      // Clean old cache entries
      this.cleanTemplateCache();

      return template;
    } catch (error) {
      SecureLogger.logError('Failed to render email template', {
        templateName,
        error: error.message
      });
      throw new Error(`Template rendering failed: ${error.message}`);
    }
  }

  /**
   * Clean expired template cache entries
   */
  cleanTemplateCache() {
    const now = Date.now();
    const ttl = this.config.templateCacheTTL;
    
    for (const [key, value] of this.templateCache.entries()) {
      if (now - value.timestamp > ttl) {
        this.templateCache.delete(key);
      }
    }
  }

  /**
   * Enforce rate limiting
   * @param {number} emailCount - Number of emails to send
   */
  async enforceRateLimit(emailCount = 1) {
    const now = Date.now();
    const windowDuration = 60 * 1000; // 1 minute
    
    // Reset counter if window expired
    if (now - this.rateLimitWindow > windowDuration) {
      this.sentEmailsCount = 0;
      this.rateLimitWindow = now;
    }

    // Check if adding these emails would exceed limit
    if (this.sentEmailsCount + emailCount > this.config.rateLimitPerMinute) {
      const waitTime = windowDuration - (now - this.rateLimitWindow);
      SecureLogger.logInfo('Rate limit reached, waiting', {
        waitTime,
        currentCount: this.sentEmailsCount,
        limit: this.config.rateLimitPerMinute
      });
      
      await this.sleep(waitTime);
      
      // Reset after waiting
      this.sentEmailsCount = 0;
      this.rateLimitWindow = Date.now();
    }

    this.sentEmailsCount += emailCount;
  }

  /**
   * Verify webhook signature
   * @param {string} payload - Raw webhook payload
   * @param {string} signature - Webhook signature
   * @param {string} secret - Webhook secret
   */
  verifyWebhookSignature(payload, signature, secret = null) {
    if (!secret) {
      secret = this.config.webhookSecret;
    }
    
    if (!secret) {
      throw new Error('Webhook secret not configured');
    }

    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(payload, 'utf8');
    const expectedSignature = 'sha256=' + hmac.digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }

  /**
   * Process webhook event
   * @param {Object} event - Webhook event data
   */
  async processWebhookEvent(event) {
    try {
      const { type, data } = event;
      
      switch (type) {
        case 'bounce':
          await this.handleBounce(data);
          break;
        case 'complaint':
          await this.handleComplaint(data);
          break;
        case 'unsubscribe':
          await this.handleUnsubscribe(data);
          break;
        case 'delivery':
          await this.handleDelivery(data);
          break;
        default:
          SecureLogger.logWarning('Unknown webhook event type', { type, data });
      }
      
      this.emit('webhook-processed', { type, data });
    } catch (error) {
      SecureLogger.logError('Failed to process webhook event', {
        event,
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Handle email bounce webhook
   */
  async handleBounce(data) {
    this.metrics.bounces++;
    this.updateDeliveryRate();
    
    SecureLogger.logWarning('Email bounce received', {
      email: data.email,
      reason: data.reason,
      type: data.bounceType
    });
    
    this.emit('bounce', data);
  }

  /**
   * Handle email complaint webhook
   */
  async handleComplaint(data) {
    SecureLogger.logWarning('Email complaint received', {
      email: data.email,
      reason: data.reason
    });
    
    this.emit('complaint', data);
  }

  /**
   * Handle unsubscribe webhook
   */
  async handleUnsubscribe(data) {
    this.metrics.unsubscribes++;
    
    SecureLogger.logInfo('Email unsubscribe received', {
      email: data.email
    });
    
    this.emit('unsubscribe', data);
  }

  /**
   * Handle delivery confirmation webhook
   */
  async handleDelivery(data) {
    SecureLogger.logInfo('Email delivery confirmed', {
      email: data.email,
      messageId: data.messageId
    });
    
    this.emit('delivery', data);
  }

  /**
   * Check if error is retryable
   */
  isRetryableError(error) {
    const retryableErrors = [
      'ECONNRESET',
      'ENOTFOUND',
      'ECONNREFUSED',
      'ETIMEDOUT',
      'rate limit',
      'timeout',
      'temporary failure'
    ];
    
    const message = error.message?.toLowerCase() || '';
    return retryableErrors.some(retryable => message.includes(retryable));
  }

  /**
   * Track email sent for metrics
   */
  trackEmailSent(type, duration) {
    if (this.realTimeMetrics) {
      this.realTimeMetrics.emit('email-sent', {
        type,
        duration,
        timestamp: new Date()
      });
    }
  }

  /**
   * Track email failed for metrics
   */
  trackEmailFailed(type, error) {
    if (this.realTimeMetrics) {
      this.realTimeMetrics.emit('email-failed', {
        type,
        error: error.message,
        timestamp: new Date()
      });
    }
  }

  /**
   * Update delivery rate metric
   */
  updateDeliveryRate() {
    const total = this.metrics.totalSent + this.metrics.totalFailed;
    this.metrics.deliveryRate = total > 0 ? (this.metrics.totalSent / total) : 1;
  }

  /**
   * Get service metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      cacheSize: this.templateCache.size,
      providersAvailable: Object.keys(this.providers).filter(p => this.providers[p]).length,
      rateLimitStatus: {
        sentInWindow: this.sentEmailsCount,
        limit: this.config.rateLimitPerMinute,
        windowStart: new Date(this.rateLimitWindow)
      }
    };
  }

  /**
   * Reset metrics
   */
  resetMetrics() {
    this.metrics = {
      totalSent: 0,
      totalFailed: 0,
      bounces: 0,
      unsubscribes: 0,
      deliveryRate: 0,
      lastResetTime: new Date()
    };
    
    SecureLogger.logInfo('Email service metrics reset');
  }

  /**
   * Utility sleep function
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Shutdown email service
   */
  async shutdown() {
    SecureLogger.logInfo('Shutting down EmailService');
    
    // Clear template cache
    this.templateCache.clear();
    
    // Remove all listeners
    this.removeAllListeners();
    
    SecureLogger.logInfo('EmailService shutdown complete');
  }
}

module.exports = EmailService;