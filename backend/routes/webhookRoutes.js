const express = require('express');
const crypto = require('crypto');
const SecureLogger = require('../utils/secureLogger');
const Contact = require('../models/Contact');
const User = require('../models/User');

const router = express.Router();

/**
 * Email Webhook Routes for Form-a-Friend v2
 * 
 * Handles webhook events from email providers (Resend/Postmark)
 * - Bounces: Mark contacts as bounced
 * - Complaints: Mark contacts as complained
 * - Unsubscribes: Mark contacts as unsubscribed
 * - Deliveries: Track successful deliveries
 * 
 * Security: HMAC-SHA256 signature verification
 * Processing: Asynchronous with retry logic
 * Compliance: GDPR-compliant immediate opt-out processing
 */

/**
 * Middleware to verify webhook signatures
 */
function verifyWebhookSignature(secret) {
  return (req, res, next) => {
    try {
      const signature = req.get('X-Webhook-Signature') || req.get('Authorization');
      
      if (!signature) {
        SecureLogger.logWarning('Webhook signature missing', {
          headers: Object.keys(req.headers),
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        return res.status(401).json({ error: 'Signature required' });
      }

      const payload = JSON.stringify(req.body);
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(payload, 'utf8');
      const expectedSignature = 'sha256=' + hmac.digest('hex');
      
      const isValid = crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );

      if (!isValid) {
        SecureLogger.logWarning('Invalid webhook signature', {
          provided: signature.substring(0, 20) + '...',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        return res.status(401).json({ error: 'Invalid signature' });
      }

      next();
    } catch (error) {
      SecureLogger.logError('Webhook signature verification failed', {
        error: error.message,
        ip: req.ip
      });
      return res.status(400).json({ error: 'Signature verification failed' });
    }
  };
}

/**
 * Middleware to parse webhook provider
 */
function parseWebhookProvider(req, res, next) {
  const userAgent = req.get('User-Agent') || '';
  const provider = req.params.provider;
  
  if (provider === 'resend' || userAgent.includes('Resend')) {
    req.emailProvider = 'resend';
  } else if (provider === 'postmark' || userAgent.includes('Postmark')) {
    req.emailProvider = 'postmark';
  } else {
    req.emailProvider = 'unknown';
  }
  
  SecureLogger.logInfo('Webhook provider detected', {
    provider: req.emailProvider,
    userAgent: userAgent.substring(0, 100),
    ip: req.ip
  });
  
  next();
}

/**
 * Generic webhook handler for all providers
 */
// Create middleware with webhook secret
const webhookMiddleware = verifyWebhookSignature(process.env.EMAIL_WEBHOOK_SECRET);

// Specific provider routes
router.post('/email/resend', parseWebhookProvider, webhookMiddleware, handleWebhook);
router.post('/email/postmark', parseWebhookProvider, webhookMiddleware, handleWebhook);
// Generic route for unknown providers
router.post('/email', parseWebhookProvider, webhookMiddleware, handleWebhook);

/**
 * Main webhook handler function
 */
async function handleWebhook(req, res) {
  try {
    const { body, emailProvider } = req;
    
    SecureLogger.logInfo('Email webhook received', {
      provider: emailProvider,
      eventType: body.type || body.event_type || 'unknown',
      messageId: body.data?.message_id || body.MessageID,
      ip: req.ip
    });

    // Process webhook based on provider
    let eventData;
    if (emailProvider === 'resend') {
      eventData = await processResendWebhook(body);
    } else if (emailProvider === 'postmark') {
      eventData = await processPostmarkWebhook(body);
    } else {
      // Try to auto-detect and process
      eventData = await processGenericWebhook(body);
    }

    if (eventData) {
      // Process the normalized event data
      await processEmailEvent(eventData);
      
      SecureLogger.logInfo('Webhook processed successfully', {
        provider: emailProvider,
        eventType: eventData.type,
        email: eventData.email,
        messageId: eventData.messageId
      });
    }

    res.status(200).json({ success: true, processed: !!eventData });
  } catch (error) {
    SecureLogger.logError('Webhook processing failed', {
      error: error.message,
      provider: req.emailProvider,
      body: JSON.stringify(req.body).substring(0, 500),
      ip: req.ip
    });
    
    // Return 200 to prevent provider retries for permanent errors
    if (error.message.includes('Invalid email format') || 
        error.message.includes('Contact not found')) {
      return res.status(200).json({ success: false, error: error.message });
    }
    
    // Return 500 for temporary errors to trigger retries
    res.status(500).json({ success: false, error: 'Processing failed' });
  }
}

/**
 * Process Resend webhook
 */
async function processResendWebhook(body) {
  const { type, data } = body;
  
  if (!type || !data) {
    throw new Error('Invalid Resend webhook format');
  }

  const eventMap = {
    'email.bounced': 'bounce',
    'email.complained': 'complaint',
    'email.delivered': 'delivery',
    'email.opened': 'open',
    'email.clicked': 'click'
  };

  const eventType = eventMap[type];
  if (!eventType) {
    SecureLogger.logWarning('Unknown Resend event type', { type });
    return null;
  }

  return {
    type: eventType,
    email: data.to,
    messageId: data.email_id,
    timestamp: new Date(data.created_at),
    reason: data.bounce_reason || data.complaint_reason,
    provider: 'resend',
    metadata: data
  };
}

/**
 * Process Postmark webhook
 */
async function processPostmarkWebhook(body) {
  const { Type, Email, MessageID, BouncedAt, ReceivedAt } = body;
  
  if (!Type || !Email) {
    throw new Error('Invalid Postmark webhook format');
  }

  const eventMap = {
    'Bounce': 'bounce',
    'SpamComplaint': 'complaint',
    'Delivery': 'delivery',
    'Open': 'open',
    'Click': 'click'
  };

  const eventType = eventMap[Type];
  if (!eventType) {
    SecureLogger.logWarning('Unknown Postmark event type', { Type });
    return null;
  }

  return {
    type: eventType,
    email: Email,
    messageId: MessageID,
    timestamp: new Date(BouncedAt || ReceivedAt || Date.now()),
    reason: body.Description || body.Details,
    bounceType: body.TypeCode,
    provider: 'postmark',
    metadata: body
  };
}

/**
 * Process generic webhook (auto-detection)
 */
async function processGenericWebhook(body) {
  // Try to detect common webhook formats
  if (body.event && body.data) {
    // Generic event/data format
    return {
      type: body.event,
      email: body.data.email || body.data.to,
      messageId: body.data.message_id || body.data.id,
      timestamp: new Date(body.data.timestamp || Date.now()),
      reason: body.data.reason,
      provider: 'generic',
      metadata: body.data
    };
  }
  
  SecureLogger.logWarning('Unknown webhook format', {
    bodyKeys: Object.keys(body),
    sample: JSON.stringify(body).substring(0, 200)
  });
  
  return null;
}

/**
 * Process normalized email event
 */
async function processEmailEvent(eventData) {
  const { type, email, messageId, timestamp, reason, bounceType, provider, metadata } = eventData;
  
  if (!email || !isValidEmail(email)) {
    throw new Error(`Invalid email format: ${email}`);
  }

  switch (type) {
    case 'bounce':
      await handleEmailBounce(email, messageId, reason, bounceType, timestamp, provider, metadata);
      break;
    case 'complaint':
      await handleEmailComplaint(email, messageId, reason, timestamp, provider, metadata);
      break;
    case 'delivery':
      await handleEmailDelivery(email, messageId, timestamp, provider, metadata);
      break;
    case 'open':
      await handleEmailOpen(email, messageId, timestamp, provider, metadata);
      break;
    case 'click':
      await handleEmailClick(email, messageId, timestamp, provider, metadata);
      break;
    default:
      SecureLogger.logWarning('Unhandled email event type', { type, email, messageId });
  }
}

/**
 * Handle email bounce
 */
async function handleEmailBounce(email, messageId, reason, bounceType, timestamp, provider, metadata) {
  try {
    // Find and update contact
    const contact = await Contact.findOne({ email: email.toLowerCase() });
    
    if (contact) {
      // Determine if bounce is permanent or temporary
      const isPermanent = isPermanentBounce(reason, bounceType);
      
      // Use the new Contact model method
      await contact.markAsBounced(reason, isPermanent, timestamp);
      
      SecureLogger.logWarning('Email bounced', {
        email,
        messageId,
        reason,
        bounceType,
        isPermanent,
        bounceCount: contact.bounceCount,
        provider
      });
    }
    
    // Also check Users table
    const user = await User.findOne({ email: email.toLowerCase() });
    if (user) {
      user.metadata.emailBounced = true;
      user.metadata.lastBounceAt = timestamp;
      user.metadata.bounceReason = reason;
      await user.save();
    }
    
    // Log for analytics
    await logEmailEvent('bounce', email, messageId, { reason, bounceType, isPermanent: isPermanentBounce(reason, bounceType) });
    
  } catch (error) {
    SecureLogger.logError('Failed to handle email bounce', {
      email,
      messageId,
      error: error.message
    });
    throw error;
  }
}

/**
 * Handle email complaint (spam report)
 */
async function handleEmailComplaint(email, messageId, reason, timestamp, provider, metadata) {
  try {
    // Find and update contact - immediate opt-out for GDPR compliance
    const contact = await Contact.findOne({ email: email.toLowerCase() });
    
    if (contact) {
      // Use the new Contact model method for GDPR-compliant complaint handling
      await contact.markAsComplained(reason, timestamp);
      
      SecureLogger.logWarning('Email complaint received - immediate opt-out', {
        email,
        messageId,
        reason,
        provider
      });
    }
    
    // Also update Users table
    const user = await User.findOne({ email: email.toLowerCase() });
    if (user) {
      user.metadata.emailComplained = true;
      user.metadata.lastComplaintAt = timestamp;
      user.metadata.isActive = false;
      await user.save();
    }
    
    // Log for analytics and compliance
    await logEmailEvent('complaint', email, messageId, { reason, gdprOptOut: true });
    
  } catch (error) {
    SecureLogger.logError('Failed to handle email complaint', {
      email,
      messageId,
      error: error.message
    });
    throw error;
  }
}

/**
 * Handle email delivery confirmation
 */
async function handleEmailDelivery(email, messageId, timestamp, provider, metadata) {
  try {
    // Update contact delivery status
    const contact = await Contact.findOne({ email: email.toLowerCase() });
    
    if (contact) {
      // Use the new Contact model method
      await contact.markAsDelivered(timestamp);
    }
    
    // Log for analytics
    await logEmailEvent('delivery', email, messageId, { provider });
    
    SecureLogger.logInfo('Email delivered successfully', {
      email,
      messageId,
      provider
    });
    
  } catch (error) {
    SecureLogger.logError('Failed to handle email delivery', {
      email,
      messageId,
      error: error.message
    });
    // Don't throw - delivery tracking is not critical
  }
}

/**
 * Handle email open
 */
async function handleEmailOpen(email, messageId, timestamp, provider, metadata) {
  try {
    // Log engagement for analytics
    await logEmailEvent('open', email, messageId, { 
      provider,
      userAgent: metadata.userAgent,
      ipAddress: metadata.ipAddress
    });
    
    SecureLogger.logInfo('Email opened', {
      email,
      messageId,
      provider
    });
    
  } catch (error) {
    SecureLogger.logError('Failed to handle email open', {
      email,
      messageId,
      error: error.message
    });
    // Don't throw - open tracking is not critical
  }
}

/**
 * Handle email click
 */
async function handleEmailClick(email, messageId, timestamp, provider, metadata) {
  try {
    // Log engagement for analytics
    await logEmailEvent('click', email, messageId, { 
      provider,
      url: metadata.url,
      userAgent: metadata.userAgent,
      ipAddress: metadata.ipAddress
    });
    
    SecureLogger.logInfo('Email link clicked', {
      email,
      messageId,
      url: metadata.url,
      provider
    });
    
  } catch (error) {
    SecureLogger.logError('Failed to handle email click', {
      email,
      messageId,
      error: error.message
    });
    // Don't throw - click tracking is not critical
  }
}

/**
 * Determine if bounce is permanent
 */
function isPermanentBounce(reason, bounceType) {
  if (!reason) return false;
  
  const permanentReasons = [
    'user unknown',
    'mailbox does not exist',
    'invalid mailbox',
    'no such user',
    'account disabled',
    'mailbox full',
    'domain not found',
    'smtp error 550',
    'smtp error 551',
    'smtp error 553'
  ];
  
  const reasonLower = reason.toLowerCase();
  const isPermanent = permanentReasons.some(perm => reasonLower.includes(perm));
  
  // Postmark bounce type codes
  if (bounceType) {
    const permanentCodes = [1, 2, 6, 7, 8, 9, 10]; // Hard bounce codes
    if (permanentCodes.includes(parseInt(bounceType))) {
      return true;
    }
  }
  
  return isPermanent;
}

/**
 * Validate email format
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Log email event for analytics
 */
async function logEmailEvent(eventType, email, messageId, metadata = {}) {
  try {
    // This could be expanded to write to a dedicated analytics collection
    SecureLogger.logInfo('Email event tracked', {
      event: eventType,
      email: email.substring(0, 3) + '***', // Partial email for privacy
      messageId,
      timestamp: new Date(),
      ...metadata
    });
  } catch (error) {
    SecureLogger.logError('Failed to log email event', {
      eventType,
      error: error.message
    });
  }
}

/**
 * Health check endpoint for webhook
 */
router.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    service: 'email-webhooks',
    timestamp: new Date().toISOString()
  });
});

/**
 * Manual unsubscribe endpoint (for email links)
 */
router.get('/unsubscribe', async (req, res) => {
  try {
    const { email, token } = req.query;
    
    if (!email && !token) {
      return res.status(400).json({ error: 'Email or token required' });
    }
    
    let contact;
    
    if (email && isValidEmail(email)) {
      contact = await Contact.findOne({ email: email.toLowerCase() });
    } else if (token) {
      // Look up by invitation token
      const Invitation = require('../models/Invitation');
      const invitation = await Invitation.findOne({ token }).populate('userId');
      if (invitation && invitation.userId) {
        contact = await Contact.findOne({ email: invitation.userId.email });
      }
    }
    
    if (contact) {
      // Use the new Contact model method
      await contact.optOut('manual_unsubscribe');
      
      SecureLogger.logInfo('Manual unsubscribe processed', {
        email: contact.email.substring(0, 3) + '***',
        method: email ? 'email' : 'token'
      });
      
      res.status(200).json({ 
        success: true, 
        message: 'Vous avez été désabonné avec succès' 
      });
    } else {
      res.status(404).json({ 
        success: false, 
        message: 'Contact non trouvé' 
      });
    }
    
  } catch (error) {
    SecureLogger.logError('Manual unsubscribe failed', {
      error: error.message,
      query: req.query
    });
    
    res.status(500).json({ 
      success: false, 
      message: 'Erreur lors du désabonnement' 
    });
  }
});

module.exports = router;