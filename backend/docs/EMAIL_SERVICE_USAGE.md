# EmailService Usage Guide for Form-a-Friend v2

## Overview

The EmailService provides a complete multi-provider email solution for the Form-a-Friend v2 symmetric monthly sharing system. It includes support for Resend (primary) and Postmark (fallback), responsive HTML templates, webhook handling, and comprehensive monitoring.

## Setup

### 1. Environment Variables

Add the following environment variables to your `.env` file:

```bash
# Email Service Configuration
RESEND_API_KEY=your-resend-api-key
POSTMARK_API_KEY=your-postmark-api-key
EMAIL_FROM_ADDRESS=noreply@your-domain.com
EMAIL_FROM_NAME=Form-a-Friend
EMAIL_BATCH_SIZE=50
EMAIL_RATE_LIMIT_PER_MINUTE=100
EMAIL_WEBHOOK_SECRET=your-webhook-secret
EMAIL_TEMPLATE_CACHE_TTL=600000

# Optional - Auto-detected if not set
EMAIL_PROVIDER_PRIORITY=resend,postmark
```

### 2. Install Dependencies

The required dependencies are already added to package.json:

```bash
npm install
```

### 3. Initialize Service

```javascript
const ServiceFactory = require('./services/serviceFactory');
const factory = ServiceFactory.create();
const emailService = factory.getEmailService();
```

## Basic Usage

### Sending Invitation Emails

```javascript
const invitation = {
  _id: 'invitation-id',
  token: 'unique-token',
  month: '2025-01',
  expiresAt: new Date('2025-01-31')
};

const user = {
  _id: 'user-id',
  username: 'john_doe',
  email: 'john@example.com'
};

try {
  const result = await emailService.sendInvitation(invitation, user);
  console.log('Invitation sent:', result.messageId);
} catch (error) {
  console.error('Failed to send invitation:', error.message);
}
```

### Sending Reminder Emails

```javascript
// First reminder (Day +3)
try {
  const result = await emailService.sendReminder(invitation, user, 'first');
  console.log('First reminder sent:', result.messageId);
} catch (error) {
  console.error('Failed to send reminder:', error.message);
}

// Second reminder (Day +7)
try {
  const result = await emailService.sendReminder(invitation, user, 'second');
  console.log('Final reminder sent:', result.messageId);
} catch (error) {
  console.error('Failed to send reminder:', error.message);
}
```

### Sending Handshake Emails

```javascript
const handshake = {
  _id: 'handshake-id',
  token: 'handshake-token',
  message: 'I would love to connect and share our responses!',
  expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
};

const sender = {
  _id: 'sender-id',
  username: 'alice',
  email: 'alice@example.com'
};

const recipient = {
  _id: 'recipient-id',
  username: 'bob',
  email: 'bob@example.com'
};

try {
  const result = await emailService.sendHandshake(handshake, sender, recipient);
  console.log('Handshake email sent:', result.messageId);
} catch (error) {
  console.error('Failed to send handshake:', error.message);
}
```

### Batch Email Sending

```javascript
const emailBatch = [
  {
    to: 'user1@example.com',
    subject: 'Monthly Invitation',
    html: '<p>Your invitation is ready!</p>',
    metadata: { type: 'invitation', month: '2025-01' }
  },
  {
    to: 'user2@example.com',
    subject: 'Monthly Invitation',
    html: '<p>Your invitation is ready!</p>',
    metadata: { type: 'invitation', month: '2025-01' }
  }
  // ... more emails
];

try {
  const result = await emailService.sendBatch(emailBatch);
  console.log(`Batch complete: ${result.success}/${result.total} sent`);
} catch (error) {
  console.error('Batch send failed:', error.message);
}
```

## Event Handling

The EmailService emits events for monitoring and integration:

```javascript
// Listen for successful sends
emailService.on('invitation-sent', (data) => {
  console.log('Invitation sent to:', data.user.email);
  // Update database, trigger analytics, etc.
});

// Listen for failures
emailService.on('invitation-failed', (data) => {
  console.error('Invitation failed for:', data.user.email, data.error.message);
  // Log error, retry later, notify admin, etc.
});

// Listen for webhook events
emailService.on('bounce', (data) => {
  console.log('Email bounced:', data.email, data.reason);
  // Update contact status, remove from active list
});

emailService.on('complaint', (data) => {
  console.log('Spam complaint:', data.email);
  // Immediate opt-out, review sending practices
});

emailService.on('unsubscribe', (data) => {
  console.log('User unsubscribed:', data.email);
  // Update preferences, respect opt-out
});
```

## Webhook Integration

### 1. Add Webhook Routes to Express App

```javascript
const webhookRoutes = require('./routes/webhookRoutes');
app.use('/webhooks', webhookRoutes);
```

### 2. Configure Provider Webhooks

#### Resend Webhook Configuration

1. Go to Resend Dashboard → Webhooks
2. Add webhook URL: `https://your-domain.com/webhooks/email/resend`
3. Select events: `email.sent`, `email.delivered`, `email.bounced`, `email.complained`
4. Set secret to your `EMAIL_WEBHOOK_SECRET`

#### Postmark Webhook Configuration

1. Go to Postmark → Servers → Your Server → Webhooks
2. Add webhook URL: `https://your-domain.com/webhooks/email/postmark`
3. Select events: `Bounce`, `SpamComplaint`, `Delivery`
4. Set authentication to use your `EMAIL_WEBHOOK_SECRET`

### 3. Manual Unsubscribe Links

The webhook routes automatically provide unsubscribe functionality:

```html
<a href="https://your-domain.com/webhooks/unsubscribe?email={{email}}">Unsubscribe</a>
<!-- or -->
<a href="https://your-domain.com/webhooks/unsubscribe?token={{invitationToken}}">Unsubscribe</a>
```

## Monitoring and Metrics

### Real-Time Metrics Integration

```javascript
const RealTimeMetrics = require('./services/realTimeMetrics');
const DBPerformanceMonitor = require('./services/dbPerformanceMonitor');

// Initialize monitoring
const dbMonitor = new DBPerformanceMonitor();
const realTimeMetrics = new RealTimeMetrics(dbMonitor);

// Connect email service to metrics
emailService.setRealTimeMetrics(realTimeMetrics);

// Start monitoring
realTimeMetrics.startCollection();
```

### Get Service Metrics

```javascript
const metrics = emailService.getMetrics();
console.log('Email Metrics:', {
  totalSent: metrics.totalSent,
  totalFailed: metrics.totalFailed,
  deliveryRate: `${(metrics.deliveryRate * 100).toFixed(2)}%`,
  bounces: metrics.bounces,
  unsubscribes: metrics.unsubscribes,
  providersAvailable: metrics.providersAvailable,
  cacheSize: metrics.cacheSize
});
```

### Performance Alerting

```javascript
emailService.on('alert-triggered', (alert) => {
  console.warn('Email Service Alert:', alert.details.message);
  
  switch (alert.key) {
    case 'slow_query_rate':
      // Handle slow email sending
      break;
    case 'delivery_rate_low':
      // Handle delivery issues
      break;
    case 'rate_limit_exceeded':
      // Handle rate limiting
      break;
  }
});
```

## Custom Templates

### Template Structure

Templates are stored in `/backend/templates/emails/` and use simple `{{variable}}` substitution:

```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{subject}}</title>
    <!-- Responsive CSS here -->
</head>
<body>
    <div class="email-container">
        <h1>Bonjour {{userName}} !</h1>
        <p>{{message}}</p>
        <a href="{{actionUrl}}" class="cta-button">{{actionText}}</a>
    </div>
</body>
</html>
```

### Available Template Variables

#### Invitation Template (`invitation.html`)
- `userName` - User's display name
- `invitationToken` - Unique invitation token
- `invitationUrl` - Complete invitation URL
- `expiresAt` - Formatted expiration date
- `month` - Month identifier (e.g., "2025-01")
- `fromName` - Service name
- `appBaseUrl` - Application base URL
- `unsubscribeUrl` - Unsubscribe link

#### Reminder Templates (`reminder-first.html`, `reminder-second.html`)
- All invitation variables plus:
- `reminderNumber` - "1er" or "2ème"
- `daysRemaining` - Days until expiration

#### Handshake Template (`handshake.html`)
- `recipientName` - Recipient's display name
- `senderName` - Sender's display name
- `message` - Personal message from sender
- `handshakeUrl` - Handshake acceptance URL
- `expiresAt` - Formatted expiration date

### Creating Custom Templates

1. Create new template file in `/backend/templates/emails/`
2. Use responsive CSS (inline styles recommended)
3. Include dark mode support with media queries
4. Test across email clients (Gmail, Outlook, Apple Mail)

```javascript
// Use custom template
const customHtml = await emailService.renderTemplate('custom-template', {
  customVar1: 'value1',
  customVar2: 'value2'
});
```

## Error Handling

### Provider Fallback

The service automatically fails over between providers:

```javascript
// Automatic fallback - no code changes needed
try {
  const result = await emailService.sendEmail(emailData);
  console.log(`Sent via ${result.provider}: ${result.messageId}`);
} catch (error) {
  // This means ALL providers failed
  console.error('All email providers failed:', error.message);
}
```

### Retry Logic

Retries are handled automatically with exponential backoff:

```javascript
// Configure retry behavior in service initialization
const emailService = new EmailService({
  // ... other config
  retryDelays: [1000, 5000, 15000], // 1s, 5s, 15s
  maxRetries: 3
});
```

### Error Types

```javascript
try {
  await emailService.sendInvitation(invitation, user);
} catch (error) {
  if (error.message.includes('Rate limit')) {
    // Handle rate limiting
    console.log('Rate limited, will retry later');
  } else if (error.message.includes('Invalid email')) {
    // Handle invalid email
    console.error('Invalid email address:', user.email);
  } else if (error.message.includes('All providers failed')) {
    // Handle complete failure
    console.error('Email service unavailable');
  }
}
```

## Best Practices

### 1. Rate Limiting

- Default: 100 emails/minute
- Monitor metrics to adjust limits
- Use batch sending for bulk operations

### 2. Template Performance

- Templates are cached for 10 minutes by default
- Keep templates lightweight
- Use inline CSS for maximum compatibility

### 3. Webhook Security

- Always verify webhook signatures
- Use HTTPS for webhook endpoints
- Monitor for suspicious activity

### 4. Monitoring

- Set up alerts for delivery rate < 95%
- Monitor bounce rates (target < 2%)
- Track unsubscribe rates for compliance

### 5. Compliance

- Honor unsubscribe requests immediately
- Implement double opt-in for new contacts
- Maintain audit logs for GDPR compliance

## Testing

### Unit Tests

```bash
npm test -- emailService.test.js
npm test -- webhookRoutes.test.js
```

### Integration Tests

```bash
# Test with sandbox email providers
EMAIL_PROVIDER=sandbox npm test -- emailService.integration.test.js
```

### Load Testing

```bash
# Test batch processing performance
npm test -- emailService.performance.test.js
```

## Troubleshooting

### Common Issues

1. **Template not found**
   - Check file path in `/backend/templates/emails/`
   - Verify file permissions

2. **Provider authentication failed**
   - Verify API keys in environment variables
   - Check provider account status

3. **High bounce rate**
   - Review email content and sender reputation
   - Check domain DNS settings (SPF, DKIM, DMARC)

4. **Webhook signature verification failed**
   - Verify `EMAIL_WEBHOOK_SECRET` matches provider configuration
   - Check webhook endpoint URL

### Debug Logging

Enable debug logging for troubleshooting:

```javascript
const emailService = new EmailService({
  // ... config
  debug: true
});

// Or set environment variable
process.env.EMAIL_SERVICE_DEBUG = 'true';
```

## Production Deployment

### 1. DNS Configuration

Set up email authentication records:

```dns
TXT _dmarc.yourdomain.com "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"
TXT yourdomain.com "v=spf1 include:_spf.postmarkapp.com include:_spf.resend.com ~all"
```

### 2. Provider Setup

- Configure custom domains in Resend/Postmark
- Set up DKIM signing
- Verify domain ownership

### 3. Monitoring

- Set up health checks for webhook endpoints
- Monitor email delivery rates
- Configure alerting for failures

### 4. Scaling

- Use multiple worker processes for high volume
- Implement Redis-based rate limiting for distributed systems
- Consider provider-specific limits and quotas

This comprehensive guide covers all aspects of using the EmailService in Form-a-Friend v2. The service provides a robust, scalable solution for the symmetric monthly sharing system with full monitoring and compliance features.