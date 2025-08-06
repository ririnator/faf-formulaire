const request = require('supertest');
const express = require('express');
const { validateResponseStrict, handleValidationErrors, sanitizeResponse } = require('../middleware/validation');

describe('Validation Middleware Security Tests', () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    // Test route using strict validation
    app.post('/test-strict', 
      validateResponseStrict,
      handleValidationErrors,
      sanitizeResponse,
      (req, res) => {
        res.json({ 
          success: true, 
          sanitized: {
            name: req.body.name,
            responses: req.body.responses
          }
        });
      }
    );
  });

  describe('XSS Injection Protection', () => {
    test('should escape script tags in name field', async () => {
      const maliciousData = {
        name: '<script>alert("xss")</script>John',
        responses: [
          {
            question: 'Safe question',
            answer: 'Safe answer'
          }
        ]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(maliciousData)
        .expect(200);

      expect(response.body.sanitized.name).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;John');
      expect(response.body.sanitized.name).not.toContain('<script>');
    });

    test('should escape HTML entities in questions', async () => {
      const maliciousData = {
        name: 'John Doe',
        responses: [
          {
            question: '<img src="x" onerror="alert(1)">What is your name?',
            answer: 'Safe answer'
          }
        ]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(maliciousData)
        .expect(200);

      expect(response.body.sanitized.responses[0].question).toContain('&lt;img');
      expect(response.body.sanitized.responses[0].question).not.toContain('<img');
    });

    test('should escape JavaScript events in answers', async () => {
      const maliciousData = {
        name: 'John Doe',
        responses: [
          {
            question: 'What is your favorite color?',
            answer: '<div onmouseover="document.cookie=\'stolen\'">Blue</div>'
          }
        ]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(maliciousData)
        .expect(200);

      expect(response.body.sanitized.responses[0].answer).toContain('&lt;div');
      expect(response.body.sanitized.responses[0].answer).toContain('onmouseover');
      expect(response.body.sanitized.responses[0].answer).not.toContain('<div onmouseover=');
    });

    test('should handle complex XSS payloads', async () => {
      const complexXSS = {
        name: 'BadUser', // Simplified name that passes length validation
        responses: [
          {
            question: '"><svg/onload=alert(/XSS/)>What is your name?',
            answer: '\'-confirm(1)-\' This is my answer'
          }
        ]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(complexXSS)
        .expect(200);

      // Verify all dangerous characters are escaped
      expect(response.body.sanitized.responses[0].question).not.toContain('<svg');
      expect(response.body.sanitized.responses[0].question).toContain('&lt;svg');
      // Single quotes should be escaped as &#x27;
      expect(response.body.sanitized.responses[0].answer).toContain('&#x27;');
    });

    test('should preserve legitimate content while escaping malicious parts', async () => {
      const mixedContent = {
        name: 'John & Jane <safe>',
        responses: [
          {
            question: 'What is 2 < 3 && 4 > 1?',
            answer: 'True! Math: 2 < 3 is correct'
          }
        ]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(mixedContent)
        .expect(200);

      expect(response.body.sanitized.name).toContain('John &amp; Jane');
      expect(response.body.sanitized.responses[0].question).toContain('2 &lt; 3');
      expect(response.body.sanitized.responses[0].answer).toContain('2 &lt; 3');
    });
  });

  describe('Character Limit Boundary Testing', () => {
    test('should accept name at exactly 100 characters', async () => {
      const exactLimit = 'A'.repeat(100);
      const validData = {
        name: exactLimit,
        responses: [{ question: 'Test?', answer: 'Test!' }]
      };

      await request(app)
        .post('/test-strict')
        .send(validData)
        .expect(200);
    });

    test('should reject name over 100 characters', async () => {
      const overLimit = 'A'.repeat(101);
      const invalidData = {
        name: overLimit,
        responses: [{ question: 'Test?', answer: 'Test!' }]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(invalidData)
        .expect(400);

      expect(response.body.message).toContain('100 caractères');
    });

    test('should accept question at exactly 500 characters', async () => {
      const exactLimit = 'Q'.repeat(500);
      const validData = {
        name: 'John Doe',
        responses: [{ question: exactLimit, answer: 'Test!' }]
      };

      await request(app)
        .post('/test-strict')
        .send(validData)
        .expect(200);
    });

    test('should reject question over 500 characters', async () => {
      const overLimit = 'Q'.repeat(501);
      const invalidData = {
        name: 'John Doe',
        responses: [{ question: overLimit, answer: 'Test!' }]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(invalidData)
        .expect(400);

      expect(response.body.message).toContain('500 caractères');
    });

    test('should accept answer at exactly 10000 characters', async () => {
      const exactLimit = 'A'.repeat(10000);
      const validData = {
        name: 'John Doe',
        responses: [{ question: 'Long answer?', answer: exactLimit }]
      };

      await request(app)
        .post('/test-strict')
        .send(validData)
        .expect(200);
    });

    test('should reject answer over 10000 characters', async () => {
      const overLimit = 'A'.repeat(10001);
      const invalidData = {
        name: 'John Doe',
        responses: [{ question: 'Long answer?', answer: overLimit }]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(invalidData)
        .expect(400);

      expect(response.body.message).toContain('10000 caractères');
    });

    test('should accept exactly 20 responses', async () => {
      const responses = Array.from({ length: 20 }, (_, i) => ({
        question: `Question ${i + 1}?`,
        answer: `Answer ${i + 1}`
      }));

      const validData = {
        name: 'John Doe',
        responses
      };

      await request(app)
        .post('/test-strict')
        .send(validData)
        .expect(200);
    });

    test('should reject more than 20 responses', async () => {
      const responses = Array.from({ length: 21 }, (_, i) => ({
        question: `Question ${i + 1}?`,
        answer: `Answer ${i + 1}`
      }));

      const invalidData = {
        name: 'John Doe',
        responses
      };

      const response = await request(app)
        .post('/test-strict')
        .send(invalidData)
        .expect(400);

      expect(response.body.message).toContain('20 réponses');
    });

    test('should handle edge case with minimum valid data', async () => {
      const minimalData = {
        name: 'Jo', // 2 characters minimum
        responses: [{ question: 'Q', answer: 'A' }] // 1 response minimum
      };

      await request(app)
        .post('/test-strict')
        .send(minimalData)
        .expect(200);
    });

    test('should reject name under 2 characters', async () => {
      const invalidData = {
        name: 'J', // 1 character - too short
        responses: [{ question: 'Test?', answer: 'Test!' }]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(invalidData)
        .expect(400);

      expect(response.body.message).toContain('2 et 100 caractères');
    });
  });

  describe('Data Sanitization Edge Cases', () => {
    test('should handle null and undefined values gracefully', async () => {
      const edgeCaseData = {
        name: 'John Doe',
        responses: [
          { question: null, answer: 'Valid answer' },
          { question: 'Valid question?', answer: undefined }
        ]
      };

      // Should be caught by validation before reaching sanitization
      const response = await request(app)
        .post('/test-strict')
        .send(edgeCaseData)
        .expect(400);

      // Express-validator returns 'Invalid value' for null/undefined
      expect(response.body.message).toContain('Invalid value');
    });

    test('should handle empty strings after trimming', async () => {
      const edgeCaseData = {
        name: '   ', // Only whitespace
        responses: [{ question: '  ', answer: '  ' }]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(edgeCaseData)
        .expect(400);

      expect(response.body.message).toContain('2 et 100 caractères');
    });

    test('should properly trim and validate whitespace-padded content', async () => {
      const paddedData = {
        name: '  John Doe  ',
        responses: [
          {
            question: '  What is your name?  ',
            answer: '  John Doe  '
          }
        ]
      };

      const response = await request(app)
        .post('/test-strict')
        .send(paddedData)
        .expect(200);

      // Trimming happens during validation
      expect(response.body.sanitized.name).toBe('John Doe');
    });

    test('should handle unicode characters properly', async () => {
      const unicodeData = {
        name: 'José María 测试',
        responses: [
          {
            question: 'What is your favorite émoji? 😀',
            answer: 'I like 🎉 and 🚀!'
          }
        ]
      };

      await request(app)
        .post('/test-strict')
        .send(unicodeData)
        .expect(200);
    });
  });

  describe('Honeypot Spam Protection', () => {
    test('should reject submissions with honeypot field filled', async () => {
      const spamData = {
        name: 'Spammer',
        responses: [{ question: 'Spam?', answer: 'Yes' }],
        website: 'http://spam.com' // Honeypot field
      };

      const response = await request(app)
        .post('/test-strict')
        .send(spamData)
        .expect(400);

      expect(response.body.message).toBe('Spam détecté');
    });

    test('should accept submissions with empty honeypot field', async () => {
      const validData = {
        name: 'Real User',
        responses: [{ question: 'Real question?', answer: 'Real answer' }],
        website: '' // Empty honeypot field
      };

      await request(app)
        .post('/test-strict')
        .send(validData)
        .expect(200);
    });

    test('should accept submissions without honeypot field', async () => {
      const validData = {
        name: 'Real User',
        responses: [{ question: 'Real question?', answer: 'Real answer' }]
        // No honeypot field at all
      };

      await request(app)
        .post('/test-strict')
        .send(validData)
        .expect(200);
    });
  });
});