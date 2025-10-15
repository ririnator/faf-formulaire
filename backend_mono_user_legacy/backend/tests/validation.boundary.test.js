const request = require('supertest');
const express = require('express');
const { 
  validateResponseStrict, 
  validateResponse, 
  handleValidationErrors, 
  sanitizeResponse,
  applySafeEscape
} = require('../middleware/validation');
const { createFormBodyParser } = require('../middleware/bodyParser');

describe('Validation Boundary Conditions', () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(express.json());
  });

  describe('Length Boundaries', () => {
    beforeEach(() => {
      app.post('/test-boundary', 
        validateResponseStrict, 
        handleValidationErrors, 
        sanitizeResponse,
        (req, res) => res.json({ success: true, body: req.body })
      );
    });

    describe('Name Length Validation', () => {
      test('should reject name with 1 character', async () => {
        const data = {
          name: 'A',
          responses: [{ question: 'Q', answer: 'A' }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(400);
      });

      test('should accept name with exactly 2 characters (min boundary)', async () => {
        const data = {
          name: 'AB',
          responses: [{ question: 'Q', answer: 'A' }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(200);
      });

      test('should accept name with exactly 100 characters (max boundary)', async () => {
        const data = {
          name: 'A'.repeat(100),
          responses: [{ question: 'Q', answer: 'A' }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(200);
      });

      test('should reject name with 101 characters', async () => {
        const data = {
          name: 'A'.repeat(101),
          responses: [{ question: 'Q', answer: 'A' }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(400);
      });
    });

    describe('Question Length Validation', () => {
      test('should accept question with exactly 500 characters (max boundary)', async () => {
        const data = {
          name: 'Valid Name',
          responses: [{ question: 'Q'.repeat(500), answer: 'A' }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(200);
      });

      test('should reject question with 501 characters', async () => {
        const data = {
          name: 'Valid Name',
          responses: [{ question: 'Q'.repeat(501), answer: 'A' }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(400);
      });

      test('should handle question truncation in sanitization', async () => {
        app.post('/test-sanitize-only', 
          sanitizeResponse,
          (req, res) => res.json({ sanitized: req.body })
        );

        const data = {
          name: 'Valid Name',
          responses: [{ question: 'Q'.repeat(600), answer: 'A' }]
        };

        const response = await request(app)
          .post('/test-sanitize-only')
          .send(data)
          .expect(200);

        expect(response.body.sanitized.responses[0].question).toHaveLength(500);
      });
    });

    describe('Answer Length Validation', () => {
      test('should accept answer with exactly 10000 characters (max boundary)', async () => {
        const data = {
          name: 'Valid Name',
          responses: [{ question: 'Q', answer: 'A'.repeat(10000) }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(200);
      });

      test('should reject answer with 10001 characters', async () => {
        const data = {
          name: 'Valid Name',
          responses: [{ question: 'Q', answer: 'A'.repeat(10001) }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(400);
      });

      test('should handle answer truncation in sanitization', async () => {
        app.post('/test-sanitize-only', 
          sanitizeResponse,
          (req, res) => res.json({ sanitized: req.body })
        );

        const data = {
          name: 'Valid Name',
          responses: [{ question: 'Q', answer: 'A'.repeat(15000) }]
        };

        const response = await request(app)
          .post('/test-sanitize-only')
          .send(data)
          .expect(200);

        expect(response.body.sanitized.responses[0].answer).toHaveLength(10000);
      });
    });

    describe('Responses Array Length Validation', () => {
      test('should reject empty responses array', async () => {
        const data = {
          name: 'Valid Name',
          responses: []
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(400);
      });

      test('should accept exactly 1 response (min boundary)', async () => {
        const data = {
          name: 'Valid Name',
          responses: [{ question: 'Q', answer: 'A' }]
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(200);
      });

      test('should accept exactly 20 responses (max boundary)', async () => {
        const responses = Array(20).fill().map((_, i) => ({
          question: `Question ${i + 1}`,
          answer: `Answer ${i + 1}`
        }));

        const data = {
          name: 'Valid Name',
          responses: responses
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(200);
      });

      test('should reject 21 responses', async () => {
        const responses = Array(21).fill().map((_, i) => ({
          question: `Question ${i + 1}`,
          answer: `Answer ${i + 1}`
        }));

        const data = {
          name: 'Valid Name',
          responses: responses
        };

        await request(app)
          .post('/test-boundary')
          .send(data)
          .expect(400);
      });
    });
  });

  describe('Whitespace Handling', () => {
    beforeEach(() => {
      app.post('/test-whitespace', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ body: req.body })
      );
    });

    test('should trim whitespace from name', async () => {
      const data = {
        name: '  Valid Name  ',
        responses: [{ question: 'Q', answer: 'A' }]
      };

      const response = await request(app)
        .post('/test-whitespace')
        .send(data)
        .expect(200);

      expect(response.body.body.name).toBe('Valid Name');
    });

    test('should trim whitespace from questions', async () => {
      const data = {
        name: 'Valid Name',
        responses: [{ question: '  Question with spaces  ', answer: 'A' }]
      };

      const response = await request(app)
        .post('/test-whitespace')
        .send(data)
        .expect(200);

      expect(response.body.body.responses[0].question).toBe('Question with spaces');
    });

    test('should trim whitespace from answers', async () => {
      const data = {
        name: 'Valid Name',
        responses: [{ question: 'Q', answer: '  Answer with spaces  ' }]
      };

      const response = await request(app)
        .post('/test-whitespace')
        .send(data)
        .expect(200);

      expect(response.body.body.responses[0].answer).toBe('Answer with spaces');
    });

    test('should consider only-whitespace name as invalid', async () => {
      const data = {
        name: '    ',  // Only spaces
        responses: [{ question: 'Q', answer: 'A' }]
      };

      await request(app)
        .post('/test-whitespace')
        .send(data)
        .expect(400);
    });

    test('should consider only-whitespace question as empty', async () => {
      const data = {
        name: 'Valid Name',
        responses: [{ question: '   ', answer: 'A' }]
      };

      await request(app)
        .post('/test-whitespace')
        .send(data)
        .expect(400);
    });
  });

  describe('Unicode and Special Characters', () => {
    beforeEach(() => {
      app.post('/test-unicode', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ body: req.body })
      );
    });

    test('should accept unicode characters in name', async () => {
      const data = {
        name: 'José María',
        responses: [{ question: 'Question', answer: 'Answer' }]
      };

      await request(app)
        .post('/test-unicode')
        .send(data)
        .expect(200);
    });

    test('should accept emojis in responses', async () => {
      const data = {
        name: 'User Name',
        responses: [{ question: 'How are you? 😊', answer: 'Great! 👍✨' }]
      };

      await request(app)
        .post('/test-unicode')
        .send(data)
        .expect(200);
    });

    test('should handle CJK characters correctly', async () => {
      const data = {
        name: '田中太郎',
        responses: [{ question: 'こんにちは', answer: '元気です' }]
      };

      await request(app)
        .post('/test-unicode')
        .send(data)
        .expect(200);
    });

    test('should count unicode characters correctly for length validation', async () => {
      // Unicode characters may be counted as multiple bytes but should be counted as single characters
      const unicodeName = '🦄'.repeat(50); // 50 unicorn emojis
      const data = {
        name: unicodeName,
        responses: [{ question: 'Q', answer: 'A' }]
      };

      await request(app)
        .post('/test-unicode')
        .send(data)
        .expect(200);
    });
  });

  describe('Numeric Edge Cases', () => {
    beforeEach(() => {
      app.post('/test-numeric', 
        validateResponseStrict, 
        handleValidationErrors, 
        sanitizeResponse,
        (req, res) => res.json({ body: req.body })
      );
    });

    test('should handle zero as a name', async () => {
      const data = {
        name: 0,
        responses: [{ question: 'Q', answer: 'A' }]
      };

      const response = await request(app)
        .post('/test-numeric')
        .send(data)
        .expect(400); // Should fail length validation after string conversion

      expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
    });

    test('should handle large numbers', async () => {
      const data = {
        name: 123456789012345,
        responses: [{ question: 'Q', answer: 'A' }]
      };

      await request(app)
        .post('/test-numeric')
        .send(data)
        .expect(200); // Should pass after string conversion
    });

    test('should handle negative numbers', async () => {
      const data = {
        name: -12,
        responses: [{ question: 'Q', answer: 'A' }]
      };

      await request(app)
        .post('/test-numeric')
        .send(data)
        .expect(200); // "-12" has 3 characters, should pass
    });

    test('should handle floating point numbers', async () => {
      const data = {
        name: 3.14159,
        responses: [{ question: 'Q', answer: 'A' }]
      };

      await request(app)
        .post('/test-numeric')
        .send(data)
        .expect(200);
    });
  });

  describe('HTML Entity Escaping', () => {
    beforeEach(() => {
      app.post('/test-escape', 
        validateResponseStrict, 
        handleValidationErrors,
        applySafeEscape,  // Appliquer l'escape intelligent
        (req, res) => res.json({ body: req.body })
      );
    });

    test('should escape HTML in name', async () => {
      const data = {
        name: '<script>alert("xss")</script>',
        responses: [{ question: 'Q', answer: 'A' }]
      };

      const response = await request(app)
        .post('/test-escape')
        .send(data)
        .expect(200);

      expect(response.body.body.name).toContain('&lt;script&gt;');
      expect(response.body.body.name).not.toContain('<script>');
    });

    test('should escape HTML in questions', async () => {
      const data = {
        name: 'Valid Name',
        responses: [{ question: '<img src="x" onerror="alert(1)">', answer: 'A' }]
      };

      const response = await request(app)
        .post('/test-escape')
        .send(data)
        .expect(200);

      expect(response.body.body.responses[0].question).toContain('&lt;img');
      expect(response.body.body.responses[0].question).not.toContain('<img');
    });

    test('should escape HTML in answers', async () => {
      const data = {
        name: 'Valid Name',
        responses: [{ question: 'Q', answer: '"><script>alert("xss")</script>' }]
      };

      const response = await request(app)
        .post('/test-escape')
        .send(data)
        .expect(200);

      // smartEscape() escape tout sauf les URLs Cloudinary
      expect(response.body.body.responses[0].answer).toContain('&gt;&lt;script&gt;');
      expect(response.body.body.responses[0].answer).toContain('&quot;');
      expect(response.body.body.responses[0].answer).not.toContain('><script>');
    });
  });

  describe('Performance Edge Cases', () => {
    test('should handle maximum valid payload efficiently', async () => {
      // Create fresh app with larger body parser for this test
      const perfApp = express();
      perfApp.use(createFormBodyParser());
      perfApp.post('/test-performance', 
        validateResponseStrict, 
        handleValidationErrors, 
        sanitizeResponse,
        (req, res) => res.json({ success: true })
      );

      const maxPayload = {
        name: 'A'.repeat(100), // Max name length
        responses: Array(20).fill().map((_, i) => ({ // Max responses count
          question: 'Q'.repeat(500), // Max question length
          answer: 'A'.repeat(10000)  // Max answer length
        }))
      };

      const startTime = Date.now();

      await request(perfApp)
        .post('/test-performance')
        .send(maxPayload)
        .expect(200);

      const processingTime = Date.now() - startTime;
      
      // Should process large valid payload in reasonable time (under 1 second)
      expect(processingTime).toBeLessThan(1000);
    });

    test('should reject oversized payload quickly', async () => {
      app.post('/test-performance-reject', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ success: true })
      );

      const oversizedPayload = {
        name: 'A'.repeat(101), // Over max name length
        responses: [{ question: 'Q', answer: 'A' }]
      };

      const startTime = Date.now();

      await request(app)
        .post('/test-performance-reject')
        .send(oversizedPayload)
        .expect(400);

      const processingTime = Date.now() - startTime;
      
      // Should reject quickly (under 100ms)
      expect(processingTime).toBeLessThan(100);
    });
  });
});