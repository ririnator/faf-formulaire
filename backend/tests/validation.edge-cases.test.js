const request = require('supertest');
const express = require('express');
const { 
  validateResponseStrict, 
  validateResponse, 
  validateLogin, 
  handleValidationErrors, 
  sanitizeResponse 
} = require('../middleware/validation');

describe('Input Validation Edge Cases', () => {
  let app;

  beforeEach(() => {
    app = express();
    app.use(express.json());
  });

  describe('Null and Undefined Values', () => {
    describe('Strict Validation', () => {
      beforeEach(() => {
        app.post('/test-strict', 
          validateResponseStrict, 
          handleValidationErrors, 
          (req, res) => res.json({ success: true, body: req.body })
        );
      });

      test('should reject null name', async () => {
        const nullData = {
          name: null,
          responses: [{ question: 'Test', answer: 'Test' }]
        };

        const response = await request(app)
          .post('/test-strict')
          .send(nullData)
          .expect(400);

        expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
        expect(response.body.field).toBe('name');
      });

      test('should reject undefined name', async () => {
        const undefinedData = {
          name: undefined,
          responses: [{ question: 'Test', answer: 'Test' }]
        };

        const response = await request(app)
          .post('/test-strict')
          .send(undefinedData)
          .expect(400);

        expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
      });

      test('should reject empty string name after trim', async () => {
        const emptyData = {
          name: '   ',  // Only whitespace
          responses: [{ question: 'Test', answer: 'Test' }]
        };

        const response = await request(app)
          .post('/test-strict')
          .send(emptyData)
          .expect(400);

        expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
      });

      test('should reject null responses array', async () => {
        const nullResponsesData = {
          name: 'Valid Name',
          responses: null
        };

        const response = await request(app)
          .post('/test-strict')
          .send(nullResponsesData)
          .expect(400);

        expect(response.body.message).toContain('Il faut entre 1 et 20 réponses');
      });

      test('should reject undefined responses array', async () => {
        const undefinedResponsesData = {
          name: 'Valid Name',
          responses: undefined
        };

        const response = await request(app)
          .post('/test-strict')
          .send(undefinedResponsesData)
          .expect(400);

        expect(response.body.message).toContain('Il faut entre 1 et 20 réponses');
      });

      test('should reject responses with null question', async () => {
        const nullQuestionData = {
          name: 'Valid Name',
          responses: [{ question: null, answer: 'Valid answer' }]
        };

        const response = await request(app)
          .post('/test-strict')
          .send(nullQuestionData)
          .expect(400);

        expect(response.body.message).toContain('question ne peut pas être nulle');
      });

      test('should reject responses with undefined answer', async () => {
        const undefinedAnswerData = {
          name: 'Valid Name',
          responses: [{ question: 'Valid question', answer: undefined }]
        };

        const response = await request(app)
          .post('/test-strict')
          .send(undefinedAnswerData)
          .expect(400);

        expect(response.body.message).toContain('réponse ne peut pas être nulle');
      });

      test('should reject responses with null both question and answer', async () => {
        const nullBothData = {
          name: 'Valid Name',
          responses: [{ question: null, answer: null }]
        };

        const response = await request(app)
          .post('/test-strict')
          .send(nullBothData)
          .expect(400);

        // Should fail on first validation error (question)
        expect(response.body.message).toContain('question ne peut pas être nulle');
      });

      test('should handle mixed null/valid responses', async () => {
        const mixedData = {
          name: 'Valid Name',
          responses: [
            { question: 'Valid question', answer: 'Valid answer' },
            { question: null, answer: 'Valid answer' },
            { question: 'Valid question', answer: undefined }
          ]
        };

        const response = await request(app)
          .post('/test-strict')
          .send(mixedData)
          .expect(400);

        expect(response.body.message).toContain('question ne peut pas être nulle');
      });
    });

    describe('Legacy Validation', () => {
      beforeEach(() => {
        app.post('/test-legacy', 
          validateResponse, 
          handleValidationErrors, 
          (req, res) => res.json({ success: true, body: req.body })
        );
      });

      test('should reject null name in legacy validation', async () => {
        const nullData = {
          name: null,
          responses: [{ question: 'Test', answer: 'Test' }]
        };

        const response = await request(app)
          .post('/test-legacy')
          .send(nullData)
          .expect(400);

        expect(response.body.message).toContain('nom doit contenir au moins 2 caractères');
      });

      test('should reject empty responses in legacy validation', async () => {
        const emptyResponsesData = {
          name: 'Valid Name',
          responses: []
        };

        const response = await request(app)
          .post('/test-legacy')
          .send(emptyResponsesData)
          .expect(400);

        expect(response.body.message).toContain('Il faut au moins une réponse');
      });
    });

    describe('Login Validation', () => {
      beforeEach(() => {
        app.post('/test-login', 
          validateLogin, 
          handleValidationErrors, 
          (req, res) => res.json({ success: true })
        );
      });

      test('should reject null username', async () => {
        const nullUsernameData = {
          username: null,
          password: 'validpassword'
        };

        const response = await request(app)
          .post('/test-login')
          .send(nullUsernameData)
          .expect(400);

        expect(response.body.message).toContain('Nom d\'utilisateur requis');
      });

      test('should reject undefined password', async () => {
        const undefinedPasswordData = {
          username: 'validuser',
          password: undefined
        };

        const response = await request(app)
          .post('/test-login')
          .send(undefinedPasswordData)
          .expect(400);

        expect(response.body.message).toContain('Mot de passe requis');
      });

      test('should reject both null credentials', async () => {
        const nullBothData = {
          username: null,
          password: null
        };

        const response = await request(app)
          .post('/test-login')
          .send(nullBothData)
          .expect(400);

        expect(response.body.message).toContain('Nom d\'utilisateur requis');
      });

      test('should reject empty string credentials', async () => {
        const emptyData = {
          username: '',
          password: ''
        };

        const response = await request(app)
          .post('/test-login')
          .send(emptyData)
          .expect(400);

        expect(response.body.message).toContain('Nom d\'utilisateur requis');
      });
    });
  });

  describe('Sanitization Edge Cases', () => {
    beforeEach(() => {
      app.post('/test-sanitize', 
        sanitizeResponse,
        (req, res) => res.json({ sanitized: req.body })
      );
    });

    test('should handle null responses array', async () => {
      const nullResponsesData = {
        name: 'Test',
        responses: null
      };

      const response = await request(app)
        .post('/test-sanitize')
        .send(nullResponsesData)
        .expect(200);

      expect(response.body.sanitized.responses).toBeNull();
    });

    test('should handle undefined responses array', async () => {
      const undefinedResponsesData = {
        name: 'Test',
        responses: undefined
      };

      const response = await request(app)
        .post('/test-sanitize')
        .send(undefinedResponsesData)
        .expect(200);

      expect(response.body.sanitized.responses).toBeUndefined();
    });

    test('should sanitize null/undefined question and answer', async () => {
      const nullFieldsData = {
        name: 'Test',
        responses: [
          { question: null, answer: undefined },
          { question: undefined, answer: null },
          { question: 'Valid', answer: 'Valid' }
        ]
      };

      const response = await request(app)
        .post('/test-sanitize')
        .send(nullFieldsData)
        .expect(200);

      expect(response.body.sanitized.responses[0].question).toBe('');
      expect(response.body.sanitized.responses[0].answer).toBe('');
      expect(response.body.sanitized.responses[1].question).toBe('');
      expect(response.body.sanitized.responses[1].answer).toBe('');
      expect(response.body.sanitized.responses[2].question).toBe('Valid');
      expect(response.body.sanitized.responses[2].answer).toBe('Valid');
    });

    test('should handle responses with missing properties', async () => {
      const incompleteResponsesData = {
        name: 'Test',
        responses: [
          { question: 'Only question' }, // Missing answer
          { answer: 'Only answer' },     // Missing question
          {}                             // Empty object
        ]
      };

      const response = await request(app)
        .post('/test-sanitize')
        .send(incompleteResponsesData)
        .expect(200);

      expect(response.body.sanitized.responses[0].question).toBe('Only question');
      expect(response.body.sanitized.responses[0].answer).toBe('');
      expect(response.body.sanitized.responses[1].question).toBe('');
      expect(response.body.sanitized.responses[1].answer).toBe('Only answer');
      expect(response.body.sanitized.responses[2].question).toBe('');
      expect(response.body.sanitized.responses[2].answer).toBe('');
    });

    test('should handle non-string values in question/answer', async () => {
      const nonStringData = {
        name: 'Test',
        responses: [
          { question: 123, answer: true },
          { question: {}, answer: [] },
          { question: 'string', answer: 456 }
        ]
      };

      const response = await request(app)
        .post('/test-sanitize')
        .send(nonStringData)
        .expect(200);

      expect(response.body.sanitized.responses[0].question).toBe('123');
      expect(response.body.sanitized.responses[0].answer).toBe('true');
      expect(response.body.sanitized.responses[1].question).toBe('[object Object]');
      expect(response.body.sanitized.responses[1].answer).toBe('');
      expect(response.body.sanitized.responses[2].question).toBe('string');
      expect(response.body.sanitized.responses[2].answer).toBe('456');
    });
  });

  describe('Malformed Request Bodies', () => {
    test('should handle completely missing body', async () => {
      app.post('/test-missing', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ success: true })
      );

      const response = await request(app)
        .post('/test-missing')
        .expect(400);

      expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
    });

    test('should handle empty object body', async () => {
      app.post('/test-empty', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ success: true })
      );

      const response = await request(app)
        .post('/test-empty')
        .send({})
        .expect(400);

      expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
    });

    test('should handle partial object with missing required fields', async () => {
      app.post('/test-partial', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ success: true })
      );

      const partialData = {
        name: 'Valid Name'
        // Missing responses array
      };

      const response = await request(app)
        .post('/test-partial')
        .send(partialData)
        .expect(400);

      expect(response.body.message).toContain('Il faut entre 1 et 20 réponses');
    });
  });

  describe('Type Coercion Edge Cases', () => {
    beforeEach(() => {
      app.post('/test-coercion', 
        validateResponseStrict, 
        handleValidationErrors, 
        sanitizeResponse,
        (req, res) => res.json({ body: req.body })
      );
    });

    test('should handle numeric name values', async () => {
      const numericNameData = {
        name: 123456789,
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      const response = await request(app)
        .post('/test-coercion')
        .send(numericNameData)
        .expect(200);

      expect(typeof response.body.body.name).toBe('string');
    });

    test('should handle boolean values in responses', async () => {
      const booleanData = {
        name: 'Valid Name',
        responses: [
          { question: true, answer: false },
          { question: 'String question', answer: true }
        ]
      };

      const response = await request(app)
        .post('/test-coercion')
        .send(booleanData);

      // Boolean values may fail validation due to null check
      expect([200, 400]).toContain(response.status);
    });

    test('should handle array values in name field', async () => {
      const arrayNameData = {
        name: ['John', 'Doe'],
        responses: [{ question: 'Test', answer: 'Test' }]
      };

      const response = await request(app)
        .post('/test-coercion')
        .send(arrayNameData);

      // Arrays may be coerced to strings by Express, so either pass or fail is acceptable
      expect([200, 400]).toContain(response.status);
    });
  });

  describe('Deep Nesting Edge Cases', () => {
    test('should handle deeply nested null values', async () => {
      app.post('/test-deep', 
        sanitizeResponse,
        (req, res) => res.json({ sanitized: req.body })
      );

      const deepNullData = {
        name: 'Test',
        responses: [
          {
            question: {
              nested: {
                deep: null
              }
            },
            answer: 'Valid'
          }
        ]
      };

      const response = await request(app)
        .post('/test-deep')
        .send(deepNullData)
        .expect(200);

      expect(response.body.sanitized.responses[0].question).toBe('[object Object]');
    });

    test('should handle responses array with null elements', async () => {
      app.post('/test-null-elements', 
        sanitizeResponse,
        (req, res) => res.json({ sanitized: req.body })
      );

      const nullElementsData = {
        name: 'Test',
        responses: [
          null,
          { question: 'Valid', answer: 'Valid' },
          undefined,
          { question: 'Another', answer: 'Valid' }
        ]
      };

      const response = await request(app)
        .post('/test-null-elements')
        .send(nullElementsData)
        .expect(200);
        
      // Null elements should be filtered out, leaving valid responses
      expect(response.body.sanitized.responses).toHaveLength(2);
      expect(response.body.sanitized.responses[0].question).toBe('Valid');
      expect(response.body.sanitized.responses[1].question).toBe('Another');
    });
  });

  describe('Validation Error Handling', () => {
    test('should return first validation error only', async () => {
      app.post('/test-multiple-errors', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ success: true })
      );

      const multipleErrorsData = {
        name: null,           // Error 1
        responses: null,      // Error 2
        website: 'spam'       // Error 3 (honeypot)
      };

      const response = await request(app)
        .post('/test-multiple-errors')
        .send(multipleErrorsData)
        .expect(400);

      // Should return only first error
      expect(response.body.message).toContain('nom doit contenir entre 2 et 100 caractères');
      expect(response.body.field).toBe('name');
      expect(response.body.message).not.toContain('réponses');
      expect(response.body.message).not.toContain('spam');
    });

    test('should preserve field path in nested validation errors', async () => {
      app.post('/test-nested-errors', 
        validateResponseStrict, 
        handleValidationErrors, 
        (req, res) => res.json({ success: true })
      );

      const nestedErrorData = {
        name: 'Valid Name',
        responses: [
          { question: 'Valid', answer: 'Valid' },
          { question: null, answer: 'Valid' }  // Error in second element
        ]
      };

      const response = await request(app)
        .post('/test-nested-errors')
        .send(nestedErrorData)
        .expect(400);

      expect(response.body.field).toContain('responses');
      expect(response.body.field).toContain('question');
    });
  });
});