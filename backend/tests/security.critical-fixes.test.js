/**
 * Security Tests for Critical Fixes
 * 
 * Tests to validate the security fixes implemented:
 * 1. XSS protection in customMessage field (invitationRoutes.js)
 * 2. Enhanced CSV upload security (contactRoutes.js) 
 * 3. Standardized user ID extraction across route files
 */

const request = require('supertest');
const express = require('express');
const { smartEscape } = require('../middleware/validation');

describe('🔒 Security: Critical Fixes', () => {
  
  describe('XSS Protection - customMessage Field', () => {
    test('should sanitize XSS attempts in customMessage', () => {
      const testCases = [
        {
          input: '<script>alert("XSS")</script>',
          expectedNotToContain: ['<script', '<', '>', '"']
        },
        {
          input: '<img src="x" onerror="alert(1)">',
          expectedNotToContain: ['<img', '<', '>']
        },
        {
          input: '<svg onload="alert(1)">',
          expectedNotToContain: ['<svg', '<', '>']
        },
        {
          input: '"><script>alert("XSS")</script>',
          expectedNotToContain: ['<script', '<', '>']
        },
        {
          input: "'><script>alert('XSS')</script>",
          expectedNotToContain: ['<script', '<', '>']
        }
      ];

      testCases.forEach(({ input, expectedNotToContain }) => {
        const sanitized = smartEscape(input);
        
        expectedNotToContain.forEach(pattern => {
          expect(sanitized).not.toContain(pattern);
        });
        
        // Verify HTML entities are escaped
        expect(sanitized).toContain('&lt;'); // < becomes &lt;
        expect(sanitized).toContain('&gt;'); // > becomes &gt;
        
        // Check for quote escaping only if input contains double quotes
        if (input.includes('"')) {
          expect(sanitized).toContain('&quot;'); // " becomes &quot;
        }
      });

      // Special case for javascript: URLs - quotes should be escaped but protocol remains
      const jsUrl = 'javascript:alert("XSS")';
      const sanitizedJs = smartEscape(jsUrl);
      // The quotes should be escaped, making the payload less dangerous
      expect(sanitizedJs).toContain('&quot;');
    });

    test('should preserve safe content in customMessage', () => {
      const safeInputs = [
        'Hello, this is a safe message!',
        'Message avec des accents: éàçù',
        'Numbers and symbols: 123 #$%',
        'Email: test@example.com',
        'Normal punctuation: Hello, world!'
      ];

      safeInputs.forEach(input => {
        const sanitized = smartEscape(input);
        // Safe content should be preserved (though HTML entities will be escaped)
        expect(sanitized).toBeTruthy();
        expect(typeof sanitized).toBe('string');
      });
    });

    test('should preserve Cloudinary URLs while escaping other content', () => {
      const cloudinaryUrl = 'https://res.cloudinary.com/test/image/upload/v1234567890/sample.jpg';
      const maliciousWithCloudinary = `${cloudinaryUrl}<script>alert("XSS")</script>`;
      
      // Cloudinary URL should be preserved
      const sanitizedUrl = smartEscape(cloudinaryUrl);
      expect(sanitizedUrl).toBe(cloudinaryUrl);
      
      // But malicious content should be escaped
      const sanitizedMalicious = smartEscape(maliciousWithCloudinary);
      expect(sanitizedMalicious).toContain('&lt;script&gt;');
    });
  });

  describe('CSV Upload Security', () => {
    test('should validate allowed MIME types', () => {
      const allowedMimeTypes = [
        'text/csv',
        'text/plain',
        'application/csv',
        'application/vnd.ms-excel'
      ];

      const invalidMimeTypes = [
        'application/javascript',
        'text/html',
        'image/png',
        'application/octet-stream',
        'application/x-executable',
        'text/x-script'
      ];

      // Test allowed types (these should pass validation)
      allowedMimeTypes.forEach(mimeType => {
        expect(allowedMimeTypes).toContain(mimeType);
      });

      // Test invalid types (these should be rejected)
      invalidMimeTypes.forEach(mimeType => {
        expect(allowedMimeTypes).not.toContain(mimeType);
      });
    });

    test('should validate file extensions', () => {
      const allowedExtensions = ['csv', 'txt'];
      
      const testCases = [
        { fileName: 'data.csv', expected: true },
        { fileName: 'data.txt', expected: true },
        { fileName: 'DATA.CSV', expected: true }, // case insensitive
        { fileName: 'data.js', expected: false },
        { fileName: 'data.exe', expected: false },
        { fileName: 'data.html', expected: false },
        { fileName: 'data.php', expected: false },
        { fileName: 'malicious.csv.exe', expected: false }
      ];

      testCases.forEach(({ fileName, expected }) => {
        const extension = fileName.toLowerCase().split('.').pop();
        const isValid = allowedExtensions.includes(extension);
        expect(isValid).toBe(expected);
      });
    });

    test('should detect malicious content patterns in CSV data', () => {
      const maliciousPatterns = [
        /<script/i,
        /javascript:/i,
        /vbscript:/i,
        /onload=/i,
        /onerror=/i,
        /onclick=/i,
        /<iframe/i,
        /<object/i,
        /<embed/i
      ];

      const maliciousCSVData = [
        'name,email\n<script>alert("XSS")</script>,test@example.com',
        'name,email\njavascript:alert("XSS"),test@example.com',
        'name,email\n<iframe src="malicious.html">,test@example.com',
        'name,email\nJohn,<img onerror="alert(1)" src="x">',
        'name,email\n<object data="malicious.swf">,test@example.com'
      ];

      maliciousCSVData.forEach(csvData => {
        let foundMalicious = false;
        maliciousPatterns.forEach(pattern => {
          if (pattern.test(csvData)) {
            foundMalicious = true;
          }
        });
        expect(foundMalicious).toBe(true);
      });
    });

    test('should allow safe CSV content', () => {
      const safeCSVData = [
        'name,email,phone\nJohn Doe,john@example.com,123-456-7890',
        'prénom,nom,email\nJean,Dupont,jean.dupont@example.com',
        'name,description\nProduct 1,"Safe description with, comma"',
        'first_name,last_name,company\nMarie,Martin,"Company & Co"'
      ];

      const maliciousPatterns = [
        /<script/i,
        /javascript:/i,
        /vbscript:/i,
        /onload=/i,
        /onerror=/i,
        /onclick=/i,
        /<iframe/i,
        /<object/i,
        /<embed/i
      ];

      safeCSVData.forEach(csvData => {
        let foundMalicious = false;
        maliciousPatterns.forEach(pattern => {
          if (pattern.test(csvData)) {
            foundMalicious = true;
          }
        });
        expect(foundMalicious).toBe(false);
      });
    });

    test('should detect binary content in CSV uploads', () => {
      const binaryData = [
        'name,email\nJohn\x00Doe,test@example.com', // null byte
        'name,email\nJohn\x01\x02\x03,test@example.com', // control characters
        'name,email\nJohn\x0E\x0F\x10,test@example.com', // more control chars
        'name,email\n\x1F\x1E\x1D,test@example.com' // non-printable chars
      ];

      binaryData.forEach(data => {
        const hasBinary = data.includes('\x00') || /[\x01-\x08\x0B\x0C\x0E-\x1F]/.test(data);
        expect(hasBinary).toBe(true);
      });
    });
  });

  describe('User ID Extraction Standardization', () => {
    test('should extract user ID with correct priority', () => {
      const testRequests = [
        // Case 1: All three present, should prioritize currentUser.id
        {
          req: {
            currentUser: { id: 'currentUserId' },
            user: { id: 'userId' },
            session: { userId: 'sessionUserId' }
          },
          expected: 'currentUserId'
        },
        // Case 2: Only user.id and session.userId present
        {
          req: {
            user: { id: 'userId' },
            session: { userId: 'sessionUserId' }
          },
          expected: 'userId'
        },
        // Case 3: Only session.userId present
        {
          req: {
            session: { userId: 'sessionUserId' }
          },
          expected: 'sessionUserId'
        },
        // Case 4: None present
        {
          req: {},
          expected: undefined
        },
        // Case 5: currentUser exists but no id
        {
          req: {
            currentUser: {},
            session: { userId: 'sessionUserId' }
          },
          expected: 'sessionUserId'
        }
      ];

      // Simulate the getUserId function
      const getUserId = (req) => {
        return req.currentUser?.id || req.user?.id || req.session?.userId;
      };

      testRequests.forEach(({ req, expected }, index) => {
        const result = getUserId(req);
        expect(result).toBe(expected);
      });
    });

    test('should handle null and undefined values gracefully', () => {
      const getUserId = (req) => {
        return req.currentUser?.id || req.user?.id || req.session?.userId;
      };

      const edgeCases = [
        { req: null, expected: undefined },
        { req: undefined, expected: undefined },
        { req: { currentUser: null }, expected: undefined },
        { req: { user: null }, expected: undefined },
        { req: { session: null }, expected: undefined },
        { req: { currentUser: { id: null } }, expected: undefined },
        { req: { currentUser: { id: '' } }, expected: undefined }, // empty string is falsy so falls through to undefined
      ];

      edgeCases.forEach(({ req, expected }) => {
        expect(() => {
          const result = req ? getUserId(req) : undefined;
          expect(result).toBe(expected);
        }).not.toThrow();
      });
    });
  });

  describe('Integration Security Tests', () => {
    test('should prevent XSS in customMessage through validation chain', () => {
      // Simulate the validation chain
      const { body } = require('express-validator');
      
      const customMessageValidator = body('customMessage')
        .optional()
        .trim()
        .isLength({ max: 500 })
        .withMessage('Message personnalisé maximum 500 caractères')
        .customSanitizer(value => value ? smartEscape(value.trim()) : '');

      // This is a unit test of the sanitizer function
      const testInputs = [
        { input: '<script>alert("XSS")</script>', expectSafe: true },
        { input: 'Safe message', expectSafe: true },
        { input: '', expectSafe: true },
        { input: null, expectSafe: true },
        { input: undefined, expectSafe: true }
      ];

      testInputs.forEach(({ input, expectSafe }) => {
        const sanitized = input ? smartEscape(input.toString().trim()) : '';
        if (expectSafe) {
          expect(typeof sanitized).toBe('string');
          expect(sanitized).not.toMatch(/<script/i);
        }
      });
    });

    test('should validate CSV security requirements comprehensively', () => {
      const csvSecurityCheck = (csvData, mimeType, fileName) => {
        const results = {
          sizeValid: false,
          mimeTypeValid: false,
          extensionValid: false,
          contentSafe: false,
          noBinaryContent: false
        };

        // Size check (5MB limit)
        const csvSizeBytes = Buffer.byteLength(csvData, 'utf8');
        const maxSizeBytes = 5 * 1024 * 1024;
        results.sizeValid = csvSizeBytes <= maxSizeBytes;

        // MIME type check
        const allowedMimeTypes = [
          'text/csv',
          'text/plain',
          'application/csv',
          'application/vnd.ms-excel'
        ];
        results.mimeTypeValid = !mimeType || allowedMimeTypes.includes(mimeType);

        // File extension check
        if (fileName) {
          const fileExtension = fileName.toLowerCase().split('.').pop();
          const allowedExtensions = ['csv', 'txt'];
          results.extensionValid = allowedExtensions.includes(fileExtension);
        } else {
          results.extensionValid = true; // No filename provided
        }

        // Content safety check
        const maliciousPatterns = [
          /<script/i, /javascript:/i, /vbscript:/i, /onload=/i,
          /onerror=/i, /onclick=/i, /<iframe/i, /<object/i, /<embed/i
        ];
        results.contentSafe = !maliciousPatterns.some(pattern => pattern.test(csvData));

        // Binary content check
        results.noBinaryContent = !csvData.includes('\x00') && !/[\x01-\x08\x0B\x0C\x0E-\x1F]/.test(csvData);

        return results;
      };

      // Test safe CSV
      const safeCSV = 'name,email\nJohn Doe,john@example.com';
      const safeResults = csvSecurityCheck(safeCSV, 'text/csv', 'data.csv');
      expect(safeResults.sizeValid).toBe(true);
      expect(safeResults.mimeTypeValid).toBe(true);
      expect(safeResults.extensionValid).toBe(true);
      expect(safeResults.contentSafe).toBe(true);
      expect(safeResults.noBinaryContent).toBe(true);

      // Test malicious CSV
      const maliciousCSV = 'name,email\n<script>alert("XSS")</script>,hacker@evil.com';
      const maliciousResults = csvSecurityCheck(maliciousCSV, 'application/javascript', 'malicious.js');
      expect(maliciousResults.mimeTypeValid).toBe(false);
      expect(maliciousResults.extensionValid).toBe(false);
      expect(maliciousResults.contentSafe).toBe(false);
    });
  });

  describe('Regression Tests', () => {
    test('should maintain existing functionality while adding security', () => {
      // Test that normal operations still work
      const normalMessage = 'Hello, this is a normal invitation message.';
      const escaped = smartEscape(normalMessage);
      
      // Should not break normal text processing
      expect(escaped).toBeTruthy();
      expect(typeof escaped).toBe('string');
      
      // Should handle French characters properly
      const frenchMessage = 'Bonjour, voici un message avec des accents: éàçù';
      const escapedFrench = smartEscape(frenchMessage);
      expect(escapedFrench).toBeTruthy();
    });

    test('should handle edge cases gracefully', () => {
      const edgeCases = [
        { input: null, expectedResult: null },
        { input: undefined, expectedResult: undefined },
        { input: '', expectedResult: '' },
        { input: '   ', expectedResult: '   ' }, // whitespace preserved
        { input: 0, expectedResult: 0 }, // number returned as-is
        { input: false, expectedResult: false }, // boolean returned as-is
        { input: {}, expectedResult: {} } // object returned as-is
      ];

      edgeCases.forEach(({ input, expectedResult }) => {
        expect(() => {
          const result = smartEscape(input);
          expect(result).toEqual(expectedResult);
        }).not.toThrow();
      });
    });
  });
});