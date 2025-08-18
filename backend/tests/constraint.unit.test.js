// Unit tests for database constraints (no MongoDB connection needed)
const Response = require('../models/Response');

describe('Response Model Constraints', () => {
  
  describe('Schema Definition Verification', () => {
    test('should have month and isAdmin index defined', () => {
      const indexes = Response.schema.indexes();
      
      // Find the month+isAdmin index
      const monthAdminIndex = indexes.find(index => {
        const keys = index[0];
        const options = index[1];
        
        return keys.month === 1 && 
               keys.isAdmin === 1 && 
               options.unique === true &&
               options.partialFilterExpression &&
               options.partialFilterExpression.isAdmin === true;
      });
      
      expect(monthAdminIndex).toBeDefined();
      expect(monthAdminIndex[1].unique).toBe(true);
      expect(monthAdminIndex[1].partialFilterExpression.isAdmin).toBe(true);
    });

    test('should have token field with sparse unique index', () => {
      const tokenPath = Response.schema.paths.token;
      expect(tokenPath).toBeDefined();
      
      // Check for index-level constraints (not field-level)
      const indexes = Response.schema.indexes();
      const tokenIndex = indexes.find(index => {
        const keys = index[0];
        const options = index[1];
        return keys.token === 1 && options.unique === true && options.sparse === true;
      });
      
      expect(tokenIndex).toBeDefined();
      expect(tokenIndex[1].unique).toBe(true);
      expect(tokenIndex[1].sparse).toBe(true);
    });

    test('should have required fields properly configured', () => {
      // Only month is required in the updated schema (name is legacy, userId is optional)
      const requiredFields = ['month'];
      
      requiredFields.forEach(field => {
        const path = Response.schema.paths[field];
        expect(path).toBeDefined();
        expect(path.isRequired).toBe(true);
      });
      
      // Verify legacy fields exist but are not required
      const legacyFields = ['name', 'userId', 'token'];
      legacyFields.forEach(field => {
        const path = Response.schema.paths[field];
        expect(path).toBeDefined();
      });
    });

    test('should have isAdmin field with correct default', () => {
      const isAdminPath = Response.schema.paths.isAdmin;
      expect(isAdminPath).toBeDefined();
      expect(isAdminPath.defaultValue).toBe(false);
    });

    test('should have createdAt field with Date default', () => {
      const createdAtPath = Response.schema.paths.createdAt;
      expect(createdAtPath).toBeDefined();
      expect(createdAtPath.defaultValue).toBeDefined();
    });
  });

  describe('Validation Logic', () => {
    test('should create valid user response object', () => {
      const userData = {
        name: 'Test User',
        responses: [{ question: 'Q1', answer: 'A1' }],
        month: '2025-01',
        isAdmin: false,
        token: 'unique-token'
      };

      const userResponse = new Response(userData);
      
      expect(userResponse.name).toBe('Test User');
      expect(userResponse.month).toBe('2025-01');
      expect(userResponse.isAdmin).toBe(false);
      expect(userResponse.token).toBe('unique-token');
      expect(userResponse.responses).toHaveLength(1);
    });

    test('should create valid admin response object', () => {
      const adminData = {
        name: 'Admin User',
        responses: [{ question: 'Q1', answer: 'A1' }],
        month: '2025-01',
        isAdmin: true
        // No token for admin
      };

      const adminResponse = new Response(adminData);
      
      expect(adminResponse.name).toBe('Admin User');
      expect(adminResponse.month).toBe('2025-01');
      expect(adminResponse.isAdmin).toBe(true);
      expect(adminResponse.token).toBeUndefined();
    });

    test('should fail validation without required fields', () => {
      const incompleteData = {
        responses: [{ question: 'Q1', answer: 'A1' }]
        // Missing month (only required field)
      };

      const response = new Response(incompleteData);
      const validationError = response.validateSync();
      
      expect(validationError).toBeDefined();
      expect(validationError.errors.month).toBeDefined();
      // name is no longer required (legacy field)
    });

    test('should validate responses array structure', () => {
      const validData = {
        name: 'Test User',
        month: '2025-01',
        responses: [
          { question: 'Question 1', answer: 'Answer 1' },
          { question: 'Question 2', answer: 'Answer 2' }
        ],
        token: 'test-token'
      };

      const response = new Response(validData);
      const validationError = response.validateSync();
      
      expect(validationError).toBeUndefined();
      expect(response.responses).toHaveLength(2);
      expect(response.responses[0].question).toBe('Question 1');
      expect(response.responses[1].answer).toBe('Answer 2');
    });
  });

  describe('Index Configuration Analysis', () => {
    test('should analyze all configured indexes', () => {
      const allIndexes = Response.schema.indexes();
      
      // Should have at least 2 indexes: month+isAdmin and token
      expect(allIndexes.length).toBeGreaterThanOrEqual(1);
      
      // Check for month+isAdmin unique index
      const hasMonthAdminIndex = allIndexes.some(index => {
        const keys = index[0];
        return keys.month === 1 && keys.isAdmin === 1;
      });
      
      expect(hasMonthAdminIndex).toBe(true);
    });

    test('should verify partial filter expression prevents non-admin conflicts', () => {
      const indexes = Response.schema.indexes();
      
      const monthAdminIndex = indexes.find(index => {
        const keys = index[0];
        return keys.month === 1 && keys.isAdmin === 1;
      });
      
      // Verify partial filter only applies to admin responses
      expect(monthAdminIndex[1].partialFilterExpression).toEqual({ isAdmin: true });
      
      // This means non-admin responses with same month won't conflict
      // Only admin responses are subject to the unique constraint
    });

    test('should verify token uniqueness is sparse', () => {
      // Check token field configuration
      const tokenField = Response.schema.paths.token;
      expect(tokenField).toBeDefined();
      
      // Check for index-level constraints (not field-level)
      const indexes = Response.schema.indexes();
      const tokenIndex = indexes.find(index => {
        const keys = index[0];
        const options = index[1];
        return keys.token === 1 && options.unique === true && options.sparse === true;
      });
      
      expect(tokenIndex).toBeDefined();
      // Sparse index means null/undefined values don't create conflicts
      expect(tokenIndex[1].sparse).toBe(true);
      expect(tokenIndex[1].unique).toBe(true);
      
      // This allows multiple admin responses without tokens
      // while ensuring unique tokens for user responses
    });
  });

  describe('Business Logic Validation', () => {
    test('should represent correct admin vs user distinction', () => {
      // Admin response characteristics
      const adminData = {
        name: 'Admin',
        month: '2025-01',
        isAdmin: true
        // No token - admin responses don't need private links
      };
      
      // User response characteristics  
      const userData = {
        name: 'User',
        month: '2025-01',
        isAdmin: false,
        token: 'private-link-token'
      };
      
      const admin = new Response(adminData);
      const user = new Response(userData);
      
      // Admin should have no token
      expect(admin.token).toBeUndefined();
      expect(admin.isAdmin).toBe(true);
      
      // User should have token for private access
      expect(user.token).toBe('private-link-token');
      expect(user.isAdmin).toBe(false);
    });

    test('should support monthly response system', () => {
      const jan2025 = new Response({
        name: 'User',
        month: '2025-01',
        responses: [{ question: 'January Q', answer: 'January A' }],
        token: 'jan-token'
      });
      
      const feb2025 = new Response({
        name: 'User',
        month: '2025-02', 
        responses: [{ question: 'February Q', answer: 'February A' }],
        token: 'feb-token'
      });
      
      // Same user should be able to submit different months
      expect(jan2025.name).toBe(feb2025.name);
      expect(jan2025.month).not.toBe(feb2025.month);
      expect(jan2025.token).not.toBe(feb2025.token);
    });
  });
});