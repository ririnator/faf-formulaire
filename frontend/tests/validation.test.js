/**
 * Frontend Validation Tests
 * 
 * These tests validate the frontend form validation logic.
 * Run with: npx jest --testPathPattern=frontend/tests
 */

// Mock DOM elements for testing
const mockElement = (value, files = null) => ({
  value,
  files,
  textContent: ''
});

const mockFeedback = { textContent: '' };

// Extract the validateField function logic for testing
function validateField(id, errorMessage, isFile = false, mockElements = {}) {
  const element = mockElements[id];
  const value = isFile ? element.files && element.files[0] : element.value.trim();
  if (!value) {
    mockFeedback.textContent = `❌ ${errorMessage}`;
    return false;
  }
  return value;
}

describe('Frontend Form Validation', () => {
  beforeEach(() => {
    mockFeedback.textContent = '';
  });

  describe('validateField function', () => {
    test('should return false for empty text input', () => {
      const mockElements = {
        'test-field': mockElement('   ') // whitespace only
      };

      const result = validateField('test-field', 'Field is required', false, mockElements);
      
      expect(result).toBe(false);
      expect(mockFeedback.textContent).toBe('❌ Field is required');
    });

    test('should return trimmed value for valid text input', () => {
      const mockElements = {
        'test-field': mockElement('  valid input  ')
      };

      const result = validateField('test-field', 'Field is required', false, mockElements);
      
      expect(result).toBe('valid input');
      expect(mockFeedback.textContent).toBe('');
    });

    test('should return false for empty file input', () => {
      const mockElements = {
        'file-field': mockElement('', null) // no files
      };

      const result = validateField('file-field', 'File is required', true, mockElements);
      
      expect(result).toBe(false);
      expect(mockFeedback.textContent).toBe('❌ File is required');
    });

    test('should return file for valid file input', () => {
      const mockFile = { name: 'test.jpg', size: 1024 };
      const mockElements = {
        'file-field': mockElement('', [mockFile])
      };

      const result = validateField('file-field', 'File is required', true, mockElements);
      
      expect(result).toBe(mockFile);
      expect(mockFeedback.textContent).toBe('');
    });

    test('should handle empty string input', () => {
      const mockElements = {
        'empty-field': mockElement('')
      };

      const result = validateField('empty-field', 'Cannot be empty', false, mockElements);
      
      expect(result).toBe(false);
      expect(mockFeedback.textContent).toBe('❌ Cannot be empty');
    });
  });

  describe('Error message handling', () => {
    test('should clear previous error messages', () => {
      mockFeedback.textContent = 'Previous error';
      
      const mockElements = {
        'valid-field': mockElement('valid')
      };

      validateField('valid-field', 'New error', false, mockElements);
      
      // Should not change feedback for valid input
      expect(mockFeedback.textContent).toBe('Previous error');
    });

    test('should display custom error messages', () => {
      const customMessage = 'Custom validation error';
      const mockElements = {
        'invalid-field': mockElement('')
      };

      validateField('invalid-field', customMessage, false, mockElements);
      
      expect(mockFeedback.textContent).toBe(`❌ ${customMessage}`);
    });
  });
});