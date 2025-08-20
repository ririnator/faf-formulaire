/**
 * Test Constants Configuration
 * Centralizes all test configuration values and environment-specific settings
 */

// Test Environment Configuration
const TEST_ENV = {
  NODE_ENV: 'test',
  DATABASE_NAME: process.env.TEST_DB_NAME || 'faf-test-db',
  TIMEOUT: {
    DEFAULT: parseInt(process.env.TEST_TIMEOUT_DEFAULT) || 10000,
    INTEGRATION: parseInt(process.env.TEST_TIMEOUT_INTEGRATION) || 15000,
    E2E: parseInt(process.env.TEST_TIMEOUT_E2E) || 30000,
    API: parseInt(process.env.TEST_TIMEOUT_API) || 5000
  },
  RETRY_ATTEMPTS: parseInt(process.env.TEST_RETRY_ATTEMPTS) || 3
};

// Test Data Configuration
const TEST_DATA = {
  USERS: {
    REGULAR: {
      PROFILE: {
        firstName: 'Test',
        lastName: 'User',
        dateOfBirth: new Date('1990-01-01'),
        profession: 'Software Developer',
        location: 'Paris, France'
      },
      PREFERENCES: {
        emailNotifications: true,
        reminderFrequency: 'weekly',
        timezone: 'Europe/Paris',
        language: 'fr',
        privacy: {
          shareProfile: true,
          allowSearchByEmail: true
        }
      }
    },
    ADMIN: {
      PROFILE: {
        firstName: 'Admin',
        lastName: 'User',
        dateOfBirth: new Date('1985-01-01'),
        profession: 'System Administrator'
      }
    }
  },
  
  SUBMISSIONS: {
    SAMPLE_RESPONSES: [
      { questionId: 'q1', type: 'text', answer: 'Sample answer 1' },
      { questionId: 'q2', type: 'text', answer: 'Sample answer 2' },
      { questionId: 'q3', type: 'photo', answer: '', photoUrl: 'https://res.cloudinary.com/test/image.jpg' }
    ],
    COMPLETION_RATES: [0, 25, 50, 75, 100]
  },

  HANDSHAKES: {
    // French text for internationalization testing - validates UTF-8 support
    FRENCH_MESSAGE: 'Salut! Veux-tu rejoindre Form-a-Friend?',
    NOTIFICATION_TITLE: 'Handshake accepté',
    NOTIFICATION_MESSAGE: 'Votre demande de contact a été acceptée par {email}'
  }
};

// Test Security Configuration
const SECURITY_CONFIG = {
  PASSWORD_REQUIREMENTS: {
    MIN_LENGTH: 8,
    REQUIRE_SPECIAL_CHARS: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_UPPERCASE: true
  },
  
  RATE_LIMITING: {
    MAX_REQUESTS: parseInt(process.env.TEST_RATE_LIMIT_MAX) || 100,
    WINDOW_MS: parseInt(process.env.TEST_RATE_LIMIT_WINDOW) || 900000, // 15 minutes
    MAX_CONCURRENT: parseInt(process.env.TEST_MAX_CONCURRENT) || 10
  },

  SESSION: {
    COOKIE_NAME: 'faf-session',
    MAX_AGE: parseInt(process.env.TEST_SESSION_MAX_AGE) || 3600000, // 1 hour
    SECURE_COOKIES: process.env.NODE_ENV === 'production'
  }
};

// Performance Testing Thresholds
const PERFORMANCE_THRESHOLDS = {
  API_RESPONSE_TIME: parseInt(process.env.TEST_API_RESPONSE_THRESHOLD) || 500, // ms
  DATABASE_QUERY_TIME: parseInt(process.env.TEST_DB_QUERY_THRESHOLD) || 100, // ms
  CONCURRENT_USERS: parseInt(process.env.TEST_CONCURRENT_USERS) || 50,
  MEMORY_USAGE_MB: parseInt(process.env.TEST_MEMORY_THRESHOLD) || 512
};

// Error Handling Configuration
const ERROR_PATTERNS = {
  REQUIRED_ERROR_FIELDS: ['error', 'code'],
  VALID_HTTP_CODES: [200, 201, 400, 401, 403, 404, 409, 422, 429, 500, 503],
  ERROR_CODES: {
    AUTH_REQUIRED: 'AUTH_REQUIRED',
    INVALID_INPUT: 'INVALID_INPUT',
    DATABASE_ERROR: 'DATABASE_ERROR',
    RATE_LIMITED: 'RATE_LIMITED',
    INTERNAL_ERROR: 'INTERNAL_ERROR'
  }
};

// File Upload Testing
const UPLOAD_CONFIG = {
  MAX_FILE_SIZE: parseInt(process.env.TEST_MAX_FILE_SIZE) || 5242880, // 5MB
  ALLOWED_MIME_TYPES: ['image/jpeg', 'image/png', 'image/gif'],
  TEST_FILES_PATH: process.env.TEST_FILES_PATH || './tests/fixtures'
};

module.exports = {
  TEST_ENV,
  TEST_DATA,
  SECURITY_CONFIG,
  PERFORMANCE_THRESHOLDS,
  ERROR_PATTERNS,
  UPLOAD_CONFIG
};