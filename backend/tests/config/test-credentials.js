/**
 * Secure Test Credentials Configuration
 * Uses environment variables or secure defaults for testing
 */

const bcrypt = require('bcrypt');

// Generate secure test credentials
const generateTestCredentials = async () => {
  const testPassword = process.env.TEST_PASSWORD || 'SecureTestPass2024!';
  const hashedPassword = await bcrypt.hash(testPassword, 10);
  
  return {
    admin: {
      username: process.env.TEST_ADMIN_USERNAME || 'test_admin_user',
      password: testPassword,
      hashedPassword: hashedPassword,
      email: process.env.TEST_ADMIN_EMAIL || 'test.admin@example.com'
    },
    user: {
      username: process.env.TEST_USER_USERNAME || 'test_regular_user',
      password: testPassword,
      hashedPassword: hashedPassword,
      email: process.env.TEST_USER_EMAIL || 'test.user@example.com'
    }
  };
};

// Pre-generated hash for consistent testing (matches SecureTestPass2024!)
const TEST_PASSWORD_HASH = '$2b$10$rZ7qF8XvN2mP9wE4tJ5xAuYvQc6sR8nD1mL3kO9pB4fG7hI2jU0vS';

const getTestCredentials = () => ({
  admin: {
    username: process.env.TEST_ADMIN_USERNAME || 'test_admin_user',
    password: process.env.TEST_PASSWORD || 'SecureTestPass2024!',
    hashedPassword: TEST_PASSWORD_HASH,
    email: process.env.TEST_ADMIN_EMAIL || 'test.admin@example.com'
  },
  user: {
    username: process.env.TEST_USER_USERNAME || 'test_regular_user',
    password: process.env.TEST_PASSWORD || 'SecureTestPass2024!',
    hashedPassword: TEST_PASSWORD_HASH,
    email: process.env.TEST_USER_EMAIL || 'test.user@example.com'
  }
});

module.exports = {
  generateTestCredentials,
  getTestCredentials,
  TEST_PASSWORD_HASH
};