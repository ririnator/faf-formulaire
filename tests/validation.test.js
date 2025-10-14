const {
  validateUsername,
  validateEmail,
  validatePassword,
  escapeHtml,
  normalizeUsername,
  normalizeEmail
} = require('../utils/validation');

describe('Validation Utils', () => {

  describe('validateUsername', () => {
    test('Should accept valid usernames', () => {
      expect(validateUsername('alice')).toBe(true);
      expect(validateUsername('bob123')).toBe(true);
      expect(validateUsername('user_name')).toBe(true);
      expect(validateUsername('user-name')).toBe(true);
      expect(validateUsername('a1b2c3')).toBe(true);
      expect(validateUsername('abc')).toBe(true); // Min 3 chars
      expect(validateUsername('a'.repeat(20))).toBe(true); // Max 20 chars
    });

    test('Should reject invalid usernames', () => {
      expect(validateUsername('ab')).toBe(false); // too short
      expect(validateUsername('a'.repeat(21))).toBe(false); // too long
      expect(validateUsername('User')).toBe(false); // uppercase
      expect(validateUsername('Alice')).toBe(false); // uppercase
      expect(validateUsername('user@name')).toBe(false); // special char
      expect(validateUsername('user name')).toBe(false); // space
      expect(validateUsername('user.name')).toBe(false); // dot
      expect(validateUsername('user#name')).toBe(false); // hash
      expect(validateUsername('')).toBe(false); // empty
      expect(validateUsername(null)).toBe(false); // null
      expect(validateUsername(undefined)).toBe(false); // undefined
      expect(validateUsername(123)).toBe(false); // number
    });
  });

  describe('validateEmail', () => {
    test('Should accept valid emails', () => {
      expect(validateEmail('test@example.com')).toBe(true);
      expect(validateEmail('user+tag@domain.co.uk')).toBe(true);
      expect(validateEmail('a@b.c')).toBe(true);
      expect(validateEmail('first.last@company.com')).toBe(true);
      expect(validateEmail('user123@test-domain.com')).toBe(true);
    });

    test('Should reject invalid emails', () => {
      expect(validateEmail('notanemail')).toBe(false);
      expect(validateEmail('@example.com')).toBe(false);
      expect(validateEmail('user@')).toBe(false);
      expect(validateEmail('user@domain')).toBe(false); // no TLD
      expect(validateEmail('user domain@test.com')).toBe(false); // space
      expect(validateEmail('')).toBe(false); // empty
      expect(validateEmail(null)).toBe(false); // null
      expect(validateEmail(undefined)).toBe(false); // undefined
      expect(validateEmail(123)).toBe(false); // number
    });
  });

  describe('validatePassword', () => {
    test('Should accept strong passwords', () => {
      expect(validatePassword('Password1')).toBe(true);
      expect(validatePassword('MyPass123')).toBe(true);
      expect(validatePassword('Abcdefg1')).toBe(true);
      expect(validatePassword('Test1234')).toBe(true);
      expect(validatePassword('SuperSecret99')).toBe(true);
      expect(validatePassword('P@ssw0rd')).toBe(true); // Special chars ok
    });

    test('Should reject weak passwords', () => {
      expect(validatePassword('pass')).toBe(false); // too short
      expect(validatePassword('password')).toBe(false); // no uppercase
      expect(validatePassword('PASSWORD')).toBe(false); // no digit
      expect(validatePassword('Password')).toBe(false); // no digit
      expect(validatePassword('Pass')).toBe(false); // too short
      expect(validatePassword('12345678')).toBe(false); // no uppercase
      expect(validatePassword('ABCDEFGH')).toBe(false); // no digit
      expect(validatePassword('')).toBe(false); // empty
      expect(validatePassword(null)).toBe(false); // null
      expect(validatePassword(undefined)).toBe(false); // undefined
      expect(validatePassword(123)).toBe(false); // number
    });
  });

  describe('escapeHtml', () => {
    test('Should escape HTML characters', () => {
      expect(escapeHtml('<script>alert("XSS")</script>'))
        .toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;');

      expect(escapeHtml("It's mine & yours"))
        .toBe('It&#x27;s mine &amp; yours');

      expect(escapeHtml('<div class="test">Content</div>'))
        .toBe('&lt;div class=&quot;test&quot;&gt;Content&lt;/div&gt;');
    });

    test('Should handle all dangerous characters', () => {
      expect(escapeHtml('<')).toBe('&lt;');
      expect(escapeHtml('>')).toBe('&gt;');
      expect(escapeHtml('&')).toBe('&amp;');
      expect(escapeHtml('"')).toBe('&quot;');
      expect(escapeHtml("'")).toBe('&#x27;');
    });

    test('Should handle empty/null input', () => {
      expect(escapeHtml('')).toBe('');
      expect(escapeHtml(null)).toBe('');
      expect(escapeHtml(undefined)).toBe('');
    });

    test('Should not escape safe text', () => {
      expect(escapeHtml('Hello World')).toBe('Hello World');
      expect(escapeHtml('This is safe text 123')).toBe('This is safe text 123');
    });

    test('Should handle mixed content', () => {
      expect(escapeHtml('Hello <b>World</b> & "Friends"'))
        .toBe('Hello &lt;b&gt;World&lt;/b&gt; &amp; &quot;Friends&quot;');
    });
  });

  describe('normalizeUsername', () => {
    test('Should normalize usernames', () => {
      expect(normalizeUsername('Alice')).toBe('alice');
      expect(normalizeUsername('  bob  ')).toBe('bob');
      expect(normalizeUsername('USER')).toBe('user');
      expect(normalizeUsername('Test_User')).toBe('test_user');
    });

    test('Should handle edge cases', () => {
      expect(normalizeUsername('')).toBe('');
      expect(normalizeUsername('   ')).toBe('');
      expect(normalizeUsername(null)).toBe('');
      expect(normalizeUsername(undefined)).toBe('');
    });

    test('Should preserve hyphens and underscores', () => {
      expect(normalizeUsername('user-name')).toBe('user-name');
      expect(normalizeUsername('user_name')).toBe('user_name');
      expect(normalizeUsername('User-Name_123')).toBe('user-name_123');
    });
  });

  describe('normalizeEmail', () => {
    test('Should normalize emails', () => {
      expect(normalizeEmail('Test@Example.COM')).toBe('test@example.com');
      expect(normalizeEmail('  user@domain.com  ')).toBe('user@domain.com');
      expect(normalizeEmail('USER@TEST.ORG')).toBe('user@test.org');
    });

    test('Should handle edge cases', () => {
      expect(normalizeEmail('')).toBe('');
      expect(normalizeEmail('   ')).toBe('');
      expect(normalizeEmail(null)).toBe('');
      expect(normalizeEmail(undefined)).toBe('');
    });

    test('Should preserve email structure', () => {
      expect(normalizeEmail('First.Last@Company.COM')).toBe('first.last@company.com');
      expect(normalizeEmail('user+tag@domain.co.uk')).toBe('user+tag@domain.co.uk');
    });
  });

});
