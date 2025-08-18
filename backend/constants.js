// constants.js - Application constants and HTTP status codes

const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  GONE: 410,
  PAYLOAD_TOO_LARGE: 413,
  REQUEST_ENTITY_TOO_LARGE: 413, // Alias for compatibility
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503
};

const APP_CONSTANTS = {
  DEFAULT_PORT: 3000,
  RATE_LIMIT_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  SESSION_EXPIRY_MS: 1 * 60 * 60 * 1000, // 1 hour
  MAX_FILE_SIZE: 5 * 1024 * 1024, // 5MB
  MAX_RESPONSES_PER_SUBMISSION: 20,
  MAX_QUESTION_LENGTH: 500,
  MAX_ANSWER_LENGTH: 10000,
  MAX_NAME_LENGTH: 100,
  MIN_NAME_LENGTH: 2,
  CLEANUP_INTERVAL_MS: 24 * 60 * 60 * 1000, // 24 hours
  SESSION_MONITORING_INTERVAL_MS: 5 * 60 * 1000, // 5 minutes
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_TIME_MS: 15 * 60 * 1000, // 15 minutes
  
  // Form-a-Friend V2 constants
  MAX_CONTACTS_PER_USER: 1000,
  HANDSHAKE_EXPIRY_DAYS: 30,
  INVITATION_EXPIRY_DAYS: 7,
  SUBMISSION_EDIT_WINDOW_HOURS: 24,
  MAX_BULK_OPERATIONS: 100,
  
  // Body parser limits
  BODY_LIMITS: {
    STANDARD: '512kb',
    FORMS: '2mb', 
    IMAGES: '5mb',
    ADMIN: '1mb'
  },
  
  // Cache settings
  CACHE_TTL_MINUTES: 10,
  MAX_CACHE_SIZE: 50
};

const SECURITY_CONSTANTS = {
  CSRF_TOKEN_LENGTH: 32,
  SESSION_SECRET_MIN_LENGTH: 32,
  BCRYPT_ROUNDS: 12,
  MAX_SUSPICIOUS_ACTIVITIES: 5,
  IP_BLOCK_DURATION_MS: 15 * 60 * 1000, // 15 minutes
  
  // XSS Protection
  XSS_PATTERNS: [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi
  ],
  
  // Content Security Policy
  CSP_NONCE_LENGTH: 16,
  
  // Rate limiting
  RATE_LIMITS: {
    AUTH: 5, // per 15 minutes
    API: 100, // per 15 minutes
    FORM_SUBMISSION: 3, // per 15 minutes
    ADMIN: 50 // per 15 minutes
  }
};

const VALIDATION_PATTERNS = {
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  USERNAME: /^[a-zA-Z0-9_-]{3,30}$/,
  PHONE: /^\+?[\d\s\-\(\)]{8,20}$/,
  PASSWORD_STRENGTH: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  CLOUDINARY_URL: /^https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/[a-zA-Z]+\/upload\/[a-zA-Z0-9_\-\/\.]+$/
};

module.exports = {
  HTTP_STATUS,
  APP_CONSTANTS,
  SECURITY_CONSTANTS,
  VALIDATION_PATTERNS
};