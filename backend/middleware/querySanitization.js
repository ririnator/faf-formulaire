/**
 * Advanced MongoDB Query Sanitization Middleware
 * 
 * Provides comprehensive protection against NoSQL injection attacks,
 * query operator attacks, and other query-based security vulnerabilities.
 * 
 * Security Features:
 * - NoSQL injection prevention
 * - MongoDB operator validation and whitelisting
 * - Query depth limits to prevent DoS
 * - Advanced regex pattern sanitization
 * - Query structure validation
 * - Performance-conscious logging and monitoring
 * 
 * @author FAF Security Team
 * @version 2.0.0
 */

const mongoose = require('mongoose');

// Configuration constants
const CONFIG = {
  MAX_QUERY_DEPTH: 10,
  MAX_ARRAY_LENGTH: 100,
  MAX_STRING_LENGTH: 10000,
  MAX_REGEX_LENGTH: 1000,
  ENABLE_SECURITY_LOGGING: process.env.NODE_ENV === 'production',
  
  // Whitelisted MongoDB operators (comprehensive list)
  ALLOWED_OPERATORS: new Set([
    // Comparison operators
    '$eq', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
    
    // Logical operators
    '$and', '$or', '$not', '$nor',
    
    // Element operators
    '$exists', '$type',
    
    // Array operators
    '$all', '$elemMatch', '$size',
    
    // Update operators
    '$set', '$unset', '$inc', '$mul', '$rename', '$setOnInsert',
    '$addToSet', '$pop', '$pull', '$push', '$pullAll',
    
    // Aggregation operators (limited subset for safety)
    '$match', '$group', '$sort', '$limit', '$skip', '$project',
    '$unwind', '$lookup', '$count', '$facet', '$sum', '$avg',
    '$min', '$max', '$first', '$last', '$push', '$addToSet',
    
    // Text search operators
    '$text', '$search', '$language', '$caseSensitive',
    
    // Geospatial operators (if needed)
    '$geoWithin', '$geoIntersects', '$near', '$nearSphere',
    
    // Aggregation stage operators
    '$addFields', '$replaceRoot', '$replaceWith'
  ]),
  
  // Dangerous operators that are explicitly blocked
  BLOCKED_OPERATORS: new Set([
    '$where', '$expr', '$function', '$accumulator', '$merge', '$out',
    '$planCacheClear', '$currentOp', '$listLocalSessions', '$listSessions'
  ]),
  
  // Fields that should never be queried directly by users
  PROTECTED_FIELDS: new Set([
    'password', '__v', '_id.$oid', 'session', 'sessionId',
    'internal', 'system', 'admin.password'
  ]),
  
  // Field patterns that should be allowed (more permissive for metadata)
  ALLOWED_FIELD_PATTERNS: [
    /^metadata\./,
    /^profile\./,
    /^settings\./,
    /^tracking\./
  ]
};

/**
 * Security event logger for query sanitization
 */
function logSecurityEvent(eventType, details, severity = 'medium') {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event: eventType,
    severity,
    source: 'querySanitization',
    ...details
  };
  
  if (CONFIG.ENABLE_SECURITY_LOGGING) {
    console.warn('🔐 QUERY_SECURITY_EVENT:', JSON.stringify(logEntry));
  }
  
  // Store critical events for analysis
  if (severity === 'high' || severity === 'critical') {
    storeSecurityEvent(logEntry);
  }
}

/**
 * Store critical security events for analysis
 */
const criticalSecurityEvents = [];
const MAX_SECURITY_EVENTS = 1000;

function storeSecurityEvent(event) {
  criticalSecurityEvents.push(event);
  if (criticalSecurityEvents.length > MAX_SECURITY_EVENTS) {
    criticalSecurityEvents.shift(); // Remove oldest event
  }
}

/**
 * Validates and sanitizes MongoDB ObjectIds
 * @param {*} id - ID to validate
 * @returns {string|null} Valid ObjectId string or null
 */
function sanitizeObjectId(id) {
  if (!id) return null;
  
  // Handle ObjectId objects
  if (typeof id === 'object' && id._id) {
    id = id._id.toString();
  } else if (typeof id === 'object' && id.toString) {
    id = id.toString();
  }
  
  // Validate string format
  if (typeof id !== 'string') return null;
  
  // Additional security: check for injection patterns in ObjectId
  if (/[{}[\]$.]/.test(id)) {
    logSecurityEvent('MALICIOUS_OBJECTID_PATTERN', { 
      id: id.substring(0, 50),
      pattern: 'contains_injection_chars'
    }, 'high');
    return null;
  }
  
  return mongoose.Types.ObjectId.isValid(id) ? id : null;
}

/**
 * Sanitizes MongoDB query operators
 * @param {string} operator - Operator to validate
 * @returns {boolean} Whether operator is safe
 */
function isValidOperator(operator) {
  if (typeof operator !== 'string') return false;
  
  // Check if operator is explicitly blocked
  if (CONFIG.BLOCKED_OPERATORS.has(operator)) {
    logSecurityEvent('BLOCKED_OPERATOR_DETECTED', { 
      operator,
      action: 'blocked',
      attackType: 'nosql_operator_injection'
    }, 'critical');
    return false;
  }
  
  // Check if operator is in whitelist
  if (!CONFIG.ALLOWED_OPERATORS.has(operator)) {
    logSecurityEvent('UNKNOWN_OPERATOR_DETECTED', { 
      operator,
      action: 'blocked',
      attackType: 'unknown_operator_injection'
    }, 'high');
    return false;
  }
  
  return true;
}

/**
 * Sanitizes string values for potential injection attacks
 * @param {string} str - String to sanitize
 * @returns {string} Sanitized string
 */
function sanitizeString(str) {
  if (typeof str !== 'string') return str;
  
  // Length validation
  if (str.length > CONFIG.MAX_STRING_LENGTH) {
    logSecurityEvent('STRING_TOO_LONG', { 
      length: str.length,
      maxLength: CONFIG.MAX_STRING_LENGTH
    }, 'medium');
    return str.substring(0, CONFIG.MAX_STRING_LENGTH);
  }
  
  // Check for obvious injection patterns
  const injectionPatterns = [
    /\$where\s*:/i,
    /javascript\s*:/i,
    /eval\s*\(/i,
    /function\s*\(/i,
    /this\./i,
    /db\./i,
    /collection\./i
  ];
  
  for (const pattern of injectionPatterns) {
    if (pattern.test(str)) {
      logSecurityEvent('STRING_INJECTION_PATTERN', { 
        pattern: pattern.toString(),
        value: str.substring(0, 100)
      }, 'high');
      // Replace suspicious content
      str = str.replace(pattern, '');
    }
  }
  
  return str;
}

/**
 * Sanitizes regex objects and patterns
 * @param {*} regex - Regex to sanitize
 * @returns {*} Sanitized regex or string
 */
function sanitizeRegex(regex) {
  if (regex instanceof RegExp) {
    const source = regex.source;
    
    // Check regex length
    if (source.length > CONFIG.MAX_REGEX_LENGTH) {
      logSecurityEvent('REGEX_TOO_LONG', { 
        length: source.length,
        maxLength: CONFIG.MAX_REGEX_LENGTH
      }, 'medium');
      return new RegExp(source.substring(0, CONFIG.MAX_REGEX_LENGTH), regex.flags);
    }
    
    // Check for potentially dangerous regex patterns
    const dangerousPatterns = [
      /\(\?\=/,  // Positive lookahead (can cause ReDoS)
      /\(\?\!/,  // Negative lookahead
      /\(\?\<=/,  // Positive lookbehind
      /\(\?\<!/,  // Negative lookbehind
      /\*\+/,     // Nested quantifiers
      /\+\+/,     // Nested quantifiers
      /\{\d{4,}\}/ // Very large quantifiers
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(source)) {
        logSecurityEvent('DANGEROUS_REGEX_PATTERN', { 
          pattern: pattern.toString(),
          regexSource: source.substring(0, 100)
        }, 'high');
        // Return a safer version - just the escaped literal
        return new RegExp(source.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      }
    }
    
    return regex;
  }
  
  // If it's a string that looks like a regex, be cautious
  if (typeof regex === 'string' && regex.length > 2) {
    return sanitizeString(regex);
  }
  
  return regex;
}

/**
 * Validates field names against protected fields
 * @param {string} fieldName - Field name to validate
 * @returns {boolean} Whether field is safe to query
 */
function isValidFieldName(fieldName) {
  if (typeof fieldName !== 'string') return false;
  
  // Check against protected fields
  for (const protectedField of CONFIG.PROTECTED_FIELDS) {
    if (fieldName.includes(protectedField)) {
      logSecurityEvent('PROTECTED_FIELD_ACCESS', { 
        fieldName,
        protectedField
      }, 'high');
      return false;
    }
  }
  
  // Check for field injection patterns - but allow some MongoDB field syntax
  if (fieldName.includes('$')) {
    // Check for dangerous $ patterns but allow some cases
    const dangerousPatterns = [
      /\$where/i,
      /\$expr/i,
      /\$function/i,
      /\$.*\$/ // Double $ patterns
    ];
    
    if (dangerousPatterns.some(pattern => pattern.test(fieldName))) {
      logSecurityEvent('FIELD_INJECTION_PATTERN', { 
        fieldName,
        pattern: 'dangerous_dollar_pattern'
      }, 'high');
      return false;
    }
  }
  
  // Allow certain dot notation patterns
  if (fieldName.includes('.')) {
    const isAllowedPattern = CONFIG.ALLOWED_FIELD_PATTERNS.some(pattern => 
      pattern.test(fieldName)
    );
    
    // If it contains dots but doesn't match allowed patterns, check for injection
    if (!isAllowedPattern && /\$/.test(fieldName)) {
      logSecurityEvent('FIELD_INJECTION_PATTERN', { 
        fieldName,
        pattern: 'dot_dollar_injection'
      }, 'medium');
      return false;
    }
  }
  
  return true;
}

/**
 * Main recursive sanitization function
 * @param {*} input - Input to sanitize
 * @param {number} depth - Current recursion depth
 * @returns {*} Sanitized input
 */
function sanitizeMongoInput(input, depth = 0) {
  // Prevent deep recursion attacks
  if (depth > CONFIG.MAX_QUERY_DEPTH) {
    logSecurityEvent('QUERY_DEPTH_EXCEEDED', { 
      maxDepth: CONFIG.MAX_QUERY_DEPTH,
      currentDepth: depth
    }, 'high');
    return {};
  }
  
  // Handle null/undefined
  if (input === null || input === undefined) {
    return input;
  }
  
  // Handle primitive types
  if (typeof input === 'string') {
    return sanitizeString(input);
  }
  
  if (typeof input === 'number' || typeof input === 'boolean') {
    return input;
  }
  
  // Handle Date objects
  if (input instanceof Date) {
    return input;
  }
  
  // Handle RegExp objects
  if (input instanceof RegExp) {
    return sanitizeRegex(input);
  }
  
  // Handle ObjectId objects
  if (mongoose.Types.ObjectId.isValid(input)) {
    return sanitizeObjectId(input);
  }
  
  // Handle arrays
  if (Array.isArray(input)) {
    if (input.length > CONFIG.MAX_ARRAY_LENGTH) {
      logSecurityEvent('ARRAY_TOO_LONG', { 
        length: input.length,
        maxLength: CONFIG.MAX_ARRAY_LENGTH
      }, 'medium');
      input = input.slice(0, CONFIG.MAX_ARRAY_LENGTH);
    }
    
    return input.map(item => sanitizeMongoInput(item, depth + 1));
  }
  
  // Handle objects (the main case)
  if (typeof input === 'object') {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(input)) {
      // Validate operators
      if (key.startsWith('$')) {
        if (!isValidOperator(key)) {
          // Skip invalid operators entirely
          continue;
        }
      } else {
        // Validate field names
        if (!isValidFieldName(key)) {
          // Skip invalid field names
          continue;
        }
      }
      
      // Recursively sanitize the value
      sanitized[key] = sanitizeMongoInput(value, depth + 1);
    }
    
    return sanitized;
  }
  
  // Unknown type - be safe and return empty object
  logSecurityEvent('UNKNOWN_INPUT_TYPE', { 
    type: typeof input,
    constructor: input?.constructor?.name
  }, 'medium');
  
  return {};
}

/**
 * Sanitizes aggregation pipelines
 * @param {Array} pipeline - Aggregation pipeline to sanitize
 * @returns {Array} Sanitized pipeline
 */
function sanitizeAggregationPipeline(pipeline) {
  if (!Array.isArray(pipeline)) {
    logSecurityEvent('INVALID_AGGREGATION_PIPELINE', { 
      type: typeof pipeline
    }, 'high');
    return [];
  }
  
  const allowedStages = new Set([
    '$match', '$group', '$sort', '$limit', '$skip', '$project',
    '$unwind', '$lookup', '$count', '$facet', '$addFields',
    '$replaceRoot', '$replaceWith'
  ]);
  
  return pipeline
    .filter((stage, index) => {
      if (typeof stage !== 'object' || !stage) return false;
      
      const stageKeys = Object.keys(stage);
      if (stageKeys.length !== 1) {
        logSecurityEvent('INVALID_AGGREGATION_STAGE', { 
          stageIndex: index,
          keysCount: stageKeys.length
        }, 'high');
        return false;
      }
      
      const stageOperator = stageKeys[0];
      if (!allowedStages.has(stageOperator)) {
        logSecurityEvent('BLOCKED_AGGREGATION_STAGE', { 
          stageIndex: index,
          stageOperator
        }, 'high');
        return false;
      }
      
      return true;
    })
    .map(stage => sanitizeMongoInput(stage));
}

/**
 * Express middleware for query sanitization
 * @param {Object} options - Configuration options
 * @returns {Function} Express middleware function
 */
function createQuerySanitizationMiddleware(options = {}) {
  const config = { ...CONFIG, ...options };
  
  return (req, res, next) => {
    try {
      // Sanitize query parameters
      if (req.query && typeof req.query === 'object') {
        req.query = sanitizeMongoInput(req.query);
      }
      
      // Sanitize request body
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeMongoInput(req.body);
      }
      
      // Sanitize route parameters
      if (req.params && typeof req.params === 'object') {
        for (const [key, value] of Object.entries(req.params)) {
          if (key.includes('id') || key.includes('Id')) {
            req.params[key] = sanitizeObjectId(value);
          } else {
            req.params[key] = sanitizeString(value);
          }
        }
      }
      
      next();
    } catch (error) {
      logSecurityEvent('SANITIZATION_ERROR', { 
        error: error.message,
        url: req.url,
        method: req.method
      }, 'critical');
      
      return res.status(400).json({
        error: 'Invalid request data',
        code: 'SANITIZATION_ERROR'
      });
    }
  };
}

/**
 * Utility function to manually sanitize data in services
 * @param {*} data - Data to sanitize
 * @returns {*} Sanitized data
 */
function sanitizeQueryData(data) {
  return sanitizeMongoInput(data);
}

/**
 * Get security events for monitoring
 * @returns {Array} Array of security events
 */
function getSecurityEvents() {
  return [...criticalSecurityEvents];
}

/**
 * Clear security events (for admin purposes)
 */
function clearSecurityEvents() {
  criticalSecurityEvents.length = 0;
}

/**
 * Enhanced sanitization for specific MongoDB operations
 */
const mongoOperationSanitizers = {
  /**
   * Sanitize find query
   */
  find: (filter, options = {}) => ({
    filter: sanitizeMongoInput(filter),
    options: sanitizeMongoInput(options)
  }),
  
  /**
   * Sanitize update operations
   */
  update: (filter, update, options = {}) => ({
    filter: sanitizeMongoInput(filter),
    update: sanitizeMongoInput(update),
    options: sanitizeMongoInput(options)
  }),
  
  /**
   * Sanitize aggregation operations
   */
  aggregate: (pipeline, options = {}) => ({
    pipeline: sanitizeAggregationPipeline(pipeline),
    options: sanitizeMongoInput(options)
  }),
  
  /**
   * Sanitize delete operations
   */
  delete: (filter, options = {}) => ({
    filter: sanitizeMongoInput(filter),
    options: sanitizeMongoInput(options)
  })
};

module.exports = {
  // Main functions
  sanitizeMongoInput,
  sanitizeObjectId,
  sanitizeAggregationPipeline,
  sanitizeQueryData,
  
  // Express middleware
  createQuerySanitizationMiddleware,
  
  // Operation-specific sanitizers
  mongoOperationSanitizers,
  
  // Security monitoring
  getSecurityEvents,
  clearSecurityEvents,
  logSecurityEvent,
  
  // Configuration
  CONFIG,
  
  // Individual validators (for advanced usage)
  isValidOperator,
  isValidFieldName,
  sanitizeString,
  sanitizeRegex
};