/**
 * MongoDB Query Sanitization Utilities
 * Prevents NoSQL injection attacks by sanitizing user inputs before database queries
 */

const mongoose = require('mongoose');

/**
 * Sanitize MongoDB query input to prevent NoSQL injection
 * @param {*} input - Input to sanitize
 * @returns {*} Sanitized input
 */
function sanitizeMongoInput(input) {
  if (input === null || input === undefined) {
    return input;
  }
  
  // If input is a Date object, return as-is
  if (input instanceof Date) {
    return input;
  }
  
  // If input is a valid ObjectId, return as-is
  if (mongoose.Types.ObjectId.isValid(input)) {
    return input;
  }
  
  // If input is an object, check for MongoDB operators
  if (typeof input === 'object' && !Array.isArray(input)) {
    const sanitized = {};
    Object.keys(input).forEach(key => {
      // Remove any keys that start with $ (MongoDB operators) or contain dots (path traversal)
      if (!key.startsWith('$') && !key.includes('.') && !key.includes('\\')) {
        sanitized[key] = sanitizeMongoInput(input[key]);
      }
    });
    return sanitized;
  }
  
  // If input is an array, sanitize each element
  if (Array.isArray(input)) {
    return input.map(item => sanitizeMongoInput(item));
  }
  
  // For strings, check for potential injection patterns
  if (typeof input === 'string') {
    // Remove potential regex injection patterns and control characters
    return input
      .replace(/[{}[\]\\]/g, '') // Remove regex metacharacters
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
      .trim();
  }
  
  // For numbers and booleans, return as-is
  return input;
}

/**
 * Validate and sanitize ObjectId
 * @param {string} id - ID to validate
 * @returns {mongoose.Types.ObjectId|null} Valid ObjectId or null
 */
function sanitizeObjectId(id) {
  if (!id || typeof id !== 'string') return null;
  if (!mongoose.Types.ObjectId.isValid(id)) return null;
  return new mongoose.Types.ObjectId(id);
}

/**
 * Sanitize query parameters for MongoDB search operations
 * @param {Object} query - Query object to sanitize
 * @returns {Object} Sanitized query object
 */
function sanitizeSearchQuery(query) {
  const sanitized = {};
  
  if (query.search && typeof query.search === 'string') {
    // Escape special regex characters but preserve alphanumeric and basic punctuation
    sanitized.search = query.search
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      .trim()
      .substring(0, 200); // Limit search length
  }
  
  if (query.status && typeof query.status === 'string') {
    // Whitelist allowed status values
    const allowedStatuses = ['active', 'inactive', 'pending', 'completed', 'cancelled'];
    if (allowedStatuses.includes(query.status)) {
      sanitized.status = query.status;
    }
  }
  
  if (query.page && typeof query.page === 'string') {
    const page = parseInt(query.page, 10);
    sanitized.page = !isNaN(page) && page > 0 ? page : 1;
  }
  
  if (query.limit && typeof query.limit === 'string') {
    const limit = parseInt(query.limit, 10);
    sanitized.limit = !isNaN(limit) && limit > 0 && limit <= 100 ? limit : 20;
  }
  
  if (query.sortBy && typeof query.sortBy === 'string') {
    // Whitelist allowed sort fields
    const allowedSortFields = ['createdAt', 'updatedAt', 'name', 'email', 'status'];
    if (allowedSortFields.includes(query.sortBy)) {
      sanitized.sortBy = query.sortBy;
    }
  }
  
  if (query.sortOrder && typeof query.sortOrder === 'string') {
    sanitized.sortOrder = ['asc', 'desc'].includes(query.sortOrder) ? query.sortOrder : 'desc';
  }
  
  return sanitized;
}

/**
 * Sanitize date range inputs
 * @param {string} dateString - Date string to validate
 * @returns {Date|null} Valid Date object or null
 */
function sanitizeDate(dateString) {
  if (!dateString || typeof dateString !== 'string') return null;
  
  const date = new Date(dateString);
  if (isNaN(date.getTime())) return null;
  
  // Prevent dates too far in the past or future
  const now = new Date();
  const minDate = new Date(now.getFullYear() - 10, 0, 1);
  const maxDate = new Date(now.getFullYear() + 1, 11, 31);
  
  if (date < minDate || date > maxDate) return null;
  
  return date;
}

/**
 * Sanitize aggregation pipeline stages
 * @param {Array} pipeline - MongoDB aggregation pipeline
 * @returns {Array} Sanitized pipeline
 */
function sanitizeAggregationPipeline(pipeline) {
  if (!Array.isArray(pipeline)) return [];
  
  const allowedStages = ['$match', '$project', '$sort', '$limit', '$skip', '$group', '$lookup', '$unwind'];
  
  return pipeline
    .filter(stage => {
      if (typeof stage !== 'object' || Array.isArray(stage)) return false;
      const stageKeys = Object.keys(stage);
      return stageKeys.length === 1 && allowedStages.includes(stageKeys[0]);
    })
    .map(stage => sanitizeMongoInput(stage));
}

module.exports = {
  sanitizeMongoInput,
  sanitizeObjectId,
  sanitizeSearchQuery,
  sanitizeDate,
  sanitizeAggregationPipeline
};