// middleware/bodyParser.js
const express = require('express');

/**
 * Optimized Body Parser Configuration
 * 
 * Different limits for different types of content:
 * - Text-only form responses: 2MB (generous for text data)
 * - Image uploads: Handled separately by Multer (no body parser needed)
 * - Admin operations: 1MB (smaller payloads)
 */

/**
 * Standard body parser for text-only form responses
 * Used for /api/response endpoint
 */
function createFormBodyParser() {
  return [
    express.json({ 
      limit: '2mb',
      type: 'application/json'
    }),
    express.urlencoded({ 
      limit: '2mb', 
      extended: true,
      type: 'application/x-www-form-urlencoded'
    })
  ];
}

/**
 * Compact body parser for admin operations
 * Used for admin endpoints with smaller payloads
 */
function createAdminBodyParser() {
  return [
    express.json({ 
      limit: '1mb',
      type: 'application/json'
    }),
    express.urlencoded({ 
      limit: '1mb', 
      extended: true,
      type: 'application/x-www-form-urlencoded'
    })
  ];
}

/**
 * Minimal body parser for general use
 * Used for endpoints that don't need large payloads
 */
function createStandardBodyParser() {
  return [
    express.json({ 
      limit: '512kb',
      type: 'application/json'
    }),
    express.urlencoded({ 
      limit: '512kb', 
      extended: true,
      type: 'application/x-www-form-urlencoded'
    })
  ];
}

/**
 * Error handler for payload too large
 */
function createPayloadErrorHandler() {
  return (error, req, res, next) => {
    if (error.type === 'entity.too.large') {
      const limit = error.limit ? Math.round(error.limit / 1024 / 1024) : 'unknown';
      return res.status(413).json({
        message: `Données trop volumineuses (limite: ${limit}MB)`,
        error: 'PAYLOAD_TOO_LARGE'
      });
    }
    
    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({
        message: 'Format de données invalide',
        error: 'INVALID_JSON'
      });
    }
    
    next(error);
  };
}

/**
 * Get appropriate body parser based on endpoint type
 */
function getBodyParserForEndpoint(endpointType) {
  switch (endpointType) {
    case 'form':
      return createFormBodyParser();
    case 'admin':
      return createAdminBodyParser();
    case 'standard':
    default:
      return createStandardBodyParser();
  }
}

/**
 * Middleware factory for specific content size limits
 */
function createSizedBodyParser(limitMB) {
  const limit = `${limitMB}mb`;
  
  return [
    express.json({ limit }),
    express.urlencoded({ limit, extended: true })
  ];
}

/**
 * Large body parser for CSV imports and bulk operations
 * Used for endpoints that handle bulk data imports
 */
function createBulkImportBodyParser() {
  return [
    express.json({ 
      limit: '5mb',
      type: 'application/json'
    }),
    express.urlencoded({ 
      limit: '5mb', 
      extended: true,
      type: 'application/x-www-form-urlencoded'
    })
  ];
}

module.exports = {
  createFormBodyParser,
  createAdminBodyParser,
  createStandardBodyParser,
  createBulkImportBodyParser,
  createPayloadErrorHandler,
  getBodyParserForEndpoint,
  createSizedBodyParser
};