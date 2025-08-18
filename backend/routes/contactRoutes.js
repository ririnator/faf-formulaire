// routes/contactRoutes.js
const express = require('express');
const multer = require('multer');
const router = express.Router();
const { body, param, query, validationResult } = require('express-validator');
const { createAdminBodyParser, createBulkImportBodyParser } = require('../middleware/bodyParser');
const { csrfProtectionStrict } = require('../middleware/csrf');
const { authLimiters } = require('../middleware/authRateLimit');
const { 
  contactLimiter, 
  bulkImportLimiter, 
  apiLimiter,
  searchBasicLimiter,
  searchAdvancedLimiter,
  searchAnalyticsLimiter 
} = require('../middleware/rateLimiting');
const { searchComplexityMiddleware } = require('../middleware/searchComplexityAnalyzer');
const { checkSearchBlocking } = require('../middleware/searchBlockingMiddleware');
const searchMonitoringService = require('../services/searchMonitoringService');
const { trackGlobalStats, trackSimpleStats } = require('../middleware/statisticsMonitoring');
const { requireUserAuth } = require('../middleware/hybridAuth');
const { smartEscape } = require('../middleware/validation');
const { createEmailDomainMiddleware } = require('../middleware/emailDomainValidation');
const { csvSecurityMonitor, trackCSVImport, trackCSVExport, blockSuspiciousIPs } = require('../middleware/csvSecurityMonitoring');
const ServiceFactory = require('../services/serviceFactory');
const { 
  preventParameterPollution,
  securityLogger,
  antiAutomation,
  validateContentType
} = require('../middleware/enhancedSecurity');

// CSV file upload configuration for security tests
const csvUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit for CSV files
    fieldSize: 1024 * 1024,    // 1MB limit for form fields
    files: 1                   // Only 1 file per upload
  },
  fileFilter: (req, file, cb) => {
    // Validate file extension
    const allowedExtensions = ['.csv', '.txt'];
    const fileExtension = file.originalname.toLowerCase().slice(file.originalname.lastIndexOf('.'));
    
    if (!allowedExtensions.includes(fileExtension)) {
      return cb(new Error('Invalid file format'), false);
    }
    
    // Validate MIME type
    const allowedMimeTypes = [
      'text/csv',
      'text/plain',
      'application/csv',
      'application/vnd.ms-excel'
    ];
    
    if (!allowedMimeTypes.includes(file.mimetype)) {
      return cb(new Error('Invalid file format'), false);
    }
    
    cb(null, true);
  }
});

// Apply body parser middleware for all routes
router.use(createAdminBodyParser());

// Apply security middleware for all routes
router.use(securityLogger);
router.use(preventParameterPollution(['tags', 'emails']));
router.use(antiAutomation());

// Apply authentication middleware for all routes
router.use(requireUserAuth);

// Secure validation error handler - prevents information disclosure
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Log detailed errors server-side for debugging
    console.warn('Validation errors:', {
      ip: req.ip,
      path: req.path,
      errors: errors.array(),
      timestamp: new Date().toISOString()
    });
    
    // Return generic error to client to prevent information disclosure
    return res.status(400).json({ 
      success: false,
      error: 'Données invalides. Vérifiez votre saisie.', 
      code: 'VALIDATION_ERROR'
    });
  }
  next();
};

// Secure user ID extraction helper
const getUserId = (req) => {
  // Priority: currentUser.id (from enrichUserData middleware) > user.id > session.userId
  const userId = req.currentUser?.id || req.currentUser?._id || req.user?.id || req.user?._id || req.session?.userId;
  
  // Debug logging for tests (disabled)
  // if (process.env.NODE_ENV === 'test') {
  //   console.log('getUserId debug:', ...);
  // }
  
  // Convert ObjectId to string if necessary
  return userId ? userId.toString() : null;
};

// Search monitoring middleware
const trackSearchEvent = (req, res, next) => {
  const originalSend = res.send;
  const startTime = Date.now();
  
  res.send = function(data) {
    const responseTime = Date.now() - startTime;
    
    // Parse response to get result count if possible
    let resultCount = 0;
    let success = res.statusCode < 400;
    
    try {
      const responseData = typeof data === 'string' ? JSON.parse(data) : data;
      if (responseData.contacts) {
        resultCount = Array.isArray(responseData.contacts) ? responseData.contacts.length : 0;
      } else if (responseData.total !== undefined) {
        resultCount = responseData.total;
      }
    } catch (e) {
      // Ignore parsing errors
    }

    // Record search event
    searchMonitoringService.recordSearchEvent({
      userId: getUserId(req),
      ip: req.ip,
      query: req.query.search || req.query.q || '',
      path: req.path,
      complexity: req.searchComplexity,
      responseTime,
      resultCount,
      success,
      userAgent: req.get('user-agent')
    });

    return originalSend.call(this, data);
  };
  
  next();
};

// CSV data validation middleware with 5MB size limit and MIME type validation
const validateCSVData = (req, res, next) => {
  const { csvData, mimeType, fileName } = req.body;
  
  if (!csvData) {
    return res.status(400).json({
      error: 'CSV data is required',
      code: 'MISSING_CSV_DATA'
    });
  }
  
  // MIME type validation for CSV files
  const allowedMimeTypes = [
    'text/csv',
    'text/plain',
    'application/csv',
    'application/vnd.ms-excel'
  ];
  
  if (mimeType && !allowedMimeTypes.includes(mimeType)) {
    console.warn('Invalid MIME type for CSV upload', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      mimeType,
      fileName,
      path: req.path
    });
    
    return res.status(400).json({
      error: 'Invalid file type. Only CSV files are allowed.',
      code: 'INVALID_MIME_TYPE',
      allowedTypes: allowedMimeTypes,
      receivedType: mimeType
    });
  }
  
  // File extension validation if fileName is provided
  if (fileName) {
    const fileExtension = fileName.toLowerCase().split('.').pop();
    const allowedExtensions = ['csv', 'txt'];
    
    if (!allowedExtensions.includes(fileExtension)) {
      console.warn('Invalid file extension for CSV upload', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        fileName,
        extension: fileExtension,
        path: req.path
      });
      
      return res.status(400).json({
        error: 'Invalid file extension. Only .csv and .txt files are allowed.',
        code: 'INVALID_FILE_EXTENSION',
        allowedExtensions,
        receivedExtension: fileExtension
      });
    }
  }
  
  // Check CSV data size (5MB = 5 * 1024 * 1024 bytes)
  const csvSizeBytes = Buffer.byteLength(csvData, 'utf8');
  const maxSizeBytes = 5 * 1024 * 1024; // 5MB
  
  if (csvSizeBytes > maxSizeBytes) {
    console.warn('CSV import size limit exceeded', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      csvSizeBytes,
      maxSizeBytes,
      fileName,
      path: req.path
    });
    
    return res.status(413).json({
      error: 'CSV data too large. Maximum size is 5MB.',
      code: 'CSV_SIZE_LIMIT_EXCEEDED',
      maxSizeMB: 5,
      actualSizeMB: Math.round((csvSizeBytes / 1024 / 1024) * 100) / 100
    });
  }
  
  // Validate CSV structure (basic check for CSV-like content)
  if (typeof csvData !== 'string' || csvData.trim().length === 0) {
    return res.status(400).json({
      error: 'Invalid CSV data format',
      code: 'INVALID_CSV_FORMAT'
    });
  }
  
  // Enhanced security check: prevent binary data uploads disguised as CSV
  if (csvData.includes('\x00') || /[\x01-\x08\x0B\x0C\x0E-\x1F]/.test(csvData)) {
    console.warn('Binary content detected in CSV upload', {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      fileName,
      path: req.path
    });
    
    return res.status(400).json({
      error: 'Binary content detected in CSV data',
      code: 'INVALID_CSV_CONTENT'
    });
  }
  
  // Additional security: check for potential malicious content patterns
  const maliciousPatterns = [
    /<script/i,
    /javascript:/i,
    /vbscript:/i,
    /onload=/i,
    /onerror=/i,
    /onclick=/i,
    // Enhanced CSV Formula injection patterns
    /^[=@+\-\t\r]/m,  // Formula indicators at line start (including tab/carriage return)
    /^=.*\(/m,    // Excel formula with function call
    /^@.*\(/m,    // Alternative formula syntax
    /^\+.*\(/m,   // Plus prefix with function
    /^\-.*\(/m,   // Minus prefix with function
    /\|.*cmd/i,   // Command injection attempts
    /WEBSERVICE\s*\(/i,  // Excel WEBSERVICE function
    /IMPORTDATA\s*\(/i,  // Google Sheets IMPORTDATA
    /IMPORTXML\s*\(/i,   // Google Sheets IMPORTXML
    /IMPORTHTML\s*\(/i,  // Google Sheets IMPORTHTML
    /HYPERLINK\s*\(/i,   // Hyperlink function injection
    /DDE\s*\(/i,         // Dynamic Data Exchange
    /EXEC\s*\(/i,        // Execute function
    /CALL\s*\(/i,        // Call function
    /MDETERM\s*\(/i,     // Matrix determinant (exploitation vector)
    /MMULT\s*\(/i,       // Matrix multiplication (exploitation vector)
    /\bcmd\b/i,          // Command execution attempts
    /\bpowershell\b/i,   // PowerShell execution attempts
    /\bbash\b/i,         // Bash execution attempts
    /\bsh\b/i,           // Shell execution attempts
    /\$\{.*\}/i,         // Variable substitution patterns
    /\beval\s*\(/i,      // Eval function calls
    /\bexec\s*\(/i,      // Exec function calls
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /<script/i,
    /<link/i,
    /<meta/i
  ];
  
  for (const pattern of maliciousPatterns) {
    if (pattern.test(csvData)) {
      // Track security violation
      csvSecurityMonitor.trackCSVImportEvent(req, 'injection_attempt', {
        pattern: pattern.source,
        fileName,
        contentLength: csvData.length
      });
      
      console.warn('Potentially malicious content detected in CSV upload', {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        fileName,
        pattern: pattern.source,
        path: req.path
      });
      
      return res.status(400).json({
        error: 'Potentially malicious content detected in CSV data',
        code: 'MALICIOUS_CONTENT_DETECTED'
      });
    }
  }
  
  next();
};

/**
 * GET /api/contacts - Get user's contacts with pagination and search
 */
router.get('/', 
  checkSearchBlocking, // Check if user is blocked from searching
  searchComplexityMiddleware, // Apply smart search rate limiting based on complexity
  trackSearchEvent, // Monitor search patterns
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('search').optional().trim().isLength({ max: 200 }),
    query('status').optional().isIn(['active', 'inactive', 'pending', '']),
    query('tags').optional().trim(),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', status = '', tags = '' } = req.query;
    const userId = getUserId(req);

    const contactService = ServiceFactory.create().getContactService();
    
    const filters = {
      search: search.trim(),
      status: status.trim(),
      tags: tags ? tags.split(',').map(tag => tag.trim()) : []
    };

    const pagination = {
      page: parseInt(page),
      limit: Math.min(100, parseInt(limit))
    };

    const result = await contactService.getContactsWithStats(userId, filters, pagination);
    res.json(result);

  } catch (error) {
    console.error('❌ Error getting contacts:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer les contacts.', 
      code: 'GET_CONTACTS_ERROR' 
    });
  }
});

// Email domain validation middleware for contact creation
const contactEmailValidation = createEmailDomainMiddleware({
  emailField: 'email',
  logBlocked: true
});

/**
 * POST /api/contacts - Create a new contact
 */
router.post('/', 
  contactLimiter,
  csrfProtectionStrict(),
  contactEmailValidation,
  [
    body('email').trim().isEmail().normalizeEmail(),
    body('firstName').optional().trim().isLength({ min: 1, max: 100 }),
    body('lastName').optional().trim().isLength({ min: 1, max: 100 }),
    body('tags').optional().isArray(),
    body('tags.*').optional().trim().isLength({ min: 1, max: 50 }),
    body('notes').optional().trim().isLength({ max: 1000 }),
    body('source').optional().isIn(['manual', 'import', 'api', 'form']),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);

    const { email, firstName, lastName, tags, notes, source } = req.body;

    const contactService = ServiceFactory.create().getContactService();
    
    const contactData = {
      email: email,
      firstName: firstName ? smartEscape(firstName) : undefined,
      lastName: lastName ? smartEscape(lastName) : undefined,
      tags: Array.isArray(tags) ? tags.map(tag => smartEscape(tag)) : [],
      notes: notes ? smartEscape(notes) : undefined,
      source: source || 'manual'
    };

    const result = await contactService.addContact(contactData, userId);
    
    res.status(201).json({
      success: true,
      contact: result.contact,
      handshake: result.handshake,
      message: result.message
    });

  } catch (error) {
    console.error('❌ Error creating contact:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    
    if (error.message.includes('existe déjà')) {
      return res.status(409).json({ 
        success: false,
        error: 'Ce contact existe déjà.', 
        code: 'DUPLICATE_CONTACT' 
      });
    }
    
    res.status(400).json({ 
      success: false,
      error: 'Impossible de créer le contact.', 
      code: 'CREATE_CONTACT_ERROR' 
    });
  }
});

/**
 * GET /api/contacts/search - Recherche avancée de contacts
 */
router.get('/search', 
  checkSearchBlocking, // Check if user is blocked from searching
  searchAdvancedLimiter, // Use advanced search rate limiting
  trackSearchEvent, // Monitor search patterns  
  async (req, res) => {
  try {
    const userId = getUserId(req);

    const { 
      q = '', 
      fields = 'email,firstName,lastName', 
      limit = 20,
      exactMatch = false,
      status = '',
      tags = ''
    } = req.query;

    if (!q.trim()) {
      return res.status(400).json({ error: 'Search query is required', code: 'VALIDATION_ERROR' });
    }

    const contactService = ServiceFactory.create().getContactService();
    
    const searchOptions = {
      query: q.trim(),
      fields: fields.split(',').map(f => f.trim()),
      limit: Math.min(100, parseInt(limit)),
      exactMatch: exactMatch === 'true',
      status: status.trim(),
      tags: tags ? tags.split(',').map(tag => tag.trim()) : []
    };

    const contacts = await contactService.searchContacts(userId, q.trim(), {
      limit: Math.min(100, parseInt(limit)),
      includeInactive: false
    });
    
    res.json({
      success: true,
      contacts: contacts,
      total: contacts.length,
      query: q.trim(),
      searchOptions
    });

  } catch (error) {
    console.error('❌ Error searching contacts:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      query: req.query.q,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de rechercher les contacts.', 
      code: 'SEARCH_CONTACTS_ERROR' 
    });
  }
});

/**
 * GET /api/contacts/:id - Get specific contact
 */
router.get('/:id', 
  apiLimiter,
  [
    param('id').isMongoId(),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    const contactId = req.params.id;
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const contactService = ServiceFactory.create().getContactService();
    const contact = await contactService.getContactById(contactId, userId);
    
    if (!contact) {
      return res.status(404).json({ error: 'Contact not found', code: 'NOT_FOUND' });
    }

    res.json({ contact });

  } catch (error) {
    console.error('❌ Error getting contact:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      contactId: req.params.id,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer le contact.', 
      code: 'GET_CONTACT_ERROR' 
    });
  }
});

// Email domain validation middleware for contact updates (only when email is provided)
const contactUpdateEmailValidation = createEmailDomainMiddleware({
  emailField: 'email',
  logBlocked: true,
  skipValidationFor: [] // Apply to all routes by default
});

/**
 * PUT /api/contacts/:id - Update contact
 */
router.put('/:id', 
  contactLimiter,
  csrfProtectionStrict(),
  // Apply email validation only if email field is present
  (req, res, next) => {
    if (req.body.email) {
      contactUpdateEmailValidation(req, res, next);
    } else {
      next();
    }
  },
  [
    param('id').isMongoId(),
    body('email').optional().trim().isEmail().normalizeEmail(),
    body('firstName').optional().trim().isLength({ min: 1, max: 100 }),
    body('lastName').optional().trim().isLength({ min: 1, max: 100 }),
    body('tags').optional().isArray(),
    body('tags.*').optional().trim().isLength({ min: 1, max: 50 }),
    body('notes').optional().trim().isLength({ max: 1000 }),
    body('status').optional().isIn(['active', 'inactive', 'pending']),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    const contactId = req.params.id;
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    // Apply XSS protection to string fields
    const updateData = {};
    if (req.body.email) updateData.email = req.body.email;
    if (req.body.firstName) updateData.firstName = smartEscape(req.body.firstName);
    if (req.body.lastName) updateData.lastName = smartEscape(req.body.lastName);
    if (req.body.notes) updateData.notes = smartEscape(req.body.notes);
    if (req.body.tags) updateData.tags = req.body.tags.map(tag => smartEscape(tag));
    if (req.body.status) updateData.status = req.body.status;
    
    const contactService = ServiceFactory.create().getContactService();
    
    const updatedContact = await contactService.updateContact(contactId, userId, updateData);
    
    if (!updatedContact) {
      return res.status(404).json({ error: 'Contact not found', code: 'NOT_FOUND' });
    }

    res.json({
      success: true,
      contact: updatedContact,
      message: 'Contact updated successfully'
    });

  } catch (error) {
    console.error('❌ Error updating contact:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      contactId: req.params.id,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(400).json({ 
      success: false,
      error: 'Impossible de mettre à jour le contact.', 
      code: 'UPDATE_CONTACT_ERROR' 
    });
  }
});

/**
 * DELETE /api/contacts/:id - Delete contact
 */
router.delete('/:id', 
  contactLimiter,
  csrfProtectionStrict(),
  [
    param('id').isMongoId(),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    const contactId = req.params.id;
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const contactService = ServiceFactory.create().getContactService();
    const result = await contactService.deleteContact(contactId, userId);
    
    if (!result.success) {
      return res.status(404).json({ error: 'Contact not found', code: 'NOT_FOUND' });
    }

    res.json({
      success: true,
      message: 'Contact deleted successfully',
      deletedRelations: result.deletedRelations
    });

  } catch (error) {
    console.error('❌ Error deleting contact:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      contactId: req.params.id,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de supprimer le contact.', 
      code: 'DELETE_CONTACT_ERROR' 
    });
  }
});

/**
 * GET /api/contacts/stats/global - Statistiques globales des contacts
 * SECURITY: Uses statsGlobalLimiter for database-wide queries (12 requests per 45 minutes)
 */
router.get('/stats/global', 
  require('../middleware/rateLimiting').statsGlobalLimiter, // Use global stats rate limiting
  trackGlobalStats, // Monitor statistics access patterns
  trackSearchEvent, // Monitor search patterns
  async (req, res) => {
  try {
    const userId = getUserId(req);

    const { period = '30d', groupBy = 'status' } = req.query;

    const contactService = ServiceFactory.create().getContactService();
    
    const options = {
      period,
      groupBy
    };

    const stats = await contactService.getGlobalContactStats(userId, options);
    
    res.json({
      success: true,
      stats,
      period,
      groupBy
    });

  } catch (error) {
    console.error('❌ Error getting global contact stats:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer les statistiques.', 
      code: 'GET_GLOBAL_STATS_ERROR' 
    });
  }
});

/**
 * POST /api/contacts/import - Import CSV de contacts (alias pour /bulk)
 * Supports both file upload and direct CSV data in body
 */
router.post('/import', 
  (req, res, next) => {
    // Check if request has file upload content type
    const contentType = req.get('content-type') || '';
    if (contentType.includes('multipart/form-data')) {
      // Use multer for file uploads
      csvUpload.single('file')(req, res, (err) => {
        if (err) {
          console.warn('CSV upload validation failed', {
            error: err.message,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            path: req.path
          });
          return res.status(400).json({
            success: false,
            error: 'Invalid file format',
            code: 'FILE_VALIDATION_ERROR'
          });
        }
        
        // Convert file buffer to csvData for compatibility
        if (req.file) {
          req.body.csvData = req.file.buffer.toString('utf8');
          req.body.fileName = req.file.originalname;
          req.body.mimeType = req.file.mimetype;
        }
        next();
      });
    } else {
      // Use body parser for direct CSV data
      createBulkImportBodyParser()(req, res, next);
    }
  },
  bulkImportLimiter, 
  blockSuspiciousIPs(), // Block IPs with repeated CSV violations
  csrfProtectionStrict(),
  validateCSVData, // Validate CSV data size and format
  [
    body('options.skipDuplicates').optional().isBoolean(),
    body('options.updateExisting').optional().isBoolean(),
    body('options.defaultTags').optional().isArray(),
    body('options.defaultTags.*').optional().trim().isLength({ min: 1, max: 50 }),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);

    const { csvData, options = {} } = req.body;

    const contactService = ServiceFactory.create().getContactService();
    const result = await contactService.importContactsFromCSV(csvData, userId, options);

    // Track successful import
    csvSecurityMonitor.trackCSVImportEvent(req, 'successful_import', {
      recordCount: result.imported.length,
      totalProcessed: result.total,
      errorCount: result.errors.length
    });

    res.json({
      success: true,
      imported: result.imported,
      errors: result.errors,
      duplicates: result.duplicates,
      total: result.total,
      message: `Successfully imported ${result.imported.length} contacts`
    });

  } catch (error) {
    console.error('❌ Error importing contacts (import route):', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(400).json({ 
      success: false,
      error: 'Impossible d\'importer les contacts.', 
      code: 'IMPORT_CONTACTS_ERROR' 
    });
  }
});

/**
 * POST /api/contacts/bulk - Bulk import contacts from CSV
 */
router.post('/bulk', 
  createBulkImportBodyParser(), // Use 5MB body parser for CSV imports
  bulkImportLimiter, 
  blockSuspiciousIPs(), // Block IPs with repeated CSV violations
  csrfProtectionStrict(), 
  validateCSVData, // Validate CSV data size and format
  async (req, res) => {
  try {
    const userId = getUserId(req);

    const { csvData, options = {} } = req.body;

    const contactService = ServiceFactory.create().getContactService();
    const result = await contactService.importContactsFromCSV(csvData, userId, options);

    // Track successful import
    csvSecurityMonitor.trackCSVImportEvent(req, 'successful_import', {
      recordCount: result.imported.length,
      totalProcessed: result.total,
      errorCount: result.errors.length
    });

    res.json({
      success: true,
      imported: result.imported,
      errors: result.errors,
      duplicates: result.duplicates,
      total: result.total,
      message: `Successfully imported ${result.imported.length} contacts`
    });

  } catch (error) {
    console.error('❌ Error importing contacts (bulk route):', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(400).json({ 
      success: false,
      error: 'Impossible d\'importer les contacts.', 
      code: 'IMPORT_CONTACTS_ERROR' 
    });
  }
});

/**
 * GET /api/contacts/:id/stats - Get contact statistics
 * SECURITY: Uses statsSimpleLimiter for individual contact stats (40 requests per 10 minutes)
 */
router.get('/:id/stats', 
  require('../middleware/rateLimiting').statsSimpleLimiter, // Use simple stats rate limiting
  trackSimpleStats, // Monitor statistics access patterns
  trackSearchEvent, // Monitor search patterns
  async (req, res) => {
  try {
    const userId = getUserId(req);
    const contactId = req.params.id;
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const contactService = ServiceFactory.create().getContactService();
    const stats = await contactService.getContactStats(contactId, userId);
    
    if (!stats) {
      return res.status(404).json({ error: 'Contact not found', code: 'NOT_FOUND' });
    }

    res.json({ stats });

  } catch (error) {
    console.error('❌ Error getting contact stats:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      contactId: req.params.id,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible de récupérer les statistiques du contact.', 
      code: 'GET_CONTACT_STATS_ERROR' 
    });
  }
});

/**
 * POST /api/contacts/:id/tracking - Update contact tracking
 */
router.post('/:id/tracking', contactLimiter, csrfProtectionStrict(), async (req, res) => {
  try {
    const userId = getUserId(req);
    const contactId = req.params.id;
    const { event, metadata = {} } = req.body;
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    if (!event || !['sent', 'opened', 'submitted'].includes(event)) {
      return res.status(400).json({ 
        error: 'Valid event is required (sent, opened, submitted)', 
        code: 'VALIDATION_ERROR' 
      });
    }

    const contactService = ServiceFactory.create().getContactService();
    const result = await contactService.updateContactTracking(contactId, userId, event, metadata);
    
    if (!result.success) {
      return res.status(404).json({ error: 'Contact not found', code: 'NOT_FOUND' });
    }

    res.json({
      success: true,
      contact: result.contact,
      message: `Tracking updated for event: ${event}`
    });

  } catch (error) {
    console.error('❌ Error updating contact tracking:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      contactId: req.params.id,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(400).json({ 
      success: false,
      error: 'Impossible de mettre à jour le suivi du contact.', 
      code: 'UPDATE_TRACKING_ERROR' 
    });
  }
});

/**
 * GET /api/contacts/export/csv - Export contacts to CSV format
 */
router.get('/export/csv', 
  require('../middleware/rateLimiting').statsGlobalLimiter, // Use global stats rate limiting
  csrfProtectionStrict(),
  [
    query('status').optional().isIn(['active', 'inactive', 'pending', 'all']),
    query('tags').optional().trim(),
    query('dateFrom').optional().isISO8601().toDate(),
    query('dateTo').optional().isISO8601().toDate(),
    handleValidationErrors
  ],
  async (req, res) => {
  try {
    const userId = getUserId(req);
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    }

    const { status = 'all', tags = '', dateFrom, dateTo } = req.query;
    
    const contactService = ServiceFactory.create().getContactService();
    
    const filters = {
      status: status === 'all' ? '' : status,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
      dateFrom,
      dateTo
    };

    // Get all contacts matching filters (no pagination for export)
    const result = await contactService.getContactsWithStats(userId, filters, { page: 1, limit: 10000 });
    
    if (!result.contacts || result.contacts.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Aucun contact trouvé avec les critères spécifiés.',
        code: 'NO_CONTACTS_FOUND'
      });
    }

    // Generate CSV content with proper sanitization
    const csvData = await contactService.exportContactsToCSV(result.contacts);
    
    // Track successful export
    csvSecurityMonitor.trackCSVExportEvent(req, 'successful_export', {
      recordCount: result.contacts.length,
      filters
    });
    
    // Security logging for CSV export
    console.log('📥 CSV export requested:', {
      userId,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      contactCount: result.contacts.length,
      filters,
      timestamp: new Date().toISOString()
    });

    // Set CSV headers
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `contacts-export-${timestamp}.csv`;
    
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    res.send(csvData);

  } catch (error) {
    console.error('❌ Error exporting contacts to CSV:', {
      error: error.message,
      stack: error.stack,
      userId: getUserId(req),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      success: false,
      error: 'Impossible d\'exporter les contacts.', 
      code: 'EXPORT_CONTACTS_ERROR' 
    });
  }
});

module.exports = router;