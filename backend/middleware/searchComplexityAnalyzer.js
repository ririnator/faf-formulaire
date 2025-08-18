// middleware/searchComplexityAnalyzer.js

/**
 * Search Query Complexity Analyzer Middleware
 * 
 * Analyzes search queries to determine complexity level and apply appropriate rate limiting.
 * Helps prevent abuse through complex queries that could overload the database.
 */

const { 
  searchBasicLimiter, 
  searchAdvancedLimiter, 
  searchAnalyticsLimiter,
  searchSuggestionsLimiter,
  searchAnonymousLimiter 
} = require('./rateLimiting');

/**
 * Calculate search query complexity score
 * @param {Object} query - Express query object
 * @param {String} path - Request path
 * @returns {Object} Complexity analysis result
 */
function analyzeSearchComplexity(query, path) {
  let complexityScore = 0;
  let complexityFactors = [];
  let searchType = 'basic';

  // Path-based complexity assessment
  if (path.includes('/search')) {
    complexityScore += 2;
    complexityFactors.push('dedicated_search_endpoint');
  }
  
  if (path.includes('/stats') || path.includes('/analytics')) {
    complexityScore += 3;
    complexityFactors.push('statistics_endpoint');
    searchType = 'analytics';
  }
  
  if (path.includes('/suggestions') || path.includes('/recommendations')) {
    complexityScore += 2;
    complexityFactors.push('suggestion_endpoint');
    searchType = 'suggestions';
  }
  
  if (path.includes('/timeline') || path.includes('/comparison')) {
    complexityScore += 3;
    complexityFactors.push('timeline_analytics');
    searchType = 'analytics';
  }

  // Query parameter complexity analysis
  const queryParams = Object.keys(query);
  
  // Multiple search parameters increase complexity
  if (queryParams.length > 3) {
    complexityScore += Math.min(queryParams.length - 3, 5);
    complexityFactors.push(`multiple_params:${queryParams.length}`);
  }

  // Specific complex parameters
  const complexParams = ['tags', 'status', 'dateFrom', 'dateTo', 'fields', 'groupBy', 'period'];
  const complexParamCount = queryParams.filter(param => complexParams.includes(param)).length;
  
  if (complexParamCount > 0) {
    complexityScore += complexParamCount * 1.5;
    complexityFactors.push(`complex_filters:${complexParamCount}`);
  }

  // Search query length and complexity
  const searchQuery = query.q || query.search || '';
  if (searchQuery) {
    if (searchQuery.length > 50) {
      complexityScore += 2;
      complexityFactors.push('long_search_query');
    }
    
    // Advanced search patterns (regex-like, wildcards, boolean operators)
    const advancedPatterns = [/[*%]/, /AND|OR|NOT/i, /[{}[\]()]/];
    if (advancedPatterns.some(pattern => pattern.test(searchQuery))) {
      complexityScore += 3;
      complexityFactors.push('advanced_search_patterns');
    }
  }

  // Date range queries are expensive
  if (query.dateFrom || query.dateTo) {
    complexityScore += 2;
    complexityFactors.push('date_range_filter');
  }

  // Large limit requests are resource intensive
  const limit = parseInt(query.limit) || 10;
  if (limit > 50) {
    complexityScore += Math.floor(limit / 25);
    complexityFactors.push(`large_limit:${limit}`);
  }

  // Exact match vs fuzzy search
  if (query.exactMatch === 'true') {
    complexityScore += 1;
    complexityFactors.push('exact_match');
  }

  // Multiple field search
  const fields = query.fields ? query.fields.split(',') : [];
  if (fields.length > 3) {
    complexityScore += fields.length - 3;
    complexityFactors.push(`multi_field_search:${fields.length}`);
  }

  // Determine complexity level
  let complexityLevel = 'low';
  if (complexityScore >= 8) {
    complexityLevel = 'critical';
    searchType = 'analytics';
  } else if (complexityScore >= 5) {
    complexityLevel = 'high';
    searchType = searchType === 'basic' ? 'advanced' : searchType;
  } else if (complexityScore >= 3) {
    complexityLevel = 'medium';
    searchType = searchType === 'basic' ? 'advanced' : searchType;
  }

  return {
    score: complexityScore,
    level: complexityLevel,
    type: searchType,
    factors: complexityFactors,
    params: queryParams,
    queryLength: searchQuery.length
  };
}

/**
 * Select appropriate rate limiter based on complexity and user status
 * @param {Object} analysis - Complexity analysis result
 * @param {Boolean} isAuthenticated - Whether user is authenticated
 * @returns {Function} Rate limiter middleware
 */
function selectRateLimiter(analysis, isAuthenticated) {
  // Anonymous users get stricter limits
  if (!isAuthenticated) {
    return searchAnonymousLimiter;
  }

  // Select based on search type and complexity
  switch (analysis.type) {
    case 'analytics':
      return searchAnalyticsLimiter;
    case 'suggestions':
      return searchSuggestionsLimiter;
    case 'advanced':
      return searchAdvancedLimiter;
    default:
      return searchBasicLimiter;
  }
}

/**
 * Middleware that analyzes search complexity and applies appropriate rate limiting
 */
function searchComplexityMiddleware(req, res, next) {
  try {
    // Skip analysis for non-search operations
    if (req.method !== 'GET' || Object.keys(req.query).length === 0) {
      return next();
    }

    const analysis = analyzeSearchComplexity(req.query, req.path);
    const isAuthenticated = !!(req.user || req.session?.userId || req.currentUser);
    
    // Log high complexity searches for monitoring
    if (analysis.level === 'high' || analysis.level === 'critical') {
      console.warn('🔍 High complexity search detected:', {
        ip: req.ip,
        userId: req.user?.id || req.session?.userId || 'anonymous',
        userAgent: req.get('user-agent'),
        path: req.path,
        query: req.query,
        complexity: analysis,
        isAuthenticated,
        timestamp: new Date().toISOString()
      });
    }

    // Block critical complexity searches to prevent DoS
    if (analysis.level === 'critical') {
      console.error('🚨 Critical complexity search blocked:', {
        ip: req.ip,
        userId: req.user?.id || req.session?.userId || 'anonymous',
        path: req.path,
        complexity: analysis,
        timestamp: new Date().toISOString()
      });
      
      return res.status(429).json({
        success: false,
        error: 'Requête trop complexe. Simplifiez vos critères de recherche.',
        code: 'SEARCH_TOO_COMPLEX',
        complexity: {
          level: analysis.level,
          score: analysis.score,
          factors: analysis.factors
        },
        retryAfter: 300
      });
    }

    // Attach analysis to request for potential use by route handlers
    req.searchComplexity = analysis;

    // Apply appropriate rate limiter
    const rateLimiter = selectRateLimiter(analysis, isAuthenticated);
    return rateLimiter(req, res, next);

  } catch (error) {
    console.error('❌ Error in search complexity analyzer:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip,
      path: req.path,
      query: req.query,
      timestamp: new Date().toISOString()
    });
    
    // Fallback to basic rate limiting if analysis fails
    return searchBasicLimiter(req, res, next);
  }
}

/**
 * Create smart search middleware for specific search operations
 * @param {Object} options - Configuration options
 * @returns {Function} Configured middleware
 */
function createSmartSearchLimiter(options = {}) {
  const config = {
    enableComplexityAnalysis: true,
    allowedComplexityLevels: ['low', 'medium', 'high'],
    logThreshold: 'medium',
    ...options
  };

  return (req, res, next) => {
    if (!config.enableComplexityAnalysis) {
      return searchBasicLimiter(req, res, next);
    }

    const analysis = analyzeSearchComplexity(req.query, req.path);
    
    // Block if complexity level not allowed
    if (!config.allowedComplexityLevels.includes(analysis.level)) {
      return res.status(429).json({
        success: false,
        error: 'Niveau de complexité de recherche non autorisé.',
        code: 'COMPLEXITY_NOT_ALLOWED',
        allowedLevels: config.allowedComplexityLevels,
        currentLevel: analysis.level
      });
    }

    // Log based on threshold
    const shouldLog = (
      config.logThreshold === 'low' ||
      (config.logThreshold === 'medium' && ['medium', 'high', 'critical'].includes(analysis.level)) ||
      (config.logThreshold === 'high' && ['high', 'critical'].includes(analysis.level))
    );

    if (shouldLog) {
      console.log('🔍 Smart search middleware:', {
        ip: req.ip,
        path: req.path,
        complexity: analysis,
        timestamp: new Date().toISOString()
      });
    }

    req.searchComplexity = analysis;
    
    const isAuthenticated = !!(req.user || req.session?.userId || req.currentUser);
    const rateLimiter = selectRateLimiter(analysis, isAuthenticated);
    
    return rateLimiter(req, res, next);
  };
}

module.exports = {
  searchComplexityMiddleware,
  createSmartSearchLimiter,
  analyzeSearchComplexity,
  selectRateLimiter
};