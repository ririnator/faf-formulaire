// routes/adminRoutes.js
const express  = require('express');
const mongoose = require('mongoose');
const router   = express.Router();
const Response = require('../models/Response');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtection, csrfTokenEndpoint } = require('../middleware/csrf');
const { normalizeQuestion } = require('../utils/questionNormalizer');
const SessionConfig = require('../config/session');
const DBPerformanceMonitor = require('../services/dbPerformanceMonitor');
const RealTimeMetrics = require('../services/realTimeMetrics');

// Configuration constants
const PIE_CHART_QUESTION = process.env.PIE_CHART_QUESTION || "En rapide, comment ça va ?";

// Monthly question order cache to avoid repeated DB queries
const questionOrderCache = new Map(); // Key: "YYYY-MM", Value: { order: [...], timestamp: Date }
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes cache
const MAX_CACHE_SIZE = 50; // Prevent memory leaks from unlimited month caching

/**
 * Cache cleanup utility to prevent memory leaks
 * Removes expired entries and enforces size limits
 */
function cleanupCache() {
  const now = Date.now();
  let removedCount = 0;
  
  // Remove expired entries
  for (const [key, value] of questionOrderCache.entries()) {
    if ((now - value.timestamp) > CACHE_TTL) {
      questionOrderCache.delete(key);
      removedCount++;
    }
  }
  
  // Enforce max cache size (LRU-style cleanup)
  if (questionOrderCache.size > MAX_CACHE_SIZE) {
    const entries = Array.from(questionOrderCache.entries());
    // Sort by timestamp (oldest first)
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    
    const toRemove = entries.slice(0, questionOrderCache.size - MAX_CACHE_SIZE);
    toRemove.forEach(([key]) => {
      questionOrderCache.delete(key);
      removedCount++;
    });
  }
  
  if (removedCount > 0) {
    console.log(`🧹 Cache cleanup: removed ${removedCount} entries, size: ${questionOrderCache.size}`);
  }
}

// Periodic cache cleanup every 5 minutes (only in production)
if (process.env.NODE_ENV === 'production') {
  setInterval(cleanupCache, 5 * 60 * 1000);
}

/**
 * Pre-warm cache for current month to improve initial performance
 * Called on server startup and monthly
 */
async function preWarmCurrentMonth() {
  try {
    const currentMonth = new Date().toISOString().slice(0, 7); // "YYYY-MM"
    const match = {
      createdAt: {
        $gte: new Date(currentMonth + '-01'),
        $lt: new Date(new Date(currentMonth + '-01').getFullYear(), 
                     new Date(currentMonth + '-01').getMonth() + 1, 1)
      }
    };
    
    // Check if current month already cached
    if (!questionOrderCache.has(currentMonth)) {
      console.log(`🔥 Pre-warming cache for current month: ${currentMonth}`);
      await getQuestionOrderForMonth(currentMonth, match, PIE_CHART_QUESTION);
    }
  } catch (error) {
    console.warn('⚠️ Failed to pre-warm cache:', error.message);
  }
}

// Pre-warm on startup (only in production, not during tests)
if (process.env.NODE_ENV === 'production') {
  setTimeout(preWarmCurrentMonth, 10000);

  // Pre-warm monthly (on the 1st of each month at 1 AM)
  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1, 1, 0, 0);
  const timeToNextMonth = nextMonth.getTime() - now.getTime();
  setTimeout(() => {
    preWarmCurrentMonth();
    // Then repeat monthly
    setInterval(preWarmCurrentMonth, 30 * 24 * 60 * 60 * 1000); // 30 days
  }, timeToNextMonth);
}

/**
 * Retrieves cached question order or fetches from database
 * Implements intelligent caching with TTL to optimize performance
 * 
 * @param {string} monthKey - Month identifier (YYYY-MM or 'all')
 * @param {Object} match - MongoDB match query for filtering responses
 * @param {string} PIE_Q - The pie chart question to prioritize first
 * @returns {Promise<string[]>} Array of questions in natural form order
 */
async function getQuestionOrderForMonth(monthKey, match, PIE_Q) {
  const startTime = Date.now();
  const now = Date.now();
  const cached = questionOrderCache.get(monthKey);
  
  const logContext = {
    month: monthKey,
    cacheSize: questionOrderCache.size,
    operation: 'getQuestionOrder'
  };
  
  // Return cached order if valid and not expired
  if (cached && (now - cached.timestamp) < CACHE_TTL) {
    const cacheAge = Math.round((now - cached.timestamp) / 1000);
    console.log(`📋 Cache HIT for ${monthKey} (age: ${cacheAge}s, questions: ${cached.order.length})`);
    return cached.order;
  }
  
  console.log(`📋 Cache MISS for ${monthKey}, fetching from database...`);
  
  // Fetch from database with performance tracking
  let questionOrder = [];
  let dbQueries = 0;
  
  try {
    // Add PIE_Q first if it exists in the dataset
    dbQueries++;
    const hasPieData = await mongoose.connection.db
      .collection('responses')
      .countDocuments({ 
        ...match, 
        'responses.question': PIE_Q 
      });
    
    if (hasPieData > 0) {
      questionOrder.push(PIE_Q);
      console.log(`📊 PIE_Q found in dataset (${hasPieData} responses)`);
    }
    
    // Find first response for natural order
    dbQueries++;
    const firstResponse = await Response.findOne(match).sort({ createdAt: 1 });
    
    if (!firstResponse) {
      console.warn(`⚠️ No responses found for month ${monthKey}`, logContext);
      return questionOrder; // Return empty or PIE_Q only
    }
    
    const responseInfo = {
      id: firstResponse._id,
      user: firstResponse.name,
      createdAt: firstResponse.createdAt,
      responseCount: firstResponse.responses?.length || 0
    };
    
    console.log(`📋 Using first response as order reference:`, responseInfo);
    
    if (firstResponse.responses?.length) {
      const validResponses = firstResponse.responses.filter(r => 
        r && typeof r.question === 'string' && r.question.trim()
      );
      
      const invalidCount = firstResponse.responses.length - validResponses.length;
      if (invalidCount > 0) {
        console.warn(`⚠️ Filtered out ${invalidCount} invalid questions from first response`, {
          ...logContext,
          responseId: firstResponse._id,
          totalQuestions: firstResponse.responses.length,
          validQuestions: validResponses.length
        });
      }
      
      if (validResponses.length > 0) {
        let addedCount = 0;
        let skippedCount = 0;
        
        validResponses.forEach((r, index) => {
          if (r.question !== PIE_Q) {
            const normalized = normalizeQuestion(r.question);
            if (normalized) {
              const alreadyExists = questionOrder.some(q => normalizeQuestion(q) === normalized);
              if (!alreadyExists) {
                questionOrder.push(r.question);
                addedCount++;
              } else {
                skippedCount++;
              }
            }
          }
        });
        
        console.log(`📋 Question order established: ${addedCount} added, ${skippedCount} skipped duplicates`);
      } else {
        console.warn(`⚠️ First response has no valid questions`, {
          ...logContext,
          responseId: firstResponse._id
        });
      }
    }
    
    // Cache the result with metadata
    questionOrderCache.set(monthKey, {
      order: questionOrder,
      timestamp: now,
      source: 'database',
      dbQueries,
      firstResponseId: firstResponse._id
    });
    
    const duration = Date.now() - startTime;
    console.log(`📋 Question order cached for ${monthKey}:`, {
      questionsCount: questionOrder.length,
      duration: `${duration}ms`,
      dbQueries,
      cacheSize: questionOrderCache.size
    });
    
    return questionOrder;
    
  } catch (error) {
    console.error(`❌ Error fetching question order for ${monthKey}:`, {
      ...logContext,
      error: error.message,
      // Stack trace seulement en développement
      ...(process.env.NODE_ENV !== 'production' && { stack: error.stack }),
      duration: `${Date.now() - startTime}ms`
    });
    
    // Return cached data if available, even if expired, as fallback
    if (cached) {
      console.warn(`⚠️ Using expired cache as fallback for ${monthKey}`);
      return cached.order;
    }
    
    // Last resort: return empty array or PIE_Q only
    return questionOrder.length > 0 ? questionOrder : [];
  }
}

// Apply admin-specific body parser (1MB limit) to all admin routes
router.use(createAdminBodyParser());

// Endpoint pour récupérer le token CSRF
router.get('/csrf-token', csrfTokenEndpoint());

// DEBUG: Endpoint sécurisé pour analyser les questions (admin + dev uniquement)
router.get('/debug/questions', (req, res, next) => {
  // SÉCURITÉ: Uniquement en développement local
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Not found' });
  }
  next();
}, (req, res, next) => {
  // SÉCURITÉ: Vérifier authentification admin même en dev
  if (!req.session || !req.session.isAdmin) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  next();
}, async (req, res) => {
  try {
    // Configuration question pie chart (même logique que summary)
    const PIE_Q = PIE_CHART_QUESTION;
    
    const docs = await Response.find()
      .select('responses.question')  // Suppression des noms utilisateurs
      .lean();
    
    const allQuestions = [];
    const questionMap = new Map(); // Éviter doublons
    
    docs.forEach(doc => {
      doc.responses.forEach(r => {
        if (r.question && r.question !== PIE_Q) {
          const key = r.question;
          if (!questionMap.has(key)) {
            questionMap.set(key, {
              question: r.question,
              count: 0,
              length: r.question.length,
              charCodes: Array.from(r.question).map(c => c.charCodeAt(0)),
              // Masquer données sensibles en prod
              hexDump: Array.from(r.question).map(c => 
                `${c === ' ' ? '·' : c}(${c.charCodeAt(0).toString(16)})`
              ).join(' ')
            });
          }
          questionMap.get(key).count++;
        }
      });
    });
    
    res.json({ 
      total: questionMap.size,
      questions: Array.from(questionMap.values()).sort((a, b) => b.count - a.count)
    });
  } catch (err) {
    console.error('Debug endpoint error:', err);
    res.status(500).json({ error: 'Debug error' });
  }
});

// Middleware : charge la réponse dans req.responseDoc
router.param('id', async (req, res, next, id) => {
  try {
    const doc = await Response.findById(id);
    if (!doc) return res.status(404).json({ error: 'Réponse non trouvée', code: 'NOT_FOUND' });
    req.responseDoc = doc;
    next();
  } catch (err) {
    console.error('❌ Erreur param :id :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la récupération', code: 'SERVER_ERROR' });
  }
});

// GET /api/admin/responses?page=1&limit=10&search=term
// Pour l'UI de gestion paginée, incluant maintenant isAdmin et token
router.get('/responses', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const skip  = (page - 1) * limit;
    const search = req.query.search?.trim();

    // Construction du filtre de recherche sécurisée avec text search
    let filter = {};
    if (search) {
      // Validation basique de la recherche
      const sanitizedSearch = search.trim().replace(/["\\]/g, '').substring(0, 100);
      
      if (sanitizedSearch.length >= 2) {
        // Utiliser MongoDB text search avec fallback linguistique
        const textSearchOptions = {
          $search: sanitizedSearch,
          $caseSensitive: false
        };
        
        // Détecter la langue et appliquer le fallback approprié
        const hasAccents = /[àáâäæãåāèéêëēėęîïíīįìôöòóœøōõûüùúūñń]/i.test(sanitizedSearch);
        const hasEnglishWords = /\b(the|and|or|in|on|at|to|for|of|with|by)\b/i.test(sanitizedSearch);
        
        if (hasAccents || (!hasEnglishWords && sanitizedSearch.length > 0)) {
          textSearchOptions.$language = 'french';
        } else if (hasEnglishWords) {
          textSearchOptions.$language = 'english';
        } else {
          // Pas de langue spécifique - MongoDB utilisera la langue par défaut
          textSearchOptions.$language = 'none';
        }
        
        filter.$text = textSearchOptions;
      } else {
        // Fallback pour recherches courtes avec une approche sécurisée
        filter.name = { 
          $regex: `^${sanitizedSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`,
          $options: 'i'
        };
      }
    }

    let totalCount, data;
    
    try {
      totalCount = await Response.countDocuments(filter);
      const totalPages = Math.ceil(totalCount / limit);

      data = await Response.find(filter)
        .select('name month createdAt isAdmin token')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean();
    } catch (searchError) {
      // Fallback si la recherche text échoue (ex: langue non supportée)
      if (searchError.name === 'MongoServerError' && searchError.code === 17124) {
        console.warn('⚠️ Text search failed, falling back to regex:', searchError.message);
        
        // Utiliser regex comme fallback
        if (search && search.trim().length >= 2) {
          const sanitizedSearch = search.trim().replace(/["\\]/g, '').substring(0, 100);
          filter = {
            $or: [
              { name: { $regex: sanitizedSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
              { 'responses.question': { $regex: sanitizedSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
              { 'responses.answer': { $regex: sanitizedSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } }
            ]
          };
        } else {
          filter = {}; // Recherche vide si fallback impossible
        }
        
        totalCount = await Response.countDocuments(filter);
        data = await Response.find(filter)
          .select('name month createdAt isAdmin token')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean();
      } else {
        throw searchError; // Re-throw si ce n'est pas une erreur de text search
      }
    }
    
    const totalPages = Math.ceil(totalCount / limit);

    res.json({
      responses:  data,
      pagination: { page, totalPages, totalCount },
      search: search || null
    });
  } catch (err) {
    console.error('❌ Erreur pagination /responses :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la récupération des réponses', code: 'SERVER_ERROR' });
  }
});

// GET & DELETE /api/admin/responses/:id
router.route('/responses/:id')
  .get((req, res) => {
    res.json(req.responseDoc);
  })
  .delete(csrfProtection(), async (req, res) => {
    try {
      await req.responseDoc.deleteOne();
      res.json({ message: 'Réponse supprimée avec succès' });
    } catch (err) {
      console.error('❌ Erreur suppression /responses/:id :', err);
      res.status(500).json({ error: 'Erreur serveur lors de la suppression', code: 'SERVER_ERROR' });
    }
  });

/**
 * GET /api/admin/summary?month=YYYY-MM
 * 
 * Dynamic Question Ordering Algorithm:
 * =====================================
 * 
 * PROBLEM: Previously used hardcoded QUESTION_ORDER array that required manual maintenance
 * and could desync from actual form questions.
 * 
 * SOLUTION: Dynamic ordering based on natural form submission order
 * 
 * Algorithm Steps:
 * 1. Check cache for month-specific question order (10min TTL)
 * 2. If cache miss, find oldest response for the month
 * 3. Use that response's question order as the canonical ordering
 * 4. Always prioritize PIE_Q (pie chart question) first
 * 5. Group similar questions using normalizeQuestion() for deduplication
 * 6. Cache result to avoid repeated DB queries
 * 7. Fallback to textSummary order if no valid first response found
 * 
 * Benefits:
 * - Zero maintenance: automatically adapts to form changes
 * - Performance: cached results reduce DB load
 * - Robust: handles corrupted/invalid data gracefully
 * - Consistent: same order across multiple API calls
 * 
 * Cache Strategy:
 * - Key: month string (e.g. "2025-01" or "all")  
 * - TTL: 10 minutes (balances performance vs data freshness)
 * - Fallback: expired cache used if DB error occurs
 * - Metadata: tracks source, query count, performance metrics
 */
router.get('/summary', async (req, res) => {
  try {
    const match = {};
    if (req.query.month && req.query.month !== 'all') {
      const [y, m] = req.query.month.split('-').map(n => parseInt(n, 10));
      match.createdAt = {
        $gte: new Date(y, m - 1, 1),
        $lt:  new Date(y, m,     1)
      };
    }

    // Configuration question pie chart (centralisée)
    const PIE_Q = PIE_CHART_QUESTION;
    const piePipeline = [
      { $match: match },
      { $unwind: '$responses' },
      { $match: { 'responses.question': PIE_Q } },
      { $group: {
          _id: '$responses.question',
          items: { $push: { user: '$name', answer: '$responses.answer' } }
      }},
      { $project: {
          _id:      0,
          question: '$_id',
          items:    1
      }}
    ];
    const pieSummary = await mongoose.connection.db
      .collection('responses')
      .aggregate(piePipeline, { allowDiskUse: true })
      .toArray();

    // Optimisation: Utiliser aggregation pipeline pour éviter O(n²)
    const textPipeline = [
      { $match: match },
      { $unwind: '$responses' },
      { $match: { 'responses.question': { $ne: PIE_Q } } },
      {
        $group: {
          _id: '$responses.question',
          items: { $push: { user: '$name', answer: '$responses.answer' } }
        }
      },
      {
        $project: {
          _id: 0,
          question: '$_id',
          items: 1
        }
      }
    ];

    const rawTextSummary = await mongoose.connection.db
      .collection('responses')
      .aggregate(textPipeline, { allowDiskUse: true })
      .toArray();

    // STEP 1: Question Deduplication and Normalization
    // ================================================
    // Group similar questions (with accents, spacing variations) into canonical form
    // Uses normalizeQuestion() to handle French accents, extra spaces, punctuation variations
    const textMap = {};
    const questionNormalizedMap = {}; // Map: normalized → première question originale
    
    rawTextSummary.forEach(({ question, items }) => {
      const normalizedQ = normalizeQuestion(question);
      
      // Ignorer questions vides après normalisation
      if (!normalizedQ) {
        console.warn(`⚠️  Question vide ignorée:`, question);
        return;
      }
      
      // Utiliser la première version de la question comme clé de référence
      if (!questionNormalizedMap[normalizedQ]) {
        questionNormalizedMap[normalizedQ] = question;
      }
      
      const canonicalQ = questionNormalizedMap[normalizedQ];
      textMap[canonicalQ] = textMap[canonicalQ] || [];
      textMap[canonicalQ].push(...items); // Merger les items
    });
    
    const textSummary = Object.entries(textMap)
      .map(([question, items]) => ({ question, items }));

    // Debug sécurisé pour diagnostiquer (LOCAL uniquement)
    if (process.env.NODE_ENV === 'development' && !process.env.RENDER) {
      console.log('📊 Questions regroupées:', Object.keys(textMap).length);
      
      // Debug doublons uniquement (sans contenu sensible)
      const questionsByNormalized = {};
      rawTextSummary.forEach(({question}) => {
        const norm = normalizeQuestion(question);
        if (!questionsByNormalized[norm]) questionsByNormalized[norm] = [];
        questionsByNormalized[norm].push(question.length); // Juste la longueur
      });
      
      const duplicates = Object.entries(questionsByNormalized)
        .filter(([norm, lengths]) => lengths.length > 1);
      
      if (duplicates.length > 0) {
        console.log(`🔍 ${duplicates.length} groupes de doublons détectés`);
      }
    }

    // STEP 2: Dynamic Question Ordering 
    // =================================
    // Get natural question order from first submission (cached for performance)
    // This replaces the hardcoded QUESTION_ORDER array for zero-maintenance ordering
    const monthKey = req.query.month || 'all';
    let questionOrder = await getQuestionOrderForMonth(monthKey, match, PIE_Q);
    
    // STEP 3: Fallback Strategy
    // ========================= 
    // If no valid first response found, use textSummary order as emergency fallback
    if (questionOrder.length <= (pieSummary.length > 0 ? 1 : 0)) {
      console.warn('⚠️ No question order found from cache/first response, using textSummary fallback');
      textSummary.forEach(({ question }) => {
        if (question && question !== PIE_Q) {
          const normalized = normalizeQuestion(question);
          if (normalized) {
            const alreadyExists = questionOrder.some(q => normalizeQuestion(q) === normalized);
            if (!alreadyExists) {
              questionOrder.push(question);
            }
          }
        }
      });
    }

    // STEP 4: Final Assembly and Sorting
    // ==================================
    // Combine PIE chart data (always first) with text questions in natural form order
    const allSummary = [...pieSummary, ...textSummary];
    
    // Apply the dynamic ordering: sort by position in natural form order
    // Questions not found in reference order are placed at the end
    const sortedSummary = allSummary.sort((a, b) => {
      const normalizedA = normalizeQuestion(a.question);
      const normalizedB = normalizeQuestion(b.question);
      
      // Find position in the determined question order
      let indexA = questionOrder.findIndex(q => normalizeQuestion(q) === normalizedA);
      let indexB = questionOrder.findIndex(q => normalizeQuestion(q) === normalizedB);
      
      // Unknown questions go to end (maintains stability)
      if (indexA === -1) indexA = questionOrder.length;
      if (indexB === -1) indexB = questionOrder.length;
      
      return indexA - indexB; // Sort by natural form position
    });

    // Debug pour vérifier l'ordre (dev uniquement) - contenu anonymisé
    if (process.env.NODE_ENV === 'development' && !process.env.RENDER && process.env.DEBUG_VERBOSE) {
      console.log('📋 Ordre des questions basé sur première soumission:');
      questionOrder.forEach((q, i) => {
        // Log seulement la longueur et hash pour sécurité
        const questionHash = q.length > 0 ? `[Q${i+1}_${q.length}chars]` : '[empty]';
        console.log(`  ${i + 1}. ${questionHash}`);
      });
      console.log('📋 Résumé final:');
      sortedSummary.forEach((item, index) => {
        const shortQ = item.question.substring(0, 50) + (item.question.length > 50 ? '...' : '');
        console.log(`  ${index + 1}. ${shortQ}`);
      });
    }

    res.json(sortedSummary);
  } catch (err) {
    console.error('❌ Erreur summary :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la génération du résumé', code: 'SERVER_ERROR' });
  }
});

// GET /api/admin/months
// inchangé
router.get('/months', async (req, res) => {
  try {
    const pipeline = [
      { $project: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } } },
      { $group:   { _id: { y: '$year', m: '$month' } } },
      { $sort:    { '_id.y': -1, '_id.m': -1 } },
      { $project: {
          _id: 0,
          key: {
            $concat: [
              { $toString: '$_id.y' }, '-',
              { $cond: [
                { $lt: ['$_id.m', 10] },
                { $concat: ['0', { $toString: '$_id.m' }] },
                { $toString: '$_id.m' }
              ] }
            ]
          },
          label: {
            $concat: [
              { $arrayElemAt: [[
                'janvier','février','mars','avril','mai','juin',
                'juillet','août','septembre','octobre','novembre','décembre'
              ], { $subtract: ['$_id.m', 1] }] },
              ' ',
              { $toString: '$_id.y' }
            ]
          }
      }}
    ];

    const months = await mongoose.connection.db
      .collection('responses')
      .aggregate(pipeline, { allowDiskUse: true })
      .toArray();

    res.json(months);
  } catch (err) {
    console.error('❌ Erreur months :', err);
    res.status(500).json({ error: 'Erreur serveur lors de la récupération des mois', code: 'SERVER_ERROR' });
  }
});

// ============================================
// Session Cleanup Management Endpoints
// ============================================

// Get cleanup service status and statistics
router.get('/cleanup/status', async (req, res) => {
  try {
    const cleanupService = SessionConfig.getCleanupService();
    
    if (!cleanupService) {
      return res.status(404).json({ 
        error: 'Cleanup service not initialized',
        initialized: false
      });
    }

    const stats = cleanupService.getCleanupStats();
    
    res.json({
      initialized: true,
      stats,
      config: {
        sessionTTL: cleanupService.config.sessionTTL,
        userInactivityThreshold: cleanupService.config.userInactivityThreshold,
        cleanupInterval: cleanupService.config.cleanupInterval,
        batchSize: cleanupService.config.batchSize,
        enableAutoCleanup: cleanupService.config.enableAutoCleanup
      },
      lastCleanup: stats.lastCleanup
    });
    
  } catch (error) {
    console.error('❌ Error getting cleanup status:', error);
    res.status(500).json({ 
      error: 'Failed to get cleanup status', 
      code: 'CLEANUP_STATUS_ERROR' 
    });
  }
});

// Run manual cleanup (dry run by default)
router.post('/cleanup/run', createAdminBodyParser(), async (req, res) => {
  try {
    const { dryRun = true, type = 'complete' } = req.body;
    const cleanupService = SessionConfig.getCleanupService();
    
    if (!cleanupService) {
      return res.status(404).json({ 
        error: 'Cleanup service not initialized',
        code: 'SERVICE_NOT_FOUND'
      });
    }

    let result;
    
    switch (type) {
      case 'sessions':
        await cleanupService.cleanupExpiredSessions(dryRun);
        result = {
          type: 'sessions',
          stats: { expiredSessions: cleanupService.cleanupStats.expiredSessions },
          dryRun
        };
        break;
        
      case 'users':
        await cleanupService.cleanupInactiveUsers(dryRun);
        result = {
          type: 'users',
          stats: { inactiveUsers: cleanupService.cleanupStats.inactiveUsers },
          dryRun
        };
        break;
        
      case 'orphaned':
        await cleanupService.cleanupOrphanedData(dryRun);
        result = {
          type: 'orphaned',
          stats: { orphanedData: cleanupService.cleanupStats.orphanedData },
          dryRun
        };
        break;
        
      case 'complete':
      default:
        result = await cleanupService.runManualCleanup({ dryRun });
        break;
    }

    res.json({
      success: true,
      cleanup: result,
      timestamp: new Date()
    });
    
  } catch (error) {
    console.error('❌ Error running manual cleanup:', error);
    res.status(500).json({ 
      error: 'Failed to run cleanup', 
      code: 'CLEANUP_RUN_ERROR',
      details: error.message
    });
  }
});

// Update cleanup configuration
router.put('/cleanup/config', createAdminBodyParser(), async (req, res) => {
  try {
    const cleanupService = SessionConfig.getCleanupService();
    
    if (!cleanupService) {
      return res.status(404).json({ 
        error: 'Cleanup service not initialized',
        code: 'SERVICE_NOT_FOUND'
      });
    }

    const allowedConfigKeys = [
      'sessionTTL',
      'userInactivityThreshold', 
      'cleanupInterval',
      'batchSize',
      'enableAutoCleanup'
    ];

    const newConfig = {};
    for (const key of allowedConfigKeys) {
      if (req.body[key] !== undefined) {
        newConfig[key] = req.body[key];
      }
    }

    if (Object.keys(newConfig).length === 0) {
      return res.status(400).json({
        error: 'No valid configuration provided',
        allowedKeys: allowedConfigKeys
      });
    }

    cleanupService.updateConfig(newConfig);
    
    res.json({
      success: true,
      updatedConfig: cleanupService.config,
      timestamp: new Date()
    });
    
  } catch (error) {
    console.error('❌ Error updating cleanup config:', error);
    res.status(500).json({ 
      error: 'Failed to update cleanup configuration', 
      code: 'CLEANUP_CONFIG_ERROR',
      details: error.message
    });
  }
});

// Initialize or restart cleanup service
router.post('/cleanup/initialize', async (req, res) => {
  try {
    // Shutdown existing service if any
    SessionConfig.shutdownCleanupService();
    
    // Initialize new service
    const cleanupService = SessionConfig.initializeCleanupService();
    
    res.json({
      success: true,
      message: 'Cleanup service initialized successfully',
      config: cleanupService.config,
      timestamp: new Date()
    });
    
  } catch (error) {
    console.error('❌ Error initializing cleanup service:', error);
    res.status(500).json({ 
      error: 'Failed to initialize cleanup service', 
      code: 'CLEANUP_INIT_ERROR',
      details: error.message
    });
  }
});

// Shutdown cleanup service
router.post('/cleanup/shutdown', async (req, res) => {
  try {
    SessionConfig.shutdownCleanupService();
    
    res.json({
      success: true,
      message: 'Cleanup service shutdown successfully',
      timestamp: new Date()
    });
    
  } catch (error) {
    console.error('❌ Error shutting down cleanup service:', error);
    res.status(500).json({ 
      error: 'Failed to shutdown cleanup service', 
      code: 'CLEANUP_SHUTDOWN_ERROR',
      details: error.message
    });
  }
});

// ============================================
// Database Performance Monitoring Endpoints
// ============================================

// Global performance monitor instances (will be initialized by app.js)
let performanceMonitor = null;
let realTimeMetrics = null;

// Initialize performance monitoring
router.initializePerformanceMonitoring = (monitor, metrics) => {
  performanceMonitor = monitor;
  realTimeMetrics = metrics;
};

// Get performance monitoring status
router.get('/performance/status', async (req, res) => {
  try {
    if (!performanceMonitor || !realTimeMetrics) {
      return res.status(503).json({
        error: 'Performance monitoring not initialized',
        initialized: false
      });
    }

    const monitorStatus = {
      dbMonitor: {
        isMonitoring: performanceMonitor.isMonitoring,
        config: performanceMonitor.config,
        metricsCount: {
          queries: performanceMonitor.metrics.queries.size,
          slowQueries: performanceMonitor.metrics.slowQueries.length,
          collections: performanceMonitor.metrics.collections.size,
          indexes: performanceMonitor.metrics.indexes.size
        }
      },
      realTimeMetrics: {
        isCollecting: realTimeMetrics.isCollecting,
        config: realTimeMetrics.config,
        windowsCount: realTimeMetrics.windows.length,
        activeAlertsCount: realTimeMetrics.activeAlerts.size
      },
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
      }
    };

    res.json({
      initialized: true,
      status: monitorStatus,
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting performance status:', error);
    res.status(500).json({
      error: 'Failed to get performance monitoring status',
      code: 'PERFORMANCE_STATUS_ERROR'
    });
  }
});

// Get current performance summary
router.get('/performance/summary', async (req, res) => {
  try {
    if (!performanceMonitor || !realTimeMetrics) {
      return res.status(503).json({
        error: 'Performance monitoring not initialized'
      });
    }

    const summary = performanceMonitor.getPerformanceSummary();
    const realtimeStats = realTimeMetrics.getCurrentStats();
    
    res.json({
      summary,
      realtime: realtimeStats,
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting performance summary:', error);
    res.status(500).json({
      error: 'Failed to get performance summary',
      code: 'PERFORMANCE_SUMMARY_ERROR'
    });
  }
});

// Get real-time metrics
router.get('/performance/realtime', async (req, res) => {
  try {
    if (!realTimeMetrics) {
      return res.status(503).json({
        error: 'Real-time metrics not initialized'
      });
    }

    const stats = realTimeMetrics.getCurrentStats();
    const { timespan } = req.query;
    
    let windowAnalysis = null;
    if (timespan) {
      const timespanMs = parseInt(timespan) * 60 * 1000; // Convert minutes to ms
      windowAnalysis = realTimeMetrics.getWindowAnalysis(timespanMs);
    }

    res.json({
      current: stats,
      analysis: windowAnalysis,
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting real-time metrics:', error);
    res.status(500).json({
      error: 'Failed to get real-time metrics',
      code: 'REALTIME_METRICS_ERROR'
    });
  }
});

// Get slow queries analysis
router.get('/performance/slow-queries', async (req, res) => {
  try {
    if (!performanceMonitor) {
      return res.status(503).json({
        error: 'Performance monitoring not initialized'
      });
    }

    const { limit = 50, collection, minExecutionTime } = req.query;
    
    let slowQueries = [...performanceMonitor.metrics.slowQueries];
    
    // Filter by collection if specified
    if (collection) {
      slowQueries = slowQueries.filter(query => query.collection === collection);
    }
    
    // Filter by minimum execution time if specified
    if (minExecutionTime) {
      const minTime = parseInt(minExecutionTime);
      slowQueries = slowQueries.filter(query => query.executionTime >= minTime);
    }
    
    // Sort by execution time (descending) and limit
    slowQueries = slowQueries
      .sort((a, b) => b.executionTime - a.executionTime)
      .slice(0, parseInt(limit));

    // Add analysis for each slow query
    const analyzedQueries = slowQueries.map(query => ({
      ...query,
      hybridIndexAnalysis: performanceMonitor.analyzeHybridIndexUsage(query.filter),
      indexPattern: performanceMonitor.detectIndexPattern(query.filter)
    }));

    res.json({
      slowQueries: analyzedQueries,
      summary: {
        total: performanceMonitor.metrics.slowQueries.length,
        filtered: analyzedQueries.length,
        avgExecutionTime: analyzedQueries.length > 0 
          ? analyzedQueries.reduce((sum, q) => sum + q.executionTime, 0) / analyzedQueries.length 
          : 0
      },
      filters: {
        collection,
        minExecutionTime,
        limit: parseInt(limit)
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting slow queries:', error);
    res.status(500).json({
      error: 'Failed to get slow queries analysis',
      code: 'SLOW_QUERIES_ERROR'
    });
  }
});

// Get hybrid index analysis
router.get('/performance/hybrid-indexes', async (req, res) => {
  try {
    if (!performanceMonitor) {
      return res.status(503).json({
        error: 'Performance monitoring not initialized'
      });
    }

    const hybridEfficiency = performanceMonitor.calculateHybridIndexEfficiency();
    const indexesInfo = Array.from(performanceMonitor.metrics.indexes.entries());
    
    // Analyze query patterns by hybrid index type
    const queryPatterns = {};
    for (const [signature, queryData] of performanceMonitor.metrics.queries.entries()) {
      if (queryData.hybridIndexUsage && queryData.hybridIndexUsage.type !== 'none') {
        const type = queryData.hybridIndexUsage.type;
        if (!queryPatterns[type]) {
          queryPatterns[type] = {
            queries: 0,
            totalTime: 0,
            avgTime: 0,
            efficiency: 0,
            examples: []
          };
        }
        
        queryPatterns[type].queries += queryData.count;
        queryPatterns[type].totalTime += queryData.totalTime;
        queryPatterns[type].avgTime = queryData.avgTime;
        queryPatterns[type].efficiency = queryData.hybridIndexUsage.efficiency;
        
        if (queryPatterns[type].examples.length < 3) {
          queryPatterns[type].examples.push({
            collection: queryData.collection,
            operation: queryData.operation,
            avgTime: queryData.avgTime,
            count: queryData.count
          });
        }
      }
    }

    res.json({
      hybridIndexEfficiency,
      indexes: indexesInfo.map(([collection, data]) => ({
        collection,
        indexCount: data.indexes.length,
        indexes: data.indexes,
        lastAnalyzed: data.lastAnalyzed
      })),
      queryPatterns,
      recommendations: performanceMonitor.generatePerformanceRecommendations()
        .filter(rec => rec.type.includes('index') || rec.type.includes('hybrid')),
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting hybrid index analysis:', error);
    res.status(500).json({
      error: 'Failed to get hybrid index analysis',
      code: 'HYBRID_INDEX_ERROR'
    });
  }
});

// Get active performance alerts
router.get('/performance/alerts', async (req, res) => {
  try {
    if (!realTimeMetrics) {
      return res.status(503).json({
        error: 'Real-time metrics not initialized'
      });
    }

    const { includeHistory = false, severity } = req.query;
    
    let activeAlerts = Array.from(realTimeMetrics.activeAlerts.values());
    
    // Filter by severity if specified
    if (severity) {
      activeAlerts = activeAlerts.filter(alert => alert.severity === severity);
    }
    
    let alertHistory = [];
    if (includeHistory === 'true') {
      alertHistory = realTimeMetrics.alertHistory
        .slice(-100) // Last 100 historical alerts
        .sort((a, b) => new Date(b.lastTriggered) - new Date(a.lastTriggered));
    }

    res.json({
      activeAlerts,
      alertHistory,
      summary: {
        total: activeAlerts.length,
        bySeverity: {
          high: activeAlerts.filter(a => a.severity === 'high').length,
          medium: activeAlerts.filter(a => a.severity === 'medium').length,
          low: activeAlerts.filter(a => a.severity === 'low').length
        },
        oldestActive: activeAlerts.length > 0 
          ? Math.min(...activeAlerts.map(a => new Date(a.firstTriggered).getTime()))
          : null
      },
      thresholds: realTimeMetrics.config.alertThresholds,
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error getting performance alerts:', error);
    res.status(500).json({
      error: 'Failed to get performance alerts',
      code: 'PERFORMANCE_ALERTS_ERROR'
    });
  }
});

// Start/stop performance monitoring
router.post('/performance/control', createAdminBodyParser(), async (req, res) => {
  try {
    const { action, config } = req.body;

    if (!performanceMonitor || !realTimeMetrics) {
      return res.status(503).json({
        error: 'Performance monitoring not initialized'
      });
    }

    switch (action) {
      case 'start':
        if (!performanceMonitor.isMonitoring) {
          await performanceMonitor.startMonitoring();
        }
        if (!realTimeMetrics.isCollecting) {
          realTimeMetrics.startCollection();
        }
        break;

      case 'stop':
        if (performanceMonitor.isMonitoring) {
          performanceMonitor.stopMonitoring();
        }
        if (realTimeMetrics.isCollecting) {
          realTimeMetrics.stopCollection();
        }
        break;

      case 'restart':
        performanceMonitor.stopMonitoring();
        realTimeMetrics.stopCollection();
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        await performanceMonitor.startMonitoring();
        realTimeMetrics.startCollection();
        break;

      case 'reset':
        performanceMonitor.resetMetrics();
        realTimeMetrics.resetMetrics();
        break;

      default:
        return res.status(400).json({
          error: 'Invalid action. Use: start, stop, restart, or reset'
        });
    }

    res.json({
      success: true,
      action,
      status: {
        dbMonitoring: performanceMonitor.isMonitoring,
        realtimeCollection: realTimeMetrics.isCollecting
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error controlling performance monitoring:', error);
    res.status(500).json({
      error: 'Failed to control performance monitoring',
      code: 'PERFORMANCE_CONTROL_ERROR'
    });
  }
});

// Update performance monitoring configuration
router.put('/performance/config', createAdminBodyParser(), async (req, res) => {
  try {
    if (!performanceMonitor || !realTimeMetrics) {
      return res.status(503).json({
        error: 'Performance monitoring not initialized'
      });
    }

    const { dbMonitorConfig, realTimeConfig } = req.body;
    
    let updated = {};

    // Update DB monitor config
    if (dbMonitorConfig) {
      const allowedKeys = [
        'slowQueryThreshold',
        'sampleRate',
        'enableProfiling',
        'enableExplainAnalysis',
        'maxMetricsBuffer'
      ];
      
      const filteredConfig = {};
      allowedKeys.forEach(key => {
        if (dbMonitorConfig[key] !== undefined) {
          filteredConfig[key] = dbMonitorConfig[key];
        }
      });

      performanceMonitor.config = { ...performanceMonitor.config, ...filteredConfig };
      updated.dbMonitor = filteredConfig;
    }

    // Update real-time metrics config
    if (realTimeConfig) {
      const allowedKeys = [
        'windowSize',
        'updateInterval',
        'alertThresholds',
        'retainWindows'
      ];
      
      const filteredConfig = {};
      allowedKeys.forEach(key => {
        if (realTimeConfig[key] !== undefined) {
          filteredConfig[key] = realTimeConfig[key];
        }
      });

      realTimeMetrics.config = { ...realTimeMetrics.config, ...filteredConfig };
      updated.realTimeMetrics = filteredConfig;
    }

    res.json({
      success: true,
      updated,
      currentConfig: {
        dbMonitor: performanceMonitor.config,
        realTimeMetrics: realTimeMetrics.config
      },
      timestamp: new Date()
    });

  } catch (error) {
    console.error('❌ Error updating performance config:', error);
    res.status(500).json({
      error: 'Failed to update performance configuration',
      code: 'PERFORMANCE_CONFIG_ERROR'
    });
  }
});

// Export performance data
router.get('/performance/export', async (req, res) => {
  try {
    if (!performanceMonitor || !realTimeMetrics) {
      return res.status(503).json({
        error: 'Performance monitoring not initialized'
      });
    }

    const { format = 'json', includeRawData = false } = req.query;
    
    const exportData = {
      metadata: {
        exportDate: new Date(),
        version: '1.0',
        nodeVersion: process.version,
        uptime: process.uptime()
      },
      summary: performanceMonitor.getPerformanceSummary(),
      realtimeMetrics: realTimeMetrics.getCurrentStats(),
      configuration: {
        dbMonitor: performanceMonitor.config,
        realTimeMetrics: realTimeMetrics.config
      }
    };

    if (includeRawData === 'true') {
      exportData.rawData = {
        dbPerformance: performanceMonitor.exportPerformanceData(),
        realTimeMetrics: realTimeMetrics.exportMetricsData()
      };
    }

    if (format === 'json') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="performance-export-${Date.now()}.json"`);
      res.json(exportData);
    } else {
      res.status(400).json({
        error: 'Unsupported export format. Use: json'
      });
    }

  } catch (error) {
    console.error('❌ Error exporting performance data:', error);
    res.status(500).json({
      error: 'Failed to export performance data',
      code: 'PERFORMANCE_EXPORT_ERROR'
    });
  }
});

module.exports = router;
