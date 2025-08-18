// routes/dashboardRoutes.js
// Universal dashboard routes accessible to all authenticated users with role-based data filtering

const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const Response = require('../models/Response');
const User = require('../models/User');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtectionStrict, csrfTokenEndpoint } = require('../middleware/csrf');
const { normalizeQuestion } = require('../utils/questionNormalizer');
const { createQuerySanitizationMiddleware, sanitizeMongoInput, sanitizeObjectId } = require('../middleware/querySanitization');
const { requireAdminAccess, requireDashboardAccess } = require('../middleware/hybridAuth');

// Configuration constants
const PIE_CHART_QUESTION = process.env.PIE_CHART_QUESTION || "En rapide, comment ça va ?";

// Apply dashboard-specific middleware
router.use(createAdminBodyParser());
router.use(createQuerySanitizationMiddleware());

// Helper function to determine user's data access level
function getUserDataAccess(req) {
  // Admin users get full access
  if (req.authMethod === 'legacy-admin' || req.currentUser?.role === 'admin') {
    return {
      level: 'admin',
      canViewAll: true,
      canManage: true,
      userId: req.currentUser?.id || null
    };
  }
  
  // Regular users get limited access to their own data
  if (req.authMethod === 'user' && req.currentUser) {
    return {
      level: 'user',
      canViewAll: false,
      canManage: false,
      userId: req.currentUser.id
    };
  }
  
  return {
    level: 'none',
    canViewAll: false,
    canManage: false,
    userId: null
  };
}

// Helper function to create user-specific data filter
function createUserDataFilter(req, baseFilter = {}) {
  const access = getUserDataAccess(req);
  
  if (access.level === 'admin') {
    // Admins see all data
    return baseFilter;
  } else if (access.level === 'user') {
    // Users only see their own submissions
    return {
      ...baseFilter,
      userId: access.userId
    };
  }
  
  // No access
  return { _id: { $exists: false } }; // Returns no results
}

// CSRF token endpoint
router.get('/csrf-token', csrfTokenEndpoint());

// Get user profile and role information
router.get('/profile', (req, res) => {
  try {
    const access = getUserDataAccess(req);
    
    const profile = {
      authMethod: req.authMethod,
      accessLevel: access.level,
      permissions: {
        canViewAll: access.canViewAll,
        canManage: access.canManage,
        canViewAdminFeatures: access.level === 'admin'
      }
    };
    
    // Add user-specific information if available
    if (req.currentUser) {
      profile.user = {
        id: req.currentUser.id,
        username: req.currentUser.username,
        email: req.currentUser.email,
        role: req.currentUser.role,
        displayName: req.currentUser.displayName || req.currentUser.username
      };
    }
    
    res.json(profile);
  } catch (error) {
    console.error('Error getting user profile:', error);
    res.status(500).json({ 
      error: 'Failed to get user profile',
      code: 'PROFILE_ERROR'
    });
  }
});

// Get months with role-based filtering
router.get('/months', async (req, res) => {
  try {
    const access = getUserDataAccess(req);
    const matchFilter = createUserDataFilter(req);
    
    const pipeline = [
      { $match: matchFilter },
      { $project: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } } },
      { $group: { _id: { y: '$year', m: '$month' } } },
      { $sort: { '_id.y': -1, '_id.m': -1 } },
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
  } catch (error) {
    console.error('Error getting months:', error);
    res.status(500).json({ 
      error: 'Erreur serveur lors de la récupération des mois', 
      code: 'SERVER_ERROR' 
    });
  }
});

// Get summary data with role-based filtering
router.get('/summary', async (req, res) => {
  try {
    const access = getUserDataAccess(req);
    
    // Build base match filter with user restrictions
    let match = createUserDataFilter(req);
    
    // Add month filter if specified
    if (req.query.month && req.query.month !== 'all') {
      const [y, m] = req.query.month.split('-').map(n => parseInt(n, 10));
      match.createdAt = {
        $gte: new Date(y, m - 1, 1),
        $lt: new Date(y, m, 1)
      };
    }

    const PIE_Q = PIE_CHART_QUESTION;
    
    // For regular users, provide limited summary data
    if (access.level === 'user') {
      // Users only see their own responses summary
      const userResponses = await Response.find(match)
        .select('responses month createdAt')
        .sort({ createdAt: -1 })
        .lean();
      
      if (userResponses.length === 0) {
        return res.json([]);
      }
      
      // Create user-specific summary
      const userSummary = [];
      const questionMap = new Map();
      
      userResponses.forEach(doc => {
        doc.responses.forEach(r => {
          if (r.question && r.answer) {
            const question = r.question;
            if (!questionMap.has(question)) {
              questionMap.set(question, {
                question,
                items: []
              });
            }
            questionMap.get(question).items.push({
              user: 'Moi', // Always show as "Me" for user's own data
              answer: r.answer
            });
          }
        });
      });
      
      const summary = Array.from(questionMap.values());
      
      // Sort to put PIE_Q first if it exists
      summary.sort((a, b) => {
        if (a.question === PIE_Q) return -1;
        if (b.question === PIE_Q) return 1;
        return 0;
      });
      
      return res.json(summary);
    }
    
    // Admin users get full summary (existing admin logic)
    const piePipeline = [
      { $match: match },
      { $unwind: '$responses' },
      { $match: { 'responses.question': PIE_Q } },
      { $group: {
          _id: '$responses.question',
          items: { $push: { user: '$name', answer: '$responses.answer' } }
      }},
      { $project: {
          _id: 0,
          question: '$_id',
          items: 1
      }}
    ];
    
    const pieSummary = await mongoose.connection.db
      .collection('responses')
      .aggregate(piePipeline, { allowDiskUse: true })
      .toArray();

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

    // Question deduplication for admin view
    const textMap = {};
    const questionNormalizedMap = {};
    
    rawTextSummary.forEach(({ question, items }) => {
      const normalizedQ = normalizeQuestion(question);
      
      if (!normalizedQ) {
        console.warn('⚠️ Question vide ignorée:', question);
        return;
      }
      
      if (!questionNormalizedMap[normalizedQ]) {
        questionNormalizedMap[normalizedQ] = question;
      }
      
      const canonicalQ = questionNormalizedMap[normalizedQ];
      textMap[canonicalQ] = textMap[canonicalQ] || [];
      textMap[canonicalQ].push(...items);
    });
    
    const textSummary = Object.entries(textMap)
      .map(([question, items]) => ({ question, items }));

    const allSummary = [...pieSummary, ...textSummary];
    
    // Simple ordering: PIE_Q first, then alphabetical
    const sortedSummary = allSummary.sort((a, b) => {
      if (a.question === PIE_Q) return -1;
      if (b.question === PIE_Q) return 1;
      return a.question.localeCompare(b.question);
    });

    res.json(sortedSummary);
  } catch (error) {
    console.error('Error getting summary:', error);
    res.status(500).json({ 
      error: 'Erreur serveur lors de la génération du résumé', 
      code: 'SERVER_ERROR' 
    });
  }
});

// Get dashboard statistics
router.get('/stats', async (req, res) => {
  try {
    const access = getUserDataAccess(req);
    const matchFilter = createUserDataFilter(req);
    
    if (access.level === 'user') {
      // User-specific statistics
      const userResponses = await Response.countDocuments(matchFilter);
      const latestResponse = await Response.findOne(matchFilter)
        .sort({ createdAt: -1 })
        .select('createdAt month')
        .lean();
      
      const stats = {
        totalResponses: userResponses,
        latestSubmission: latestResponse?.createdAt || null,
        latestMonth: latestResponse?.month || null,
        userRole: 'user'
      };
      
      res.json(stats);
    } else if (access.level === 'admin') {
      // Admin statistics - full system stats
      const totalResponses = await Response.countDocuments({});
      const totalUsers = await User.countDocuments({ 'metadata.isActive': true });
      const thisMonth = new Date().toISOString().slice(0, 7);
      const thisMonthResponses = await Response.countDocuments({
        month: thisMonth
      });
      
      const stats = {
        totalResponses,
        totalUsers,
        thisMonthResponses,
        userRole: 'admin'
      };
      
      res.json(stats);
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  } catch (error) {
    console.error('Error getting dashboard stats:', error);
    res.status(500).json({ 
      error: 'Failed to get dashboard statistics',
      code: 'STATS_ERROR'
    });
  }
});

// Admin-only routes - forward to existing admin routes with proper access control
router.use('/admin', requireAdminAccess, (req, res, next) => {
  // Forward to admin routes for admin-specific functionality
  next();
});

module.exports = router;