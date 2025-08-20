// routes/dashboardRoutes.js
// Universal dashboard routes accessible to all authenticated users with role-based data filtering

const express = require('express');
const mongoose = require('mongoose');
const router = express.Router();
const Response = require('../models/Response');
const User = require('../models/User');
const Contact = require('../models/Contact');
const Submission = require('../models/Submission');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtectionStrict, csrfTokenEndpoint } = require('../middleware/csrf');
const { normalizeQuestion } = require('../utils/questionNormalizer');
const { createQuerySanitizationMiddleware, sanitizeMongoInput, sanitizeObjectId } = require('../middleware/querySanitization');
const { requireAdminAccess, requireDashboardAccess, requireUserAuth, detectAuthMethod, enrichUserData } = require('../middleware/hybridAuth');
const { dashboardLimiter } = require('../middleware/rateLimiting');
const ContactService = require('../services/contactService');
const SubmissionService = require('../services/submissionService');

// Configuration constants
const PIE_CHART_QUESTION = process.env.PIE_CHART_QUESTION || "En rapide, comment ça va ?";

// Performance optimization: Universal cache system
const dashboardCache = new Map();
const CACHE_TTLS = {
  months: 30 * 60 * 1000,    // 30 minutes (rarely changes)
  summary: 10 * 60 * 1000,   // 10 minutes (moderate changes)
  stats: 5 * 60 * 1000,      // 5 minutes (frequent changes)
  contacts: 15 * 60 * 1000   // 15 minutes (moderate changes)
};

function getCachedData(type, userId, isAdmin, extra = '') {
  const cacheKey = `${type}_${userId || 'all'}_${isAdmin ? 'admin' : 'user'}_${extra}`;
  const cached = dashboardCache.get(cacheKey);
  
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTLS[type]) {
    return cached.data;
  }
  
  return null;
}

function setCachedData(type, userId, isAdmin, data, extra = '') {
  const cacheKey = `${type}_${userId || 'all'}_${isAdmin ? 'admin' : 'user'}_${extra}`;
  dashboardCache.set(cacheKey, {
    data,
    timestamp: Date.now()
  });
  
  // Prevent memory leaks - limit cache size
  if (dashboardCache.size > 200) {
    const firstKey = dashboardCache.keys().next().value;
    dashboardCache.delete(firstKey);
  }
}

// Legacy functions for backward compatibility
function getCachedMonths(userId, isAdmin) {
  return getCachedData('months', userId, isAdmin);
}

function setCachedMonths(userId, isAdmin, data) {
  setCachedData('months', userId, isAdmin, data);
}

// Cache invalidation function
function invalidateUserCache(userId) {
  const keysToDelete = [];
  for (const [key] of dashboardCache) {
    if (key.includes(`_${userId}_`)) {
      keysToDelete.push(key);
    }
  }
  keysToDelete.forEach(key => dashboardCache.delete(key));
}

// Apply dashboard-specific middleware
router.use(createAdminBodyParser());
router.use(createQuerySanitizationMiddleware());
router.use(detectAuthMethod);
router.use(enrichUserData);
router.use(requireDashboardAccess);

// Rate limiting for dashboard endpoints
router.use(dashboardLimiter);

// Initialize services
const contactService = new ContactService();
const submissionService = new SubmissionService();

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
    
    // Check cache first
    const cachedMonths = getCachedMonths(access.userId, access.level === 'admin');
    if (cachedMonths) {
      return res.json(cachedMonths);
    }
    
    const matchFilter = createUserDataFilter(req);
    
    // Optimized pipeline with early projection
    const pipeline = [
      { $match: matchFilter },
      { $project: { 
          year: { $year: '$createdAt' }, 
          month: { $month: '$createdAt' },
          _id: 0  // Exclude _id early to save memory
      }},
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

    // Use collection with hint for optimal index usage
    const collection = mongoose.connection.db.collection('responses');
    const months = await collection
      .aggregate(pipeline, { 
        allowDiskUse: true,
        hint: { createdAt: -1 }  // Use createdAt index for better performance
      })
      .toArray();

    // Cache the results
    setCachedMonths(access.userId, access.level === 'admin', months);

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
    const month = req.query.month || 'all';
    
    // Check cache first
    const cachedSummary = getCachedData('summary', access.userId, access.level === 'admin', month);
    if (cachedSummary) {
      return res.json(cachedSummary);
    }
    
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
      
      // Cache the user summary
      setCachedData('summary', access.userId, access.level === 'admin', summary, month);
      
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

    // Cache the admin summary
    setCachedData('summary', access.userId, access.level === 'admin', sortedSummary, month);
    
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

// ====================
// NEW DASHBOARD ROUTES
// ====================

// GET /dashboard - Main user dashboard with summary data
router.get('/', async (req, res) => {
  try {
    const access = getUserDataAccess(req);
    
    if (access.level === 'user') {
      // User dashboard with personal summary
      const userId = access.userId;
      const currentMonth = new Date().toISOString().slice(0, 7);
      
      // Get user's submission for current month
      const currentSubmission = await Submission.findOne({
        userId: new mongoose.Types.ObjectId(userId),
        month: currentMonth
      }).lean();
      
      // Get total contacts count
      const totalContacts = await Contact.countDocuments({
        ownerId: new mongoose.Types.ObjectId(userId),
        isActive: true
      });
      
      // Get recent submissions (last 3 months)
      const recentSubmissions = await Submission.find({
        userId: new mongoose.Types.ObjectId(userId)
      })
      .sort({ month: -1 })
      .limit(3)
      .select('month completionRate submittedAt')
      .lean();
      
      // Get contacts with recent activity
      const recentContacts = await Contact.find({
        ownerId: new mongoose.Types.ObjectId(userId),
        'tracking.lastInteractionAt': { $exists: true }
      })
      .sort({ 'tracking.lastInteractionAt': -1 })
      .limit(5)
      .select('firstName lastName email tracking')
      .lean();
      
      const dashboardData = {
        user: {
          username: req.currentUser.username,
          email: req.currentUser.email,
          role: req.currentUser.role
        },
        currentMonth: {
          month: currentMonth,
          hasSubmitted: !!currentSubmission,
          submission: currentSubmission ? {
            completionRate: currentSubmission.completionRate,
            submittedAt: currentSubmission.submittedAt
          } : null
        },
        stats: {
          totalContacts,
          totalSubmissions: recentSubmissions.length,
          averageCompletion: recentSubmissions.length > 0 ? 
            Math.round(recentSubmissions.reduce((sum, s) => sum + s.completionRate, 0) / recentSubmissions.length) : 0
        },
        recentActivity: {
          submissions: recentSubmissions,
          contacts: recentContacts
        }
      };
      
      res.json(dashboardData);
    } else if (access.level === 'admin') {
      // Admin dashboard with system overview
      const currentMonth = new Date().toISOString().slice(0, 7);
      
      const [totalUsers, totalSubmissions, thisMonthSubmissions, totalContacts] = await Promise.all([
        User.countDocuments({ 'metadata.isActive': true }),
        Submission.countDocuments({}),
        Submission.countDocuments({ month: currentMonth }),
        Contact.countDocuments({ isActive: true })
      ]);
      
      const dashboardData = {
        user: {
          username: 'Admin',
          role: 'admin'
        },
        currentMonth: {
          month: currentMonth
        },
        systemStats: {
          totalUsers,
          totalSubmissions,
          thisMonthSubmissions,
          totalContacts,
          submissionRate: totalUsers > 0 ? Math.round((thisMonthSubmissions / totalUsers) * 100) : 0
        }
      };
      
      res.json(dashboardData);
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  } catch (error) {
    console.error('Error loading dashboard:', error);
    res.status(500).json({ 
      error: 'Failed to load dashboard',
      code: 'DASHBOARD_ERROR'
    });
  }
});

// GET /dashboard/contacts - Contact management interface
router.get('/contacts', requireUserAuth, async (req, res) => {
  try {
    const userId = req.currentUser.id;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
    const skip = (page - 1) * limit;
    const search = req.query.search?.trim();
    const status = req.query.status;
    
    // Build filter
    let filter = {
      ownerId: new mongoose.Types.ObjectId(userId)
    };
    
    if (search) {
      filter.$or = [
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status && ['active', 'pending', 'opted_out', 'bounced'].includes(status)) {
      filter.status = status;
    }
    
    const [contacts, totalCount] = await Promise.all([
      Contact.find(filter)
        .sort({ 'tracking.lastInteractionAt': -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .select('firstName lastName email status tracking emailStatus isActive optedOut tags')
        .lean(),
      Contact.countDocuments(filter)
    ]);
    
    // Enhanced contact data with response status
    const currentMonth = new Date().toISOString().slice(0, 7);
    const contactsWithStatus = contacts.map(contact => {
      return {
        id: contact._id,
        firstName: contact.firstName,
        lastName: contact.lastName,
        email: contact.email,
        status: contact.status,
        emailStatus: contact.emailStatus,
        isActive: contact.isActive,
        optedOut: contact.optedOut,
        tags: contact.tags || [],
        tracking: {
          responsesReceived: contact.tracking?.responsesReceived || 0,
          responseRate: contact.tracking?.responseRate || 0,
          lastInteractionAt: contact.tracking?.lastInteractionAt,
          lastSentAt: contact.tracking?.lastSentAt
        },
        canReceiveInvitation: contact.status === 'active' && contact.isActive && !contact.optedOut
      };
    });
    
    res.json({
      contacts: contactsWithStatus,
      pagination: {
        page,
        limit,
        total: totalCount,
        pages: Math.ceil(totalCount / limit)
      },
      summary: {
        total: totalCount,
        active: contacts.filter(c => c.status === 'active').length,
        pending: contacts.filter(c => c.status === 'pending').length,
        optedOut: contacts.filter(c => c.optedOut).length
      }
    });
  } catch (error) {
    console.error('Error loading contacts:', error);
    res.status(500).json({ 
      error: 'Failed to load contacts',
      code: 'CONTACTS_ERROR'
    });
  }
});

// GET /dashboard/responses - Response history and form access
router.get('/responses', requireUserAuth, async (req, res) => {
  try {
    const userId = req.currentUser.id;
    const currentMonth = new Date().toISOString().slice(0, 7);
    
    // Get user's submission history
    const submissions = await Submission.find({
      userId: new mongoose.Types.ObjectId(userId)
    })
    .sort({ month: -1 })
    .select('month completionRate submittedAt responses freeText')
    .lean();
    
    // Check if current month form is available
    const currentSubmission = submissions.find(s => s.month === currentMonth);
    const canSubmitThisMonth = !currentSubmission;
    
    // Process submissions for response
    const submissionHistory = submissions.map(submission => ({
      month: submission.month,
      completionRate: submission.completionRate,
      submittedAt: submission.submittedAt,
      responseCount: submission.responses?.length || 0,
      hasFreeText: !!submission.freeText?.trim()
    }));
    
    // Get monthly stats
    const stats = {
      totalSubmissions: submissions.length,
      averageCompletion: submissions.length > 0 ? 
        Math.round(submissions.reduce((sum, s) => sum + s.completionRate, 0) / submissions.length) : 0,
      bestMonth: submissions.length > 0 ? 
        submissions.reduce((best, current) => 
          current.completionRate > (best?.completionRate || 0) ? current : best
        ) : null
    };
    
    res.json({
      currentMonth: {
        month: currentMonth,
        canSubmit: canSubmitThisMonth,
        hasSubmitted: !!currentSubmission,
        submission: currentSubmission ? {
          completionRate: currentSubmission.completionRate,
          submittedAt: currentSubmission.submittedAt
        } : null
      },
      history: submissionHistory,
      stats
    });
  } catch (error) {
    console.error('Error loading responses:', error);
    res.status(500).json({ 
      error: 'Failed to load responses',
      code: 'RESPONSES_ERROR'
    });
  }
});

// GET /responses/current - Get current month status  
router.get('/responses/current', requireUserAuth, async (req, res) => {
  try {
    const userId = req.currentUser.id;
    const currentMonth = new Date().toISOString().slice(0, 7);
    
    // Check if user has submitted for current month
    const currentSubmission = await Submission.findOne({
      userId: new mongoose.Types.ObjectId(userId),
      month: currentMonth
    }).lean();
    
    res.json({
      month: currentMonth,
      hasSubmitted: !!currentSubmission,
      submission: currentSubmission ? {
        completionRate: currentSubmission.completionRate,
        submittedAt: currentSubmission.submittedAt,
        responseCount: currentSubmission.responses?.length || 0
      } : null
    });
  } catch (error) {
    console.error('Error getting current month status:', error);
    res.status(500).json({ 
      error: 'Failed to get current month status',
      code: 'CURRENT_STATUS_ERROR'
    });
  }
});

// GET /dashboard/contact/:id - Individual contact 1-vs-1 view
router.get('/contact/:id', requireUserAuth, async (req, res) => {
  try {
    const userId = req.currentUser.id;
    const contactId = sanitizeObjectId(req.params.id);
    
    if (!contactId) {
      return res.status(400).json({ error: 'Invalid contact ID' });
    }
    
    // Get contact with ownership verification
    const contact = await Contact.findOne({
      _id: new mongoose.Types.ObjectId(contactId),
      ownerId: new mongoose.Types.ObjectId(userId)
    }).lean();
    
    if (!contact) {
      return res.status(404).json({ error: 'Contact not found' });
    }
    
    // Optimized: Use single $facet aggregation to get both user and contact submissions
    const submissionPipeline = [
      {
        $match: {
          userId: { 
            $in: contact.contactUserId 
              ? [new mongoose.Types.ObjectId(userId), contact.contactUserId]
              : [new mongoose.Types.ObjectId(userId)]
          }
        }
      },
      {
        $facet: {
          userSubmissions: [
            { $match: { userId: new mongoose.Types.ObjectId(userId) } },
            { $sort: { month: -1 } },
            { $project: { month: 1, responses: 1, freeText: 1, submittedAt: 1, completionRate: 1 } }
          ],
          contactSubmissions: contact.contactUserId ? [
            { $match: { userId: contact.contactUserId } },
            { $sort: { month: -1 } },
            { $project: { month: 1, responses: 1, freeText: 1, submittedAt: 1, completionRate: 1 } }
          ] : []
        }
      }
    ];
    
    const [result] = await Submission.aggregate(submissionPipeline);
    const userSubmissions = result.userSubmissions || [];
    const contactSubmissions = result.contactSubmissions || [];
    
    // Create comparison data
    const comparisonData = [];
    const allMonths = new Set([...userSubmissions.map(s => s.month), ...contactSubmissions.map(s => s.month)]);
    
    for (const month of Array.from(allMonths).sort().reverse()) {
      const userSub = userSubmissions.find(s => s.month === month);
      const contactSub = contactSubmissions.find(s => s.month === month);
      
      comparisonData.push({
        month,
        user: userSub ? {
          submitted: true,
          completionRate: userSub.completionRate,
          responseCount: userSub.responses?.length || 0,
          submittedAt: userSub.submittedAt
        } : { submitted: false },
        contact: contactSub ? {
          submitted: true,
          completionRate: contactSub.completionRate,
          responseCount: contactSub.responses?.length || 0,
          submittedAt: contactSub.submittedAt
        } : { submitted: false }
      });
    }
    
    // Enhanced contact info
    const contactInfo = {
      id: contact._id,
      firstName: contact.firstName,
      lastName: contact.lastName,
      email: contact.email,
      status: contact.status,
      hasUserAccount: !!contact.contactUserId,
      tracking: {
        responsesReceived: contact.tracking?.responsesReceived || 0,
        responseRate: contact.tracking?.responseRate || 0,
        averageResponseTime: contact.tracking?.averageResponseTime,
        lastInteractionAt: contact.tracking?.lastInteractionAt,
        firstResponseAt: contact.tracking?.firstResponseAt
      },
      tags: contact.tags || [],
      notes: contact.notes
    };
    
    res.json({
      contact: contactInfo,
      comparison: comparisonData,
      stats: {
        totalSharedMonths: comparisonData.filter(m => m.user.submitted && m.contact.submitted).length,
        userSubmissions: userSubmissions.length,
        contactSubmissions: contactSubmissions.length
      }
    });
  } catch (error) {
    console.error('Error loading contact comparison:', error);
    res.status(500).json({ 
      error: 'Failed to load contact comparison',
      code: 'CONTACT_COMPARISON_ERROR'
    });
  }
});

// Admin-only routes - forward to existing admin routes with proper access control
router.use('/admin', requireAdminAccess, (req, res, next) => {
  // Forward to admin routes for admin-specific functionality
  next();
});

module.exports = router;