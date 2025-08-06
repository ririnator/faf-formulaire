// routes/adminRoutes.js
const express  = require('express');
const mongoose = require('mongoose');
const router   = express.Router();
const Response = require('../models/Response');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtection, csrfTokenEndpoint } = require('../middleware/csrf');
const { normalizeQuestion } = require('../utils/questionNormalizer');

// Configuration constants
const PIE_CHART_QUESTION = process.env.PIE_CHART_QUESTION || "En rapide, comment ça va ?";

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

    // Construction du filtre de recherche avec protection ReDoS
    let filter = {};
    if (search) {
      // Échapper les caractères spéciaux regex pour éviter ReDoS
      const escapeRegex = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const escapedSearch = escapeRegex(search);
      filter.name = { $regex: escapedSearch, $options: 'i' };
    }

    const totalCount = await Response.countDocuments(filter);
    const totalPages = Math.ceil(totalCount / limit);

    const data = await Response.find(filter)
      .select('name month createdAt isAdmin token')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

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

// GET /api/admin/summary?month=YYYY-MM
// inchangé
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

    // Note: normalizeQuestion est maintenant importée du module utils/questionNormalizer

    // Regrouper questions similaires après aggregation (plus efficace)
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

    // Get question order from first submission in the period
    let questionOrder = [];
    if (pieSummary.length > 0) {
      questionOrder.push(PIE_Q); // Pie chart question first
    }
    
    // Find the oldest response in the period to get natural question order
    const firstResponse = await Response.findOne(match).sort({ createdAt: 1 });
    if (firstResponse) {
      firstResponse.responses.forEach(r => {
        if (r.question && r.question !== PIE_Q) {
          const normalized = normalizeQuestion(r.question);
          // Add question if not already in order (avoid duplicates)
          const alreadyExists = questionOrder.some(q => normalizeQuestion(q) === normalized);
          if (!alreadyExists) {
            questionOrder.push(r.question);
          }
        }
      });
    }

    // Combine all summary data
    const allSummary = [...pieSummary, ...textSummary];
    
    // Sort according to natural question order from first submission
    const sortedSummary = allSummary.sort((a, b) => {
      const normalizedA = normalizeQuestion(a.question);
      const normalizedB = normalizeQuestion(b.question);
      
      // Find index in natural question order
      let indexA = questionOrder.findIndex(q => normalizeQuestion(q) === normalizedA);
      let indexB = questionOrder.findIndex(q => normalizeQuestion(q) === normalizedB);
      
      // If question not found in order, put at end
      if (indexA === -1) indexA = questionOrder.length;
      if (indexB === -1) indexB = questionOrder.length;
      
      return indexA - indexB;
    });

    // Debug pour vérifier l'ordre (dev uniquement)
    if (process.env.NODE_ENV === 'development' && !process.env.RENDER) {
      console.log('📋 Ordre des questions basé sur première soumission:');
      questionOrder.forEach((q, i) => {
        const shortQ = q.substring(0, 50) + (q.length > 50 ? '...' : '');
        console.log(`  ${i + 1}. ${shortQ}`);
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

module.exports = router;
