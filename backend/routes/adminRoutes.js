// routes/adminRoutes.js
const express  = require('express');
const mongoose = require('mongoose');
const router   = express.Router();
const Response = require('../models/Response');
const { createAdminBodyParser } = require('../middleware/bodyParser');
const { csrfProtection, csrfTokenEndpoint } = require('../middleware/csrf');

// Apply admin-specific body parser (1MB limit) to all admin routes
router.use(createAdminBodyParser());

// Endpoint pour récupérer le token CSRF
router.get('/csrf-token', csrfTokenEndpoint());

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

    const PIE_Q = "En rapide, comment ça va ?";
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

    const docs = await Response.find(match)
      .select('name responses.question responses.answer')
      .lean();

    const textMap = {};
    docs.forEach(doc => {
      doc.responses.forEach(r => {
        if (r.question === PIE_Q) return;
        textMap[r.question] = textMap[r.question] || [];
        textMap[r.question].push({ user: doc.name, answer: r.answer });
      });
    });
    const textSummary = Object.entries(textMap)
      .map(([question, items]) => ({ question, items }));

    res.json([ ...pieSummary, ...textSummary ]);
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
