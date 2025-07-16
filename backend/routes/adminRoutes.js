// routes/adminRoutes.js
const express  = require('express');
const router   = express.Router();
const Response = require('../models/Response');

// Middleware : charge la réponse dans req.responseDoc
router.param('id', async (req, res, next, id) => {
  try {
    const doc = await Response.findById(id);
    if (!doc) return res.status(404).json({ message: 'Réponse non trouvée' });
    req.responseDoc = doc;
    next();
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/responses?page=1&limit=10
// Pour l’UI de gestion paginée
router.get('/responses', async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.min(20, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const skip  = (page - 1) * limit;

    const totalCount = await Response.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);

    const data = await Response.find()
      .select('name createdAt')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    res.json({
      responses:  data,
      pagination: { page, totalPages, totalCount }
    });
  } catch (err) {
    console.error('❌ Erreur pagination /responses :', err);
    res.status(500).json({ message: 'Erreur serveur pagination' });
  }
});

// GET & DELETE /api/admin/responses/:id
router.route('/responses/:id')
  .get((req, res) => {
    res.json(req.responseDoc);
  })
  .delete(async (req, res) => {
    try {
      await req.responseDoc.deleteOne();
      res.json({ message: 'Réponse supprimée avec succès' });
    } catch (err) {
      console.error('❌ Erreur suppression /responses/:id :', err);
      res.status(500).json({ message: 'Erreur serveur suppression' });
    }
  });

// GET /api/admin/summary?month=YYYY-MM
// Résumé pour l’UI graphique (camembert + listes)
router.get('/summary', async (req, res) => {
  try {
    // Filtre optionnel par mois (format "YYYY-MM")
    const match = {};
    if (req.query.month && req.query.month !== 'all') {
      const [year, month] = req.query.month.split('-').map(n => parseInt(n, 10));
      match.createdAt = {
        $gte: new Date(year, month - 1, 1),
        $lt:  new Date(year, month,     1)
      };
    }

    const pipeline = [
      { $match: match },
      { $unwind: '$responses' },
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

    // Ajout de allowDiskUse pour éviter l’erreur mémoire
    const summary = await Response.aggregate(pipeline)
                                 .allowDiskUse(true)
                                 .exec();

    res.json(summary);
  } catch (err) {
    console.error('❌ Erreur summary :', err);
    res.status(500).json({ message: 'Erreur serveur summary' });
  }
});

// GET /api/admin/months
// Liste des mois disponibles pour le filtre
router.get('/months', async (req, res) => {
  try {
    const pipeline = [
      { $project: { year: { $year: '$createdAt' }, month: { $month: '$createdAt' } } },
      { $group:   { _id: { y: '$year', m: '$month' } } },
      { $sort:    { '_id.y': -1, '_id.m': -1 } },
      { $project: {
          _id:   0,
          key:   {
            $concat: [
              { $toString: '$_id.y' }, '-',
              { $cond: [ { $lt: ['$_id.m', 10] },
                        { $concat: ['0', { $toString: '$_id.m' }] },
                        { $toString: '$_id.m' } ] }
            ]
          },
          label: {
            $concat: [
              { $arrayElemAt: [ [
                "janvier","février","mars","avril","mai","juin",
                "juillet","août","septembre","octobre","novembre","décembre"
              ], { $subtract: ['$_id.m', 1] } ] },
              ' ',
              { $toString: '$_id.y' }
            ]
          }
      }}
    ];

    // allowDiskUse pour ce gros pipeline
    const months = await Response.aggregate(pipeline)
                                 .allowDiskUse(true)
                                 .exec();

    res.json(months);
  } catch (err) {
    console.error('❌ Erreur months :', err);
    res.status(500).json({ message: 'Erreur serveur months' });
  }
});

module.exports = router;