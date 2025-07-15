const express = require('express');
const router  = express.Router();
const Response = require('../models/Response');

// Middleware pour charger la réponse dans req.responseDoc
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
router.get('/responses', async (req, res) => {
  try {
    // Récupère et normalise les paramètres
    const page  = Math.max(1, parseInt(req.query.page, 10)  || 1);
    const limit = Math.max(1, parseInt(req.query.limit, 10) || 10);
    const skip  = (page - 1) * limit;

    // Comptage total pour pagination
    const totalCount = await Response.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);

      // Requête paginée avec allowDiskUse pour éviter le dépassement mémoire
      const data = await Response.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();
    // Renvoie dans le shape attendu par ton front
    res.json({
      responses: data,
      pagination: { page, totalPages, totalCount }
    });
  } catch (err) {
    console.error('❌ Erreur serveur pagination :', err);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});


// GET /api/admin/responses/:id et DELETE /api/admin/responses/:id
router.route('/responses/:id')
  .get((req, res) => {
    res.json(req.responseDoc);
  })
  .delete(async (req, res) => {
    try {
      await req.responseDoc.deleteOne();
      res.json({ message: 'Réponse supprimée avec succès' });
    } catch (err) {
      console.error('Erreur en supprimant la réponse :', err);
      res.status(500).json({ message: 'Erreur lors de la suppression' });
    }
  });

// GET /api/admin/summary?month=YYYY-MM
// Renvoie pour chaque question la liste déjà groupée { user, answer }
router.get('/summary', async (req, res) => {
  try {
    // Filtre sur le mois si fourni
    const match = {};
    if (req.query.month) {
      const [y, m] = req.query.month.split('-').map(n => parseInt(n,10));
      match.createdAt = {
        $gte: new Date(y, m-1, 1),
        $lt:  new Date(y, m,   1)
      };
    }

    // Mongo gère le grouping en pipeline
    const summary = await Response.aggregate([
      { $match: match },
      { $unwind: '$responses' },
      { $group: {
         _id: '$responses.question',
         items: { $push: { user:'$name', answer:'$responses.answer' } }
      }},
      { $project: {
         _id:      0,
         question: '$_id',
         items:    1
      }}
    ]).allowDiskUse(true);

    res.json(summary);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message:'Erreur summary' });
  }
});

module.exports = router;
