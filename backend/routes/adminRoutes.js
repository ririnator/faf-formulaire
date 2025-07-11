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

// GET /api/admin/responses?page=1&limit=10&month=YYYY-MM
router.get('/responses', async (req, res) => {
  try {
    // Pagination
    const pageRaw  = parseInt(req.query.page,  10);
    const limitRaw = parseInt(req.query.limit, 10);
    const page  = Number.isInteger(pageRaw)  && pageRaw  > 0 ? pageRaw  : 1;
    const limit = Number.isInteger(limitRaw) && limitRaw > 0 ? Math.min(20, limitRaw) : 10;
    const skip  = (page - 1) * limit;

    // Filtre optionnel par mois (format "2025-06")
    const filter = {};
    if (req.query.month) {
      const [year, month] = req.query.month.split('-').map(n => parseInt(n, 10));
      if (Number.isInteger(year) && Number.isInteger(month)) {
        filter.createdAt = {
          $gte: new Date(year, month - 1, 1),
          $lt:  new Date(year, month, 1)
        };
      }
    }

    // Comptage et pagination
    const totalCount = await Response.countDocuments(filter);
    const totalPages = Math.ceil(totalCount / limit);

    // Requête paginée, uniquement name + createdAt pour alléger
    const data = await Response.find(filter)
      .select('name createdAt')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    return res.json({
      responses:  data,
      pagination: { page, totalPages, totalCount }
    });
  } catch (err) {
    console.error('❌ Erreur serveur pagination :', err);
    return res.status(500).json({ message: 'Erreur serveur' });
  }
});

// GET /api/admin/all-responses
// Renvoyer tous les documents (avec champ `responses`) pour l’admin summary
router.get('/all-responses', async (req, res) => {
  try {
    const all = await Response.find()
      .sort({ createdAt: -1 })
      .lean();
    return res.json(all);
  } catch (err) {
    console.error('❌ Erreur serveur all-responses :', err);
    return res.status(500).json({ message: 'Erreur serveur all-responses' });
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
      console.error('❌ Erreur suppression réponse :', err);
      res.status(500).json({ message: 'Erreur lors de la suppression' });
    }
  });

module.exports = router;
