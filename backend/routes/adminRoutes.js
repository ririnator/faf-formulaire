console.log('🔌  Chargement de adminRoutes.js');

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

    // Requête paginée
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

module.exports = router;
