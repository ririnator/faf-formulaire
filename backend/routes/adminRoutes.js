const express = require('express');
const router  = express.Router();
const Response = require('../models/Response');

// Middleware qui va charger la réponse dans req.responseDoc
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

// GET /api/admin/responses
router.get('/responses', async (req, res) => {
  const docs = await Response.find().sort({ createdAt: -1 });
  res.json({ responses: docs });
});

// On passe par /responses/:id pour both GET et DELETE
router.route('/responses/:id')
  // GET /api/admin/responses/:id
  .get((req, res) => {
    res.json(req.responseDoc);
  })
  // DELETE /api/admin/responses/:id
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
