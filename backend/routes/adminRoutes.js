const express = require('express');
const router = express.Router();
const Response = require('../models/Response');

// GET /api/admin/responses
router.get('/responses', async (req, res) => {
  try {
    // Récupère toutes les réponses, triées du plus récent au plus ancien
    const docs = await Response.find().sort({ createdAt: -1 });
    // On renvoie un objet { responses: [...] }
    return res.json({ responses: docs });
  } catch (err) {
    console.error('❌ Erreur GET /api/admin/responses :', err);
    return res.status(500).json({
      message: 'Erreur en récupérant les réponses',
      error: err.message
    });
  }
});

module.exports = router;
