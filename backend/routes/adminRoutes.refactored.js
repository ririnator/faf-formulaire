const express = require('express');
const router = express.Router();

const ResponseService = require('../services/responseService');

// GET /api/admin/responses?page=1&limit=10&sortBy=createdAt&sortOrder=desc
router.get('/responses', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(20, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const sortBy = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder || 'desc';

    const result = await ResponseService.getAllResponses(page, limit, sortBy, sortOrder);
    
    res.json(result);
  } catch (err) {
    console.error('❌ Erreur pagination /responses :', err);
    res.status(500).json({ message: 'Erreur serveur pagination' });
  }
});

// GET /api/admin/responses/:id
router.get('/responses/:id', async (req, res) => {
  try {
    const response = await ResponseService.getResponseById(req.params.id);
    if (!response) {
      return res.status(404).json({ message: 'Réponse non trouvée' });
    }
    res.json(response);
  } catch (err) {
    console.error('❌ Erreur get response :', err);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

// DELETE /api/admin/responses/:id
router.delete('/responses/:id', async (req, res) => {
  try {
    const deleted = await ResponseService.deleteResponse(req.params.id);
    if (!deleted) {
      return res.status(404).json({ message: 'Réponse non trouvée' });
    }
    res.json({ message: 'Réponse supprimée avec succès' });
  } catch (err) {
    console.error('❌ Erreur suppression /responses/:id :', err);
    res.status(500).json({ message: 'Erreur serveur suppression' });
  }
});

// GET /api/admin/summary?month=YYYY-MM
router.get('/summary', async (req, res) => {
  try {
    const result = await ResponseService.getResponsesSummary();
    res.json(result);
  } catch (err) {
    console.error('❌ Erreur summary :', err);
    res.status(500).json({ message: 'Erreur serveur summary' });
  }
});

// GET /api/admin/months
router.get('/months', async (req, res) => {
  try {
    const months = await ResponseService.getAvailableMonths();
    res.json(months);
  } catch (err) {
    console.error('❌ Erreur months :', err);
    res.status(500).json({ message: 'Erreur serveur months' });
  }
});

module.exports = router;