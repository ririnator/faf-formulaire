const express = require('express');
const router = express.Router();

const ResponseService = require('../services/responseService');
const { validateResponse, handleValidationErrors } = require('../middleware/validation');

// POST /api/response
router.post('/',
  validateResponse,
  handleValidationErrors,
  async (req, res) => {
    try {
      const result = await ResponseService.createResponse(req.body);
      
      res.status(201).json({
        message: 'Réponse enregistrée avec succès !',
        link: result.link
      });
    } catch (err) {
      console.error('Erreur en sauvegardant la réponse :', err);
      
      if (err.message.includes('admin existe déjà')) {
        return res.status(409).json({ message: err.message });
      }
      
      res.status(500).json({ 
        message: 'Erreur en sauvegardant la réponse' 
      });
    }
  }
);

module.exports = router;