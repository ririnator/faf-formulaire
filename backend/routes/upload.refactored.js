const express = require('express');
const router = express.Router();

const uploadService = require('../services/uploadService');

// POST /api/upload
router.post('/', async (req, res) => {
  try {
    const result = await uploadService.uploadSingle(req, res);
    res.json({ 
      url: result.url,
      meta: {
        size: result.size,
        format: result.format
      }
    });
  } catch (err) {
    console.error('⛔️ Erreur pendant l\'upload :', err);
    
    let statusCode = 500;
    let message = 'Erreur upload';

    if (err.message.includes('Type de fichier')) {
      statusCode = 400;
      message = err.message;
    } else if (err.message.includes('trop volumineux')) {
      statusCode = 413;
      message = err.message;
    } else if (err.message.includes('Aucun fichier')) {
      statusCode = 400;
      message = err.message;
    }

    res.status(statusCode).json({ 
      message,
      detail: err.message 
    });
  }
});

module.exports = router;