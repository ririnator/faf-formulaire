const express = require('express');
const router = express.Router();
const Response = require('../models/Response');

router.post('/response', async (req, res) => {
  try {
    // Ici, req.body.responses doit être déjà un tableau d'objets { question, answer }
    const { name, responses } = req.body;
    
    // Add required month field (same logic as responseRoutes.js)
    const month = new Date().toISOString().slice(0, 7); // "YYYY-MM"
    
    // Basic admin detection (simplified version)
    const isAdmin = name && name.trim().toLowerCase() === process.env.FORM_ADMIN_NAME?.toLowerCase();
    
    // Generate token for non-admin users
    const token = isAdmin ? null : require('crypto').randomBytes(32).toString('hex');

    // Création du document avec le nouveau format
    const responseDoc = new Response({
      name,
      responses,  // Déjà au bon format
      month,
      isAdmin,
      token
    });

    await responseDoc.save();
    res.json({ 
      message: "Réponse enregistrée avec succès",
      responseId: responseDoc._id.toString(),
      ...(token && { viewUrl: `${process.env.APP_BASE_URL || 'http://localhost:3000'}/view.html?token=${token}` })
    });
  } catch (error) {
    console.error("Erreur lors de l'enregistrement :", error);
    res.status(500).json({ message: "Erreur lors de l'enregistrement de la réponse" });
  }
});

module.exports = router;