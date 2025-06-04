const express = require('express');
const router = express.Router();

// Exemple d'endpoint GET pour tester le routeur
router.get('/', (req, res) => {
  res.send('API Formulaire fonctionne !');
});

module.exports = router;
