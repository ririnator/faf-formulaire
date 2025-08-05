function errorHandler(err, req, res, next) {
  console.error('Erreur capturée:', err);

  // Erreur de validation Mongoose
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(error => error.message);
    return res.status(400).json({
      error: 'Erreur de validation',
      details: errors
    });
  }

  // Erreur de cast MongoDB (ID invalide)
  if (err.name === 'CastError') {
    return res.status(400).json({
      error: 'ID invalide'
    });
  }

  // Erreur de duplicata MongoDB
  if (err.code === 11000) {
    return res.status(409).json({
      error: 'Ressource déjà existante'
    });
  }

  // Erreur par défaut
  res.status(err.status || 500).json({
    error: err.message || 'Erreur interne du serveur'
  });
}

function notFoundHandler(req, res) {
  const path = require('path');
  res.status(404).sendFile(path.join(__dirname, '../../frontend/404.html'));
}

module.exports = {
  errorHandler,
  notFoundHandler
};