require('dotenv').config();

const express = require('express');
const path = require('path');

// Configuration centralisée
const EnvironmentConfig = require('./config/environment');
const DatabaseConfig = require('./config/database');
const CorsConfig = require('./config/cors');
const SessionConfig = require('./config/session');

// Middleware centralisé
const { ensureAdmin, authenticateAdmin, logout } = require('./middleware/auth');
const { formLimiter, loginLimiter } = require('./middleware/rateLimiting');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const { validateLogin, handleValidationErrors } = require('./middleware/validation');
const { 
  validateToken, 
  handleParamValidationErrors, 
  validateTokenSecurity,
  tokenRateLimit 
} = require('./middleware/paramValidation');

// Services
const ResponseService = require('./services/responseService');
const AuthService = require('./services/authService');

// Routes
const formRoutes = require('./routes/formRoutes');
const responseRoutes = require('./routes/responseRoutes');
const adminRoutes = require('./routes/adminRoutes');
const uploadRoutes = require('./routes/upload');

class App {
  constructor() {
    this.app = express();
    this.port = process.env.PORT || 3000;
  }

  async initialize() {
    // 1. Validation de l'environnement
    EnvironmentConfig.validate();
    EnvironmentConfig.logEnvironment();

    // 2. Configuration des middlewares de base
    this.setupBasicMiddleware();

    // 3. Connexion à la base de données
    await DatabaseConfig.connect();

    // 4. Configuration des routes
    this.setupRoutes();

    // 5. Gestionnaire d'erreurs (à la fin)
    this.setupErrorHandlers();

    return this.app;
  }

  setupBasicMiddleware() {
    // CORS
    this.app.use(CorsConfig.middleware());
    CorsConfig.logConfig();

    // Trust proxy pour rate limiting
    this.app.set('trust proxy', 1);

    // Sessions
    this.app.use(SessionConfig.middleware());

    // Parseurs de body
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ limit: '50mb', extended: true }));

    // Fichiers statiques publics
    this.app.use(express.static(path.join(__dirname, '../frontend/public')));
  }

  setupRoutes() {
    // Pages de connexion/déconnexion
    this.setupAuthRoutes();

    // Interface admin
    this.setupAdminRoutes();

    // API consultation privée
    this.setupViewRoute();

    // API publiques avec rate limiting
    this.setupPublicApiRoutes();

    // Route catch-all pour view/:token
    this.setupViewTokenRoute();
  }

  setupAuthRoutes() {
    this.app.get('/login', (req, res) => {
      res.sendFile(path.join(__dirname, '../frontend/public/login.html'));
    });

    this.app.post('/login', 
      loginLimiter,
      validateLogin,
      handleValidationErrors,
      authenticateAdmin
    );

    this.app.get('/logout', logout);
  }

  setupAdminRoutes() {
    // Pages admin
    this.app.get('/admin', ensureAdmin, (req, res) => {
      res.sendFile(path.join(__dirname, '../frontend/admin/admin.html'));
    });

    this.app.get('/admin/gestion', ensureAdmin, (req, res) => {
      res.sendFile(path.join(__dirname, '../frontend/admin/admin_gestion.html'));
    });

    // Assets admin
    this.app.use('/admin/assets', ensureAdmin,
      express.static(path.join(__dirname, '../frontend/admin'))
    );

    // API Admin
    this.app.use('/api/admin', ensureAdmin, adminRoutes);
  }

  setupViewRoute() {
    this.app.get('/api/view/:token', 
      tokenRateLimit,
      validateTokenSecurity,
      validateToken,
      handleParamValidationErrors,
      async (req, res) => {
        try {
          const { token } = req.params;
          const result = await ResponseService.getResponseByToken(token);
          
          if (!result) {
            return res.status(404).json({ error: 'Lien invalide ou expiré' });
          }

          res.json(result);
        } catch (err) {
          console.error('Erreur API view:', err);
          
          // Gestion d'erreurs spécifiques
          if (err.name === 'CastError') {
            return res.status(400).json({ 
              error: 'Token malformé',
              details: 'Le format du token n\'est pas valide pour la base de données'
            });
          }
          
          if (err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
            return res.status(503).json({ 
              error: 'Service temporairement indisponible',
              details: 'Problème de connexion à la base de données'
            });
          }

          res.status(500).json({ error: 'Erreur serveur' });
        }
      }
    );
  }

  setupPublicApiRoutes() {
    // Rate limiting pour les soumissions
    this.app.use('/api/response', formLimiter);

    // Routes API publiques
    this.app.use('/api/form', formRoutes);
    this.app.use('/api/response', responseRoutes);
    this.app.use('/api/upload', uploadRoutes);
  }

  setupViewTokenRoute() {
    this.app.get('/view/:token', 
      validateToken,
      handleParamValidationErrors,
      (req, res) => {
        res.sendFile(path.join(__dirname, '../frontend/public/view.html'));
      }
    );
  }

  setupErrorHandlers() {
    // 404 pour routes non trouvées
    this.app.use(notFoundHandler);

    // Gestionnaire d'erreurs global
    this.app.use(errorHandler);
  }

  async start() {
    try {
      await this.initialize();
      
      this.app.listen(this.port, () => {
        console.log(`🚀 Serveur lancé sur le port ${this.port}`);
        console.log(`🌐 Application disponible sur ${process.env.APP_BASE_URL}`);
      });
    } catch (error) {
      console.error('❌ Erreur lors du démarrage:', error);
      process.exit(1);
    }
  }
}

// Démarrage de l'application
if (require.main === module) {
  const app = new App();
  app.start();
}

module.exports = App;