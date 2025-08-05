require('dotenv').config();

const express = require('express');
const path = require('path');

// Configuration centralisée
const EnvironmentConfig = require('./config/environment');
const DatabaseConfig = require('./config/database');
const CorsConfig = require('./config/cors');
const SessionConfig = require('./config/session');

// Middleware centralisé
const { formLimiter, loginLimiter } = require('./middleware/rateLimiting');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const { validateLogin, validateResponse, handleValidationErrors } = require('./middleware/validation');
const { 
  validateToken, 
  handleParamValidationErrors, 
  validateTokenSecurity,
  tokenRateLimit 
} = require('./middleware/paramValidation');

// Services statiques
const ResponseService = require('./services/responseService');
const AuthService = require('./services/authService');
const UploadService = require('./services/uploadService.static');

// Routes
const formRoutes = require('./routes/formRoutes');
const adminRoutes = require('./routes/adminRoutes');

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
      async (req, res) => {
        try {
          const { username, password } = req.body;
          const isValid = await AuthService.validateAdminCredentials(username, password);
          
          if (isValid) {
            AuthService.createAdminSession(req);
            return res.redirect('/admin');
          }
          
          return res.redirect('/login?error=1');
        } catch (err) {
          console.error('Erreur login:', err);
          return res.redirect('/login?error=1');
        }
      }
    );

    this.app.get('/logout', async (req, res) => {
      await AuthService.destroySession(req);
      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  }

  setupAdminRoutes() {
    // Middleware auth pour les routes admin
    const ensureAdmin = (req, res, next) => {
      if (AuthService.isAuthenticated(req)) return next();
      return res.redirect('/login');
    };

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
    // Route pour les réponses avec service statique
    this.app.post('/api/response',
      formLimiter,
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
          
          // Gestion d'erreurs spécifiques
          if (err.message.includes('admin existe déjà')) {
            return res.status(409).json({ message: err.message });
          }

          if (err.name === 'ValidationError') {
            return res.status(400).json({ 
              message: 'Données de réponse invalides',
              details: err.message 
            });
          }

          if (err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
            return res.status(503).json({ 
              message: 'Service temporairement indisponible',
              details: 'Problème de connexion à la base de données'
            });
          }

          if (err.code === 11000) {
            return res.status(409).json({ 
              message: 'Réponse déjà enregistrée pour ce mois' 
            });
          }
          
          res.status(500).json({ 
            message: 'Erreur en sauvegardant la réponse' 
          });
        }
      }
    );

    // Route upload avec service statique
    this.app.post('/api/upload', async (req, res) => {
      try {
        const result = await UploadService.uploadSingle(req, res);
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

    // Autres routes
    this.app.use('/api/form', formRoutes);
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
        console.log(`🔧 Services statiques utilisés pour la consistance`);
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