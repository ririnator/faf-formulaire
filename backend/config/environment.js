class EnvironmentConfig {
  static requiredVars = [
    'MONGODB_URI',
    'SESSION_SECRET',
    'LOGIN_ADMIN_USER',
    'LOGIN_ADMIN_PASS',
    'FORM_ADMIN_NAME',
    'APP_BASE_URL'
  ];

  static optionalVars = [
    'FRONTEND_URL',
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET',
    'PORT'
  ];

  static validate() {
    const missing = [];
    const warnings = [];

    // Vérifier les variables requises
    this.requiredVars.forEach(varName => {
      if (!process.env[varName]) {
        missing.push(varName);
      }
    });

    // Vérifier les variables optionnelles avec warning
    this.optionalVars.forEach(varName => {
      if (!process.env[varName]) {
        warnings.push(varName);
      }
    });

    if (missing.length > 0) {
      console.error('❌ Variables d\'environnement manquantes:', missing);
      throw new Error(`Variables d'environnement requises manquantes: ${missing.join(', ')}`);
    }

    if (warnings.length > 0) {
      console.warn('⚠️  Variables d\'environnement optionnelles manquantes:', warnings);
    }

    console.log('✅ Variables d\'environnement validées');
    return true;
  }

  static getConfig() {
    return {
      port: process.env.PORT || 3000,
      nodeEnv: process.env.NODE_ENV || 'development',
      mongodb: {
        uri: process.env.MONGODB_URI
      },
      session: {
        secret: process.env.SESSION_SECRET
      },
      admin: {
        user: process.env.LOGIN_ADMIN_USER,
        password: process.env.LOGIN_ADMIN_PASS,
        formName: process.env.FORM_ADMIN_NAME
      },
      urls: {
        appBase: process.env.APP_BASE_URL,
        frontend: process.env.FRONTEND_URL
      },
      cloudinary: {
        cloudName: process.env.CLOUDINARY_CLOUD_NAME,
        apiKey: process.env.CLOUDINARY_API_KEY,
        apiSecret: process.env.CLOUDINARY_API_SECRET
      }
    };
  }

  static isDevelopment() {
    return process.env.NODE_ENV !== 'production';
  }

  static isProduction() {
    return process.env.NODE_ENV === 'production';
  }

  static logEnvironment() {
    const config = this.getConfig();
    console.log(`🚀 Environnement: ${config.nodeEnv}`);
    console.log(`📡 Port: ${config.port}`);
    console.log(`🔗 URL de base: ${config.urls.appBase}`);
  }
}

module.exports = EnvironmentConfig;