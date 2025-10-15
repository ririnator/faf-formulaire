const cors = require('cors');

class CorsConfig {
  static getAllowedOrigins() {
    const origins = [
      process.env.APP_BASE_URL,
      process.env.FRONTEND_URL
    ].filter(Boolean); // Retire les valeurs undefined

    if (origins.length === 0) {
      console.warn('⚠️  Aucune origine CORS configurée, utilisation de localhost par défaut');
      return ['http://localhost:3000'];
    }

    return origins;
  }

  static getConfig() {
    return {
      origin: this.getAllowedOrigins(),
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Origin',
        'X-Requested-With', 
        'Content-Type',
        'Accept',
        'Authorization'
      ],
      exposedHeaders: ['X-Total-Count'],
      maxAge: 86400 // 24h cache pour preflight
    };
  }

  static middleware() {
    return cors(this.getConfig());
  }

  static logConfig() {
    console.log('🌐 Origines CORS autorisées:', this.getAllowedOrigins());
  }
}

module.exports = CorsConfig;