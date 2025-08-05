const session = require('express-session');
const MongoStore = require('connect-mongo');

class SessionConfig {
  static getConfig() {
    if (!process.env.SESSION_SECRET) {
      throw new Error('SESSION_SECRET manquant dans les variables d\'environnement');
    }

    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI manquant pour le store de sessions');
    }

    return {
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60,    // 14 jours
        autoRemove: 'native',
        touchAfter: 24 * 3600      // Mise à jour max 1x/24h
      }),
      cookie: {
        maxAge: 1000 * 60 * 60,    // 1 heure
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true
      },
      name: 'faf.session'
    };
  }

  static middleware() {
    return session(this.getConfig());
  }
}

module.exports = SessionConfig;