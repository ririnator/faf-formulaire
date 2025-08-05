const mongoose = require('mongoose');

class DatabaseConfig {
  static async connect() {
    try {
      const connection = await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 5000,
        heartbeatFrequencyMS: 2000
      });

      console.log("✅ Connecté à la base de données");
      
      // Créer les index nécessaires
      await this.createIndexes();
      
      // Gérer les événements de connexion
      this.setupConnectionEvents();
      
      return connection;
    } catch (err) {
      console.error("❌ Erreur de connexion à la DB :", err);
      process.exit(1);
    }
  }

  static async createIndexes() {
    try {
      const db = mongoose.connection.db;
      
      // Index sur createdAt pour le tri
      await db.collection('responses').createIndex({ createdAt: -1 });
      
      // Index composé pour les requêtes par mois et type admin
      await db.collection('responses').createIndex({ 
        month: 1, 
        isAdmin: 1 
      });
      
      // Index sur le token pour les recherches rapides
      await db.collection('responses').createIndex({ 
        token: 1 
      }, { 
        sparse: true // Seulement pour les documents avec token
      });
      
      console.log("✅ Index MongoDB créés");
    } catch (err) {
      console.error("❌ Erreur création des index :", err);
    }
  }

  static setupConnectionEvents() {
    mongoose.connection.on('connected', () => {
      console.log('📊 Mongoose connecté à MongoDB');
    });

    mongoose.connection.on('error', (err) => {
      console.error('❌ Erreur MongoDB:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('📊 Mongoose déconnecté de MongoDB');
    });

    // Fermer la connexion proprement lors de l'arrêt de l'app
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('📊 Connexion MongoDB fermée');
      process.exit(0);
    });
  }

  static isConnected() {
    return mongoose.connection.readyState === 1;
  }
}

module.exports = DatabaseConfig;