// Script d'initialisation MongoDB pour FAF
// Exécuté automatiquement au premier démarrage de MongoDB

// Passer à la base de données FAF
db = db.getSiblingDB('faf');

// Créer un utilisateur applicatif (plus sécurisé que root)
db.createUser({
  user: 'faf_app',
  pwd: 'faf_app_password',
  roles: [
    {
      role: 'readWrite',
      db: 'faf'
    }
  ]
});

// Créer les index pour optimiser les performances
// (Réplique les index définis dans models/Response.js)

// Collection responses
db.responses.createIndex({ "createdAt": 1 });
db.responses.createIndex({ "month": 1 });
db.responses.createIndex({ "token": 1 }, { sparse: true });
db.responses.createIndex({ "isAdmin": 1, "month": 1 }, { unique: true, partialFilterExpression: { "isAdmin": true } });

print("✅ Base de données FAF initialisée avec succès");
print("✅ Utilisateur applicatif créé");
print("✅ Index de performance créés");