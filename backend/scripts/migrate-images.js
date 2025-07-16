// scripts/migrate-images.js
require('dotenv').config();
const mongoose   = require('mongoose');
const cloudinary = require('cloudinary').v2;
const Response   = require('../models/Response'); // ajuste le chemin si besoin

// 1. Configuration Cloudinary
cloudinary.config({
  cloud_name:  process.env.CLOUDINARY_CLOUD_NAME,
  api_key:     process.env.CLOUDINARY_API_KEY,
  api_secret:  process.env.CLOUDINARY_API_SECRET,
});

// 2. Connexion à MongoDB
async function connectDB() {
  await mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser:    true,
    useUnifiedTopology: true,
  });
  console.log('✅ MongoDB connecté');
}

// 3. Migration
async function migrate() {
  await connectDB();

  // Utilise un curseur pour éviter de tout charger en mémoire
  const cursor = Response.find().cursor();

  let countTotal = 0;
  let countMigrated = 0;

  for await (const doc of cursor) {
    let modified = false;

    // Parcours chaque réponse
    for (const item of doc.responses) {
      const ans = item.answer;
      // Détecte le Base64 (data:image...)
      if (typeof ans === 'string' && ans.startsWith('data:image')) {
        countTotal++;
        try {
          // upload vers Cloudinary
          const uploadRes = await cloudinary.uploader.upload(ans, {
            folder: 'faf-images',
            overwrite: false,
            resource_type: 'auto'
          });
          item.answer = uploadRes.secure_url;
          modified = true;
          countMigrated++;
          console.log(`→ Migré doc ${doc._id} / question "${item.question}"`);
        } catch (err) {
          console.error(`✖ Erreur upload doc ${doc._id}:`, err.message);
        }
      }
    }

    if (modified) {
      await doc.save();
      console.log(`✔ Document ${doc._id} mis à jour`);
    }
  }

  console.log(`\n🎉 Migration terminée : ${countMigrated}/${countTotal} images migrées.`);
  process.exit(0);
}

// 4. Lancer la migration
migrate().catch(err => {
  console.error('❌ Migration échouée :', err);
  process.exit(1);
});