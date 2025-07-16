// scripts/migrate-images.js
require('dotenv').config();
const mongoose  = require('mongoose');
const cloudinary = require('cloudinary').v2;
const Response  = require('../models/Response');

// Configuration Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Fonction principale
async function migrate() {
  try {
    // 1) connexion à MongoDB
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('✅ MongoDB connecté');

    const cursor = Response.find().cursor();
    let totalImages = 0;
    let migratedImages = 0;

    for await (const doc of cursor) {
      let docMigrated = false;

      // 2) on parcourt chaque réponse du document
      for (const resp of doc.responses) {
        const { answer, question } = resp;
        // on ne traite que les chaînes base64 data:image
        if (typeof answer === 'string' && answer.startsWith('data:image')) {
          totalImages++;
          try {
            // on génère un public_id safe à partir de l'ID + question
            const publicId = `faf/${doc._id}_${question
              .toLowerCase()
              .replace(/[^a-z0-9]+/g, '_')
              .replace(/_+/g, '_')
              .replace(/^_|_$/g, '')}`;

            const result = await cloudinary.uploader.upload(answer, {
              folder:    'faf-images',
              public_id: publicId,
            });

            // on remplace la réponse base64 par l'URL sécurisée
            resp.answer = result.secure_url;
            migratedImages++;
            docMigrated = true;
          } catch (err) {
            console.error(
              `✖ Erreur upload doc ${doc._id} (“${question}”):`,
              err.message || JSON.stringify(err)
            );
          }
        }
      }

      // 3) si on a modifié au moins une réponse, on sauve le document
      if (docMigrated) {
        await doc.save();
        console.log(`💾 Document ${doc._id} mis à jour`);
      }
    }

    console.log(
      `🎉 Migration terminée : ${migratedImages}/${totalImages} images migrées.`
    );
    process.exit(0);

  } catch (err) {
    console.error('❌ Migration échouée :', err);
    process.exit(1);
  }
}

// Lancement
migrate();