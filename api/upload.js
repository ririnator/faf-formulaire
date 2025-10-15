/**
 * API Route: POST /api/upload
 *
 * Upload d'image vers Cloudinary avec validation MIME et sécurité
 * Utilise formidable pour Vercel serverless compatibility
 */

const cloudinary = require('cloudinary').v2;
const { formidable } = require('formidable');

// Configuration Cloudinary depuis les variables d'environnement
// Note: Trim les valeurs pour éviter les espaces parasites
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME?.trim(),
  api_key: process.env.CLOUDINARY_API_KEY?.trim(),
  api_secret: process.env.CLOUDINARY_API_SECRET?.trim()
});

/**
 * Handler principal de la route
 * Compatible avec Vercel serverless functions
 */
async function handler(req, res) {
  // 1. Vérifier la méthode HTTP
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed'
    });
  }

  try {
    // Debug: Vérifier configuration Cloudinary
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME?.trim();
    const apiKey = process.env.CLOUDINARY_API_KEY?.trim();
    const apiSecret = process.env.CLOUDINARY_API_SECRET?.trim();

    console.log('🔑 Cloudinary config check:', {
      hasCloudName: !!cloudName,
      hasApiKey: !!apiKey,
      hasApiSecret: !!apiSecret,
      cloudNameLength: cloudName?.length,
      apiKeyLength: apiKey?.length,
      apiSecretLength: apiSecret?.length
    });

    if (!cloudName || !apiKey || !apiSecret) {
      console.error('⛔️ Variables Cloudinary manquantes ou vides');
      return res.status(500).json({
        success: false,
        message: 'Configuration Cloudinary incomplète',
        detail: 'Les variables d\'environnement Cloudinary ne sont pas configurées'
      });
    }

    console.log('📝 Parsing formulaire multipart...');

    // 2. Parser le formulaire multipart avec formidable
    const form = formidable({
      maxFileSize: 5 * 1024 * 1024, // 5MB limit
      maxFields: 10,
      maxFieldsSize: 1024 * 1024,
      allowEmptyFiles: false,
      filter: (part) => {
        // Only accept image mime types
        const isImage = part.mimetype && part.mimetype.startsWith('image/');
        console.log(`📎 Fichier détecté: ${part.name}, MIME: ${part.mimetype}, accepté: ${isImage}`);
        return isImage;
      }
    });

    const [fields, files] = await new Promise((resolve, reject) => {
      form.parse(req, (err, fields, files) => {
        if (err) {
          console.error('⛔️ Erreur parsing formidable:', err);
          reject(err);
        } else {
          console.log('✅ Parsing réussi, fichiers:', Object.keys(files));
          resolve([fields, files]);
        }
      });
    });

    // 3. Vérifier qu'un fichier image a été uploadé
    if (!files.image || !files.image[0]) {
      console.error('⛔️ Aucun fichier image trouvé dans:', Object.keys(files));
      return res.status(400).json({
        success: false,
        message: 'Aucun fichier image reçu',
        debug: { receivedFields: Object.keys(fields), receivedFiles: Object.keys(files) }
      });
    }

    const file = files.image[0];
    console.log(`📄 Fichier reçu: ${file.originalFilename}, taille: ${file.size} bytes, MIME: ${file.mimetype}`);

    // 4. Validation MIME type supplémentaire
    const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif'];
    if (!allowedMimeTypes.includes(file.mimetype)) {
      console.error(`⛔️ Type MIME non autorisé: ${file.mimetype}`);
      return res.status(400).json({
        success: false,
        message: 'Type de fichier non autorisé. Seules les images sont acceptées.',
        detail: `Type reçu: ${file.mimetype}`
      });
    }

    console.log(`☁️ Upload vers Cloudinary: ${file.filepath}`);

    // 5. Upload vers Cloudinary
    const uploadResult = await cloudinary.uploader.upload(file.filepath, {
      folder: 'faf-images',
      public_id: `${Date.now()}-${file.originalFilename.replace(/\s+/g, '_')}`,
      resource_type: 'image',
      allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic']
    });

    // 6. Validation de sécurité: vérifier que l'URL retournée est bien de Cloudinary
    const uploadedUrl = uploadResult.secure_url;
    const trustedCloudinaryPattern = /^https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/image\/upload\/.+$/;

    if (!trustedCloudinaryPattern.test(uploadedUrl)) {
      console.error('🚨 SECURITY: Upload returned untrusted URL:', uploadedUrl);
      return res.status(500).json({
        success: false,
        message: 'Erreur de sécurité lors de l\'upload',
        detail: 'URL non sécurisée retournée par le service'
      });
    }

    // 7. Retourner l'URL sécurisée
    console.log('✅ Upload sécurisé réussi:', uploadedUrl);
    return res.status(200).json({
      success: true,
      url: uploadedUrl
    });

  } catch (error) {
    console.error('⛔️ Erreur pendant l\'upload:', error);
    return res.status(500).json({
      success: false,
      message: 'Erreur lors de l\'upload',
      detail: error.message
    });
  }
}

// Configuration Vercel pour formidable (body parser doit être désactivé)
module.exports = handler;
module.exports.config = {
  api: {
    bodyParser: false // Nécessaire pour que formidable puisse traiter les fichiers
  }
};
