/**
 * API Route: POST /api/upload
 *
 * Upload d'image vers Cloudinary avec validation MIME et sécurité
 * Utilise multer + multer-storage-cloudinary pour gérer l'upload
 */

const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;

// Configuration Cloudinary depuis les variables d'environnement
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configuration du storage Cloudinary
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'faf-images',
    public_id: (req, file) =>
      `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`,
    allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'heic']
  }
});

// Parser Multer avec limites optimisées
const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit for images
    fieldSize: 1024 * 1024,    // 1MB limit for form fields
    files: 1                   // Only 1 file per upload
  },
  fileFilter: (req, file, cb) => {
    // Only allow images
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Seuls les fichiers image sont autorisés'), false);
    }
  }
});

/**
 * Handler principal de la route
 * Note: Vercel nécessite une approche spéciale pour multer
 */
async function handler(req, res) {
  // 1. Vérifier la méthode HTTP
  if (req.method !== 'POST') {
    return res.status(405).json({
      success: false,
      error: 'Method not allowed'
    });
  }

  // 2. Traiter l'upload avec multer
  upload.single('image')(req, res, (err) => {
    if (err) {
      console.error('⛔️ Erreur pendant l\'upload:', err);
      return res.status(500).json({
        success: false,
        message: 'Erreur upload',
        detail: err.message
      });
    }

    // 3. Vérifier qu'un fichier a été uploadé
    if (!req.file || !req.file.path) {
      return res.status(400).json({
        success: false,
        message: 'Aucun fichier reçu'
      });
    }

    // 4. Validation de sécurité: vérifier que l'URL retournée est bien de Cloudinary
    const uploadedUrl = req.file.path;
    const trustedCloudinaryPattern = /^https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/image\/upload\/.+$/;

    if (!trustedCloudinaryPattern.test(uploadedUrl)) {
      console.error('🚨 SECURITY: Upload returned untrusted URL:', uploadedUrl);
      return res.status(500).json({
        success: false,
        message: 'Erreur de sécurité lors de l\'upload',
        detail: 'URL non sécurisée retournée par le service'
      });
    }

    // 5. Retourner l'URL sécurisée
    console.log('✅ Upload sécurisé réussi:', uploadedUrl);
    return res.status(200).json({
      success: true,
      url: uploadedUrl
    });
  });
}

// Configuration Vercel pour multer (body parser doit être désactivé)
module.exports = handler;
module.exports.config = {
  api: {
    bodyParser: false // Nécessaire pour que multer puisse traiter les fichiers
  }
};
