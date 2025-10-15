// backend/routes/upload.js
const express               = require('express');
const multer                = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary            = require('../config/cloudinary');
const router                = express.Router();

// ← configuration du storage Cloudinary
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder:    'faf-images',
    public_id: (req, file) =>
      `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`
  }
});

// ← parser Multer branché sur Cloudinary avec limites optimisées
const parser = multer({
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

// ← Route POST /api/upload
router.post('/', (req, res) => {
    parser.single('image')(req, res, err => {
      if (err) {
        console.error('⛔️ Erreur pendant l’upload :', err);
        return res.status(500).json({ message: 'Erreur upload', detail: err.message });
      }
      if (!req.file || !req.file.path) {
        return res.status(400).json({ message: 'Aucun fichier reçu' });
      }

      // 🔒 SECURITY: Validate that returned URL is from trusted Cloudinary domain
      const uploadedUrl = req.file.path;
      const trustedCloudinaryPattern = /^https:\/\/res\.cloudinary\.com\/[a-zA-Z0-9_-]+\/image\/upload\/.+$/;
      
      if (!trustedCloudinaryPattern.test(uploadedUrl)) {
        console.error('🚨 SECURITY: Upload returned untrusted URL:', uploadedUrl);
        return res.status(500).json({ 
          message: 'Erreur de sécurité lors de l\'upload',
          detail: 'URL non sécurisée retournée par le service'
        });
      }

      console.log('✅ Upload sécurisé réussi:', uploadedUrl);
      res.json({ url: uploadedUrl });
    });
  });

module.exports = router;
