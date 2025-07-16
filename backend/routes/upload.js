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

// ← parser Multer branché sur Cloudinary
const parser = multer({
  storage
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
      res.json({ url: req.file.path });
    });
  });

module.exports = router;
