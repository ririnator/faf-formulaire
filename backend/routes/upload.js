// backend/routes/upload.js
const express               = require('express');
const multer                = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary            = require('../config/cloudinary');
const router                = express.Router();

// Rate limiting spécifique pour les uploads
const uploadAttempts = new Map();
const UPLOAD_RATE_LIMIT = {
  maxUploads: 5,           // Max 5 uploads
  windowMs: 15 * 60 * 1000, // Par 15 minutes
  maxFileSize: 5 * 1024 * 1024, // 5MB par fichier
  maxTotalSize: 20 * 1024 * 1024 // 20MB total par période
};

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

// Middleware de rate limiting pour uploads
function uploadRateLimit(req, res, next) {
  const clientIP = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const userAttempts = uploadAttempts.get(clientIP) || {
    uploads: [],
    totalSize: 0
  };
  
  // Nettoyer les anciennes tentatives
  userAttempts.uploads = userAttempts.uploads.filter(
    upload => now - upload.timestamp < UPLOAD_RATE_LIMIT.windowMs
  );
  
  // Recalculer la taille totale
  userAttempts.totalSize = userAttempts.uploads.reduce(
    (total, upload) => total + upload.size, 0
  );
  
  // Vérifier le nombre d'uploads
  if (userAttempts.uploads.length >= UPLOAD_RATE_LIMIT.maxUploads) {
    const oldestUpload = userAttempts.uploads[0];
    const resetTime = Math.ceil((oldestUpload.timestamp + UPLOAD_RATE_LIMIT.windowMs - now) / 1000);
    
    return res.status(429).json({
      error: 'Too many uploads',
      message: `Maximum ${UPLOAD_RATE_LIMIT.maxUploads} uploads per ${UPLOAD_RATE_LIMIT.windowMs / 60000} minutes`,
      retryAfter: resetTime,
      remaining: 0
    });
  }
  
  // Vérifier la taille totale (estimation basée sur Content-Length)
  const contentLength = parseInt(req.headers['content-length']) || 0;
  if (userAttempts.totalSize + contentLength > UPLOAD_RATE_LIMIT.maxTotalSize) {
    return res.status(413).json({
      error: 'Upload quota exceeded',
      message: `Maximum ${UPLOAD_RATE_LIMIT.maxTotalSize / 1024 / 1024}MB total per ${UPLOAD_RATE_LIMIT.windowMs / 60000} minutes`,
      used: Math.round(userAttempts.totalSize / 1024 / 1024 * 100) / 100,
      limit: UPLOAD_RATE_LIMIT.maxTotalSize / 1024 / 1024
    });
  }
  
  // Stocker la tentative (sera mise à jour avec la vraie taille après upload)
  req.uploadStartTime = now;
  req.userAttempts = userAttempts;
  req.clientIP = clientIP;
  
  next();
}

// Fonction pour enregistrer l'upload réussi
function recordSuccessfulUpload(req, fileSize) {
  const { userAttempts, clientIP, uploadStartTime } = req;
  
  userAttempts.uploads.push({
    timestamp: uploadStartTime,
    size: fileSize
  });
  
  userAttempts.totalSize += fileSize;
  uploadAttempts.set(clientIP, userAttempts);
  
  // Log pour monitoring
  console.log('📤 Upload recorded:', {
    ip: clientIP,
    size: `${Math.round(fileSize / 1024)}KB`,
    remaining: UPLOAD_RATE_LIMIT.maxUploads - userAttempts.uploads.length,
    quotaUsed: `${Math.round(userAttempts.totalSize / 1024 / 1024 * 100) / 100}MB`
  });
}

// ← Route POST /api/upload avec rate limiting
router.post('/', uploadRateLimit, (req, res) => {
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

      // Enregistrer l'upload réussi pour le rate limiting
      const fileSize = req.file.size || 0;
      recordSuccessfulUpload(req, fileSize);
      
      console.log('✅ Upload sécurisé réussi:', uploadedUrl);
      res.json({ url: uploadedUrl });
    });
  });

// Cleanup périodique des tentatives expirées pour éviter les fuites mémoire
setInterval(() => {
  const now = Date.now();
  let cleanedCount = 0;
  
  for (const [ip, attempts] of uploadAttempts.entries()) {
    const validUploads = attempts.uploads.filter(
      upload => now - upload.timestamp < UPLOAD_RATE_LIMIT.windowMs
    );
    
    if (validUploads.length === 0) {
      uploadAttempts.delete(ip);
      cleanedCount++;
    } else if (validUploads.length !== attempts.uploads.length) {
      attempts.uploads = validUploads;
      attempts.totalSize = validUploads.reduce((total, upload) => total + upload.size, 0);
      uploadAttempts.set(ip, attempts);
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`🧹 Upload rate limit cleanup: removed ${cleanedCount} expired entries`);
  }
}, 5 * 60 * 1000); // Cleanup toutes les 5 minutes

// Export pour monitoring
router.getUploadStats = () => ({
  activeIPs: uploadAttempts.size,
  rateLimits: UPLOAD_RATE_LIMIT,
  totalAttempts: Array.from(uploadAttempts.values()).reduce(
    (total, attempts) => total + attempts.uploads.length, 0
  )
});

module.exports = router;
