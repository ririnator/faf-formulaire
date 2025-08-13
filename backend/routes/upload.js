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

// Seuils de surveillance mémoire
const MEMORY_THRESHOLDS = {
  maxMapSize: 1000,        // Seuil d'urgence: max 1000 IPs trackées
  emergencyCleanup: 500,   // Déclencher nettoyage d'urgence à 500 IPs
  memoryCheckInterval: 60000 // Vérifier la mémoire toutes les minutes
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
  const userAttempts = getUploadAttempts(clientIP);
  
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
  setUploadAttempts(clientIP, userAttempts);
  
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

// Cleanup périodique optimisé avec LRU cache
setInterval(() => {
  const now = Date.now();
  let cleanedCount = 0;
  
  for (const [ip, attempts] of optimizedUploadAttempts.entries()) {
    const validUploads = attempts.uploads.filter(
      upload => now - upload.timestamp < UPLOAD_RATE_LIMIT.windowMs
    );
    
    if (validUploads.length === 0) {
      optimizedUploadAttempts.delete(ip);
      cleanedCount++;
    } else if (validUploads.length !== attempts.uploads.length) {
      attempts.uploads = validUploads;
      attempts.totalSize = validUploads.reduce((total, upload) => total + upload.size, 0);
      setUploadAttempts(ip, attempts);
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`🧹 Upload rate limit cleanup: removed ${cleanedCount} expired entries (LRU optimized)`);
  }
}, 5 * 60 * 1000); // Cleanup toutes les 5 minutes

// LRU Cache implementation with optimization
class OptimizedLRUUploadCache {
  constructor(maxSize = 1000) {
    this.maxSize = maxSize;
    this.cache = new Map(); // Maintains insertion order in modern JS
    this.accessOrder = new Map(); // Track access frequency
  }

  get(ip) {
    if (!this.cache.has(ip)) return undefined;
    
    // Update access order (LRU tracking)
    const item = this.cache.get(ip);
    this.cache.delete(ip);
    this.cache.set(ip, item);
    
    // Track access frequency for intelligent cleanup
    const currentFreq = this.accessOrder.get(ip) || 0;
    this.accessOrder.set(ip, currentFreq + 1);
    
    return item;
  }

  set(ip, value) {
    if (this.cache.has(ip)) {
      // Update existing entry
      this.cache.delete(ip);
    } else if (this.cache.size >= this.maxSize) {
      // Remove LRU items intelligently
      this.performIntelligentCleanup();
    }
    
    this.cache.set(ip, value);
    this.accessOrder.set(ip, (this.accessOrder.get(ip) || 0) + 1);
  }

  delete(ip) {
    const result = this.cache.delete(ip);
    this.accessOrder.delete(ip);
    return result;
  }

  performIntelligentCleanup() {
    if (this.cache.size <= this.maxSize * 0.7) return; // Only cleanup when 70% full
    
    const entries = Array.from(this.cache.entries());
    const accessFreqs = this.accessOrder;
    const now = Date.now();
    
    // Score-based cleanup: consider both age and frequency
    const scoredEntries = entries.map(([ip, attempts]) => {
      const lastActivity = Math.max(...attempts.uploads.map(u => u.timestamp));
      const age = now - lastActivity;
      const frequency = accessFreqs.get(ip) || 1;
      
      // Lower score = higher priority for removal
      const score = (frequency * 1000) / (age + 1); // Frequency bonus / age penalty
      
      return { ip, score, lastActivity, frequency };
    });
    
    // Sort by score (lowest first = candidates for removal)
    scoredEntries.sort((a, b) => a.score - b.score);
    
    // Remove bottom 30% of entries
    const toRemove = Math.floor(this.cache.size * 0.3);
    let removedCount = 0;
    
    for (let i = 0; i < Math.min(toRemove, scoredEntries.length); i++) {
      const { ip } = scoredEntries[i];
      if (this.delete(ip)) {
        removedCount++;
      }
    }
    
    console.log(`🧹 Intelligent LRU cleanup: removed ${removedCount} entries (score-based)`);
  }

  size() {
    return this.cache.size;
  }

  entries() {
    return this.cache.entries();
  }

  has(ip) {
    return this.cache.has(ip);
  }
}

// Replace Map with optimized LRU cache
const optimizedUploadAttempts = new OptimizedLRUUploadCache(MEMORY_THRESHOLDS.maxMapSize);

// Updated functions to use LRU cache
function getUploadAttempts(ip) {
  return optimizedUploadAttempts.get(ip) || { uploads: [], totalSize: 0 };
}

function setUploadAttempts(ip, attempts) {
  optimizedUploadAttempts.set(ip, attempts);
}

// Surveillance mémoire et nettoyage d'urgence optimisé
function performEmergencyMemoryCleanup() {
  const mapSize = optimizedUploadAttempts.size();
  
  if (mapSize <= MEMORY_THRESHOLDS.emergencyCleanup) return;
  
  console.warn(`⚠️ Emergency cleanup triggered: ${mapSize} IPs tracked`);
  
  // Use optimized LRU cleanup
  optimizedUploadAttempts.performIntelligentCleanup();
  
  console.warn(`🚨 Emergency cleanup completed: ${optimizedUploadAttempts.size()} entries remaining`);
}

// Monitoring mémoire périodique optimisé
setInterval(() => {
  const mapSize = optimizedUploadAttempts.size();
  const heapUsed = process.memoryUsage().heapUsed;
  const heapUsedMB = Math.round(heapUsed / 1024 / 1024);
  
  // Déclencher nettoyage d'urgence si nécessaire
  if (mapSize >= MEMORY_THRESHOLDS.emergencyCleanup) {
    performEmergencyMemoryCleanup();
  }
  
  // Déclencher nettoyage préventif intelligent
  if (mapSize >= MEMORY_THRESHOLDS.maxMapSize * 0.7) {
    optimizedUploadAttempts.performIntelligentCleanup();
  }
  
  // Alerter si proche du seuil critique
  if (mapSize >= MEMORY_THRESHOLDS.maxMapSize * 0.8) {
    console.warn(`🔔 Memory warning: ${mapSize}/${MEMORY_THRESHOLDS.maxMapSize} IPs tracked (${heapUsedMB}MB heap)`);
  }
  
  // Log périodique pour monitoring avec métriques LRU
  if (mapSize > 50) {
    console.log(`📊 Upload tracking: ${mapSize} IPs, ${heapUsedMB}MB heap (LRU optimized)`);
  }
}, MEMORY_THRESHOLDS.memoryCheckInterval);

// Export pour monitoring avec métriques LRU optimisées
router.getUploadStats = () => ({
  activeIPs: optimizedUploadAttempts.size(),
  rateLimits: UPLOAD_RATE_LIMIT,
  memoryThresholds: MEMORY_THRESHOLDS,
  totalAttempts: Array.from(optimizedUploadAttempts.entries()).reduce(
    (total, [ip, attempts]) => total + attempts.uploads.length, 0
  ),
  cacheEfficiency: {
    accessPatterns: optimizedUploadAttempts.accessOrder.size,
    avgAccessFreq: Array.from(optimizedUploadAttempts.accessOrder.values()).reduce(
      (sum, freq) => sum + freq, 0
    ) / (optimizedUploadAttempts.accessOrder.size || 1)
  }
});

module.exports = router;
