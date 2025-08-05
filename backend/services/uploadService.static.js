const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('../config/cloudinary');

class UploadService {
  static _storage = null;
  static _upload = null;

  // Initialisation lazy du storage
  static getStorage() {
    if (!this._storage) {
      this._storage = new CloudinaryStorage({
        cloudinary,
        params: {
          folder: 'faf-images',
          public_id: (req, file) =>
            `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`,
          allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp']
        }
      });
    }
    return this._storage;
  }

  // Initialisation lazy de multer
  static getUpload() {
    if (!this._upload) {
      this._upload = multer({
        storage: this.getStorage(),
        limits: {
          fileSize: 10 * 1024 * 1024, // 10MB
          files: 1
        },
        fileFilter: this.fileFilter
      });
    }
    return this._upload;
  }

  static fileFilter(req, file, cb) {
    const allowedMimes = [
      'image/jpeg',
      'image/jpg', 
      'image/png',
      'image/gif',
      'image/webp'
    ];

    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Type de fichier non autorisé. Utilisez JPG, PNG, GIF ou WebP.'), false);
    }
  }

  static getSingleUploader() {
    return this.getUpload().single('image');
  }

  static async uploadSingle(req, res) {
    return new Promise((resolve, reject) => {
      this.getSingleUploader()(req, res, (err) => {
        if (err) {
          if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_FILE_SIZE') {
              reject(new Error('Fichier trop volumineux (max 10MB)'));
            } else {
              reject(new Error(`Erreur Multer: ${err.message}`));
            }
          } else {
            reject(err);
          }
          return;
        }

        if (!req.file || !req.file.path) {
          reject(new Error('Aucun fichier reçu'));
          return;
        }

        resolve({
          url: req.file.path,
          public_id: req.file.public_id,
          format: req.file.format,
          size: req.file.bytes
        });
      });
    });
  }

  static async deleteFromCloudinary(publicId) {
    try {
      const result = await cloudinary.uploader.destroy(publicId);
      return result;
    } catch (error) {
      console.error('Erreur lors de la suppression Cloudinary:', error);
      throw error;
    }
  }

  // Méthode pour réinitialiser le cache (utile pour les tests)
  static resetCache() {
    this._storage = null;
    this._upload = null;
  }

  // Méthode pour la configuration (si besoin)
  static configure(options = {}) {
    this.resetCache();
    
    if (options.folder) {
      // Possibilité d'override le dossier Cloudinary
      this._configOptions = { ...this._configOptions, ...options };
    }
  }
}

module.exports = UploadService;