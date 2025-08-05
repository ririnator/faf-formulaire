const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

class UploadService {
  constructor(config = {}) {
    // Configuration avec des valeurs par défaut
    this.config = {
      folder: config.folder || 'faf-images',
      maxFileSize: config.maxFileSize || 10 * 1024 * 1024, // 10MB
      allowedFormats: config.allowedFormats || ['jpg', 'jpeg', 'png', 'gif', 'webp'],
      allowedMimes: config.allowedMimes || [
        'image/jpeg',
        'image/jpg', 
        'image/png',
        'image/gif',
        'image/webp'
      ],
      cloudinary: config.cloudinary
    };

    // Validation de la config
    if (!this.config.cloudinary) {
      throw new Error('Configuration Cloudinary requise pour UploadService');
    }

    this.initializeStorage();
    this.initializeUpload();
  }

  initializeStorage() {
    this.storage = new CloudinaryStorage({
      cloudinary: this.config.cloudinary,
      params: {
        folder: this.config.folder,
        public_id: (req, file) =>
          `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`,
        allowed_formats: this.config.allowedFormats
      }
    });
  }

  initializeUpload() {
    this.upload = multer({
      storage: this.storage,
      limits: {
        fileSize: this.config.maxFileSize,
        files: 1
      },
      fileFilter: this.fileFilter.bind(this)
    });
  }

  fileFilter(req, file, cb) {
    if (this.config.allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      const allowedTypes = this.config.allowedFormats.join(', ').toUpperCase();
      cb(new Error(`Type de fichier non autorisé. Utilisez: ${allowedTypes}`), false);
    }
  }

  getSingleUploader() {
    return this.upload.single('image');
  }

  async uploadSingle(req, res) {
    return new Promise((resolve, reject) => {
      this.getSingleUploader()(req, res, (err) => {
        if (err) {
          if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_FILE_SIZE') {
              const maxSizeMB = this.config.maxFileSize / (1024 * 1024);
              reject(new Error(`Fichier trop volumineux (max ${maxSizeMB}MB)`));
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
          size: req.file.bytes,
          folder: this.config.folder
        });
      });
    });
  }

  async deleteFromCloudinary(publicId) {
    try {
      const result = await this.config.cloudinary.uploader.destroy(publicId);
      return result;
    } catch (error) {
      console.error('Erreur lors de la suppression Cloudinary:', error);
      throw error;
    }
  }

  // Méthodes utilitaires
  getConfig() {
    return { ...this.config };
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    this.initializeStorage();
    this.initializeUpload();
  }

  // Validation d'un fichier sans upload
  async validateFile(file) {
    if (!file) {
      throw new Error('Aucun fichier fourni');
    }

    if (!this.config.allowedMimes.includes(file.mimetype)) {
      const allowedTypes = this.config.allowedFormats.join(', ').toUpperCase();
      throw new Error(`Type de fichier non autorisé. Utilisez: ${allowedTypes}`);
    }

    if (file.size > this.config.maxFileSize) {
      const maxSizeMB = this.config.maxFileSize / (1024 * 1024);
      throw new Error(`Fichier trop volumineux (max ${maxSizeMB}MB)`);
    }

    return true;
  }
}

module.exports = UploadService;