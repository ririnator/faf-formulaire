const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('../config/cloudinary');

class UploadService {
  constructor() {
    this.storage = new CloudinaryStorage({
      cloudinary,
      params: {
        folder: 'faf-images',
        public_id: (req, file) =>
          `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`,
        allowed_formats: ['jpg', 'jpeg', 'png', 'gif', 'webp']
      }
    });

    this.upload = multer({
      storage: this.storage,
      limits: {
        fileSize: 10 * 1024 * 1024, // 10MB
        files: 1
      },
      fileFilter: this.fileFilter
    });
  }

  fileFilter(req, file, cb) {
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

  getSingleUploader() {
    return this.upload.single('image');
  }

  async uploadSingle(req, res) {
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

  async deleteFromCloudinary(publicId) {
    try {
      const result = await cloudinary.uploader.destroy(publicId);
      return result;
    } catch (error) {
      console.error('Erreur lors de la suppression Cloudinary:', error);
      throw error;
    }
  }
}

module.exports = new UploadService();