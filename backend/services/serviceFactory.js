const EnvironmentConfig = require('../config/environment');
const ResponseService = require('./responseService.v2');
const AuthService = require('./authService.v2');
const UploadServiceV2 = require('./uploadService.v2');
const cloudinary = require('../config/cloudinary');

class ServiceFactory {
  constructor() {
    this.config = EnvironmentConfig.getConfig();
    this._services = new Map();
  }

  getResponseService() {
    if (!this._services.has('response')) {
      this._services.set('response', new ResponseService(this.config));
    }
    return this._services.get('response');
  }

  getAuthService() {
    if (!this._services.has('auth')) {
      this._services.set('auth', new AuthService(this.config));
    }
    return this._services.get('auth');
  }

  getUploadService() {
    if (!this._services.has('upload')) {
      const uploadConfig = {
        folder: 'faf-images',
        maxFileSize: 10 * 1024 * 1024, // 10MB
        allowedFormats: ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        cloudinary: cloudinary
      };
      this._services.set('upload', new UploadServiceV2(uploadConfig));
    }
    return this._services.get('upload');
  }

  // Factory method pour créer tous les services avec la config
  static create() {
    return new ServiceFactory();
  }
}

module.exports = ServiceFactory;