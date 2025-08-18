/**
 * Photo Compression Module for Form-a-Friend
 * Implements client-side image compression, mobile-first optimization, and progressive loading
 * Integrates seamlessly with existing Cloudinary upload system
 */

// =============================================================================
// CONFIGURATION AND CONSTANTS
// =============================================================================

const COMPRESSION_CONFIG = {
  // Quality levels based on image size and device capabilities
  quality: {
    high: 0.9,     // Large devices, high-res displays
    medium: 0.8,   // Standard desktop/tablet
    low: 0.6,      // Mobile devices, slow connections
    ultra: 0.4     // Very slow connections or large files
  },
  
  // Maximum dimensions to prevent memory issues on mobile
  maxDimensions: {
    mobile: { width: 1200, height: 1200 },
    tablet: { width: 1600, height: 1600 },
    desktop: { width: 2400, height: 2400 }
  },
  
  // File size thresholds for automatic compression selection
  sizeThresholds: {
    small: 500 * 1024,    // 500KB
    medium: 2 * 1024 * 1024,  // 2MB
    large: 5 * 1024 * 1024    // 5MB
  },
  
  // Supported file types
  supportedTypes: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'],
  
  // Progressive JPEG settings
  progressive: true,
  
  // Memory management
  maxCanvasSize: 4096 * 4096 // Prevent canvas memory errors
};

// =============================================================================
// DEVICE DETECTION AND CAPABILITY ASSESSMENT
// =============================================================================

class DeviceCapabilities {
  static getDeviceType() {
    const width = window.innerWidth;
    if (width <= 768) return 'mobile';
    if (width <= 1024) return 'tablet';
    return 'desktop';
  }
  
  static getConnectionSpeed() {
    if ('connection' in navigator) {
      const conn = navigator.connection;
      if (conn.effectiveType === 'slow-2g' || conn.effectiveType === '2g') return 'slow';
      if (conn.effectiveType === '3g') return 'medium';
      return 'fast';
    }
    return 'unknown';
  }
  
  static getDeviceMemory() {
    if ('deviceMemory' in navigator) {
      return navigator.deviceMemory; // GB
    }
    return 4; // Default assumption
  }
  
  static isHighDensityDisplay() {
    return window.devicePixelRatio > 1.5;
  }
  
  static getOptimalQuality() {
    const device = this.getDeviceType();
    const connection = this.getConnectionSpeed();
    const memory = this.getDeviceMemory();
    
    // Prioritize mobile experience and slow connections
    if (device === 'mobile' || connection === 'slow') return 'low';
    if (connection === 'medium' || memory < 4) return 'medium';
    return 'high';
  }
  
  static getMaxDimensions() {
    const device = this.getDeviceType();
    return COMPRESSION_CONFIG.maxDimensions[device];
  }
}

// =============================================================================
// CORE PHOTO COMPRESSION ENGINE
// =============================================================================

class PhotoCompressor {
  constructor() {
    this.canvas = null;
    this.ctx = null;
    this.worker = null; // For web worker support in future
  }
  
  /**
   * Main compression method - analyzes file and applies optimal compression
   */
  async compressPhoto(file, options = {}) {
    try {
      // Validate file type
      if (!this.isValidImageType(file.type)) {
        throw new Error(`Type de fichier non supporté: ${file.type}`);
      }
      
      // Get compression settings based on device and file size
      const settings = this.getCompressionSettings(file, options);
      
      // Create progress callback if not provided
      const onProgress = options.onProgress || (() => {});
      
      onProgress(10, 'Analyse de l\'image...');
      
      // Load and analyze image
      const image = await this.loadImage(file);
      onProgress(30, 'Optimisation des dimensions...');
      
      // Calculate optimal dimensions
      const dimensions = this.calculateOptimalDimensions(image, settings);
      onProgress(50, 'Compression en cours...');
      
      // Perform compression
      const compressedBlob = await this.performCompression(image, dimensions, settings);
      onProgress(90, 'Finalisation...');
      
      // Calculate compression statistics
      const stats = this.calculateCompressionStats(file, compressedBlob);
      onProgress(100, 'Compression terminée');
      
      return {
        originalFile: file,
        compressedBlob,
        stats,
        settings: settings.applied
      };
      
    } catch (error) {
      console.error('Erreur compression photo:', error);
      throw new Error(`Échec de la compression: ${error.message}`);
    }
  }
  
  /**
   * Validates if the file type is supported for compression
   */
  isValidImageType(mimeType) {
    return COMPRESSION_CONFIG.supportedTypes.includes(mimeType.toLowerCase());
  }
  
  /**
   * Determines optimal compression settings based on file size, device, and user preferences
   */
  getCompressionSettings(file, userOptions) {
    const deviceType = DeviceCapabilities.getDeviceType();
    const optimalQuality = DeviceCapabilities.getOptimalQuality();
    const maxDimensions = DeviceCapabilities.getMaxDimensions();
    
    // Auto-select quality based on file size if not specified
    let quality = userOptions.quality || optimalQuality;
    
    if (file.size > COMPRESSION_CONFIG.sizeThresholds.large) {
      quality = 'ultra'; // Aggressive compression for very large files
    } else if (file.size > COMPRESSION_CONFIG.sizeThresholds.medium) {
      quality = Math.min(quality, 'low'); // Ensure at least low compression
    }
    
    return {
      quality: COMPRESSION_CONFIG.quality[quality],
      maxWidth: userOptions.maxWidth || maxDimensions.width,
      maxHeight: userOptions.maxHeight || maxDimensions.height,
      outputFormat: userOptions.format || (file.type === 'image/png' ? 'image/png' : 'image/jpeg'),
      progressive: COMPRESSION_CONFIG.progressive && deviceType !== 'mobile',
      applied: {
        qualityLevel: quality,
        deviceType,
        originalSize: file.size
      }
    };
  }
  
  /**
   * Loads image file and returns HTMLImageElement
   */
  loadImage(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('Impossible de charger l\'image'));
      
      // Create object URL for the file
      const url = URL.createObjectURL(file);
      img.src = url;
      
      // Clean up URL after loading
      img.onload = () => {
        URL.revokeObjectURL(url);
        resolve(img);
      };
    });
  }
  
  /**
   * Calculates optimal dimensions while maintaining aspect ratio
   */
  calculateOptimalDimensions(image, settings) {
    const { naturalWidth: width, naturalHeight: height } = image;
    const { maxWidth, maxHeight } = settings;
    
    // If image is already smaller than max dimensions, use original size
    if (width <= maxWidth && height <= maxHeight) {
      return { width, height, scale: 1 };
    }
    
    // Calculate scaling factor to fit within max dimensions
    const scaleX = maxWidth / width;
    const scaleY = maxHeight / height;
    const scale = Math.min(scaleX, scaleY);
    
    return {
      width: Math.floor(width * scale),
      height: Math.floor(height * scale),
      scale
    };
  }
  
  /**
   * Performs the actual image compression using Canvas API
   */
  async performCompression(image, dimensions, settings) {
    // Create or reuse canvas
    if (!this.canvas) {
      this.canvas = document.createElement('canvas');
      this.ctx = this.canvas.getContext('2d');
    }
    
    const { width, height } = dimensions;
    
    // Set canvas dimensions
    this.canvas.width = width;
    this.canvas.height = height;
    
    // Configure rendering for better quality
    this.ctx.imageSmoothingEnabled = true;
    this.ctx.imageSmoothingQuality = 'high';
    
    // Draw image to canvas with new dimensions
    this.ctx.drawImage(image, 0, 0, width, height);
    
    // Convert to blob with compression
    return new Promise((resolve, reject) => {
      this.canvas.toBlob(
        (blob) => {
          if (blob) {
            resolve(blob);
          } else {
            reject(new Error('Échec de la conversion en blob'));
          }
        },
        settings.outputFormat,
        settings.quality
      );
    });
  }
  
  /**
   * Calculates compression statistics for user feedback
   */
  calculateCompressionStats(originalFile, compressedBlob) {
    const originalSize = originalFile.size;
    const compressedSize = compressedBlob.size;
    const reductionPercent = Math.round(((originalSize - compressedSize) / originalSize) * 100);
    
    return {
      originalSize,
      compressedSize,
      reductionPercent,
      originalSizeFormatted: this.formatFileSize(originalSize),
      compressedSizeFormatted: this.formatFileSize(compressedSize),
      savedSpace: this.formatFileSize(originalSize - compressedSize)
    };
  }
  
  /**
   * Formats file size for human-readable display
   */
  formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }
  
  /**
   * Clean up resources
   */
  cleanup() {
    if (this.canvas) {
      this.canvas.width = 1;
      this.canvas.height = 1;
      this.ctx = null;
    }
  }
}

// =============================================================================
// PROGRESSIVE LOADING AND PREVIEW SYSTEM
// =============================================================================

class PhotoPreviewManager {
  constructor() {
    this.previews = new Map(); // Track active previews for cleanup
  }
  
  /**
   * Creates a preview of the image before compression
   */
  createPreview(file, container, options = {}) {
    const preview = document.createElement('div');
    preview.className = 'photo-preview';
    preview.innerHTML = `
      <div class="preview-container">
        <img class="preview-image" alt="Aperçu de l'image">
        <div class="preview-overlay">
          <div class="preview-info">
            <span class="file-name">${this.escapeHtml(file.name)}</span>
            <span class="file-size">${this.formatFileSize(file.size)}</span>
          </div>
        </div>
        <div class="preview-actions">
          <button type="button" class="btn-compress" aria-label="Compresser l'image">
            🗜️ Compresser
          </button>
          <button type="button" class="btn-remove" aria-label="Supprimer l'image">
            🗑️ Supprimer
          </button>
        </div>
      </div>
    `;
    
    // Load image with progressive enhancement
    const img = preview.querySelector('.preview-image');
    const url = URL.createObjectURL(file);
    
    img.onload = () => {
      URL.revokeObjectURL(url);
      preview.classList.add('loaded');
    };
    
    img.onerror = () => {
      URL.revokeObjectURL(url);
      this.showPreviewError(preview, 'Impossible de charger l\'image');
    };
    
    img.src = url;
    
    // Store reference for cleanup
    this.previews.set(preview, url);
    
    // Add to container
    container.appendChild(preview);
    
    return preview;
  }
  
  /**
   * Shows compression progress in the preview
   */
  showCompressionProgress(preview, progress, message) {
    let progressBar = preview.querySelector('.compression-progress');
    
    if (!progressBar) {
      progressBar = document.createElement('div');
      progressBar.className = 'compression-progress';
      progressBar.innerHTML = `
        <div class="progress-bar">
          <div class="progress-fill" style="width: 0%"></div>
        </div>
        <div class="progress-text">Initialisation...</div>
      `;
      preview.querySelector('.preview-container').appendChild(progressBar);
    }
    
    const fill = progressBar.querySelector('.progress-fill');
    const text = progressBar.querySelector('.progress-text');
    
    fill.style.width = `${progress}%`;
    text.textContent = message;
    
    if (progress === 100) {
      setTimeout(() => {
        progressBar.remove();
      }, 1000);
    }
  }
  
  /**
   * Shows compression results in the preview
   */
  showCompressionResults(preview, stats) {
    const overlay = preview.querySelector('.preview-overlay');
    const info = overlay.querySelector('.preview-info');
    
    // Update with compression stats
    info.innerHTML = `
      <span class="file-name">Image compressée</span>
      <span class="file-size">${stats.compressedSizeFormatted}</span>
      <span class="compression-savings">-${stats.reductionPercent}% (${stats.savedSpace} économisés)</span>
    `;
    
    preview.classList.add('compressed');
  }
  
  /**
   * Shows error in preview
   */
  showPreviewError(preview, message) {
    const overlay = preview.querySelector('.preview-overlay');
    overlay.innerHTML = `
      <div class="preview-error">
        <span>❌ ${this.escapeHtml(message)}</span>
      </div>
    `;
    preview.classList.add('error');
  }
  
  /**
   * Removes preview and cleans up resources
   */
  removePreview(preview) {
    if (this.previews.has(preview)) {
      const url = this.previews.get(preview);
      URL.revokeObjectURL(url);
      this.previews.delete(preview);
    }
    preview.remove();
  }
  
  /**
   * Clean up all previews
   */
  cleanup() {
    this.previews.forEach((url, preview) => {
      URL.revokeObjectURL(url);
      preview.remove();
    });
    this.previews.clear();
  }
  
  /**
   * Helper methods
   */
  formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
  }
  
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// =============================================================================
// DRAG AND DROP INTERFACE
// =============================================================================

class DragDropManager {
  constructor() {
    this.dragCounter = 0; // Track drag enter/leave events
  }
  
  /**
   * Initializes drag and drop functionality for a container
   */
  initializeDragDrop(container, onFilesDropped) {
    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      container.addEventListener(eventName, this.preventDefaults, false);
      document.body.addEventListener(eventName, this.preventDefaults, false);
    });
    
    // Highlight drop zone
    ['dragenter', 'dragover'].forEach(eventName => {
      container.addEventListener(eventName, () => this.highlight(container), false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
      container.addEventListener(eventName, () => this.unhighlight(container), false);
    });
    
    // Handle dropped files
    container.addEventListener('drop', (e) => {
      const files = Array.from(e.dataTransfer.files);
      const imageFiles = files.filter(file => file.type.startsWith('image/'));
      
      if (imageFiles.length > 0) {
        onFilesDropped(imageFiles);
      }
    }, false);
  }
  
  preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }
  
  highlight(container) {
    container.classList.add('drag-over');
  }
  
  unhighlight(container) {
    container.classList.remove('drag-over');
  }
}

// =============================================================================
// MAIN PHOTO OPTIMIZATION MANAGER
// =============================================================================

class PhotoOptimizationManager {
  constructor() {
    this.compressor = new PhotoCompressor();
    this.previewManager = new PhotoPreviewManager();
    this.dragDropManager = new DragDropManager();
    this.optimizedFiles = new Map(); // Store compressed files
  }
  
  /**
   * Initializes photo optimization for a file input
   */
  initializeForInput(inputElement, options = {}) {
    const container = this.createPhotoContainer(inputElement);
    
    // Initialize drag and drop
    this.dragDropManager.initializeDragDrop(container, (files) => {
      this.handleFiles(files, inputElement, container);
    });
    
    // Handle file input change
    inputElement.addEventListener('change', (e) => {
      const files = Array.from(e.target.files);
      this.handleFiles(files, inputElement, container);
    });
    
    return container;
  }
  
  /**
   * Creates photo container UI
   */
  createPhotoContainer(inputElement) {
    const container = document.createElement('div');
    container.className = 'photo-upload-container';
    container.innerHTML = `
      <div class="upload-zone">
        <div class="upload-icon">📷</div>
        <div class="upload-text">
          <strong>Cliquez pour sélectionner</strong> ou glissez-déposez vos photos
        </div>
        <div class="upload-hint">Formats supportés: JPG, PNG, WebP • Compression automatique</div>
      </div>
      <div class="photo-previews"></div>
    `;
    
    // Insert after the file input
    inputElement.parentNode.insertBefore(container, inputElement.nextSibling);
    
    // Hide original input
    inputElement.style.display = 'none';
    
    return container;
  }
  
  /**
   * Handles selected or dropped files
   */
  async handleFiles(files, inputElement, container) {
    const previewsContainer = container.querySelector('.photo-previews');
    
    for (const file of files) {
      try {
        // Create preview
        const preview = this.previewManager.createPreview(file, previewsContainer);
        
        // Add event listeners
        this.setupPreviewEvents(preview, file, inputElement);
        
        // Auto-compress if option is enabled
        if (container.dataset.autoCompress !== 'false') {
          await this.compressPhoto(file, preview, inputElement);
        }
        
      } catch (error) {
        console.error('Erreur traitement fichier:', error);
        this.showError(`Erreur avec ${file.name}: ${error.message}`);
      }
    }
  }
  
  /**
   * Sets up event listeners for preview actions
   */
  setupPreviewEvents(preview, file, inputElement) {
    const compressBtn = preview.querySelector('.btn-compress');
    const removeBtn = preview.querySelector('.btn-remove');
    
    compressBtn.addEventListener('click', () => {
      this.compressPhoto(file, preview, inputElement);
    });
    
    removeBtn.addEventListener('click', () => {
      this.removePhoto(preview, inputElement);
    });
  }
  
  /**
   * Compresses a photo and updates the UI
   */
  async compressPhoto(file, preview, inputElement) {
    try {
      const result = await this.compressor.compressPhoto(file, {
        onProgress: (progress, message) => {
          this.previewManager.showCompressionProgress(preview, progress, message);
        }
      });
      
      // Store compressed file
      this.optimizedFiles.set(inputElement, result.compressedBlob);
      
      // Update preview with results
      this.previewManager.showCompressionResults(preview, result.stats);
      
      // Show success message
      this.showSuccess(`Image compressée: ${result.stats.reductionPercent}% de réduction`);
      
    } catch (error) {
      console.error('Erreur compression:', error);
      this.previewManager.showPreviewError(preview, error.message);
    }
  }
  
  /**
   * Removes a photo preview
   */
  removePhoto(preview, inputElement) {
    this.previewManager.removePreview(preview);
    this.optimizedFiles.delete(inputElement);
    inputElement.value = ''; // Clear file input
  }
  
  /**
   * Gets the optimized file for an input (for form submission)
   */
  getOptimizedFile(inputElement) {
    return this.optimizedFiles.get(inputElement) || null;
  }
  
  /**
   * Utility methods for user feedback
   */
  showSuccess(message) {
    this.showNotification(message, 'success');
  }
  
  showError(message) {
    this.showNotification(message, 'error');
  }
  
  showNotification(message, type) {
    // Create notification if it doesn't exist
    let notification = document.getElementById('photo-notification');
    if (!notification) {
      notification = document.createElement('div');
      notification.id = 'photo-notification';
      notification.className = 'photo-notification';
      document.body.appendChild(notification);
    }
    
    notification.className = `photo-notification ${type}`;
    notification.textContent = message;
    notification.style.display = 'block';
    
    // Auto-hide after 3 seconds
    setTimeout(() => {
      notification.style.display = 'none';
    }, 3000);
  }
  
  /**
   * Clean up resources
   */
  cleanup() {
    this.compressor.cleanup();
    this.previewManager.cleanup();
    this.optimizedFiles.clear();
  }
}

// =============================================================================
// GLOBAL EXPORT
// =============================================================================

// Create global instance for easy access
window.PhotoOptimization = new PhotoOptimizationManager();

// Also export classes for advanced usage
window.PhotoOptimization.PhotoCompressor = PhotoCompressor;
window.PhotoOptimization.DeviceCapabilities = DeviceCapabilities;
window.PhotoOptimization.PhotoPreviewManager = PhotoPreviewManager;
window.PhotoOptimization.DragDropManager = DragDropManager;

// Export for ES6 modules (commented out for browser compatibility)
// export {
//   PhotoOptimizationManager,
//   PhotoCompressor,
//   DeviceCapabilities,
//   PhotoPreviewManager,
//   DragDropManager,
//   COMPRESSION_CONFIG
// };

// Browser-compatible exports via global object (already done above via window.PhotoOptimization)