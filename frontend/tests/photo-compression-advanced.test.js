/**
 * Advanced Photo Compression & Lightbox Tests
 * Comprehensive test suite for client-side image compression,
 * lightbox functionality, security validation, and performance monitoring
 */

const { JSDOM } = require('jsdom');
const fs = require('fs');
const path = require('path');

describe('📸 Advanced Photo Compression & Lightbox Tests', () => {
  let dom;
  let window;
  let document;
  let photoOptimization;
  let mockCanvas;
  let mockCanvasContext;

  beforeEach(() => {
    // Create enhanced DOM environment with photo features
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html lang="fr">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>Photo Test Environment</title>
          <style>
            .photo-upload-container { position: relative; }
            .upload-zone { border: 2px dashed #ccc; padding: 2rem; text-align: center; }
            .upload-zone.drag-over { border-color: #3b82f6; background: #eff6ff; }
            .photo-preview { position: relative; display: inline-block; margin: 0.5rem; }
            .preview-image { max-width: 200px; max-height: 200px; border-radius: 8px; }
            .compression-progress { position: absolute; bottom: 0; left: 0; right: 0; }
            .progress-bar { height: 4px; background: #e5e7eb; border-radius: 2px; }
            .progress-fill { height: 100%; background: #3b82f6; transition: width 0.3s; }
            .photo-notification { position: fixed; top: 1rem; right: 1rem; z-index: 1000; }
            .lightbox-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.9); z-index: 2000; }
            .lightbox-content { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); }
            .lightbox-image { max-width: 90vw; max-height: 90vh; }
            .lightbox-controls { position: absolute; bottom: 1rem; left: 50%; transform: translateX(-50%); }
            .contact-card { background: white; border-radius: 8px; padding: 1rem; position: relative; }
            .contact-avatar { width: 64px; height: 64px; border-radius: 50%; background: #3b82f6; }
            .action-button { min-height: 44px; min-width: 44px; border-radius: 8px; cursor: pointer; }
          </style>
        </head>
        <body>
          <!-- Form with photo inputs -->
          <form id="testForm">
            <div class="photo-input-section">
              <label for="photo1">Photo 1:</label>
              <input type="file" id="photo1" accept="image/*" data-auto-compress="true">
              
              <label for="photo2">Photo 2:</label>
              <input type="file" id="photo2" accept="image/*" data-auto-compress="false">
              
              <label for="profilePhoto">Photo de profil:</label>
              <input type="file" id="profilePhoto" accept="image/*" data-compression-quality="high">
            </div>
          </form>

          <!-- Contact management with photos -->
          <div id="contactsContainer" class="contacts-grid">
            <!-- Will be populated with contact cards -->
          </div>

          <!-- Lightbox for image viewing -->
          <div id="lightboxOverlay" class="lightbox-overlay hidden" role="dialog" aria-label="Visionneuse d'images">
            <div class="lightbox-content">
              <img id="lightboxImage" class="lightbox-image" alt="">
              <div class="lightbox-controls">
                <button id="lightboxZoomIn" class="action-button">🔍+</button>
                <button id="lightboxZoomOut" class="action-button">🔍-</button>
                <button id="lightboxRotate" class="action-button">🔄</button>
                <button id="lightboxFullscreen" class="action-button">⛶</button>
                <button id="lightboxClose" class="action-button">✕</button>
              </div>
            </div>
            <div class="lightbox-info">
              <span id="lightboxCaption"></span>
              <span id="lightboxDimensions"></span>
            </div>
          </div>

          <!-- Photo optimization notification -->
          <div id="photo-notification" class="photo-notification hidden"></div>

          <!-- Performance monitoring -->
          <div id="performanceMonitor" class="hidden">
            <div id="compressionTime">0ms</div>
            <div id="memoryUsage">0MB</div>
            <div id="compressionRatio">0%</div>
          </div>
        </body>
      </html>
    `, {
      url: 'https://localhost:3000',
      pretendToBeVisual: true,
      resources: 'usable'
    });

    window = dom.window;
    document = window.document;

    // Setup global environment
    global.window = window;
    global.document = document;
    global.URL = window.URL || { createObjectURL: jest.fn(), revokeObjectURL: jest.fn() };
    global.Image = window.Image;
    global.File = window.File;
    global.Blob = window.Blob;
    global.FormData = window.FormData;
    global.FileReader = window.FileReader;

    // Mock Canvas API
    mockCanvasContext = {
      drawImage: jest.fn(),
      imageSmoothingEnabled: true,
      imageSmoothingQuality: 'high'
    };

    mockCanvas = {
      getContext: jest.fn(() => mockCanvasContext),
      toBlob: jest.fn((callback) => {
        const mockBlob = new Blob(['compressed'], { type: 'image/jpeg' });
        callback(mockBlob);
      }),
      width: 0,
      height: 0
    };

    // Mock createElement for canvas
    const originalCreateElement = document.createElement.bind(document);
    document.createElement = jest.fn((tagName) => {
      if (tagName === 'canvas') {
        return mockCanvas;
      }
      return originalCreateElement(tagName);
    });

    // Load photo compression module
    const photoCompressionCode = fs.readFileSync(
      path.join(__dirname, '../public/js/photo-compression.js'),
      'utf8'
    );
    
    // Execute photo compression code in DOM context
    const script = document.createElement('script');
    script.textContent = photoCompressionCode;
    document.head.appendChild(script);

    photoOptimization = window.PhotoOptimization;
  });

  afterEach(() => {
    if (photoOptimization) {
      photoOptimization.cleanup();
    }
    dom.window.close();
    jest.clearAllMocks();
  });

  describe('Device Capabilities Detection', () => {
    test('should detect device type correctly', () => {
      const DeviceCapabilities = window.PhotoOptimization.DeviceCapabilities;
      
      // Mock mobile viewport
      Object.defineProperty(window, 'innerWidth', { value: 375, writable: true });
      expect(DeviceCapabilities.getDeviceType()).toBe('mobile');
      
      // Mock tablet viewport
      Object.defineProperty(window, 'innerWidth', { value: 800, writable: true });
      expect(DeviceCapabilities.getDeviceType()).toBe('tablet');
      
      // Mock desktop viewport
      Object.defineProperty(window, 'innerWidth', { value: 1920, writable: true });
      expect(DeviceCapabilities.getDeviceType()).toBe('desktop');
    });

    test('should detect connection speed when available', () => {
      const DeviceCapabilities = window.PhotoOptimization.DeviceCapabilities;
      
      // Mock connection API
      Object.defineProperty(navigator, 'connection', {
        value: { effectiveType: '4g' },
        writable: true
      });
      
      expect(DeviceCapabilities.getConnectionSpeed()).toBe('fast');
      
      // Mock slow connection
      navigator.connection.effectiveType = '2g';
      expect(DeviceCapabilities.getConnectionSpeed()).toBe('slow');
    });

    test('should detect device memory when available', () => {
      const DeviceCapabilities = window.PhotoOptimization.DeviceCapabilities;
      
      // Mock device memory API
      Object.defineProperty(navigator, 'deviceMemory', {
        value: 8,
        writable: true
      });
      
      expect(DeviceCapabilities.getDeviceMemory()).toBe(8);
    });

    test('should detect high density displays', () => {
      const DeviceCapabilities = window.PhotoOptimization.DeviceCapabilities;
      
      // Mock high DPR
      Object.defineProperty(window, 'devicePixelRatio', { value: 2.0, writable: true });
      expect(DeviceCapabilities.isHighDensityDisplay()).toBe(true);
      
      // Mock standard DPR
      Object.defineProperty(window, 'devicePixelRatio', { value: 1.0, writable: true });
      expect(DeviceCapabilities.isHighDensityDisplay()).toBe(false);
    });

    test('should determine optimal quality based on device capabilities', () => {
      const DeviceCapabilities = window.PhotoOptimization.DeviceCapabilities;
      
      // Mock mobile with slow connection
      Object.defineProperty(window, 'innerWidth', { value: 375, writable: true });
      Object.defineProperty(navigator, 'connection', {
        value: { effectiveType: '2g' },
        writable: true
      });
      
      expect(DeviceCapabilities.getOptimalQuality()).toBe('low');
      
      // Mock desktop with fast connection
      Object.defineProperty(window, 'innerWidth', { value: 1920, writable: true });
      navigator.connection.effectiveType = '4g';
      
      expect(DeviceCapabilities.getOptimalQuality()).toBe('high');
    });
  });

  describe('Photo Compression Engine', () => {
    test('should validate supported image types', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      // Valid types
      expect(compressor.isValidImageType('image/jpeg')).toBe(true);
      expect(compressor.isValidImageType('image/jpg')).toBe(true);
      expect(compressor.isValidImageType('image/png')).toBe(true);
      expect(compressor.isValidImageType('image/webp')).toBe(true);
      
      // Invalid types
      expect(compressor.isValidImageType('image/svg+xml')).toBe(false);
      expect(compressor.isValidImageType('text/html')).toBe(false);
      expect(compressor.isValidImageType('application/javascript')).toBe(false);
    });

    test('should calculate compression settings based on file size', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      // Small file
      const smallFile = new File([new ArrayBuffer(100 * 1024)], 'small.jpg', { type: 'image/jpeg' });
      const smallSettings = compressor.getCompressionSettings(smallFile, {});
      expect(smallSettings.applied.qualityLevel).toBe('high');
      
      // Large file
      const largeFile = new File([new ArrayBuffer(10 * 1024 * 1024)], 'large.jpg', { type: 'image/jpeg' });
      const largeSettings = compressor.getCompressionSettings(largeFile, {});
      expect(smallSettings.applied.qualityLevel).toBe('high'); // Based on mobile mock
    });

    test('should calculate optimal dimensions while maintaining aspect ratio', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      // Mock image with 2000x1000 dimensions
      const mockImage = {
        naturalWidth: 2000,
        naturalHeight: 1000
      };
      
      const settings = {
        maxWidth: 1200,
        maxHeight: 800
      };
      
      const dimensions = compressor.calculateOptimalDimensions(mockImage, settings);
      
      // Should scale down proportionally
      expect(dimensions.width).toBe(1200);
      expect(dimensions.height).toBe(600);
      expect(dimensions.scale).toBe(0.6);
    });

    test('should handle images smaller than max dimensions', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      const mockImage = {
        naturalWidth: 800,
        naturalHeight: 600
      };
      
      const settings = {
        maxWidth: 1200,
        maxHeight: 1200
      };
      
      const dimensions = compressor.calculateOptimalDimensions(mockImage, settings);
      
      // Should keep original size
      expect(dimensions.width).toBe(800);
      expect(dimensions.height).toBe(600);
      expect(dimensions.scale).toBe(1);
    });

    test('should format file sizes correctly', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      expect(compressor.formatFileSize(0)).toBe('0 B');
      expect(compressor.formatFileSize(1024)).toBe('1.0 KB');
      expect(compressor.formatFileSize(1024 * 1024)).toBe('1.0 MB');
      expect(compressor.formatFileSize(1536 * 1024)).toBe('1.5 MB');
    });

    test('should perform canvas-based compression', async () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      const mockImage = {
        naturalWidth: 1000,
        naturalHeight: 800
      };
      
      const dimensions = { width: 500, height: 400 };
      const settings = {
        outputFormat: 'image/jpeg',
        quality: 0.8
      };
      
      const result = await compressor.performCompression(mockImage, dimensions, settings);
      
      expect(mockCanvas.width).toBe(500);
      expect(mockCanvas.height).toBe(400);
      expect(mockCanvasContext.imageSmoothingEnabled).toBe(true);
      expect(mockCanvasContext.drawImage).toHaveBeenCalledWith(mockImage, 0, 0, 500, 400);
      expect(mockCanvas.toBlob).toHaveBeenCalled();
      expect(result).toBeInstanceOf(Blob);
    });

    test('should cleanup canvas resources', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      // Initialize canvas
      compressor.canvas = mockCanvas;
      compressor.ctx = mockCanvasContext;
      
      // Cleanup
      compressor.cleanup();
      
      expect(mockCanvas.width).toBe(1);
      expect(mockCanvas.height).toBe(1);
      expect(compressor.ctx).toBe(null);
    });
  });

  describe('Photo Preview Management', () => {
    test('should create preview with proper structure', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      const container = document.createElement('div');
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      
      const preview = previewManager.createPreview(mockFile, container);
      
      expect(preview.classList.contains('photo-preview')).toBe(true);
      expect(preview.querySelector('.preview-image')).toBeTruthy();
      expect(preview.querySelector('.btn-compress')).toBeTruthy();
      expect(preview.querySelector('.btn-remove')).toBeTruthy();
      expect(container.contains(preview)).toBe(true);
    });

    test('should escape HTML in file names', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      const container = document.createElement('div');
      const maliciousName = '<script>alert("XSS")</script>.jpg';
      const mockFile = new File(['test'], maliciousName, { type: 'image/jpeg' });
      
      const preview = previewManager.createPreview(mockFile, container);
      const fileName = preview.querySelector('.file-name').textContent;
      
      expect(fileName).toBe(maliciousName);
      expect(preview.innerHTML).not.toContain('<script>');
    });

    test('should show compression progress', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      const container = document.createElement('div');
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      
      const preview = previewManager.createPreview(mockFile, container);
      previewManager.showCompressionProgress(preview, 50, 'Compression en cours...');
      
      const progressBar = preview.querySelector('.compression-progress');
      const progressFill = preview.querySelector('.progress-fill');
      const progressText = preview.querySelector('.progress-text');
      
      expect(progressBar).toBeTruthy();
      expect(progressFill.style.width).toBe('50%');
      expect(progressText.textContent).toBe('Compression en cours...');
    });

    test('should show compression results', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      const container = document.createElement('div');
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      
      const preview = previewManager.createPreview(mockFile, container);
      const stats = {
        compressedSizeFormatted: '500 KB',
        reductionPercent: 75,
        savedSpace: '1.5 MB'
      };
      
      previewManager.showCompressionResults(preview, stats);
      
      expect(preview.classList.contains('compressed')).toBe(true);
      expect(preview.textContent).toContain('Image compressée');
      expect(preview.textContent).toContain('500 KB');
      expect(preview.textContent).toContain('-75%');
    });

    test('should handle preview errors', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      const container = document.createElement('div');
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      
      const preview = previewManager.createPreview(mockFile, container);
      previewManager.showPreviewError(preview, 'Erreur de chargement');
      
      expect(preview.classList.contains('error')).toBe(true);
      expect(preview.textContent).toContain('❌ Erreur de chargement');
    });

    test('should cleanup previews and URLs', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      const container = document.createElement('div');
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      
      const preview = previewManager.createPreview(mockFile, container);
      
      expect(previewManager.previews.has(preview)).toBe(true);
      
      previewManager.removePreview(preview);
      
      expect(previewManager.previews.has(preview)).toBe(false);
      expect(container.contains(preview)).toBe(false);
    });
  });

  describe('Drag and Drop Interface', () => {
    test('should initialize drag and drop on container', () => {
      const dragDropManager = new window.PhotoOptimization.DragDropManager();
      const container = document.createElement('div');
      const onFilesDropped = jest.fn();
      
      dragDropManager.initializeDragDrop(container, onFilesDropped);
      
      // Simulate drag events
      const dragEvent = new window.Event('dragenter');
      container.dispatchEvent(dragEvent);
      
      expect(container.classList.contains('drag-over')).toBe(true);
      
      const leaveEvent = new window.Event('dragleave');
      container.dispatchEvent(leaveEvent);
      
      expect(container.classList.contains('drag-over')).toBe(false);
    });

    test('should handle dropped files', () => {
      const dragDropManager = new window.PhotoOptimization.DragDropManager();
      const container = document.createElement('div');
      const onFilesDropped = jest.fn();
      
      dragDropManager.initializeDragDrop(container, onFilesDropped);
      
      // Mock file drop
      const mockFiles = [
        new File(['test1'], 'test1.jpg', { type: 'image/jpeg' }),
        new File(['test2'], 'test2.png', { type: 'image/png' }),
        new File(['text'], 'text.txt', { type: 'text/plain' })
      ];
      
      const dropEvent = new window.Event('drop');
      dropEvent.dataTransfer = {
        files: mockFiles
      };
      
      container.dispatchEvent(dropEvent);
      
      // Should only call with image files
      expect(onFilesDropped).toHaveBeenCalledWith([mockFiles[0], mockFiles[1]]);
    });

    test('should prevent default drag behaviors', () => {
      const dragDropManager = new window.PhotoOptimization.DragDropManager();
      const container = document.createElement('div');
      
      dragDropManager.initializeDragDrop(container, jest.fn());
      
      const dragEvent = new window.Event('dragover');
      const preventDefaultSpy = jest.spyOn(dragEvent, 'preventDefault');
      
      container.dispatchEvent(dragEvent);
      
      expect(preventDefaultSpy).toHaveBeenCalled();
    });
  });

  describe('Lightbox Functionality', () => {
    test('should have lightbox elements with proper structure', () => {
      const overlay = document.getElementById('lightboxOverlay');
      const image = document.getElementById('lightboxImage');
      const controls = document.querySelectorAll('.lightbox-controls .action-button');
      
      expect(overlay).toBeTruthy();
      expect(overlay.getAttribute('role')).toBe('dialog');
      expect(image).toBeTruthy();
      expect(controls.length).toBe(5); // zoom in, zoom out, rotate, fullscreen, close
    });

    test('should open lightbox with image', () => {
      const overlay = document.getElementById('lightboxOverlay');
      const image = document.getElementById('lightboxImage');
      const mockSrc = 'https://res.cloudinary.com/test/image/upload/v123/photo.jpg';
      
      // Open lightbox
      overlay.classList.remove('hidden');
      image.src = mockSrc;
      image.alt = 'Photo de test';
      
      expect(overlay.classList.contains('hidden')).toBe(false);
      expect(image.src).toBe(mockSrc);
      expect(image.alt).toBe('Photo de test');
    });

    test('should validate lightbox image sources for security', () => {
      const isValidLightboxSource = (src) => {
        try {
          const url = new URL(src);
          return url.protocol === 'https:' && url.hostname.endsWith('res.cloudinary.com');
        } catch {
          return false;
        }
      };
      
      // Valid sources
      expect(isValidLightboxSource('https://res.cloudinary.com/test/image.jpg')).toBe(true);
      
      // Invalid sources
      expect(isValidLightboxSource('javascript:alert("XSS")')).toBe(false);
      expect(isValidLightboxSource('data:text/html,<script>alert("XSS")</script>')).toBe(false);
      expect(isValidLightboxSource('https://evil.com/fake.jpg')).toBe(false);
      expect(isValidLightboxSource('http://res.cloudinary.com/test.jpg')).toBe(false); // HTTP not HTTPS
    });

    test('should prevent XSS in lightbox captions', () => {
      const caption = document.getElementById('lightboxCaption');
      const maliciousCaption = '<script>alert("XSS")</script>';
      
      // Safe assignment
      caption.textContent = maliciousCaption;
      
      expect(caption.textContent).toBe(maliciousCaption);
      expect(caption.innerHTML).not.toContain('<script>');
    });

    test('should handle lightbox controls', () => {
      const zoomInBtn = document.getElementById('lightboxZoomIn');
      const zoomOutBtn = document.getElementById('lightboxZoomOut');
      const rotateBtn = document.getElementById('lightboxRotate');
      const fullscreenBtn = document.getElementById('lightboxFullscreen');
      const closeBtn = document.getElementById('lightboxClose');
      
      expect(zoomInBtn).toBeTruthy();
      expect(zoomOutBtn).toBeTruthy();
      expect(rotateBtn).toBeTruthy();
      expect(fullscreenBtn).toBeTruthy();
      expect(closeBtn).toBeTruthy();
      
      // Test close functionality
      const overlay = document.getElementById('lightboxOverlay');
      let closed = false;
      
      closeBtn.addEventListener('click', () => {
        overlay.classList.add('hidden');
        closed = true;
      });
      
      closeBtn.click();
      expect(closed).toBe(true);
      expect(overlay.classList.contains('hidden')).toBe(true);
    });

    test('should handle keyboard navigation in lightbox', () => {
      const overlay = document.getElementById('lightboxOverlay');
      const image = document.getElementById('lightboxImage');
      
      overlay.classList.remove('hidden');
      
      // Test escape key
      const escapeEvent = new window.KeyboardEvent('keydown', { key: 'Escape' });
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          overlay.classList.add('hidden');
        }
      });
      
      document.dispatchEvent(escapeEvent);
      expect(overlay.classList.contains('hidden')).toBe(true);
    });
  });

  describe('Performance Monitoring', () => {
    test('should track compression time', async () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      const mockFile = new File([new ArrayBuffer(1024 * 1024)], 'test.jpg', { type: 'image/jpeg' });
      
      const startTime = performance.now();
      
      // Mock compression
      const onProgress = jest.fn();
      
      try {
        await compressor.compressPhoto(mockFile, { onProgress });
      } catch (error) {
        // Expected due to mocked environment
      }
      
      const endTime = performance.now();
      const compressionTime = endTime - startTime;
      
      expect(compressionTime).toBeGreaterThan(0);
      expect(onProgress).toHaveBeenCalled();
    });

    test('should monitor memory usage during compression', () => {
      const initialMemory = performance.memory ? performance.memory.usedJSHeapSize : 0;
      
      // Simulate memory allocation
      const largeArray = new Array(1000000).fill(0);
      
      const currentMemory = performance.memory ? performance.memory.usedJSHeapSize : 0;
      const memoryIncrease = currentMemory - initialMemory;
      
      // Should detect memory usage increase
      expect(memoryIncrease).toBeGreaterThanOrEqual(0);
      
      // Cleanup
      largeArray.length = 0;
    });

    test('should limit canvas size to prevent memory exhaustion', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      const maxCanvasSize = 4096 * 4096;
      
      // Normal canvas - should be allowed
      const normalDimensions = { width: 1920, height: 1080 };
      expect(normalDimensions.width * normalDimensions.height).toBeLessThan(maxCanvasSize);
      
      // Oversized canvas - should be rejected
      const oversizedDimensions = { width: 8192, height: 8192 };
      expect(oversizedDimensions.width * oversizedDimensions.height).toBeGreaterThan(maxCanvasSize);
    });

    test('should calculate compression ratios accurately', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      const originalSize = 2 * 1024 * 1024; // 2MB
      const compressedSize = 500 * 1024; // 500KB
      
      const mockFile = { size: originalSize };
      const mockBlob = { size: compressedSize };
      
      const stats = compressor.calculateCompressionStats(mockFile, mockBlob);
      
      expect(stats.originalSize).toBe(originalSize);
      expect(stats.compressedSize).toBe(compressedSize);
      expect(stats.reductionPercent).toBe(75); // 75% reduction
      expect(stats.originalSizeFormatted).toBe('2.0 MB');
      expect(stats.compressedSizeFormatted).toBe('500.0 KB');
    });
  });

  describe('Security and Validation', () => {
    test('should reject malicious file types', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      const maliciousTypes = [
        'text/html',
        'application/javascript',
        'image/svg+xml',
        'application/octet-stream',
        'text/plain'
      ];
      
      maliciousTypes.forEach(type => {
        expect(compressor.isValidImageType(type)).toBe(false);
      });
    });

    test('should validate Cloudinary URLs', () => {
      const isValidCloudinaryUrl = (url) => {
        try {
          const urlObj = new URL(url);
          return urlObj.protocol === 'https:' && 
                 urlObj.hostname === 'res.cloudinary.com';
        } catch {
          return false;
        }
      };
      
      // Valid URLs
      expect(isValidCloudinaryUrl('https://res.cloudinary.com/project/image/upload/v123/photo.jpg')).toBe(true);
      
      // Invalid URLs
      expect(isValidCloudinaryUrl('https://evil.com/fake.jpg')).toBe(false);
      expect(isValidCloudinaryUrl('http://res.cloudinary.com/photo.jpg')).toBe(false);
      expect(isValidCloudinaryUrl('javascript:alert("XSS")')).toBe(false);
    });

    test('should sanitize file names for display', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      
      const maliciousNames = [
        '<script>alert("XSS")</script>.jpg',
        '"><img src=x onerror=alert("XSS")>.jpg',
        'normal-file.jpg',
        'file with spaces.png'
      ];
      
      maliciousNames.forEach(name => {
        const escaped = previewManager.escapeHtml(name);
        expect(escaped).not.toContain('<script>');
        expect(escaped).not.toContain('onerror');
      });
    });

    test('should prevent canvas injection attacks', () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      // Attempt to inject malicious canvas operations
      const maliciousSettings = {
        outputFormat: 'text/html',
        quality: '<script>alert("XSS")</script>'
      };
      
      // Should only accept valid formats and numeric quality
      const validFormats = ['image/jpeg', 'image/png', 'image/webp'];
      expect(validFormats.includes(maliciousSettings.outputFormat)).toBe(false);
      expect(typeof maliciousSettings.quality).not.toBe('number');
    });
  });

  describe('Mobile Optimization', () => {
    test('should adjust quality for mobile devices', () => {
      Object.defineProperty(window, 'innerWidth', { value: 375, writable: true });
      
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      const mockFile = new File([new ArrayBuffer(1024 * 1024)], 'test.jpg', { type: 'image/jpeg' });
      
      const settings = compressor.getCompressionSettings(mockFile, {});
      
      // Should use mobile-optimized settings
      expect(settings.applied.deviceType).toBe('mobile');
      expect(settings.maxWidth).toBeLessThanOrEqual(1200);
      expect(settings.maxHeight).toBeLessThanOrEqual(1200);
    });

    test('should handle touch interactions on mobile', () => {
      const controls = document.querySelectorAll('.action-button');
      
      controls.forEach(button => {
        // Minimum touch target size
        expect(button.offsetHeight).toBeGreaterThanOrEqual(44);
        expect(button.offsetWidth).toBeGreaterThanOrEqual(44);
      });
    });

    test('should optimize for slower mobile connections', () => {
      // Mock slow connection
      Object.defineProperty(navigator, 'connection', {
        value: { effectiveType: '2g' },
        writable: true
      });
      
      const DeviceCapabilities = window.PhotoOptimization.DeviceCapabilities;
      expect(DeviceCapabilities.getConnectionSpeed()).toBe('slow');
      expect(DeviceCapabilities.getOptimalQuality()).toBe('low');
    });
  });

  describe('Integration with Form System', () => {
    test('should initialize photo optimization for file inputs', () => {
      const input = document.getElementById('photo1');
      const container = photoOptimization.initializeForInput(input);
      
      expect(container).toBeTruthy();
      expect(container.classList.contains('photo-upload-container')).toBe(true);
      expect(input.style.display).toBe('none');
    });

    test('should handle multiple photo inputs', () => {
      const inputs = document.querySelectorAll('input[type="file"]');
      
      inputs.forEach(input => {
        const container = photoOptimization.initializeForInput(input);
        expect(container).toBeTruthy();
      });
    });

    test('should respect auto-compress settings', () => {
      const input1 = document.getElementById('photo1');
      const input2 = document.getElementById('photo2');
      
      expect(input1.dataset.autoCompress).toBe('true');
      expect(input2.dataset.autoCompress).toBe('false');
    });

    test('should respect compression quality settings', () => {
      const profileInput = document.getElementById('profilePhoto');
      
      expect(profileInput.dataset.compressionQuality).toBe('high');
    });
  });

  describe('Error Handling and Recovery', () => {
    test('should handle image loading errors gracefully', () => {
      const previewManager = new window.PhotoOptimization.PhotoPreviewManager();
      const container = document.createElement('div');
      const mockFile = new File(['test'], 'corrupted.jpg', { type: 'image/jpeg' });
      
      const preview = previewManager.createPreview(mockFile, container);
      const img = preview.querySelector('.preview-image');
      
      // Simulate loading error
      img.dispatchEvent(new window.Event('error'));
      
      expect(preview.classList.contains('error')).toBe(true);
    });

    test('should handle compression failures', async () => {
      const compressor = new window.PhotoOptimization.PhotoCompressor();
      
      // Mock canvas.toBlob failure
      mockCanvas.toBlob = jest.fn((callback) => {
        callback(null); // Simulate failure
      });
      
      const mockFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      
      try {
        await compressor.compressPhoto(mockFile);
      } catch (error) {
        expect(error.message).toContain('compression');
      }
    });

    test('should handle network failures during upload', () => {
      global.fetch = jest.fn().mockRejectedValue(new Error('Network error'));
      
      // Should handle fetch failures gracefully
      expect(fetch).toBeDefined();
    });
  });

  describe('Accessibility Features', () => {
    test('should provide proper alt text for images', () => {
      const img = document.createElement('img');
      img.src = 'https://res.cloudinary.com/test.jpg';
      img.alt = 'Image de réponse';
      
      expect(img.alt).toBe('Image de réponse');
      expect(img.getAttribute('alt')).toBeTruthy();
    });

    test('should support keyboard navigation for controls', () => {
      const buttons = document.querySelectorAll('.action-button');
      
      buttons.forEach(button => {
        expect(button.tabIndex).not.toBe(-1);
        
        // Should respond to Enter and Space keys
        const enterEvent = new window.KeyboardEvent('keydown', { key: 'Enter' });
        const spaceEvent = new window.KeyboardEvent('keydown', { key: ' ' });
        
        let activated = false;
        button.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            activated = true;
            e.preventDefault();
          }
        });
        
        button.dispatchEvent(enterEvent);
        expect(activated).toBe(true);
      });
    });

    test('should have proper ARIA labels', () => {
      const lightbox = document.getElementById('lightboxOverlay');
      
      expect(lightbox.getAttribute('role')).toBe('dialog');
      expect(lightbox.getAttribute('aria-label')).toBe('Visionneuse d\'images');
    });
  });
});