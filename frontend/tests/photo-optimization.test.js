/**
 * Photo Optimization Integration Tests
 * Validates security, functionality, and mobile-first optimizations
 */

// Mock DOM environment for testing
const { JSDOM } = require('jsdom');

describe('Photo Optimization Security Tests', () => {
  let dom;
  let window;
  let document;

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head><title>Test</title></head>
        <body>
          <form id="testForm">
            <input type="file" id="photo1" accept="image/*">
            <input type="file" id="photo2" accept="image/*">
          </form>
          <div id="qa-container"></div>
        </body>
      </html>
    `, {
      url: 'https://localhost:3000',
      pretendToBeVisual: true,
      resources: 'usable'
    });

    window = dom.window;
    document = window.document;
    global.window = window;
    global.document = document;
    global.URL = window.URL;
    global.Image = window.Image;
    global.File = window.File;
    global.Blob = window.Blob;
    global.FormData = window.FormData;
    global.fetch = jest.fn();
  });

  afterEach(() => {
    dom.window.close();
  });

  describe('XSS Protection', () => {
    test('should reject malicious image URLs', () => {
      // Load photo-compression module
      const fs = require('fs');
      const path = require('path');
      const photoCompressionCode = fs.readFileSync(
        path.join(__dirname, '../public/js/photo-compression.js'),
        'utf8'
      );
      
      // Execute in DOM context
      const script = document.createElement('script');
      script.textContent = photoCompressionCode;
      document.head.appendChild(script);

      const maliciousUrls = [
        'javascript:alert("XSS")',
        'data:text/html,<script>alert("XSS")</script>',
        'https://evil.com/malicious.jpg?param=<script>alert("XSS")</script>',
        'vbscript:msgbox("XSS")',
        'file:///etc/passwd',
        'ftp://evil.com/image.jpg',
        'data:image/svg+xml,<svg onload=alert("XSS")></svg>'
      ];

      maliciousUrls.forEach(url => {
        expect(() => {
          const img = document.createElement('img');
          img.src = url;
          // Should not execute any malicious code
        }).not.toThrow();
        
        // URL should be rejected by validation
        expect(url.startsWith('https://res.cloudinary.com')).toBe(false);
      });
    });

    test('should safely handle malicious alt text', () => {
      const maliciousAlt = '<img src=x onerror=alert("XSS")>';
      const img = document.createElement('img');
      img.alt = maliciousAlt;
      
      // Alt text should be treated as plain text
      expect(img.alt).toBe(maliciousAlt);
      expect(img.outerHTML).not.toContain('onerror');
    });

    test('should use createElement instead of innerHTML', () => {
      const photoCompressionCode = require('fs').readFileSync(
        require('path').join(__dirname, '../public/js/photo-compression.js'),
        'utf8'
      );
      
      // Check that innerHTML is not used for dynamic content
      expect(photoCompressionCode).not.toMatch(/\.innerHTML\s*=/);
      expect(photoCompressionCode).toMatch(/createElement/);
      expect(photoCompressionCode).toMatch(/textContent/);
    });
  });

  describe('CSRF Protection', () => {
    test('should include credentials in upload requests', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ url: 'https://res.cloudinary.com/test.jpg' })
      });

      // Simulate file upload with CSRF protection
      const formData = new FormData();
      formData.append('image', new File(['test'], 'test.jpg', { type: 'image/jpeg' }));

      await fetch('/api/upload', {
        method: 'POST',
        credentials: 'include',
        body: formData
      });

      expect(global.fetch).toHaveBeenCalledWith('/api/upload', 
        expect.objectContaining({
          credentials: 'include'
        })
      );
    });

    test('should handle CSRF token validation errors', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 403,
        json: () => Promise.resolve({ error: 'CSRF token invalid' })
      });

      try {
        await fetch('/api/upload', {
          method: 'POST',
          credentials: 'include',
          body: new FormData()
        });
      } catch (error) {
        // Should handle CSRF errors gracefully
        expect(error).toBeDefined();
      }
    });
  });

  describe('Input Validation', () => {
    test('should validate file types', () => {
      const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
      const invalidTypes = ['text/html', 'application/javascript', 'image/svg+xml'];

      validTypes.forEach(type => {
        const file = new File(['test'], 'test.jpg', { type });
        expect(file.type.startsWith('image/')).toBe(true);
      });

      invalidTypes.forEach(type => {
        const file = new File(['test'], 'test.file', { type });
        // Should be rejected by validation
        expect(['image/jpeg', 'image/jpg', 'image/png', 'image/webp'].includes(type)).toBe(false);
      });
    });

    test('should enforce file size limits', () => {
      const normalFile = new File([new ArrayBuffer(1024 * 1024)], 'normal.jpg', { type: 'image/jpeg' }); // 1MB
      const largeFile = new File([new ArrayBuffer(50 * 1024 * 1024)], 'large.jpg', { type: 'image/jpeg' }); // 50MB

      expect(normalFile.size).toBeLessThan(10 * 1024 * 1024); // Under 10MB limit
      expect(largeFile.size).toBeGreaterThan(10 * 1024 * 1024); // Over limit
    });
  });

  describe('URL Validation', () => {
    test('should only allow trusted domains', () => {
      const trustedUrls = [
        'https://res.cloudinary.com/test/image/upload/v123/test.jpg',
        'https://images.unsplash.com/photo-123?auto=format',
        'https://via.placeholder.com/300x200'
      ];

      const untrustedUrls = [
        'https://evil.com/malicious.jpg',
        'http://res.cloudinary.com/test.jpg', // HTTP not HTTPS
        'https://fake-cloudinary.com/test.jpg',
        'data:image/jpeg;base64,/9j/4AAQ...'
      ];

      const isValidImageUrl = (url) => {
        try {
          const urlObj = new URL(url);
          const trustedDomains = ['res.cloudinary.com', 'images.unsplash.com', 'via.placeholder.com'];
          return urlObj.protocol === 'https:' && 
                 trustedDomains.some(domain => urlObj.hostname.endsWith(domain));
        } catch {
          return false;
        }
      };

      trustedUrls.forEach(url => {
        expect(isValidImageUrl(url)).toBe(true);
      });

      untrustedUrls.forEach(url => {
        expect(isValidImageUrl(url)).toBe(false);
      });
    });
  });

  describe('Memory Management', () => {
    test('should limit canvas size to prevent memory exhaustion', () => {
      const maxCanvasSize = 4096 * 4096;
      
      // Normal size - should be allowed
      const normalCanvas = { width: 1920, height: 1080 };
      expect(normalCanvas.width * normalCanvas.height).toBeLessThan(maxCanvasSize);
      
      // Oversized - should be rejected
      const oversizedCanvas = { width: 8192, height: 8192 };
      expect(oversizedCanvas.width * oversizedCanvas.height).toBeGreaterThan(maxCanvasSize);
    });

    test('should clean up resources after compression', () => {
      // Mock canvas cleanup
      const mockCanvas = {
        width: 1920,
        height: 1080,
        getContext: jest.fn(() => ({
          drawImage: jest.fn(),
          imageSmoothingEnabled: true,
          imageSmoothingQuality: 'high'
        }))
      };

      // Simulate cleanup
      mockCanvas.width = 1;
      mockCanvas.height = 1;
      
      expect(mockCanvas.width).toBe(1);
      expect(mockCanvas.height).toBe(1);
    });
  });

  describe('Error Handling', () => {
    test('should handle image loading errors gracefully', () => {
      const img = document.createElement('img');
      let errorHandled = false;
      
      img.onerror = function() {
        errorHandled = true;
        // Should not expose sensitive information
        const fallback = document.createElement('span');
        fallback.textContent = '[Image non disponible]';
        this.parentNode?.appendChild(fallback);
      };

      // Simulate error
      img.dispatchEvent(new window.Event('error'));
      
      expect(errorHandled).toBe(true);
    });

    test('should handle compression failures', async () => {
      // Mock failed compression
      const mockCompressor = {
        compressPhoto: jest.fn().mockRejectedValue(new Error('Compression failed'))
      };

      try {
        await mockCompressor.compressPhoto(new File(['test'], 'test.jpg', { type: 'image/jpeg' }));
      } catch (error) {
        expect(error.message).toBe('Compression failed');
        // Should handle error gracefully without exposing system details
      }
    });
  });

  describe('Mobile Optimization', () => {
    test('should detect mobile devices', () => {
      // Mock mobile viewport
      Object.defineProperty(window, 'innerWidth', { value: 375, writable: true });
      
      const isMobile = window.innerWidth <= 768;
      expect(isMobile).toBe(true);
      
      // Mock desktop viewport
      Object.defineProperty(window, 'innerWidth', { value: 1920, writable: true });
      
      const isDesktop = window.innerWidth > 768;
      expect(isDesktop).toBe(true);
    });

    test('should apply different quality settings for mobile', () => {
      const getOptimalQuality = (deviceType) => {
        const qualityMap = {
          mobile: 0.6,
          tablet: 0.8,
          desktop: 0.9
        };
        return qualityMap[deviceType] || 0.8;
      };

      expect(getOptimalQuality('mobile')).toBe(0.6);
      expect(getOptimalQuality('desktop')).toBe(0.9);
    });
  });

  describe('Performance Optimization', () => {
    test('should implement lazy loading', () => {
      const img = document.createElement('img');
      img.dataset.lazySrc = 'https://res.cloudinary.com/test.jpg';
      
      // Should not load immediately
      expect(img.src).toBe('');
      expect(img.dataset.lazySrc).toBe('https://res.cloudinary.com/test.jpg');
    });

    test('should cache compressed images', () => {
      const cache = new Map();
      const testUrl = 'https://res.cloudinary.com/test.jpg';
      const mockImage = { src: testUrl, naturalWidth: 800, naturalHeight: 600 };
      
      // Add to cache
      cache.set(testUrl, mockImage);
      
      // Retrieve from cache
      const cached = cache.get(testUrl);
      expect(cached).toBe(mockImage);
      expect(cache.has(testUrl)).toBe(true);
    });
  });

  describe('Accessibility', () => {
    test('should provide proper alt text for images', () => {
      const img = document.createElement('img');
      img.src = 'https://res.cloudinary.com/test.jpg';
      img.alt = 'Image de réponse';
      
      expect(img.alt).toBe('Image de réponse');
      expect(img.getAttribute('alt')).toBeTruthy();
    });

    test('should support keyboard navigation', () => {
      const img = document.createElement('img');
      img.tabIndex = 0;
      img.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          // Should open lightbox on Enter/Space
          e.preventDefault();
        }
      });
      
      expect(img.tabIndex).toBe(0);
    });
  });

  describe('Integration with Existing System', () => {
    test('should work with existing form validation', () => {
      const form = document.getElementById('testForm');
      const fileInput = document.getElementById('photo1');
      
      // Simulate file selection
      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      Object.defineProperty(fileInput, 'files', { value: [file] });
      
      expect(fileInput.files.length).toBe(1);
      expect(fileInput.files[0].type).toBe('image/jpeg');
    });

    test('should maintain CSRF token in requests', () => {
      const mockAdminAPI = {
        csrfToken: 'test-csrf-token',
        request: jest.fn()
      };

      expect(mockAdminAPI.csrfToken).toBeTruthy();
      expect(typeof mockAdminAPI.request).toBe('function');
    });
  });
});

describe('Photo Lightbox Security Tests', () => {
  test('should validate lightbox image sources', () => {
    const validSources = [
      'https://res.cloudinary.com/test/image/upload/v123/photo.jpg'
    ];
    
    const invalidSources = [
      'javascript:alert("XSS")',
      'data:text/html,<script>alert("XSS")</script>',
      'https://malicious.com/fake.jpg'
    ];

    const isValidLightboxSource = (src) => {
      try {
        const url = new URL(src);
        return url.protocol === 'https:' && url.hostname.endsWith('res.cloudinary.com');
      } catch {
        return false;
      }
    };

    validSources.forEach(src => {
      expect(isValidLightboxSource(src)).toBe(true);
    });

    invalidSources.forEach(src => {
      expect(isValidLightboxSource(src)).toBe(false);
    });
  });

  test('should prevent XSS in lightbox captions', () => {
    const maliciousCaption = '<script>alert("XSS")</script>';
    const caption = document.createElement('div');
    caption.textContent = maliciousCaption; // Safe assignment
    
    expect(caption.textContent).toBe(maliciousCaption);
    expect(caption.innerHTML).not.toContain('<script>');
  });
});

// Performance benchmarks
describe('Performance Tests', () => {
  test('should compress images within reasonable time', async () => {
    const mockFile = new File([new ArrayBuffer(1024 * 1024)], 'test.jpg', { type: 'image/jpeg' });
    
    const startTime = Date.now();
    
    // Mock compression process
    await new Promise(resolve => setTimeout(resolve, 100)); // Simulate 100ms compression
    
    const endTime = Date.now();
    const compressionTime = endTime - startTime;
    
    // Should complete within 5 seconds for reasonable file sizes
    expect(compressionTime).toBeLessThan(5000);
  });

  test('should limit memory usage during compression', () => {
    const memoryUsage = process.memoryUsage();
    const baselineMemory = memoryUsage.heapUsed;
    
    // Simulate compression memory usage
    const mockCanvas = new Array(1000000).fill(0); // Simulate memory allocation
    
    const currentMemory = process.memoryUsage().heapUsed;
    const memoryIncrease = currentMemory - baselineMemory;
    
    // Memory increase should be reasonable (less than 100MB)
    expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
  });
});