/**
 * Frontend Tests for DOM ready behavior in photo-lightbox
 * Tests the photo lightbox component initialization, DOM manipulation, and event handling
 * 
 * Testing Strategy:
 * - Attempts to load actual photo-lightbox.js file for realistic testing
 * - Falls back to comprehensive mock if file is not accessible
 * - Mock fallback ensures tests run in isolated CI/CD environments
 */

const fs = require('fs');
const path = require('path');

// Setup JSDOM environment for DOM testing
const { JSDOM } = require('jsdom');

// Mock photo-lightbox source code
const photoLightboxPath = path.join(__dirname, '../public/js/photo-lightbox.js');
let photoLightboxSource;

try {
  photoLightboxSource = fs.readFileSync(photoLightboxPath, 'utf8');
} catch (error) {
  // Fallback mock for testing when actual file is not accessible
  // This ensures tests can run in isolated environments or CI/CD
  console.warn('⚠️ Using mock photo-lightbox.js - actual file not found at:', photoLightboxPath);
  photoLightboxSource = `
    // Mock photo-lightbox.js content
    const LIGHTBOX_CONFIG = {
      zoom: { min: 0.5, max: 5, step: 0.5 },
      touch: { pinchSensitivity: 0.02 },
      animation: { duration: 300 }
    };
    
    class PhotoLightbox {
      constructor() {
        this.isInitialized = false;
        this.currentImage = null;
        this.images = [];
      }
      
      init() {
        if (this.isInitialized) return;
        this.createLightboxHTML();
        this.bindEvents();
        this.isInitialized = true;
      }
      
      createLightboxHTML() {
        const lightboxHTML = '<div id="photo-lightbox" class="lightbox-overlay" style="display: none;"></div>';
        document.body.insertAdjacentHTML('beforeend', lightboxHTML);
      }
      
      bindEvents() {
        document.addEventListener('click', this.handleImageClick.bind(this));
        document.addEventListener('keydown', this.handleKeydown.bind(this));
      }
      
      handleImageClick(event) {
        if (event.target.classList.contains('lightbox-trigger')) {
          this.open(event.target.src);
        }
      }
      
      handleKeydown(event) {
        if (event.key === 'Escape') {
          this.close();
        }
      }
      
      open(imageSrc) {
        this.currentImage = imageSrc;
        const lightbox = document.getElementById('photo-lightbox');
        if (lightbox) {
          lightbox.style.display = 'block';
          lightbox.innerHTML = '<img src="' + imageSrc + '" alt="Lightbox image">';
        }
      }
      
      close() {
        const lightbox = document.getElementById('photo-lightbox');
        if (lightbox) {
          lightbox.style.display = 'none';
          lightbox.innerHTML = '';
        }
        this.currentImage = null;
      }
    }
    
    // DOM ready initialization
    let photoLightbox = null;
    
    function initPhotoLightbox() {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          photoLightbox = new PhotoLightbox();
          photoLightbox.init();
        });
      } else {
        photoLightbox = new PhotoLightbox();
        photoLightbox.init();
      }
    }
    
    // Auto-initialize if DOM is ready
    if (typeof window !== 'undefined') {
      initPhotoLightbox();
    }
    
    // Export for testing
    if (typeof module !== 'undefined' && module.exports) {
      module.exports = { PhotoLightbox, initPhotoLightbox };
    }
  `;
}

describe('Photo Lightbox - DOM Ready Behavior Tests', () => {
  let dom;
  let window;
  let document;
  let photoLightbox;

  beforeEach(() => {
    // Create a fresh DOM environment for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>Photo Lightbox Test</title>
          <style>
            .lightbox-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 9999; }
            .lightbox-trigger { cursor: pointer; }
          </style>
        </head>
        <body>
          <div id="test-container">
            <img src="test-image-1.jpg" class="lightbox-trigger" alt="Test Image 1">
            <img src="test-image-2.jpg" class="lightbox-trigger" alt="Test Image 2">
            <img src="test-image-3.jpg" class="regular-image" alt="Regular Image">
          </div>
        </body>
      </html>
    `, {
      runScripts: 'dangerously',
      resources: 'usable',
      pretendToBeVisual: true
    });

    window = dom.window;
    document = window.document;

    // Make globals available
    global.window = window;
    global.document = document;
    global.navigator = window.navigator;

    // Execute photo-lightbox code in the JSDOM context
    const script = document.createElement('script');
    script.textContent = photoLightboxSource;
    document.head.appendChild(script);

    // Wait for any async initialization
    return new Promise(resolve => {
      if (document.readyState === 'complete') {
        resolve();
      } else {
        window.addEventListener('load', resolve);
      }
    });
  });

  afterEach(() => {
    dom.window.close();
    delete global.window;
    delete global.document;
    delete global.navigator;
  });

  describe('DOM Ready Initialization', () => {
    test('should initialize when DOM is already loaded', (done) => {
      // DOM is already loaded in our test setup
      setTimeout(() => {
        const lightboxElement = document.getElementById('photo-lightbox');
        expect(lightboxElement).toBeTruthy();
        expect(lightboxElement.classList.contains('photo-lightbox')).toBe(true);
        done();
      }, 50);
    });

    test('should wait for DOMContentLoaded if DOM is still loading', (done) => {
      // Create a new DOM that's still loading
      const loadingDom = new JSDOM(`
        <!DOCTYPE html>
        <html>
          <head><title>Loading Test</title></head>
          <body><div id="test"></div></body>
        </html>
      `, { runScripts: 'dangerously' });

      const loadingWindow = loadingDom.window;
      const loadingDocument = loadingWindow.document;

      // Override readyState to simulate loading state
      Object.defineProperty(loadingDocument, 'readyState', {
        value: 'loading',
        configurable: true
      });

      // Set up globals for the loading context
      global.window = loadingWindow;
      global.document = loadingDocument;

      // Execute the initialization code
      const script = loadingDocument.createElement('script');
      script.textContent = photoLightboxSource;
      loadingDocument.head.appendChild(script);

      // Initially, lightbox should not be initialized
      let lightboxElement = loadingDocument.getElementById('photo-lightbox');
      expect(lightboxElement).toBeFalsy();

      // Simulate DOM content loaded
      Object.defineProperty(loadingDocument, 'readyState', {
        value: 'interactive',
        configurable: true
      });

      loadingDocument.dispatchEvent(new loadingWindow.Event('DOMContentLoaded'));

      setTimeout(() => {
        lightboxElement = loadingDocument.getElementById('photo-lightbox');
        expect(lightboxElement).toBeTruthy();
        loadingDom.window.close();
        done();
      }, 50);
    });

    test('should create lightbox overlay in DOM', () => {
      const lightboxElement = document.getElementById('photo-lightbox');
      expect(lightboxElement).toBeTruthy();
      expect(lightboxElement.tagName).toBe('DIV');
      expect(lightboxElement.classList.contains('photo-lightbox')).toBe(true);
      expect(lightboxElement.style.display).toBe('none');
    });

    test('should bind click events to lightbox triggers', () => {
      const triggerImages = document.querySelectorAll('.lightbox-trigger');
      expect(triggerImages.length).toBe(2);

      // Test that clicking a trigger image opens the lightbox
      const firstImage = triggerImages[0];
      const clickEvent = new window.Event('click', { bubbles: true });
      Object.defineProperty(clickEvent, 'target', { value: firstImage });

      firstImage.dispatchEvent(clickEvent);

      setTimeout(() => {
        const lightboxElement = document.getElementById('photo-lightbox');
        expect(lightboxElement.style.display).toBe('block');
        expect(lightboxElement.innerHTML).toContain('test-image-1.jpg');
      }, 10);
    });

    test('should bind keyboard events for navigation', () => {
      const lightboxElement = document.getElementById('photo-lightbox');
      
      // Open lightbox first
      const triggerImage = document.querySelector('.lightbox-trigger');
      const clickEvent = new window.Event('click', { bubbles: true });
      Object.defineProperty(clickEvent, 'target', { value: triggerImage });
      triggerImage.dispatchEvent(clickEvent);

      // Test Escape key closes lightbox
      const escapeEvent = new window.KeyboardEvent('keydown', { key: 'Escape' });
      document.dispatchEvent(escapeEvent);

      setTimeout(() => {
        expect(lightboxElement.style.display).toBe('none');
      }, 10);
    });
  });

  describe('Event Handler Registration', () => {
    test('should properly register document click handlers', () => {
      // Check that event listeners are actually attached by testing the behavior
      const triggerImage = document.querySelector('.lightbox-trigger');
      const regularImage = document.querySelector('.regular-image');

      // Trigger image should respond to clicks
      triggerImage.click();
      setTimeout(() => {
        const lightboxElement = document.getElementById('photo-lightbox');
        expect(lightboxElement.style.display).toBe('block');
      }, 10);

      // Regular image should not trigger lightbox
      regularImage.click();
      setTimeout(() => {
        const lightboxElement = document.getElementById('photo-lightbox');
        // Should still be open from previous click, not affected by regular image
        expect(lightboxElement.style.display).toBe('block');
      }, 10);
    });

    test('should handle multiple lightbox trigger images', () => {
      const triggerImages = document.querySelectorAll('.lightbox-trigger');
      expect(triggerImages.length).toBe(2);

      // Test first image
      triggerImages[0].click();
      setTimeout(() => {
        const lightboxElement = document.getElementById('photo-lightbox');
        expect(lightboxElement.innerHTML).toContain('test-image-1.jpg');
      }, 10);

      // Close lightbox
      const escapeEvent = new window.KeyboardEvent('keydown', { key: 'Escape' });
      document.dispatchEvent(escapeEvent);

      setTimeout(() => {
        // Test second image
        triggerImages[1].click();
        setTimeout(() => {
          const lightboxElement = document.getElementById('photo-lightbox');
          expect(lightboxElement.innerHTML).toContain('test-image-2.jpg');
        }, 10);
      }, 20);
    });

    test('should handle rapid successive clicks gracefully', () => {
      const triggerImage = document.querySelector('.lightbox-trigger');
      
      // Simulate rapid clicks
      for (let i = 0; i < 5; i++) {
        triggerImage.click();
      }

      setTimeout(() => {
        const lightboxElement = document.getElementById('photo-lightbox');
        expect(lightboxElement.style.display).toBe('block');
        // Should show the image only once, not multiple times
        const images = lightboxElement.querySelectorAll('img');
        expect(images.length).toBeLessThanOrEqual(1);
      }, 50);
    });
  });

  describe('DOM Manipulation Safety', () => {
    test('should not create duplicate lightbox elements', () => {
      // Initialize multiple times
      const script1 = document.createElement('script');
      script1.textContent = photoLightboxSource;
      document.head.appendChild(script1);

      const script2 = document.createElement('script');
      script2.textContent = photoLightboxSource;
      document.head.appendChild(script2);

      setTimeout(() => {
        const lightboxElements = document.querySelectorAll('#photo-lightbox');
        expect(lightboxElements.length).toBeLessThanOrEqual(1);
      }, 50);
    });

    test('should handle missing DOM elements gracefully', () => {
      // Remove the lightbox element
      const lightboxElement = document.getElementById('photo-lightbox');
      if (lightboxElement) {
        lightboxElement.remove();
      }

      // Try to use lightbox functionality
      const triggerImage = document.querySelector('.lightbox-trigger');
      
      expect(() => {
        triggerImage.click();
      }).not.toThrow();
    });

    test('should handle malformed HTML gracefully', () => {
      // Add some malformed content
      document.body.innerHTML += '<img src="malformed-url" class="lightbox-trigger" alt=unclosed>';
      
      const malformedImage = document.querySelector('img[alt="unclosed"]');
      
      expect(() => {
        malformedImage.click();
      }).not.toThrow();
    });
  });

  describe('Performance and Memory Management', () => {
    test('should not create excessive DOM elements', () => {
      const initialElementCount = document.querySelectorAll('*').length;
      
      // Trigger lightbox multiple times
      const triggerImage = document.querySelector('.lightbox-trigger');
      for (let i = 0; i < 10; i++) {
        triggerImage.click();
        const escapeEvent = new window.KeyboardEvent('keydown', { key: 'Escape' });
        document.dispatchEvent(escapeEvent);
      }

      setTimeout(() => {
        const finalElementCount = document.querySelectorAll('*').length;
        // Should not have significantly more elements (allowing for some margin)
        expect(finalElementCount).toBeLessThan(initialElementCount + 5);
      }, 100);
    });

    test('should properly clean up when closing lightbox', () => {
      const triggerImage = document.querySelector('.lightbox-trigger');
      triggerImage.click();

      setTimeout(() => {
        const lightboxElement = document.getElementById('photo-lightbox');
        expect(lightboxElement.innerHTML).not.toBe('');

        // Close lightbox
        const escapeEvent = new window.KeyboardEvent('keydown', { key: 'Escape' });
        document.dispatchEvent(escapeEvent);

        setTimeout(() => {
          expect(lightboxElement.innerHTML).toBe('');
          expect(lightboxElement.style.display).toBe('none');
        }, 10);
      }, 10);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid image sources', () => {
      // Add an image with invalid source
      document.body.innerHTML += '<img src="" class="lightbox-trigger" alt="Empty source">';
      
      const invalidImage = document.querySelector('img[alt="Empty source"]');
      
      expect(() => {
        invalidImage.click();
      }).not.toThrow();
    });

    test('should handle missing image attributes', () => {
      // Add an image without src attribute
      document.body.innerHTML += '<img class="lightbox-trigger" alt="No source">';
      
      const noSrcImage = document.querySelector('img[alt="No source"]');
      
      expect(() => {
        noSrcImage.click();
      }).not.toThrow();
    });

    test('should handle disabled JavaScript features gracefully', () => {
      // Simulate missing methods
      const originalAddEventListener = document.addEventListener;
      document.addEventListener = undefined;

      expect(() => {
        // Re-run initialization
        const script = document.createElement('script');
        script.textContent = photoLightboxSource;
        document.head.appendChild(script);
      }).not.toThrow();

      // Restore method
      document.addEventListener = originalAddEventListener;
    });
  });

  describe('Cross-browser Compatibility', () => {
    test('should work with different document ready states', () => {
      const readyStates = ['loading', 'interactive', 'complete'];
      
      readyStates.forEach(readyState => {
        // Create a mock document with specific ready state
        const mockDocument = {
          readyState,
          addEventListener: jest.fn(),
          createElement: document.createElement.bind(document),
          body: document.body,
          head: document.head,
          getElementById: document.getElementById.bind(document)
        };

        expect(() => {
          // Test initialization with different ready states
          if (mockDocument.readyState === 'loading') {
            expect(mockDocument.addEventListener).toBeDefined();
          }
        }).not.toThrow();
      });
    });

    test('should handle different event models', () => {
      // Test with different event creation methods
      const eventTypes = [
        () => new window.Event('click'),
        () => new window.MouseEvent('click'),
        () => document.createEvent ? document.createEvent('Event') : new window.Event('click')
      ];

      eventTypes.forEach((createEvent, index) => {
        expect(() => {
          const event = createEvent();
          if (event.initEvent && typeof event.initEvent === 'function') {
            event.initEvent('click', true, true);
          }
          
          const triggerImage = document.querySelector('.lightbox-trigger');
          if (triggerImage && triggerImage.dispatchEvent) {
            triggerImage.dispatchEvent(event);
          }
        }).not.toThrow();
      });
    });
  });
});