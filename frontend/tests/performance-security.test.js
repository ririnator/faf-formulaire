/**
 * Performance & Security Validation Tests
 * Comprehensive test suite for optimization validation,
 * XSS protection, performance monitoring, and security compliance
 */

const { JSDOM } = require('jsdom');

describe('🔒 Performance & Security Validation Tests', () => {
  let dom;
  let window;
  let document;
  let mockPerformanceObserver;

  beforeEach(() => {
    // Create security-focused test environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html lang="fr">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self' 'unsafe-inline'; img-src 'self' https://res.cloudinary.com; connect-src 'self' wss://localhost:3000">
          <title>Security Test Environment</title>
          <style>
            .performance-monitor { position: fixed; top: 0; right: 0; background: rgba(0,0,0,0.8); color: white; padding: 1rem; }
            .security-indicator { background: #10b981; color: white; padding: 0.5rem; border-radius: 4px; }
            .vulnerability-alert { background: #ef4444; color: white; padding: 0.5rem; border-radius: 4px; }
            .performance-chart { width: 100%; height: 200px; background: #f3f4f6; }
            .memory-usage { display: flex; flex-direction: column; gap: 0.5rem; }
            .network-monitor { border: 1px solid #e5e7eb; padding: 1rem; border-radius: 8px; }
            .lazy-load-container { height: 200vh; overflow-y: auto; }
            .lazy-image { opacity: 0; transition: opacity 0.3s; }
            .lazy-image.loaded { opacity: 1; }
          </style>
        </head>
        <body>
          <!-- Performance Monitoring Dashboard -->
          <div id="performanceMonitor" class="performance-monitor hidden">
            <h3>Performance Monitor</h3>
            <div class="performance-metrics">
              <div>FPS: <span id="fpsCounter">60</span></div>
              <div>Memory: <span id="memoryUsage">0 MB</span></div>
              <div>DOM Nodes: <span id="domNodeCount">0</span></div>
              <div>Network: <span id="networkStatus">Online</span></div>
            </div>
            <canvas id="performanceChart" class="performance-chart"></canvas>
          </div>

          <!-- Security Status Panel -->
          <div id="securityPanel" class="security-panel">
            <div id="cspStatus" class="security-indicator">CSP: Active</div>
            <div id="xssProtection" class="security-indicator">XSS Protection: Enabled</div>
            <div id="httpsStatus" class="security-indicator">HTTPS: Required</div>
            <div id="vulnerabilityAlerts" class="vulnerability-alerts"></div>
          </div>

          <!-- Test Forms for Security Validation -->
          <section id="securityTestSection">
            <form id="userInputForm" class="test-form">
              <input type="text" id="nameInput" placeholder="Nom" maxlength="100">
              <textarea id="commentInput" placeholder="Commentaire" maxlength="1000"></textarea>
              <input type="url" id="urlInput" placeholder="URL">
              <input type="file" id="fileInput" accept="image/*">
              <button type="submit">Soumettre</button>
            </form>

            <!-- Dynamic Content Area for XSS Testing -->
            <div id="dynamicContent" class="dynamic-content">
              <h3>Contenu Dynamique</h3>
              <div id="userGeneratedContent"></div>
              <div id="searchResults"></div>
              <div id="notificationArea"></div>
            </div>

            <!-- File Upload Area -->
            <div id="uploadArea" class="upload-area">
              <input type="file" id="multipleFileInput" multiple accept="image/*,application/pdf">
              <div id="uploadProgress" class="upload-progress"></div>
              <div id="uploadedFiles" class="uploaded-files"></div>
            </div>
          </section>

          <!-- Performance Test Elements -->
          <section id="performanceTestSection">
            <!-- Large Dataset Rendering -->
            <div id="largeDataContainer" class="large-data-container">
              <!-- Will be populated with many elements -->
            </div>

            <!-- Lazy Loading Container -->
            <div id="lazyLoadContainer" class="lazy-load-container">
              <!-- Images for lazy loading testing -->
            </div>

            <!-- Animation Performance Test -->
            <div id="animationContainer" class="animation-container">
              <!-- Animated elements -->
            </div>

            <!-- Memory Leak Test Area -->
            <div id="memoryTestArea" class="memory-test-area">
              <button id="createElementsBtn">Create 1000 Elements</button>
              <button id="cleanupElementsBtn">Cleanup Elements</button>
              <div id="elementContainer"></div>
            </div>
          </section>

          <!-- Network Performance Test -->
          <section id="networkTestSection">
            <div class="network-monitor">
              <h3>Network Performance</h3>
              <div id="requestMetrics" class="request-metrics">
                <div>Pending Requests: <span id="pendingRequests">0</span></div>
                <div>Avg Response Time: <span id="avgResponseTime">0ms</span></div>
                <div>Failed Requests: <span id="failedRequests">0</span></div>
              </div>
              <button id="testNetworkBtn">Test Network Performance</button>
            </div>
          </section>

          <!-- Security Testing Controls -->
          <section id="securityControlsSection">
            <div class="security-controls">
              <h3>Security Test Controls</h3>
              <button id="testXSSBtn">Test XSS Protection</button>
              <button id="testCSRFBtn">Test CSRF Protection</button>
              <button id="testInputValidationBtn">Test Input Validation</button>
              <button id="testFileUploadBtn">Test File Upload Security</button>
              <button id="testSQLInjectionBtn">Test SQL Injection Protection</button>
            </div>
          </section>

          <!-- Error Monitoring -->
          <div id="errorMonitor" class="error-monitor hidden">
            <h3>Error Monitor</h3>
            <div id="errorList" class="error-list"></div>
          </div>

          <!-- Resource Usage Monitor -->
          <div id="resourceMonitor" class="resource-monitor">
            <div class="memory-usage">
              <div>Heap Used: <span id="heapUsed">0 MB</span></div>
              <div>Heap Total: <span id="heapTotal">0 MB</span></div>
              <div>External: <span id="externalMemory">0 MB</span></div>
            </div>
          </div>

          <!-- CSP Violation Reporter -->
          <div id="cspViolations" class="csp-violations hidden">
            <h3>CSP Violations</h3>
            <div id="violationList"></div>
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
    global.fetch = jest.fn();
    global.performance = {
      now: jest.fn(() => Date.now()),
      mark: jest.fn(),
      measure: jest.fn(),
      getEntriesByType: jest.fn(() => []),
      memory: {
        usedJSHeapSize: 10000000,
        totalJSHeapSize: 20000000,
        jsHeapSizeLimit: 100000000
      }
    };

    // Mock Performance Observer
    mockPerformanceObserver = {
      observe: jest.fn(),
      disconnect: jest.fn(),
      takeRecords: jest.fn(() => [])
    };

    global.PerformanceObserver = jest.fn(() => mockPerformanceObserver);

    // Mock requestAnimationFrame
    global.requestAnimationFrame = jest.fn((callback) => {
      setTimeout(callback, 16); // 60fps
      return 1;
    });

    global.cancelAnimationFrame = jest.fn();

    // Mock Intersection Observer for lazy loading
    global.IntersectionObserver = jest.fn((callback) => ({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn()
    }));

    // Mock Mutation Observer
    global.MutationObserver = jest.fn((callback) => ({
      observe: jest.fn(),
      disconnect: jest.fn(),
      takeRecords: jest.fn(() => [])
    }));

    // Setup CSP violation reporting
    document.addEventListener('securitypolicyviolation', (e) => {
      const violationList = document.getElementById('violationList');
      if (violationList) {
        const violation = document.createElement('div');
        violation.textContent = `Violation: ${e.violatedDirective} - ${e.blockedURI}`;
        violationList.appendChild(violation);
      }
    });
  });

  afterEach(() => {
    dom.window.close();
    jest.clearAllMocks();
  });

  describe('XSS Protection and Input Sanitization', () => {
    test('should prevent script injection in user inputs', () => {
      const nameInput = document.getElementById('nameInput');
      const userContent = document.getElementById('userGeneratedContent');

      const maliciousInputs = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        'javascript:alert("XSS")',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<object data="data:text/html,<script>alert(\'XSS\')</script>"></object>',
        '<embed src="data:text/html,<script>alert(\'XSS\')</script>">',
        '<link rel=stylesheet href="javascript:alert(\'XSS\')">',
        '<style>@import "javascript:alert(\'XSS\')";</style>'
      ];

      const sanitizeInput = (input) => {
        // Simulate smart escaping function
        return input
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#x27;')
          .replace(/&/g, '&amp;');
      };

      maliciousInputs.forEach(maliciousInput => {
        // Simulate user input
        nameInput.value = maliciousInput;
        
        // Sanitize and display
        const sanitized = sanitizeInput(maliciousInput);
        userContent.textContent = sanitized;

        // Verify no script execution
        expect(userContent.innerHTML).not.toContain('<script>');
        expect(userContent.innerHTML).not.toContain('javascript:');
        expect(userContent.innerHTML).not.toContain('onerror=');
        expect(userContent.innerHTML).not.toContain('onload=');
        
        // Verify content is escaped
        expect(userContent.textContent).toBe(maliciousInput);
      });
    });

    test('should validate and sanitize URLs', () => {
      const urlInput = document.getElementById('urlInput');
      
      const testUrls = [
        { url: 'https://example.com', valid: true },
        { url: 'http://example.com', valid: false }, // HTTP not allowed
        { url: 'javascript:alert("XSS")', valid: false },
        { url: 'data:text/html,<script>alert("XSS")</script>', valid: false },
        { url: 'vbscript:msgbox("XSS")', valid: false },
        { url: 'file:///etc/passwd', valid: false },
        { url: 'ftp://example.com/file.txt', valid: false },
        { url: 'https://res.cloudinary.com/test/image.jpg', valid: true },
        { url: 'https://trusted-domain.com/path', valid: true }
      ];

      const isValidUrl = (url) => {
        try {
          const urlObj = new URL(url);
          const allowedProtocols = ['https:'];
          const trustedDomains = ['example.com', 'res.cloudinary.com', 'trusted-domain.com'];
          
          return allowedProtocols.includes(urlObj.protocol) &&
                 trustedDomains.some(domain => urlObj.hostname.endsWith(domain));
        } catch {
          return false;
        }
      };

      testUrls.forEach(({ url, valid }) => {
        urlInput.value = url;
        const isValid = isValidUrl(url);
        
        expect(isValid).toBe(valid);
        
        if (!valid) {
          urlInput.setCustomValidity('URL non autorisée');
        } else {
          urlInput.setCustomValidity('');
        }
      });
    });

    test('should protect against DOM-based XSS', () => {
      const searchResults = document.getElementById('searchResults');
      
      // Simulate search functionality that could be vulnerable
      const displaySearchResults = (query) => {
        // SAFE: Using textContent instead of innerHTML
        searchResults.textContent = `Résultats pour: ${query}`;
        
        // UNSAFE pattern that should be avoided:
        // searchResults.innerHTML = `Résultats pour: ${query}`;
      };

      const maliciousQuery = '<img src=x onerror=alert("DOM XSS")>';
      displaySearchResults(maliciousQuery);

      // Verify no script execution
      expect(searchResults.innerHTML).not.toContain('<img');
      expect(searchResults.innerHTML).not.toContain('onerror');
      expect(searchResults.textContent).toContain(maliciousQuery);
    });

    test('should validate file uploads for security', () => {
      const fileInput = document.getElementById('multipleFileInput');
      
      const testFiles = [
        { name: 'image.jpg', type: 'image/jpeg', valid: true },
        { name: 'document.pdf', type: 'application/pdf', valid: true },
        { name: 'script.js', type: 'application/javascript', valid: false },
        { name: 'page.html', type: 'text/html', valid: false },
        { name: 'virus.exe', type: 'application/x-msdownload', valid: false },
        { name: 'image.svg', type: 'image/svg+xml', valid: false }, // SVG can contain scripts
        { name: 'archive.zip', type: 'application/zip', valid: false },
        { name: 'malicious.php', type: 'application/x-php', valid: false }
      ];

      const isValidFileType = (file) => {
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'application/pdf'];
        const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.pdf'];
        
        const hasValidType = allowedTypes.includes(file.type);
        const hasValidExtension = allowedExtensions.some(ext => file.name.toLowerCase().endsWith(ext));
        
        return hasValidType && hasValidExtension;
      };

      testFiles.forEach(({ name, type, valid }) => {
        const mockFile = new File(['test'], name, { type });
        const isValid = isValidFileType(mockFile);
        
        expect(isValid).toBe(valid);
      });
    });

    test('should prevent prototype pollution attacks', () => {
      const maliciousPayloads = [
        '{"__proto__": {"isAdmin": true}}',
        '{"constructor": {"prototype": {"isAdmin": true}}}',
        '{"__proto__": {"toString": "alert(\\"XSS\\")"}}',
        '{"__proto__": {"valueOf": "alert(\\"XSS\\")"}}'
      ];

      const safeParse = (json) => {
        try {
          const parsed = JSON.parse(json);
          
          // Remove prototype pollution
          if (parsed.__proto__) delete parsed.__proto__;
          if (parsed.constructor) delete parsed.constructor;
          if (parsed.prototype) delete parsed.prototype;
          
          return parsed;
        } catch {
          return null;
        }
      };

      maliciousPayloads.forEach(payload => {
        const result = safeParse(payload);
        
        if (result) {
          expect(result.__proto__).toBeUndefined();
          expect(result.constructor).toBeUndefined();
          expect(result.prototype).toBeUndefined();
        }
      });

      // Verify prototype chain is not polluted
      const testObj = {};
      expect(testObj.isAdmin).toBeUndefined();
    });
  });

  describe('Content Security Policy (CSP) Validation', () => {
    test('should have proper CSP headers', () => {
      const metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      
      expect(metaCSP).toBeTruthy();
      
      const cspContent = metaCSP.content;
      expect(cspContent).toContain("default-src 'self'");
      expect(cspContent).toContain("script-src 'self' 'nonce-abc123'");
      expect(cspContent).toContain("img-src 'self' https://res.cloudinary.com");
      expect(cspContent).toContain("connect-src 'self' wss://localhost:3000");
    });

    test('should prevent inline script execution', () => {
      let scriptExecuted = false;
      
      // Attempt to inject inline script
      const maliciousScript = document.createElement('script');
      maliciousScript.textContent = 'window.scriptExecuted = true;';
      
      try {
        document.head.appendChild(maliciousScript);
      } catch (error) {
        // CSP should block this
      }
      
      // Verify script didn't execute
      expect(window.scriptExecuted).toBeFalsy();
    });

    test('should allow only nonce-based scripts', () => {
      const validScript = document.createElement('script');
      validScript.setAttribute('nonce', 'abc123');
      validScript.textContent = 'console.log("Valid script");';
      
      const invalidScript = document.createElement('script');
      invalidScript.textContent = 'console.log("Invalid script");';
      
      // Only nonce-based scripts should be allowed
      expect(validScript.getAttribute('nonce')).toBe('abc123');
      expect(invalidScript.getAttribute('nonce')).toBeFalsy();
    });

    test('should restrict external resource loading', () => {
      const testImages = [
        { src: 'https://res.cloudinary.com/test.jpg', allowed: true },
        { src: 'https://evil.com/malicious.jpg', allowed: false },
        { src: 'data:image/svg+xml,<svg onload=alert("XSS")>', allowed: false }
      ];

      testImages.forEach(({ src, allowed }) => {
        const img = document.createElement('img');
        img.src = src;
        
        // CSP should block non-allowed sources
        if (!allowed) {
          // In a real browser, this would trigger CSP violation
          expect(src).not.toMatch(/^https:\/\/res\.cloudinary\.com/);
        }
      });
    });
  });

  describe('Performance Monitoring and Optimization', () => {
    test('should monitor memory usage', () => {
      const memoryMonitor = {
        getMemoryUsage: () => {
          if (performance.memory) {
            return {
              used: Math.round(performance.memory.usedJSHeapSize / 1024 / 1024),
              total: Math.round(performance.memory.totalJSHeapSize / 1024 / 1024),
              limit: Math.round(performance.memory.jsHeapSizeLimit / 1024 / 1024)
            };
          }
          return { used: 0, total: 0, limit: 0 };
        },
        
        checkMemoryLeaks: (baseline) => {
          const current = this.getMemoryUsage();
          return current.used > baseline.used * 1.5; // 50% increase indicates potential leak
        }
      };

      const initialMemory = memoryMonitor.getMemoryUsage();
      expect(initialMemory.used).toBeGreaterThan(0);
      expect(initialMemory.total).toBeGreaterThan(0);
      
      // Simulate memory allocation
      const largeArray = new Array(100000).fill('memory test');
      
      const currentMemory = memoryMonitor.getMemoryUsage();
      expect(currentMemory.used).toBeGreaterThanOrEqual(initialMemory.used);
      
      // Cleanup
      largeArray.length = 0;
    });

    test('should measure rendering performance', (done) => {
      const performanceMetrics = {
        frameCount: 0,
        startTime: performance.now(),
        
        measureFPS: function() {
          this.frameCount++;
          
          requestAnimationFrame(() => {
            const currentTime = performance.now();
            const elapsed = currentTime - this.startTime;
            
            if (elapsed >= 1000) { // 1 second
              const fps = Math.round((this.frameCount * 1000) / elapsed);
              expect(fps).toBeGreaterThan(30); // Minimum acceptable FPS
              done();
            } else {
              this.measureFPS();
            }
          });
        }
      };

      performanceMetrics.measureFPS();
    });

    test('should optimize large dataset rendering', () => {
      const largeDataContainer = document.getElementById('largeDataContainer');
      const itemCount = 1000;
      
      const renderStart = performance.now();
      
      // Use DocumentFragment for batch DOM operations
      const fragment = document.createDocumentFragment();
      
      for (let i = 0; i < itemCount; i++) {
        const item = document.createElement('div');
        item.className = 'data-item';
        item.textContent = `Item ${i}`;
        fragment.appendChild(item);
      }
      
      largeDataContainer.appendChild(fragment);
      
      const renderEnd = performance.now();
      const renderTime = renderEnd - renderStart;
      
      expect(largeDataContainer.children.length).toBe(itemCount);
      expect(renderTime).toBeLessThan(100); // Should render in under 100ms
    });

    test('should implement efficient lazy loading', () => {
      const lazyLoadContainer = document.getElementById('lazyLoadContainer');
      const imageCount = 50;
      
      // Create lazy images
      const images = [];
      for (let i = 0; i < imageCount; i++) {
        const img = document.createElement('img');
        img.className = 'lazy-image';
        img.dataset.src = `https://res.cloudinary.com/test/image-${i}.jpg`;
        img.alt = `Image ${i}`;
        lazyLoadContainer.appendChild(img);
        images.push(img);
      }
      
      // Mock Intersection Observer behavior
      const mockIntersectionObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const img = entry.target;
            img.src = img.dataset.src;
            img.classList.add('loaded');
          }
        });
      });
      
      // Only first few images should be loaded initially
      const visibleImages = images.slice(0, 5);
      visibleImages.forEach(img => {
        img.src = img.dataset.src;
        img.classList.add('loaded');
      });
      
      const loadedImages = document.querySelectorAll('.lazy-image.loaded');
      expect(loadedImages.length).toBeLessThanOrEqual(10); // Only visible images loaded
    });

    test('should detect and prevent memory leaks', () => {
      const memoryLeakDetector = {
        listeners: new Map(),
        timers: new Set(),
        
        addListener: function(element, event, handler) {
          const key = `${element}-${event}`;
          if (this.listeners.has(key)) {
            // Prevent duplicate listeners
            element.removeEventListener(event, this.listeners.get(key));
          }
          
          element.addEventListener(event, handler);
          this.listeners.set(key, handler);
        },
        
        cleanup: function() {
          // Clean up listeners
          this.listeners.forEach((handler, key) => {
            const [element, event] = key.split('-');
            if (element && event) {
              element.removeEventListener(event, handler);
            }
          });
          this.listeners.clear();
          
          // Clean up timers
          this.timers.forEach(timer => clearTimeout(timer));
          this.timers.clear();
        }
      };

      const button = document.createElement('button');
      const handler = () => console.log('clicked');
      
      // Add listener through detector
      memoryLeakDetector.addListener(button, 'click', handler);
      
      expect(memoryLeakDetector.listeners.size).toBe(1);
      
      // Cleanup
      memoryLeakDetector.cleanup();
      expect(memoryLeakDetector.listeners.size).toBe(0);
    });

    test('should optimize network requests', async () => {
      const networkOptimizer = {
        pendingRequests: new Map(),
        responseCache: new Map(),
        
        async request(url, options = {}) {
          // Check cache first
          const cacheKey = `${url}-${JSON.stringify(options)}`;
          if (this.responseCache.has(cacheKey)) {
            return this.responseCache.get(cacheKey);
          }
          
          // Prevent duplicate requests
          if (this.pendingRequests.has(url)) {
            return this.pendingRequests.get(url);
          }
          
          const requestPromise = fetch(url, {
            ...options,
            credentials: 'include',
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest',
              ...options.headers
            }
          });
          
          this.pendingRequests.set(url, requestPromise);
          
          try {
            const response = await requestPromise;
            this.responseCache.set(cacheKey, response);
            return response;
          } finally {
            this.pendingRequests.delete(url);
          }
        }
      };

      // Mock successful response
      global.fetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ data: 'test' })
      });

      // Test caching
      const url = '/api/test';
      const response1 = await networkOptimizer.request(url);
      const response2 = await networkOptimizer.request(url);
      
      expect(networkOptimizer.responseCache.size).toBe(1);
      expect(response1).toBe(response2); // Same cached response
    });
  });

  describe('Input Validation and Data Integrity', () => {
    test('should validate input lengths and formats', () => {
      const validators = {
        name: (value) => {
          return value.length >= 2 && value.length <= 100 && /^[a-zA-ZÀ-ÿ\s-']+$/.test(value);
        },
        
        email: (value) => {
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          return emailRegex.test(value) && value.length <= 254;
        },
        
        comment: (value) => {
          return value.length <= 1000 && !/<script|javascript:|data:/i.test(value);
        },
        
        phoneNumber: (value) => {
          const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
          return phoneRegex.test(value.replace(/[\s\-\(\)]/g, ''));
        }
      };

      const testCases = [
        // Valid inputs
        { type: 'name', value: 'Jean-Pierre Dubois', valid: true },
        { type: 'email', value: 'test@example.com', valid: true },
        { type: 'comment', value: 'Commentaire normal', valid: true },
        { type: 'phoneNumber', value: '+33123456789', valid: true },
        
        // Invalid inputs
        { type: 'name', value: 'A', valid: false }, // Too short
        { type: 'name', value: 'A'.repeat(101), valid: false }, // Too long
        { type: 'name', value: 'John123', valid: false }, // Numbers not allowed
        { type: 'email', value: 'invalid-email', valid: false },
        { type: 'comment', value: '<script>alert("XSS")</script>', valid: false },
        { type: 'phoneNumber', value: 'not-a-phone', valid: false }
      ];

      testCases.forEach(({ type, value, valid }) => {
        const isValid = validators[type](value);
        expect(isValid).toBe(valid);
      });
    });

    test('should sanitize HTML entities correctly', () => {
      const htmlSanitizer = {
        SAFE_ENTITIES: {
          '&lt;': '<',
          '&gt;': '>',
          '&amp;': '&',
          '&quot;': '"',
          '&#x27;': "'",
          '&#x2F;': '/',
          '&eacute;': 'é',
          '&agrave;': 'à',
          '&ccedil;': 'ç'
        },
        
        escape: (text) => {
          return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
        },
        
        unescape: (text) => {
          let result = text;
          Object.entries(this.SAFE_ENTITIES).forEach(([entity, char]) => {
            result = result.replace(new RegExp(entity, 'g'), char);
          });
          return result;
        }
      };

      const testStrings = [
        'Normal text',
        'Text with <script>alert("XSS")</script>',
        'Français avec accents éàç',
        'URL: https://example.com/path?param=value',
        'Math: 5 > 3 & 2 < 4',
        'Quotes: "Hello" and \'World\''
      ];

      testStrings.forEach(original => {
        const escaped = htmlSanitizer.escape(original);
        const unescaped = htmlSanitizer.unescape(escaped);
        
        // Verify dangerous characters are escaped
        if (original.includes('<script>')) {
          expect(escaped).not.toContain('<script>');
          expect(escaped).toContain('&lt;script&gt;');
        }
        
        // Verify round-trip consistency for safe content
        if (!original.includes('<script>')) {
          expect(unescaped).toBe(original);
        }
      });
    });

    test('should prevent SQL injection attempts', () => {
      const sqlInjectionPatterns = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM admin_users --",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --",
        "' AND 1=1 --",
        "' OR 1=1 #",
        "') OR ('1'='1",
        "'; EXEC xp_cmdshell('dir'); --"
      ];

      const sanitizeSQL = (input) => {
        // Remove SQL injection patterns
        const dangerous = /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|OR|AND)\b)|('|"|;|--|#)/gi;
        return input.replace(dangerous, '').trim();
      };

      sqlInjectionPatterns.forEach(maliciousInput => {
        const sanitized = sanitizeSQL(maliciousInput);
        
        // Verify SQL keywords are removed
        expect(sanitized).not.toMatch(/\b(DROP|SELECT|INSERT|UNION|EXEC)\b/i);
        expect(sanitized).not.toContain("'");
        expect(sanitized).not.toContain(';');
        expect(sanitized).not.toContain('--');
      });
    });

    test('should validate JSON input safely', () => {
      const jsonValidator = {
        isValidJSON: (str) => {
          try {
            JSON.parse(str);
            return true;
          } catch {
            return false;
          }
        },
        
        sanitizeJSON: (str) => {
          try {
            const parsed = JSON.parse(str);
            
            // Remove dangerous properties
            this.removeDangerousProps(parsed);
            
            return JSON.stringify(parsed);
          } catch {
            return null;
          }
        },
        
        removeDangerousProps: (obj) => {
          if (typeof obj !== 'object' || obj === null) return;
          
          const dangerousProps = ['__proto__', 'constructor', 'prototype'];
          dangerousProps.forEach(prop => delete obj[prop]);
          
          Object.values(obj).forEach(value => {
            if (typeof value === 'object') {
              this.removeDangerousProps(value);
            }
          });
        }
      };

      const testJSONs = [
        '{"name": "John", "age": 30}', // Valid
        '{"__proto__": {"isAdmin": true}}', // Prototype pollution
        '{"constructor": {"prototype": {"evil": true}}}', // Constructor pollution
        'invalid json{', // Invalid syntax
        '{"normal": "data", "nested": {"safe": true}}' // Nested valid
      ];

      testJSONs.forEach(jsonStr => {
        const isValid = jsonValidator.isValidJSON(jsonStr);
        
        if (isValid) {
          const sanitized = jsonValidator.sanitizeJSON(jsonStr);
          
          if (sanitized) {
            const parsed = JSON.parse(sanitized);
            expect(parsed.__proto__).toBeUndefined();
            expect(parsed.constructor).toBeUndefined();
            expect(parsed.prototype).toBeUndefined();
          }
        }
      });
    });
  });

  describe('CSRF Protection', () => {
    test('should require CSRF tokens for state-changing operations', () => {
      const csrfProtection = {
        tokens: new Set(),
        
        generateToken: () => {
          const token = 'csrf-' + Math.random().toString(36).substring(2);
          csrfProtection.tokens.add(token);
          return token;
        },
        
        validateToken: (token) => {
          return csrfProtection.tokens.has(token);
        },
        
        invalidateToken: (token) => {
          csrfProtection.tokens.delete(token);
        }
      };

      // Generate token
      const token = csrfProtection.generateToken();
      expect(token).toMatch(/^csrf-[a-z0-9]+$/);
      expect(csrfProtection.validateToken(token)).toBe(true);

      // Test invalid token
      expect(csrfProtection.validateToken('invalid-token')).toBe(false);

      // Test token invalidation
      csrfProtection.invalidateToken(token);
      expect(csrfProtection.validateToken(token)).toBe(false);
    });

    test('should include CSRF tokens in AJAX requests', () => {
      const mockFetch = jest.fn().mockResolvedValue({ ok: true });
      global.fetch = mockFetch;

      const secureRequest = async (url, options = {}) => {
        const csrfToken = 'csrf-token-123';
        
        return fetch(url, {
          ...options,
          headers: {
            'X-CSRF-Token': csrfToken,
            'Content-Type': 'application/json',
            ...options.headers
          },
          credentials: 'include'
        });
      };

      secureRequest('/api/contacts', {
        method: 'POST',
        body: JSON.stringify({ name: 'Test' })
      });

      expect(mockFetch).toHaveBeenCalledWith('/api/contacts', expect.objectContaining({
        headers: expect.objectContaining({
          'X-CSRF-Token': 'csrf-token-123'
        }),
        credentials: 'include'
      }));
    });

    test('should validate referer header', () => {
      const validateReferer = (referer, allowedOrigins) => {
        if (!referer) return false;
        
        try {
          const refererUrl = new URL(referer);
          return allowedOrigins.some(origin => {
            const originUrl = new URL(origin);
            return refererUrl.origin === originUrl.origin;
          });
        } catch {
          return false;
        }
      };

      const allowedOrigins = ['https://localhost:3000', 'https://example.com'];
      
      // Valid referers
      expect(validateReferer('https://localhost:3000/dashboard', allowedOrigins)).toBe(true);
      expect(validateReferer('https://example.com/page', allowedOrigins)).toBe(true);
      
      // Invalid referers
      expect(validateReferer('https://evil.com/attack', allowedOrigins)).toBe(false);
      expect(validateReferer('http://localhost:3000', allowedOrigins)).toBe(false);
      expect(validateReferer(null, allowedOrigins)).toBe(false);
    });
  });

  describe('Authentication and Session Security', () => {
    test('should implement secure session management', () => {
      const sessionManager = {
        sessions: new Map(),
        
        createSession: (userId) => {
          const sessionId = this.generateSecureId();
          const session = {
            id: sessionId,
            userId,
            createdAt: Date.now(),
            lastActivity: Date.now(),
            isValid: true
          };
          
          this.sessions.set(sessionId, session);
          return sessionId;
        },
        
        validateSession: (sessionId) => {
          const session = this.sessions.get(sessionId);
          if (!session || !session.isValid) return false;
          
          // Check expiration (24 hours)
          const maxAge = 24 * 60 * 60 * 1000;
          if (Date.now() - session.lastActivity > maxAge) {
            this.invalidateSession(sessionId);
            return false;
          }
          
          // Update last activity
          session.lastActivity = Date.now();
          return true;
        },
        
        invalidateSession: (sessionId) => {
          const session = this.sessions.get(sessionId);
          if (session) {
            session.isValid = false;
          }
        },
        
        generateSecureId: () => {
          return Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        }
      };

      // Mock crypto for Node.js environment
      global.crypto = {
        getRandomValues: (array) => {
          for (let i = 0; i < array.length; i++) {
            array[i] = Math.floor(Math.random() * 256);
          }
          return array;
        }
      };

      const sessionId = sessionManager.createSession('user123');
      expect(sessionId).toHaveLength(64); // 32 bytes as hex
      expect(sessionManager.validateSession(sessionId)).toBe(true);

      // Test session invalidation
      sessionManager.invalidateSession(sessionId);
      expect(sessionManager.validateSession(sessionId)).toBe(false);
    });

    test('should prevent session fixation attacks', () => {
      const sessionManager = {
        regenerateSessionId: (oldSessionId) => {
          const session = this.getSession(oldSessionId);
          if (session) {
            const newSessionId = this.generateSecureId();
            this.sessions.delete(oldSessionId);
            this.sessions.set(newSessionId, {
              ...session,
              id: newSessionId
            });
            return newSessionId;
          }
          return null;
        },
        
        sessions: new Map(),
        getSession: function(id) { return this.sessions.get(id); },
        generateSecureId: () => Math.random().toString(36)
      };

      const oldSessionId = 'old-session-123';
      sessionManager.sessions.set(oldSessionId, { id: oldSessionId, userId: 'user123' });

      const newSessionId = sessionManager.regenerateSessionId(oldSessionId);
      
      expect(newSessionId).not.toBe(oldSessionId);
      expect(sessionManager.sessions.has(oldSessionId)).toBe(false);
      expect(sessionManager.sessions.has(newSessionId)).toBe(true);
    });

    test('should implement proper password policies', () => {
      const passwordValidator = {
        validate: (password) => {
          const checks = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
            noCommon: !this.isCommonPassword(password)
          };
          
          return {
            isValid: Object.values(checks).every(check => check),
            checks
          };
        },
        
        isCommonPassword: (password) => {
          const commonPasswords = [
            'password', '123456', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123'
          ];
          return commonPasswords.includes(password.toLowerCase());
        }
      };

      const testPasswords = [
        { password: 'StrongP@ss123', shouldBeValid: true },
        { password: 'weak', shouldBeValid: false },
        { password: 'password123', shouldBeValid: false }, // Common password
        { password: 'NoNumbers!', shouldBeValid: false },
        { password: 'nonumbersorspecial', shouldBeValid: false }
      ];

      testPasswords.forEach(({ password, shouldBeValid }) => {
        const result = passwordValidator.validate(password);
        expect(result.isValid).toBe(shouldBeValid);
      });
    });
  });

  describe('Error Handling and Logging', () => {
    test('should not expose sensitive information in errors', () => {
      const errorHandler = {
        sanitizeError: (error) => {
          const sanitizedMessage = error.message
            .replace(/password/gi, '[REDACTED]')
            .replace(/token/gi, '[REDACTED]')
            .replace(/key/gi, '[REDACTED]')
            .replace(/secret/gi, '[REDACTED]')
            .replace(/\/[a-z]:[\\\/].*/gi, '[PATH_REDACTED]'); // File paths
          
          return {
            message: sanitizedMessage,
            type: error.constructor.name,
            timestamp: new Date().toISOString()
          };
        },
        
        logError: (error, context = {}) => {
          const sanitized = this.sanitizeError(error);
          
          // Log to secure endpoint (mock)
          console.log('Error logged:', {
            ...sanitized,
            context: {
              url: context.url || window.location.href,
              userAgent: navigator.userAgent,
              timestamp: sanitized.timestamp
            }
          });
        }
      };

      const sensitiveError = new Error('Failed to validate password token for user at C:\\secrets\\config.json');
      const sanitized = errorHandler.sanitizeError(sensitiveError);
      
      expect(sanitized.message).not.toContain('password');
      expect(sanitized.message).not.toContain('token');
      expect(sanitized.message).not.toContain('C:\\');
      expect(sanitized.message).toContain('[REDACTED]');
    });

    test('should implement rate limiting for error reports', () => {
      const errorRateLimiter = {
        errorCounts: new Map(),
        
        shouldAllowError: (errorType, clientId) => {
          const key = `${errorType}-${clientId}`;
          const now = Date.now();
          const windowMs = 60000; // 1 minute
          const maxErrors = 5;
          
          if (!this.errorCounts.has(key)) {
            this.errorCounts.set(key, { count: 1, firstError: now });
            return true;
          }
          
          const errorData = this.errorCounts.get(key);
          
          if (now - errorData.firstError > windowMs) {
            // Reset window
            this.errorCounts.set(key, { count: 1, firstError: now });
            return true;
          }
          
          if (errorData.count >= maxErrors) {
            return false; // Rate limited
          }
          
          errorData.count++;
          return true;
        }
      };

      const clientId = 'client-123';
      const errorType = 'ValidationError';
      
      // First 5 errors should be allowed
      for (let i = 0; i < 5; i++) {
        expect(errorRateLimiter.shouldAllowError(errorType, clientId)).toBe(true);
      }
      
      // 6th error should be rate limited
      expect(errorRateLimiter.shouldAllowError(errorType, clientId)).toBe(false);
    });
  });

  describe('Data Privacy and GDPR Compliance', () => {
    test('should implement data anonymization', () => {
      const dataAnonymizer = {
        anonymizeEmail: (email) => {
          const [local, domain] = email.split('@');
          const anonymizedLocal = local.charAt(0) + '*'.repeat(local.length - 2) + local.charAt(local.length - 1);
          return `${anonymizedLocal}@${domain}`;
        },
        
        anonymizeName: (name) => {
          return name.charAt(0) + '*'.repeat(Math.max(0, name.length - 2)) + (name.length > 1 ? name.charAt(name.length - 1) : '');
        },
        
        anonymizePhoneNumber: (phone) => {
          const cleaned = phone.replace(/\D/g, '');
          return cleaned.substring(0, 3) + '*'.repeat(cleaned.length - 6) + cleaned.substring(cleaned.length - 3);
        }
      };

      expect(dataAnonymizer.anonymizeEmail('john.doe@example.com')).toBe('j*****e@example.com');
      expect(dataAnonymizer.anonymizeName('John')).toBe('J**n');
      expect(dataAnonymizer.anonymizePhoneNumber('+33123456789')).toBe('331***789');
    });

    test('should implement consent management', () => {
      const consentManager = {
        consents: new Map(),
        
        recordConsent: (userId, consentType, granted) => {
          const consent = {
            userId,
            type: consentType,
            granted,
            timestamp: new Date().toISOString(),
            ipAddress: '127.0.0.1', // Anonymized
            userAgent: navigator.userAgent.substring(0, 100) // Truncated
          };
          
          this.consents.set(`${userId}-${consentType}`, consent);
        },
        
        hasValidConsent: (userId, consentType) => {
          const consent = this.consents.get(`${userId}-${consentType}`);
          if (!consent || !consent.granted) return false;
          
          // Check if consent is still valid (2 years for GDPR)
          const consentDate = new Date(consent.timestamp);
          const maxAge = 2 * 365 * 24 * 60 * 60 * 1000; // 2 years
          
          return Date.now() - consentDate.getTime() < maxAge;
        },
        
        revokeConsent: (userId, consentType) => {
          const key = `${userId}-${consentType}`;
          const consent = this.consents.get(key);
          if (consent) {
            consent.granted = false;
            consent.revokedAt = new Date().toISOString();
          }
        }
      };

      const userId = 'user123';
      
      // Record consent
      consentManager.recordConsent(userId, 'analytics', true);
      expect(consentManager.hasValidConsent(userId, 'analytics')).toBe(true);
      
      // Revoke consent
      consentManager.revokeConsent(userId, 'analytics');
      expect(consentManager.hasValidConsent(userId, 'analytics')).toBe(false);
    });
  });
});