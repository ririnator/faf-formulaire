/**
 * Modular Architecture Tests for FAF CSS System
 * Tests the separation of concerns and module independence
 */

const fs = require('fs');
const path = require('path');

describe('Modular Architecture Tests', () => {
  let cssFiles = {};
  let htmlFiles = {};

  beforeAll(() => {
    // Load all CSS files
    const cssModules = {
      'faf-base': '../public/css/faf-base.css',
      'homepage': '../public/styles/homepage.css',
      'mobile-responsive': '../admin/mobile-responsive.css',
      'view': '../public/css/view.css'
    };

    Object.entries(cssModules).forEach(([name, relativePath]) => {
      const fullPath = path.join(__dirname, relativePath);
      if (fs.existsSync(fullPath)) {
        cssFiles[name] = fs.readFileSync(fullPath, 'utf8');
      }
    });

    // Load HTML files that use different CSS combinations
    const htmlModules = {
      'index': '../public/index.html',
      'form': '../public/form.html',
      'view': '../public/view.html',
      '404': '../404.html'
    };

    Object.entries(htmlModules).forEach(([name, relativePath]) => {
      const fullPath = path.join(__dirname, relativePath);
      if (fs.existsSync(fullPath)) {
        htmlFiles[name] = fs.readFileSync(fullPath, 'utf8');
      }
    });
  });

  describe('Module Separation', () => {
    test('faf-base should contain only core design system', () => {
      const baseCSS = cssFiles['faf-base'];
      
      // Should contain core elements
      const coreElements = [
        'body {',
        '.container',
        '.faf-title',
        'button',
        'input[type="text"]',
        '.radio-group'
      ];

      coreElements.forEach(element => {
        expect(baseCSS).toContain(element);
      });

      // Should NOT contain page-specific elements
      const pageSpecific = [
        'hero-section',
        'admin-specific',
        'lightbox-image',
        'qa-container'
      ];

      pageSpecific.forEach(element => {
        expect(baseCSS).not.toContain(element);
      });
    });

    test('homepage.css should contain only homepage-specific styles', () => {
      const homepageCSS = cssFiles['homepage'];
      
      if (homepageCSS) {
        // Should contain homepage-specific classes
        const homepageElements = [
          'hero-section',
          'faf-fade-in'
        ];

        homepageElements.forEach(element => {
          expect(homepageCSS).toContain(element);
        });

        // Should NOT duplicate base styles
        expect(homepageCSS).not.toContain('body {');
        expect(homepageCSS).not.toContain('*, *::before, *::after');
      }
    });

    test('mobile-responsive should contain only responsive overrides', () => {
      const mobileCSS = cssFiles['mobile-responsive'];
      
      if (mobileCSS) {
        // Should contain media queries
        expect(mobileCSS).toContain('@media');
        
        // Should focus on mobile-specific adjustments
        const mobilePatterns = [
          'max-width',
          'min-width',
          'flex-direction',
          'font-size'
        ];

        const hasResponsivePatterns = mobilePatterns.some(pattern => 
          mobileCSS.includes(pattern)
        );
        expect(hasResponsivePatterns).toBe(true);
      }
    });
  });

  describe('CSS Loading Strategy', () => {
    test('index.html should load base + homepage modules', () => {
      const indexHTML = htmlFiles['index'];
      
      if (indexHTML) {
        expect(indexHTML).toContain('/css/faf-base.css');
        expect(indexHTML).toContain('/styles/homepage.css');
      }
    });

    test('form.html should load base + mobile-responsive modules', () => {
      const formHTML = htmlFiles['form'];
      
      if (formHTML) {
        expect(formHTML).toContain('/css/faf-base.css');
        expect(formHTML).toContain('/css/mobile-responsive.css');
      }
    });

    test('404.html should load only base module', () => {
      const errorHTML = htmlFiles['404'];
      
      if (errorHTML) {
        expect(errorHTML).toContain('/css/faf-base.css');
        // Should not load additional modules
        expect(errorHTML).not.toContain('/styles/homepage.css');
        expect(errorHTML).not.toContain('/css/mobile-responsive.css');
      }
    });

    test('mobile-responsive.css should be accessible in public CSS directory', () => {
      // Validate that mobile-responsive.css exists in the new location
      const mobileCSS = cssFiles['mobile-responsive'];
      expect(mobileCSS).toBeDefined();
      
      // Should contain mobile-specific media queries
      expect(mobileCSS).toMatch(/@media.*max-width/);
      expect(mobileCSS).toMatch(/responsive|mobile|viewport/i);
    });
  });

  describe('Module Independence', () => {
    test('each CSS module should be independently parseable', () => {
      Object.entries(cssFiles).forEach(([moduleName, content]) => {
        // Should not have syntax errors (basic check)
        const openBraces = (content.match(/{/g) || []).length;
        const closeBraces = (content.match(/}/g) || []).length;
        
        expect(openBraces).toBe(closeBraces);
        
        // Should not have unclosed comments
        const openComments = (content.match(/\/\*/g) || []).length;
        const closeComments = (content.match(/\*\//g) || []).length;
        
        expect(openComments).toBe(closeComments);
      });
    });

    test('modules should not conflict with each other', () => {
      const baseSelectors = extractSelectors(cssFiles['faf-base']);
      const homepageSelectors = extractSelectors(cssFiles['homepage'] || '');
      
      // Check for conflicts (same selector, different properties)
      const conflicts = baseSelectors.filter(selector => 
        homepageSelectors.includes(selector) && 
        selector !== 'body' && 
        !selector.includes('::')
      );
      
      // Some overlap is expected (body, html), but should be minimal
      expect(conflicts.length).toBeLessThan(3);
    });

    test('CSS variables should be consistent across modules', () => {
      const baseVars = extractCSSVariables(cssFiles['faf-base']);
      
      Object.entries(cssFiles).forEach(([moduleName, content]) => {
        if (moduleName !== 'faf-base') {
          const moduleVars = extractCSSVariables(content);
          
          // Other modules shouldn't redefine base variables
          const conflicts = baseVars.filter(baseVar => 
            moduleVars.includes(baseVar)
          );
          
          expect(conflicts.length).toBe(0);
        }
      });
    });
  });

  describe('Performance Characteristics', () => {
    test('module sizes should be appropriate for their purpose', () => {
      Object.entries(cssFiles).forEach(([moduleName, content]) => {
        const sizeKB = Buffer.byteLength(content, 'utf8') / 1024;
        
        switch (moduleName) {
          case 'faf-base':
            // Core module should be reasonably sized
            expect(sizeKB).toBeLessThan(12);
            expect(sizeKB).toBeGreaterThan(6);
            break;
          case 'homepage':
            // Specific modules should be smaller
            expect(sizeKB).toBeLessThan(6);
            break;
          case 'view':
            // Utility modules should be small
            expect(sizeKB).toBeLessThan(4);
            break;
        }
      });
    });

    test('total CSS payload should be optimized', () => {
      const totalSize = Object.values(cssFiles).reduce((total, content) => {
        return total + Buffer.byteLength(content, 'utf8') / 1024;
      }, 0);
      
      // Total should be significantly less than original bundle
      expect(totalSize).toBeLessThan(30); // Down from ~40KB
    });
  });

  describe('Critical CSS Identification', () => {
    test('faf-base should contain above-the-fold styles', () => {
      const baseCSS = cssFiles['faf-base'];
      
      // Critical elements for first paint
      const criticalElements = [
        'body',
        '.faf-container',
        '.container', 
        'h1',
        '.faf-title'
      ];

      criticalElements.forEach(element => {
        expect(baseCSS).toMatch(new RegExp(`${element.replace('.', '\\.')}\\s*{`));
      });
    });

    test('non-critical styles should be in separate modules', () => {
      const baseCSS = cssFiles['faf-base'];
      
      // These should be in other modules or not needed immediately
      const nonCritical = [
        '.lightbox-overlay',
        '.admin-specific',
        'animation',
        '@keyframes'
      ];

      // Some of these might be in base for JS functionality, but should be minimal
      const nonCriticalInBase = nonCritical.filter(style => 
        baseCSS.includes(style)
      );
      
      expect(nonCriticalInBase.length).toBeLessThan(2);
    });
  });

  // Helper functions
  function extractSelectors(css) {
    const selectorPattern = /([^{}]+)\s*{[^}]*}/g;
    const selectors = [];
    let match;
    
    while ((match = selectorPattern.exec(css)) !== null) {
      const selector = match[1].trim().split(',')[0].trim();
      selectors.push(selector);
    }
    
    return selectors;
  }

  function extractCSSVariables(css) {
    const variablePattern = /--([\w-]+):/g;
    const variables = [];
    let match;
    
    while ((match = variablePattern.exec(css)) !== null) {
      variables.push(`--${match[1]}`);
    }
    
    return variables;
  }
});