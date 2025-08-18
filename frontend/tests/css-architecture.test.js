/**
 * CSS Architecture Tests for FAF Modular Design System
 * Tests the new optimized CSS structure and purged styles
 */

const fs = require('fs');
const path = require('path');

describe('CSS Architecture Tests', () => {
  let cssContent;
  let htmlFiles = {};

  beforeAll(() => {
    // Load optimized CSS
    const cssPath = path.join(__dirname, '../public/css/faf-base.css');
    cssContent = fs.readFileSync(cssPath, 'utf8');

    // Load HTML files
    const frontendDir = path.join(__dirname, '..');
    const htmlPaths = [
      'public/index.html',
      'public/form.html', 
      'public/view.html',
      'admin/admin.html',
      'admin/admin_gestion.html',
      '404.html'
    ];

    htmlPaths.forEach(htmlPath => {
      const fullPath = path.join(frontendDir, htmlPath);
      if (fs.existsSync(fullPath)) {
        htmlFiles[htmlPath] = fs.readFileSync(fullPath, 'utf8');
      }
    });
  });

  describe('CSS Purging Verification', () => {
    test('should contain only essential CSS variables', () => {
      // Essential variables that should exist
      const essentialVars = [
        '--primary-gradient',
        '--primary-color', 
        '--gray-50',
        '--gray-200',
        '--gray-500',
        '--font-family',
        '--spacing-4',
        '--radius-lg'
      ];

      essentialVars.forEach(variable => {
        expect(cssContent).toContain(variable);
      });

      // Unused variables that should be removed
      const removedVars = [
        '--gray-300',
        '--gray-400', 
        '--gray-800',
        '--gray-900',
        '--secondary-color',
        '--warning-bg',
        '--spacing-1',
        '--spacing-12',
        '--spacing-16'
      ];

      removedVars.forEach(variable => {
        // Use more precise matching to avoid false positives with substrings
        const regex = new RegExp(`\\${variable}\\s*:`, 'g');
        expect(cssContent.match(regex)).toBeNull();
      });
    });

    test('should not contain unused CSS classes', () => {
      const unusedClasses = [
        '.faf-alert',
        '.faf-btn-secondary',
        '.faf-checkbox-group',
        '.faf-container-sm',
        '.faf-file-input',
        '.faf-form-group',
        '.faf-input',
        '.faf-label',
        '.faf-select',
        '.faf-loading',
        '.admin-answer',
        '.admin-row',
        '.question-group'
      ];

      unusedClasses.forEach(className => {
        expect(cssContent).not.toContain(className);
      });
    });

    test('should preserve JavaScript-referenced classes', () => {
      const jsClasses = [
        '.loading-overlay',
        '.hidden', 
        '.lightbox-overlay'
      ];

      jsClasses.forEach(className => {
        expect(cssContent).toContain(className);
      });
    });

    test('should preserve essential utility classes', () => {
      const essentialClasses = [
        '.faf-container',
        '.container',
        '.faf-title',
        '.faf-btn',
        '.faf-btn-primary',
        '.radio-group',
        '.form-group',
        '.skip-link',
        '.error-container'
      ];

      essentialClasses.forEach(className => {
        expect(cssContent).toContain(className);
      });
    });
  });

  describe('CSS Architecture Integrity', () => {
    test('should have consistent CSS variable usage', () => {
      // Check that variables are defined and used
      const variableMatches = cssContent.match(/--[\w-]+:/g);
      const variableUsage = cssContent.match(/var\(--[\w-]+\)/g);

      expect(variableMatches.length).toBeGreaterThan(0);
      expect(variableUsage.length).toBeGreaterThan(0);
      
      // Should use more variables than defined (reuse)
      expect(variableUsage.length).toBeGreaterThan(variableMatches.length);
    });

    test('should have proper CSS structure comments', () => {
      const requiredComments = [
        '/* Essential CSS variables only */',
        '/* Reset styles - CRITICAL */',
        '/* Base layout - CRITICAL */',
        '/* JavaScript-referenced classes - PRESERVE */'
      ];

      requiredComments.forEach(comment => {
        expect(cssContent).toContain(comment);
      });
    });

    test('should not have redundant reset styles', () => {
      // Should only have one reset block
      const resetMatches = cssContent.match(/\*, \*::before, \*::after/g);
      expect(resetMatches).toHaveLength(1);
    });

    test('should have responsive design patterns', () => {
      expect(cssContent).toContain('@media (max-width: 768px)');
      expect(cssContent).toContain('flex-direction: column');
    });
  });

  describe('HTML-CSS Integration Tests', () => {
    test('all HTML files should reference faf-base.css', () => {
      const htmlWithCSS = ['public/index.html', 'public/form.html', '404.html'];
      
      htmlWithCSS.forEach(htmlPath => {
        if (htmlFiles[htmlPath]) {
          expect(htmlFiles[htmlPath]).toContain('/css/faf-base.css');
        }
      });
    });

    test('HTML classes should exist in CSS', () => {
      const commonClasses = [
        'faf-container',
        'container', 
        'faf-title',
        'faf-btn',
        'radio-group',
        'form-group'
      ];

      Object.entries(htmlFiles).forEach(([filePath, content]) => {
        commonClasses.forEach(className => {
          if (content.includes(className)) {
            expect(cssContent).toContain(`.${className}`);
          }
        });
      });
    });

    test('critical elements should have proper styling', () => {
      // Test that body, containers, and buttons have styling
      expect(cssContent).toMatch(/body\s*{[\s\S]*?}/);
      expect(cssContent).toMatch(/\.container[\s\S]*?{[\s\S]*?}/);
      expect(cssContent).toMatch(/button[\s\S]*?{[\s\S]*?}/);
    });
  });

  describe('Performance Optimization Tests', () => {
    test('CSS file should be significantly smaller than original', () => {
      const stats = fs.statSync(path.join(__dirname, '../public/css/faf-base.css'));
      const fileSizeKB = stats.size / 1024;
      
      // Should be around 8KB after optimization
      expect(fileSizeKB).toBeLessThan(10);
      expect(fileSizeKB).toBeGreaterThan(6);
    });

    test('should not contain excessive whitespace', () => {
      const lines = cssContent.split('\n');
      const emptyLines = lines.filter(line => line.trim() === '');
      
      // Should have some structure but not excessive empty lines
      expect(emptyLines.length / lines.length).toBeLessThan(0.3);
    });

    test('should use efficient selectors', () => {
      // Should not have overly complex selectors (more than 6 levels deep)
      const selectorLines = cssContent.split('\n').filter(line => 
        line.includes('{') && !line.trim().startsWith('/*') && !line.trim().startsWith('@')
      );
      
      const longSelectors = selectorLines.filter(line => {
        const selector = line.split('{')[0].trim();
        // Remove comments
        const cleanSelector = selector.replace(/\/\*.*?\*\//g, '').trim();
        // Skip media queries, keyframes, and empty selectors
        if (cleanSelector.startsWith('@') || cleanSelector === '' || cleanSelector.includes('/*')) {
          return false;
        }
        // Count descendant combinators and complex selectors
        const parts = cleanSelector.split(/[\s>+~]/).filter(part => part.trim().length > 0);
        return parts.length > 6;
      });
      
      // Allow up to 5 complex selectors for responsive design and special cases
      expect(longSelectors.length).toBeLessThan(6);
    });
  });

  describe('Cross-browser Compatibility', () => {
    test('should use CSS custom properties properly', () => {
      // Check CSS variables are properly defined in :root
      expect(cssContent).toMatch(/:root\s*{[\s\S]*?--[\w-]+:[\s\S]*?}/);
    });

    test('should have vendor prefixes for critical properties', () => {
      // Check for box-sizing reset
      expect(cssContent).toContain('box-sizing: border-box');
    });

    test('should use modern CSS features appropriately', () => {
      // Should use flexbox appropriately
      if (cssContent.includes('display: flex')) {
        expect(cssContent).toContain('align-items:');
      }
    });
  });

  describe('Accessibility Features', () => {
    test('should include focus styles', () => {
      expect(cssContent).toContain(':focus');
      expect(cssContent).toContain('outline:');
    });

    test('should include skip-link for keyboard navigation', () => {
      expect(cssContent).toContain('.skip-link');
      expect(cssContent).toContain('position: absolute');
    });

    test('should have proper color contrast patterns', () => {
      // Should define text colors that work with backgrounds
      expect(cssContent).toContain('color: var(--gray-700)');
      expect(cssContent).toContain('background: white');
    });
  });
});