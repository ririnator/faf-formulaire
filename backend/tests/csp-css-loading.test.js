/**
 * CSP CSS Loading Tests
 * Validates that CSS files load correctly without CSP violations
 */

const request = require('supertest');
const express = require('express');
const path = require('path');
const fs = require('fs');

// Import security middleware
const { createSecurityMiddleware } = require('../middleware/security');
const TemplateRenderer = require('../utils/templateRenderer');

describe('CSP CSS Loading Tests', () => {
  let app;

  beforeEach(() => {
    app = express();
    
    // Apply security middleware
    app.use(createSecurityMiddleware());
    
    // Test route that serves form.html (which loads CSS files)
    app.get('/form', (req, res) => {
      try {
        const html = TemplateRenderer.renderWithNonce(
          path.join(__dirname, '../../frontend/public/form.html'), 
          res
        );
        res.send(html);
      } catch (error) {
        res.status(500).send('Error rendering form');
      }
    });

    // Serve CSS files with proper MIME types
    app.use('/css', (req, res, next) => {
      if (req.path.endsWith('.css')) {
        res.setHeader('Content-Type', 'text/css; charset=utf-8');
      }
      next();
    }, express.static(path.join(__dirname, '../../frontend/public/css')));

    app.use('/admin', (req, res, next) => {
      if (req.path.endsWith('.css')) {
        res.setHeader('Content-Type', 'text/css; charset=utf-8');
      }
      next();
    }, express.static(path.join(__dirname, '../../frontend/admin')));
  });

  describe('🔒 CSP Configuration Validation', () => {
    test('should have styleSrc directive that allows self without nonces', async () => {
      const response = await request(app).get('/form');
      
      expect(response.status).toBe(200);
      const cspHeader = response.headers['content-security-policy'];
      expect(cspHeader).toBeDefined();
      
      // Should include 'self' in styleSrc
      expect(cspHeader).toMatch(/style-src[^;]*'self'/);
      
      // Should NOT require nonces for CSS (unlike scripts)
      expect(cspHeader).not.toMatch(/style-src[^;]*'nonce-/);
      
      // Should allow external CSS CDNs
      expect(cspHeader).toMatch(/style-src[^;]*cdn\.tailwindcss\.com/);
      expect(cspHeader).toMatch(/style-src[^;]*cdnjs\.cloudflare\.com/);
    });

    test('should still require nonces for scripts but not CSS', async () => {
      const response = await request(app).get('/form');
      
      const cspHeader = response.headers['content-security-policy'];
      
      // Scripts should still require nonces for security
      expect(cspHeader).toMatch(/script-src[^;]*'nonce-/);
      
      // But CSS should not require nonces
      expect(cspHeader).toMatch(/style-src[^;]*'self'/);
      expect(cspHeader).not.toMatch(/style-src[^;]*'nonce-/);
    });
  });

  describe('📄 CSS File Accessibility', () => {
    test('should serve faf-base.css with correct MIME type', async () => {
      const response = await request(app).get('/css/faf-base.css');
      
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toBe('text/css; charset=utf-8');
      
      // Should contain honeypot rules
      expect(response.text).toMatch(/input\[name="website"\]/);
      expect(response.text).toMatch(/display:\s*none\s*!important/);
    });

    test('should serve mobile-responsive.css with correct MIME type', async () => {
      const response = await request(app).get('/admin/mobile-responsive.css');
      
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toBe('text/css; charset=utf-8');
      
      // Verify it's actual CSS content
      expect(response.text).toMatch(/\/\*.*\*\//); // CSS comments
      expect(response.text).toMatch(/@media/); // Media queries
    });

    test('should serve all required CSS files from form.html', async () => {
      // Read form.html to extract CSS file references
      const formHtmlPath = path.join(__dirname, '../../frontend/public/form.html');
      
      if (!fs.existsSync(formHtmlPath)) {
        console.warn('form.html not found, skipping CSS file validation');
        return;
      }

      const formHtml = fs.readFileSync(formHtmlPath, 'utf8');
      const cssFiles = [];
      
      // Extract CSS file references
      const linkRegex = /<link[^>]+href=["']([^"']+\.css)["'][^>]*>/g;
      let match;
      while ((match = linkRegex.exec(formHtml)) !== null) {
        cssFiles.push(match[1]);
      }

      expect(cssFiles.length).toBeGreaterThan(0);

      // Test each CSS file
      for (const cssFile of cssFiles) {
        const response = await request(app).get(cssFile);
        expect(response.status).toBe(200);
        expect(response.headers['content-type']).toBe('text/css; charset=utf-8');
      }
    });
  });

  describe('🛡️ Honeypot CSS Rules Validation', () => {
    test('should have complete honeypot hiding rules in faf-base.css', async () => {
      const response = await request(app).get('/css/faf-base.css');
      
      expect(response.status).toBe(200);
      
      const cssContent = response.text;
      
      // Check for comprehensive honeypot hiding
      expect(cssContent).toMatch(/input\[name="website"\]\s*\{[^}]*display:\s*none\s*!important/);
      expect(cssContent).toMatch(/input\[name="website"\]\s*\{[^}]*visibility:\s*hidden\s*!important/);
      expect(cssContent).toMatch(/input\[name="website"\]\s*\{[^}]*position:\s*absolute\s*!important/);
      expect(cssContent).toMatch(/input\[name="website"\]\s*\{[^}]*left:\s*-9999px\s*!important/);
      expect(cssContent).toMatch(/input\[name="website"\]\s*\{[^}]*width:\s*0\s*!important/);
      expect(cssContent).toMatch(/input\[name="website"\]\s*\{[^}]*height:\s*0\s*!important/);
    });

    test('should not interfere with legitimate text inputs', async () => {
      const response = await request(app).get('/css/faf-base.css');
      
      const cssContent = response.text;
      
      // Should specifically target honeypot field only
      expect(cssContent).toMatch(/input\[type="text"\]:not\(\[name="website"\]\)/);
      
      // Regular inputs should have normal styling
      expect(cssContent).toMatch(/input\[type="text"\]:not\(\[name="website"\]\)[^{]*\{[^}]*width:\s*100%/);
    });
  });

  describe('⚡ Performance and Caching', () => {
    test('should set appropriate cache headers for CSS files', async () => {
      const response = await request(app).get('/css/faf-base.css');
      
      expect(response.status).toBe(200);
      expect(response.headers['cache-control']).toBeDefined();
      
      // Should have some caching enabled
      expect(response.headers['cache-control']).toMatch(/(public|max-age)/);
    });

    test('should serve CSS files efficiently', async () => {
      const start = Date.now();
      await request(app).get('/css/faf-base.css');
      const duration = Date.now() - start;
      
      // Should serve CSS files quickly (under 100ms in tests)
      expect(duration).toBeLessThan(100);
    });
  });

  describe('🔄 Integration with Template Rendering', () => {
    test('should render form.html with nonces for scripts but allow CSS without nonces', async () => {
      const response = await request(app).get('/form');
      
      expect(response.status).toBe(200);
      const html = response.text;
      
      // Should have nonces on script tags
      expect(html).toMatch(/<script[^>]+nonce="[^"]+"/);
      
      // Should have normal link tags for CSS (no nonces needed)
      expect(html).toMatch(/<link[^>]+rel="stylesheet"[^>]+href="[^"]+\.css"/);
      expect(html).not.toMatch(/<link[^>]+nonce=/);
      
      // Should include honeypot CSS file
      expect(html).toMatch(/href="\/css\/faf-base\.css"/);
    });
  });
});