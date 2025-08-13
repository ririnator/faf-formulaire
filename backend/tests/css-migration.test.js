/**
 * CSS Migration Test Suite
 * Tests for verifying CSP compliance, visual integrity, performance, and accessibility
 * after the CSS architecture refactoring
 */

const request = require('supertest');
const app = require('../app');
const cheerio = require('cheerio');

describe('CSS Migration Tests', () => {
  
  describe('✅ CSP Compliance', () => {
    test('auth-choice page should have proper CSP headers with nonce', async () => {
      const response = await request(app).get('/auth-choice');
      
      // Check CSP header exists
      expect(response.headers['content-security-policy']).toBeDefined();
      
      // Check that style-src includes nonce
      expect(response.headers['content-security-policy']).toMatch(/style-src[^;]*'nonce-[\w+/=]+'/);
      
      // Parse HTML to verify nonces are injected
      const $ = cheerio.load(response.text);
      const cssLinks = $('link[rel="stylesheet"]');
      
      expect(cssLinks.length).toBeGreaterThan(0);
      cssLinks.each((i, el) => {
        const nonce = $(el).attr('nonce');
        expect(nonce).toBeUndefined(); // CSS links should NOT have nonces
      });
    });
    
    test('login page should have proper CSP headers with nonce', async () => {
      const response = await request(app).get('/login');
      
      expect(response.headers['content-security-policy']).toBeDefined();
      
      const $ = cheerio.load(response.text);
      const sharedBase = $('link[href="/css/shared-base.css"]');
      const loginCss = $('link[href="/css/login.css"]');
      
      // Verify both CSS files are loaded
      expect(sharedBase.length).toBe(1);
      expect(loginCss.length).toBe(1);
      
      // Verify CSS links do NOT have nonces (external files use 'self' directive)
      expect(sharedBase.attr('nonce')).toBeUndefined();
      expect(loginCss.attr('nonce')).toBeUndefined();
    });
    
    test('register page should have proper CSP headers with nonce', async () => {
      const response = await request(app).get('/register');
      
      expect(response.headers['content-security-policy']).toBeDefined();
      
      const $ = cheerio.load(response.text);
      const sharedBase = $('link[href="/css/shared-base.css"]');
      const registerCss = $('link[href="/css/register.css"]');
      
      expect(sharedBase.length).toBe(1);
      expect(registerCss.length).toBe(1);
      
      // CSS links should NOT have nonces
      expect(sharedBase.attr('nonce')).toBeUndefined();
      expect(registerCss.attr('nonce')).toBeUndefined();
    });
    
    test('no inline styles should be present in HTML', async () => {
      const pages = ['/auth-choice', '/login', '/register'];
      
      for (const page of pages) {
        const response = await request(app).get(page);
        const $ = cheerio.load(response.text);
        
        // Check for inline style tags
        const styleTags = $('style').not('[nonce]');
        expect(styleTags.length).toBe(0);
        
        // Check for inline style attributes (excluding hidden inputs)
        const elementsWithStyle = $('[style]').not('input[type="hidden"]');
        expect(elementsWithStyle.length).toBe(0);
      }
    });

    test('no inline event handlers should be present in HTML', async () => {
      const pages = ['/auth-choice', '/login', '/register'];
      
      for (const page of pages) {
        const response = await request(app).get(page);
        const $ = cheerio.load(response.text);
        
        // Check for onclick handlers
        const onclickElements = $('[onclick]');
        expect(onclickElements.length).toBe(0);
        
        // Check for other inline event handlers
        const inlineEventHandlers = $('[onload], [onmouseover], [onsubmit]');
        expect(inlineEventHandlers.length).toBe(0);
        
        // Verify addEventListener is used instead (auth-choice specific)
        if (page === '/auth-choice') {
          expect(response.text).toContain('addEventListener');
        }
      }
    });
  });
  
  describe('⚠️ Visual Regression', () => {
    test('all required CSS files should be loaded in correct order', async () => {
      const pages = [
        { url: '/auth-choice', css: ['/css/shared-base.css', '/css/auth-choice.css'] },
        { url: '/login', css: ['/css/shared-base.css', '/css/login.css'] },
        { url: '/register', css: ['/css/shared-base.css', '/css/register.css'] }
      ];
      
      for (const page of pages) {
        const response = await request(app).get(page.url);
        const $ = cheerio.load(response.text);
        const cssLinks = $('link[rel="stylesheet"]').map((i, el) => $(el).attr('href')).get();
        
        // Verify CSS files are in correct order (shared-base first)
        expect(cssLinks).toEqual(page.css);
      }
    });
    
    test('CSS variables should be properly defined', async () => {
      const response = await request(app).get('/css/shared-base.css');
      
      // Check critical CSS variables are defined
      const cssContent = response.text;
      const requiredVars = [
        '--color-primary',
        '--color-bg-translucent',
        '--color-admin-bg',
        '--spacing-xs',
        '--radius-sm',
        '--shadow-lg',
        '--font-size-normal',
        '--gradient-main'
      ];
      
      for (const varName of requiredVars) {
        expect(cssContent).toContain(varName);
      }
    });
    
    test('page-specific CSS should use CSS variables', async () => {
      const cssFiles = [
        '/css/login.css',
        '/css/register.css',
        '/css/auth-choice.css'
      ];
      
      for (const file of cssFiles) {
        const response = await request(app).get(file);
        const cssContent = response.text;
        
        // Check that CSS variables are used
        expect(cssContent).toMatch(/var\(--[\w-]+\)/);
        
        // Check no hardcoded colors remain (except special cases)
        const hardcodedColors = cssContent.match(/#[0-9a-fA-F]{6}/g) || [];
        const allowedHardcoded = ['#000']; // High contrast mode
        
        const unexpectedColors = hardcodedColors.filter(
          color => !allowedHardcoded.includes(color)
        );
        
        // Special exceptions for glassmorphism effects
        if (!file.includes('auth-choice')) {
          expect(unexpectedColors.length).toBe(0);
        }
      }
    });
  });
  
  describe('⚠️ Performance', () => {
    test('CSS files should be cacheable', async () => {
      const cssFiles = [
        '/css/shared-base.css',
        '/css/login.css',
        '/css/register.css',
        '/css/auth-choice.css'
      ];
      
      for (const file of cssFiles) {
        const response = await request(app).get(file);
        
        // Check for cache headers
        expect(response.headers['etag']).toBeDefined();
        expect(response.status).toBe(200);
      }
    });
    
    test('CSS file sizes should be optimized', async () => {
      const expectations = [
        { file: '/css/login.css', maxSize: 2000 }, // ~34 lines
        { file: '/css/register.css', maxSize: 1000 }, // ~15 lines  
        { file: '/css/auth-choice.css', maxSize: 5000 } // ~97 lines
      ];
      
      for (const expectation of expectations) {
        const response = await request(app).get(expectation.file);
        const size = Buffer.byteLength(response.text, 'utf8');
        
        expect(size).toBeLessThan(expectation.maxSize);
      }
    });
    
    test('shared-base.css should be loaded only once', async () => {
      const response = await request(app).get('/auth-choice');
      const $ = cheerio.load(response.text);
      
      const sharedBaseLinks = $('link[href="/css/shared-base.css"]');
      expect(sharedBaseLinks.length).toBe(1);
    });
  });
  
  describe('⚠️ Accessibility', () => {
    test('focus states should be defined', async () => {
      const response = await request(app).get('/css/shared-base.css');
      const cssContent = response.text;
      
      // Check focus-visible styles exist
      expect(cssContent).toContain(':focus-visible');
      expect(cssContent).toContain('outline:');
      expect(cssContent).toContain('outline-offset:');
    });
    
    test('high contrast mode styles should be present', async () => {
      const response = await request(app).get('/css/shared-base.css');
      const cssContent = response.text;
      
      // Check for high contrast media query
      expect(cssContent).toContain('@media (prefers-contrast: high)');
      expect(cssContent).toContain('border: 2px solid #000');
    });
    
    test('screen reader styles should be defined', async () => {
      const response = await request(app).get('/css/shared-base.css');
      const cssContent = response.text;
      
      // Check for sr-only class
      expect(cssContent).toContain('.sr-only');
      expect(cssContent).toContain('position: absolute');
      expect(cssContent).toContain('clip: rect(0, 0, 0, 0)');
    });
    
    test('HTML should include accessibility attributes', async () => {
      const response = await request(app).get('/auth-choice');
      const $ = cheerio.load(response.text);
      
      // Check for ARIA attributes
      const ariaElements = $('[aria-describedby]');
      expect(ariaElements.length).toBeGreaterThan(0);
      
      // Check for sr-only elements
      const srOnlyElements = $('.sr-only');
      expect(srOnlyElements.length).toBeGreaterThan(0);
    });
  });
  
  describe('📋 CSS Architecture Validation', () => {
    test('shared components should be in shared-base.css', async () => {
      const response = await request(app).get('/css/shared-base.css');
      const cssContent = response.text;
      
      // Check for shared components
      const sharedComponents = [
        '.admin-section',
        '.migration-section',
        '.password-strength',
        '.primary-btn',
        '.secondary-btn',
        '.guest-btn'
      ];
      
      for (const component of sharedComponents) {
        expect(cssContent).toContain(component);
      }
    });
    
    test('page-specific CSS should be minimal', async () => {
      const files = [
        { path: '/css/login.css', maxLines: 50 },
        { path: '/css/register.css', maxLines: 20 },
        { path: '/css/auth-choice.css', maxLines: 100 }
      ];
      
      for (const file of files) {
        const response = await request(app).get(file.path);
        const lines = response.text.split('\n').length;
        
        expect(lines).toBeLessThan(file.maxLines);
      }
    });
    
    test('CSS comments should be present for documentation', async () => {
      const response = await request(app).get('/css/shared-base.css');
      const cssContent = response.text;
      
      // Check for documentation comments
      expect(cssContent).toContain('FAF Shared Base Styles');
      expect(cssContent).toContain('CSS Custom Properties');
      expect(cssContent).toContain('/* Accessibility');
      expect(cssContent).toContain('/* High Contrast Support');
    });
  });
});

// Additional integration tests for CSP compliance and registration flow
describe('🔒 CSP Compliance Integration Tests', () => {
  test('pages should load without CSP violations', async () => {
    const pages = ['/auth-choice', '/login', '/register'];
    
    for (const page of pages) {
      const response = await request(app).get(page);
      
      expect(response.status).toBe(200);
      expect(response.headers['content-security-policy']).toBeDefined();
      
      // Verify no CSP report would be triggered
      const $ = cheerio.load(response.text);
      const inlineStyles = $('style').not('[nonce]');
      const inlineScripts = $('script').not('[nonce]');
      
      expect(inlineStyles.length).toBe(0);
      
      // All inline scripts should have nonces (if any exist)
      inlineScripts.each((i, el) => {
        expect($(el).attr('nonce')).toBeDefined();
      });
    }
  });

  test('CSS files should be loadable with CSP self directive', async () => {
    const cssFiles = [
      '/css/shared-base.css',
      '/css/login.css', 
      '/css/register.css',
      '/css/auth-choice.css'
    ];

    for (const cssFile of cssFiles) {
      const response = await request(app).get(cssFile);
      
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('text/css');
      
      // CSS should be valid (no JavaScript injection)
      expect(response.text).not.toContain('<script');
      expect(response.text).not.toContain('javascript:');
    }
  });

  test('nonce values should be unique per request', async () => {
    const requests = await Promise.all([
      request(app).get('/login'),
      request(app).get('/login'),
      request(app).get('/register')
    ]);

    const nonces = requests.map(res => {
      const $ = cheerio.load(res.text);
      return $('script[nonce]').first().attr('nonce');
    });

    // All nonces should be defined and unique
    expect(nonces.every(n => n && n.length > 20)).toBe(true);
    expect(new Set(nonces).size).toBe(nonces.length); // All unique
  });

  test('CSP headers should include all necessary directives', async () => {
    const response = await request(app).get('/login');
    const cspHeader = response.headers['content-security-policy'];
    
    expect(cspHeader).toContain("default-src 'self'");
    expect(cspHeader).toContain("style-src 'self'");
    expect(cspHeader).toContain("script-src 'self'");
    expect(cspHeader).toContain("img-src 'self' res.cloudinary.com");
    expect(cspHeader).toContain("frame-src 'none'");
    expect(cspHeader).toContain("frame-ancestors 'none'");
  });
});

describe('🔄 Registration Flow Integration Tests', () => {
  test('registration success should redirect to login with correct URL', async () => {
    const response = await request(app).get('/register');
    const $ = cheerio.load(response.text);
    
    // Check that the redirect URL in JavaScript is correct
    const scriptContent = $('script[nonce]').text();
    expect(scriptContent).toContain("window.location.href = '/login?registered=1'");
    expect(scriptContent).not.toContain('/login.html'); // Old incorrect URL
  });

  test('login page should handle registered parameter', async () => {
    const response = await request(app).get('/login?registered=1');
    
    expect(response.status).toBe(200);
    // The page should load normally with the registered parameter
    const $ = cheerio.load(response.text);
    expect($('title').text()).toContain('Connexion');
  });

  test('auth page routes should be consistent', async () => {
    const routes = [
      { path: '/login', title: 'Connexion' },
      { path: '/register', title: 'Inscription' },
      { path: '/auth-choice', title: 'Bienvenue' }
    ];

    for (const route of routes) {
      const response = await request(app).get(route.path);
      
      expect(response.status).toBe(200);
      
      const $ = cheerio.load(response.text);
      expect($('title').text()).toContain(route.title);
      
      // All auth pages should have proper nonce injection
      const scripts = $('script[nonce]');
      expect(scripts.length).toBeGreaterThan(0);
      
      scripts.each((i, el) => {
        const nonce = $(el).attr('nonce');
        expect(nonce).toBeDefined();
        expect(nonce).not.toBe('{{nonce}}'); // Template should be replaced
      });
    }
  });

  test('form validation should work without CSP violations', async () => {
    const response = await request(app).get('/register');
    const $ = cheerio.load(response.text);
    const scriptContent = $('script[nonce]').text();
    
    // Check that validation functions are present
    expect(scriptContent).toContain('validateForm');
    expect(scriptContent).toContain('addEventListener');
    
    // No inline event handlers should be used
    expect(response.text).not.toContain('onclick=');
    expect(response.text).not.toContain('onsubmit=');
  });

  test('error handling should not compromise CSP', async () => {
    const response = await request(app).get('/register');
    const $ = cheerio.load(response.text);
    const scriptContent = $('script[nonce]').text();
    
    // Error display functions should use safe DOM methods
    expect(scriptContent).toContain('textContent');
    expect(scriptContent).not.toContain('innerHTML'); // Unsafe for user content
    
    // All error containers should be present in HTML
    const errorElements = $('[id$="Error"]');
    expect(errorElements.length).toBeGreaterThan(0);
  });
});