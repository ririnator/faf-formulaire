/**
 * Configuration Lighthouse CI - FAF Multi-Tenant
 * Objectif : Score > 90 pour Performance, Accessibility, Best Practices, SEO
 */

module.exports = {
  ci: {
    collect: {
      numberOfRuns: 3,
      startServerCommand: 'vercel dev',
      startServerReadyPattern: 'Ready! Available at',
      startServerReadyTimeout: 30000,
      url: [
        'http://localhost:3001/',
        'http://localhost:3001/auth/login.html',
        'http://localhost:3001/auth/register.html',
        'http://localhost:3001/admin/dashboard.html'
      ],
      settings: {
        preset: 'desktop',
        throttling: {
          rttMs: 40,
          throughputKbps: 10 * 1024,
          cpuSlowdownMultiplier: 1
        }
      }
    },
    assert: {
      assertions: {
        // Performance
        'categories:performance': ['error', { minScore: 0.9 }],

        // Accessibility
        'categories:accessibility': ['error', { minScore: 0.9 }],

        // Best Practices
        'categories:best-practices': ['error', { minScore: 0.9 }],

        // SEO
        'categories:seo': ['error', { minScore: 0.9 }],

        // Core Web Vitals
        'first-contentful-paint': ['warn', { maxNumericValue: 2000 }],
        'largest-contentful-paint': ['warn', { maxNumericValue: 2500 }],
        'cumulative-layout-shift': ['warn', { maxNumericValue: 0.1 }],
        'total-blocking-time': ['warn', { maxNumericValue: 300 }],

        // Security
        'is-on-https': 'off', // Désactivé pour local
        'uses-http2': 'off',

        // Network
        'offscreen-images': 'warn',
        'render-blocking-resources': 'warn',
        'unminified-css': 'warn',
        'unminified-javascript': 'warn',
        'unused-css-rules': 'warn',
        'uses-long-cache-ttl': 'warn',
        'uses-optimized-images': 'warn',
        'uses-text-compression': 'warn',
        'uses-responsive-images': 'warn',

        // Errors
        'errors-in-console': 'warn'
      }
    },
    upload: {
      target: 'temporary-public-storage'
    }
  }
};
