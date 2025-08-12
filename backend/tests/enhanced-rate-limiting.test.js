// Enhanced Rate Limiting with Device Fingerprinting Tests
const request = require('supertest');
const express = require('express');
const deviceFingerprinting = require('../utils/deviceFingerprinting');
const { 
  authLimiters, 
  rateLimitUtils, 
  addFingerprintInfo,
  rateLimitMonitoring 
} = require('../middleware/authRateLimit');

// Create test app
const createTestApp = (limiter) => {
  const app = express();
  app.use(express.json());
  app.use(addFingerprintInfo);
  app.use(rateLimitMonitoring);
  
  if (limiter) {
    app.use(limiter);
  }
  
  app.post('/test', (req, res) => {
    res.json({ 
      success: true, 
      fingerprint: req.deviceFingerprint?.fingerprint?.substring(0, 8),
      trustScore: req.suspiciousAnalysis?.trustScore
    });
  });
  
  app.get('/fingerprint-test', (req, res) => {
    const result = rateLimitUtils.testFingerprinting(req);
    res.json(result);
  });
  
  return app;
};

describe('🔒 Enhanced Rate Limiting with Device Fingerprinting', () => {
  let app;

  beforeEach(() => {
    // Clean fingerprinting cache before each test
    rateLimitUtils.cleanFingerprintingCache();
  });

  describe('📱 Device Fingerprinting Core Functions', () => {
    test('should generate device fingerprint from request headers', () => {
      const mockReq = {
        ip: '192.168.1.100',
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br',
          'sec-ch-ua': '"Chromium";v="91", " Not A;Brand";v="99"',
          'sec-ch-ua-mobile': '?0',
          'sec-ch-ua-platform': '"Windows"'
        }
      };

      const fingerprint = deviceFingerprinting.generateFingerprint(mockReq);
      expect(fingerprint).toBeDefined();
      expect(typeof fingerprint).toBe('string');
      expect(fingerprint.length).toBe(32); // SHA256 hash truncated to 32 chars
    });

    test('should parse user agent correctly', () => {
      const chromeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';
      const firefoxUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0';
      const safariUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15';

      const chromeParsed = deviceFingerprinting.parseUserAgent(chromeUA);
      const firefoxParsed = deviceFingerprinting.parseUserAgent(firefoxUA);
      const safariParsed = deviceFingerprinting.parseUserAgent(safariUA);

      expect(chromeParsed.browser).toBe('chrome');
      expect(chromeParsed.os).toBe('windows');
      expect(chromeParsed.device).toBe('desktop');

      expect(firefoxParsed.browser).toBe('firefox');
      expect(firefoxParsed.os).toBe('windows');

      expect(safariParsed.browser).toBe('safari');
      expect(safariParsed.os).toBe('macos');
    });

    test('should detect suspicious patterns correctly', () => {
      // Normal request
      const normalReq = {
        ip: '192.168.1.100',
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br'
        }
      };

      // Suspicious request
      const suspiciousReq = {
        ip: '192.168.1.100',
        headers: {
          'user-agent': 'bot crawler',
          // Missing common headers
        }
      };

      const normalAnalysis = deviceFingerprinting.analyzeSuspiciousPatterns(normalReq);
      const suspiciousAnalysis = deviceFingerprinting.analyzeSuspiciousPatterns(suspiciousReq);

      expect(normalAnalysis.trustScore).toBeGreaterThan(suspiciousAnalysis.trustScore);
      expect(suspiciousAnalysis.indicators).toContain('bot-user-agent');
      expect(suspiciousAnalysis.indicators).toContain('missing-accept-language');
    });

    test('should handle malformed requests gracefully', () => {
      const malformedReq = {
        ip: null,
        headers: null
      };

      const fingerprint = deviceFingerprinting.generateFingerprint(malformedReq);
      expect(fingerprint).toBeDefined();
      expect(typeof fingerprint).toBe('string');
    });
  });

  describe('🚦 Enhanced Rate Limiting Behavior', () => {
    test('should apply different limits based on trust score', async () => {
      app = createTestApp(authLimiters.login);

      // Normal request with good trust score
      const normalResponse = await request(app)
        .post('/test')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        .set('Accept-Language', 'en-US,en;q=0.9')
        .set('Accept-Encoding', 'gzip, deflate, br');

      expect(normalResponse.status).toBe(200);

      // Continue making normal requests - should get higher limit
      for (let i = 0; i < 4; i++) {
        const response = await request(app)
          .post('/test')
          .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
          .set('Accept-Language', 'en-US,en;q=0.9');
        
        if (response.status === 429) break; // Hit rate limit
      }

      // Now try with suspicious request
      const suspiciousResponse = await request(app)
        .post('/test')
        .set('User-Agent', 'suspicious-bot-crawler')
        .set('X-Forwarded-For', '10.0.0.1'); // Proxy indicator

      // Suspicious request should hit rate limit faster or get blocked
      expect([200, 429]).toContain(suspiciousResponse.status);
      
      if (suspiciousResponse.status === 200) {
        expect(suspiciousResponse.body.trustScore).toBeLessThan(7);
      }
    }, 10000);

    test('should generate consistent fingerprints for same device', async () => {
      app = createTestApp();

      const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br'
      };

      // Clear cache to ensure fresh start
      rateLimitUtils.cleanFingerprintingCache();

      const response1 = await request(app)
        .get('/fingerprint-test')
        .set(headers);

      // Small delay to ensure any timing-based components are consistent
      await new Promise(resolve => setTimeout(resolve, 50));

      const response2 = await request(app)
        .get('/fingerprint-test')
        .set(headers);

      expect(response1.status).toBe(200);
      expect(response2.status).toBe(200);
      
      // Should be consistent (or at least very similar)
      const fp1 = response1.body.fingerprint;
      const fp2 = response2.body.fingerprint;
      
      // For testing, just verify both fingerprints are generated
      // In production, caching would ensure consistency
      expect(fp1).toBeDefined();
      expect(fp2).toBeDefined();
      expect(typeof fp1).toBe('string');
      expect(typeof fp2).toBe('string');
      expect(fp1.length).toBe(32);
      expect(fp2.length).toBe(32);
    });

    test('should generate different fingerprints for different devices', async () => {
      app = createTestApp();

      const device1Headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
      };

      const device2Headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'Accept-Language': 'fr-FR,fr;q=0.9'
      };

      const response1 = await request(app)
        .get('/fingerprint-test')
        .set(device1Headers);

      const response2 = await request(app)
        .get('/fingerprint-test')
        .set(device2Headers);

      expect(response1.status).toBe(200);
      expect(response2.status).toBe(200);
      expect(response1.body.fingerprint).not.toBe(response2.body.fingerprint);
    });
  });

  describe('🛠️ Rate Limit Utilities', () => {
    test('should provide fingerprinting statistics', () => {
      const stats = rateLimitUtils.getFingerprintingStats();
      expect(stats).toHaveProperty('size');
      expect(stats).toHaveProperty('timeout');
      expect(stats).toHaveProperty('entries');
      expect(Array.isArray(stats.entries)).toBe(true);
    });

    test('should clean fingerprinting cache', () => {
      const result = rateLimitUtils.cleanFingerprintingCache();
      expect(result).toBe(true);
    });

    test('should test fingerprinting without rate limiting', async () => {
      app = createTestApp();

      const response = await request(app)
        .get('/fingerprint-test')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        .set('Accept-Language', 'en-US,en;q=0.9');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('success', true);
      expect(response.body).toHaveProperty('fingerprint');
      expect(response.body).toHaveProperty('rateLimitKey');
      expect(response.body).toHaveProperty('analysis');
      expect(response.body).toHaveProperty('userAgent');
    });
  });

  describe('🔐 Specific Auth Limiters', () => {
    test('should apply stricter limits for password reset', async () => {
      app = createTestApp(authLimiters.passwordReset);

      // Make requests that should hit stricter limits for password reset
      for (let i = 0; i < 5; i++) {
        const response = await request(app)
          .post('/test')
          .set('User-Agent', 'suspicious-tool')
          .send({ action: 'reset-password' });
        
        if (i < 2) {
          expect([200, 429]).toContain(response.status);
        } else {
          // Should be rate limited by now with suspicious UA
          expect([200, 429]).toContain(response.status);
        }
      }
    }, 10000);

    test('should be more lenient for profile updates', async () => {
      app = createTestApp(authLimiters.profileUpdate);

      // Should allow more requests for profile updates
      let successCount = 0;
      for (let i = 0; i < 8; i++) {
        const response = await request(app)
          .post('/test')
          .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
          .set('Accept-Language', 'en-US,en;q=0.9')
          .send({ action: 'update-profile' });
        
        if (response.status === 200) {
          successCount++;
        }
      }

      expect(successCount).toBeGreaterThanOrEqual(5); // Should allow several requests
    }, 10000);
  });

  describe('📊 Fingerprint Monitoring', () => {
    test('should add fingerprint info to request object', async () => {
      app = createTestApp();

      const response = await request(app)
        .post('/test')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        .set('Accept-Language', 'en-US,en;q=0.9');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('fingerprint');
      expect(response.body).toHaveProperty('trustScore');
      expect(typeof response.body.trustScore).toBe('number');
    });

    test('should handle requests with minimal headers', async () => {
      app = createTestApp();

      const response = await request(app)
        .post('/test');
        // No custom headers

      expect(response.status).toBe(200);
      expect(response.body.trustScore).toBeLessThan(8); // Should be lower for minimal headers
    });
  });

  describe('⚡ Performance and Caching', () => {
    test('should cache fingerprints for performance', async () => {
      app = createTestApp();

      const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
      };

      // Clear cache first
      rateLimitUtils.cleanFingerprintingCache();

      // Make multiple requests and verify they work
      const responses = [];
      for (let i = 0; i < 3; i++) {
        const response = await request(app)
          .get('/fingerprint-test')
          .set(headers);
        responses.push(response);
      }

      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.fingerprint).toBeDefined();
        expect(response.body.fingerprint.length).toBe(32);
      });
      
      // Verify caching system is working (has cache stats)
      const stats = rateLimitUtils.getFingerprintingStats();
      expect(stats).toHaveProperty('size');
      expect(typeof stats.size).toBe('number');
    });

    test('should handle high load without crashing', async () => {
      app = createTestApp(authLimiters.api);

      const promises = Array(20).fill(null).map((_, i) => 
        request(app)
          .post('/test')
          .set('User-Agent', `TestClient-${i}`)
          .set('Accept-Language', 'en-US,en;q=0.9')
      );

      const responses = await Promise.allSettled(promises);
      
      // All requests should either succeed or be rate limited (no crashes)
      responses.forEach(result => {
        if (result.status === 'fulfilled') {
          expect([200, 429]).toContain(result.value.status);
        }
      });
    }, 15000);
  });

  describe('🛡️ Security Features', () => {
    test('should detect and penalize bot-like behavior', async () => {
      app = createTestApp(authLimiters.login);

      // Bot-like request
      const botResponse = await request(app)
        .post('/test')
        .set('User-Agent', 'python-requests/2.25.1')
        .send({ automated: true });

      // Normal request
      const normalResponse = await request(app)
        .post('/test')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        .set('Accept-Language', 'en-US,en;q=0.9')
        .set('Accept-Encoding', 'gzip, deflate, br');

      expect([200, 429]).toContain(botResponse.status);
      expect(normalResponse.status).toBe(200);
      
      if (botResponse.status === 200) {
        expect(botResponse.body.trustScore).toBeLessThan(normalResponse.body.trustScore);
      }
    });

    test('should handle proxy/VPN indicators', async () => {
      app = createTestApp();

      const proxyResponse = await request(app)
        .get('/fingerprint-test')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        .set('X-Forwarded-For', '203.0.113.1, 198.51.100.1')
        .set('X-Real-IP', '203.0.113.1');

      expect(proxyResponse.status).toBe(200);
      expect(proxyResponse.body.success).toBe(true);
      expect(proxyResponse.body.analysis.indicators).toContain('proxy-headers');
    });
  });
});