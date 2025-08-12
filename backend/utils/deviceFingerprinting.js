// Advanced Device Fingerprinting for Enhanced Rate Limiting
const crypto = require('crypto');
const SecureLogger = require('./secureLogger');

class DeviceFingerprinting {
  constructor() {
    this.fingerprintCache = new Map();
    this.cacheTimeout = 5 * 60 * 1000; // 5 minutes cache
  }

  /**
   * Generate comprehensive device fingerprint
   */
  generateFingerprint(req) {
    try {
      const fingerprint = this.extractDeviceCharacteristics(req);
      const hash = this.hashFingerprint(fingerprint);
      
      // Cache fingerprint for performance
      this.fingerprintCache.set(req.ip, {
        fingerprint: hash,
        timestamp: Date.now(),
        raw: fingerprint
      });
      
      return hash;
    } catch (error) {
      SecureLogger.logError('Fingerprinting failed', error);
      return this.fallbackFingerprint(req);
    }
  }

  /**
   * Extract comprehensive device characteristics
   */
  extractDeviceCharacteristics(req) {
    const headers = req.headers || {};
    
    return {
      // Network characteristics
      ip: req.ip || req.connection?.remoteAddress || 'unknown',
      forwarded: headers['x-forwarded-for'] || null,
      realIp: headers['x-real-ip'] || null,
      
      // Browser and device info
      userAgent: headers['user-agent'] || 'unknown',
      acceptLanguage: headers['accept-language'] || null,
      acceptEncoding: headers['accept-encoding'] || null,
      accept: headers['accept'] || null,
      
      // Browser capabilities and preferences
      dnt: headers['dnt'] || headers['DNT'] || null, // Do Not Track
      upgradeInsecureRequests: headers['upgrade-insecure-requests'] || null,
      secFetchSite: headers['sec-fetch-site'] || null,
      secFetchMode: headers['sec-fetch-mode'] || null,
      secFetchUser: headers['sec-fetch-user'] || null,
      secFetchDest: headers['sec-fetch-dest'] || null,
      
      // Connection characteristics
      connection: headers['connection'] || null,
      cacheControl: headers['cache-control'] || null,
      pragma: headers['pragma'] || null,
      
      // Security headers that vary by browser/setup
      secChUa: headers['sec-ch-ua'] || null,
      secChUaMobile: headers['sec-ch-ua-mobile'] || null,
      secChUaPlatform: headers['sec-ch-ua-platform'] || null,
      secChUaArch: headers['sec-ch-ua-arch'] || null,
      secChUaModel: headers['sec-ch-ua-model'] || null,
      secChUaBitness: headers['sec-ch-ua-bitness'] || null,
      secChUaFullVersion: headers['sec-ch-ua-full-version'] || null,
      secChUaPlatformVersion: headers['sec-ch-ua-platform-version'] || null,
      
      // Additional fingerprinting vectors
      referer: this.sanitizeReferer(headers['referer']),
      origin: headers['origin'] || null,
      
      // TLS/HTTP version indicators
      httpVersion: req.httpVersion || null,
      httpVersionMajor: req.httpVersionMajor || null,
      httpVersionMinor: req.httpVersionMinor || null,
      
      // Timing characteristics (exclude for consistent testing)
      // requestTime: Date.now(),
      
      // Custom headers that might be device-specific
      customHeaders: this.extractCustomHeaders(headers)
    };
  }

  /**
   * Parse and extract meaningful info from User-Agent
   */
  parseUserAgent(userAgent) {
    if (!userAgent || userAgent === 'unknown') {
      return { browser: 'unknown', os: 'unknown', device: 'unknown' };
    }

    const ua = userAgent.toLowerCase();
    
    // Browser detection
    let browser = 'unknown';
    if (ua.includes('chrome/') && !ua.includes('edg/')) browser = 'chrome';
    else if (ua.includes('firefox/')) browser = 'firefox';
    else if (ua.includes('safari/') && !ua.includes('chrome/')) browser = 'safari';
    else if (ua.includes('edg/')) browser = 'edge';
    else if (ua.includes('opera/') || ua.includes('opr/')) browser = 'opera';

    // OS detection
    let os = 'unknown';
    if (ua.includes('windows')) os = 'windows';
    else if (ua.includes('mac os x') || ua.includes('macos')) os = 'macos';
    else if (ua.includes('linux')) os = 'linux';
    else if (ua.includes('android')) os = 'android';
    else if (ua.includes('iphone') || ua.includes('ipad')) os = 'ios';

    // Device type detection
    let device = 'desktop';
    if (ua.includes('mobile') || ua.includes('android')) device = 'mobile';
    else if (ua.includes('tablet') || ua.includes('ipad')) device = 'tablet';
    else if (ua.includes('smart-tv') || ua.includes('tv')) device = 'tv';

    return { browser, os, device };
  }

  /**
   * Sanitize referer to avoid logging sensitive data
   */
  sanitizeReferer(referer) {
    if (!referer) return null;
    
    try {
      const url = new URL(referer);
      // Only keep domain and path, strip query params and fragments
      return `${url.protocol}//${url.host}${url.pathname}`;
    } catch {
      return 'invalid-referer';
    }
  }

  /**
   * Extract custom headers that might be device-specific
   */
  extractCustomHeaders(headers) {
    const customHeaders = {};
    
    // Headers that might vary by device/setup
    const interestingHeaders = [
      'cf-ray', 'cf-ipcountry', // Cloudflare
      'x-forwarded-port', 'x-forwarded-proto',
      'x-request-id', 'x-correlation-id',
      'x-client-ip', 'x-cluster-client-ip',
      'fastly-client-ip', 'true-client-ip',
      'x-amz-cf-id', // Amazon CloudFront
      'x-azure-ref', // Azure
      'x-ms-request-id' // Microsoft
    ];

    interestingHeaders.forEach(header => {
      if (headers[header]) {
        customHeaders[header] = headers[header];
      }
    });

    return Object.keys(customHeaders).length > 0 ? customHeaders : null;
  }

  /**
   * Hash the fingerprint for privacy and storage efficiency
   */
  hashFingerprint(fingerprint) {
    const stringified = JSON.stringify(fingerprint, Object.keys(fingerprint).sort());
    return crypto.createHash('sha256').update(stringified).digest('hex').substring(0, 32);
  }

  /**
   * Fallback fingerprint using basic info
   */
  fallbackFingerprint(req) {
    const basic = `${req.ip}:${req.headers?.['user-agent'] || 'unknown'}`;
    return crypto.createHash('sha256').update(basic).digest('hex').substring(0, 32);
  }

  /**
   * Get cached fingerprint if available
   */
  getCachedFingerprint(ip) {
    const cached = this.fingerprintCache.get(ip);
    if (cached && (Date.now() - cached.timestamp) < this.cacheTimeout) {
      return cached.fingerprint;
    }
    
    // Clean expired cache entry
    if (cached) {
      this.fingerprintCache.delete(ip);
    }
    
    return null;
  }

  /**
   * Enhanced key generator for rate limiting
   */
  generateRateLimitKey(req, options = {}) {
    const {
      includeUserAgent = true,
      includeLanguage = false,
      includeSecHeaders = true,
      includeTiming = false
    } = options;

    // Check cache first
    const cached = this.getCachedFingerprint(req.ip);
    if (cached && !includeTiming) {
      return cached;
    }

    // Generate new fingerprint
    const fingerprint = this.generateFingerprint(req);
    
    // Add timing component if requested (prevents caching)
    if (includeTiming) {
      const timeWindow = Math.floor(Date.now() / (5 * 60 * 1000)); // 5-minute windows
      return `${fingerprint}:${timeWindow}`;
    }

    return fingerprint;
  }

  /**
   * Analyze fingerprint for suspicious patterns
   */
  analyzeSuspiciousPatterns(req) {
    const characteristics = this.extractDeviceCharacteristics(req);
    const userAgentInfo = this.parseUserAgent(characteristics.userAgent);
    const suspiciousIndicators = [];

    // Check for bot-like patterns
    if (characteristics.userAgent.toLowerCase().includes('bot') || 
        characteristics.userAgent.toLowerCase().includes('crawler')) {
      suspiciousIndicators.push('bot-user-agent');
    }

    // Check for missing common headers
    if (!characteristics.acceptLanguage) {
      suspiciousIndicators.push('missing-accept-language');
    }

    // Check for unusual header combinations
    if (characteristics.secFetchSite && !characteristics.userAgent.includes('Chrome')) {
      suspiciousIndicators.push('sec-fetch-non-chrome');
    }

    // Check for proxy/VPN indicators
    if (characteristics.forwarded || characteristics.realIp) {
      suspiciousIndicators.push('proxy-headers');
    }

    // Check for automated tool patterns
    if (characteristics.userAgent.length < 20 || 
        characteristics.userAgent === 'unknown') {
      suspiciousIndicators.push('minimal-user-agent');
    }

    // Check for inconsistent browser headers
    if (userAgentInfo.browser === 'chrome' && !characteristics.secChUa) {
      suspiciousIndicators.push('chrome-missing-sec-ch-ua');
    }

    return {
      suspiciousCount: suspiciousIndicators.length,
      indicators: suspiciousIndicators,
      trustScore: Math.max(0, 10 - suspiciousIndicators.length * 2) // 0-10 scale
    };
  }

  /**
   * Generate detailed fingerprint report for analysis
   */
  generateFingerprintReport(req) {
    const characteristics = this.extractDeviceCharacteristics(req);
    const userAgentInfo = this.parseUserAgent(characteristics.userAgent);
    const suspiciousAnalysis = this.analyzeSuspiciousPatterns(req);
    const fingerprint = this.hashFingerprint(characteristics);

    return {
      fingerprint,
      characteristics: {
        ...characteristics,
        userAgentParsed: userAgentInfo
      },
      analysis: suspiciousAnalysis,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Clean up expired cache entries
   */
  cleanupCache() {
    const now = Date.now();
    for (const [key, value] of this.fingerprintCache.entries()) {
      if ((now - value.timestamp) >= this.cacheTimeout) {
        this.fingerprintCache.delete(key);
      }
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.fingerprintCache.size,
      timeout: this.cacheTimeout,
      entries: Array.from(this.fingerprintCache.entries()).map(([key, value]) => ({
        key,
        age: Date.now() - value.timestamp
      }))
    };
  }
}

// Singleton instance
const deviceFingerprinting = new DeviceFingerprinting();

// Cleanup cache every 10 minutes (only in production)
if (process.env.NODE_ENV === 'production') {
  setInterval(() => {
    deviceFingerprinting.cleanupCache();
  }, 10 * 60 * 1000);
}

module.exports = deviceFingerprinting;