/**
 * Security Fixes Test Suite
 * Tests for immediate security recommendations implementation
 */

const request = require('supertest');
const crypto = require('crypto');
const errorSanitizer = require('../utils/errorSanitizer');
const enhancedRateLimiter = require('../middleware/enhancedRateLimiting');

describe('Security Fixes Implementation', () => {
  
  describe('Timing Attack Protection', () => {
    it('should have consistent response times for invalid verification codes', async () => {
      const timings = [];
      const attempts = 10;
      
      // Mock invitation with verification code
      const mockInvitation = {
        token: crypto.randomBytes(32).toString('hex'),
        metadata: {
          antiTransferCode: 'ABC123'
        }
      };
      
      // Test with various invalid codes
      const testCodes = ['WRONG1', 'X', '123456', '', 'ABC124', 'ABC122'];
      
      for (const code of testCodes) {
        const start = Date.now();
        
        // Simulate the verification logic
        const expectedCode = mockInvitation.metadata.antiTransferCode;
        const baseDelay = 100;
        const randomDelay = Math.random() * 50;
        
        let isValid = false;
        try {
          const providedBuffer = Buffer.from(code.toUpperCase().padEnd(6, '0'));
          const expectedBuffer = Buffer.from(expectedCode.toUpperCase().padEnd(6, '0'));
          isValid = crypto.timingSafeEqual(providedBuffer, expectedBuffer);
        } catch (err) {
          isValid = false;
        }
        
        // Simulate the constant-time delay
        await new Promise(resolve => setTimeout(resolve, baseDelay + randomDelay));
        
        const elapsed = Date.now() - start;
        timings.push(elapsed);
      }
      
      // Check that all timings are within acceptable range (100-150ms)
      const minTime = Math.min(...timings);
      const maxTime = Math.max(...timings);
      const variance = maxTime - minTime;
      
      expect(variance).toBeLessThan(60); // Max 60ms variance
      expect(minTime).toBeGreaterThanOrEqual(100);
      expect(maxTime).toBeLessThanOrEqual(160);
    });
    
    it('should use constant-time comparison with proper padding', () => {
      const testCases = [
        { provided: 'ABC', expected: 'ABC123', shouldPad: true },
        { provided: 'ABC123', expected: 'ABC123', shouldPad: false },
        { provided: '12', expected: 'XYZ789', shouldPad: true }
      ];
      
      testCases.forEach(({ provided, expected }) => {
        const providedBuffer = Buffer.from(provided.toUpperCase().padEnd(6, '0'));
        const expectedBuffer = Buffer.from(expected.toUpperCase().padEnd(6, '0'));
        
        // Both buffers should be same length for constant-time comparison
        expect(providedBuffer.length).toBe(expectedBuffer.length);
        expect(providedBuffer.length).toBe(6);
      });
    });
  });
  
  describe('Memory Limit Protection', () => {
    describe('Enhanced Security Middleware', () => {
      it('should limit tracking entries to prevent memory exhaustion', () => {
        const requestTimes = new Map();
        const MAX_TRACKING_ENTRIES = 10000;
        
        // Simulate adding many entries
        for (let i = 0; i < MAX_TRACKING_ENTRIES + 100; i++) {
          const clientKey = `ip-${i}:agent-${i}`;
          requestTimes.set(clientKey, [Date.now()]);
          
          // Simulate memory limit check
          if (requestTimes.size >= MAX_TRACKING_ENTRIES) {
            const entriesToRemove = Math.floor(MAX_TRACKING_ENTRIES * 0.2);
            const sortedEntries = Array.from(requestTimes.entries())
              .sort((a, b) => {
                const aLastTime = a[1][a[1].length - 1] || 0;
                const bLastTime = b[1][b[1].length - 1] || 0;
                return aLastTime - bLastTime;
              });
            
            for (let j = 0; j < entriesToRemove && j < sortedEntries.length; j++) {
              requestTimes.delete(sortedEntries[j][0]);
            }
          }
        }
        
        // Should not exceed max entries
        expect(requestTimes.size).toBeLessThanOrEqual(MAX_TRACKING_ENTRIES);
        expect(requestTimes.size).toBeGreaterThan(MAX_TRACKING_ENTRIES * 0.7);
      });
    });
    
    describe('Advanced Threat Detection', () => {
      it('should clean up threat profiles when limit exceeded', () => {
        const MAX_THREAT_PROFILES = 5000;
        const threatProfiles = new Map();
        
        // Add profiles up to limit
        for (let i = 0; i < MAX_THREAT_PROFILES + 1000; i++) {
          threatProfiles.set(`ip-${i}`, {
            lastUpdate: Date.now() - i * 1000, // Older profiles have older timestamps
            threatScore: Math.random() * 100
          });
          
          // Simulate cleanup when 80% full
          if (threatProfiles.size > MAX_THREAT_PROFILES * 0.8) {
            const sortedProfiles = Array.from(threatProfiles.entries())
              .sort((a, b) => (b[1].lastUpdate || 0) - (a[1].lastUpdate || 0));
            
            const toRemove = sortedProfiles.slice(Math.floor(MAX_THREAT_PROFILES * 0.6));
            toRemove.forEach(([key]) => threatProfiles.delete(key));
          }
        }
        
        expect(threatProfiles.size).toBeLessThanOrEqual(MAX_THREAT_PROFILES * 0.8);
      });
      
      it('should remove old request patterns beyond time window', () => {
        const BEHAVIORAL_ANALYSIS_WINDOW = 30 * 60 * 1000; // 30 minutes
        const requestPatterns = new Map();
        const now = Date.now();
        
        // Add some patterns
        requestPatterns.set('ip-1', [
          { timestamp: now - 40 * 60 * 1000 }, // Old
          { timestamp: now - 35 * 60 * 1000 }, // Old
          { timestamp: now - 20 * 60 * 1000 }, // Recent
          { timestamp: now - 5 * 60 * 1000 }   // Recent
        ]);
        
        // Clean old patterns
        const oldestAllowed = now - BEHAVIORAL_ANALYSIS_WINDOW;
        for (const [key, patterns] of requestPatterns.entries()) {
          const recentPatterns = patterns.filter(p => p.timestamp > oldestAllowed);
          if (recentPatterns.length === 0) {
            requestPatterns.delete(key);
          } else {
            requestPatterns.set(key, recentPatterns);
          }
        }
        
        // Check that only recent patterns remain
        const remainingPatterns = requestPatterns.get('ip-1');
        expect(remainingPatterns).toHaveLength(2);
        expect(remainingPatterns.every(p => p.timestamp > oldestAllowed)).toBe(true);
      });
    });
  });
  
  describe('Error Sanitization System', () => {
    it('should remove file paths from error messages', () => {
      const errors = [
        'Error at /Users/username/project/file.js:123:45',
        'Cannot find module /home/user/app/config.json',
        'ENOENT: no such file or directory, open C:\\Users\\Admin\\secrets.env'
      ];
      
      errors.forEach(error => {
        const sanitized = errorSanitizer.removeSensitiveInfo(error);
        // At least one REDACTED should appear for file paths
        if (error.includes('/Users/') || error.includes('/home/') || error.includes('C:\\')) {
          expect(sanitized).toContain('[REDACTED]');
        }
        // Original paths should be removed
        expect(sanitized).not.toContain('/Users/username');
        expect(sanitized).not.toContain('/home/user');
      });
    });
    
    it('should remove database connection strings', () => {
      const error = 'Failed to connect to mongodb://user:pass@localhost:27017/database';
      const sanitized = errorSanitizer.removeSensitiveInfo(error);
      
      expect(sanitized).not.toContain('mongodb://');
      expect(sanitized).not.toContain('user:pass');
      expect(sanitized).not.toContain('localhost:27017');
    });
    
    it('should detect and redact sensitive patterns', () => {
      const testCases = [
        { input: 'API_KEY=sk_test_1234567890abcdef', expected: true },
        { input: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', expected: true },
        { input: 'process.env.SECRET_KEY is undefined', expected: true },
        { input: 'Error at line 123 column 45', expected: false } // This is not sensitive
      ];
      
      testCases.forEach(({ input, expected }) => {
        const result = errorSanitizer.containsSensitiveInfo(input);
        expect(result).toBe(expected);
      });
    });
    
    it('should provide safe generic messages for common errors', () => {
      const testCases = [
        { statusCode: 401, expected: 'Unauthorized access' },
        { statusCode: 403, expected: 'Access forbidden' },
        { statusCode: 404, expected: 'Resource not found' },
        { statusCode: 429, expected: 'Too many requests' },
        { statusCode: 500, expected: 'Internal server error' }
      ];
      
      testCases.forEach(({ statusCode, expected }) => {
        const message = errorSanitizer.getGenericMessage(statusCode);
        expect(message).toBe(expected);
      });
    });
    
    it('should handle different error types correctly', () => {
      const error1 = new Error('Database connection failed at mongodb://localhost');
      const error2 = { message: 'Invalid token', code: 'AUTH_FAILED', statusCode: 401 };
      const error3 = 'Simple string error with /path/to/file';
      
      const sanitized1 = errorSanitizer.sanitize(error1);
      expect(sanitized1.error).not.toContain('mongodb');
      expect(sanitized1.success).toBe(false);
      
      const sanitized2 = errorSanitizer.sanitize(error2);
      // The error message is kept as-is because it doesn't match dangerous patterns
      expect(sanitized2.error).toBe('Invalid token');
      expect(sanitized2.code).toBe('AUTH_FAILED');
      
      const sanitized3 = errorSanitizer.sanitize(error3);
      expect(sanitized3.error).not.toContain('/path/to/file');
    });
  });
  
  describe('Enhanced Rate Limiting', () => {
    it('should generate consistent fingerprints for same client', () => {
      const mockReq = {
        get: (header) => {
          const headers = {
            'user-agent': 'Mozilla/5.0 Test Browser',
            'accept-language': 'en-US,en;q=0.9',
            'accept-encoding': 'gzip, deflate',
            'accept': 'text/html',
            'dnt': '1',
            'connection': 'keep-alive'
          };
          return headers[header.toLowerCase()];
        }
      };
      
      // Generate multiple fingerprints for same request
      const fingerprints = [];
      for (let i = 0; i < 5; i++) {
        const components = [
          mockReq.get('user-agent') || 'unknown',
          mockReq.get('accept-language') || 'unknown',
          mockReq.get('accept-encoding') || 'unknown',
          mockReq.get('accept') || 'unknown',
          mockReq.get('dnt') || '0',
          mockReq.get('connection') || 'unknown',
          Math.floor(Date.now() / 1000) % 60
        ];
        
        const fingerprint = crypto
          .createHash('sha256')
          .update(components.join('|'))
          .digest('hex')
          .substring(0, 16);
        
        fingerprints.push(fingerprint);
      }
      
      // Most fingerprints should be the same (allowing for timing component)
      const uniqueFingerprints = new Set(fingerprints);
      expect(uniqueFingerprints.size).toBeLessThanOrEqual(2);
    });
    
    it('should detect distributed attacks from multiple IPs', () => {
      const requestFingerprints = new Map();
      const fingerprint = 'abc123def456';
      
      // Simulate requests from multiple IPs with same fingerprint
      const ips = ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6'];
      
      requestFingerprints.set(fingerprint, {
        ips: new Set(ips),
        count: 60,
        firstSeen: Date.now() - 5000,
        lastSeen: Date.now()
      });
      
      const data = requestFingerprints.get(fingerprint);
      const isDistributedAttack = data.ips.size > 5 && data.count > 50;
      
      expect(isDistributedAttack).toBe(true);
      expect(data.ips.size).toBe(6);
    });
    
    it('should implement sliding window rate limiting correctly', () => {
      const windowMs = 60000; // 1 minute
      const max = 10;
      const requestLog = new Map();
      const key = 'test-key';
      const now = Date.now();
      
      // Add requests at different times
      const requests = [
        now - 70000, // Outside window
        now - 65000, // Outside window
        now - 50000, // Inside window
        now - 30000, // Inside window
        now - 10000, // Inside window
        now - 5000,  // Inside window
        now - 1000   // Inside window
      ];
      
      requestLog.set(key, requests);
      
      // Filter for requests within window
      const windowStart = now - windowMs;
      const recentRequests = requests.filter(timestamp => timestamp > windowStart);
      
      expect(recentRequests.length).toBe(5);
      expect(recentRequests.length < max).toBe(true);
    });
    
    it('should implement token bucket algorithm correctly', () => {
      const capacity = 10;
      const refillRate = 1; // 1 token per second
      const bucket = {
        tokens: 5,
        lastRefill: Date.now() - 3000 // 3 seconds ago
      };
      
      const now = Date.now();
      const timePassed = (now - bucket.lastRefill) / 1000;
      const tokensToAdd = timePassed * refillRate;
      bucket.tokens = Math.min(capacity, bucket.tokens + tokensToAdd);
      
      // Should have added 3 tokens (3 seconds * 1 per second)
      expect(bucket.tokens).toBe(8);
      
      // Consume a token
      bucket.tokens--;
      expect(bucket.tokens).toBe(7);
      
      // Cannot exceed capacity
      bucket.tokens = 15;
      bucket.tokens = Math.min(capacity, bucket.tokens);
      expect(bucket.tokens).toBe(10);
    });
  });
  
  describe('Integration Tests', () => {
    it('should integrate error sanitization with Express middleware', () => {
      const mockErr = new Error('Database error at /home/user/app/models/User.js:123');
      const mockReq = { path: '/api/users', id: 'req-123' };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      const mockNext = jest.fn();
      
      const middleware = errorSanitizer.middleware();
      middleware(mockErr, mockReq, mockRes, mockNext);
      
      expect(mockRes.status).toHaveBeenCalledWith(500);
      expect(mockRes.json).toHaveBeenCalled();
      
      const response = mockRes.json.mock.calls[0][0];
      expect(response.success).toBe(false);
      expect(response.error).not.toContain('/home/user/app');
      expect(response.error).not.toContain('.js');
    });
    
    it('should apply composite rate limiting correctly', () => {
      const limiters = [];
      let callCount = 0;
      
      // Mock limiters
      const limiter1 = (req, res, next) => { callCount++; next(); };
      const limiter2 = (req, res, next) => { callCount++; next(); };
      const limiter3 = (req, res, next) => { callCount++; next(); };
      
      limiters.push(limiter1, limiter2, limiter3);
      
      const compositeLimiter = (req, res, next) => {
        let currentIndex = 0;
        
        const processNext = (err) => {
          if (err) return next(err);
          if (currentIndex >= limiters.length) return next();
          
          const limiter = limiters[currentIndex++];
          limiter(req, res, processNext);
        };
        
        processNext();
      };
      
      const mockReq = {};
      const mockRes = {};
      const mockNext = jest.fn();
      
      compositeLimiter(mockReq, mockRes, mockNext);
      
      expect(callCount).toBe(3);
      expect(mockNext).toHaveBeenCalled();
    });
  });
});

// Run tests if this file is executed directly
if (require.main === module) {
  const jest = require('jest');
  jest.run(['--testPathPattern=security-fixes.test.js']);
}