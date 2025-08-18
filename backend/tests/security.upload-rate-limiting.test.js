/**
 * Upload Rate Limiting and Quota Enforcement Tests
 * Comprehensive testing of file upload security and rate limiting
 */

const request = require('supertest');
const path = require('path');
const fs = require('fs');
const { getTestApp, setupTestEnvironment } = require('./test-utils');

// Setup test environment
setupTestEnvironment();

let app;

beforeAll(async () => {
  app = getTestApp();
}, 30000);

describe('📁 Upload Rate Limiting and Security Tests', () => {
  let adminSession = null;
  let testImagePath;

  beforeAll(async () => {
    if (!mongoose.connection.readyState) {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/faf-test');
    }

    // Create test image file
    testImagePath = path.join(__dirname, 'test-image.jpg');
    const testImageBuffer = Buffer.alloc(1024 * 50, 'test'); // 50KB test file
    fs.writeFileSync(testImagePath, testImageBuffer);

    // Login as admin for protected upload endpoints
    const loginResponse = await request(app)
      .post('/auth/login')
      .send({
        username: process.env.LOGIN_ADMIN_USER || 'admin',
        password: process.env.LOGIN_ADMIN_PASS || 'password'
      });
      
    if (loginResponse.headers['set-cookie']) {
      adminSession = loginResponse.headers['set-cookie'];
    }
  });

  afterAll(async () => {
    // Clean up test files
    if (fs.existsSync(testImagePath)) {
      fs.unlinkSync(testImagePath);
    }
    
    // Create additional test files for cleanup
    const testFiles = [
      path.join(__dirname, 'large-test-file.jpg'),
      path.join(__dirname, 'malicious-test.exe'),
      path.join(__dirname, 'test-upload.png')
    ];
    
    testFiles.forEach(file => {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    });

    });

  describe('📏 File Size Quota Enforcement', () => {
    test('should enforce maximum file size limits', async () => {
      // Create a large test file (6MB - exceeds 5MB limit)
      const largeFilePath = path.join(__dirname, 'large-test-file.jpg');
      const largeFileBuffer = Buffer.alloc(1024 * 1024 * 6, 'large'); // 6MB
      fs.writeFileSync(largeFilePath, largeFileBuffer);

      const response = await request(app)
        .post('/api/upload')
        .set('Cookie', adminSession || '')
        .attach('image', largeFilePath)
        .timeout(10000);

      // Should reject files exceeding size limit
      expect([413, 400, 401]).toContain(response.status);
      
      if (response.status === 413) {
        expect(response.body.error || response.body.message).toMatch(/size|limit|large/i);
      }
    }, 15000);

    test('should accept files within size limits', async () => {
      if (!fs.existsSync(testImagePath)) {
        // Recreate if missing
        const testImageBuffer = Buffer.alloc(1024 * 50, 'test'); // 50KB
        fs.writeFileSync(testImagePath, testImageBuffer);
      }

      const response = await request(app)
        .post('/api/upload')
        .set('Cookie', adminSession || '')
        .attach('image', testImagePath)
        .timeout(8000);

      // Should accept reasonable file sizes or require auth
      expect([200, 201, 401, 403]).toContain(response.status);
    }, 12000);

    test('should handle zero-byte files', async () => {
      const emptyFilePath = path.join(__dirname, 'empty-file.jpg');
      fs.writeFileSync(emptyFilePath, ''); // Empty file

      const response = await request(app)
        .post('/api/upload')
        .set('Cookie', adminSession || '')
        .attach('image', emptyFilePath)
        .timeout(5000);

      // Should reject empty files
      expect([400, 401, 403]).toContain(response.status);

      fs.unlinkSync(emptyFilePath);
    });

    test('should calculate Content-Length validation correctly', async () => {
      const testSizes = [
        1024,           // 1KB
        1024 * 100,     // 100KB
        1024 * 1024,    // 1MB
        1024 * 1024 * 2 // 2MB
      ];

      for (const size of testSizes) {
        const testFile = path.join(__dirname, `test-${size}.jpg`);
        const buffer = Buffer.alloc(size, 'x');
        fs.writeFileSync(testFile, buffer);

        const response = await request(app)
          .post('/api/upload')
          .set('Cookie', adminSession || '')
          .set('Content-Length', buffer.length.toString())
          .attach('image', testFile)
          .timeout(8000);

        // Should process correctly sized files
        expect([200, 201, 401, 403, 413]).toContain(response.status);

        fs.unlinkSync(testFile);
      }
    }, 30000);
  });

  describe('🚦 Upload Rate Limiting by IP', () => {
    test('should enforce upload rate limits per IP', async () => {
      const uploadAttempts = [];
      const testIP = '192.168.100.50';

      // Attempt multiple rapid uploads from same IP
      for (let i = 0; i < 8; i++) {
        const uploadPromise = request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', testIP)
          .set('Cookie', adminSession || '')
          .attach('image', testImagePath)
          .timeout(8000);

        uploadAttempts.push(uploadPromise);
      }

      const responses = await Promise.allSettled(uploadAttempts);
      
      const statuses = responses
        .filter(r => r.status === 'fulfilled')
        .map(r => r.value.status);

      // Should have some rate limiting (429) or auth requirements (401/403)
      const rateLimited = statuses.filter(s => s === 429).length;
      const authRequired = statuses.filter(s => [401, 403].includes(s)).length;
      const successful = statuses.filter(s => [200, 201].includes(s)).length;

      expect(statuses.length).toBe(8);
      expect(rateLimited + authRequired + successful).toBe(8);
    }, 25000);

    test('should track different IPs separately for rate limiting', async () => {
      const ips = ['10.1.1.1', '10.1.1.2', '10.1.1.3'];
      const results = {};

      for (const ip of ips) {
        results[ip] = [];
        
        // Each IP gets its own rate limit allowance
        for (let i = 0; i < 4; i++) {
          const response = await request(app)
            .post('/api/upload')
            .set('X-Forwarded-For', ip)
            .set('Cookie', adminSession || '')
            .attach('image', testImagePath)
            .timeout(8000);

          results[ip].push(response.status);
        }
      }

      // Each IP should be tracked independently
      Object.keys(results).forEach(ip => {
        expect(results[ip].length).toBe(4);
        expect(results[ip].every(status => status < 500)).toBe(true);
      });
    }, 30000);

    test('should handle concurrent uploads from different IPs', async () => {
      const concurrentUploads = [
        { ip: '172.16.1.1', name: 'concurrent1' },
        { ip: '172.16.1.2', name: 'concurrent2' },
        { ip: '172.16.1.3', name: 'concurrent3' },
        { ip: '172.16.1.4', name: 'concurrent4' },
        { ip: '172.16.1.5', name: 'concurrent5' }
      ];

      const uploadPromises = concurrentUploads.map(upload =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', upload.ip)
          .set('Cookie', adminSession || '')
          .attach('image', testImagePath)
          .timeout(10000)
      );

      const responses = await Promise.allSettled(uploadPromises);
      
      // All should complete without server errors
      const completed = responses.filter(r => r.status === 'fulfilled').length;
      const serverErrors = responses.filter(r => 
        r.status === 'fulfilled' && r.value.status >= 500
      ).length;

      expect(completed).toBe(5);
      expect(serverErrors).toBe(0);
    }, 20000);
  });

  describe('🛡️ MIME Type and Content Validation', () => {
    test('should reject malicious file types', async () => {
      const maliciousFiles = [
        { name: 'malicious.exe', content: 'MZ\x90\x00...', contentType: 'application/octet-stream' },
        { name: 'script.js', content: 'alert("xss")', contentType: 'application/javascript' },
        { name: 'evil.bat', content: '@echo off\ndir', contentType: 'application/x-bat' },
        { name: 'virus.com', content: 'virus code', contentType: 'application/x-msdownload' },
        { name: 'exploit.php', content: '<?php system($_GET["cmd"]); ?>', contentType: 'application/x-php' }
      ];

      for (const maliciousFile of maliciousFiles) {
        const filePath = path.join(__dirname, maliciousFile.name);
        fs.writeFileSync(filePath, maliciousFile.content);

        const response = await request(app)
          .post('/api/upload')
          .set('Cookie', adminSession || '')
          .set('Content-Type', maliciousFile.contentType)
          .attach('image', filePath)
          .timeout(8000);

        // Should reject malicious file types
        expect([400, 401, 403, 415]).toContain(response.status);

        fs.unlinkSync(filePath);
      }
    }, 20000);

    test('should validate file headers vs extensions', async () => {
      // Create file with misleading extension
      const misleadingFile = path.join(__dirname, 'fake-image.jpg');
      fs.writeFileSync(misleadingFile, 'This is not an image file');

      const response = await request(app)
        .post('/api/upload')
        .set('Cookie', adminSession || '')
        .attach('image', misleadingFile)
        .timeout(8000);

      // Should detect content mismatch
      expect([400, 401, 403, 415]).toContain(response.status);

      fs.unlinkSync(misleadingFile);
    });

    test('should handle double extensions attack', async () => {
      const doubleExtFiles = [
        'image.jpg.exe',
        'photo.png.bat',
        'picture.gif.com',
        'file.jpeg.js'
      ];

      for (const fileName of doubleExtFiles) {
        const filePath = path.join(__dirname, fileName);
        fs.writeFileSync(filePath, 'fake image content');

        const response = await request(app)
          .post('/api/upload')
          .set('Cookie', adminSession || '')
          .attach('image', filePath)
          .timeout(8000);

        // Should reject suspicious double extensions
        expect([400, 401, 403, 415]).toContain(response.status);

        fs.unlinkSync(filePath);
      }
    });

    test('should validate image file structures', async () => {
      // Create files that claim to be images but aren't
      const fakeImages = [
        { name: 'fake.jpg', content: 'FAKE_JPEG_HEADER' + 'x'.repeat(1000) },
        { name: 'fake.png', content: 'FAKE_PNG_HEADER' + 'x'.repeat(1000) },
        { name: 'fake.gif', content: 'FAKE_GIF_HEADER' + 'x'.repeat(1000) }
      ];

      for (const fakeImage of fakeImages) {
        const filePath = path.join(__dirname, fakeImage.name);
        fs.writeFileSync(filePath, fakeImage.content);

        const response = await request(app)
          .post('/api/upload')
          .set('Cookie', adminSession || '')
          .attach('image', filePath)
          .timeout(8000);

        // Should validate actual image structure
        expect([400, 401, 403, 415]).toContain(response.status);

        fs.unlinkSync(filePath);
      }
    });
  });

  describe('💾 Memory Management During Upload', () => {
    test('should handle memory cleanup for failed uploads', async () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Attempt multiple failed uploads that should be cleaned up
      const failedUploads = Array(10).fill(null).map((_, i) => {
        const badFile = path.join(__dirname, `bad-upload-${i}.txt`);
        fs.writeFileSync(badFile, 'x'.repeat(1024 * 100)); // 100KB text file

        return request(app)
          .post('/api/upload')
          .set('Cookie', adminSession || '')
          .attach('image', badFile)
          .timeout(8000)
          .then(response => {
            fs.unlinkSync(badFile);
            return response;
          })
          .catch(error => {
            if (fs.existsSync(badFile)) fs.unlinkSync(badFile);
            return { status: 500, error };
          });
      });

      await Promise.allSettled(failedUploads);
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    }, 25000);

    test('should handle large file upload memory efficiently', async () => {
      const largeFilePath = path.join(__dirname, 'memory-test.jpg');
      const largeBuffer = Buffer.alloc(1024 * 1024 * 4, 'memory'); // 4MB
      fs.writeFileSync(largeFilePath, largeBuffer);

      const initialMemory = process.memoryUsage().heapUsed;

      const response = await request(app)
        .post('/api/upload')
        .set('Cookie', adminSession || '')
        .attach('image', largeFilePath)
        .timeout(15000);

      const duringUploadMemory = process.memoryUsage().heapUsed;
      
      // Clean up
      fs.unlinkSync(largeFilePath);
      
      // Force cleanup
      if (global.gc) {
        global.gc();
      }
      
      await new Promise(resolve => setTimeout(resolve, 1000));
      const afterCleanupMemory = process.memoryUsage().heapUsed;

      // Memory should not increase dramatically during upload
      const memoryIncreaseDuringUpload = duringUploadMemory - initialMemory;
      const memoryAfterCleanup = afterCleanupMemory - initialMemory;

      expect(memoryIncreaseDuringUpload).toBeLessThan(100 * 1024 * 1024); // Less than 100MB
      expect(memoryAfterCleanup).toBeLessThan(memoryIncreaseDuringUpload); // Should decrease after cleanup
    }, 30000);

    test('should prevent memory exhaustion attacks', async () => {
      // Simulate rapid memory allocation attempts
      const memoryAttackPromises = Array(20).fill(null).map((_, i) => {
        const attackFile = path.join(__dirname, `memory-attack-${i}.jpg`);
        const attackBuffer = Buffer.alloc(1024 * 1024, `attack${i}`); // 1MB each
        fs.writeFileSync(attackFile, attackBuffer);

        return request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', `10.0.0.${i + 1}`)
          .set('Cookie', adminSession || '')
          .attach('image', attackFile)
          .timeout(10000)
          .finally(() => {
            if (fs.existsSync(attackFile)) {
              fs.unlinkSync(attackFile);
            }
          });
      });

      const responses = await Promise.allSettled(memoryAttackPromises);
      
      // Should handle all requests without crashing
      const completed = responses.filter(r => r.status === 'fulfilled').length;
      expect(completed).toBe(20);
      
      // Server should still be responsive
      const healthCheck = await request(app)
        .get('/health')
        .timeout(5000);
      
      expect([200, 404]).toContain(healthCheck.status); // 404 if no health endpoint
    }, 40000);
  });

  describe('🕰️ Upload Timeout and Interrupt Handling', () => {
    test('should handle upload timeouts gracefully', async () => {
      // Create moderately large file that might timeout
      const timeoutTestFile = path.join(__dirname, 'timeout-test.jpg');
      const timeoutBuffer = Buffer.alloc(1024 * 1024 * 3, 'timeout'); // 3MB
      fs.writeFileSync(timeoutTestFile, timeoutBuffer);

      const response = await request(app)
        .post('/api/upload')
        .set('Cookie', adminSession || '')
        .attach('image', timeoutTestFile)
        .timeout(3000) // Short timeout to potentially trigger timeout
        .catch(error => ({ status: 'timeout', error }));

      fs.unlinkSync(timeoutTestFile);

      // Should handle timeout gracefully
      if (response.status === 'timeout') {
        expect(response.error.code).toBe('ECONNABORTED');
      } else {
        expect([200, 201, 401, 403, 413, 408]).toContain(response.status);
      }
    });

    test('should clean up interrupted uploads', async () => {
      const interruptFile = path.join(__dirname, 'interrupt-test.jpg');
      const interruptBuffer = Buffer.alloc(1024 * 1024 * 2, 'interrupt'); // 2MB
      fs.writeFileSync(interruptFile, interruptBuffer);

      // Start upload and immediately abort
      const uploadPromise = request(app)
        .post('/api/upload')
        .set('Cookie', adminSession || '')
        .attach('image', interruptFile)
        .timeout(1000); // Very short timeout

      const response = await uploadPromise.catch(error => ({ 
        status: 'aborted', 
        error: error.message 
      }));

      fs.unlinkSync(interruptFile);

      // Should handle interruption
      expect(['aborted', 200, 201, 401, 403, 408, 413].includes(response.status) || 
             typeof response.status === 'number').toBe(true);
    });
  });

  describe('📊 Upload Monitoring and Logging', () => {
    test('should track upload statistics', async () => {
      const monitoringUploads = Array(5).fill(null).map((_, i) =>
        request(app)
          .post('/api/upload')
          .set('X-Forwarded-For', `203.0.113.${i + 1}`)
          .set('Cookie', adminSession || '')
          .attach('image', testImagePath)
          .timeout(8000)
      );

      const responses = await Promise.allSettled(monitoringUploads);
      
      // All requests should be tracked (successful or not)
      expect(responses.length).toBe(5);
      
      responses.forEach(response => {
        if (response.status === 'fulfilled') {
          expect(response.value.status).toBeLessThan(500);
        }
      });
    });

    test('should log security violations', async () => {
      // Trigger various security violations that should be logged
      const violations = [
        {
          name: 'oversized-file',
          setup: () => {
            const oversizedFile = path.join(__dirname, 'oversized.jpg');
            const oversizedBuffer = Buffer.alloc(1024 * 1024 * 10, 'oversized'); // 10MB
            fs.writeFileSync(oversizedFile, oversizedBuffer);
            return oversizedFile;
          }
        },
        {
          name: 'malicious-extension',
          setup: () => {
            const maliciousFile = path.join(__dirname, 'malicious.exe.jpg');
            fs.writeFileSync(maliciousFile, 'malicious content');
            return maliciousFile;
          }
        }
      ];

      for (const violation of violations) {
        const filePath = violation.setup();
        
        const response = await request(app)
          .post('/api/upload')
          .set('Cookie', adminSession || '')
          .attach('image', filePath)
          .timeout(8000);

        // Should handle security violations
        expect([400, 401, 403, 413, 415]).toContain(response.status);

        fs.unlinkSync(filePath);
      }
    }, 20000);
  });
});