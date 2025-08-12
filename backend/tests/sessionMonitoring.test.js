const SessionMonitoringService = require('../services/sessionMonitoringService');
const sessionMonitoringMiddleware = require('../middleware/sessionMonitoring');

describe('SessionMonitoringService', () => {
  let monitoringService;

  beforeEach(() => {
    monitoringService = new SessionMonitoringService();
  });

  afterEach(() => {
    if (monitoringService) {
      monitoringService.shutdown();
    }
  });

  describe('Session Creation Tracking', () => {
    test('should track session creation successfully', () => {
      const mockReq = {
        ip: '192.168.1.100',
        get: jest.fn().mockReturnValue('Mozilla/5.0'),
        headers: { 'user-agent': 'Mozilla/5.0', 'accept': 'text/html' }
      };

      const suspicious = monitoringService.trackSessionCreation('session123', mockReq, 'user456');
      
      expect(suspicious).toBe(false);
      expect(monitoringService.activeSessions.get('192.168.1.100')).toBe(1);
      expect(monitoringService.userSessions.get('user456')).toBe(1);
    });

    test('should detect suspicious user agent', () => {
      const mockReq = {
        ip: '192.168.1.100',
        get: jest.fn().mockReturnValue('curl/7.68.0'),
        headers: { 'user-agent': 'curl/7.68.0', 'accept': '*/*' }
      };

      const suspicious = monitoringService.trackSessionCreation('session123', mockReq);
      
      expect(suspicious).toBe(true);
      expect(monitoringService.sessionMetrics.suspiciousActivities).toBe(1);
    });

    test('should detect too many sessions from same IP', () => {
      const mockReq = {
        ip: '192.168.1.100',
        get: jest.fn().mockReturnValue('Mozilla/5.0'),
        headers: { 'user-agent': 'Mozilla/5.0', 'accept': 'text/html' }
      };

      // Create multiple sessions from same IP
      for (let i = 0; i < monitoringService.config.maxSessionsPerIP + 1; i++) {
        monitoringService.trackSessionCreation(`session${i}`, mockReq);
      }

      const blockCheck = monitoringService.shouldBlockSession('192.168.1.100');
      expect(blockCheck.blocked).toBe(true);
      expect(blockCheck.reason).toBe('too_many_ip_sessions');
    });
  });

  describe('Session Destruction Tracking', () => {
    test('should track session destruction', () => {
      // First create a session
      const mockReq = {
        ip: '192.168.1.100',
        get: jest.fn().mockReturnValue('Mozilla/5.0'),
        headers: { 'user-agent': 'Mozilla/5.0', 'accept': 'text/html' }
      };

      monitoringService.trackSessionCreation('session123', mockReq, 'user456');
      expect(monitoringService.activeSessions.get('192.168.1.100')).toBe(1);
      expect(monitoringService.userSessions.get('user456')).toBe(1);

      // Then destroy it
      monitoringService.trackSessionDestruction('session123', '192.168.1.100', 'user456');
      expect(monitoringService.activeSessions.get('192.168.1.100')).toBe(0);
      expect(monitoringService.userSessions.get('user456')).toBe(0);
    });
  });

  describe('Failed Login Tracking', () => {
    test('should track failed login attempts', () => {
      const failureCount = monitoringService.trackFailedLogin(
        '192.168.1.100',
        'Mozilla/5.0',
        { email: 'test@example.com' }
      );

      expect(failureCount).toBe(1);
      expect(monitoringService.failedLogins.has('192.168.1.100')).toBe(true);
    });

    test('should mark IP as suspicious after threshold failures', () => {
      const ip = '192.168.1.100';
      
      // Create multiple failed attempts
      for (let i = 0; i < monitoringService.config.suspiciousLoginThreshold; i++) {
        monitoringService.trackFailedLogin(ip, 'Mozilla/5.0', { email: `test${i}@example.com` });
      }

      expect(monitoringService.isIPSuspicious(ip)).toBe(true);
      expect(monitoringService.suspiciousIPs.has(ip)).toBe(true);
    });

    test('should clean up old failed attempts', () => {
      const ip = '192.168.1.100';
      
      // Mock older timestamp
      const oldTimestamp = Date.now() - (monitoringService.config.timeWindow + 1000);
      monitoringService.failedLogins.set(ip, [{
        timestamp: oldTimestamp,
        userAgent: 'Mozilla/5.0',
        attemptedEmail: 'old@example.com'
      }]);

      monitoringService.cleanupOldData();

      expect(monitoringService.failedLogins.has(ip)).toBe(false);
      expect(monitoringService.suspiciousIPs.has(ip)).toBe(false);
    });
  });

  describe('Suspicious Activity Detection', () => {
    test('should detect suspicious user agents', () => {
      expect(monitoringService.isSuspiciousUserAgent('curl/7.68.0')).toBe(true);
      expect(monitoringService.isSuspiciousUserAgent('python-requests/2.25.1')).toBe(true);
      expect(monitoringService.isSuspiciousUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe(false);
      expect(monitoringService.isSuspiciousUserAgent(null)).toBe(true);
    });

    test('should detect suspicious headers', () => {
      const suspiciousHeaders = {
        'x-automated-tool': 'PostmanRuntime/7.26.8'
      };
      const normalHeaders = {
        'user-agent': 'Mozilla/5.0',
        'accept': 'text/html,application/xhtml+xml'
      };
      const missingHeaders = {
        'accept': 'text/html'
      };

      expect(monitoringService.hasSuspiciousHeaders(suspiciousHeaders)).toBe(true);
      expect(monitoringService.hasSuspiciousHeaders(normalHeaders)).toBe(false);
      expect(monitoringService.hasSuspiciousHeaders(missingHeaders)).toBe(true);
    });

    test('should block sessions from suspicious IPs', () => {
      const ip = '192.168.1.100';
      monitoringService.suspiciousIPs.add(ip);

      const blockCheck = monitoringService.shouldBlockSession(ip);
      expect(blockCheck.blocked).toBe(true);
      expect(blockCheck.reason).toBe('suspicious_ip');
    });

    test('should allow admin to reset suspicious IP', () => {
      const ip = '192.168.1.100';
      monitoringService.suspiciousIPs.add(ip);
      monitoringService.failedLogins.set(ip, [{ timestamp: Date.now() }]);

      expect(monitoringService.isIPSuspicious(ip)).toBe(true);

      monitoringService.resetSuspiciousIP(ip);

      expect(monitoringService.isIPSuspicious(ip)).toBe(false);
      expect(monitoringService.failedLogins.has(ip)).toBe(false);
    });
  });

  describe('Configuration Management', () => {
    test('should allow configuration updates', () => {
      const newConfig = {
        suspiciousLoginThreshold: 10,
        maxSessionsPerIP: 20
      };

      monitoringService.updateConfig(newConfig);

      expect(monitoringService.config.suspiciousLoginThreshold).toBe(10);
      expect(monitoringService.config.maxSessionsPerIP).toBe(20);
    });

    test('should provide monitoring statistics', () => {
      // Create some test data
      monitoringService.trackSessionCreation('session1', {
        ip: '192.168.1.100',
        get: () => 'Mozilla/5.0',
        headers: { 'user-agent': 'Mozilla/5.0', 'accept': 'text/html' }
      });

      monitoringService.trackFailedLogin('192.168.1.101', 'Mozilla/5.0');

      const stats = monitoringService.getMonitoringStats();

      expect(stats).toHaveProperty('activeSessions');
      expect(stats).toHaveProperty('uniqueIPs');
      expect(stats).toHaveProperty('suspiciousIPs');
      expect(stats).toHaveProperty('trackedFailures');
      expect(stats.activeSessions).toBeGreaterThan(0);
    });
  });

  describe('IP Utilities', () => {
    test('should correctly mask IP addresses for privacy', () => {
      expect(monitoringService.maskIP('192.168.1.100')).toBe('192.168.xxx.xxx');
      expect(monitoringService.maskIP('10.0.0.1')).toBe('10.0.xxx.xxx');
      expect(monitoringService.maskIP('')).toBe('unknown');
      expect(monitoringService.maskIP(null)).toBe('unknown');
      expect(monitoringService.maskIP('2001:db8::1')).toBe('2001:db8...'); // IPv6
    });

    test('should extract client IP correctly', () => {
      const mockReq = {
        ip: '192.168.1.100',
        connection: { remoteAddress: '10.0.0.1' },
        socket: { remoteAddress: '172.16.0.1' }
      };

      expect(monitoringService.getClientIP(mockReq)).toBe('192.168.1.100');

      delete mockReq.ip;
      expect(monitoringService.getClientIP(mockReq)).toBe('10.0.0.1');

      mockReq.connection = null;
      expect(monitoringService.getClientIP(mockReq)).toBe('172.16.0.1');
    });
  });
});

describe('SessionMonitoringMiddleware', () => {
  let mockReq, mockRes, mockNext;

  beforeEach(() => {
    mockReq = {
      sessionID: 'test-session-123',
      session: {
        userId: 'user123',
        destroy: jest.fn()
      },
      ip: '192.168.1.100',
      get: jest.fn().mockReturnValue('Mozilla/5.0'),
      headers: {
        'user-agent': 'Mozilla/5.0',
        'accept': 'text/html'
      },
      body: {}
    };

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };

    mockNext = jest.fn();
    
    // Reset the middleware between tests
    sessionMonitoringMiddleware.monitoringService = new (require('../services/sessionMonitoringService'))();
  });

  afterEach(() => {
    sessionMonitoringMiddleware.shutdown();
  });

  describe('Session Creation Tracking Middleware', () => {
    test('should track session creation through middleware', () => {
      const middleware = sessionMonitoringMiddleware.trackSessionCreation();
      
      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.session.clientIP).toBe('192.168.1.100');
      expect(mockReq.session.createdAt).toBeDefined();
      expect(mockReq.session.suspicious).toBeDefined();
    });

    test('should handle missing session gracefully', () => {
      delete mockReq.session;
      delete mockReq.sessionID;

      const middleware = sessionMonitoringMiddleware.trackSessionCreation();
      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Session Blocking Middleware', () => {
    test('should block suspicious sessions', () => {
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      monitoringService.suspiciousIPs.add('192.168.1.100');

      const middleware = sessionMonitoringMiddleware.blockSuspiciousSessions();
      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        error: 'Session blocked due to suspicious activity',
        reason: 'suspicious_ip'
      }));
      expect(mockNext).not.toHaveBeenCalled();
    });

    test('should allow normal sessions', () => {
      const middleware = sessionMonitoringMiddleware.blockSuspiciousSessions();
      middleware(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.sessionSecurityCheck).toEqual(expect.objectContaining({
        passed: true,
        clientIP: expect.any(String)
      }));
    });
  });

  describe('Failed Login Tracking Middleware', () => {
    test('should track failed logins on 401 response', () => {
      const middleware = sessionMonitoringMiddleware.trackFailedLogins();
      middleware(mockReq, mockRes, mockNext);

      // Simulate failed login response
      mockRes.statusCode = 401;
      mockReq.body.email = 'test@example.com';
      
      mockRes.json({ error: 'Invalid credentials' });

      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.sessionMonitoring).toBeDefined();
    });
  });

  describe('Admin Endpoints', () => {
    test('should provide monitoring stats endpoint', () => {
      const middleware = sessionMonitoringMiddleware.getMonitoringStats();
      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        stats: expect.any(Object),
        timestamp: expect.any(String)
      }));
    });

    test('should handle IP reset endpoint', () => {
      mockReq.body = { ip: '192.168.1.100' };

      const middleware = sessionMonitoringMiddleware.resetSuspiciousIP();
      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        success: true,
        message: 'IP 192.168.1.100 has been reset'
      }));
    });

    test('should validate IP in reset endpoint', () => {
      mockReq.body = {}; // No IP provided

      const middleware = sessionMonitoringMiddleware.resetSuspiciousIP();
      middleware(mockReq, mockRes, mockNext);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'IP address is required'
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    test('should handle malformed session data gracefully', () => {
      // Test with various malformed session scenarios
      const testCases = [
        { sessionID: null, session: null },
        { sessionID: '', session: {} },
        { sessionID: 'valid', session: { userId: null } }
      ];

      testCases.forEach(testCase => {
        const req = { ...mockReq, ...testCase };
        const middleware = sessionMonitoringMiddleware.trackSessionCreation();
        
        expect(() => {
          middleware(req, mockRes, mockNext);
        }).not.toThrow();
        
        expect(mockNext).toHaveBeenCalled();
      });
    });

    test('should handle network errors during monitoring', () => {
      // Mock network failure
      jest.spyOn(console, 'error').mockImplementation(() => {});
      
      const monitoringService = sessionMonitoringMiddleware.getMonitoringService();
      const originalTrackSession = monitoringService.trackSessionCreation;
      
      monitoringService.trackSessionCreation = jest.fn().mockImplementation(() => {
        throw new Error('Network error');
      });

      const middleware = sessionMonitoringMiddleware.trackSessionCreation();
      
      expect(() => {
        middleware(mockReq, mockRes, mockNext);
      }).not.toThrow();
      
      expect(mockNext).toHaveBeenCalled();

      // Restore
      monitoringService.trackSessionCreation = originalTrackSession;
      console.error.mockRestore();
    });
  });
});