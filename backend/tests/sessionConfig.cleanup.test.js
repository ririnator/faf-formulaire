const SessionConfig = require('../config/session');
const SessionCleanupService = require('../services/sessionCleanupService');

describe('SessionConfig Cleanup Integration', () => {
  beforeEach(() => {
    // Clean up any existing cleanup service
    SessionConfig.shutdownCleanupService();
  });

  afterEach(() => {
    // Clean up after each test
    SessionConfig.shutdownCleanupService();
  });

  describe('Cleanup Service Management', () => {
    test('should initialize cleanup service', () => {
      const service = SessionConfig.initializeCleanupService();
      
      expect(service).toBeInstanceOf(SessionCleanupService);
      expect(SessionConfig.getCleanupService()).toBe(service);
    });

    test('should return same service instance on multiple initializations', () => {
      const service1 = SessionConfig.initializeCleanupService();
      const service2 = SessionConfig.initializeCleanupService();
      
      expect(service1).toBe(service2);
    });

    test('should get null when no service is initialized', () => {
      expect(SessionConfig.getCleanupService()).toBeNull();
    });

    test('should shutdown cleanup service properly', () => {
      const service = SessionConfig.initializeCleanupService();
      expect(service).toBeTruthy();
      
      // Mock the shutdown method to verify it's called
      const shutdownSpy = jest.spyOn(service, 'shutdown');
      
      SessionConfig.shutdownCleanupService();
      
      expect(shutdownSpy).toHaveBeenCalled();
      expect(SessionConfig.getCleanupService()).toBeNull();
      
      shutdownSpy.mockRestore();
    });

    test('should handle multiple shutdown calls gracefully', () => {
      const service = SessionConfig.initializeCleanupService();
      
      SessionConfig.shutdownCleanupService();
      SessionConfig.shutdownCleanupService(); // Should not throw
      
      expect(SessionConfig.getCleanupService()).toBeNull();
    });

    test('should reinitialize service after shutdown', () => {
      const service1 = SessionConfig.initializeCleanupService();
      SessionConfig.shutdownCleanupService();
      
      const service2 = SessionConfig.initializeCleanupService();
      
      expect(service2).toBeInstanceOf(SessionCleanupService);
      expect(service2).not.toBe(service1); // New instance
    });
  });

  describe('Session Configuration', () => {
    test('should maintain existing session configuration', () => {
      const config = SessionConfig.getConfig();
      
      expect(config.secret).toBeDefined();
      expect(config.resave).toBe(false);
      expect(config.saveUninitialized).toBe(false);
      expect(config.store).toBeDefined();
      expect(config.cookie).toBeDefined();
      expect(config.name).toBe('faf.session');
    });

    test('should have correct TTL settings in store', () => {
      const config = SessionConfig.getConfig();
      
      expect(config.store.options.ttl).toBe(14 * 24 * 60 * 60); // 14 days
      expect(config.store.options.autoRemove).toBe('native');
      expect(config.store.options.touchAfter).toBe(24 * 3600);
    });

    test('should maintain environment-specific cookie settings', () => {
      const originalEnv = process.env.NODE_ENV;
      
      // Test production settings
      process.env.NODE_ENV = 'production';
      const prodConfig = SessionConfig.getConfig();
      expect(prodConfig.cookie.sameSite).toBe('none');
      expect(prodConfig.cookie.secure).toBe(true);
      
      // Test development settings
      process.env.NODE_ENV = 'development';
      const devConfig = SessionConfig.getConfig();
      expect(devConfig.cookie.sameSite).toBe('lax');
      expect(devConfig.cookie.secure).toBe(false);
      
      // Restore original environment
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Error Handling', () => {
    test('should handle cleanup service initialization errors', () => {
      // Mock SessionCleanupService constructor to throw
      const SessionCleanupService = require('../services/sessionCleanupService');
      const originalConstructor = SessionCleanupService;
      
      // Mock the constructor to throw
      jest.doMock('../services/sessionCleanupService', () => {
        return jest.fn(() => {
          throw new Error('Initialization failed');
        });
      });

      // Clear the module cache and re-require
      delete require.cache[require.resolve('../config/session')];
      const SessionConfigWithMock = require('../config/session');

      expect(() => {
        SessionConfigWithMock.initializeCleanupService();
      }).toThrow('Initialization failed');

      // Restore
      jest.dontMock('../services/sessionCleanupService');
    });

    test('should handle missing environment variables gracefully', () => {
      const originalSecret = process.env.SESSION_SECRET;
      const originalMongo = process.env.MONGODB_URI;
      
      delete process.env.SESSION_SECRET;
      
      expect(() => {
        SessionConfig.getConfig();
      }).toThrow('SESSION_SECRET manquant dans les variables d\'environnement');
      
      // Restore
      process.env.SESSION_SECRET = originalSecret;
      delete process.env.MONGODB_URI;
      
      expect(() => {
        SessionConfig.getConfig();
      }).toThrow('MONGODB_URI manquant pour le store de sessions');
      
      // Restore
      process.env.MONGODB_URI = originalMongo;
    });
  });

  describe('Integration with Cleanup Service', () => {
    test('should allow access to cleanup service methods', async () => {
      const service = SessionConfig.initializeCleanupService();
      
      // Mock the runCompleteCleanup method
      const cleanupSpy = jest.spyOn(service, 'runCompleteCleanup').mockResolvedValue({
        stats: { totalCleaned: 0 },
        recommendations: []
      });

      const result = await service.runCompleteCleanup({ dryRun: true });
      
      expect(cleanupSpy).toHaveBeenCalledWith({ dryRun: true });
      expect(result).toBeTruthy();
      
      cleanupSpy.mockRestore();
    });

    test('should allow configuration updates through session config', () => {
      const service = SessionConfig.initializeCleanupService();
      
      const updateSpy = jest.spyOn(service, 'updateConfig');
      
      service.updateConfig({ cleanupInterval: 12 * 60 * 60 * 1000 });
      
      expect(updateSpy).toHaveBeenCalledWith({ cleanupInterval: 12 * 60 * 60 * 1000 });
      
      updateSpy.mockRestore();
    });

    test('should provide access to cleanup statistics', () => {
      const service = SessionConfig.initializeCleanupService();
      
      const stats = service.getCleanupStats();
      
      expect(stats).toHaveProperty('expiredSessions');
      expect(stats).toHaveProperty('inactiveUsers');
      expect(stats).toHaveProperty('orphanedData');
      expect(stats).toHaveProperty('totalCleaned');
      expect(stats).toHaveProperty('lastCleanup');
    });
  });
});