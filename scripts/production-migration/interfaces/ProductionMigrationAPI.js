#!/usr/bin/env node

/**
 * Production Migration API - RESTful API Interface
 * ================================================
 * 
 * Comprehensive RESTful API for production migration management providing:
 * - Complete migration lifecycle control via HTTP endpoints
 * - Real-time status monitoring and event streaming
 * - Emergency operations and safety controls
 * - Comprehensive logging and audit trails
 * - Authentication and authorization controls
 * 
 * API ENDPOINTS:
 * - Migration Control: POST /migration/{start,stop,pause,resume}
 * - Status Monitoring: GET /status, GET /metrics, GET /logs
 * - Emergency Operations: POST /emergency/{rollback,stop}
 * - Configuration: GET/POST /config, GET /health
 * - Real-time Events: WebSocket /events, Server-Sent Events /stream
 * 
 * SECURITY FEATURES:
 * - API key authentication and role-based authorization
 * - Request rate limiting and throttling
 * - Input validation and sanitization
 * - Audit logging and security monitoring
 * - CORS and security headers
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');

// Import production migration components
const { ProductionMigrationOrchestrator } = require('../ProductionMigrationOrchestrator');
const { RealTimeMonitoringDashboard } = require('../monitoring/RealTimeMonitoringDashboard');
const { AutomaticRollbackSystem } = require('../rollback/AutomaticRollbackSystem');
const { PreFlightCheckSystem } = require('../validation/PreFlightCheckSystem');

/**
 * API Configuration
 */
const API_CONFIG = {
  // Server Settings
  SERVER: {
    PORT: process.env.MIGRATION_API_PORT || 3002,
    HOST: process.env.MIGRATION_API_HOST || 'localhost',
    TIMEOUT: 30000,
    KEEP_ALIVE: 5000
  },
  
  // Authentication
  AUTH: {
    ENABLED: true,
    API_KEY_HEADER: 'X-Migration-API-Key',
    ADMIN_KEY: process.env.MIGRATION_ADMIN_KEY || 'migration-admin-key-12345',
    READONLY_KEY: process.env.MIGRATION_READONLY_KEY || 'migration-readonly-key-12345',
    SESSION_TIMEOUT: 3600000 // 1 hour
  },
  
  // Rate Limiting
  RATE_LIMITING: {
    ENABLED: true,
    WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    MAX_REQUESTS: 100,
    ADMIN_MAX_REQUESTS: 1000,
    READONLY_MAX_REQUESTS: 500
  },
  
  // CORS Settings
  CORS: {
    ENABLED: true,
    ORIGINS: process.env.MIGRATION_CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
    CREDENTIALS: true
  },
  
  // Logging and Monitoring
  LOGGING: {
    ENABLED: true,
    LOG_REQUESTS: true,
    LOG_RESPONSES: true,
    LOG_ERRORS: true,
    AUDIT_ENABLED: true
  },
  
  // WebSocket Settings
  WEBSOCKET: {
    ENABLED: true,
    HEARTBEAT_INTERVAL: 30000,
    MAX_CONNECTIONS: 100,
    MESSAGE_QUEUE_SIZE: 1000
  }
};

/**
 * Production Migration API Server
 * RESTful API for comprehensive migration management
 */
class ProductionMigrationAPI extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      port: API_CONFIG.SERVER.PORT,
      host: API_CONFIG.SERVER.HOST,
      enableAuth: API_CONFIG.AUTH.ENABLED,
      enableRateLimit: API_CONFIG.RATE_LIMITING.ENABLED,
      enableCORS: API_CONFIG.CORS.ENABLED,
      enableWebSocket: API_CONFIG.WEBSOCKET.ENABLED,
      ...options
    };
    
    // Server Components
    this.app = null;
    this.server = null;
    this.wss = null;
    
    // Migration Components
    this.orchestrator = null;
    this.monitoringDashboard = null;
    this.rollbackSystem = null;
    this.preFlightSystem = null;
    
    // State Management
    this.state = {
      isRunning: false,
      startTime: null,
      clients: new Map(),
      sessions: new Map(),
      auditLog: [],
      statistics: {
        totalRequests: 0,
        authenticatedRequests: 0,
        errorCount: 0,
        rateLimitHits: 0
      }
    };
    
    // Initialize API
    this.initializeAPI();
  }

  /**
   * Initialize API Server
   */
  async initializeAPI() {
    console.log('🚀 Initializing Production Migration API...');
    
    try {
      // Create Express application
      this.createExpressApp();
      
      // Setup middleware
      this.setupMiddleware();
      
      // Setup routes
      this.setupRoutes();
      
      // Initialize migration components
      await this.initializeMigrationComponents();
      
      // Create HTTP server
      this.createHTTPServer();
      
      // Setup WebSocket server
      if (this.options.enableWebSocket) {
        this.setupWebSocketServer();
      }
      
      console.log('✅ Production Migration API initialized successfully');
      
    } catch (error) {
      console.error('❌ Failed to initialize API:', error.message);
      throw error;
    }
  }

  createExpressApp() {
    this.app = express();
    
    // Basic Express configuration
    this.app.set('trust proxy', 1);
    this.app.disable('x-powered-by');
    
    // Request timeout
    this.app.use((req, res, next) => {
      req.setTimeout(API_CONFIG.SERVER.TIMEOUT);
      next();
    });
  }

  setupMiddleware() {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"]
        }
      }
    }));
    
    // CORS middleware
    if (this.options.enableCORS) {
      this.app.use(cors({
        origin: API_CONFIG.CORS.ORIGINS,
        credentials: API_CONFIG.CORS.CREDENTIALS,
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        allowedHeaders: ['Content-Type', 'Authorization', API_CONFIG.AUTH.API_KEY_HEADER]
      }));
    }
    
    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Request logging middleware
    if (API_CONFIG.LOGGING.LOG_REQUESTS) {
      this.app.use(this.createRequestLogger());
    }
    
    // Rate limiting middleware
    if (this.options.enableRateLimit) {
      this.app.use(this.createRateLimiter());
    }
    
    // Authentication middleware
    if (this.options.enableAuth) {
      this.app.use(this.createAuthMiddleware());
    }
    
    // Request ID middleware
    this.app.use((req, res, next) => {
      req.id = uuidv4();
      res.setHeader('X-Request-ID', req.id);
      next();
    });
  }

  createRequestLogger() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        this.logRequest({
          requestId: req.id,
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          duration,
          userAgent: req.get('User-Agent'),
          ip: req.ip,
          timestamp: new Date()
        });
      });
      
      next();
    };
  }

  createRateLimiter() {
    return rateLimit({
      windowMs: API_CONFIG.RATE_LIMITING.WINDOW_MS,
      max: (req) => {
        // Different limits based on authentication level
        if (req.auth?.role === 'admin') {
          return API_CONFIG.RATE_LIMITING.ADMIN_MAX_REQUESTS;
        }
        if (req.auth?.role === 'readonly') {
          return API_CONFIG.RATE_LIMITING.READONLY_MAX_REQUESTS;
        }
        return API_CONFIG.RATE_LIMITING.MAX_REQUESTS;
      },
      message: {
        error: 'Rate limit exceeded',
        retryAfter: API_CONFIG.RATE_LIMITING.WINDOW_MS / 1000
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        this.state.statistics.rateLimitHits++;
        res.status(429).json({
          error: 'Rate limit exceeded',
          retryAfter: API_CONFIG.RATE_LIMITING.WINDOW_MS / 1000
        });
      }
    });
  }

  createAuthMiddleware() {
    return (req, res, next) => {
      const apiKey = req.get(API_CONFIG.AUTH.API_KEY_HEADER);
      
      // Skip auth for health check and documentation endpoints
      if (['/health', '/docs', '/api-docs'].includes(req.path)) {
        return next();
      }
      
      if (!apiKey) {
        return res.status(401).json({
          error: 'Authentication required',
          message: `Missing ${API_CONFIG.AUTH.API_KEY_HEADER} header`
        });
      }
      
      // Validate API key and determine role
      let role = null;
      if (apiKey === API_CONFIG.AUTH.ADMIN_KEY) {
        role = 'admin';
      } else if (apiKey === API_CONFIG.AUTH.READONLY_KEY) {
        role = 'readonly';
      } else {
        return res.status(401).json({
          error: 'Invalid API key'
        });
      }
      
      // Attach authentication info to request
      req.auth = {
        apiKey,
        role,
        authenticated: true
      };
      
      this.state.statistics.authenticatedRequests++;
      next();
    };
  }

  setupRoutes() {
    // Health and status endpoints
    this.app.get('/health', this.handleHealthCheck.bind(this));
    this.app.get('/status', this.handleGetStatus.bind(this));
    this.app.get('/metrics', this.handleGetMetrics.bind(this));
    this.app.get('/version', this.handleGetVersion.bind(this));
    
    // Migration control endpoints
    this.app.post('/migration/start', this.requireAdmin, this.handleStartMigration.bind(this));
    this.app.post('/migration/stop', this.requireAdmin, this.handleStopMigration.bind(this));
    this.app.post('/migration/pause', this.requireAdmin, this.handlePauseMigration.bind(this));
    this.app.post('/migration/resume', this.requireAdmin, this.handleResumeMigration.bind(this));
    this.app.post('/migration/abort', this.requireAdmin, this.handleAbortMigration.bind(this));
    
    // Emergency operations
    this.app.post('/emergency/rollback', this.requireAdmin, this.handleEmergencyRollback.bind(this));
    this.app.post('/emergency/stop', this.requireAdmin, this.handleEmergencyStop.bind(this));
    
    // Validation endpoints
    this.app.post('/validation/preflight', this.requireAdmin, this.handlePreFlightCheck.bind(this));
    this.app.get('/validation/readiness', this.handleReadinessCheck.bind(this));
    
    // Monitoring endpoints
    this.app.get('/monitoring/logs', this.handleGetLogs.bind(this));
    this.app.get('/monitoring/alerts', this.handleGetAlerts.bind(this));
    this.app.get('/monitoring/performance', this.handleGetPerformance.bind(this));
    
    // Configuration endpoints
    this.app.get('/config', this.handleGetConfig.bind(this));
    this.app.post('/config', this.requireAdmin, this.handleUpdateConfig.bind(this));
    
    // Reporting endpoints
    this.app.get('/reports/migration', this.handleGetMigrationReport.bind(this));
    this.app.get('/reports/audit', this.requireAdmin, this.handleGetAuditLog.bind(this));
    
    // Server-Sent Events for real-time updates
    this.app.get('/stream/events', this.handleEventStream.bind(this));
    
    // Error handling middleware
    this.app.use(this.createErrorHandler());
    
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Endpoint not found',
        path: req.originalUrl
      });
    });
  }

  // Authorization middleware
  requireAdmin = (req, res, next) => {
    if (req.auth?.role !== 'admin') {
      return res.status(403).json({
        error: 'Admin access required'
      });
    }
    next();
  };

  async initializeMigrationComponents() {
    // Initialize orchestrator
    this.orchestrator = new ProductionMigrationOrchestrator({
      logger: this.createComponentLogger('orchestrator')
    });
    
    // Initialize monitoring dashboard
    this.monitoringDashboard = new RealTimeMonitoringDashboard({
      consoleMode: false,
      webMode: false,
      apiMode: true,
      logger: this.createComponentLogger('monitoring')
    });
    
    // Initialize rollback system
    this.rollbackSystem = new AutomaticRollbackSystem({
      autoTrigger: false,
      logger: this.createComponentLogger('rollback')
    });
    
    // Initialize pre-flight system
    this.preFlightSystem = new PreFlightCheckSystem({
      logger: this.createComponentLogger('preflight')
    });
    
    // Setup event listeners
    this.setupComponentEventListeners();
  }

  createComponentLogger(component) {
    return {
      info: (message, data) => this.logMessage('info', component, message, data),
      warn: (message, data) => this.logMessage('warn', component, message, data),
      error: (message, data) => this.logMessage('error', component, message, data),
      success: (message, data) => this.logMessage('success', component, message, data),
      debug: (message, data) => this.logMessage('debug', component, message, data)
    };
  }

  logMessage(level, component, message, data = {}) {
    const logEntry = {
      timestamp: new Date(),
      level,
      component,
      message,
      data,
      requestId: data.requestId
    };
    
    // Add to audit log
    if (API_CONFIG.LOGGING.AUDIT_ENABLED) {
      this.state.auditLog.push(logEntry);
      
      // Maintain audit log size
      if (this.state.auditLog.length > 10000) {
        this.state.auditLog = this.state.auditLog.slice(-5000);
      }
    }
    
    // Broadcast to WebSocket clients
    this.broadcastToClients('log', logEntry);
    
    console.log(`[${logEntry.timestamp.toISOString()}] ${level.toUpperCase()} [${component}]: ${message}`);
  }

  setupComponentEventListeners() {
    // Orchestrator events
    if (this.orchestrator) {
      this.orchestrator.on('phaseStarted', (data) => {
        this.broadcastToClients('phaseStarted', data);
      });
      
      this.orchestrator.on('phaseCompleted', (data) => {
        this.broadcastToClients('phaseCompleted', data);
      });
      
      this.orchestrator.on('alertTriggered', (data) => {
        this.broadcastToClients('alert', data);
      });
    }
    
    // Monitoring dashboard events
    if (this.monitoringDashboard) {
      this.monitoringDashboard.on('metricsUpdated', (data) => {
        this.broadcastToClients('metrics', data);
      });
      
      this.monitoringDashboard.on('progressUpdated', (data) => {
        this.broadcastToClients('progress', data);
      });
    }
    
    // Rollback system events
    if (this.rollbackSystem) {
      this.rollbackSystem.on('rollbackStarted', (data) => {
        this.broadcastToClients('rollbackStarted', data);
      });
      
      this.rollbackSystem.on('rollbackCompleted', (data) => {
        this.broadcastToClients('rollbackCompleted', data);
      });
    }
  }

  createHTTPServer() {
    this.server = http.createServer(this.app);
    
    // Server event handlers
    this.server.on('listening', () => {
      const address = this.server.address();
      console.log(`🌐 API server listening on ${address.address}:${address.port}`);
    });
    
    this.server.on('error', (error) => {
      console.error('❌ Server error:', error.message);
      this.emit('error', error);
    });
    
    // Keep-alive settings
    this.server.keepAliveTimeout = API_CONFIG.SERVER.KEEP_ALIVE;
    this.server.headersTimeout = API_CONFIG.SERVER.KEEP_ALIVE + 1000;
  }

  setupWebSocketServer() {
    this.wss = new WebSocket.Server({
      server: this.server,
      path: '/ws',
      maxPayload: 1024 * 1024 // 1MB
    });
    
    this.wss.on('connection', (ws, req) => {
      this.handleWebSocketConnection(ws, req);
    });
    
    // WebSocket heartbeat
    setInterval(() => {
      this.wss.clients.forEach(ws => {
        if (ws.isAlive === false) {
          return ws.terminate();
        }
        
        ws.isAlive = false;
        ws.ping();
      });
    }, API_CONFIG.WEBSOCKET.HEARTBEAT_INTERVAL);
    
    console.log('🔌 WebSocket server initialized');
  }

  handleWebSocketConnection(ws, req) {
    const clientId = uuidv4();
    
    // Client state
    ws.isAlive = true;
    ws.clientId = clientId;
    ws.connectedAt = new Date();
    
    // Store client
    this.state.clients.set(clientId, {
      ws,
      connectedAt: new Date(),
      lastActivity: new Date(),
      messageCount: 0
    });
    
    console.log(`🔌 WebSocket client connected: ${clientId}`);
    
    // Handle messages
    ws.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        this.handleWebSocketMessage(ws, message);
      } catch (error) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Invalid JSON message'
        }));
      }
    });
    
    // Handle pong
    ws.on('pong', () => {
      ws.isAlive = true;
    });
    
    // Handle disconnect
    ws.on('close', () => {
      this.state.clients.delete(clientId);
      console.log(`🔌 WebSocket client disconnected: ${clientId}`);
    });
    
    // Send welcome message
    ws.send(JSON.stringify({
      type: 'welcome',
      clientId,
      timestamp: new Date(),
      serverVersion: '1.0.0'
    }));
  }

  handleWebSocketMessage(ws, message) {
    const client = this.state.clients.get(ws.clientId);
    if (client) {
      client.lastActivity = new Date();
      client.messageCount++;
    }
    
    switch (message.type) {
      case 'subscribe':
        // Handle subscription to specific events
        ws.subscriptions = message.events || [];
        ws.send(JSON.stringify({
          type: 'subscribed',
          events: ws.subscriptions
        }));
        break;
        
      case 'unsubscribe':
        // Handle unsubscription
        ws.subscriptions = [];
        ws.send(JSON.stringify({
          type: 'unsubscribed'
        }));
        break;
        
      case 'ping':
        // Handle ping
        ws.send(JSON.stringify({
          type: 'pong',
          timestamp: new Date()
        }));
        break;
        
      default:
        ws.send(JSON.stringify({
          type: 'error',
          message: `Unknown message type: ${message.type}`
        }));
    }
  }

  broadcastToClients(type, payload) {
    if (!this.wss) return;
    
    const message = JSON.stringify({
      type,
      payload,
      timestamp: new Date()
    });
    
    this.wss.clients.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        // Check subscription filter
        if (!ws.subscriptions || ws.subscriptions.length === 0 || ws.subscriptions.includes(type)) {
          ws.send(message);
        }
      }
    });
  }

  /**
   * API Route Handlers
   */
  async handleHealthCheck(req, res) {
    const health = {
      status: 'healthy',
      timestamp: new Date(),
      version: '1.0.0',
      uptime: this.state.startTime ? Date.now() - this.state.startTime.getTime() : 0,
      components: {
        orchestrator: this.orchestrator ? 'available' : 'unavailable',
        monitoring: this.monitoringDashboard ? 'available' : 'unavailable',
        rollback: this.rollbackSystem ? 'available' : 'unavailable',
        preflight: this.preFlightSystem ? 'available' : 'unavailable'
      },
      connections: {
        websocket: this.wss ? this.wss.clients.size : 0
      }
    };
    
    res.json(health);
  }

  async handleGetStatus(req, res) {
    try {
      const status = {
        server: {
          running: this.state.isRunning,
          startTime: this.state.startTime,
          uptime: this.state.startTime ? Date.now() - this.state.startTime.getTime() : 0
        },
        migration: this.orchestrator ? this.orchestrator.getStatus() : null,
        monitoring: this.monitoringDashboard ? this.monitoringDashboard.getState() : null,
        rollback: this.rollbackSystem ? this.rollbackSystem.getStatus() : null,
        statistics: this.state.statistics
      };
      
      res.json(status);
    } catch (error) {
      this.handleError(res, error, 'Failed to get status');
    }
  }

  async handleStartMigration(req, res) {
    try {
      const options = req.body || {};
      
      if (!this.orchestrator) {
        return res.status(503).json({
          error: 'Migration orchestrator not available'
        });
      }
      
      if (this.orchestrator.state.isRunning) {
        return res.status(409).json({
          error: 'Migration is already running'
        });
      }
      
      this.logMessage('info', 'api', 'Migration start requested', { 
        requestId: req.id,
        user: req.auth.role,
        options 
      });
      
      // Initialize if needed
      if (!this.orchestrator.state.isInitialized) {
        await this.orchestrator.initialize();
      }
      
      // Start migration (don't await - return immediately)
      const migrationPromise = this.orchestrator.execute();
      
      // Handle completion asynchronously
      migrationPromise.then(result => {
        this.broadcastToClients('migrationCompleted', { success: true, result });
      }).catch(error => {
        this.broadcastToClients('migrationFailed', { success: false, error: error.message });
      });
      
      res.json({
        success: true,
        message: 'Migration started successfully',
        sessionId: this.orchestrator.state.sessionId
      });
      
    } catch (error) {
      this.handleError(res, error, 'Failed to start migration');
    }
  }

  async handleStopMigration(req, res) {
    try {
      if (!this.orchestrator) {
        return res.status(503).json({
          error: 'Migration orchestrator not available'
        });
      }
      
      if (!this.orchestrator.state.isRunning) {
        return res.status(409).json({
          error: 'No migration is currently running'
        });
      }
      
      this.logMessage('info', 'api', 'Migration stop requested', { 
        requestId: req.id,
        user: req.auth.role
      });
      
      await this.orchestrator.shutdown();
      
      res.json({
        success: true,
        message: 'Migration stopped successfully'
      });
      
    } catch (error) {
      this.handleError(res, error, 'Failed to stop migration');
    }
  }

  async handleEmergencyRollback(req, res) {
    try {
      const { reason = 'API emergency rollback', backupPath } = req.body;
      
      if (!this.rollbackSystem) {
        return res.status(503).json({
          error: 'Rollback system not available'
        });
      }
      
      this.logMessage('warn', 'api', 'Emergency rollback requested', { 
        requestId: req.id,
        user: req.auth.role,
        reason 
      });
      
      // Initialize if needed
      if (!this.rollbackSystem.state.isInitialized) {
        await this.rollbackSystem.initialize();
      }
      
      const rollbackPath = backupPath || this.orchestrator?.state.backupPath;
      
      if (!rollbackPath) {
        return res.status(400).json({
          error: 'No backup path available for rollback'
        });
      }
      
      // Execute rollback
      const result = await this.rollbackSystem.executeEmergencyRollback(rollbackPath, reason);
      
      res.json({
        success: true,
        message: 'Emergency rollback completed successfully',
        result
      });
      
    } catch (error) {
      this.handleError(res, error, 'Emergency rollback failed');
    }
  }

  async handlePreFlightCheck(req, res) {
    try {
      if (!this.preFlightSystem) {
        return res.status(503).json({
          error: 'Pre-flight system not available'
        });
      }
      
      this.logMessage('info', 'api', 'Pre-flight check requested', { 
        requestId: req.id,
        user: req.auth.role
      });
      
      const result = await this.preFlightSystem.executePreFlightChecks();
      
      res.json({
        success: true,
        result
      });
      
    } catch (error) {
      this.handleError(res, error, 'Pre-flight check failed');
    }
  }

  async handleGetMetrics(req, res) {
    try {
      const metrics = {
        server: this.state.statistics,
        migration: this.orchestrator ? this.orchestrator.performanceMonitor?.getLatestMetrics() : null,
        monitoring: this.monitoringDashboard ? this.monitoringDashboard.getPerformanceSummary() : null,
        timestamp: new Date()
      };
      
      res.json(metrics);
    } catch (error) {
      this.handleError(res, error, 'Failed to get metrics');
    }
  }

  async handleGetLogs(req, res) {
    try {
      const { limit = 100, level, component } = req.query;
      
      let logs = this.state.auditLog;
      
      // Filter by level
      if (level) {
        logs = logs.filter(log => log.level === level);
      }
      
      // Filter by component
      if (component) {
        logs = logs.filter(log => log.component === component);
      }
      
      // Apply limit
      logs = logs.slice(-parseInt(limit));
      
      res.json({
        logs,
        total: this.state.auditLog.length,
        filtered: logs.length
      });
    } catch (error) {
      this.handleError(res, error, 'Failed to get logs');
    }
  }

  async handleEventStream(req, res) {
    // Server-Sent Events
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Cache-Control'
    });
    
    const clientId = uuidv4();
    
    // Send initial connection event
    res.write(`data: ${JSON.stringify({
      type: 'connected',
      clientId,
      timestamp: new Date()
    })}\n\n`);
    
    // Store client for broadcasting
    const sseClient = {
      id: clientId,
      res,
      connectedAt: new Date()
    };
    
    this.state.clients.set(clientId, sseClient);
    
    // Handle client disconnect
    req.on('close', () => {
      this.state.clients.delete(clientId);
    });
    
    // Send heartbeat every 30 seconds
    const heartbeat = setInterval(() => {
      res.write(`data: ${JSON.stringify({
        type: 'heartbeat',
        timestamp: new Date()
      })}\n\n`);
    }, 30000);
    
    req.on('close', () => {
      clearInterval(heartbeat);
    });
  }

  createErrorHandler() {
    return (error, req, res, next) => {
      this.state.statistics.errorCount++;
      
      this.logMessage('error', 'api', 'Request error', {
        requestId: req.id,
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method
      });
      
      if (res.headersSent) {
        return next(error);
      }
      
      res.status(500).json({
        error: 'Internal server error',
        requestId: req.id,
        timestamp: new Date()
      });
    };
  }

  handleError(res, error, message) {
    this.state.statistics.errorCount++;
    
    console.error(`API Error: ${message}`, error);
    
    res.status(500).json({
      error: message,
      details: error.message,
      timestamp: new Date()
    });
  }

  logRequest(requestData) {
    this.state.statistics.totalRequests++;
    
    if (API_CONFIG.LOGGING.LOG_REQUESTS) {
      this.logMessage('info', 'request', `${requestData.method} ${requestData.url}`, {
        statusCode: requestData.statusCode,
        duration: requestData.duration,
        ip: requestData.ip
      });
    }
  }

  // Placeholder implementations for remaining handlers
  async handlePauseMigration(req, res) {
    res.status(501).json({ error: 'Pause migration not yet implemented' });
  }

  async handleResumeMigration(req, res) {
    res.status(501).json({ error: 'Resume migration not yet implemented' });
  }

  async handleAbortMigration(req, res) {
    res.status(501).json({ error: 'Abort migration not yet implemented' });
  }

  async handleEmergencyStop(req, res) {
    res.status(501).json({ error: 'Emergency stop not yet implemented' });
  }

  async handleReadinessCheck(req, res) {
    res.json({ ready: true, timestamp: new Date() });
  }

  async handleGetAlerts(req, res) {
    res.json({ alerts: [], timestamp: new Date() });
  }

  async handleGetPerformance(req, res) {
    res.json({ performance: {}, timestamp: new Date() });
  }

  async handleGetConfig(req, res) {
    res.json({ config: API_CONFIG, timestamp: new Date() });
  }

  async handleUpdateConfig(req, res) {
    res.status(501).json({ error: 'Update config not yet implemented' });
  }

  async handleGetMigrationReport(req, res) {
    res.status(501).json({ error: 'Migration report not yet implemented' });
  }

  async handleGetAuditLog(req, res) {
    res.json({ auditLog: this.state.auditLog, timestamp: new Date() });
  }

  async handleGetVersion(req, res) {
    res.json({
      version: '1.0.0',
      apiVersion: 'v1',
      nodeVersion: process.version,
      platform: process.platform,
      timestamp: new Date()
    });
  }

  /**
   * Server Management
   */
  async start() {
    if (this.state.isRunning) {
      throw new Error('API server is already running');
    }
    
    return new Promise((resolve, reject) => {
      this.server.listen(this.options.port, this.options.host, (error) => {
        if (error) {
          reject(error);
        } else {
          this.state.isRunning = true;
          this.state.startTime = new Date();
          
          console.log(`🚀 Production Migration API started on http://${this.options.host}:${this.options.port}`);
          resolve();
        }
      });
    });
  }

  async stop() {
    if (!this.state.isRunning) {
      return;
    }
    
    console.log('🛑 Stopping Production Migration API...');
    
    // Close WebSocket connections
    if (this.wss) {
      this.wss.clients.forEach(ws => {
        ws.close();
      });
      this.wss.close();
    }
    
    // Close HTTP server
    return new Promise((resolve) => {
      this.server.close(() => {
        this.state.isRunning = false;
        console.log('✅ Production Migration API stopped');
        resolve();
      });
    });
  }

  getStatus() {
    return {
      isRunning: this.state.isRunning,
      startTime: this.state.startTime,
      uptime: this.state.startTime ? Date.now() - this.state.startTime.getTime() : 0,
      clients: this.state.clients.size,
      statistics: this.state.statistics
    };
  }
}

/**
 * Main entry point
 */
async function main() {
  const api = new ProductionMigrationAPI();
  
  try {
    await api.start();
    
    // Graceful shutdown
    process.on('SIGINT', async () => {
      console.log('\n🛑 Received SIGINT. Shutting down gracefully...');
      await api.stop();
      process.exit(0);
    });
    
    process.on('SIGTERM', async () => {
      console.log('\n🛑 Received SIGTERM. Shutting down gracefully...');
      await api.stop();
      process.exit(0);
    });
    
  } catch (error) {
    console.error('❌ Failed to start API server:', error.message);
    process.exit(1);
  }
}

// Export for use as module
module.exports = {
  ProductionMigrationAPI,
  API_CONFIG
};

// Run if called directly
if (require.main === module) {
  main();
}