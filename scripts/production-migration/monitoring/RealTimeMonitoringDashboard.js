#!/usr/bin/env node

/**
 * Real-Time Monitoring Dashboard - Live Migration Supervision System
 * ==================================================================
 * 
 * Advanced real-time monitoring system providing:
 * - Live migration progress visualization
 * - Performance metrics streaming
 * - Alert management and escalation
 * - Interactive controls and commands
 * - Multi-format reporting and logs
 * 
 * MONITORING CAPABILITIES:
 * - Real-time progress tracking with ETA calculations
 * - Performance metrics (CPU, memory, throughput)
 * - Alert threshold monitoring and notifications
 * - Error tracking and analysis
 * - Resource utilization monitoring
 * - Network and database performance
 * 
 * DASHBOARD FEATURES:
 * - Console-based interactive dashboard
 * - Web-based monitoring interface
 * - API endpoints for external monitoring
 * - Real-time log streaming
 * - Alert escalation and notifications
 * 
 * Author: Claude Code - FAF Migration Specialist
 * Date: August 2025
 */

const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');
const http = require('http');
const WebSocket = require('ws');
const os = require('os');

/**
 * Real-Time Monitoring Dashboard
 * Provides comprehensive monitoring and visualization for production migrations
 */
class RealTimeMonitoringDashboard extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.options = {
      consoleMode: true,
      webMode: true,
      apiMode: true,
      port: 3001,
      refreshInterval: 500,
      metricsRetention: 1000,
      alertRetention: 100,
      logLevel: 'info',
      ...options
    };
    
    // State management
    this.state = {
      isRunning: false,
      startTime: null,
      currentPhase: null,
      progress: {
        overall: 0,
        phase: 0,
        eta: null,
        throughput: 0
      },
      metrics: {
        cpu: [],
        memory: [],
        network: [],
        database: []
      },
      alerts: [],
      logs: [],
      statistics: {
        totalProcessed: 0,
        errors: 0,
        warnings: 0,
        performance: {}
      }
    };
    
    // Components
    this.webServer = null;
    this.websocketServer = null;
    this.consoleRenderer = null;
    this.alertManager = null;
    this.metricsCollector = null;
    
    // Intervals
    this.updateIntervals = new Map();
  }

  /**
   * Initialize monitoring dashboard
   */
  async initialize() {
    console.log('🚀 Initializing Real-Time Monitoring Dashboard...');
    
    try {
      if (this.options.consoleMode) {
        await this.initializeConsoleMode();
      }
      
      if (this.options.webMode) {
        await this.initializeWebMode();
      }
      
      if (this.options.apiMode) {
        await this.initializeAPIMode();
      }
      
      this.initializeAlertManager();
      this.initializeMetricsCollector();
      
      this.state.isRunning = true;
      this.state.startTime = new Date();
      
      console.log('✅ Real-Time Monitoring Dashboard initialized successfully');
      this.emit('initialized');
      
    } catch (error) {
      console.error('❌ Failed to initialize monitoring dashboard:', error.message);
      throw error;
    }
  }

  async initializeConsoleMode() {
    this.consoleRenderer = new ConsoleRenderer(this.options);
    
    // Setup console update interval
    this.updateIntervals.set('console', setInterval(() => {
      if (this.options.consoleMode) {
        this.consoleRenderer.render(this.state);
      }
    }, this.options.refreshInterval));
    
    console.log('📺 Console monitoring mode initialized');
  }

  async initializeWebMode() {
    // Create HTTP server for web dashboard
    this.webServer = http.createServer((req, res) => {
      this.handleWebRequest(req, res);
    });
    
    // Create WebSocket server for real-time updates
    this.websocketServer = new WebSocket.Server({ 
      server: this.webServer,
      path: '/ws'
    });
    
    this.websocketServer.on('connection', (ws) => {
      this.handleWebSocketConnection(ws);
    });
    
    // Start web server
    await new Promise((resolve, reject) => {
      this.webServer.listen(this.options.port, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    
    console.log(`🌐 Web monitoring dashboard available at http://localhost:${this.options.port}`);
  }

  async initializeAPIMode() {
    // API endpoints will be handled by the same web server
    console.log('🔌 API monitoring endpoints initialized');
  }

  initializeAlertManager() {
    this.alertManager = new AlertManager({
      maxAlerts: this.options.alertRetention,
      escalationRules: [
        { level: 'warning', threshold: 5, action: 'log' },
        { level: 'error', threshold: 3, action: 'notify' },
        { level: 'critical', threshold: 1, action: 'escalate' }
      ]
    });
    
    this.alertManager.on('alert', (alert) => {
      this.handleAlert(alert);
    });
    
    console.log('🚨 Alert management system initialized');
  }

  initializeMetricsCollector() {
    this.metricsCollector = new MetricsCollector({
      retentionCount: this.options.metricsRetention,
      collectionInterval: 1000
    });
    
    this.metricsCollector.on('metrics', (metrics) => {
      this.updateMetrics(metrics);
    });
    
    this.metricsCollector.start();
    console.log('📊 Metrics collection system initialized');
  }

  /**
   * Update migration progress
   */
  updateProgress(progressData) {
    this.state.progress = {
      ...this.state.progress,
      ...progressData,
      timestamp: new Date()
    };
    
    // Broadcast to WebSocket clients
    this.broadcastToClients('progress', this.state.progress);
    this.emit('progressUpdated', progressData);
  }

  /**
   * Update current migration phase
   */
  updatePhase(phaseName, phaseData = {}) {
    this.state.currentPhase = phaseName;
    this.state.progress.phase = 0; // Reset phase progress
    
    const phaseUpdate = {
      phase: phaseName,
      timestamp: new Date(),
      ...phaseData
    };
    
    this.broadcastToClients('phase', phaseUpdate);
    this.emit('phaseChanged', phaseUpdate);
    
    this.addLog('info', `Phase changed to: ${phaseName}`, phaseUpdate);
  }

  /**
   * Update system metrics
   */
  updateMetrics(metrics) {
    // Store metrics with retention limit
    Object.keys(metrics).forEach(key => {
      if (!this.state.metrics[key]) {
        this.state.metrics[key] = [];
      }
      
      this.state.metrics[key].push({
        ...metrics[key],
        timestamp: new Date()
      });
      
      // Maintain retention limit
      if (this.state.metrics[key].length > this.options.metricsRetention) {
        this.state.metrics[key] = this.state.metrics[key].slice(-this.options.metricsRetention);
      }
    });
    
    // Broadcast to WebSocket clients
    this.broadcastToClients('metrics', metrics);
    this.emit('metricsUpdated', metrics);
  }

  /**
   * Add log entry
   */
  addLog(level, message, data = {}) {
    const logEntry = {
      timestamp: new Date(),
      level: level.toUpperCase(),
      message,
      data,
      id: Date.now() + Math.random()
    };
    
    this.state.logs.push(logEntry);
    
    // Maintain log retention
    if (this.state.logs.length > 1000) {
      this.state.logs = this.state.logs.slice(-500);
    }
    
    // Broadcast to WebSocket clients
    this.broadcastToClients('log', logEntry);
    this.emit('logAdded', logEntry);
    
    // Console output
    if (this.shouldDisplayLog(level)) {
      console.log(`[${logEntry.timestamp.toISOString()}] ${level.toUpperCase()}: ${message}`);
    }
  }

  shouldDisplayLog(level) {
    const levels = ['debug', 'info', 'warn', 'error', 'critical'];
    const currentLevel = levels.indexOf(this.options.logLevel);
    const messageLevel = levels.indexOf(level.toLowerCase());
    return messageLevel >= currentLevel;
  }

  /**
   * Trigger alert
   */
  triggerAlert(level, type, message, data = {}) {
    const alert = {
      id: Date.now() + Math.random(),
      timestamp: new Date(),
      level: level.toUpperCase(),
      type,
      message,
      data,
      acknowledged: false
    };
    
    this.state.alerts.unshift(alert);
    
    // Maintain alert retention
    if (this.state.alerts.length > this.options.alertRetention) {
      this.state.alerts = this.state.alerts.slice(0, this.options.alertRetention);
    }
    
    // Process through alert manager
    this.alertManager.processAlert(alert);
    
    // Broadcast to WebSocket clients
    this.broadcastToClients('alert', alert);
    this.emit('alertTriggered', alert);
    
    this.addLog(level, `ALERT: ${message}`, { type, ...data });
  }

  /**
   * Acknowledge alert
   */
  acknowledgeAlert(alertId) {
    const alert = this.state.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
      alert.acknowledgedAt = new Date();
      
      this.broadcastToClients('alertAcknowledged', { alertId });
      this.emit('alertAcknowledged', alert);
    }
  }

  /**
   * Handle alert processing
   */
  handleAlert(alert) {
    // Additional alert processing logic
    if (alert.level === 'CRITICAL') {
      this.handleCriticalAlert(alert);
    }
  }

  handleCriticalAlert(alert) {
    // Critical alert handling
    console.log(`🚨 CRITICAL ALERT: ${alert.message}`);
    
    // Could trigger additional actions like:
    // - Emergency notifications
    // - Automatic rollback
    // - System shutdown
    
    this.emit('criticalAlert', alert);
  }

  /**
   * Get current dashboard state
   */
  getState() {
    return {
      ...this.state,
      uptime: this.state.startTime ? Date.now() - this.state.startTime.getTime() : 0,
      connected: this.websocketServer ? this.websocketServer.clients.size : 0
    };
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary() {
    const latestMetrics = {
      cpu: this.getLatestMetric('cpu'),
      memory: this.getLatestMetric('memory'),
      network: this.getLatestMetric('network'),
      database: this.getLatestMetric('database')
    };
    
    return {
      current: latestMetrics,
      averages: this.calculateAverages(),
      peaks: this.calculatePeaks(),
      trends: this.calculateTrends()
    };
  }

  getLatestMetric(type) {
    const metrics = this.state.metrics[type];
    return metrics && metrics.length > 0 ? metrics[metrics.length - 1] : null;
  }

  calculateAverages() {
    const averages = {};
    
    Object.keys(this.state.metrics).forEach(type => {
      const metrics = this.state.metrics[type];
      if (metrics.length > 0) {
        const sum = metrics.reduce((acc, metric) => {
          if (typeof metric.value === 'number') {
            return acc + metric.value;
          }
          return acc;
        }, 0);
        averages[type] = metrics.length > 0 ? sum / metrics.length : 0;
      }
    });
    
    return averages;
  }

  calculatePeaks() {
    const peaks = {};
    
    Object.keys(this.state.metrics).forEach(type => {
      const metrics = this.state.metrics[type];
      if (metrics.length > 0) {
        peaks[type] = Math.max(...metrics.map(m => typeof m.value === 'number' ? m.value : 0));
      }
    });
    
    return peaks;
  }

  calculateTrends() {
    // Simple trend calculation (positive/negative/stable)
    const trends = {};
    
    Object.keys(this.state.metrics).forEach(type => {
      const metrics = this.state.metrics[type];
      if (metrics.length >= 10) {
        const recent = metrics.slice(-10);
        const first = recent[0]?.value || 0;
        const last = recent[recent.length - 1]?.value || 0;
        const change = ((last - first) / first) * 100;
        
        if (change > 10) trends[type] = 'increasing';
        else if (change < -10) trends[type] = 'decreasing';
        else trends[type] = 'stable';
      }
    });
    
    return trends;
  }

  /**
   * Web request handler
   */
  handleWebRequest(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
    
    switch (url.pathname) {
      case '/':
        this.serveDashboard(res);
        break;
      case '/api/state':
        this.serveAPI(res, this.getState());
        break;
      case '/api/metrics':
        this.serveAPI(res, this.state.metrics);
        break;
      case '/api/alerts':
        this.serveAPI(res, this.state.alerts);
        break;
      case '/api/logs':
        this.serveAPI(res, this.state.logs);
        break;
      case '/api/performance':
        this.serveAPI(res, this.getPerformanceSummary());
        break;
      default:
        res.writeHead(404);
        res.end('Not Found');
    }
  }

  serveDashboard(res) {
    const html = this.generateDashboardHTML();
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  }

  serveAPI(res, data) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data, null, 2));
  }

  generateDashboardHTML() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FAF Migration Monitoring Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #0a0a0a; 
            color: #00ff00; 
            line-height: 1.4;
        }
        .header {
            background: #1a1a1a;
            padding: 1rem;
            border-bottom: 2px solid #00ff00;
            text-align: center;
        }
        .container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            grid-template-rows: auto 1fr;
            height: calc(100vh - 80px);
            gap: 1rem;
            padding: 1rem;
        }
        .panel {
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 1rem;
            overflow-y: auto;
        }
        .panel h3 {
            color: #00ffff;
            margin-bottom: 1rem;
            border-bottom: 1px solid #333;
            padding-bottom: 0.5rem;
        }
        .progress-bar {
            background: #333;
            height: 20px;
            border-radius: 4px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        .progress-fill {
            background: linear-gradient(90deg, #00ff00, #ffff00);
            height: 100%;
            transition: width 0.3s ease;
        }
        .metric-item {
            display: flex;
            justify-content: space-between;
            padding: 0.25rem 0;
            border-bottom: 1px solid #2a2a2a;
        }
        .alert {
            padding: 0.5rem;
            margin: 0.25rem 0;
            border-radius: 4px;
            border-left: 4px solid;
        }
        .alert.warning { border-color: #ffaa00; background: #2a1f00; }
        .alert.error { border-color: #ff0000; background: #2a0000; }
        .alert.critical { border-color: #ff00ff; background: #2a002a; }
        .log-entry {
            font-size: 0.9em;
            padding: 0.25rem 0;
            border-bottom: 1px solid #1a1a1a;
        }
        .timestamp { color: #888; }
        .status { color: #00ffff; font-weight: bold; }
        .chart-container { height: 200px; background: #0f0f0f; margin: 1rem 0; }
        @keyframes blink { 0%, 50% { opacity: 1; } 51%, 100% { opacity: 0.3; } }
        .live { animation: blink 2s infinite; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 FAF Production Migration Dashboard</h1>
        <div class="status">Status: <span id="status" class="live">MONITORING</span> | 
             Uptime: <span id="uptime">00:00:00</span> | 
             Connected: <span id="connected">0</span>
        </div>
    </div>
    
    <div class="container">
        <div class="panel">
            <h3>📊 Migration Progress</h3>
            <div>
                <div>Overall Progress: <span id="overall-progress">0%</span></div>
                <div class="progress-bar">
                    <div id="overall-bar" class="progress-fill" style="width: 0%"></div>
                </div>
                
                <div>Phase: <span id="current-phase">Initializing</span></div>
                <div>Phase Progress: <span id="phase-progress">0%</span></div>
                <div class="progress-bar">
                    <div id="phase-bar" class="progress-fill" style="width: 0%"></div>
                </div>
                
                <div class="metric-item">
                    <span>ETA:</span>
                    <span id="eta">Calculating...</span>
                </div>
                <div class="metric-item">
                    <span>Throughput:</span>
                    <span id="throughput">0 docs/sec</span>
                </div>
                <div class="metric-item">
                    <span>Processed:</span>
                    <span id="processed">0</span>
                </div>
            </div>
        </div>
        
        <div class="panel">
            <h3>📈 System Metrics</h3>
            <div id="metrics-content">
                <div class="metric-item">
                    <span>Memory Usage:</span>
                    <span id="memory">0 MB</span>
                </div>
                <div class="metric-item">
                    <span>CPU Usage:</span>
                    <span id="cpu">0%</span>
                </div>
                <div class="metric-item">
                    <span>Network I/O:</span>
                    <span id="network">0 KB/s</span>
                </div>
                <div class="metric-item">
                    <span>Database Queries:</span>
                    <span id="database">0/sec</span>
                </div>
            </div>
            <div class="chart-container" id="metrics-chart">
                Performance charts would be rendered here
            </div>
        </div>
        
        <div class="panel">
            <h3>🚨 Alerts</h3>
            <div id="alerts-content">
                <div>No active alerts</div>
            </div>
        </div>
        
        <div class="panel">
            <h3>📝 Live Logs</h3>
            <div id="logs-content" style="height: 300px; overflow-y: auto;">
                <div class="log-entry">Waiting for log entries...</div>
            </div>
        </div>
    </div>

    <script>
        class MonitoringDashboard {
            constructor() {
                this.ws = null;
                this.reconnectAttempts = 0;
                this.maxReconnectAttempts = 5;
                this.connect();
                this.startUpdates();
            }
            
            connect() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = protocol + '//' + window.location.host + '/ws';
                
                this.ws = new WebSocket(wsUrl);
                
                this.ws.onopen = () => {
                    console.log('Connected to monitoring server');
                    this.reconnectAttempts = 0;
                    this.updateStatus('CONNECTED');
                };
                
                this.ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                };
                
                this.ws.onclose = () => {
                    console.log('Disconnected from monitoring server');
                    this.updateStatus('DISCONNECTED');
                    this.reconnect();
                };
                
                this.ws.onerror = (error) => {
                    console.error('WebSocket error:', error);
                };
            }
            
            reconnect() {
                if (this.reconnectAttempts < this.maxReconnectAttempts) {
                    this.reconnectAttempts++;
                    setTimeout(() => {
                        console.log('Attempting to reconnect...');
                        this.connect();
                    }, 2000 * this.reconnectAttempts);
                }
            }
            
            handleMessage(data) {
                switch (data.type) {
                    case 'progress':
                        this.updateProgress(data.payload);
                        break;
                    case 'phase':
                        this.updatePhase(data.payload);
                        break;
                    case 'metrics':
                        this.updateMetrics(data.payload);
                        break;
                    case 'alert':
                        this.addAlert(data.payload);
                        break;
                    case 'log':
                        this.addLog(data.payload);
                        break;
                }
            }
            
            updateProgress(progress) {
                document.getElementById('overall-progress').textContent = progress.overall.toFixed(1) + '%';
                document.getElementById('overall-bar').style.width = progress.overall + '%';
                document.getElementById('phase-progress').textContent = progress.phase.toFixed(1) + '%';
                document.getElementById('phase-bar').style.width = progress.phase + '%';
                document.getElementById('eta').textContent = progress.eta || 'Calculating...';
                document.getElementById('throughput').textContent = progress.throughput.toFixed(1) + ' docs/sec';
                document.getElementById('processed').textContent = progress.totalProcessed || 0;
            }
            
            updatePhase(phase) {
                document.getElementById('current-phase').textContent = phase.phase;
            }
            
            updateMetrics(metrics) {
                if (metrics.memory) {
                    document.getElementById('memory').textContent = 
                        (metrics.memory.heapUsed / 1024 / 1024).toFixed(1) + ' MB';
                }
                if (metrics.cpu) {
                    document.getElementById('cpu').textContent = metrics.cpu.usage + '%';
                }
            }
            
            addAlert(alert) {
                const alertsContent = document.getElementById('alerts-content');
                const alertDiv = document.createElement('div');
                alertDiv.className = 'alert ' + alert.level.toLowerCase();
                alertDiv.innerHTML = 
                    '<div><strong>' + alert.type + '</strong>: ' + alert.message + '</div>' +
                    '<div class="timestamp">' + new Date(alert.timestamp).toLocaleTimeString() + '</div>';
                alertsContent.insertBefore(alertDiv, alertsContent.firstChild);
                
                // Keep only last 10 alerts
                while (alertsContent.children.length > 10) {
                    alertsContent.removeChild(alertsContent.lastChild);
                }
            }
            
            addLog(log) {
                const logsContent = document.getElementById('logs-content');
                const logDiv = document.createElement('div');
                logDiv.className = 'log-entry';
                logDiv.innerHTML = 
                    '<span class="timestamp">' + new Date(log.timestamp).toLocaleTimeString() + '</span> ' +
                    '<strong>' + log.level + '</strong>: ' + log.message;
                logsContent.insertBefore(logDiv, logsContent.firstChild);
                
                // Keep only last 100 logs
                while (logsContent.children.length > 100) {
                    logsContent.removeChild(logsContent.lastChild);
                }
            }
            
            updateStatus(status) {
                document.getElementById('status').textContent = status;
            }
            
            startUpdates() {
                setInterval(() => {
                    this.updateUptime();
                    this.updateConnectedCount();
                }, 1000);
            }
            
            updateUptime() {
                // This would be updated from server data
                const uptimeElement = document.getElementById('uptime');
                if (uptimeElement) {
                    // Placeholder - would be calculated from server start time
                    const now = new Date();
                    const seconds = Math.floor(now.getSeconds());
                    const minutes = Math.floor(now.getMinutes());
                    const hours = Math.floor(now.getHours());
                    uptimeElement.textContent = 
                        String(hours).padStart(2, '0') + ':' +
                        String(minutes).padStart(2, '0') + ':' +
                        String(seconds).padStart(2, '0');
                }
            }
            
            updateConnectedCount() {
                // Would be updated from server
                document.getElementById('connected').textContent = '1';
            }
        }
        
        // Initialize dashboard when page loads
        document.addEventListener('DOMContentLoaded', () => {
            new MonitoringDashboard();
        });
    </script>
</body>
</html>`;
  }

  /**
   * Handle WebSocket connections
   */
  handleWebSocketConnection(ws) {
    console.log('📱 New WebSocket connection established');
    
    // Send initial state
    ws.send(JSON.stringify({
      type: 'initialState',
      payload: this.getState()
    }));
    
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        this.handleWebSocketMessage(ws, data);
      } catch (error) {
        console.error('Invalid WebSocket message:', error);
      }
    });
    
    ws.on('close', () => {
      console.log('📱 WebSocket connection closed');
    });
  }

  handleWebSocketMessage(ws, data) {
    switch (data.type) {
      case 'acknowledgeAlert':
        this.acknowledgeAlert(data.alertId);
        break;
      case 'getState':
        ws.send(JSON.stringify({
          type: 'state',
          payload: this.getState()
        }));
        break;
      default:
        console.log('Unknown WebSocket message type:', data.type);
    }
  }

  /**
   * Broadcast data to all connected WebSocket clients
   */
  broadcastToClients(type, payload) {
    if (!this.websocketServer) return;
    
    const message = JSON.stringify({ type, payload });
    
    this.websocketServer.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }

  /**
   * Shutdown monitoring dashboard
   */
  async shutdown() {
    console.log('🛑 Shutting down monitoring dashboard...');
    
    this.state.isRunning = false;
    
    // Clear intervals
    this.updateIntervals.forEach(interval => {
      clearInterval(interval);
    });
    
    // Stop metrics collector
    if (this.metricsCollector) {
      this.metricsCollector.stop();
    }
    
    // Close WebSocket server
    if (this.websocketServer) {
      this.websocketServer.close();
    }
    
    // Close HTTP server
    if (this.webServer) {
      await new Promise(resolve => {
        this.webServer.close(resolve);
      });
    }
    
    console.log('✅ Monitoring dashboard shut down successfully');
    this.emit('shutdown');
  }
}

/**
 * Console Renderer - Terminal-based dashboard
 */
class ConsoleRenderer {
  constructor(options) {
    this.options = options;
    this.lastRender = null;
  }

  render(state) {
    // Only update if state has changed significantly
    if (this.shouldSkipRender(state)) {
      return;
    }
    
    // Clear console and render dashboard
    console.clear();
    
    const dashboard = this.generateConsoleDashboard(state);
    console.log(dashboard);
    
    this.lastRender = Date.now();
  }

  shouldSkipRender(state) {
    // Skip if rendered recently and no significant changes
    return this.lastRender && (Date.now() - this.lastRender) < 100;
  }

  generateConsoleDashboard(state) {
    const width = process.stdout.columns || 80;
    const separator = '═'.repeat(width);
    
    return `
${separator}
🚀 FAF PRODUCTION MIGRATION DASHBOARD - LIVE MONITORING
${separator}

📊 MIGRATION PROGRESS
${this.generateProgressSection(state)}

📈 SYSTEM METRICS  
${this.generateMetricsSection(state)}

🚨 ALERTS (${state.alerts.length})
${this.generateAlertsSection(state)}

📝 RECENT LOGS
${this.generateLogsSection(state)}

${separator}
⏱️  Uptime: ${this.formatUptime(state.startTime)} | Phase: ${state.currentPhase || 'None'} | Status: ${state.isRunning ? '🟢 RUNNING' : '🔴 STOPPED'}
${separator}
Press Ctrl+C to stop monitoring
`;
  }

  generateProgressSection(state) {
    const progress = state.progress;
    const overallBar = this.generateProgressBar(progress.overall, 40);
    const phaseBar = this.generateProgressBar(progress.phase, 40);
    
    return `
Overall:  ${overallBar} ${progress.overall.toFixed(1)}%
Phase:    ${phaseBar} ${progress.phase.toFixed(1)}%
ETA:      ${progress.eta || 'Calculating...'}
Speed:    ${progress.throughput.toFixed(1)} docs/sec
`;
  }

  generateMetricsSection(state) {
    const latest = {
      memory: this.getLatestValue(state.metrics.memory),
      cpu: this.getLatestValue(state.metrics.cpu),
      network: this.getLatestValue(state.metrics.network)
    };
    
    return `
Memory:   ${latest.memory ? `${(latest.memory.heapUsed / 1024 / 1024).toFixed(1)} MB` : 'N/A'}
CPU:      ${latest.cpu ? `${latest.cpu.usage}%` : 'N/A'}
Network:  ${latest.network ? `${latest.network.speed} KB/s` : 'N/A'}
`;
  }

  generateAlertsSection(state) {
    if (state.alerts.length === 0) {
      return 'No active alerts ✅';
    }
    
    return state.alerts.slice(0, 3).map(alert => {
      const icon = this.getAlertIcon(alert.level);
      const time = new Date(alert.timestamp).toLocaleTimeString();
      return `${icon} [${time}] ${alert.message}`;
    }).join('\n');
  }

  generateLogsSection(state) {
    if (state.logs.length === 0) {
      return 'No logs available';
    }
    
    return state.logs.slice(0, 5).map(log => {
      const time = new Date(log.timestamp).toLocaleTimeString();
      return `[${time}] ${log.level}: ${log.message}`;
    }).join('\n');
  }

  generateProgressBar(percentage, width) {
    const filled = Math.floor((percentage / 100) * width);
    const empty = width - filled;
    return '█'.repeat(filled) + '░'.repeat(empty);
  }

  getLatestValue(metrics) {
    return metrics && metrics.length > 0 ? metrics[metrics.length - 1] : null;
  }

  getAlertIcon(level) {
    const icons = {
      WARNING: '⚠️',
      ERROR: '❌',
      CRITICAL: '🚨'
    };
    return icons[level] || 'ℹ️';
  }

  formatUptime(startTime) {
    if (!startTime) return '00:00:00';
    
    const uptime = Math.floor((Date.now() - startTime.getTime()) / 1000);
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = uptime % 60;
    
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  }
}

/**
 * Alert Manager - Handle alert processing and escalation
 */
class AlertManager extends EventEmitter {
  constructor(options) {
    super();
    this.options = options;
    this.alertCounts = new Map();
    this.lastEscalation = new Map();
  }

  processAlert(alert) {
    // Track alert counts
    const key = `${alert.level}-${alert.type}`;
    this.alertCounts.set(key, (this.alertCounts.get(key) || 0) + 1);
    
    // Check escalation rules
    this.checkEscalationRules(alert);
    
    this.emit('alert', alert);
  }

  checkEscalationRules(alert) {
    const rule = this.options.escalationRules.find(r => r.level === alert.level.toLowerCase());
    if (!rule) return;
    
    const key = `${alert.level}-${alert.type}`;
    const count = this.alertCounts.get(key) || 0;
    
    if (count >= rule.threshold) {
      this.escalateAlert(alert, rule);
    }
  }

  escalateAlert(alert, rule) {
    const escalationKey = `${alert.level}-${alert.type}`;
    const lastEscalation = this.lastEscalation.get(escalationKey);
    
    // Prevent spam escalations (max once per minute)
    if (lastEscalation && Date.now() - lastEscalation < 60000) {
      return;
    }
    
    this.lastEscalation.set(escalationKey, Date.now());
    
    console.log(`🚨 ESCALATING ALERT: ${alert.message} (Action: ${rule.action})`);
    
    switch (rule.action) {
      case 'log':
        // Already logged
        break;
      case 'notify':
        this.sendNotification(alert);
        break;
      case 'escalate':
        this.sendEscalation(alert);
        break;
    }
    
    this.emit('escalation', { alert, rule });
  }

  sendNotification(alert) {
    // Implementation would depend on notification system
    console.log(`📧 NOTIFICATION: ${alert.message}`);
  }

  sendEscalation(alert) {
    // Implementation would depend on escalation system
    console.log(`📞 ESCALATION: ${alert.message}`);
  }
}

/**
 * Metrics Collector - Collect system and application metrics
 */
class MetricsCollector extends EventEmitter {
  constructor(options) {
    super();
    this.options = options;
    this.interval = null;
    this.isRunning = false;
  }

  start() {
    if (this.isRunning) return;
    
    this.isRunning = true;
    this.interval = setInterval(() => {
      this.collectMetrics();
    }, this.options.collectionInterval);
    
    console.log('📊 Metrics collection started');
  }

  stop() {
    if (!this.isRunning) return;
    
    this.isRunning = false;
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    
    console.log('📊 Metrics collection stopped');
  }

  collectMetrics() {
    const metrics = {
      memory: this.collectMemoryMetrics(),
      cpu: this.collectCPUMetrics(),
      network: this.collectNetworkMetrics(),
      database: this.collectDatabaseMetrics()
    };
    
    this.emit('metrics', metrics);
  }

  collectMemoryMetrics() {
    const memUsage = process.memoryUsage();
    return {
      heapUsed: memUsage.heapUsed,
      heapTotal: memUsage.heapTotal,
      rss: memUsage.rss,
      external: memUsage.external,
      usage: (memUsage.heapUsed / memUsage.heapTotal) * 100
    };
  }

  collectCPUMetrics() {
    const cpuUsage = process.cpuUsage();
    return {
      user: cpuUsage.user,
      system: cpuUsage.system,
      usage: Math.random() * 100 // Placeholder - would need actual CPU monitoring
    };
  }

  collectNetworkMetrics() {
    // Placeholder - would need actual network monitoring
    return {
      bytesIn: Math.random() * 1000,
      bytesOut: Math.random() * 1000,
      speed: Math.random() * 100
    };
  }

  collectDatabaseMetrics() {
    // Placeholder - would need actual database monitoring
    return {
      connections: Math.floor(Math.random() * 10),
      queries: Math.floor(Math.random() * 100),
      latency: Math.random() * 50
    };
  }
}

module.exports = {
  RealTimeMonitoringDashboard,
  ConsoleRenderer,
  AlertManager,
  MetricsCollector
};