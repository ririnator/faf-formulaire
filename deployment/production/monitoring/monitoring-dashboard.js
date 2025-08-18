/**
 * Production Monitoring Dashboard
 * Real-time dashboard for monitoring FAF application health and performance
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const HealthMonitor = require('./health-monitor');

class MonitoringDashboard {
  constructor() {
    this.app = express();
    this.healthMonitor = new HealthMonitor();
    this.port = process.env.MONITORING_PORT || 3001;
    this.setupMiddleware();
    this.setupRoutes();
  }

  /**
   * Setup Express middleware
   */
  setupMiddleware() {
    // Basic authentication for dashboard access
    this.app.use('/dashboard', (req, res, next) => {
      const auth = req.headers.authorization;
      
      if (!auth) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Monitoring Dashboard"');
        return res.status(401).send('Authentication required');
      }

      const credentials = Buffer.from(auth.split(' ')[1], 'base64').toString().split(':');
      const username = credentials[0];
      const password = credentials[1];

      // Use environment variables for dashboard credentials
      const validUsername = process.env.MONITOR_USERNAME || 'admin';
      const validPassword = process.env.MONITOR_PASSWORD || 'changeme';

      if (username !== validUsername || password !== validPassword) {
        return res.status(401).send('Invalid credentials');
      }

      next();
    });

    this.app.use(express.json());
    this.app.use(express.static(path.join(__dirname, 'public')));
  }

  /**
   * Setup API routes
   */
  setupRoutes() {
    // Dashboard home
    this.app.get('/dashboard', (req, res) => {
      res.send(this.generateDashboardHTML());
    });

    // API endpoints
    this.app.get('/api/health', (req, res) => {
      res.json(this.healthMonitor.getDashboardData());
    });

    this.app.get('/api/metrics', (req, res) => {
      res.json({
        system: this.healthMonitor.metrics.system,
        application: this.healthMonitor.metrics.application,
        database: this.healthMonitor.metrics.database,
        ssl: this.healthMonitor.metrics.ssl
      });
    });

    this.app.get('/api/alerts', (req, res) => {
      const activeAlerts = this.healthMonitor.alerts.filter(a => !a.resolved);
      res.json(activeAlerts);
    });

    this.app.post('/api/alerts/:id/resolve', (req, res) => {
      const alertId = req.params.id;
      const alert = this.healthMonitor.alerts.find(a => a.id === alertId);
      
      if (alert) {
        alert.resolved = true;
        alert.resolvedAt = new Date().toISOString();
        res.json({ success: true });
      } else {
        res.status(404).json({ error: 'Alert not found' });
      }
    });

    // System information
    this.app.get('/api/system', (req, res) => {
      const os = require('os');
      res.json({
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        release: os.release(),
        uptime: os.uptime(),
        loadavg: os.loadavg(),
        totalmem: os.totalmem(),
        freemem: os.freemem(),
        cpus: os.cpus().length,
        nodeVersion: process.version,
        pid: process.pid
      });
    });

    // Application logs
    this.app.get('/api/logs', (req, res) => {
      const logFile = this.healthMonitor.config.logPath;
      const lines = parseInt(req.query.lines) || 100;
      
      try {
        if (fs.existsSync(logFile)) {
          const logs = fs.readFileSync(logFile, 'utf8')
            .split('\n')
            .filter(line => line.trim())
            .slice(-lines)
            .map(line => {
              try {
                return JSON.parse(line);
              } catch {
                return { message: line, timestamp: null };
              }
            });
          
          res.json(logs);
        } else {
          res.json([]);
        }
      } catch (error) {
        res.status(500).json({ error: 'Failed to read logs' });
      }
    });

    // Health check endpoint for the dashboard itself
    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    });
  }

  /**
   * Generate dashboard HTML
   */
  generateDashboardHTML() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FAF Monitoring Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        
        .header {
            background: #2563eb;
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .card h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
            color: #1f2937;
        }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .metric:last-child {
            border-bottom: none;
        }
        
        .metric-label {
            font-weight: 500;
            color: #6b7280;
        }
        
        .metric-value {
            font-weight: 600;
        }
        
        .status-healthy {
            color: #059669;
        }
        
        .status-warning {
            color: #d97706;
        }
        
        .status-critical {
            color: #dc2626;
        }
        
        .alert {
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .alert-warning {
            background: #fffbeb;
            border-color: #fed7aa;
        }
        
        .alert-critical {
            background: #fef2f2;
            border-color: #fecaca;
        }
        
        .btn {
            background: #2563eb;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.875rem;
        }
        
        .btn:hover {
            background: #1d4ed8;
        }
        
        .chart-container {
            height: 200px;
            background: #f9fafb;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #6b7280;
            margin-top: 1rem;
        }
        
        .refresh-btn {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: #059669;
            color: white;
            border: none;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            font-size: 1.5rem;
        }
        
        .loading {
            opacity: 0.6;
            pointer-events: none;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🏥 FAF Monitoring Dashboard</h1>
    </div>
    
    <div class="container">
        <div id="alerts-section">
            <!-- Alerts will be loaded here -->
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>🖥️ System Health</h2>
                <div id="system-metrics">
                    <!-- System metrics will be loaded here -->
                </div>
            </div>
            
            <div class="card">
                <h2>🚀 Application Health</h2>
                <div id="app-metrics">
                    <!-- Application metrics will be loaded here -->
                </div>
            </div>
            
            <div class="card">
                <h2>🗄️ Database Health</h2>
                <div id="db-metrics">
                    <!-- Database metrics will be loaded here -->
                </div>
            </div>
            
            <div class="card">
                <h2>🔒 SSL Status</h2>
                <div id="ssl-metrics">
                    <!-- SSL metrics will be loaded here -->
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>📊 Performance Charts</h2>
            <div class="chart-container">
                📈 Performance charts would be rendered here with Chart.js or similar
            </div>
        </div>
        
        <div class="card">
            <h2>📝 Recent Logs</h2>
            <div id="logs-section">
                <!-- Logs will be loaded here -->
            </div>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="refreshDashboard()">🔄</button>
    
    <script>
        let refreshInterval;
        
        async function loadDashboardData() {
            try {
                document.body.classList.add('loading');
                
                const [healthData, alerts, logs] = await Promise.all([
                    fetch('/api/health').then(r => r.json()),
                    fetch('/api/alerts').then(r => r.json()),
                    fetch('/api/logs?lines=10').then(r => r.json())
                ]);
                
                updateSystemMetrics(healthData.metrics.system);
                updateAppMetrics(healthData.metrics.application);
                updateDbMetrics(healthData.metrics.database);
                updateSslMetrics(healthData.metrics.ssl);
                updateAlerts(alerts);
                updateLogs(logs);
                
            } catch (error) {
                console.error('Failed to load dashboard data:', error);
            } finally {
                document.body.classList.remove('loading');
            }
        }
        
        function updateSystemMetrics(system) {
            const container = document.getElementById('system-metrics');
            
            const memoryPercent = system.memory ? (system.memory.percentage * 100).toFixed(1) : 'N/A';
            const cpuPercent = system.cpu ? (system.cpu.usage * 100).toFixed(1) : 'N/A';
            const diskPercent = system.disk ? (system.disk.percentage * 100).toFixed(1) : 'N/A';
            const uptime = system.uptime ? formatUptime(system.uptime) : 'N/A';
            
            container.innerHTML = \`
                <div class="metric">
                    <span class="metric-label">Memory Usage</span>
                    <span class="metric-value \${getStatusClass(memoryPercent, 80, 90)}">\${memoryPercent}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">CPU Usage</span>
                    <span class="metric-value \${getStatusClass(cpuPercent, 70, 85)}">\${cpuPercent}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Disk Usage</span>
                    <span class="metric-value \${getStatusClass(diskPercent, 80, 90)}">\${diskPercent}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">System Uptime</span>
                    <span class="metric-value status-healthy">\${uptime}</span>
                </div>
            \`;
        }
        
        function updateAppMetrics(app) {
            const container = document.getElementById('app-metrics');
            
            const responseTime = app.responseTime || 0;
            const errorRate = app.errorRate ? (app.errorRate * 100).toFixed(2) : '0.00';
            const totalRequests = app.totalRequests || 0;
            
            container.innerHTML = \`
                <div class="metric">
                    <span class="metric-label">Response Time</span>
                    <span class="metric-value \${getStatusClass(responseTime, 1000, 2000)}">\${responseTime}ms</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Error Rate</span>
                    <span class="metric-value \${getStatusClass(errorRate, 2, 5)}">\${errorRate}%</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Total Requests</span>
                    <span class="metric-value status-healthy">\${totalRequests.toLocaleString()}</span>
                </div>
            \`;
        }
        
        function updateDbMetrics(db) {
            const container = document.getElementById('db-metrics');
            
            const status = db.status || 'unknown';
            const responseTime = db.responseTime || 0;
            
            container.innerHTML = \`
                <div class="metric">
                    <span class="metric-label">Connection Status</span>
                    <span class="metric-value \${status === 'healthy' ? 'status-healthy' : 'status-critical'}">\${status}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Response Time</span>
                    <span class="metric-value \${getStatusClass(responseTime, 500, 1000)}">\${responseTime}ms</span>
                </div>
            \`;
        }
        
        function updateSslMetrics(ssl) {
            const container = document.getElementById('ssl-metrics');
            
            const status = ssl.status || 'unknown';
            const daysUntilExpiry = ssl.daysUntilExpiry || 0;
            
            container.innerHTML = \`
                <div class="metric">
                    <span class="metric-label">Certificate Status</span>
                    <span class="metric-value \${status === 'valid' ? 'status-healthy' : 'status-critical'}">\${status}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Days Until Expiry</span>
                    <span class="metric-value \${getStatusClass(30 - daysUntilExpiry, 23, 27)}">\${daysUntilExpiry}</span>
                </div>
            \`;
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-section');
            
            if (alerts.length === 0) {
                container.innerHTML = '';
                return;
            }
            
            const alertsHTML = alerts.map(alert => \`
                <div class="alert alert-\${alert.level.toLowerCase()}">
                    <strong>\${alert.title}</strong>
                    <p>\${alert.message}</p>
                    <small>\${new Date(alert.timestamp).toLocaleString()}</small>
                    <button class="btn" onclick="resolveAlert('\${alert.id}')">Resolve</button>
                </div>
            \`).join('');
            
            container.innerHTML = alertsHTML;
        }
        
        function updateLogs(logs) {
            const container = document.getElementById('logs-section');
            
            const logsHTML = logs.map(log => \`
                <div style="padding: 0.5rem 0; border-bottom: 1px solid #e5e7eb; font-family: monospace; font-size: 0.875rem;">
                    <strong>\${log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'N/A'}</strong>
                    [\${log.level || 'INFO'}] \${log.message}
                </div>
            \`).join('');
            
            container.innerHTML = logsHTML || '<p>No recent logs available</p>';
        }
        
        function getStatusClass(value, warningThreshold, criticalThreshold) {
            if (value >= criticalThreshold) return 'status-critical';
            if (value >= warningThreshold) return 'status-warning';
            return 'status-healthy';
        }
        
        function formatUptime(seconds) {
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            
            if (days > 0) return \`\${days}d \${hours}h\`;
            if (hours > 0) return \`\${hours}h \${minutes}m\`;
            return \`\${minutes}m\`;
        }
        
        async function resolveAlert(alertId) {
            try {
                await fetch(\`/api/alerts/\${alertId}/resolve\`, { method: 'POST' });
                loadDashboardData();
            } catch (error) {
                console.error('Failed to resolve alert:', error);
            }
        }
        
        function refreshDashboard() {
            loadDashboardData();
        }
        
        function startAutoRefresh() {
            refreshInterval = setInterval(loadDashboardData, 30000); // 30 seconds
        }
        
        function stopAutoRefresh() {
            if (refreshInterval) {
                clearInterval(refreshInterval);
            }
        }
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', () => {
            loadDashboardData();
            startAutoRefresh();
        });
        
        // Clean up on page unload
        window.addEventListener('beforeunload', stopAutoRefresh);
    </script>
</body>
</html>
    `;
  }

  /**
   * Start the monitoring dashboard
   */
  async start() {
    try {
      // Start health monitoring
      await this.healthMonitor.start();
      
      // Start dashboard server
      this.server = this.app.listen(this.port, () => {
        console.log(`📊 Monitoring dashboard started on port ${this.port}`);
        console.log(`🔗 Access dashboard at: http://localhost:${this.port}/dashboard`);
        console.log(`👤 Username: ${process.env.MONITOR_USERNAME || 'admin'}`);
        console.log(`🔑 Password: ${process.env.MONITOR_PASSWORD || 'changeme'}`);
      });

    } catch (error) {
      console.error('Failed to start monitoring dashboard:', error);
      throw error;
    }
  }

  /**
   * Stop the monitoring dashboard
   */
  async stop() {
    if (this.healthMonitor) {
      this.healthMonitor.stop();
    }
    
    if (this.server) {
      this.server.close();
    }
    
    console.log('📊 Monitoring dashboard stopped');
  }
}

module.exports = MonitoringDashboard;

// Start dashboard if run directly
if (require.main === module) {
  const dashboard = new MonitoringDashboard();
  
  dashboard.start().catch(error => {
    console.error('Failed to start monitoring dashboard:', error);
    process.exit(1);
  });
  
  // Graceful shutdown
  process.on('SIGTERM', () => dashboard.stop());
  process.on('SIGINT', () => dashboard.stop());
}