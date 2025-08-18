/**
 * Production Health Monitoring System
 * Comprehensive monitoring for application health, performance, and security
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { MongoClient } = require('mongodb');
const https = require('https');
const { spawn } = require('child_process');

class HealthMonitor {
  constructor() {
    this.config = {
      checkInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 60000, // 1 minute
      alertThresholds: {
        memory: parseFloat(process.env.MEMORY_ALERT_THRESHOLD) || 0.8,
        cpu: parseFloat(process.env.CPU_ALERT_THRESHOLD) || 0.8,
        disk: parseFloat(process.env.DISK_ALERT_THRESHOLD) || 0.9,
        responseTime: parseInt(process.env.RESPONSE_TIME_THRESHOLD) || 2000,
        errorRate: parseFloat(process.env.ERROR_RATE_THRESHOLD) || 0.05
      },
      retentionHours: parseInt(process.env.METRICS_RETENTION_HOURS) || 72,
      logPath: process.env.LOG_FILE_PATH || '/var/log/faf/health.log'
    };

    this.metrics = {
      system: {
        memory: [],
        cpu: [],
        disk: [],
        uptime: 0
      },
      application: {
        responseTime: [],
        errorRate: [],
        activeConnections: 0,
        requests: {
          total: 0,
          successful: 0,
          failed: 0
        }
      },
      database: {
        connectionStatus: 'unknown',
        responseTime: [],
        activeConnections: 0,
        slowQueries: 0
      },
      ssl: {
        certificateExpiry: null,
        lastCheck: null,
        status: 'unknown'
      }
    };

    this.alerts = [];
    this.isRunning = false;
  }

  /**
   * Start health monitoring
   */
  async start() {
    console.log('🏥 Starting health monitoring system...');
    
    this.isRunning = true;
    this.createLogDirectory();
    
    // Initial system scan
    await this.performHealthCheck();
    
    // Start periodic monitoring
    this.monitoringInterval = setInterval(async () => {
      try {
        await this.performHealthCheck();
      } catch (error) {
        console.error('Health check failed:', error);
        this.logAlert('CRITICAL', 'Health check system failure', error.message);
      }
    }, this.config.checkInterval);

    // Start cleanup job
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldMetrics();
    }, 3600000); // Every hour

    console.log(`✅ Health monitoring started (interval: ${this.config.checkInterval}ms)`);
  }

  /**
   * Stop health monitoring
   */
  stop() {
    console.log('🛑 Stopping health monitoring...');
    
    this.isRunning = false;
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }
    
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    console.log('✅ Health monitoring stopped');
  }

  /**
   * Perform comprehensive health check
   */
  async performHealthCheck() {
    const startTime = Date.now();
    
    try {
      // System metrics
      await this.checkSystemHealth();
      
      // Application health
      await this.checkApplicationHealth();
      
      // Database health
      await this.checkDatabaseHealth();
      
      // SSL certificate health
      await this.checkSSLHealth();
      
      // Security monitoring
      await this.checkSecurityMetrics();
      
      const duration = Date.now() - startTime;
      this.logHealth('INFO', `Health check completed in ${duration}ms`);
      
    } catch (error) {
      this.logAlert('ERROR', 'Health check failed', error.message);
    }
  }

  /**
   * Check system resource health
   */
  async checkSystemHealth() {
    // Memory usage
    const totalMemory = os.totalmem();
    const freeMemory = os.freemem();
    const usedMemory = totalMemory - freeMemory;
    const memoryUsage = usedMemory / totalMemory;
    
    this.metrics.system.memory.push({
      timestamp: Date.now(),
      total: totalMemory,
      used: usedMemory,
      free: freeMemory,
      percentage: memoryUsage
    });

    if (memoryUsage > this.config.alertThresholds.memory) {
      this.logAlert('WARNING', 'High memory usage', 
        `Memory usage at ${(memoryUsage * 100).toFixed(2)}%`);
    }

    // CPU usage (simplified - in production use more sophisticated monitoring)
    const cpuUsage = await this.getCPUUsage();
    this.metrics.system.cpu.push({
      timestamp: Date.now(),
      usage: cpuUsage
    });

    if (cpuUsage > this.config.alertThresholds.cpu) {
      this.logAlert('WARNING', 'High CPU usage', 
        `CPU usage at ${(cpuUsage * 100).toFixed(2)}%`);
    }

    // Disk usage
    const diskUsage = await this.getDiskUsage();
    this.metrics.system.disk.push({
      timestamp: Date.now(),
      ...diskUsage
    });

    if (diskUsage.percentage > this.config.alertThresholds.disk) {
      this.logAlert('CRITICAL', 'High disk usage', 
        `Disk usage at ${(diskUsage.percentage * 100).toFixed(2)}%`);
    }

    // System uptime
    this.metrics.system.uptime = os.uptime();
  }

  /**
   * Check application health
   */
  async checkApplicationHealth() {
    try {
      const startTime = Date.now();
      
      // Test application endpoint
      const response = await this.testApplicationEndpoint();
      const responseTime = Date.now() - startTime;
      
      this.metrics.application.responseTime.push({
        timestamp: Date.now(),
        duration: responseTime,
        status: response.statusCode
      });

      if (responseTime > this.config.alertThresholds.responseTime) {
        this.logAlert('WARNING', 'Slow response time', 
          `Response time: ${responseTime}ms`);
      }

      // Update request metrics
      this.metrics.application.requests.total++;
      if (response.statusCode >= 200 && response.statusCode < 400) {
        this.metrics.application.requests.successful++;
      } else {
        this.metrics.application.requests.failed++;
      }

      // Calculate error rate
      const errorRate = this.metrics.application.requests.failed / 
                       this.metrics.application.requests.total;
      
      if (errorRate > this.config.alertThresholds.errorRate) {
        this.logAlert('CRITICAL', 'High error rate', 
          `Error rate: ${(errorRate * 100).toFixed(2)}%`);
      }

    } catch (error) {
      this.logAlert('CRITICAL', 'Application health check failed', error.message);
      this.metrics.application.requests.total++;
      this.metrics.application.requests.failed++;
    }
  }

  /**
   * Check database health
   */
  async checkDatabaseHealth() {
    if (!process.env.MONGODB_URI) {
      this.metrics.database.connectionStatus = 'not_configured';
      return;
    }

    try {
      const startTime = Date.now();
      
      const client = new MongoClient(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 5000,
        connectTimeoutMS: 5000
      });

      await client.connect();
      await client.db().admin().ping();
      
      const responseTime = Date.now() - startTime;
      
      this.metrics.database.responseTime.push({
        timestamp: Date.now(),
        duration: responseTime
      });

      // Get database stats
      const stats = await client.db().stats();
      this.metrics.database.activeConnections = stats.connections || 0;
      
      await client.close();
      
      this.metrics.database.connectionStatus = 'healthy';
      
      if (responseTime > 1000) {
        this.logAlert('WARNING', 'Slow database response', 
          `Database response time: ${responseTime}ms`);
      }

    } catch (error) {
      this.metrics.database.connectionStatus = 'failed';
      this.logAlert('CRITICAL', 'Database connection failed', error.message);
    }
  }

  /**
   * Check SSL certificate health
   */
  async checkSSLHealth() {
    const domain = process.env.COOKIE_DOMAIN;
    if (!domain) {
      return;
    }

    try {
      const certificateInfo = await this.getSSLCertificateInfo(domain);
      
      this.metrics.ssl = {
        certificateExpiry: certificateInfo.expiryDate,
        lastCheck: Date.now(),
        status: 'valid',
        daysUntilExpiry: Math.floor(
          (certificateInfo.expiryDate - Date.now()) / (1000 * 60 * 60 * 24)
        )
      };

      // Alert if certificate expires soon
      if (this.metrics.ssl.daysUntilExpiry < 30) {
        this.logAlert('WARNING', 'SSL certificate expiring soon', 
          `Certificate expires in ${this.metrics.ssl.daysUntilExpiry} days`);
      }

      if (this.metrics.ssl.daysUntilExpiry < 7) {
        this.logAlert('CRITICAL', 'SSL certificate expiring very soon', 
          `Certificate expires in ${this.metrics.ssl.daysUntilExpiry} days`);
      }

    } catch (error) {
      this.metrics.ssl.status = 'error';
      this.metrics.ssl.lastCheck = Date.now();
      this.logAlert('ERROR', 'SSL certificate check failed', error.message);
    }
  }

  /**
   * Check security metrics
   */
  async checkSecurityMetrics() {
    try {
      // Check failed login attempts (read from application logs)
      const failedLogins = await this.getFailedLoginCount();
      
      if (failedLogins > 10) {
        this.logAlert('WARNING', 'High failed login attempts', 
          `${failedLogins} failed login attempts in the last hour`);
      }

      // Check for suspicious IP activity
      const suspiciousIPs = await this.getSuspiciousIPActivity();
      
      if (suspiciousIPs.length > 0) {
        this.logAlert('WARNING', 'Suspicious IP activity detected', 
          `${suspiciousIPs.length} suspicious IPs detected`);
      }

    } catch (error) {
      console.warn('Security metrics check failed:', error.message);
    }
  }

  /**
   * Test application endpoint
   */
  async testApplicationEndpoint() {
    const domain = process.env.COOKIE_DOMAIN || 'localhost';
    const port = process.env.HTTPS === 'true' ? 443 : (process.env.PORT || 3000);
    const protocol = process.env.HTTPS === 'true' ? 'https' : 'http';
    
    return new Promise((resolve, reject) => {
      const module = protocol === 'https' ? require('https') : require('http');
      
      const options = {
        hostname: domain,
        port: port,
        path: '/health',
        method: 'GET',
        timeout: 5000,
        rejectUnauthorized: false // For self-signed certificates in testing
      };

      const req = module.request(options, (res) => {
        resolve({ statusCode: res.statusCode });
      });

      req.on('error', reject);
      req.on('timeout', () => reject(new Error('Request timeout')));
      req.setTimeout(5000);
      req.end();
    });
  }

  /**
   * Get CPU usage percentage
   */
  async getCPUUsage() {
    return new Promise((resolve) => {
      const cpus = os.cpus();
      
      let totalIdle = 0;
      let totalTick = 0;
      
      cpus.forEach(cpu => {
        for (type in cpu.times) {
          totalTick += cpu.times[type];
        }
        totalIdle += cpu.times.idle;
      });
      
      const idle = totalIdle / cpus.length;
      const total = totalTick / cpus.length;
      const usage = 1 - idle / total;
      
      resolve(Math.max(0, Math.min(1, usage)));
    });
  }

  /**
   * Get disk usage information
   */
  async getDiskUsage() {
    return new Promise((resolve, reject) => {
      const child = spawn('df', ['-h', '/'], { stdio: 'pipe' });
      let output = '';
      
      child.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      child.on('close', (code) => {
        if (code !== 0) {
          reject(new Error('Failed to get disk usage'));
          return;
        }
        
        const lines = output.trim().split('\n');
        if (lines.length < 2) {
          reject(new Error('Invalid df output'));
          return;
        }
        
        const parts = lines[1].split(/\s+/);
        const used = parseInt(parts[4].replace('%', '')) / 100;
        
        resolve({
          filesystem: parts[0],
          size: parts[1],
          used: parts[2],
          available: parts[3],
          percentage: used,
          mountpoint: parts[5]
        });
      });
    });
  }

  /**
   * Get SSL certificate information
   */
  async getSSLCertificateInfo(domain) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: domain,
        port: 443,
        method: 'GET',
        agent: false,
        rejectUnauthorized: false
      };

      const req = https.request(options, (res) => {
        const certificate = res.connection.getPeerCertificate();
        
        if (!certificate || !certificate.valid_to) {
          reject(new Error('Could not retrieve certificate information'));
          return;
        }
        
        resolve({
          expiryDate: new Date(certificate.valid_to).getTime(),
          issuer: certificate.issuer,
          subject: certificate.subject
        });
      });

      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Get failed login count from logs
   */
  async getFailedLoginCount() {
    // This is a simplified implementation
    // In production, you'd parse actual application logs
    try {
      const logFile = this.config.logPath;
      if (!fs.existsSync(logFile)) {
        return 0;
      }
      
      const oneHourAgo = Date.now() - (60 * 60 * 1000);
      // Implementation would parse logs for failed login attempts
      // For now, return 0 as placeholder
      return 0;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Get suspicious IP activity
   */
  async getSuspiciousIPActivity() {
    // Placeholder for suspicious IP detection
    // In production, this would analyze access logs for patterns
    return [];
  }

  /**
   * Create log directory
   */
  createLogDirectory() {
    const logDir = path.dirname(this.config.logPath);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  /**
   * Log health information
   */
  logHealth(level, message, details = null) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      details,
      metrics: this.getLatestMetrics()
    };

    const logLine = JSON.stringify(logEntry) + '\n';
    
    try {
      fs.appendFileSync(this.config.logPath, logLine);
    } catch (error) {
      console.error('Failed to write health log:', error);
    }
    
    console.log(`[${level}] ${message}${details ? ': ' + details : ''}`);
  }

  /**
   * Log alert
   */
  logAlert(level, title, message) {
    const alert = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      level,
      title,
      message,
      resolved: false
    };

    this.alerts.push(alert);
    this.logHealth(level, `ALERT: ${title}`, message);
    
    // In production, you'd send this to external alerting systems
    // (Slack, email, PagerDuty, etc.)
  }

  /**
   * Get latest metrics summary
   */
  getLatestMetrics() {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    
    return {
      system: {
        memory: this.metrics.system.memory.slice(-1)[0],
        cpu: this.metrics.system.cpu.slice(-1)[0],
        disk: this.metrics.system.disk.slice(-1)[0],
        uptime: this.metrics.system.uptime
      },
      application: {
        responseTime: this.getAverageResponseTime(oneMinuteAgo),
        errorRate: this.calculateErrorRate(),
        totalRequests: this.metrics.application.requests.total
      },
      database: {
        status: this.metrics.database.connectionStatus,
        responseTime: this.getAverageDatabaseResponseTime(oneMinuteAgo)
      },
      ssl: this.metrics.ssl
    };
  }

  /**
   * Get average response time
   */
  getAverageResponseTime(since) {
    const recentResponses = this.metrics.application.responseTime
      .filter(r => r.timestamp >= since);
    
    if (recentResponses.length === 0) return 0;
    
    const total = recentResponses.reduce((sum, r) => sum + r.duration, 0);
    return Math.round(total / recentResponses.length);
  }

  /**
   * Get average database response time
   */
  getAverageDatabaseResponseTime(since) {
    const recentResponses = this.metrics.database.responseTime
      .filter(r => r.timestamp >= since);
    
    if (recentResponses.length === 0) return 0;
    
    const total = recentResponses.reduce((sum, r) => sum + r.duration, 0);
    return Math.round(total / recentResponses.length);
  }

  /**
   * Calculate current error rate
   */
  calculateErrorRate() {
    const total = this.metrics.application.requests.total;
    const failed = this.metrics.application.requests.failed;
    
    if (total === 0) return 0;
    
    return failed / total;
  }

  /**
   * Clean up old metrics
   */
  cleanupOldMetrics() {
    const cutoffTime = Date.now() - (this.config.retentionHours * 60 * 60 * 1000);
    
    // Clean up system metrics
    this.metrics.system.memory = this.metrics.system.memory
      .filter(m => m.timestamp >= cutoffTime);
    this.metrics.system.cpu = this.metrics.system.cpu
      .filter(c => c.timestamp >= cutoffTime);
    this.metrics.system.disk = this.metrics.system.disk
      .filter(d => d.timestamp >= cutoffTime);
    
    // Clean up application metrics
    this.metrics.application.responseTime = this.metrics.application.responseTime
      .filter(r => r.timestamp >= cutoffTime);
    
    // Clean up database metrics
    this.metrics.database.responseTime = this.metrics.database.responseTime
      .filter(r => r.timestamp >= cutoffTime);
    
    // Clean up resolved alerts
    this.alerts = this.alerts.filter(a => 
      !a.resolved || (Date.now() - new Date(a.timestamp).getTime()) < cutoffTime);
  }

  /**
   * Get health dashboard data
   */
  getDashboardData() {
    return {
      status: this.isRunning ? 'running' : 'stopped',
      lastCheck: Date.now(),
      metrics: this.getLatestMetrics(),
      alerts: this.alerts.filter(a => !a.resolved).slice(-10),
      uptime: process.uptime()
    };
  }
}

module.exports = HealthMonitor;