/**
 * Production Intrusion Detection System
 * Real-time monitoring for security threats and suspicious activities
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');

class IntrusionDetectionSystem extends EventEmitter {
  constructor() {
    super();
    
    this.config = {
      enabled: process.env.ENABLE_SECURITY_MONITORING === 'true',
      logPaths: [
        '/var/log/nginx/access.log',
        '/var/log/nginx/error.log',
        '/var/log/auth.log',
        '/var/log/syslog',
        process.env.LOG_FILE_PATH || '/var/log/faf/app.log'
      ],
      alertThresholds: {
        failedLoginAttempts: parseInt(process.env.FAILED_LOGIN_THRESHOLD) || 5,
        timeWindow: parseInt(process.env.ATTACK_TIME_WINDOW) || 300000, // 5 minutes
        ipBlockDuration: parseInt(process.env.IP_BLOCK_DURATION) || 3600000, // 1 hour
        requestRate: parseInt(process.env.REQUEST_RATE_THRESHOLD) || 100,
        errorRate: parseFloat(process.env.ERROR_RATE_THRESHOLD) || 0.1
      },
      patterns: {
        sqlInjection: [
          /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,
          /'(\s)*(or|and)(\s)*'.*?'/i,
          /(\%27)(\%6F|\%4F)(\%72|\%52)/i
        ],
        xssAttempts: [
          /<script[\s\S]*?>[\s\S]*?<\/script>/i,
          /javascript:/i,
          /on\w+\s*=/i,
          /<iframe[\s\S]*?>/i
        ],
        pathTraversal: [
          /\.\.\//,
          /\.\.\\/,
          /%2e%2e%2f/i,
          /%2e%2e%5c/i
        ],
        bruteForce: [
          /Failed password/i,
          /Invalid user/i,
          /authentication failure/i,
          /refused connect/i
        ],
        scanning: [
          /nikto/i,
          /nmap/i,
          /sqlmap/i,
          /dirb/i,
          /gobuster/i,
          /burp/i
        ]
      }
    };

    this.threats = new Map(); // IP -> threat data
    this.blockedIPs = new Map(); // IP -> block expiry time
    this.statistics = {
      totalRequests: 0,
      blockedRequests: 0,
      threatInstances: 0,
      startTime: Date.now()
    };

    this.watchers = [];
    this.isRunning = false;
  }

  /**
   * Start intrusion detection system
   */
  async start() {
    if (!this.config.enabled) {
      console.log('⚠️ Intrusion detection system is disabled');
      return;
    }

    console.log('🛡️ Starting intrusion detection system...');
    
    this.isRunning = true;
    
    // Start log file monitoring
    await this.startLogMonitoring();
    
    // Start periodic cleanup
    this.startCleanupJob();
    
    // Start statistics reporting
    this.startStatisticsReporting();
    
    console.log('✅ Intrusion detection system started');
  }

  /**
   * Stop intrusion detection system
   */
  stop() {
    console.log('🛑 Stopping intrusion detection system...');
    
    this.isRunning = false;
    
    // Stop log watchers
    this.watchers.forEach(watcher => {
      watcher.close();
    });
    this.watchers = [];
    
    // Clear intervals
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    
    if (this.statsInterval) {
      clearInterval(this.statsInterval);
    }
    
    console.log('✅ Intrusion detection system stopped');
  }

  /**
   * Start monitoring log files
   */
  async startLogMonitoring() {
    console.log('📂 Starting log file monitoring...');
    
    for (const logPath of this.config.logPaths) {
      if (fs.existsSync(logPath)) {
        this.monitorLogFile(logPath);
        console.log(`👁️ Monitoring: ${logPath}`);
      } else {
        console.warn(`⚠️ Log file not found: ${logPath}`);
      }
    }
  }

  /**
   * Monitor a specific log file
   */
  monitorLogFile(logPath) {
    const watcher = fs.watchFile(logPath, { interval: 1000 }, (curr, prev) => {
      if (curr.mtime > prev.mtime) {
        this.readNewLogEntries(logPath, prev.size, curr.size);
      }
    });
    
    this.watchers.push(watcher);
  }

  /**
   * Read new log entries
   */
  readNewLogEntries(logPath, prevSize, currSize) {
    if (currSize <= prevSize) {
      return;
    }

    const stream = fs.createReadStream(logPath, {
      start: prevSize,
      end: currSize - 1
    });

    let buffer = '';
    
    stream.on('data', (chunk) => {
      buffer += chunk.toString();
      
      const lines = buffer.split('\\n');
      buffer = lines.pop(); // Keep incomplete line
      
      lines.forEach(line => {
        if (line.trim()) {
          this.analyzeLo/Entry(line, logPath);
        }
      });
    });

    stream.on('end', () => {
      if (buffer.trim()) {
        this.analyzeLogEntry(buffer, logPath);
      }
    });
  }

  /**
   * Analyze a log entry for threats
   */
  analyzeLogEntry(logLine, logPath) {
    try {
      this.statistics.totalRequests++;
      
      // Extract IP address from log line
      const ip = this.extractIPAddress(logLine);
      if (!ip || this.isPrivateIP(ip)) {
        return;
      }

      // Check if IP is already blocked
      if (this.isIPBlocked(ip)) {
        this.statistics.blockedRequests++;
        return;
      }

      // Analyze for various threat patterns
      const threats = this.detectThreats(logLine, ip);
      
      if (threats.length > 0) {
        this.handleThreatDetection(ip, threats, logLine);
      }

      // Analyze request patterns
      this.analyzeRequestPatterns(ip, logLine);
      
    } catch (error) {
      console.error('Error analyzing log entry:', error);
    }
  }

  /**
   * Extract IP address from log line
   */
  extractIPAddress(logLine) {
    // Try different log formats
    const patterns = [
      /^(\d+\.\d+\.\d+\.\d+)/, // Standard format
      /(\d+\.\d+\.\d+\.\d+).*?"/, // Nginx access log
      /from (\d+\.\d+\.\d+\.\d+)/, // Auth log
      /X-Forwarded-For: (\d+\.\d+\.\d+\.\d+)/ // Behind proxy
    ];

    for (const pattern of patterns) {
      const match = logLine.match(pattern);
      if (match) {
        return match[1];
      }
    }

    return null;
  }

  /**
   * Check if IP is private/internal
   */
  isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127
    );
  }

  /**
   * Detect threat patterns in log line
   */
  detectThreats(logLine, ip) {
    const threats = [];

    // Check for SQL injection
    if (this.config.patterns.sqlInjection.some(pattern => pattern.test(logLine))) {
      threats.push({ type: 'sql_injection', severity: 'high' });
    }

    // Check for XSS attempts
    if (this.config.patterns.xssAttempts.some(pattern => pattern.test(logLine))) {
      threats.push({ type: 'xss_attempt', severity: 'medium' });
    }

    // Check for path traversal
    if (this.config.patterns.pathTraversal.some(pattern => pattern.test(logLine))) {
      threats.push({ type: 'path_traversal', severity: 'high' });
    }

    // Check for brute force
    if (this.config.patterns.bruteForce.some(pattern => pattern.test(logLine))) {
      threats.push({ type: 'brute_force', severity: 'medium' });
    }

    // Check for scanning tools
    if (this.config.patterns.scanning.some(pattern => pattern.test(logLine))) {
      threats.push({ type: 'scanning', severity: 'medium' });
    }

    // Check for suspicious user agents
    if (this.isSuspiciousUserAgent(logLine)) {
      threats.push({ type: 'suspicious_agent', severity: 'low' });
    }

    // Check for large payloads (potential attacks)
    if (this.isLargePayload(logLine)) {
      threats.push({ type: 'large_payload', severity: 'medium' });
    }

    return threats;
  }

  /**
   * Check for suspicious user agents
   */
  isSuspiciousUserAgent(logLine) {
    const suspiciousAgents = [
      'sqlmap',
      'nikto',
      'nmap',
      'dirb',
      'gobuster',
      'burp',
      'python-requests',
      'curl',
      'wget'
    ];

    return suspiciousAgents.some(agent => 
      logLine.toLowerCase().includes(agent.toLowerCase())
    );
  }

  /**
   * Check for large payloads
   */
  isLargePayload(logLine) {
    // Look for very long request lines (potential buffer overflow attempts)
    return logLine.length > 2000;
  }

  /**
   * Handle threat detection
   */
  handleThreatDetection(ip, threats, logLine) {
    const now = Date.now();
    
    // Get or create threat data for this IP
    if (!this.threats.has(ip)) {
      this.threats.set(ip, {
        firstSeen: now,
        lastSeen: now,
        attempts: 0,
        threats: [],
        riskScore: 0
      });
    }

    const threatData = this.threats.get(ip);
    threatData.lastSeen = now;
    threatData.attempts++;
    threatData.threats.push(...threats);

    // Calculate risk score
    const riskScore = this.calculateRiskScore(threats, threatData);
    threatData.riskScore = Math.max(threatData.riskScore, riskScore);

    this.statistics.threatInstances++;

    // Emit threat event
    this.emit('threat', {
      ip,
      threats,
      riskScore,
      logLine,
      timestamp: now
    });

    // Auto-block high-risk IPs
    if (riskScore >= 80 || threatData.attempts >= this.config.alertThresholds.failedLoginAttempts) {
      this.blockIP(ip, 'High risk score or repeated attempts');
    }

    console.log(`🚨 Threat detected from ${ip}: ${threats.map(t => t.type).join(', ')} (Risk: ${riskScore})`);
  }

  /**
   * Calculate risk score based on threats
   */
  calculateRiskScore(threats, threatData) {
    let score = 0;

    const severityScores = {
      low: 10,
      medium: 30,
      high: 50
    };

    threats.forEach(threat => {
      score += severityScores[threat.severity] || 0;
    });

    // Increase score for repeated attempts
    score += Math.min(threatData.attempts * 5, 30);

    // Increase score for multiple threat types
    const uniqueTypes = new Set(threatData.threats.map(t => t.type));
    score += (uniqueTypes.size - 1) * 10;

    return Math.min(score, 100);
  }

  /**
   * Analyze request patterns for rate limiting
   */
  analyzeRequestPatterns(ip, logLine) {
    const now = Date.now();
    const timeWindow = this.config.alertThresholds.timeWindow;

    // Simple rate limiting check
    if (!this.threats.has(ip)) {
      this.threats.set(ip, {
        firstSeen: now,
        lastSeen: now,
        attempts: 0,
        threats: [],
        riskScore: 0,
        requests: []
      });
    }

    const data = this.threats.get(ip);
    data.requests = data.requests || [];
    data.requests.push(now);

    // Remove old requests outside time window
    data.requests = data.requests.filter(time => now - time <= timeWindow);

    // Check rate limit
    if (data.requests.length > this.config.alertThresholds.requestRate) {
      this.handleRateLimitViolation(ip, data.requests.length);
    }
  }

  /**
   * Handle rate limit violations
   */
  handleRateLimitViolation(ip, requestCount) {
    console.log(`⚠️ Rate limit violation from ${ip}: ${requestCount} requests`);
    
    this.emit('rateLimitViolation', {
      ip,
      requestCount,
      timestamp: Date.now()
    });

    // Block IP for rate limiting
    this.blockIP(ip, `Rate limit violation: ${requestCount} requests`);
  }

  /**
   * Block an IP address
   */
  blockIP(ip, reason) {
    const now = Date.now();
    const blockExpiry = now + this.config.alertThresholds.ipBlockDuration;
    
    this.blockedIPs.set(ip, {
      blockedAt: now,
      expiresAt: blockExpiry,
      reason
    });

    console.log(`🚫 Blocked IP ${ip}: ${reason}`);

    // Add iptables rule
    this.addIPTablesRule(ip);

    this.emit('ipBlocked', {
      ip,
      reason,
      blockedAt: now,
      expiresAt: blockExpiry
    });
  }

  /**
   * Check if IP is blocked
   */
  isIPBlocked(ip) {
    const blockData = this.blockedIPs.get(ip);
    
    if (!blockData) {
      return false;
    }

    if (Date.now() > blockData.expiresAt) {
      // Block expired, remove it
      this.unblockIP(ip);
      return false;
    }

    return true;
  }

  /**
   * Unblock an IP address
   */
  unblockIP(ip) {
    this.blockedIPs.delete(ip);
    this.removeIPTablesRule(ip);
    
    console.log(`✅ Unblocked IP ${ip}`);
    
    this.emit('ipUnblocked', { ip, timestamp: Date.now() });
  }

  /**
   * Add iptables rule to block IP
   */
  addIPTablesRule(ip) {
    if (process.platform !== 'linux') {
      return;
    }

    const command = `iptables -I INPUT -s ${ip} -j DROP`;
    
    spawn('bash', ['-c', command], { stdio: 'ignore' }).on('error', (error) => {
      console.error(`Failed to add iptables rule for ${ip}:`, error.message);
    });
  }

  /**
   * Remove iptables rule
   */
  removeIPTablesRule(ip) {
    if (process.platform !== 'linux') {
      return;
    }

    const command = `iptables -D INPUT -s ${ip} -j DROP`;
    
    spawn('bash', ['-c', command], { stdio: 'ignore' }).on('error', (error) => {
      // Ignore errors - rule might not exist
    });
  }

  /**
   * Start cleanup job
   */
  startCleanupJob() {
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredBlocks();
      this.cleanupOldThreats();
    }, 60000); // Every minute
  }

  /**
   * Clean up expired IP blocks
   */
  cleanupExpiredBlocks() {
    const now = Date.now();
    
    for (const [ip, blockData] of this.blockedIPs.entries()) {
      if (now > blockData.expiresAt) {
        this.unblockIP(ip);
      }
    }
  }

  /**
   * Clean up old threat data
   */
  cleanupOldThreats() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    for (const [ip, threatData] of this.threats.entries()) {
      if (now - threatData.lastSeen > maxAge) {
        this.threats.delete(ip);
      }
    }
  }

  /**
   * Start statistics reporting
   */
  startStatisticsReporting() {
    this.statsInterval = setInterval(() => {
      this.reportStatistics();
    }, 300000); // Every 5 minutes
  }

  /**
   * Report current statistics
   */
  reportStatistics() {
    const runtime = Date.now() - this.statistics.startTime;
    const hours = Math.round(runtime / (1000 * 60 * 60) * 10) / 10;
    
    console.log(`📊 IDS Statistics (${hours}h runtime):`);
    console.log(`  Requests analyzed: ${this.statistics.totalRequests}`);
    console.log(`  Requests blocked: ${this.statistics.blockedRequests}`);
    console.log(`  Threat instances: ${this.statistics.threatInstances}`);
    console.log(`  Active blocks: ${this.blockedIPs.size}`);
    console.log(`  Monitored IPs: ${this.threats.size}`);
  }

  /**
   * Get current status
   */
  getStatus() {
    return {
      enabled: this.config.enabled,
      running: this.isRunning,
      statistics: {
        ...this.statistics,
        runtime: Date.now() - this.statistics.startTime
      },
      blockedIPs: Array.from(this.blockedIPs.entries()).map(([ip, data]) => ({
        ip,
        ...data
      })),
      topThreats: this.getTopThreats(),
      recentAlerts: this.getRecentAlerts()
    };
  }

  /**
   * Get top threats by risk score
   */
  getTopThreats() {
    return Array.from(this.threats.entries())
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 10);
  }

  /**
   * Get recent alerts
   */
  getRecentAlerts() {
    // This would typically come from a persistent store
    // For now, return empty array
    return [];
  }

  /**
   * Manually block an IP
   */
  manualBlockIP(ip, reason = 'Manual block') {
    this.blockIP(ip, reason);
  }

  /**
   * Manually unblock an IP
   */
  manualUnblockIP(ip) {
    this.unblockIP(ip);
  }
}

module.exports = IntrusionDetectionSystem;