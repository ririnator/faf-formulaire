// Advanced Threat Detection System for FAF Application
const crypto = require('crypto');
const SecureLogger = require('../utils/secureLogger');

class AdvancedThreatDetectionSystem {
  constructor() {
    this.config = {
      // Threat detection thresholds
      ANOMALY_DETECTION_WINDOW: 5 * 60 * 1000, // 5 minutes
      BEHAVIORAL_ANALYSIS_WINDOW: 30 * 60 * 1000, // 30 minutes
      REQUEST_PATTERN_WINDOW: 60 * 1000, // 1 minute
      
      // Scoring thresholds
      THREAT_SCORE_THRESHOLD: 75, // 0-100 scale
      CRITICAL_THREAT_THRESHOLD: 90,
      SUSPICIOUS_ACTIVITY_THRESHOLD: 50,
      
      // Pattern analysis
      MAX_REQUESTS_PER_MINUTE: 60,
      MAX_FAILED_OPERATIONS_PER_WINDOW: 10,
      MIN_REQUEST_INTERVAL: 100, // milliseconds
      
      // Behavioral analysis
      ENABLE_ML_DETECTION: false, // Placeholder for ML-based detection
      ENABLE_REAL_TIME_ANALYSIS: true,
      ENABLE_PATTERN_CORRELATION: true,
      
      // Memory management limits
      MAX_THREAT_PROFILES: 5000, // Maximum number of threat profiles to maintain
      MAX_REQUEST_PATTERNS: 10000, // Maximum request patterns to track
      MAX_ANOMALY_PATTERNS: 1000, // Maximum anomaly patterns to store
      MAX_BEHAVIORAL_BASELINES: 2000, // Maximum behavioral baselines
      CLEANUP_INTERVAL: 5 * 60 * 1000 // Cleanup every 5 minutes
    };
    
    // Threat tracking stores with size limits
    this.threatProfiles = new Map(); // IP -> ThreatProfile
    this.requestPatterns = new Map(); // IP -> RequestPattern[]
    this.anomalyPatterns = new Map(); // Pattern -> AnomalyData
    this.globalStatistics = {
      totalRequests: 0,
      threatDetections: 0,
      blockedRequests: 0,
      criticalThreats: 0,
      lastReset: Date.now(),
      memoryCleanups: 0
    };
    
    // Pattern recognition databases
    this.knownAttackPatterns = this.initializeAttackPatterns();
    this.behavioralBaselines = new Map();
    this.correlationEngine = new ThreatCorrelationEngine();
    
    // Memory management
    this.lastCleanupTime = Date.now();
    this.memoryUsage = {
      threatProfiles: 0,
      requestPatterns: 0,
      anomalyPatterns: 0,
      behavioralBaselines: 0
    };
    
    this.initialize();
  }
  
  initialize() {
    // Start periodic analysis
    this.startPeriodicAnalysis();
    
    // Initialize baseline behavioral patterns
    this.initializeBehavioralBaselines();
    
    console.log('🔍 Advanced Threat Detection System initialized');
  }
  
  /**
   * Main threat analysis entry point for incoming requests
   */
  analyzeRequest(req, res, next) {
    try {
      const clientIP = this.getClientIP(req);
      const requestSignature = this.generateRequestSignature(req);
      
      // Update global statistics
      this.globalStatistics.totalRequests++;
      
      // Perform comprehensive threat analysis
      const threatAnalysis = this.performThreatAnalysis(req, clientIP, requestSignature);
      
      // Store analysis results in request object
      req.threatAnalysis = threatAnalysis;
      
      // Apply threat response based on score
      if (threatAnalysis.threatScore >= this.config.CRITICAL_THREAT_THRESHOLD) {
        return this.handleCriticalThreat(req, res, threatAnalysis);
      } else if (threatAnalysis.threatScore >= this.config.THREAT_SCORE_THRESHOLD) {
        return this.handleHighThreat(req, res, threatAnalysis);
      } else if (threatAnalysis.threatScore >= this.config.SUSPICIOUS_ACTIVITY_THRESHOLD) {
        this.handleSuspiciousActivity(req, threatAnalysis);
      }
      
      // Continue with normal processing
      next();
      
    } catch (error) {
      console.error('Threat analysis error:', error);
      // Don't block requests on analysis errors
      next();
    }
  }
  
  /**
   * Comprehensive threat analysis combining multiple detection methods
   */
  performThreatAnalysis(req, clientIP, requestSignature) {
    const analysis = {
      clientIP: this.maskIP(clientIP),
      timestamp: Date.now(),
      threatScore: 0,
      threatTypes: [],
      indicators: [],
      riskLevel: 'low',
      requestSignature,
      confidence: 0
    };
    
    // 1. Pattern-based detection
    const patternScore = this.analyzeRequestPatterns(req, clientIP);
    analysis.threatScore += patternScore.score;
    analysis.indicators.push(...patternScore.indicators);
    
    // 2. Behavioral anomaly detection
    const behavioralScore = this.analyzeBehavioralAnomalies(req, clientIP);
    analysis.threatScore += behavioralScore.score;
    analysis.indicators.push(...behavioralScore.indicators);
    
    // 3. Content analysis for malicious payloads
    const contentScore = this.analyzeRequestContent(req);
    analysis.threatScore += contentScore.score;
    analysis.indicators.push(...contentScore.indicators);
    
    // 4. Rate limiting and frequency analysis
    const frequencyScore = this.analyzeRequestFrequency(req, clientIP);
    analysis.threatScore += frequencyScore.score;
    analysis.indicators.push(...frequencyScore.indicators);
    
    // 5. Known threat intelligence
    const intelligenceScore = this.analyzeAgainstThreatIntelligence(req, clientIP);
    analysis.threatScore += intelligenceScore.score;
    analysis.indicators.push(...intelligenceScore.indicators);
    
    // 6. User agent and header analysis
    const headerScore = this.analyzeRequestHeaders(req);
    analysis.threatScore += headerScore.score;
    analysis.indicators.push(...headerScore.indicators);
    
    // Calculate final risk level and confidence
    analysis.riskLevel = this.calculateRiskLevel(analysis.threatScore);
    analysis.confidence = this.calculateConfidence(analysis.indicators);
    analysis.threatTypes = this.identifyThreatTypes(analysis.indicators);
    
    // Update threat profile for this IP
    this.updateThreatProfile(clientIP, analysis);
    
    // Perform memory cleanup if needed
    this.performMemoryCleanupIfNeeded();
    
    return analysis;
  }
  
  /**
   * Perform memory cleanup if limits are exceeded or time interval has passed
   */
  performMemoryCleanupIfNeeded() {
    const now = Date.now();
    const shouldCleanup = 
      now - this.lastCleanupTime > this.config.CLEANUP_INTERVAL ||
      this.threatProfiles.size > this.config.MAX_THREAT_PROFILES ||
      this.requestPatterns.size > this.config.MAX_REQUEST_PATTERNS ||
      this.anomalyPatterns.size > this.config.MAX_ANOMALY_PATTERNS ||
      this.behavioralBaselines.size > this.config.MAX_BEHAVIORAL_BASELINES;
    
    if (shouldCleanup) {
      this.performMemoryCleanup();
    }
  }
  
  /**
   * Clean up old entries to prevent memory exhaustion
   */
  performMemoryCleanup() {
    const now = Date.now();
    let cleanedEntries = 0;
    
    // Clean threat profiles (keep most recent)
    if (this.threatProfiles.size > this.config.MAX_THREAT_PROFILES * 0.8) {
      const sortedProfiles = Array.from(this.threatProfiles.entries())
        .sort((a, b) => (b[1].lastUpdate || 0) - (a[1].lastUpdate || 0));
      
      const toRemove = sortedProfiles.slice(Math.floor(this.config.MAX_THREAT_PROFILES * 0.6));
      toRemove.forEach(([key]) => {
        this.threatProfiles.delete(key);
        cleanedEntries++;
      });
    }
    
    // Clean request patterns (remove old patterns)
    if (this.requestPatterns.size > this.config.MAX_REQUEST_PATTERNS * 0.8) {
      const oldestAllowed = now - this.config.BEHAVIORAL_ANALYSIS_WINDOW;
      for (const [key, patterns] of this.requestPatterns.entries()) {
        // Filter out old patterns
        const recentPatterns = patterns.filter(p => p.timestamp > oldestAllowed);
        if (recentPatterns.length === 0) {
          this.requestPatterns.delete(key);
          cleanedEntries++;
        } else if (recentPatterns.length < patterns.length) {
          this.requestPatterns.set(key, recentPatterns);
        }
      }
    }
    
    // Clean anomaly patterns (LRU style)
    if (this.anomalyPatterns.size > this.config.MAX_ANOMALY_PATTERNS * 0.8) {
      const sortedAnomalies = Array.from(this.anomalyPatterns.entries())
        .sort((a, b) => (b[1].lastSeen || 0) - (a[1].lastSeen || 0));
      
      const toRemove = sortedAnomalies.slice(Math.floor(this.config.MAX_ANOMALY_PATTERNS * 0.6));
      toRemove.forEach(([key]) => {
        this.anomalyPatterns.delete(key);
        cleanedEntries++;
      });
    }
    
    // Clean behavioral baselines (remove inactive)
    if (this.behavioralBaselines.size > this.config.MAX_BEHAVIORAL_BASELINES * 0.8) {
      const inactiveThreshold = now - 24 * 60 * 60 * 1000; // 24 hours
      for (const [key, baseline] of this.behavioralBaselines.entries()) {
        if (baseline.lastActivity < inactiveThreshold) {
          this.behavioralBaselines.delete(key);
          cleanedEntries++;
        }
      }
    }
    
    // Update statistics and log
    this.lastCleanupTime = now;
    this.globalStatistics.memoryCleanups++;
    this.memoryUsage = {
      threatProfiles: this.threatProfiles.size,
      requestPatterns: this.requestPatterns.size,
      anomalyPatterns: this.anomalyPatterns.size,
      behavioralBaselines: this.behavioralBaselines.size
    };
    
    if (cleanedEntries > 0) {
      console.info('Advanced threat detection memory cleanup completed', {
        entriesCleaned: cleanedEntries,
        memoryUsage: this.memoryUsage,
        totalCleanups: this.globalStatistics.memoryCleanups
      });
    }
  }
  
  /**
   * Analyze request patterns for suspicious behavior
   */
  analyzeRequestPatterns(req, clientIP) {
    const score = { score: 0, indicators: [] };
    const now = Date.now();
    
    // Get or create request pattern history
    const patterns = this.requestPatterns.get(clientIP) || [];
    
    // Add current request to pattern
    const requestData = {
      timestamp: now,
      path: req.path,
      method: req.method,
      userAgent: req.get('User-Agent') || '',
      contentLength: req.get('Content-Length') || 0,
      referer: req.get('Referer') || ''
    };
    
    patterns.push(requestData);
    
    // Keep only recent patterns
    const recentPatterns = patterns.filter(p => now - p.timestamp < this.config.REQUEST_PATTERN_WINDOW);
    this.requestPatterns.set(clientIP, recentPatterns);
    
    // Analyze patterns for threats
    if (recentPatterns.length > this.config.MAX_REQUESTS_PER_MINUTE) {
      score.score += 30;
      score.indicators.push('high_frequency_requests');
    }
    
    // Check for rapid-fire requests
    if (recentPatterns.length >= 2) {
      const lastTwo = recentPatterns.slice(-2);
      const interval = lastTwo[1].timestamp - lastTwo[0].timestamp;
      if (interval < this.config.MIN_REQUEST_INTERVAL) {
        score.score += 25;
        score.indicators.push('rapid_fire_requests');
      }
    }
    
    // Check for path traversal patterns
    const suspiciousPaths = recentPatterns.filter(p => 
      p.path.includes('..') || 
      p.path.includes('%2e%2e') ||
      p.path.includes('//') ||
      p.path.match(/\/\.\.\/|\\\.\.\\/)
    );
    
    if (suspiciousPaths.length > 0) {
      score.score += 40;
      score.indicators.push('path_traversal_attempt');
    }
    
    // Check for scanning behavior
    const uniquePaths = new Set(recentPatterns.map(p => p.path));
    if (uniquePaths.size > 20 && recentPatterns.length > 30) {
      score.score += 35;
      score.indicators.push('directory_scanning');
    }
    
    return score;
  }
  
  /**
   * Analyze behavioral anomalies using statistical methods
   */
  analyzeBehavioralAnomalies(req, clientIP) {
    const score = { score: 0, indicators: [] };
    const now = Date.now();
    
    // Get behavioral baseline for this IP
    const baseline = this.behavioralBaselines.get(clientIP) || this.createBehavioralBaseline();
    
    // Current request characteristics
    const currentBehavior = {
      requestTime: now,
      pathLength: req.path.length,
      userAgentLength: (req.get('User-Agent') || '').length,
      headerCount: Object.keys(req.headers).length,
      method: req.method,
      hasReferer: !!req.get('Referer'),
      hasAccept: !!req.get('Accept'),
      contentLength: parseInt(req.get('Content-Length') || '0')
    };
    
    // Statistical anomaly detection
    const pathLengthAnomaly = this.detectStatisticalAnomaly(currentBehavior.pathLength, baseline.avgPathLength, baseline.pathLengthStdev);
    if (pathLengthAnomaly > 2) { // 2 standard deviations
      score.score += 20;
      score.indicators.push('abnormal_path_length');
    }
    
    const headerCountAnomaly = this.detectStatisticalAnomaly(currentBehavior.headerCount, baseline.avgHeaderCount, baseline.headerCountStdev);
    if (headerCountAnomaly > 2) {
      score.score += 15;
      score.indicators.push('abnormal_header_count');
    }
    
    // Missing common headers
    if (!currentBehavior.hasAccept || !currentBehavior.hasReferer) {
      score.score += 10;
      score.indicators.push('missing_common_headers');
    }
    
    // Unusual content length for method
    if (req.method === 'GET' && currentBehavior.contentLength > 0) {
      score.score += 20;
      score.indicators.push('unusual_content_length');
    }
    
    // Update baseline with current behavior
    this.updateBehavioralBaseline(clientIP, currentBehavior);
    
    return score;
  }
  
  /**
   * Analyze request content for malicious payloads
   */
  analyzeRequestContent(req) {
    const score = { score: 0, indicators: [] };
    
    // Analyze URL for malicious content
    const urlThreats = this.scanForMaliciousContent(req.originalUrl || req.url);
    score.score += urlThreats.score;
    score.indicators.push(...urlThreats.indicators);
    
    // Analyze headers for malicious content
    const headerString = JSON.stringify(req.headers);
    const headerThreats = this.scanForMaliciousContent(headerString);
    score.score += headerThreats.score * 0.5; // Lower weight for headers
    score.indicators.push(...headerThreats.indicators.map(i => `header_${i}`));
    
    // Analyze body content if available
    if (req.body) {
      const bodyString = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      const bodyThreats = this.scanForMaliciousContent(bodyString);
      score.score += bodyThreats.score;
      score.indicators.push(...bodyThreats.indicators.map(i => `body_${i}`));
    }
    
    return score;
  }
  
  /**
   * Analyze request frequency and rate limiting
   */
  analyzeRequestFrequency(req, clientIP) {
    const score = { score: 0, indicators: [] };
    const now = Date.now();
    
    // Get threat profile for frequency analysis
    let profile = this.threatProfiles.get(clientIP);
    if (!profile) {
      profile = this.createThreatProfile(clientIP);
      this.threatProfiles.set(clientIP, profile);
    }
    
    // Update request history
    profile.requestHistory.push({
      timestamp: now,
      path: req.path,
      method: req.method
    });
    
    // Clean old history
    const cutoff = now - this.config.ANOMALY_DETECTION_WINDOW;
    profile.requestHistory = profile.requestHistory.filter(r => r.timestamp > cutoff);
    
    // Frequency analysis
    const requestCount = profile.requestHistory.length;
    const timeSpan = Math.max(now - profile.firstSeen, this.config.ANOMALY_DETECTION_WINDOW);
    const requestsPerMinute = (requestCount / timeSpan) * 60000;
    
    if (requestsPerMinute > this.config.MAX_REQUESTS_PER_MINUTE) {
      const excessRatio = requestsPerMinute / this.config.MAX_REQUESTS_PER_MINUTE;
      score.score += Math.min(excessRatio * 20, 40);
      score.indicators.push('excessive_request_frequency');
    }
    
    // Burst detection
    const recentRequests = profile.requestHistory.filter(r => now - r.timestamp < 10000); // Last 10 seconds
    if (recentRequests.length > 10) {
      score.score += 25;
      score.indicators.push('request_burst');
    }
    
    return score;
  }
  
  /**
   * Check against known threat intelligence
   */
  analyzeAgainstThreatIntelligence(req, clientIP) {
    const score = { score: 0, indicators: [] };
    
    // Check IP reputation (placeholder - would integrate with real threat intel)
    if (this.isKnownMaliciousIP(clientIP)) {
      score.score += 50;
      score.indicators.push('known_malicious_ip');
    }
    
    // Check for known attack patterns in URL
    for (const [patternName, pattern] of Object.entries(this.knownAttackPatterns)) {
      if (pattern.test(req.originalUrl || req.url)) {
        score.score += 30;
        score.indicators.push(`known_attack_pattern_${patternName}`);
      }
    }
    
    // Check User-Agent against known bot signatures
    const userAgent = req.get('User-Agent') || '';
    const knownBotPatterns = [
      /sqlmap/i,
      /nikto/i,
      /nessus/i,
      /openvas/i,
      /w3af/i,
      /burpsuite/i,
      /zaproxy/i,
      /nuclei/i
    ];
    
    for (const pattern of knownBotPatterns) {
      if (pattern.test(userAgent)) {
        score.score += 40;
        score.indicators.push('security_scanner_detected');
        break;
      }
    }
    
    return score;
  }
  
  /**
   * Analyze request headers for suspicious patterns
   */
  analyzeRequestHeaders(req) {
    const score = { score: 0, indicators: [] };
    const headers = req.headers;
    
    // Check for missing standard headers
    const expectedHeaders = ['accept', 'user-agent', 'accept-language'];
    const missingHeaders = expectedHeaders.filter(header => !headers[header]);
    
    if (missingHeaders.length > 1) {
      score.score += 15;
      score.indicators.push('missing_standard_headers');
    }
    
    // Check for suspicious header values
    const userAgent = headers['user-agent'] || '';
    if (userAgent.length < 10) {
      score.score += 20;
      score.indicators.push('suspicious_user_agent');
    }
    
    // Check for automation indicators
    if (headers['x-automated-request'] || headers['x-requested-with'] === 'curl') {
      score.score += 25;
      score.indicators.push('automation_detected');
    }
    
    // Check for header injection attempts
    for (const [key, value] of Object.entries(headers)) {
      if (typeof value === 'string' && (value.includes('\n') || value.includes('\r'))) {
        score.score += 35;
        score.indicators.push('header_injection_attempt');
        break;
      }
    }
    
    return score;
  }
  
  // Helper methods
  scanForMaliciousContent(content) {
    const score = { score: 0, indicators: [] };
    
    if (!content || typeof content !== 'string') return score;
    
    // XSS patterns
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/i,
      /vbscript:/i,
      /on\w+\s*=\s*["'][^"']*["']/gi,
      /<iframe[^>]*>/gi
    ];
    
    for (const pattern of xssPatterns) {
      if (pattern.test(content)) {
        score.score += 25;
        score.indicators.push('xss_attempt');
        break;
      }
    }
    
    // SQL injection patterns
    const sqlPatterns = [
      /(\b(union|select|insert|update|delete|drop)\b.*\b(from|where|into|values)\b)/gi,
      /('|\").*(\b(or|and)\b.*\d+\s*=\s*\d+)/gi,
      /(--|\/\*|\*\/)/g
    ];
    
    for (const pattern of sqlPatterns) {
      if (pattern.test(content)) {
        score.score += 30;
        score.indicators.push('sql_injection_attempt');
        break;
      }
    }
    
    // Command injection patterns
    const cmdPatterns = [
      /(\$\(|`|&&|\|\||;)/g,
      /\b(cat|ls|pwd|whoami|id|uname)\b/gi
    ];
    
    for (const pattern of cmdPatterns) {
      if (pattern.test(content)) {
        score.score += 35;
        score.indicators.push('command_injection_attempt');
        break;
      }
    }
    
    return score;
  }
  
  initializeAttackPatterns() {
    return {
      sql_injection: /(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b)/gi,
      xss: /<script|javascript:|vbscript:|onload|onerror|onclick/gi,
      path_traversal: /(\.\.\/)|(\.\.\\)|(%2e%2e%2f)|(%2e%2e\\)/gi,
      command_injection: /(\||&|;|\$\(|`)/g,
      ldap_injection: /(\*|\(|\)|\||&)/g
    };
  }
  
  createThreatProfile(clientIP) {
    return {
      ip: clientIP,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      requestCount: 0,
      threatScore: 0,
      threatHistory: [],
      requestHistory: [],
      blockedCount: 0,
      riskLevel: 'low'
    };
  }
  
  createBehavioralBaseline() {
    return {
      avgPathLength: 15,
      pathLengthStdev: 5,
      avgHeaderCount: 8,
      headerCountStdev: 2,
      commonMethods: ['GET', 'POST'],
      avgUserAgentLength: 100
    };
  }
  
  updateThreatProfile(clientIP, analysis) {
    let profile = this.threatProfiles.get(clientIP) || this.createThreatProfile(clientIP);
    
    profile.lastSeen = Date.now();
    profile.requestCount++;
    profile.threatScore = Math.max(profile.threatScore, analysis.threatScore);
    profile.riskLevel = analysis.riskLevel;
    
    // Store threat history
    if (analysis.threatScore > 0) {
      profile.threatHistory.push({
        timestamp: Date.now(),
        score: analysis.threatScore,
        indicators: analysis.indicators,
        riskLevel: analysis.riskLevel
      });
      
      // Keep only recent history
      const cutoff = Date.now() - (24 * 60 * 60 * 1000); // 24 hours
      profile.threatHistory = profile.threatHistory.filter(t => t.timestamp > cutoff);
    }
    
    this.threatProfiles.set(clientIP, profile);
  }
  
  calculateRiskLevel(threatScore) {
    if (threatScore >= this.config.CRITICAL_THREAT_THRESHOLD) return 'critical';
    if (threatScore >= this.config.THREAT_SCORE_THRESHOLD) return 'high';
    if (threatScore >= this.config.SUSPICIOUS_ACTIVITY_THRESHOLD) return 'medium';
    return 'low';
  }
  
  calculateConfidence(indicators) {
    // Simple confidence calculation based on number and type of indicators
    if (indicators.length === 0) return 0;
    if (indicators.length >= 5) return 95;
    if (indicators.length >= 3) return 80;
    if (indicators.length >= 2) return 65;
    return 45;
  }
  
  identifyThreatTypes(indicators) {
    const types = new Set();
    
    indicators.forEach(indicator => {
      if (indicator.includes('xss') || indicator.includes('script')) types.add('XSS');
      if (indicator.includes('sql') || indicator.includes('injection')) types.add('SQLInjection');
      if (indicator.includes('path') || indicator.includes('traversal')) types.add('PathTraversal');
      if (indicator.includes('frequency') || indicator.includes('burst')) types.add('DoS');
      if (indicator.includes('scanner') || indicator.includes('bot')) types.add('Scanning');
      if (indicator.includes('malicious') || indicator.includes('known')) types.add('KnownThreat');
    });
    
    return Array.from(types);
  }
  
  // Threat response handlers
  handleCriticalThreat(req, res, analysis) {
    this.globalStatistics.criticalThreats++;
    this.globalStatistics.blockedRequests++;
    
    // Log critical threat
    console.error('🚨 CRITICAL THREAT DETECTED:', {
      ip: analysis.clientIP,
      threatScore: analysis.threatScore,
      threatTypes: analysis.threatTypes,
      indicators: analysis.indicators,
      path: req.path,
      userAgent: req.get('User-Agent')?.substring(0, 100)
    });
    
    // Block request immediately
    res.status(403).json({
      error: 'Access denied - security violation detected',
      requestId: req.headers['x-request-id']
    });
  }
  
  handleHighThreat(req, res, analysis) {
    this.globalStatistics.blockedRequests++;
    
    // Log high threat
    console.warn('⚠️ HIGH THREAT DETECTED:', {
      ip: analysis.clientIP,
      threatScore: analysis.threatScore,
      indicators: analysis.indicators,
      path: req.path
    });
    
    // Apply additional security measures
    res.setHeader('X-Security-Level', 'high');
    res.status(429).json({
      error: 'Request blocked due to suspicious activity',
      retryAfter: 300
    });
  }
  
  handleSuspiciousActivity(req, analysis) {
    // Log suspicious activity but allow request to continue
    console.log('🔍 SUSPICIOUS ACTIVITY:', {
      ip: analysis.clientIP,
      threatScore: analysis.threatScore,
      indicators: analysis.indicators,
      path: req.path
    });
    
    // Add security headers
    req.headers['x-security-monitored'] = 'true';
  }
  
  // Utility methods
  getClientIP(req) {
    return req.ip || 
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           req.connection?.remoteAddress ||
           '0.0.0.0';
  }
  
  maskIP(ip) {
    if (!ip || ip === '0.0.0.0') return 'unknown';
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.xxx.xxx`;
    }
    return ip.substring(0, 8) + '...';
  }
  
  generateRequestSignature(req) {
    const components = [
      req.method,
      req.path,
      req.get('User-Agent') || '',
      req.get('Accept') || '',
      JSON.stringify(req.query)
    ].join('|');
    
    return crypto.createHash('md5').update(components).digest('hex');
  }
  
  detectStatisticalAnomaly(value, mean, stddev) {
    if (stddev === 0) return 0;
    return Math.abs(value - mean) / stddev;
  }
  
  isKnownMaliciousIP(ip) {
    // Placeholder - would integrate with real threat intelligence feeds
    const knownMaliciousIPs = ['127.0.0.2', '192.168.1.666']; // Example IPs
    return knownMaliciousIPs.includes(ip);
  }
  
  updateBehavioralBaseline(clientIP, behavior) {
    // Simple exponential moving average update
    let baseline = this.behavioralBaselines.get(clientIP) || this.createBehavioralBaseline();
    
    const alpha = 0.1; // Learning rate
    baseline.avgPathLength = (1 - alpha) * baseline.avgPathLength + alpha * behavior.pathLength;
    baseline.avgHeaderCount = (1 - alpha) * baseline.avgHeaderCount + alpha * behavior.headerCount;
    
    this.behavioralBaselines.set(clientIP, baseline);
  }
  
  initializeBehavioralBaselines() {
    // Initialize with common baseline values
    // In production, these would be learned from legitimate traffic
  }
  
  startPeriodicAnalysis() {
    // Run correlation analysis every minute
    setInterval(() => {
      this.correlationEngine.performCorrelationAnalysis(this.threatProfiles);
      this.cleanupExpiredData();
    }, 60 * 1000);
    
    // Generate hourly security reports
    setInterval(() => {
      this.generateSecurityReport();
    }, 60 * 60 * 1000);
  }
  
  cleanupExpiredData() {
    const now = Date.now();
    const cutoff = now - (24 * 60 * 60 * 1000); // 24 hours
    
    // Clean up expired threat profiles
    for (const [ip, profile] of this.threatProfiles.entries()) {
      if (profile.lastSeen < cutoff) {
        this.threatProfiles.delete(ip);
      }
    }
    
    // Clean up expired patterns
    for (const [ip, patterns] of this.requestPatterns.entries()) {
      const recentPatterns = patterns.filter(p => p.timestamp > cutoff);
      if (recentPatterns.length === 0) {
        this.requestPatterns.delete(ip);
      } else {
        this.requestPatterns.set(ip, recentPatterns);
      }
    }
  }
  
  generateSecurityReport() {
    const report = {
      timestamp: new Date().toISOString(),
      statistics: { ...this.globalStatistics },
      activeThreatProfiles: this.threatProfiles.size,
      topThreats: this.getTopThreats(),
      threatDistribution: this.getThreatDistribution()
    };
    
    console.log('📊 HOURLY SECURITY REPORT:', report);
    
    // Reset periodic statistics
    this.globalStatistics.threatDetections = 0;
    this.globalStatistics.blockedRequests = 0;
    this.globalStatistics.lastReset = Date.now();
    
    return report;
  }
  
  getTopThreats() {
    return Array.from(this.threatProfiles.values())
      .sort((a, b) => b.threatScore - a.threatScore)
      .slice(0, 10)
      .map(profile => ({
        ip: this.maskIP(profile.ip),
        threatScore: profile.threatScore,
        riskLevel: profile.riskLevel,
        requestCount: profile.requestCount
      }));
  }
  
  getThreatDistribution() {
    const distribution = { low: 0, medium: 0, high: 0, critical: 0 };
    
    for (const profile of this.threatProfiles.values()) {
      distribution[profile.riskLevel]++;
    }
    
    return distribution;
  }
  
  // Public API methods
  getMiddleware() {
    return this.analyzeRequest.bind(this);
  }
  
  getThreatStatistics() {
    return {
      ...this.globalStatistics,
      activeThreatProfiles: this.threatProfiles.size,
      threatDistribution: this.getThreatDistribution()
    };
  }
  
  getThreatProfileSummary(ip) {
    const profile = this.threatProfiles.get(ip);
    if (!profile) return null;
    
    return {
      ip: this.maskIP(profile.ip),
      riskLevel: profile.riskLevel,
      threatScore: profile.threatScore,
      requestCount: profile.requestCount,
      firstSeen: profile.firstSeen,
      lastSeen: profile.lastSeen,
      recentThreats: profile.threatHistory.slice(-5)
    };
  }
}

/**
 * Threat Correlation Engine for advanced pattern detection
 */
class ThreatCorrelationEngine {
  constructor() {
    this.correlationRules = this.initializeCorrelationRules();
  }
  
  performCorrelationAnalysis(threatProfiles) {
    // Analyze patterns across multiple IPs and time windows
    const correlationResults = [];
    
    // Example: Detect coordinated attacks from multiple IPs
    const suspiciousIPs = Array.from(threatProfiles.values())
      .filter(profile => profile.threatScore > 30)
      .map(profile => profile.ip);
    
    if (suspiciousIPs.length > 5) {
      correlationResults.push({
        type: 'coordinated_attack',
        confidence: 80,
        involvedIPs: suspiciousIPs.length,
        timeWindow: Date.now()
      });
    }
    
    return correlationResults;
  }
  
  initializeCorrelationRules() {
    return [
      {
        name: 'distributed_scanning',
        pattern: 'multiple_ips_similar_patterns',
        threshold: 5,
        timeWindow: 300000 // 5 minutes
      },
      {
        name: 'credential_stuffing',
        pattern: 'multiple_failed_logins_different_ips',
        threshold: 10,
        timeWindow: 600000 // 10 minutes
      }
    ];
  }
}

module.exports = AdvancedThreatDetectionSystem;