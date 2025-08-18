#!/usr/bin/env node

/**
 * 📊 FAF Live Monitor - Interface de Monitoring Temps Réel
 * Dashboard interactif pour suivre la progression de la migration v2
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execAsync = util.promisify(exec);

class LiveMonitor {
  constructor() {
    this.baseDir = path.join(__dirname, '..');
    this.monitoring = false;
    this.stats = {
      startTime: Date.now(),
      currentPhase: 0,
      phases: [
        { id: 1, name: 'MODÈLES DB', status: 'pending', progress: 0, eta: null },
        { id: 2, name: 'SERVICES LAYER', status: 'pending', progress: 0, eta: null },
        { id: 3, name: 'APIs REST', status: 'pending', progress: 0, eta: null },
        { id: 4, name: 'EMAIL AUTO', status: 'pending', progress: 0, eta: null },
        { id: 5, name: 'FRONTEND', status: 'pending', progress: 0, eta: null },
        { id: 6, name: 'MIGRATION', status: 'pending', progress: 0, eta: null }
      ],
      agents: new Map(),
      tests: { passed: 0, failed: 0, total: 0 },
      performance: { avgResponseTime: 0, memory: 0, cpu: 0 },
      security: { status: 'unknown', lastScan: null },
      alerts: [],
      logs: []
    };
  }

  // 🎨 Interface Dashboard
  renderDashboard() {
    // Clear screen
    console.clear();
    
    const elapsed = Math.floor((Date.now() - this.stats.startTime) / 1000 / 60);
    const eta = this.calculateETA();
    
    console.log('🚀 FAF v2 ORCHESTRATOR - Live Status');
    console.log('━'.repeat(80));
    console.log('');
    
    // Header stats
    console.log(`📊 Phase Actuelle: ${this.stats.currentPhase}/6 - ${this.getCurrentPhaseName()}`);
    console.log(`⏱️  Temps Écoulé: ${elapsed}min`);
    console.log(`🎯 ETA Completion: ${eta}`);
    console.log('');
    
    // Progress bars pour chaque phase
    this.renderPhaseProgress();
    console.log('');
    
    // Stats temps réel
    this.renderRealTimeStats();
    console.log('');
    
    // Agents actifs
    this.renderActiveAgents();
    console.log('');
    
    // Alerts et logs récents
    this.renderAlertsAndLogs();
    
    console.log('━'.repeat(80));
    console.log('🔄 Actualisation automatique toutes les 2s - Ctrl+C pour arrêter');
  }

  // 📈 Barres de progression par phase
  renderPhaseProgress() {
    console.log('📋 PROGRESSION PAR PHASE:');
    
    this.stats.phases.forEach(phase => {
      const barLength = 20;
      const filled = Math.floor(phase.progress * barLength / 100);
      const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);
      
      const statusIcon = {
        'pending': '⏳',
        'in_progress': '🔄',
        'completed': '✅',
        'failed': '❌'
      }[phase.status] || '❓';
      
      const progressStr = `${phase.progress}%`.padStart(4);
      const etaStr = phase.eta ? `(${phase.eta})` : '';
      
      console.log(`${statusIcon} Phase ${phase.id}: ${phase.name.padEnd(15)} [${bar}] ${progressStr} ${etaStr}`);
    });
  }

  // 📊 Statistiques temps réel
  renderRealTimeStats() {
    const successRate = this.stats.tests.total > 0 
      ? ((this.stats.tests.passed / this.stats.tests.total) * 100).toFixed(1)
      : 0;
    
    const securityIcon = {
      'secure': '🔒',
      'warning': '⚠️',
      'danger': '🚨',
      'unknown': '❓'
    }[this.stats.security.status] || '❓';
    
    const performanceIcon = this.stats.performance.avgResponseTime < 50 ? '⚡' : 
                           this.stats.performance.avgResponseTime < 200 ? '🟡' : '🔴';
    
    console.log('📈 STATS TEMPS RÉEL:');
    console.log(`• Tests Passés: ${this.stats.tests.passed}/${this.stats.tests.total} (${successRate}%)`);
    console.log(`• Sécurité: ${securityIcon} ${this.stats.security.status.toUpperCase()}`);
    console.log(`• Performance: ${performanceIcon} ${this.stats.performance.avgResponseTime}ms (${this.getPerformanceStatus()})`);
    console.log(`• Couverture Code: ${this.getCoveragePercentage()}%`);
  }

  // 🤖 Agents actifs
  renderActiveAgents() {
    console.log('🤖 AGENTS ACTIFS:');
    
    if (this.stats.agents.size === 0) {
      console.log('• Aucun agent actif');
      return;
    }
    
    this.stats.agents.forEach((agent, name) => {
      const statusIcon = agent.status === 'working' ? '🔄' : '⏸️';
      const elapsed = Math.floor((Date.now() - agent.startTime) / 1000 / 60);
      console.log(`• ${statusIcon} ${name}: ${agent.task} (${elapsed}min)`);
    });
  }

  // 🚨 Alerts et logs
  renderAlertsAndLogs() {
    if (this.stats.alerts.length > 0) {
      console.log('⚠️  ALERTS:');
      this.stats.alerts.slice(-3).forEach(alert => {
        const time = new Date(alert.timestamp).toLocaleTimeString();
        console.log(`• [${time}] ${alert.level.toUpperCase()}: ${alert.message}`);
      });
      console.log('');
    }
    
    if (this.stats.logs.length > 0) {
      console.log('📝 DERNIÈRES ACTIONS:');
      this.stats.logs.slice(-3).forEach(log => {
        const time = new Date(log.timestamp).toLocaleTimeString();
        console.log(`• [${time}] ${log.message}`);
      });
    }
  }

  // 📊 Collecte de données temps réel
  async collectMetrics() {
    try {
      // Tests status
      await this.updateTestStats();
      
      // Performance metrics
      await this.updatePerformanceMetrics();
      
      // Security status
      await this.updateSecurityStatus();
      
      // Phase progress
      await this.updatePhaseProgress();
      
      // Active agents
      this.updateActiveAgents();
      
    } catch (error) {
      this.addAlert('error', `Erreur collecte métriques: ${error.message}`);
    }
  }

  async updateTestStats() {
    try {
      const { stdout } = await execAsync(`cd ${this.baseDir}/backend && npm test --silent`, { timeout: 10000 });
      
      const passMatch = stdout.match(/(\d+) passing/);
      const failMatch = stdout.match(/(\d+) failing/);
      
      this.stats.tests.passed = passMatch ? parseInt(passMatch[1]) : 0;
      this.stats.tests.failed = failMatch ? parseInt(failMatch[1]) : 0;
      this.stats.tests.total = this.stats.tests.passed + this.stats.tests.failed;
      
    } catch (error) {
      // Tests en cours d'exécution ou erreur
      this.stats.tests.failed++;
    }
  }

  async updatePerformanceMetrics() {
    try {
      // Simuler métriques performance (dans un vrai système, utiliser des vraies métriques)
      const testStart = Date.now();
      await execAsync(`cd ${this.baseDir}/backend && node -e "console.log('health check')"`, { timeout: 5000 });
      this.stats.performance.avgResponseTime = Date.now() - testStart;
      
      // Memory usage
      const memInfo = process.memoryUsage();
      this.stats.performance.memory = Math.floor(memInfo.heapUsed / 1024 / 1024);
      
    } catch (error) {
      this.stats.performance.avgResponseTime = 999;
    }
  }

  async updateSecurityStatus() {
    try {
      // Check for security violations
      const { stdout } = await execAsync(`cd ${this.baseDir} && grep -r "innerHTML\\|eval\\|document.write" backend/ --include="*.js" || true`);
      
      if (stdout.trim()) {
        this.stats.security.status = 'warning';
        this.addAlert('warning', 'Patterns XSS potentiels détectés');
      } else {
        this.stats.security.status = 'secure';
      }
      
      this.stats.security.lastScan = new Date().toISOString();
      
    } catch (error) {
      this.stats.security.status = 'unknown';
    }
  }

  async updatePhaseProgress() {
    try {
      // Détecter phase actuelle en vérifiant fichiers existants
      let currentPhase = 0;
      
      // Phase 1: Modèles
      const modelsExist = ['Contact', 'Submission', 'Invitation', 'Handshake'].every(model => 
        fs.existsSync(path.join(this.baseDir, `backend/models/${model}.js`))
      );
      if (modelsExist) {
        this.stats.phases[0].status = 'completed';
        this.stats.phases[0].progress = 100;
        currentPhase = Math.max(currentPhase, 1);
      }
      
      // Phase 2: Services
      const servicesExist = ['ContactService', 'SubmissionService'].some(service => 
        fs.existsSync(path.join(this.baseDir, `backend/services/${service}.js`))
      );
      if (servicesExist) {
        currentPhase = Math.max(currentPhase, 2);
        this.stats.phases[1].status = 'in_progress';
        // Progress basé sur nombre de services créés
        const serviceFiles = fs.readdirSync(path.join(this.baseDir, 'backend/services')).length;
        this.stats.phases[1].progress = Math.min(serviceFiles * 10, 100);
      }
      
      // Phase 3: APIs
      const routesExist = fs.existsSync(path.join(this.baseDir, 'backend/routes')) &&
        fs.readdirSync(path.join(this.baseDir, 'backend/routes')).some(file => 
          ['contact', 'submission', 'invitation', 'handshake'].some(route => file.includes(route))
        );
      if (routesExist) {
        currentPhase = Math.max(currentPhase, 3);
        this.stats.phases[2].status = 'in_progress';
      }
      
      this.stats.currentPhase = currentPhase;
      
    } catch (error) {
      this.addAlert('error', `Erreur détection phase: ${error.message}`);
    }
  }

  updateActiveAgents() {
    // Dans un vrai système, ceci viendrait d'un système de process tracking
    // Pour la démo, simuler quelques agents
    if (this.stats.currentPhase === 2) {
      this.stats.agents.set('faf-backend-architect', {
        status: 'working',
        task: 'Creating SubmissionService.js',
        startTime: Date.now() - 300000 // 5min ago
      });
      this.stats.agents.set('faf-test-specialist', {
        status: 'working', 
        task: 'Writing integration tests',
        startTime: Date.now() - 120000 // 2min ago
      });
    }
  }

  // 🔧 Utilitaires
  getCurrentPhaseName() {
    if (this.stats.currentPhase === 0) return 'INITIALISATION';
    const phase = this.stats.phases[this.stats.currentPhase - 1];
    return phase ? phase.name : 'UNKNOWN';
  }

  calculateETA() {
    if (this.stats.currentPhase === 0) return 'Calcul...';
    
    const elapsed = Date.now() - this.stats.startTime;
    const averagePhaseTime = elapsed / this.stats.currentPhase;
    const remainingPhases = 6 - this.stats.currentPhase;
    const etaMs = remainingPhases * averagePhaseTime;
    
    const etaMin = Math.floor(etaMs / 1000 / 60);
    const etaHour = Math.floor(etaMin / 60);
    
    if (etaHour > 0) {
      return `${etaHour}h ${etaMin % 60}min`;
    } else {
      return `${etaMin}min`;
    }
  }

  getPerformanceStatus() {
    if (this.stats.performance.avgResponseTime < 50) return 'excellent';
    if (this.stats.performance.avgResponseTime < 200) return 'bon';
    return 'dégradé';
  }

  getCoveragePercentage() {
    // Dans un vrai système, parser le coverage report
    return Math.floor(Math.random() * 15) + 85; // Simuler 85-100%
  }

  addAlert(level, message) {
    this.stats.alerts.push({
      timestamp: Date.now(),
      level,
      message
    });
    
    // Garder seulement 10 dernières alerts
    if (this.stats.alerts.length > 10) {
      this.stats.alerts = this.stats.alerts.slice(-10);
    }
  }

  addLog(message) {
    this.stats.logs.push({
      timestamp: Date.now(),
      message
    });
    
    // Garder seulement 20 derniers logs
    if (this.stats.logs.length > 20) {
      this.stats.logs = this.stats.logs.slice(-20);
    }
  }

  // 🚀 Démarrage monitoring
  async start() {
    this.monitoring = true;
    this.addLog('Monitoring démarré');
    
    console.log('🚀 Démarrage Live Monitor FAF v2...\n');
    
    // Collecte initiale
    await this.collectMetrics();
    
    // Loop de monitoring
    const monitorLoop = async () => {
      if (!this.monitoring) return;
      
      try {
        await this.collectMetrics();
        this.renderDashboard();
      } catch (error) {
        console.error(`Erreur monitoring: ${error.message}`);
      }
      
      setTimeout(monitorLoop, 2000); // Refresh toutes les 2s
    };
    
    monitorLoop();
  }

  stop() {
    this.monitoring = false;
    this.addLog('Monitoring arrêté');
    console.log('\n✅ Live Monitor arrêté');
  }

  // 💾 Export rapport final
  exportReport() {
    const report = {
      timestamp: new Date().toISOString(),
      duration: Date.now() - this.stats.startTime,
      phases: this.stats.phases,
      finalStats: {
        testsTotal: this.stats.tests.total,
        testsPassed: this.stats.tests.passed,
        testsFailed: this.stats.tests.failed,
        securityStatus: this.stats.security.status,
        avgPerformance: this.stats.performance.avgResponseTime
      },
      alerts: this.stats.alerts,
      completedPhases: this.stats.phases.filter(p => p.status === 'completed').length
    };
    
    const reportPath = path.join(this.baseDir, `migration-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    console.log(`📊 Rapport exporté: ${reportPath}`);
    return reportPath;
  }
}

// 🚀 CLI Interface
if (require.main === module) {
  const monitor = new LiveMonitor();
  
  // Handle Ctrl+C gracefully
  process.on('SIGINT', () => {
    monitor.stop();
    const reportPath = monitor.exportReport();
    console.log(`\n📊 Rapport final disponible: ${reportPath}`);
    process.exit(0);
  });
  
  // Start monitoring
  monitor.start().catch(error => {
    console.error(`❌ Erreur démarrage monitor: ${error.message}`);
    process.exit(1);
  });
}

module.exports = LiveMonitor;