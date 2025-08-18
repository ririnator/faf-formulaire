/**
 * Système de logging pour la validation d'intégrité
 * 
 * Fournit un logging structuré avec :
 * - Niveaux de log (debug, info, warn, error)
 * - Formatage coloré pour la console
 * - Horodatage précis
 * - Métadonnées contextuelles
 * - Sauvegarde optionnelle en fichier
 * 
 * @author FAF Migration Team
 */

const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');

class Logger {
    constructor(verbose = false, logFile = null) {
        this.verbose = verbose;
        this.logFile = logFile;
        this.startTime = Date.now();
        this.logs = [];
        
        // Configuration des niveaux de log
        this.levels = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3,
            SUCCESS: 4
        };
        
        this.currentLevel = verbose ? this.levels.DEBUG : this.levels.INFO;
        
        // Configuration des couleurs
        this.colors = {
            DEBUG: chalk.gray,
            INFO: chalk.blue,
            WARN: chalk.yellow,
            ERROR: chalk.red,
            SUCCESS: chalk.green
        };
        
        // Configuration des icônes
        this.icons = {
            DEBUG: '🔍',
            INFO: 'ℹ️',
            WARN: '⚠️',
            ERROR: '❌',
            SUCCESS: '✅'
        };
    }

    /**
     * Log de débogage
     */
    debug(message, context = {}) {
        this.log('DEBUG', message, context);
    }

    /**
     * Log d'information
     */
    info(message, context = {}) {
        this.log('INFO', message, context);
    }

    /**
     * Log d'avertissement
     */
    warn(message, context = {}) {
        this.log('WARN', message, context);
    }

    /**
     * Log d'erreur
     */
    error(message, context = {}) {
        this.log('ERROR', message, context);
    }

    /**
     * Log de succès
     */
    success(message, context = {}) {
        this.log('SUCCESS', message, context);
    }

    /**
     * Méthode de log générique
     */
    log(level, message, context = {}) {
        if (this.levels[level] < this.currentLevel) {
            return; // Niveau trop bas
        }

        const timestamp = new Date().toISOString();
        const elapsed = Date.now() - this.startTime;
        
        const logEntry = {
            timestamp,
            level,
            message,
            context,
            elapsed
        };
        
        // Ajout à l'historique
        this.logs.push(logEntry);
        
        // Affichage console
        this.displayToConsole(logEntry);
        
        // Sauvegarde en fichier si configuré
        if (this.logFile) {
            this.saveToFile(logEntry);
        }
    }

    /**
     * Affichage formaté dans la console
     */
    displayToConsole(logEntry) {
        const { timestamp, level, message, context, elapsed } = logEntry;
        
        const timeString = new Date(timestamp).toLocaleTimeString();
        const elapsedString = this.formatElapsed(elapsed);
        const color = this.colors[level] || chalk.white;
        const icon = this.icons[level] || '';
        
        // Format principal
        let output = `${color(`[${timeString}]`)} ${icon} ${color(message)}`;
        
        // Ajout du temps écoulé si pertinent
        if (this.verbose) {
            output += ` ${chalk.gray(`(+${elapsedString})`)}`;
        }
        
        console.log(output);
        
        // Affichage du contexte si présent et en mode verbose
        if (this.verbose && Object.keys(context).length > 0) {
            console.log(chalk.gray('  Context:'), this.formatContext(context));
        }
    }

    /**
     * Formatage du temps écoulé
     */
    formatElapsed(elapsed) {
        if (elapsed < 1000) {
            return `${elapsed}ms`;
        } else if (elapsed < 60000) {
            return `${(elapsed / 1000).toFixed(1)}s`;
        } else {
            const minutes = Math.floor(elapsed / 60000);
            const seconds = ((elapsed % 60000) / 1000).toFixed(0);
            return `${minutes}m ${seconds}s`;
        }
    }

    /**
     * Formatage du contexte
     */
    formatContext(context) {
        if (typeof context === 'string') {
            return context;
        }
        
        try {
            return JSON.stringify(context, null, 2);
        } catch (error) {
            return '[Contexte non-sérialisable]';
        }
    }

    /**
     * Sauvegarde en fichier
     */
    async saveToFile(logEntry) {
        try {
            const logLine = JSON.stringify(logEntry) + '\n';
            await fs.appendFile(this.logFile, logLine);
        } catch (error) {
            // En cas d'erreur de sauvegarde, afficher en console
            console.error(chalk.red('❌ Erreur de sauvegarde du log:'), error.message);
        }
    }

    /**
     * Configuration d'un fichier de log
     */
    async setLogFile(filePath) {
        try {
            // Création du répertoire si nécessaire
            const dir = path.dirname(filePath);
            await fs.mkdir(dir, { recursive: true });
            
            this.logFile = filePath;
            
            // En-tête du fichier de log
            const header = {
                timestamp: new Date().toISOString(),
                level: 'INFO',
                message: 'Début de la session de validation',
                context: { version: '2.0.0', verbose: this.verbose },
                elapsed: 0
            };
            
            await this.saveToFile(header);
            this.info(`📁 Fichier de log configuré: ${filePath}`);
            
        } catch (error) {
            this.error(`Impossible de configurer le fichier de log: ${error.message}`);
        }
    }

    /**
     * Création d'un sous-logger avec préfixe
     */
    createSubLogger(prefix) {
        const subLogger = new Logger(this.verbose, this.logFile);
        subLogger.startTime = this.startTime;
        
        // Redéfinition des méthodes avec préfixe
        const originalLog = subLogger.log.bind(subLogger);
        subLogger.log = (level, message, context = {}) => {
            const prefixedMessage = `[${prefix}] ${message}`;
            originalLog(level, prefixedMessage, context);
        };
        
        return subLogger;
    }

    /**
     * Mesure de performance avec log
     */
    time(label) {
        const startTime = Date.now();
        this.debug(`⏱️ Début de mesure: ${label}`);
        
        return {
            end: () => {
                const duration = Date.now() - startTime;
                this.debug(`⏱️ Fin de mesure: ${label} (${this.formatElapsed(duration)})`);
                return duration;
            }
        };
    }

    /**
     * Log de progression
     */
    progress(current, total, operation = 'Progression') {
        const percentage = total > 0 ? ((current / total) * 100).toFixed(1) : 0;
        const bar = this.createProgressBar(current, total);
        
        this.info(`${operation}: ${bar} ${percentage}% (${current}/${total})`);
    }

    /**
     * Création d'une barre de progression
     */
    createProgressBar(current, total, width = 20) {
        const filled = Math.round((current / total) * width);
        const empty = width - filled;
        
        return '█'.repeat(filled) + '░'.repeat(empty);
    }

    /**
     * Log d'erreur avec stack trace
     */
    logError(error, context = {}) {
        this.error(error.message, {
            ...context,
            stack: error.stack,
            name: error.name
        });
    }

    /**
     * Génération d'un rapport de log
     */
    generateReport() {
        const report = {
            totalLogs: this.logs.length,
            byLevel: {},
            duration: Date.now() - this.startTime,
            startTime: this.startTime,
            endTime: Date.now()
        };
        
        // Comptage par niveau
        for (const log of this.logs) {
            report.byLevel[log.level] = (report.byLevel[log.level] || 0) + 1;
        }
        
        return report;
    }

    /**
     * Sauvegarde complète des logs
     */
    async saveLogs(filePath) {
        try {
            const report = this.generateReport();
            const output = {
                metadata: report,
                logs: this.logs
            };
            
            await fs.writeFile(filePath, JSON.stringify(output, null, 2));
            this.success(`📁 Logs sauvegardés: ${filePath}`);
            
        } catch (error) {
            this.error(`Erreur de sauvegarde des logs: ${error.message}`);
        }
    }

    /**
     * Nettoyage des logs anciens
     */
    clearOldLogs(maxAge = 3600000) { // 1 heure par défaut
        const cutoff = Date.now() - maxAge;
        const initialCount = this.logs.length;
        
        this.logs = this.logs.filter(log => 
            new Date(log.timestamp).getTime() > cutoff
        );
        
        const removed = initialCount - this.logs.length;
        if (removed > 0) {
            this.debug(`🧹 ${removed} logs anciens supprimés`);
        }
    }

    /**
     * Affichage d'un résumé
     */
    displaySummary() {
        const report = this.generateReport();
        
        console.log('\n' + '─'.repeat(60));
        console.log(chalk.bold.blue('📊 RÉSUMÉ DES LOGS'));
        console.log('─'.repeat(60));
        
        console.log(`⏱️ Durée totale: ${this.formatElapsed(report.duration)}`);
        console.log(`📝 Logs générés: ${report.totalLogs}`);
        
        console.log('\n📈 Répartition par niveau:');
        for (const [level, count] of Object.entries(report.byLevel)) {
            const color = this.colors[level] || chalk.white;
            const icon = this.icons[level] || '';
            console.log(`  ${icon} ${color(level)}: ${count}`);
        }
        
        console.log('─'.repeat(60));
    }
}

module.exports = Logger;