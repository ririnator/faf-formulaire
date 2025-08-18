#!/usr/bin/env node

/**
 * Exemple d'utilisation du système de validation d'intégrité FAF
 * 
 * Démontre :
 * - Validation programmée complète
 * - Gestion des erreurs
 * - Génération de rapports multiples
 * - Actions correctives automatiques
 * 
 * @author FAF Migration Team
 */

const chalk = require('chalk');
const path = require('path');
const fs = require('fs').promises;

const IntegrityValidationSystem = require('./index.js');

class ValidationExample {
    constructor() {
        this.outputDir = './example-reports';
        this.startTime = Date.now();
    }

    /**
     * Exemple complet de validation
     */
    async runExample() {
        console.log(chalk.blue.bold('🎯 EXEMPLE - Système de Validation d\'Intégrité FAF'));
        console.log(chalk.blue('=' .repeat(70)));
        
        try {
            // Étape 1 : Préparation
            await this.setupExample();
            
            // Étape 2 : Validation complète
            const fullReport = await this.runFullValidation();
            
            // Étape 3 : Validation ciblée si nécessaire
            if (fullReport.summary.overallScore < 95) {
                await this.runTargetedValidation(fullReport);
            }
            
            // Étape 4 : Génération de rapports
            await this.generateReports(fullReport);
            
            // Étape 5 : Actions correctives
            await this.demonstrateCorrectiveActions(fullReport);
            
            // Étape 6 : Résumé final
            this.displaySummary(fullReport);
            
        } catch (error) {
            console.error(chalk.red.bold('❌ Erreur dans l\'exemple:'), error.message);
            console.error(chalk.red('Stack trace:'), error.stack);
        }
    }

    /**
     * Configuration de l'exemple
     */
    async setupExample() {
        console.log(chalk.yellow('\n📋 Étape 1: Préparation de l\'exemple'));
        
        // Création du répertoire de sortie
        await fs.mkdir(this.outputDir, { recursive: true });
        console.log(chalk.green(`✅ Répertoire créé: ${this.outputDir}`));
        
        // Vérification de l'environnement
        console.log(chalk.cyan('🔍 Vérification de l\'environnement:'));
        console.log(chalk.gray(`   Node.js: ${process.version}`));
        console.log(chalk.gray(`   Platform: ${process.platform}`));
        console.log(chalk.gray(`   MongoDB URI: ${process.env.MONGODB_URI ? 'Configuré' : 'Non configuré'}`));
        
        console.log(chalk.green('✅ Préparation terminée'));
    }

    /**
     * Validation complète
     */
    async runFullValidation() {
        console.log(chalk.yellow('\n🔍 Étape 2: Validation complète'));
        
        const validator = new IntegrityValidationSystem({
            verbose: true,
            outputDir: this.outputDir,
            timeout: 300000 // 5 minutes
        });
        
        console.log(chalk.cyan('⏳ Lancement de la validation complète...'));
        const startTime = Date.now();
        
        const report = await validator.run();
        
        const duration = Date.now() - startTime;
        console.log(chalk.green(`✅ Validation terminée en ${this.formatDuration(duration)}`));
        console.log(chalk.bold(`🎯 Score global: ${this.getScoreColor(report.summary.overallScore)}${report.summary.overallScore}%`));
        
        return report;
    }

    /**
     * Validation ciblée
     */
    async runTargetedValidation(fullReport) {
        console.log(chalk.yellow('\n🎯 Étape 3: Validation ciblée des problèmes détectés'));
        
        // Identification des catégories en échec
        const failedCategories = [];
        for (const [category, details] of Object.entries(fullReport.categories)) {
            if (details.score < 95) {
                failedCategories.push(category);
            }
        }
        
        if (failedCategories.length === 0) {
            console.log(chalk.green('✅ Aucune validation ciblée nécessaire'));
            return;
        }
        
        console.log(chalk.cyan(`🔍 Re-validation des catégories: ${failedCategories.join(', ')}`));
        
        for (const category of failedCategories) {
            const validator = new IntegrityValidationSystem({
                verbose: false,
                outputDir: this.outputDir,
                skipTests: this.getAllCategoriesExcept(category)
            });
            
            console.log(chalk.cyan(`   Validation: ${category}...`));
            const targetedReport = await validator.run();
            
            const categoryScore = targetedReport.categories[category]?.score || 0;
            console.log(chalk.gray(`   Score ${category}: ${categoryScore}%`));
        }
        
        console.log(chalk.green('✅ Validations ciblées terminées'));
    }

    /**
     * Génération de rapports multiples
     */
    async generateReports(report) {
        console.log(chalk.yellow('\n📊 Étape 4: Génération de rapports multiples'));
        
        try {
            const ReportGenerator = require('./reporters/ReportGenerator');
            const Logger = require('./utils/Logger');
            
            const logger = new Logger(false);
            const reporter = new ReportGenerator(logger);
            
            // Rapport HTML
            const htmlPath = path.join(this.outputDir, 'example-report.html');
            await reporter.generateHtmlReport(report, htmlPath);
            console.log(chalk.green(`✅ Rapport HTML: ${htmlPath}`));
            
            // Rapport CSV
            const csvPath = path.join(this.outputDir, 'example-report.csv');
            await reporter.generateCsvReport(report, csvPath);
            console.log(chalk.green(`✅ Rapport CSV: ${csvPath}`));
            
            // Rapport JSON détaillé
            const jsonPath = path.join(this.outputDir, 'example-detailed.json');
            await fs.writeFile(jsonPath, JSON.stringify(report, null, 2));
            console.log(chalk.green(`✅ Rapport JSON: ${jsonPath}`));
            
        } catch (error) {
            console.error(chalk.red(`❌ Erreur génération rapports: ${error.message}`));
        }
    }

    /**
     * Démonstration des actions correctives
     */
    async demonstrateCorrectiveActions(report) {
        console.log(chalk.yellow('\n🔧 Étape 5: Démonstration des actions correctives'));
        
        if (report.correctiveActions && report.correctiveActions.length > 0) {
            console.log(chalk.cyan('Actions correctives recommandées:'));
            
            for (const action of report.correctiveActions) {
                console.log(chalk.yellow(`\n📋 Catégorie: ${action.category} (Urgence: ${action.urgency})`));
                
                for (const act of action.actions) {
                    console.log(chalk.gray(`   ${act.type}: ${act.description}`));
                    
                    if (act.automated) {
                        console.log(chalk.green(`   ✅ Action automatisée: ${act.command}`));
                        // En mode démo, on ne les exécute pas vraiment
                        console.log(chalk.cyan('   (Simulation - non exécutée en mode démo)'));
                    } else {
                        console.log(chalk.yellow(`   ⚠️ Action manuelle requise: ${act.command}`));
                    }
                }
            }
        } else {
            console.log(chalk.green('✅ Aucune action corrective nécessaire'));
        }
        
        // Exemple d'action corrective simulée
        console.log(chalk.cyan('\n🎭 Simulation d\'action corrective:'));
        console.log(chalk.gray('   Commande simulée: node correctors/relation-corrector.js --dry-run'));
        console.log(chalk.green('   ✅ Simulation terminée - 0 corrections nécessaires'));
    }

    /**
     * Affichage du résumé final
     */
    displaySummary(report) {
        const totalTime = Date.now() - this.startTime;
        
        console.log(chalk.blue('\n' + '=' .repeat(70)));
        console.log(chalk.blue.bold('📋 RÉSUMÉ DE L\'EXEMPLE'));
        console.log(chalk.blue('=' .repeat(70)));
        
        console.log(chalk.bold(`🎯 Score final: ${this.getScoreColor(report.summary.overallScore)}${report.summary.overallScore}%`));
        console.log(chalk.bold(`📊 Statut: ${this.getStatusColor(report.summary.status)}${report.summary.status}`));
        console.log(chalk.gray(`⏱️ Temps total: ${this.formatDuration(totalTime)}`));
        console.log(chalk.gray(`📁 Rapports: ${this.outputDir}/`));
        
        // Détail par catégorie
        console.log(chalk.cyan('\n📈 Détail par catégorie:'));
        for (const [category, details] of Object.entries(report.categories)) {
            const icon = details.score >= 95 ? '✅' : details.score >= 80 ? '⚠️' : '❌';
            console.log(`${icon} ${details.name}: ${details.score}%`);
        }
        
        // Recommandations
        if (report.summary.recommendations.length > 0) {
            console.log(chalk.yellow('\n💡 Recommandations principales:'));
            report.summary.recommendations.slice(0, 5).forEach(rec => {
                console.log(chalk.yellow(`  • ${rec}`));
            });
        }
        
        // Conclusion
        if (report.summary.overallScore >= 95) {
            console.log(chalk.green.bold('\n🎉 MIGRATION VALIDÉE - Prête pour la production'));
        } else if (report.summary.overallScore >= 80) {
            console.log(chalk.yellow.bold('\n⚠️ MIGRATION PARTIELLEMENT VALIDÉE - Corrections mineures recommandées'));
        } else {
            console.log(chalk.red.bold('\n❌ MIGRATION EN ÉCHEC - Corrections majeures requises'));
        }
        
        console.log(chalk.blue('\n🚀 Utilisation normale: node index.js'));
        console.log(chalk.blue('📖 Documentation: README.md'));
        console.log(chalk.blue('🆘 Aide: node index.js --help'));
    }

    /**
     * Obtention de toutes les catégories sauf une
     */
    getAllCategoriesExcept(category) {
        const allCategories = ['counts', 'relations', 'tokens', 'functionality', 'data'];
        return allCategories.filter(cat => cat !== category);
    }

    /**
     * Formatage de durée
     */
    formatDuration(ms) {
        if (ms < 1000) return `${ms}ms`;
        if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
        const minutes = Math.floor(ms / 60000);
        const seconds = ((ms % 60000) / 1000).toFixed(0);
        return `${minutes}m ${seconds}s`;
    }

    /**
     * Couleur du score
     */
    getScoreColor(score) {
        if (score >= 95) return chalk.green;
        if (score >= 80) return chalk.yellow;
        return chalk.red;
    }

    /**
     * Couleur du statut
     */
    getStatusColor(status) {
        if (status === 'MIGRATION_VALIDATED') return chalk.green;
        if (status === 'MIGRATION_PARTIAL') return chalk.yellow;
        return chalk.red;
    }
}

// Exécution si appelé directement
if (require.main === module) {
    const example = new ValidationExample();
    example.runExample();
}

module.exports = ValidationExample;