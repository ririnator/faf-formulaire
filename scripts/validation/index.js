#!/usr/bin/env node

/**
 * FAF Migration Integrity Validation System
 * 
 * Système complet de validation d'intégrité post-migration pour vérifier
 * tous les aspects critiques de la migration FAF v1 → Form-a-Friend v2
 * 
 * Fonctionnalités :
 * - Validation des comptages (documents, collections, agrégations)
 * - Validation des relations et intégrité référentielle
 * - Validation des tokens legacy et mapping
 * - Validation des fonctionnalités et workflows
 * - Validation des données et structures
 * - Génération de rapports détaillés avec scoring d'intégrité
 * 
 * @author FAF Migration Team
 * @version 2.0.0
 */

const path = require('path');
const fs = require('fs').promises;
const { program } = require('commander');
const chalk = require('chalk');

// Vérification préalable des dépendances
try {
    require('mongodb');
} catch (error) {
    console.error(chalk.red('❌ MongoDB driver manquant. Exécutez: npm install'));
    process.exit(1);
}

// Import des validateurs
const CountValidator = require('./validators/CountValidator');
const RelationValidator = require('./validators/RelationValidator');
const TokenValidator = require('./validators/TokenValidator');
const FunctionalityValidator = require('./validators/FunctionalityValidator');
const DataValidator = require('./validators/DataValidator');
const ReportGenerator = require('./reporters/ReportGenerator');
const DatabaseConnection = require('./utils/DatabaseConnection');
const Logger = require('./utils/Logger');

/**
 * Classe principale de validation d'intégrité
 */
class IntegrityValidationSystem {
    constructor(options = {}) {
        this.options = {
            verbose: false,
            outputDir: './validation-reports',
            skipTests: [],
            maxParallelism: 5,
            timeout: 300000, // 5 minutes
            ...options
        };
        
        this.logger = new Logger(this.options.verbose);
        this.db = null;
        this.startTime = null;
        this.validationResults = new Map();
    }

    /**
     * Point d'entrée principal du système de validation
     */
    async run() {
        try {
            this.startTime = Date.now();
            this.logger.info('🚀 Démarrage du système de validation d\'intégrité FAF');
            
            await this.initialize();
            const results = await this.executeValidations();
            const report = await this.generateReport(results);
            
            await this.displaySummary(report);
            await this.cleanup();
            
            return report;
            
        } catch (error) {
            this.logger.error('❌ Erreur critique dans le système de validation:', error);
            throw error;
        }
    }

    /**
     * Initialisation du système
     */
    async initialize() {
        this.logger.info('📋 Initialisation du système de validation...');
        
        // Connexion à la base de données
        this.db = new DatabaseConnection();
        await this.db.connect();
        
        // Création du répertoire de sortie
        await fs.mkdir(this.options.outputDir, { recursive: true });
        
        this.logger.success('✅ Initialisation terminée');
    }

    /**
     * Exécution de toutes les validations
     */
    async executeValidations() {
        this.logger.info('🔍 Exécution des validations d\'intégrité...');
        
        const validators = this.createValidators();
        const results = new Map();
        
        // Exécution séquentielle pour éviter la surcharge
        for (const [name, validator] of validators) {
            if (this.options.skipTests.includes(name)) {
                this.logger.warn(`⏭️ Validation ${name} ignorée`);
                continue;
            }
            
            try {
                this.logger.info(`🔍 Exécution: ${name}`);
                const startTime = Date.now();
                
                const result = await Promise.race([
                    validator.validate(),
                    this.createTimeoutPromise(this.options.timeout)
                ]);
                
                const duration = Date.now() - startTime;
                result.metadata = {
                    ...result.metadata,
                    duration,
                    timestamp: new Date().toISOString()
                };
                
                results.set(name, result);
                this.logger.success(`✅ ${name} terminée (${duration}ms)`);
                
            } catch (error) {
                this.logger.error(`❌ Erreur dans ${name}:`, error);
                results.set(name, {
                    category: name,
                    success: false,
                    score: 0,
                    errors: [error.message],
                    details: {},
                    metadata: {
                        duration: 0,
                        timestamp: new Date().toISOString(),
                        error: error.message
                    }
                });
            }
        }
        
        return results;
    }

    /**
     * Création des validateurs
     */
    createValidators() {
        const validators = new Map();
        
        validators.set('counts', new CountValidator(this.db, this.logger));
        validators.set('relations', new RelationValidator(this.db, this.logger));
        validators.set('tokens', new TokenValidator(this.db, this.logger));
        validators.set('functionality', new FunctionalityValidator(this.db, this.logger));
        validators.set('data', new DataValidator(this.db, this.logger));
        
        return validators;
    }

    /**
     * Génération du rapport final
     */
    async generateReport(results) {
        this.logger.info('📊 Génération du rapport d\'intégrité...');
        
        const reporter = new ReportGenerator(this.logger);
        const report = await reporter.generate(results, {
            totalDuration: Date.now() - this.startTime,
            options: this.options,
            timestamp: new Date().toISOString()
        });
        
        // Sauvegarde du rapport
        const reportPath = path.join(
            this.options.outputDir,
            `integrity-report-${Date.now()}.json`
        );
        
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
        this.logger.success(`📁 Rapport sauvegardé: ${reportPath}`);
        
        return report;
    }

    /**
     * Affichage du résumé
     */
    async displaySummary(report) {
        console.log('\n' + '='.repeat(80));
        console.log(chalk.bold.blue('📊 RAPPORT DE VALIDATION D\'INTÉGRITÉ FAF'));
        console.log('='.repeat(80));
        
        console.log(chalk.bold(`🎯 Score global d'intégrité: ${report.summary.overallScore}%`));
        
        if (report.summary.overallScore >= 95) {
            console.log(chalk.green('✅ Migration validée avec succès'));
        } else if (report.summary.overallScore >= 80) {
            console.log(chalk.yellow('⚠️ Migration partiellement validée - Attention requise'));
        } else {
            console.log(chalk.red('❌ Migration en échec - Correction nécessaire'));
        }
        
        console.log(`\n📈 Détails par catégorie:`);
        for (const [category, result] of Object.entries(report.categories)) {
            const icon = result.score >= 95 ? '✅' : result.score >= 80 ? '⚠️' : '❌';
            console.log(`${icon} ${category}: ${result.score}% (${result.errors.length} erreur(s))`);
        }
        
        console.log(`\n⏱️ Durée totale: ${report.summary.totalDuration}ms`);
        console.log(`📅 Horodatage: ${report.summary.timestamp}`);
        
        if (report.summary.criticalErrors.length > 0) {
            console.log(chalk.red('\n🚨 ERREURS CRITIQUES:'));
            report.summary.criticalErrors.forEach(error => {
                console.log(chalk.red(`  • ${error}`));
            });
        }
        
        if (report.summary.recommendations.length > 0) {
            console.log(chalk.blue('\n💡 RECOMMANDATIONS:'));
            report.summary.recommendations.forEach(rec => {
                console.log(chalk.blue(`  • ${rec}`));
            });
        }
    }

    /**
     * Nettoyage des ressources
     */
    async cleanup() {
        if (this.db) {
            await this.db.disconnect();
        }
        this.logger.info('🧹 Nettoyage terminé');
    }

    /**
     * Création d'une promesse de timeout
     */
    createTimeoutPromise(timeout) {
        return new Promise((_, reject) => {
            setTimeout(() => {
                reject(new Error(`Validation timeout après ${timeout}ms`));
            }, timeout);
        });
    }
}

/**
 * Configuration CLI
 */
function setupCLI() {
    program
        .name('faf-integrity-validator')
        .description('Système de validation d\'intégrité post-migration FAF')
        .version('2.0.0');

    program
        .option('-v, --verbose', 'Mode verbeux')
        .option('-o, --output-dir <dir>', 'Répertoire de sortie', './validation-reports')
        .option('-s, --skip <tests>', 'Tests à ignorer (séparés par des virgules)')
        .option('-p, --parallelism <num>', 'Niveau de parallélisme', '5')
        .option('-t, --timeout <ms>', 'Timeout par validation', '300000')
        .option('--counts-only', 'Exécuter uniquement la validation des comptages')
        .option('--relations-only', 'Exécuter uniquement la validation des relations')
        .option('--tokens-only', 'Exécuter uniquement la validation des tokens')
        .option('--functionality-only', 'Exécuter uniquement la validation fonctionnelle')
        .option('--data-only', 'Exécuter uniquement la validation des données')
        .action(async (options) => {
            try {
                // Traitement des options
                const skipTests = options.skip ? options.skip.split(',') : [];
                
                // Ajout des tests à ignorer basé sur les options spécifiques
                if (options.countsOnly) skipTests.push('relations', 'tokens', 'functionality', 'data');
                if (options.relationsOnly) skipTests.push('counts', 'tokens', 'functionality', 'data');
                if (options.tokensOnly) skipTests.push('counts', 'relations', 'functionality', 'data');
                if (options.functionalityOnly) skipTests.push('counts', 'relations', 'tokens', 'data');
                if (options.dataOnly) skipTests.push('counts', 'relations', 'tokens', 'functionality');
                
                const validationOptions = {
                    verbose: options.verbose,
                    outputDir: options.outputDir,
                    skipTests,
                    maxParallelism: parseInt(options.parallelism),
                    timeout: parseInt(options.timeout)
                };
                
                const validator = new IntegrityValidationSystem(validationOptions);
                const report = await validator.run();
                
                // Code de sortie basé sur le score
                process.exit(report.summary.overallScore >= 80 ? 0 : 1);
                
            } catch (error) {
                console.error(chalk.red('❌ Erreur fatale:'), error.message);
                process.exit(1);
            }
        });

    return program;
}

// Exécution CLI si appelé directement
if (require.main === module) {
    const cli = setupCLI();
    cli.parse();
}

module.exports = IntegrityValidationSystem;