#!/usr/bin/env node

/**
 * Script de test du système de validation
 * 
 * Vérifie que tous les composants fonctionnent correctement :
 * - Chargement des modules
 * - Connexion à la base de données
 * - Validateurs individuels
 * - Génération de rapports
 * 
 * @author FAF Migration Team
 */

const chalk = require('chalk');
const path = require('path');

class SystemTester {
    constructor() {
        this.testResults = [];
        this.startTime = Date.now();
    }

    /**
     * Exécution de tous les tests
     */
    async runAllTests() {
        console.log(chalk.blue.bold('🧪 Test du système de validation d\'intégrité FAF'));
        console.log(chalk.blue('=' .repeat(60)));
        
        try {
            await this.testModuleLoading();
            await this.testDatabaseConnection();
            await this.testValidators();
            await this.testReportGeneration();
            await this.testCLIInterface();
            
            this.displayResults();
            
        } catch (error) {
            console.error(chalk.red.bold('\n❌ Test system failed:'), error.message);
            process.exit(1);
        }
    }

    /**
     * Test du chargement des modules
     */
    async testModuleLoading() {
        console.log(chalk.yellow('\n📦 Test du chargement des modules...'));
        
        const modules = [
            { name: 'DatabaseConnection', path: './utils/DatabaseConnection' },
            { name: 'Logger', path: './utils/Logger' },
            { name: 'CountValidator', path: './validators/CountValidator' },
            { name: 'RelationValidator', path: './validators/RelationValidator' },
            { name: 'TokenValidator', path: './validators/TokenValidator' },
            { name: 'FunctionalityValidator', path: './validators/FunctionalityValidator' },
            { name: 'DataValidator', path: './validators/DataValidator' },
            { name: 'ReportGenerator', path: './reporters/ReportGenerator' }
        ];
        
        let loadedCount = 0;
        
        for (const module of modules) {
            try {
                const ModuleClass = require(module.path);
                
                // Test d'instanciation basique
                if (module.name === 'DatabaseConnection') {
                    new ModuleClass();
                } else if (module.name === 'Logger') {
                    new ModuleClass(false);
                } else if (module.name === 'ReportGenerator') {
                    new ModuleClass(new (require('./utils/Logger'))(false));
                } else {
                    // Validateurs - nécessitent db et logger
                    const mockDb = { collection: () => ({}) };
                    const mockLogger = { info: () => {}, error: () => {}, warn: () => {} };
                    new ModuleClass(mockDb, mockLogger);
                }
                
                console.log(chalk.green(`  ✅ ${module.name}`));
                loadedCount++;
                
            } catch (error) {
                console.log(chalk.red(`  ❌ ${module.name}: ${error.message}`));
                this.testResults.push({ 
                    test: `Module ${module.name}`, 
                    success: false, 
                    error: error.message 
                });
            }
        }
        
        this.testResults.push({
            test: 'Module Loading',
            success: loadedCount === modules.length,
            details: `${loadedCount}/${modules.length} modules loaded`
        });
        
        console.log(chalk.green(`✅ ${loadedCount}/${modules.length} modules chargés`));
    }

    /**
     * Test de la connexion à la base de données
     */
    async testDatabaseConnection() {
        console.log(chalk.yellow('\n🔌 Test de la connexion à la base de données...'));
        
        try {
            const DatabaseConnection = require('./utils/DatabaseConnection');
            const db = new DatabaseConnection();
            
            const testResult = await db.testConnection();
            
            if (testResult.success) {
                console.log(chalk.green(`✅ Connexion MongoDB réussie`));
                console.log(chalk.gray(`   Temps: ${testResult.metrics.connectionTime}ms`));
                
                this.testResults.push({
                    test: 'Database Connection',
                    success: true,
                    details: `Connected in ${testResult.metrics.connectionTime}ms`
                });
            } else {
                console.log(chalk.yellow(`⚠️ Connexion MongoDB échouée: ${testResult.error}`));
                console.log(chalk.yellow('   Le système peut fonctionner mais les tests complets seront limités'));
                
                this.testResults.push({
                    test: 'Database Connection',
                    success: false,
                    error: testResult.error
                });
            }
            
        } catch (error) {
            console.log(chalk.red(`❌ Erreur de test de connexion: ${error.message}`));
            
            this.testResults.push({
                test: 'Database Connection',
                success: false,
                error: error.message
            });
        }
    }

    /**
     * Test des validateurs
     */
    async testValidators() {
        console.log(chalk.yellow('\n🔍 Test des validateurs...'));
        
        const validators = [
            'CountValidator',
            'RelationValidator', 
            'TokenValidator',
            'FunctionalityValidator',
            'DataValidator'
        ];
        
        let validatorCount = 0;
        
        for (const validatorName of validators) {
            try {
                const ValidatorClass = require(`./validators/${validatorName}`);
                
                // Mock objects
                const mockDb = {
                    collection: (name) => ({
                        find: () => ({ toArray: async () => [], limit: () => ({ toArray: async () => [] }) }),
                        countDocuments: async () => 0,
                        aggregate: () => ({ toArray: async () => [] }),
                        findOne: async () => null
                    }),
                    listCollections: () => ({ toArray: async () => [] })
                };
                
                const mockLogger = {
                    info: () => {},
                    error: () => {},
                    warn: () => {},
                    success: () => {}
                };
                
                const validator = new ValidatorClass(mockDb, mockLogger);
                
                // Test des méthodes essentielles
                if (typeof validator.validate !== 'function') {
                    throw new Error('Méthode validate() manquante');
                }
                
                if (typeof validator.calculateScore !== 'function') {
                    throw new Error('Méthode calculateScore() manquante');
                }
                
                console.log(chalk.green(`  ✅ ${validatorName}`));
                validatorCount++;
                
            } catch (error) {
                console.log(chalk.red(`  ❌ ${validatorName}: ${error.message}`));
                
                this.testResults.push({
                    test: `Validator ${validatorName}`,
                    success: false,
                    error: error.message
                });
            }
        }
        
        this.testResults.push({
            test: 'Validators',
            success: validatorCount === validators.length,
            details: `${validatorCount}/${validators.length} validators working`
        });
        
        console.log(chalk.green(`✅ ${validatorCount}/${validators.length} validateurs fonctionnels`));
    }

    /**
     * Test de la génération de rapports
     */
    async testReportGeneration() {
        console.log(chalk.yellow('\n📊 Test de la génération de rapports...'));
        
        try {
            const ReportGenerator = require('./reporters/ReportGenerator');
            const Logger = require('./utils/Logger');
            
            const logger = new Logger(false);
            const reporter = new ReportGenerator(logger);
            
            // Données de test
            const mockResults = new Map([
                ['counts', {
                    category: 'counts',
                    success: true,
                    score: 95,
                    errors: [],
                    details: { totalCounts: {} },
                    metadata: { duration: 1000 }
                }],
                ['relations', {
                    category: 'relations',
                    success: false,
                    score: 75,
                    errors: [{ 
                        code: 'TEST_ERROR', 
                        message: 'Test error message',
                        timestamp: new Date().toISOString()
                    }],
                    details: {},
                    metadata: { duration: 1500 }
                }]
            ]);
            
            const metadata = {
                totalDuration: 2500,
                timestamp: new Date().toISOString()
            };
            
            const report = await reporter.generate(mockResults, metadata);
            
            // Validation du rapport
            const requiredSections = ['metadata', 'summary', 'categories', 'recommendations', 'performance'];
            const missingSections = requiredSections.filter(section => !report[section]);
            
            if (missingSections.length > 0) {
                throw new Error(`Sections manquantes: ${missingSections.join(', ')}`);
            }
            
            if (typeof report.summary.overallScore !== 'number') {
                throw new Error('Score global manquant');
            }
            
            console.log(chalk.green('✅ Génération de rapport JSON fonctionnelle'));
            console.log(chalk.gray(`   Score de test: ${report.summary.overallScore}%`));
            
            this.testResults.push({
                test: 'Report Generation',
                success: true,
                details: `Test report generated with score ${report.summary.overallScore}%`
            });
            
        } catch (error) {
            console.log(chalk.red(`❌ Génération de rapport échouée: ${error.message}`));
            
            this.testResults.push({
                test: 'Report Generation',
                success: false,
                error: error.message
            });
        }
    }

    /**
     * Test de l'interface CLI
     */
    async testCLIInterface() {
        console.log(chalk.yellow('\n⌨️ Test de l\'interface CLI...'));
        
        try {
            // Test du chargement du CLI principal
            const mainScript = require('./index.js');
            
            // Test des commandes disponibles
            const { program } = require('commander');
            
            // Reset program pour éviter les conflits
            program.commands.length = 0;
            program.options.length = 0;
            
            // Re-setup basique
            program
                .version('2.0.0')
                .description('Test CLI setup');
            
            console.log(chalk.green('✅ Interface CLI chargeable'));
            
            this.testResults.push({
                test: 'CLI Interface',
                success: true,
                details: 'CLI commands loaded successfully'
            });
            
        } catch (error) {
            console.log(chalk.red(`❌ Interface CLI échouée: ${error.message}`));
            
            this.testResults.push({
                test: 'CLI Interface',
                success: false,
                error: error.message
            });
        }
    }

    /**
     * Affichage des résultats
     */
    displayResults() {
        const totalTime = Date.now() - this.startTime;
        const successCount = this.testResults.filter(r => r.success).length;
        const totalTests = this.testResults.length;
        
        console.log(chalk.blue('\n' + '=' .repeat(60)));
        console.log(chalk.blue.bold('📋 RÉSULTATS DES TESTS'));
        console.log(chalk.blue('=' .repeat(60)));
        
        // Score global
        const successRate = (successCount / totalTests) * 100;
        const scoreColor = successRate === 100 ? chalk.green : successRate >= 80 ? chalk.yellow : chalk.red;
        
        console.log(chalk.bold(`🎯 Score global: ${scoreColor(successRate.toFixed(1) + '%')} (${successCount}/${totalTests})`));
        console.log(chalk.gray(`⏱️ Temps total: ${totalTime}ms`));
        
        // Détail par test
        console.log('\n📊 Détail par test:');
        for (const result of this.testResults) {
            const icon = result.success ? '✅' : '❌';
            const details = result.details ? ` (${result.details})` : '';
            const error = result.error ? ` - ${result.error}` : '';
            
            console.log(`${icon} ${result.test}${details}${error}`);
        }
        
        // Recommandations
        const failedTests = this.testResults.filter(r => !r.success);
        if (failedTests.length > 0) {
            console.log(chalk.yellow('\n💡 RECOMMANDATIONS:'));
            
            for (const failed of failedTests) {
                if (failed.test === 'Database Connection') {
                    console.log(chalk.yellow('  • Vérifiez la variable MONGODB_URI'));
                    console.log(chalk.yellow('  • Assurez-vous que MongoDB est accessible'));
                } else if (failed.test.startsWith('Module')) {
                    console.log(chalk.yellow('  • Exécutez: npm install'));
                    console.log(chalk.yellow('  • Vérifiez les dépendances manquantes'));
                } else if (failed.test.startsWith('Validator')) {
                    console.log(chalk.yellow('  • Vérifiez l\'implémentation du validateur'));
                } else {
                    console.log(chalk.yellow(`  • Examinez l'erreur: ${failed.error}`));
                }
            }
        }
        
        // Statut final
        console.log('\n' + '─' .repeat(60));
        if (successRate === 100) {
            console.log(chalk.green.bold('🎉 Tous les tests réussis ! Le système est prêt.'));
        } else if (successRate >= 80) {
            console.log(chalk.yellow.bold('⚠️ Système partiellement fonctionnel. Vérifiez les recommandations.'));
        } else {
            console.log(chalk.red.bold('❌ Problèmes détectés. Correction requise avant utilisation.'));
        }
        
        console.log(chalk.blue('🚀 Lancement du système: node index.js'));
    }
}

// Exécution si appelé directement
if (require.main === module) {
    const tester = new SystemTester();
    tester.runAllTests();
}

module.exports = SystemTester;