#!/usr/bin/env node

/**
 * Script principal pour lancer la suite complète de tests staging
 * Orchestration des tests de migration avec rapports détaillés
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;

class StagingTestRunner {
    constructor() {
        this.testSuites = [
            {
                name: 'Data Validation Tests',
                file: 'data-validation.test.js',
                description: 'Tests de validation des données et migration',
                timeout: 30000
            },
            {
                name: 'Functionality Tests', 
                file: 'functionality.test.js',
                description: 'Tests des fonctionnalités complètes post-migration',
                timeout: 45000
            },
            {
                name: 'Performance Tests',
                file: 'performance.test.js', 
                description: 'Tests de performance et stress testing',
                timeout: 60000
            },
            {
                name: 'Regression Tests',
                file: 'regression.test.js',
                description: 'Tests de régression complète',
                timeout: 45000
            },
            {
                name: 'Monitoring Tests',
                file: 'monitoring.test.js',
                description: 'Tests du système de monitoring et rapports',
                timeout: 30000
            }
        ];

        this.results = {
            startTime: new Date(),
            endTime: null,
            totalTests: 0,
            passedTests: 0,
            failedTests: 0,
            suiteResults: [],
            errors: [],
            summary: {}
        };

        this.options = {
            verbose: process.argv.includes('--verbose'),
            coverage: process.argv.includes('--coverage'),
            parallel: process.argv.includes('--parallel'),
            suite: this.extractSuiteOption(),
            report: process.argv.includes('--report')
        };
    }

    extractSuiteOption() {
        const suiteIndex = process.argv.indexOf('--suite');
        if (suiteIndex !== -1 && process.argv[suiteIndex + 1]) {
            return process.argv[suiteIndex + 1];
        }
        return null;
    }

    async run() {
        console.log('🚀 Démarrage des tests de migration staging...\n');
        
        this.printConfiguration();
        
        try {
            if (this.options.parallel && !this.options.suite) {
                await this.runParallel();
            } else {
                await this.runSequential();
            }
            
            this.results.endTime = new Date();
            await this.generateFinalReport();
            
        } catch (error) {
            console.error('❌ Erreur fatale lors de l\'exécution des tests:', error);
            process.exit(1);
        }
    }

    printConfiguration() {
        console.log('⚙️ Configuration des tests:');
        console.log(`   Mode: ${this.options.parallel ? 'Parallèle' : 'Séquentiel'}`);
        console.log(`   Coverage: ${this.options.coverage ? 'Activé' : 'Désactivé'}`);
        console.log(`   Verbose: ${this.options.verbose ? 'Activé' : 'Désactivé'}`);
        console.log(`   Suite spécifique: ${this.options.suite || 'Toutes'}`);
        console.log(`   Génération rapport: ${this.options.report ? 'Activé' : 'Désactivé'}`);
        console.log('');
    }

    async runSequential() {
        const suitesToRun = this.options.suite 
            ? this.testSuites.filter(suite => suite.file === this.options.suite || suite.name.toLowerCase().includes(this.options.suite.toLowerCase()))
            : this.testSuites;

        console.log(`📋 Exécution séquentielle de ${suitesToRun.length} suite(s) de tests...\n`);

        for (const suite of suitesToRun) {
            console.log(`🧪 Exécution: ${suite.name}`);
            console.log(`   Description: ${suite.description}`);
            console.log(`   Fichier: ${suite.file}`);
            console.log(`   Timeout: ${suite.timeout}ms\n`);

            const result = await this.runTestSuite(suite);
            this.results.suiteResults.push(result);

            if (result.success) {
                console.log(`✅ ${suite.name} - SUCCÈS`);
                this.results.passedTests++;
            } else {
                console.log(`❌ ${suite.name} - ÉCHEC`);
                this.results.failedTests++;
                this.results.errors.push({
                    suite: suite.name,
                    error: result.error
                });
            }

            console.log(`   Tests: ${result.stats.tests || 0}`);
            console.log(`   Durée: ${result.duration}ms\n`);
        }

        this.results.totalTests = suitesToRun.length;
    }

    async runParallel() {
        console.log(`🔄 Exécution parallèle de ${this.testSuites.length} suites de tests...\n`);

        const promises = this.testSuites.map(async (suite) => {
            console.log(`🧪 Démarrage parallèle: ${suite.name}`);
            const result = await this.runTestSuite(suite);
            
            if (result.success) {
                console.log(`✅ ${suite.name} - SUCCÈS (${result.duration}ms)`);
            } else {
                console.log(`❌ ${suite.name} - ÉCHEC (${result.duration}ms)`);
            }
            
            return result;
        });

        const results = await Promise.allSettled(promises);
        
        results.forEach((result, index) => {
            const suite = this.testSuites[index];
            
            if (result.status === 'fulfilled') {
                this.results.suiteResults.push(result.value);
                if (result.value.success) {
                    this.results.passedTests++;
                } else {
                    this.results.failedTests++;
                    this.results.errors.push({
                        suite: suite.name,
                        error: result.value.error
                    });
                }
            } else {
                this.results.failedTests++;
                this.results.errors.push({
                    suite: suite.name,
                    error: result.reason.message
                });
            }
        });

        this.results.totalTests = this.testSuites.length;
    }

    async runTestSuite(suite) {
        const startTime = Date.now();
        
        return new Promise((resolve) => {
            const jestArgs = [
                '--testPathPattern=' + suite.file,
                '--setupFilesAfterEnv=<rootDir>/tests/staging/setup-staging.js',
                '--testTimeout=' + suite.timeout,
                '--maxWorkers=1',
                '--detectOpenHandles',
                '--forceExit'
            ];

            if (this.options.verbose) {
                jestArgs.push('--verbose');
            }

            if (this.options.coverage) {
                jestArgs.push('--coverage');
                jestArgs.push('--coverageDirectory=coverage/staging/' + suite.name.replace(/\s+/g, '-').toLowerCase());
            }

            const jest = spawn('npx', ['jest', ...jestArgs], {
                cwd: path.join(__dirname, '../..'),
                stdio: this.options.verbose ? 'inherit' : 'pipe'
            });

            let output = '';
            let errorOutput = '';

            if (!this.options.verbose) {
                jest.stdout?.on('data', (data) => {
                    output += data.toString();
                });

                jest.stderr?.on('data', (data) => {
                    errorOutput += data.toString();
                });
            }

            jest.on('close', (code) => {
                const endTime = Date.now();
                const duration = endTime - startTime;

                const result = {
                    suite: suite.name,
                    file: suite.file,
                    success: code === 0,
                    exitCode: code,
                    duration,
                    startTime: new Date(startTime),
                    endTime: new Date(endTime),
                    output: this.options.verbose ? null : output,
                    errorOutput: this.options.verbose ? null : errorOutput,
                    stats: this.parseJestOutput(output),
                    error: code !== 0 ? (errorOutput || `Exit code: ${code}`) : null
                };

                resolve(result);
            });

            jest.on('error', (error) => {
                const endTime = Date.now();
                resolve({
                    suite: suite.name,
                    file: suite.file,
                    success: false,
                    exitCode: -1,
                    duration: endTime - startTime,
                    startTime: new Date(startTime),
                    endTime: new Date(endTime),
                    error: error.message,
                    stats: {}
                });
            });
        });
    }

    parseJestOutput(output) {
        const stats = {
            tests: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            suites: 0
        };

        if (!output) return stats;

        // Extraction des statistiques Jest
        const testSuiteMatch = output.match(/Test Suites:\s+(\d+)\s+passed/);
        if (testSuiteMatch) {
            stats.suites = parseInt(testSuiteMatch[1]);
        }

        const testsMatch = output.match(/Tests:\s+(\d+)\s+passed/);
        if (testsMatch) {
            stats.tests = parseInt(testsMatch[1]);
            stats.passed = parseInt(testsMatch[1]);
        }

        const failedMatch = output.match(/(\d+)\s+failed/);
        if (failedMatch) {
            stats.failed = parseInt(failedMatch[1]);
        }

        const skippedMatch = output.match(/(\d+)\s+skipped/);
        if (skippedMatch) {
            stats.skipped = parseInt(skippedMatch[1]);
        }

        return stats;
    }

    async generateFinalReport() {
        const duration = this.results.endTime - this.results.startTime;
        
        this.results.summary = {
            totalDuration: duration,
            averageDuration: this.results.suiteResults.length > 0 
                ? this.results.suiteResults.reduce((sum, r) => sum + r.duration, 0) / this.results.suiteResults.length 
                : 0,
            successRate: this.results.totalTests > 0 
                ? (this.results.passedTests / this.results.totalTests) * 100 
                : 0,
            totalTestsRun: this.results.suiteResults.reduce((sum, r) => sum + (r.stats.tests || 0), 0),
            totalTestsPassed: this.results.suiteResults.reduce((sum, r) => sum + (r.stats.passed || 0), 0),
            totalTestsFailed: this.results.suiteResults.reduce((sum, r) => sum + (r.stats.failed || 0), 0)
        };

        console.log('\n📊 RAPPORT FINAL DES TESTS STAGING');
        console.log('=====================================');
        console.log(`Début: ${this.results.startTime.toISOString()}`);
        console.log(`Fin: ${this.results.endTime.toISOString()}`);
        console.log(`Durée totale: ${duration}ms (${(duration/1000).toFixed(1)}s)`);
        console.log(`Durée moyenne par suite: ${this.results.summary.averageDuration.toFixed(0)}ms`);
        console.log('');
        console.log('📈 STATISTIQUES GLOBALES:');
        console.log(`Suites de tests: ${this.results.totalTests}`);
        console.log(`Suites réussies: ${this.results.passedTests}`);
        console.log(`Suites échouées: ${this.results.failedTests}`);
        console.log(`Taux de succès: ${this.results.summary.successRate.toFixed(1)}%`);
        console.log('');
        console.log(`Tests individuels: ${this.results.summary.totalTestsRun}`);
        console.log(`Tests réussis: ${this.results.summary.totalTestsPassed}`);
        console.log(`Tests échoués: ${this.results.summary.totalTestsFailed}`);
        console.log('');

        // Détail par suite
        console.log('📋 DÉTAIL PAR SUITE:');
        this.results.suiteResults.forEach(result => {
            const status = result.success ? '✅' : '❌';
            console.log(`${status} ${result.suite}`);
            console.log(`   Durée: ${result.duration}ms`);
            console.log(`   Tests: ${result.stats.tests || 0} (${result.stats.passed || 0} réussis, ${result.stats.failed || 0} échoués)`);
            if (!result.success && result.error) {
                console.log(`   Erreur: ${result.error.substring(0, 100)}...`);
            }
        });

        if (this.results.errors.length > 0) {
            console.log('\n❌ ERREURS DÉTECTÉES:');
            this.results.errors.forEach((error, index) => {
                console.log(`${index + 1}. ${error.suite}:`);
                console.log(`   ${error.error}`);
            });
        }

        // Génération du fichier de rapport si demandé
        if (this.options.report) {
            await this.saveReportToFile();
        }

        // Recommandations
        console.log('\n💡 RECOMMANDATIONS:');
        if (this.results.summary.successRate === 100) {
            console.log('✅ Tous les tests sont passés ! La migration est prête.');
        } else if (this.results.summary.successRate >= 80) {
            console.log('⚠️ La plupart des tests passent, mais quelques problèmes à corriger.');
        } else {
            console.log('🚨 Plusieurs tests échouent, révision nécessaire avant migration.');
        }

        console.log('🔍 Vérifiez les logs détaillés pour plus d\'informations.');
        console.log('📊 Consultez les rapports de coverage si générés.');
        console.log('🔄 Relancez les tests après corrections.');

        // Code de sortie
        const exitCode = this.results.failedTests > 0 ? 1 : 0;
        if (exitCode !== 0) {
            console.log(`\n❌ Tests échoués détectés. Code de sortie: ${exitCode}`);
        } else {
            console.log('\n✅ Tous les tests sont passés avec succès !');
        }

        process.exit(exitCode);
    }

    async saveReportToFile() {
        try {
            const reportsDir = path.join(__dirname, '../../reports');
            await fs.mkdir(reportsDir, { recursive: true });

            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const reportPath = path.join(reportsDir, `staging-tests-${timestamp}.json`);

            const fullReport = {
                metadata: {
                    generatedAt: new Date().toISOString(),
                    testRunner: 'staging-test-runner',
                    version: '1.0.0',
                    environment: {
                        nodeVersion: process.version,
                        platform: process.platform,
                        arch: process.arch
                    }
                },
                configuration: this.options,
                results: this.results
            };

            await fs.writeFile(reportPath, JSON.stringify(fullReport, null, 2));
            console.log(`\n📄 Rapport détaillé sauvegardé: ${reportPath}`);

            // Génération du rapport HTML si possible
            await this.generateHTMLReport(fullReport, reportsDir, timestamp);

        } catch (error) {
            console.error('❌ Erreur lors de la sauvegarde du rapport:', error.message);
        }
    }

    async generateHTMLReport(data, reportsDir, timestamp) {
        try {
            const htmlReport = this.generateHTMLContent(data);
            const htmlPath = path.join(reportsDir, `staging-tests-${timestamp}.html`);
            
            await fs.writeFile(htmlPath, htmlReport);
            console.log(`📄 Rapport HTML généré: ${htmlPath}`);
        } catch (error) {
            console.error('❌ Erreur génération HTML:', error.message);
        }
    }

    generateHTMLContent(data) {
        return `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport Tests Staging - ${data.metadata.generatedAt}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .success { color: #28a745; }
        .error { color: #dc3545; }
        .warning { color: #ffc107; }
        .suite { margin: 10px 0; padding: 15px; border-left: 4px solid #007bff; background: #f8f9fa; }
        .suite.success { border-left-color: #28a745; }
        .suite.error { border-left-color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 Rapport Tests de Migration Staging</h1>
        <p><strong>Généré le:</strong> ${data.metadata.generatedAt}</p>
        
        <div class="summary">
            <div class="metric">
                <div class="metric-value ${data.results.summary.successRate === 100 ? 'success' : data.results.summary.successRate >= 80 ? 'warning' : 'error'}">${data.results.summary.successRate.toFixed(1)}%</div>
                <div>Taux de succès</div>
            </div>
            <div class="metric">
                <div class="metric-value">${data.results.totalTests}</div>
                <div>Suites de tests</div>
            </div>
            <div class="metric">
                <div class="metric-value">${data.results.summary.totalTestsRun}</div>
                <div>Tests individuels</div>
            </div>
            <div class="metric">
                <div class="metric-value">${(data.results.summary.totalDuration/1000).toFixed(1)}s</div>
                <div>Durée totale</div>
            </div>
        </div>

        <h2>📋 Résultats par suite</h2>
        ${data.results.suiteResults.map(result => `
            <div class="suite ${result.success ? 'success' : 'error'}">
                <h3>${result.success ? '✅' : '❌'} ${result.suite}</h3>
                <p><strong>Durée:</strong> ${result.duration}ms</p>
                <p><strong>Tests:</strong> ${result.stats.tests || 0} (${result.stats.passed || 0} réussis, ${result.stats.failed || 0} échoués)</p>
                ${!result.success && result.error ? `<p><strong>Erreur:</strong> ${result.error}</p>` : ''}
            </div>
        `).join('')}

        ${data.results.errors.length > 0 ? `
            <h2>❌ Erreurs détectées</h2>
            ${data.results.errors.map(error => `
                <div class="suite error">
                    <h3>${error.suite}</h3>
                    <pre>${error.error}</pre>
                </div>
            `).join('')}
        ` : ''}

        <h2>⚙️ Configuration</h2>
        <table>
            <tr><th>Paramètre</th><th>Valeur</th></tr>
            <tr><td>Mode d'exécution</td><td>${data.configuration.parallel ? 'Parallèle' : 'Séquentiel'}</td></tr>
            <tr><td>Coverage</td><td>${data.configuration.coverage ? 'Activé' : 'Désactivé'}</td></tr>
            <tr><td>Verbose</td><td>${data.configuration.verbose ? 'Activé' : 'Désactivé'}</td></tr>
            <tr><td>Suite spécifique</td><td>${data.configuration.suite || 'Toutes'}</td></tr>
        </table>

        <h2>🔧 Environnement</h2>
        <table>
            <tr><th>Propriété</th><th>Valeur</th></tr>
            <tr><td>Node.js</td><td>${data.metadata.environment.nodeVersion}</td></tr>
            <tr><td>Plateforme</td><td>${data.metadata.environment.platform}</td></tr>
            <tr><td>Architecture</td><td>${data.metadata.environment.arch}</td></tr>
        </table>
    </div>
</body>
</html>
        `;
    }
}

// Fonction d'aide
function printUsage() {
    console.log(`
🧪 Lanceur de Tests de Migration Staging

Usage: node run-staging-tests.js [options]

Options:
  --verbose        Affichage détaillé des tests
  --coverage       Génération de rapports de coverage
  --parallel       Exécution parallèle des suites (plus rapide)
  --suite <name>   Exécute une suite spécifique
  --report         Génère un rapport détaillé (JSON + HTML)
  --help           Affiche cette aide

Exemples:
  node run-staging-tests.js
  node run-staging-tests.js --verbose --coverage
  node run-staging-tests.js --parallel --report
  node run-staging-tests.js --suite data-validation
  node run-staging-tests.js --suite "Performance Tests"

Suites disponibles:
  - data-validation.test.js (Data Validation Tests)
  - functionality.test.js (Functionality Tests)
  - performance.test.js (Performance Tests)
  - regression.test.js (Regression Tests)
  - monitoring.test.js (Monitoring Tests)
    `);
}

// Point d'entrée
async function main() {
    if (process.argv.includes('--help')) {
        printUsage();
        process.exit(0);
    }

    const runner = new StagingTestRunner();
    await runner.run();
}

// Gestion des signaux pour nettoyage
process.on('SIGINT', () => {
    console.log('\n🛑 Interruption demandée. Nettoyage en cours...');
    process.exit(1);
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Terminaison demandée. Nettoyage en cours...');
    process.exit(1);
});

if (require.main === module) {
    main().catch(error => {
        console.error('❌ Erreur fatale:', error);
        process.exit(1);
    });
}

module.exports = StagingTestRunner;