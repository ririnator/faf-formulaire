/**
 * Générateur de Rapports - Validation FAF
 * 
 * Génère des rapports détaillés avec scoring d'intégrité :
 * - Score d'intégrité global (%)
 * - Détails par catégorie de validation
 * - Liste des erreurs avec recommandations
 * - Métriques de performance
 * - Actions correctives automatiques
 * 
 * @author FAF Migration Team
 */

const fs = require('fs').promises;
const path = require('path');

class ReportGenerator {
    constructor(logger) {
        this.logger = logger;
        this.reportTemplate = this.defineReportTemplate();
    }

    /**
     * Génération du rapport principal
     */
    async generate(validationResults, metadata = {}) {
        this.logger.info('📊 Génération du rapport d\'intégrité...');
        
        try {
            const report = {
                metadata: this.buildMetadata(metadata),
                summary: this.buildSummary(validationResults),
                categories: this.buildCategoryDetails(validationResults),
                recommendations: this.generateRecommendations(validationResults),
                correctiveActions: this.generateCorrectiveActions(validationResults),
                performance: this.buildPerformanceMetrics(validationResults, metadata),
                rawData: this.buildRawData(validationResults)
            };
            
            // Validation du rapport
            this.validateReport(report);
            
            this.logger.success('✅ Rapport généré avec succès');
            return report;
            
        } catch (error) {
            this.logger.error('❌ Erreur lors de la génération du rapport:', error);
            throw error;
        }
    }

    /**
     * Construction des métadonnées
     */
    buildMetadata(metadata) {
        return {
            version: '2.0.0',
            generatedAt: new Date().toISOString(),
            generator: 'FAF Integrity Validation System',
            environment: process.env.NODE_ENV || 'development',
            totalDuration: metadata.totalDuration || 0,
            validationOptions: metadata.options || {},
            system: {
                node: process.version,
                platform: process.platform,
                arch: process.arch,
                memory: process.memoryUsage()
            }
        };
    }

    /**
     * Construction du résumé
     */
    buildSummary(validationResults) {
        const scores = [];
        const errorCounts = [];
        const categoryStats = {};
        const criticalErrors = [];
        const recommendations = [];
        
        for (const [categoryName, result] of validationResults) {
            if (result && typeof result.score === 'number') {
                scores.push(result.score);
                errorCounts.push(result.errors ? result.errors.length : 0);
                
                categoryStats[categoryName] = {
                    score: result.score,
                    success: result.success,
                    errorCount: result.errors ? result.errors.length : 0,
                    status: this.getCategoryStatus(result.score)
                };
                
                // Identification des erreurs critiques
                if (result.errors && result.errors.length > 0) {
                    for (const error of result.errors) {
                        if (this.isCriticalError(error)) {
                            criticalErrors.push(`[${categoryName}] ${error.message}`);
                        }
                    }
                }
                
                // Collecte des recommandations
                const categoryRecommendations = this.getCategoryRecommendations(categoryName, result);
                recommendations.push(...categoryRecommendations);
            }
        }
        
        const overallScore = scores.length > 0 
            ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
            : 0;
        
        const totalErrors = errorCounts.reduce((a, b) => a + b, 0);
        
        return {
            overallScore,
            status: this.getOverallStatus(overallScore),
            totalErrors,
            categoriesValidated: scores.length,
            categoriesSuccess: scores.filter(s => s >= 95).length,
            categoriesWarning: scores.filter(s => s >= 80 && s < 95).length,
            categoriesFailure: scores.filter(s => s < 80).length,
            criticalErrors,
            recommendations: recommendations.slice(0, 10), // Top 10 recommandations
            timestamp: new Date().toISOString(),
            breakdown: categoryStats
        };
    }

    /**
     * Construction des détails par catégorie
     */
    buildCategoryDetails(validationResults) {
        const categoryDetails = {};
        
        for (const [categoryName, result] of validationResults) {
            if (result) {
                categoryDetails[categoryName] = {
                    name: this.getCategoryDisplayName(categoryName),
                    score: result.score || 0,
                    success: result.success || false,
                    status: this.getCategoryStatus(result.score || 0),
                    errors: this.formatErrors(result.errors || []),
                    warnings: this.formatWarnings(result.warnings || []),
                    details: result.details || {},
                    metadata: result.metadata || {},
                    executionTime: this.getExecutionTime(result),
                    recommendations: this.getCategoryRecommendations(categoryName, result)
                };
            }
        }
        
        return categoryDetails;
    }

    /**
     * Génération des recommandations
     */
    generateRecommendations(validationResults) {
        const recommendations = [];
        
        for (const [categoryName, result] of validationResults) {
            if (result && result.score < 95) {
                const categoryRecommendations = this.getCategoryRecommendations(categoryName, result);
                recommendations.push({
                    category: categoryName,
                    priority: this.getRecommendationPriority(result.score),
                    recommendations: categoryRecommendations
                });
            }
        }
        
        // Tri par priorité
        recommendations.sort((a, b) => {
            const priorityOrder = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
            return priorityOrder[b.priority] - priorityOrder[a.priority];
        });
        
        return recommendations;
    }

    /**
     * Recommandations spécifiques par catégorie
     */
    getCategoryRecommendations(categoryName, result) {
        const recommendations = [];
        
        switch (categoryName) {
            case 'counts':
                if (result.score < 95) {
                    recommendations.push('Vérifier la correspondance 1:1 entre Response et Submission');
                    recommendations.push('Examiner les doublons détectés et corriger les données');
                    if (result.details && result.details.discrepancies) {
                        recommendations.push('Analyser les divergences dans les comptages mensuels');
                    }
                }
                break;
                
            case 'relations':
                if (result.score < 95) {
                    recommendations.push('Corriger les références orphelines détectées');
                    recommendations.push('Vérifier l\'intégrité référentielle User↔Submission');
                    recommendations.push('Valider les contraintes d\'unicité (username, email)');
                }
                break;
                
            case 'tokens':
                if (result.score < 95) {
                    recommendations.push('Restaurer les tokens legacy manquants');
                    recommendations.push('Vérifier le mapping Response.token → Invitation.token');
                    recommendations.push('Tester l\'accessibilité des URLs legacy');
                }
                break;
                
            case 'functionality':
                if (result.score < 95) {
                    recommendations.push('Tester les workflows d\'authentification');
                    recommendations.push('Valider l\'accès aux données historiques');
                    recommendations.push('Vérifier les fonctionnalités de dashboard');
                }
                break;
                
            case 'data':
                if (result.score < 95) {
                    recommendations.push('Corriger les violations de schéma détectées');
                    recommendations.push('Valider l\'encodage UTF-8 des caractères français');
                    recommendations.push('Enforcer les contraintes de données');
                }
                break;
        }
        
        return recommendations;
    }

    /**
     * Génération des actions correctives
     */
    generateCorrectiveActions(validationResults) {
        const actions = [];
        
        for (const [categoryName, result] of validationResults) {
            if (result && result.score < 80) {
                const categoryActions = this.getCategoryCorrectiveActions(categoryName, result);
                actions.push({
                    category: categoryName,
                    urgency: this.getActionUrgency(result.score),
                    actions: categoryActions
                });
            }
        }
        
        return actions;
    }

    /**
     * Actions correctives par catégorie
     */
    getCategoryCorrectiveActions(categoryName, result) {
        const actions = [];
        
        switch (categoryName) {
            case 'counts':
                if (result.details && result.details.discrepancies) {
                    actions.push({
                        type: 'DATA_CORRECTION',
                        description: 'Corriger les divergences de comptage',
                        automated: false,
                        command: 'node scripts/validation/correctors/count-corrector.js'
                    });
                }
                break;
                
            case 'relations':
                if (result.details && result.details.orphanedReferences) {
                    actions.push({
                        type: 'REFERENCE_CLEANUP',
                        description: 'Nettoyer les références orphelines',
                        automated: true,
                        command: 'node scripts/validation/correctors/relation-corrector.js --clean-orphans'
                    });
                }
                break;
                
            case 'tokens':
                if (result.details && result.details.tokenPreservation) {
                    actions.push({
                        type: 'TOKEN_RESTORATION',
                        description: 'Restaurer les tokens manquants',
                        automated: true,
                        command: 'node scripts/validation/correctors/token-corrector.js --restore-missing'
                    });
                }
                break;
                
            case 'functionality':
                actions.push({
                    type: 'FUNCTIONAL_TEST',
                    description: 'Re-tester les fonctionnalités en échec',
                    automated: true,
                    command: 'node scripts/validation/index.js --functionality-only'
                });
                break;
                
            case 'data':
                if (result.details && result.details.constraintValidation) {
                    actions.push({
                        type: 'SCHEMA_ENFORCEMENT',
                        description: 'Enforcer les contraintes de schéma',
                        automated: false,
                        command: 'node scripts/validation/correctors/data-corrector.js --enforce-schema'
                    });
                }
                break;
        }
        
        return actions;
    }

    /**
     * Construction des métriques de performance
     */
    buildPerformanceMetrics(validationResults, metadata) {
        const performance = {
            totalDuration: metadata.totalDuration || 0,
            averageCategoryTime: 0,
            slowestCategory: null,
            fastestCategory: null,
            memoryUsage: process.memoryUsage(),
            categoryTimes: {}
        };
        
        const categoryTimes = [];
        
        for (const [categoryName, result] of validationResults) {
            if (result && result.metadata && result.metadata.duration) {
                const duration = result.metadata.duration;
                performance.categoryTimes[categoryName] = duration;
                categoryTimes.push({ name: categoryName, duration });
            }
        }
        
        if (categoryTimes.length > 0) {
            performance.averageCategoryTime = categoryTimes.reduce((sum, cat) => sum + cat.duration, 0) / categoryTimes.length;
            
            const sortedTimes = categoryTimes.sort((a, b) => b.duration - a.duration);
            performance.slowestCategory = sortedTimes[0];
            performance.fastestCategory = sortedTimes[sortedTimes.length - 1];
        }
        
        return performance;
    }

    /**
     * Construction des données brutes
     */
    buildRawData(validationResults) {
        const rawData = {};
        
        for (const [categoryName, result] of validationResults) {
            rawData[categoryName] = {
                score: result.score,
                success: result.success,
                errors: result.errors || [],
                warnings: result.warnings || [],
                details: result.details || {},
                metadata: result.metadata || {}
            };
        }
        
        return rawData;
    }

    /**
     * Formatage des erreurs
     */
    formatErrors(errors) {
        return errors.map(error => ({
            code: error.code,
            message: error.message,
            severity: this.getErrorSeverity(error.code),
            timestamp: error.timestamp,
            context: error.context || {},
            recommendation: this.getErrorRecommendation(error.code)
        }));
    }

    /**
     * Formatage des avertissements
     */
    formatWarnings(warnings) {
        return warnings.map(warning => ({
            code: warning.code,
            message: warning.message,
            timestamp: warning.timestamp,
            context: warning.context || {}
        }));
    }

    /**
     * Obtention du statut d'une catégorie
     */
    getCategoryStatus(score) {
        if (score >= 95) return 'SUCCESS';
        if (score >= 80) return 'WARNING';
        return 'FAILURE';
    }

    /**
     * Obtention du statut global
     */
    getOverallStatus(score) {
        if (score >= 95) return 'MIGRATION_VALIDATED';
        if (score >= 80) return 'MIGRATION_PARTIAL';
        return 'MIGRATION_FAILED';
    }

    /**
     * Obtention du nom d'affichage d'une catégorie
     */
    getCategoryDisplayName(categoryName) {
        const displayNames = {
            'counts': 'Validation des Comptages',
            'relations': 'Validation des Relations',
            'tokens': 'Validation des Tokens Legacy',
            'functionality': 'Validation des Fonctionnalités',
            'data': 'Validation des Données'
        };
        
        return displayNames[categoryName] || categoryName;
    }

    /**
     * Obtention du temps d'exécution
     */
    getExecutionTime(result) {
        return result.metadata && result.metadata.duration 
            ? result.metadata.duration 
            : 0;
    }

    /**
     * Obtention de la priorité d'une recommandation
     */
    getRecommendationPriority(score) {
        if (score < 50) return 'HIGH';
        if (score < 80) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Obtention de l'urgence d'une action
     */
    getActionUrgency(score) {
        if (score < 50) return 'CRITICAL';
        if (score < 70) return 'HIGH';
        return 'MEDIUM';
    }

    /**
     * Détection des erreurs critiques
     */
    isCriticalError(error) {
        const criticalCodes = [
            'COLLECTION_NOT_FOUND',
            'ORPHANED_SUBMISSION',
            'ORPHANED_INVITATION',
            'USERNAME_DUPLICATE',
            'EMAIL_DUPLICATE',
            'MISSING_TOKEN',
            'ADMIN_USER_NOT_FOUND',
            'INSUFFICIENT_USER_ACCOUNTS'
        ];
        
        return criticalCodes.includes(error.code);
    }

    /**
     * Obtention de la sévérité d'une erreur
     */
    getErrorSeverity(errorCode) {
        const highSeverityErrors = [
            'COLLECTION_NOT_FOUND',
            'ORPHANED_SUBMISSION',
            'ORPHANED_INVITATION',
            'USERNAME_DUPLICATE',
            'EMAIL_DUPLICATE',
            'MISSING_TOKEN'
        ];
        
        const mediumSeverityErrors = [
            'UNMATCHED_RESPONSE',
            'UNMATCHED_SUBMISSION',
            'ROLE_MISMATCH',
            'MONTHLY_MISMATCH'
        ];
        
        if (highSeverityErrors.includes(errorCode)) return 'HIGH';
        if (mediumSeverityErrors.includes(errorCode)) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Obtention de la recommandation pour une erreur
     */
    getErrorRecommendation(errorCode) {
        const recommendations = {
            'COLLECTION_NOT_FOUND': 'Vérifier la configuration de la base de données et l\'état de la migration',
            'ORPHANED_SUBMISSION': 'Créer l\'utilisateur manquant ou supprimer la submission orpheline',
            'ORPHANED_INVITATION': 'Créer l\'utilisateur manquant ou supprimer l\'invitation orpheline',
            'USERNAME_DUPLICATE': 'Résoudre le conflit de username en renommant l\'un des comptes',
            'EMAIL_DUPLICATE': 'Résoudre le conflit d\'email en modifiant l\'une des adresses',
            'MISSING_TOKEN': 'Créer l\'invitation manquante pour ce token legacy',
            'UNMATCHED_RESPONSE': 'Créer la submission correspondante pour cette response',
            'UNMATCHED_SUBMISSION': 'Vérifier l\'origine de cette submission sans response correspondante',
            'ROLE_MISMATCH': 'Corriger le rôle de l\'utilisateur pour qu\'il corresponde au type de submission',
            'MONTHLY_MISMATCH': 'Vérifier les données de migration pour ce mois spécifique'
        };
        
        return recommendations[errorCode] || 'Examiner l\'erreur et appliquer la correction appropriée';
    }

    /**
     * Définition du template de rapport
     */
    defineReportTemplate() {
        return {
            metadata: {},
            summary: {},
            categories: {},
            recommendations: [],
            correctiveActions: [],
            performance: {},
            rawData: {}
        };
    }

    /**
     * Validation du rapport
     */
    validateReport(report) {
        const requiredSections = ['metadata', 'summary', 'categories', 'recommendations', 'performance'];
        
        for (const section of requiredSections) {
            if (!report[section]) {
                throw new Error(`Section manquante dans le rapport: ${section}`);
            }
        }
        
        if (typeof report.summary.overallScore !== 'number') {
            throw new Error('Score global manquant ou invalide');
        }
        
        if (report.summary.overallScore < 0 || report.summary.overallScore > 100) {
            throw new Error('Score global hors limites (0-100)');
        }
    }

    /**
     * Génération d'un rapport HTML
     */
    async generateHtmlReport(report, outputPath) {
        this.logger.info('🌐 Génération du rapport HTML...');
        
        try {
            const htmlContent = this.buildHtmlContent(report);
            await fs.writeFile(outputPath, htmlContent);
            this.logger.success(`📁 Rapport HTML généré: ${outputPath}`);
        } catch (error) {
            this.logger.error('❌ Erreur génération HTML:', error.message);
            throw error;
        }
    }

    /**
     * Construction du contenu HTML
     */
    buildHtmlContent(report) {
        const statusClass = report.summary.status === 'MIGRATION_VALIDATED' ? 'success' : 
                           report.summary.status === 'MIGRATION_PARTIAL' ? 'warning' : 'error';
        
        return `
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Validation d'Intégrité FAF</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .score { font-size: 2em; font-weight: bold; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .error { color: #dc3545; }
        .category { margin: 20px 0; padding: 15px; border-left: 4px solid #007bff; background: #f8f9fa; }
        .recommendations { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .performance { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .error-list { max-height: 300px; overflow-y: auto; }
        .timestamp { font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Rapport de Validation d'Intégrité FAF</h1>
        <div class="score ${statusClass}">Score Global: ${report.summary.overallScore}%</div>
        <div class="timestamp">Généré le: ${new Date(report.metadata.generatedAt).toLocaleString('fr-FR')}</div>
        <div class="timestamp">Durée totale: ${this.formatDuration(report.performance.totalDuration)}</div>
    </div>

    <h2>📊 Résumé Exécutif</h2>
    <div class="performance">
        <div class="metric">
            <h4>Catégories Validées</h4>
            <div class="score">${report.summary.categoriesValidated}</div>
        </div>
        <div class="metric">
            <h4>Succès</h4>
            <div class="score success">${report.summary.categoriesSuccess}</div>
        </div>
        <div class="metric">
            <h4>Avertissements</h4>
            <div class="score warning">${report.summary.categoriesWarning}</div>
        </div>
        <div class="metric">
            <h4>Échecs</h4>
            <div class="score error">${report.summary.categoriesFailure}</div>
        </div>
    </div>

    <h2>📋 Détails par Catégorie</h2>
    ${Object.entries(report.categories).map(([name, category]) => `
        <div class="category">
            <h3>${category.name} - <span class="${category.status.toLowerCase()}">${category.score}%</span></h3>
            <p><strong>Statut:</strong> ${category.status}</p>
            <p><strong>Erreurs:</strong> ${category.errors.length}</p>
            <p><strong>Temps d'exécution:</strong> ${this.formatDuration(category.executionTime)}</p>
            ${category.errors.length > 0 ? `
                <div class="error-list">
                    <h4>Erreurs:</h4>
                    <ul>
                        ${category.errors.map(error => `<li><strong>${error.code}:</strong> ${error.message}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `).join('')}

    ${report.summary.criticalErrors.length > 0 ? `
        <h2>🚨 Erreurs Critiques</h2>
        <div class="recommendations">
            <ul>
                ${report.summary.criticalErrors.map(error => `<li>${error}</li>`).join('')}
            </ul>
        </div>
    ` : ''}

    ${report.recommendations.length > 0 ? `
        <h2>💡 Recommandations</h2>
        ${report.recommendations.map(rec => `
            <div class="recommendations">
                <h4>Catégorie: ${rec.category} (Priorité: ${rec.priority})</h4>
                <ul>
                    ${rec.recommendations.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </div>
        `).join('')}
    ` : ''}

    <h2>⚡ Métriques de Performance</h2>
    <div class="performance">
        <div class="metric">
            <h4>Durée Totale</h4>
            <div>${this.formatDuration(report.performance.totalDuration)}</div>
        </div>
        <div class="metric">
            <h4>Temps Moyen</h4>
            <div>${this.formatDuration(report.performance.averageCategoryTime)}</div>
        </div>
        ${report.performance.slowestCategory ? `
            <div class="metric">
                <h4>Plus Lent</h4>
                <div>${report.performance.slowestCategory.name}: ${this.formatDuration(report.performance.slowestCategory.duration)}</div>
            </div>
        ` : ''}
        ${report.performance.fastestCategory ? `
            <div class="metric">
                <h4>Plus Rapide</h4>
                <div>${report.performance.fastestCategory.name}: ${this.formatDuration(report.performance.fastestCategory.duration)}</div>
            </div>
        ` : ''}
    </div>

    <div class="timestamp">
        Rapport généré par ${report.metadata.generator} v${report.metadata.version}
    </div>
</body>
</html>`;
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
     * Génération d'un rapport CSV
     */
    async generateCsvReport(report, outputPath) {
        this.logger.info('📊 Génération du rapport CSV...');
        
        try {
            const csvContent = this.buildCsvContent(report);
            await fs.writeFile(outputPath, csvContent);
            this.logger.success(`📁 Rapport CSV généré: ${outputPath}`);
        } catch (error) {
            this.logger.error('❌ Erreur génération CSV:', error.message);
            throw error;
        }
    }

    /**
     * Construction du contenu CSV
     */
    buildCsvContent(report) {
        const lines = [
            'Category,Score,Status,Errors,Warnings,ExecutionTime'
        ];
        
        for (const [name, category] of Object.entries(report.categories)) {
            lines.push([
                name,
                category.score,
                category.status,
                category.errors.length,
                category.warnings.length,
                category.executionTime
            ].join(','));
        }
        
        return lines.join('\n');
    }
}

module.exports = ReportGenerator;