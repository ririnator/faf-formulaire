#!/usr/bin/env node

/**
 * Script d'installation et de configuration du système de validation
 * 
 * Fonctionnalités :
 * - Installation des dépendances
 * - Configuration de l'environnement
 * - Test de connexion à la base de données
 * - Création des répertoires de sortie
 * 
 * @author FAF Migration Team
 */

const { execSync } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');

class ValidatorInstaller {
    constructor() {
        this.baseDir = __dirname;
        this.backendDir = path.join(this.baseDir, '../../backend');
    }

    /**
     * Installation principale
     */
    async install() {
        console.log(chalk.blue.bold('🚀 Installation du système de validation d\'intégrité FAF'));
        console.log(chalk.blue('=' .repeat(60)));
        
        try {
            await this.checkNodeVersion();
            await this.installDependencies();
            await this.createDirectories();
            await this.setupEnvironment();
            await this.testConnection();
            await this.createShortcuts();
            
            console.log(chalk.green.bold('\n✅ Installation terminée avec succès !'));
            this.displayUsageInstructions();
            
        } catch (error) {
            console.error(chalk.red.bold('\n❌ Erreur d\'installation:'), error.message);
            process.exit(1);
        }
    }

    /**
     * Vérification de la version Node.js
     */
    async checkNodeVersion() {
        console.log(chalk.yellow('🔍 Vérification de la version Node.js...'));
        
        const nodeVersion = process.version;
        const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
        
        if (majorVersion < 16) {
            throw new Error(`Node.js version ${nodeVersion} détectée. Version 16+ requise.`);
        }
        
        console.log(chalk.green(`✅ Node.js ${nodeVersion} compatible`));
    }

    /**
     * Installation des dépendances
     */
    async installDependencies() {
        console.log(chalk.yellow('📦 Installation des dépendances...'));
        
        try {
            // Installation des dépendances du validateur
            execSync('npm install', { 
                cwd: this.baseDir, 
                stdio: 'inherit'
            });
            
            console.log(chalk.green('✅ Dépendances installées'));
            
        } catch (error) {
            throw new Error(`Échec d'installation des dépendances: ${error.message}`);
        }
    }

    /**
     * Création des répertoires
     */
    async createDirectories() {
        console.log(chalk.yellow('📁 Création des répertoires...'));
        
        const directories = [
            './validation-reports',
            './logs',
            './correctors',
            './tests'
        ];
        
        for (const dir of directories) {
            const fullPath = path.join(this.baseDir, dir);
            await fs.mkdir(fullPath, { recursive: true });
            console.log(chalk.gray(`  ✓ ${dir}`));
        }
        
        console.log(chalk.green('✅ Répertoires créés'));
    }

    /**
     * Configuration de l'environnement
     */
    async setupEnvironment() {
        console.log(chalk.yellow('⚙️ Configuration de l\'environnement...'));
        
        try {
            // Copie du .env depuis le backend si il existe
            const backendEnvPath = path.join(this.backendDir, '.env');
            const validatorEnvPath = path.join(this.baseDir, '.env');
            
            try {
                await fs.access(backendEnvPath);
                await fs.copyFile(backendEnvPath, validatorEnvPath);
                console.log(chalk.green('✅ Configuration environnement copiée depuis backend'));
            } catch (error) {
                console.log(chalk.yellow('⚠️ Fichier .env backend non trouvé, utilisation des variables système'));
            }
            
            // Test de l'environnement
            require('dotenv').config({ path: validatorEnvPath });
            
            const requiredVars = ['MONGODB_URI'];
            const missingVars = requiredVars.filter(varName => !process.env[varName]);
            
            if (missingVars.length > 0) {
                console.log(chalk.yellow(`⚠️ Variables manquantes: ${missingVars.join(', ')}`));
                console.log(chalk.yellow('   Ces variables peuvent être définies dans le système'));
            }
            
        } catch (error) {
            console.log(chalk.yellow('⚠️ Configuration environnement partielle'));
        }
    }

    /**
     * Test de connexion à la base de données
     */
    async testConnection() {
        console.log(chalk.yellow('🔌 Test de connexion à la base de données...'));
        
        try {
            const DatabaseConnection = require('./utils/DatabaseConnection');
            const db = new DatabaseConnection();
            
            const testResult = await db.testConnection();
            
            if (testResult.success) {
                console.log(chalk.green('✅ Connexion MongoDB réussie'));
                console.log(chalk.gray(`   Temps de connexion: ${testResult.metrics.connectionTime}ms`));
            } else {
                console.log(chalk.yellow('⚠️ Connexion MongoDB échouée:'), testResult.error);
                console.log(chalk.yellow('   Le validateur peut toujours être utilisé avec une connexion ultérieure'));
            }
            
        } catch (error) {
            console.log(chalk.yellow('⚠️ Test de connexion impossible:'), error.message);
        }
    }

    /**
     * Création des raccourcis
     */
    async createShortcuts() {
        console.log(chalk.yellow('🔗 Création des raccourcis...'));
        
        // Script de validation rapide
        const quickValidateScript = `#!/bin/bash
# Script de validation rapide FAF
cd "$(dirname "$0")"
node index.js "$@"
`;
        
        const scriptPath = path.join(this.baseDir, 'validate.sh');
        await fs.writeFile(scriptPath, quickValidateScript);
        
        // Rendre exécutable sur Unix
        if (process.platform !== 'win32') {
            try {
                execSync(`chmod +x "${scriptPath}"`);
            } catch (error) {
                // Ignorer les erreurs de chmod
            }
        }
        
        // Script Windows
        const windowsScript = `@echo off
cd /d "%~dp0"
node index.js %*
`;
        
        const batPath = path.join(this.baseDir, 'validate.bat');
        await fs.writeFile(batPath, windowsScript);
        
        console.log(chalk.green('✅ Raccourcis créés'));
    }

    /**
     * Affichage des instructions d'utilisation
     */
    displayUsageInstructions() {
        console.log(chalk.blue('\n📋 Instructions d\'utilisation:'));
        console.log(chalk.white('─'.repeat(50)));
        
        console.log(chalk.cyan('\n🔍 Validation complète:'));
        console.log(chalk.white('  node index.js'));
        console.log(chalk.white('  ./validate.sh (Unix) ou validate.bat (Windows)'));
        
        console.log(chalk.cyan('\n🎯 Validations spécifiques:'));
        console.log(chalk.white('  node index.js --counts-only        # Comptages uniquement'));
        console.log(chalk.white('  node index.js --relations-only     # Relations uniquement'));
        console.log(chalk.white('  node index.js --tokens-only        # Tokens uniquement'));
        console.log(chalk.white('  node index.js --functionality-only # Fonctionnalités uniquement'));
        console.log(chalk.white('  node index.js --data-only          # Données uniquement'));
        
        console.log(chalk.cyan('\n⚙️ Options avancées:'));
        console.log(chalk.white('  node index.js --verbose            # Mode verbeux'));
        console.log(chalk.white('  node index.js --output-dir ./reports # Répertoire de sortie'));
        console.log(chalk.white('  node index.js --timeout 600000     # Timeout (ms)'));
        
        console.log(chalk.cyan('\n📊 Formats de rapport:'));
        console.log(chalk.white('  Les rapports sont générés en JSON (par défaut)'));
        console.log(chalk.white('  HTML et CSV disponibles via les options du générateur'));
        
        console.log(chalk.cyan('\n🆘 Aide:'));
        console.log(chalk.white('  node index.js --help'));
        
        console.log(chalk.blue('\n🎉 Le système est prêt à utiliser !'));
    }
}

// Exécution si appelé directement
if (require.main === module) {
    const installer = new ValidatorInstaller();
    installer.install();
}

module.exports = ValidatorInstaller;