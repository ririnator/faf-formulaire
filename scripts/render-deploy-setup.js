#!/usr/bin/env node

/**
 * Script de Configuration Automatique pour Déploiement Render.com
 * 
 * Ce script aide à préparer l'application FAF pour le déploiement sur Render.com
 * en validant la configuration et en générant les variables d'environnement nécessaires.
 */

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

class RenderDeploySetup {
  constructor() {
    this.requiredVars = [
      'MONGODB_URI',
      'SESSION_SECRET',
      'LOGIN_ADMIN_USER', 
      'LOGIN_ADMIN_PASS',
      'FORM_ADMIN_NAME',
      'APP_BASE_URL',
      'CLOUDINARY_CLOUD_NAME',
      'CLOUDINARY_API_KEY',
      'CLOUDINARY_API_SECRET'
    ];
    
    this.optionalVars = [
      'FRONTEND_URL',
      'RESEND_API_KEY',
      'EMAIL_FROM_ADDRESS',
      'COOKIE_DOMAIN'
    ];
    
    this.generateSecrets();
  }

  /**
   * Génère les secrets de sécurité nécessaires
   */
  generateSecrets() {
    console.log('🔐 Génération des secrets de sécurité...\n');
    
    // SESSION_SECRET : clé de 64 caractères
    const sessionSecret = crypto.randomBytes(32).toString('hex');
    console.log('SESSION_SECRET (64 caractères) :');
    console.log(sessionSecret);
    console.log();
    
    // Clé API factice pour exemple
    const apiKey = crypto.randomBytes(16).toString('hex');
    console.log('Exemple clé API (32 caractères) :');
    console.log(apiKey);
    console.log();
  }

  /**
   * Valide la configuration actuelle
   */
  validateConfig() {
    console.log('✅ Validation de la configuration...\n');
    
    const missing = [];
    const warnings = [];
    
    // Vérifier les variables requises
    this.requiredVars.forEach(varName => {
      if (!process.env[varName]) {
        missing.push(varName);
      }
    });
    
    // Vérifier les variables optionnelles
    this.optionalVars.forEach(varName => {
      if (!process.env[varName]) {
        warnings.push(varName);
      }
    });
    
    if (missing.length > 0) {
      console.log('❌ Variables requises manquantes :');
      missing.forEach(varName => console.log(`  - ${varName}`));
      console.log();
    }
    
    if (warnings.length > 0) {
      console.log('⚠️  Variables optionnelles manquantes :');
      warnings.forEach(varName => console.log(`  - ${varName}`));
      console.log();
    }
    
    if (missing.length === 0) {
      console.log('✅ Toutes les variables requises sont présentes');
    }
    
    return missing.length === 0;
  }

  /**
   * Génère le template de variables d'environnement pour Render
   */
  generateEnvTemplate() {
    console.log('📝 Génération du template variables d\'environnement...\n');
    
    const template = `# Variables d'environnement pour Render.com
# Copiez ces variables dans le dashboard Render > Environment Variables

# ========== VARIABLES OBLIGATOIRES ==========

# Base de données MongoDB Atlas
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/faf-production?retryWrites=true&w=majority

# Sécurité des sessions (utilisez la valeur générée ci-dessus)
SESSION_SECRET=${crypto.randomBytes(32).toString('hex')}

# Authentification admin
LOGIN_ADMIN_USER=admin
LOGIN_ADMIN_PASS=votre-mot-de-passe-admin-très-sécurisé
FORM_ADMIN_NAME=riri

# URLs et CORS (mettez à jour avec votre vraie URL Render)
APP_BASE_URL=https://votre-app.onrender.com
FRONTEND_URL=https://votre-app.onrender.com

# Upload d'images Cloudinary
CLOUDINARY_CLOUD_NAME=votre-cloud-name
CLOUDINARY_API_KEY=votre-api-key
CLOUDINARY_API_SECRET=votre-api-secret

# Configuration production
NODE_ENV=production
PORT=10000
HTTPS=true

# ========== VARIABLES OPTIONNELLES ==========

# Domaine des cookies (pour sous-domaines)
COOKIE_DOMAIN=.votre-domaine.com

# Email service
RESEND_API_KEY=votre-resend-api-key
EMAIL_FROM_ADDRESS=noreply@votre-domaine.com
EMAIL_FROM_NAME=Form-a-Friend

# Monitoring email
ENABLE_EMAIL_MONITORING=true
EMAIL_BOUNCE_RATE_THRESHOLD=0.05
EMAIL_COMPLAINT_RATE_THRESHOLD=0.01

# Configuration scheduler
SCHEDULER_TIMEZONE=Europe/Paris
SCHEDULER_MONTHLY_JOB_DAY=5
SCHEDULER_MONTHLY_JOB_HOUR=18

# Limites service
CONTACT_MAX_CSV_SIZE=5242880
CONTACT_MAX_BATCH_SIZE=100
INVITATION_EXPIRATION_DAYS=60
HANDSHAKE_EXPIRATION_DAYS=30

# Debug et développement
DISABLE_RATE_LIMITING=false
DEBUG_VERBOSE=false`;

    // Sauvegarder le template
    const outputPath = path.join(__dirname, '..', 'render-env-template.txt');
    fs.writeFileSync(outputPath, template);
    
    console.log('📁 Template sauvegardé dans : render-env-template.txt');
    console.log(`📍 Chemin complet : ${outputPath}`);
    console.log();
  }

  /**
   * Valide les prérequis système
   */
  validatePrerequisites() {
    console.log('🔍 Validation des prérequis...\n');
    
    const checks = [
      {
        name: 'Node.js version',
        check: () => {
          const version = process.version;
          const major = parseInt(version.substr(1).split('.')[0]);
          return major >= 18;
        },
        message: 'Node.js 18+ requis'
      },
      {
        name: 'package.json présent',
        check: () => fs.existsSync(path.join(__dirname, '..', 'backend', 'package.json')),
        message: 'package.json manquant dans /backend/'
      },
      {
        name: 'app.js présent',
        check: () => fs.existsSync(path.join(__dirname, '..', 'backend', 'app.js')),
        message: 'app.js manquant dans /backend/'
      },
      {
        name: 'Frontend présent',
        check: () => fs.existsSync(path.join(__dirname, '..', 'frontend')),
        message: 'Dossier frontend manquant'
      },
      {
        name: 'Tests post-déploiement',
        check: () => fs.existsSync(path.join(__dirname, '..', 'backend', 'tests', 'post-deployment')),
        message: 'Tests post-déploiement manquants dans /backend/tests/'
      }
    ];
    
    let allPassed = true;
    
    checks.forEach(({ name, check, message }) => {
      const passed = check();
      console.log(`${passed ? '✅' : '❌'} ${name} : ${passed ? 'OK' : message}`);
      if (!passed) allPassed = false;
    });
    
    console.log();
    return allPassed;
  }

  /**
   * Génère les instructions de déploiement
   */
  generateDeployInstructions() {
    console.log('📋 Instructions de déploiement Render.com...\n');
    
    const instructions = `
# Instructions de Déploiement Render.com

## 1. Prérequis
- Compte GitHub avec le code FAF
- Compte Render.com
- Compte MongoDB Atlas
- Compte Cloudinary

## 2. Configuration MongoDB Atlas
1. Créez un cluster MongoDB Atlas
2. Configurez l'accès réseau : 0.0.0.0/0 (Render utilise des IPs dynamiques)
3. Créez un utilisateur avec droits readWrite
4. Récupérez la string de connexion

## 3. Configuration Cloudinary
1. Créez un compte Cloudinary
2. Récupérez : Cloud Name, API Key, API Secret
3. Configurez les upload presets si nécessaire

## 4. Configuration Render
1. Connectez votre repo GitHub à Render
2. Créez un nouveau Web Service
3. Configuration :
   - Name: faf-production
   - Environment: Node
   - Region: Frankfurt (Europe) ou Oregon (US)
   - Branch: main
   - Root Directory: backend
   - Build Command: npm ci --only=production
   - Start Command: npm start

## 5. Variables d'Environnement
Copiez toutes les variables du fichier render-env-template.txt
dans Render Dashboard > Environment Variables

## 6. Déploiement
1. Cliquez "Create Web Service"
2. Attendez la completion du build
3. Vérifiez le health check sur /health

## 7. Tests Post-Déploiement
Une fois déployé, exécutez :
curl https://votre-app.onrender.com/health

## 8. Configuration du Domaine (Optionnel)
1. Render Dashboard > Settings > Custom Domains
2. Ajoutez votre domaine
3. Configurez les enregistrements DNS

## Endpoints Critiques à Tester :
- GET /health (health check)
- GET /form (formulaire public)
- POST /admin-login (authentification admin)
- GET /admin (dashboard admin)
- GET /api/v2/health (health check API v2)
`;

    console.log(instructions);
  }

  /**
   * Exécute toute la configuration
   */
  run() {
    console.log('🚀 Configuration Automatique Render.com pour FAF\n');
    console.log('='.repeat(50) + '\n');
    
    // 1. Valider les prérequis
    const prereqsOK = this.validatePrerequisites();
    if (!prereqsOK) {
      console.log('❌ Prérequis non satisfaits. Corrigez les erreurs avant de continuer.');
      return;
    }
    
    // 2. Générer les secrets
    this.generateSecrets();
    
    // 3. Générer le template d'environnement
    this.generateEnvTemplate();
    
    // 4. Valider la config actuelle (si .env existe)
    const envPath = path.join(__dirname, '..', 'backend', '.env');
    if (fs.existsSync(envPath)) {
      require('dotenv').config({ path: envPath });
      this.validateConfig();
    }
    
    // 5. Instructions finales
    this.generateDeployInstructions();
    
    console.log('\n' + '='.repeat(50));
    console.log('✅ Configuration terminée !');
    console.log('📁 Fichiers générés :');
    console.log('  - render-env-template.txt (variables d\'environnement)');
    console.log('  - render.yaml (configuration Render)');
    console.log('\n📖 Consultez RENDER_DEPLOYMENT_GUIDE.md pour les détails complets.');
  }
}

// Exécuter si appelé directement
if (require.main === module) {
  const setup = new RenderDeploySetup();
  setup.run();
}

module.exports = RenderDeploySetup;